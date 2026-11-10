"""
Talking to a RouterOS box, for tests.

WHY SSH AND NOT THE REST API
----------------------------
RouterOS 7 has a perfectly good REST API, and for a greenfield tool it would be
the obvious choice. It's the wrong choice *here*, for two reasons that are
specific to this fleet:

1. The templates disable `www`, `www-ssl`, `api` and `api-ssl` BY NAME
   (see the `/ip/service` block in br.rsc.j2). Enabling one to run tests would
   put a new listening service on a router whose ether1 faces the DFZ, plus a
   self-signed certificate to verify or pin. Widening the attack surface of
   the box in order to check on it.

2. The deploy path is irreducibly SSH and SCP: upload the .rsc, then
   `reset-configuration run-after-reset=`. Testing over a different transport
   means a second credential, a second ACL entry and a second thing that can be
   wrong: and the failure mode is tests that can't reach a router the
   deployment can, or the reverse.

What the API would actually have bought is STRUCTURED DATA, and that's
available over SSH: `:serialize ... to=json` (RouterOS 7.13+) turns any
`print as-value` into JSON. So we get JSON, over the transport that already
exists, with no new service.

>>> IF YOU ARE ON ROUTEROS OLDER THAN 7.13, `:serialize` doesn't exist and
>>> every probe here returns PROBE-ERROR. The fleet is on 7.24.

ONE ROUND TRIP
--------------
All of it's fetched in a single ssh invocation that emits one `@@section`
line per menu. Ten SSH handshakes per router was the previous design's real
cost, and batching also means the whole snapshot is consistent. Taken at one
instant rather than smeared across a minute of reconnects.

Every section is individually wrapped in `:do {...} on-error={...}`, so an
unknown property in one menu costs you that section and reports itself as
`PROBE-ERROR` rather than silently returning an empty list that every
assertion downstream would read as "the network is down".
"""

import json
import subprocess

# Marker for one section of the probe output. Chosen because it can't appear
# in RouterOS JSON: `@` isn't a JSON structural character and the pair isn't
# something any property value here contains.
MARK = "@@"

# What a section returns when RouterOS refused the expression. Almost always a
# property that was renamed between releases. Distinguished from an empty list
# on purpose: "I couldn't ask" and "the answer is none" are different facts,
# and conflating them turns a tooling problem into a fake outage.
ERROR = "PROBE-ERROR"

SSH_OPTS = [
    # reset-configuration regenerates the router's host key, so a pinned
    # known_hosts entry would break every post-deploy reconnect.
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=10",
    # Fail fast instead of hanging on a password prompt. These tests run
    # unattended; a prompt is an indefinite hang, not an error.
    "-o", "BatchMode=yes",
]


def _section(name, expr):
    """One probe section: emit `@@name <json>`, or `@@name PROBE-ERROR`.

    `:serialize` is what turns `print as-value` into JSON. `options=json.pretty`
    is deliberately NOT used: the output has to stay on one line so the
    section marker can split it.
    """
    return (f':do {{ :put ("{MARK}{name} " . [:serialize to=json {expr}]) }} '
            f'on-error={{ :put "{MARK}{name} {ERROR}" }};')


def _scalar(name, expr):
    """A section holding one value rather than a table."""
    return (f':do {{ :put ("{MARK}{name} " . [:tostr {expr}]) }} '
            f'on-error={{ :put "{MARK}{name} {ERROR}" }};')


# The one thing `print as-value` can't give us.
#
# `/interface/wireguard/peers print as-value` returns only the CONFIGURED
# properties: interface, public-key, endpoint, allowed-address. The runtime
# ones (`last-handshake`, rx/tx counters, the current endpoint) are absent, and
# `print stats as-value` doesn't exist for this menu. Verified on 7.24.
#
# Worse than a missing field usually is, because the handshake
# is the ONLY liveness signal a WireGuard tunnel has. The interface reports
# `running` whether or not the far end has ever answered.
#
# So it's fetched with an explicit `get` per peer. The result is a flat
# `iface=age` list rather than JSON: building an array of dicts in RouterOS
# means concatenating named-key arrays, and named-key arrays MERGE on
# concatenation: every peer collapses into one entry with the last value
# winning. (That isn't a guess; it's what the first version of this did.)
# A space-delimited pair list has no such trap, and neither an interface name
# nor a time interval can contain a space or an `=`.
def _pairs(name, body):
    """A section emitting `k=v k=v`, for the values `print as-value` omits.

    `body` builds up a local `$o`; this wraps it in the marker and the error
    trap so it behaves like every other section.
    """
    return (f':do {{ :local o ""; {body} :put ("{MARK}{name} " . $o) }} '
            f'on-error={{ :put "{MARK}{name} {ERROR}" }};')


WG_HANDSHAKE_BODY = (
    ':foreach p in=[/interface/wireguard/peers find] do={'
    ' :local h [/interface/wireguard/peers get $p last-handshake];'
    ' :set o ($o . " " . [/interface/wireguard/peers get $p interface] . "="'
    ' . [:tostr $h]) };'
)

# Sections that are pair lists rather than JSON, parsed with parse_pairs.
PAIR_SECTIONS = frozenset({"wg_handshakes"})


def parse_pairs(payload):
    """`a=1 b=2` -> {"a": "1", "b": "2"}. A key with an empty value is kept:
    for the handshake probe that's the difference between "this peer has never
    handshaked" and "this peer isn't configured", and they aren't the same
    fault."""
    out = {}
    for token in (payload or "").split():
        key, sep, value = token.partition("=")
        if sep:
            out[key] = value.strip()
    return out


# Patterns that mean the config import was REJECTED partway through. RouterOS
# stops at the first line it can't parse and skips the rest.
IMPORT_ERROR_PATTERNS = (
    "syntax error",
    "Script Error",
    "expected end of command",
    "bad command name",
    "already have such entry",
)

# ...but matching one of those is NOT enough to call it an import failure.
#
# This used to count every match, on the reasoning that reset-configuration
# clears the log, so anything left had to be ours. True at the instant the
# import ends and false from then on: the log keeps accumulating, and the same
# five patterns are produced by anything typed at the CLI. A malformed chaos
# deadman and an operator typo put two `expected end of command` lines in
# br1's log and turned the next pipeline's BASELINE red. On a router whose
# config was, and had been all along, perfectly correct.
#
# A gate that fails for someone else's typo is a gate people learn to re-run
# until it's green, which is the opposite of what it's for.
#
# RouterOS distinguishes them itself, and both halves are confirmed from real
# log entries on this fleet:
#
#   import   system,error,critical  error while running run-after-reset
#                                   script: Script Error: missing value(s) of
#                                   argument(s) password (/user/add; line 144)
#
#   ad-hoc   script,error,debug     (ssh-cmd:gitlab-runner@203.0.113.236)
#                                   expected end of command (line 1 col 114)
#
# The import runs from run-after-reset at boot, when there's no session to
# attribute it to, so it can never carry this tag. Excluding tagged entries
# therefore drops CLI noise and can't drop a genuine import failure.
#
# Deliberately a denylist, not an allowlist: an error logged by something this
# comment didn't anticipate still COUNTS. Being red for an unknown reason is
# the safe direction for a deployment gate; being green isn't.
INTERACTIVE_MARK = "ssh-cmd:"


def import_error_query(interactive=False):
    """The `where` clause for import-attributable log errors.

    Also used to build the remediation command printed on failure, so the
    command in the message and the count in the assertion can't disagree.
    They did, and the printed command matched NEITHER of the two errors that
    were actually in the log, which sent the first person to read it looking
    for a fault that wasn't there.
    """
    match = " || ".join(f'message~"{p}"' for p in IMPORT_ERROR_PATTERNS)
    negate = "" if interactive else "!"
    return f'({match}) && {negate}(message~"{INTERACTIVE_MARK}")'


def build_probe(claims=()):
    """The single command that collects a router's entire state.

    `claims` are the customer-granted prefixes to count installed routes in;
    they come from the manifest, so an edge router asks about exactly what its
    firewalls were granted and a border router asks about nothing.

    Returned as ONE LINE. It has to be: this string is passed to ssh as
    a single argv element, and a newline landing inside a `:do { }` block or a
    parenthesised expression is a RouterOS syntax error whose symptom is an
    empty probe. `test_probes.py` asserts it.
    """
    parts = [
        _scalar("identity", "[/system/identity/get name]"),
        _scalar("version", "[/system/resource/get version]"),
        _scalar("logerr",
                f'[:len [/log find where {import_error_query()}]]'),
        # Counted separately and asserted on by nothing. It's here so a
        # genuine import failure can be told apart from a router someone has
        # been typing on, without a second trip to the box.
        _scalar("logerr_adhoc",
                f'[:len [/log find where {import_error_query(interactive=True)}]]'),
        _section("logerr_msgs",
                 f'[/log print as-value where {import_error_query()}]'),

        _section("ospf", "[/routing/ospf/neighbor print as-value]"),
        _section("bgp", "[/routing/bgp/session print as-value]"),
        _section("wg_peers", "[/interface/wireguard/peers print as-value]"),
        _section("wg_ifaces", "[/interface/wireguard print as-value]"),
        # Runtime, so not available from print as-value. See the note above.
        _pairs("wg_handshakes", WG_HANDSHAKE_BODY),
        _section("bfd", "[/routing/bfd/session print as-value]"),

        # Route table slices rather than the whole table. A border router's v4
        # table is tiny (filter-nlri drops everything but the default before it
        # is stored) but an edge router's isn't, and shipping it all back would
        # be a lot of JSON to prove two facts.
        _section("default4",
                 '[/ip/route print as-value where dst-address="0.0.0.0/0"]'),
        _section("default6",
                 '[/ipv6/route print as-value where dst-address="::/0"]'),
        _section("blackhole4", "[/ip/route print as-value where blackhole]"),
        _section("blackhole6", "[/ipv6/route print as-value where blackhole]"),
    ]

    # Customer routes actually installed inside each granted block.
    #
    # `!blackhole`, NOT `blackhole=no`. RouterOS leaves the property UNSET on a
    # route that isn't a blackhole, so `blackhole=no` matches nothing at all.
    # It silently returns zero rows for a table full of healthy routes. This
    # probe was written with the wrong spelling first and reported an edge
    # router carrying live customer routes as carrying none.
    #
    # The same mistake was in anchor-guard on the border routers, where it was
    # considerably worse; see the note in templates/br.rsc.j2.
    for i, prefix in enumerate(claims):
        parts.append(_section(
            f"claim{i}",
            f'[/ip/route print as-value where dst-address in {prefix} '
            f'&& active && !blackhole]'))

    return " ".join(parts)


def parse_probe(stdout):
    """`@@section payload` lines -> {section: parsed}.

    A section that failed comes back as the ERROR sentinel rather than as data,
    and stays that way through to the assertion, which reports it as a probe
    problem rather than as a network fault.
    """
    out = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith(MARK):
            continue
        name, _, payload = line[len(MARK):].partition(" ")
        payload = payload.strip()
        if payload == ERROR:
            out[name] = ERROR
            continue
        if name in PAIR_SECTIONS:
            out[name] = parse_pairs(payload)
        elif payload.startswith(("[", "{")):
            try:
                out[name] = json.loads(payload)
            except json.JSONDecodeError:
                out[name] = ERROR
        else:
            out[name] = payload
    return out


def as_bool(value):
    """RouterOS booleans through `:serialize` arrive as strings unless
    `options=json.no-string-conversion` is set, and which one you get has
    varied. Accept both rather than depending on it."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "yes", "1")


def _diagnose(stderr, role):
    """Name the actual cause instead of listing every possible one.

    These three failures look identical in a test summary and have nothing to
    do with each other. The first version of this printed the mgmt_prefixes
    explanation for all of them, which sent a malformed key file (a local
    problem, fixable in ten seconds) off to be investigated as a router
    firewall question.
    """
    err = (stderr or "").lower()

    if "error in libcrypto" in err or "invalid format" in err:
        return (
            "THE KEY FILE IS MALFORMED -- this is not an authorization or "
            "network problem. OpenSSH could not parse the private key at all, "
            "so it never offered one.\n"
            "  Almost always a MISSING TRAILING NEWLINE on the SSH_PRIVATE_KEY "
            "CI variable, or CRLF line endings from a copy-paste. Re-paste it "
            "with `cat ~/.ssh/<key> | pbcopy` (or `xclip`), which keeps the "
            "final newline that selecting the text by hand drops.\n"
            "  Verify locally with: ssh-keygen -y -f <the key file>")

    if "permission denied" in err:
        return (
            "The key was offered and REJECTED. The account exists or the "
            "server would have failed differently, so this is the key not "
            "being authorised for that user on THIS router.\n"
            "  A router that has not been deployed since `automation.keys` was "
            "added does not have it yet -- deploy it, or seed the account from "
            "a workstation that already has access.")

    if "timed out" in err or "no route to host" in err or "refused" in err:
        base = (
            "The TCP connection never completed -- nothing was rejected, "
            "nothing answered. This is reachability or a source filter, NOT "
            "the key.\n")
        if role in ("br", "sr"):
            return base + (
                "  SSH is bound to mgmt_prefixes in the template, so the most "
                "likely cause is the control node's source address not being "
                "in that list. Check what this host actually egresses as "
                "toward that address, and check for an outbound TCP/22 rule "
                "between them.")
        return base + (
            "  An edge router is reached on its TRANSIT address, which the "
            "input chain accepts by interface ahead of every source filter -- "
            "so mgmt_prefixes is NOT the cause here. Suspect reachability to "
            "the transit segment itself.")

    return (
        "Unrecognised ssh failure. Read the stderr above; it is the whole "
        "story, and nothing below this line would add to it.")


class ProbeError(AssertionError):
    """A probe couldn't be taken. Deliberately its own type: this is a tooling
    failure, and reporting it as a network failure is how a gate loses the
    trust that makes it worth having."""


class Router:
    """One router, over SSH."""

    def __init__(self, fqdn, host, user, port=22, role=None, timeout=60):
        self.fqdn = fqdn
        self.host = host
        self.user = user
        self.port = port
        self.role = role
        self.timeout = timeout
        # Keyed on the claim list, not a single slot. The fleet-wide tests ask
        # every router for a probe with NO claims; caching that against a bare
        # attribute meant an edge router's later request for its customer
        # sections got the earlier, claim-free answer back. And the claim
        # assertion then failed with a KeyError on a healthy router.
        self._probes = {}

    def __repr__(self):
        return f"<Router {self.fqdn} ({self.role}) at {self.host}>"

    # ---- transport ---------------------------------------------------
    def run(self, command, timeout=None):
        """One RouterOS command. Returns stdout; raises on transport failure.

        `command` goes to ssh as a SINGLE argv element, so no shell on either
        side ever sees it: RouterOS's own quoting is the only quoting there
        is, and nothing here needs escaping for a shell that isn't involved.
        """
        argv = (["ssh", "-p", str(self.port)] + SSH_OPTS
                + [f"{self.user}@{self.host}", command])
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout or self.timeout)
        if proc.returncode != 0:
            raise ProbeError(
                f"ssh to {self.fqdn} ({self.host}) failed rc={proc.returncode}\n"
                f"  command: {command[:120]}...\n"
                f"  stderr:  {proc.stderr.strip()}\n"
                f"{_diagnose(proc.stderr, self.role)}")
        return proc.stdout

    # ---- state -------------------------------------------------------
    def probe(self, claims=(), refresh=False):
        """The whole snapshot, in one round trip. Cached per claim set."""
        key = tuple(claims)
        if key not in self._probes or refresh:
            raw = self.run(build_probe(claims))
            parsed = parse_probe(raw)
            if not parsed:
                raise ProbeError(
                    f"{self.fqdn} returned nothing recognisable. Either "
                    f"`:serialize` is unavailable (RouterOS older than 7.13) "
                    f"or the SSH user cannot read these menus.\n"
                    f"Raw output:\n{raw[:2000]}")
            self._probes[key] = parsed
        return self._probes[key]

    def section(self, name, claims=()):
        """One section, with the tooling-vs-network distinction enforced."""
        value = self.probe(claims).get(name)
        if value is None:
            raise ProbeError(
                f"{self.fqdn}: probe returned no '{name}' section at all. "
                f"Sections present: {sorted(self.probe(claims))}")
        if value == ERROR:
            raise ProbeError(
                f"{self.fqdn}: the '{name}' probe ERRORED on the router. This "
                f"is almost certainly a RouterOS property rename, NOT a "
                f"network fault -- do not read it as one. Check by hand:\n"
                f"  ssh {self.user}@{self.host} '/{name} print as-value'\n"
                f"and update build_probe() in tests/functional/routeros.py.")
        return value

    # ---- the data plane ----------------------------------------------
    def ping(self, target, src=None, count=3, size=None, df=False):
        """Successful replies, as an int.

        `/ping` returns the number of packets that came back, which is exactly
        what we want and avoids parsing the table it would otherwise print."""
        cmd = f"/ping {target} count={count}"
        if src:
            cmd += f" src-address={src}"
        if size:
            cmd += f" size={size}"
        if df:
            cmd += " do-not-fragment"
        out = self.run(f":put [{cmd}]", timeout=max(self.timeout, count * 4 + 20))
        for line in reversed(out.strip().splitlines()):
            line = line.strip()
            if line.isdigit():
                return int(line)
        return 0
