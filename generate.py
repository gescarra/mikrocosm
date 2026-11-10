#!/usr/bin/env python3
"""
AS64500 RouterOS config generator.

  topology.yml  (commit)  ->  derived topology  ->  out/*.rsc  (NEVER commit)
       keys.json (NEVER commit, generated once, reused forever)

The whole point: br1's peer stanza needs er1's PUBLIC key and vice versa.
That cross-reference graph is why a flat .env + envsubst can't do this job.
(I tried. The .env lost.)

Usage:
    python3 generate.py                 # generate (keys reused if present)
    python3 generate.py --rotate-keys   # DESTRUCTIVE: new keys, all peers break
    python3 generate.py --check         # validate only, render nothing

CI-facing (see docs/netdevops.md):
    python3 generate.py --check --json  # machine-readable validation result
    python3 generate.py --pin out/pin.json      # freeze build-time fetches
    python3 generate.py --use-pin out/pin.json  # re-render from a frozen build

    --topology / --keys / --out relocate the three paths this reads and writes,
    so a test can render a mutated fleet into a temp dir without going anywhere
    near the real keystore. Nothing about the defaults changes.
"""

import argparse
import base64
import csv
import hashlib
import ipaddress
import itertools
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import urllib.request

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

import emit

ROOT = pathlib.Path(__file__).resolve().parent
TOPOLOGY = ROOT / "topology.yml"
KEYSTORE = ROOT / "keys.json"
OUTDIR = ROOT / "out"


# ---------------------------------------------------------------------
#  WireGuard keys
# ---------------------------------------------------------------------
def _genkey_wg():
    """Use the canonical wg(8) tool if available."""
    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True,
                          check=True).stdout.strip()
    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True,
                         text=True, check=True).stdout.strip()
    return priv, pub


def _genkey_py():
    """Fallback: X25519 with the same clamping wg genkey applies."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser

    raw = bytearray(secrets.token_bytes(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    k = X25519PrivateKey.from_private_bytes(bytes(raw))
    priv = base64.b64encode(bytes(raw)).decode()
    pub = base64.b64encode(
        k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    ).decode()
    return priv, pub


GENKEY = _genkey_wg if shutil.which("wg") else _genkey_py


def load_keystore(rotate=False):
    if KEYSTORE.exists() and not rotate:
        return json.loads(KEYSTORE.read_text())
    if rotate and KEYSTORE.exists():
        backup = KEYSTORE.with_suffix(".json.bak")
        shutil.copy(KEYSTORE, backup)
        # You asked for this. The backup is the only kindness left to offer.
        print(f"!! rotating keys; previous keystore saved to {backup.name}",
              file=sys.stderr)
    return {}


def _rel(path):
    """Display path: repo-relative when it's under the repo, absolute when it
    isn't. --out can point anywhere, and relative_to() raises rather than
    falling back."""
    try:
        return path.relative_to(ROOT)
    except ValueError:
        return path


def save_keystore(ks):
    KEYSTORE.write_text(json.dumps(ks, indent=2, sort_keys=True) + "\n")
    os.chmod(KEYSTORE, 0o600)


def key_for(ks, ident):
    """Idempotent: an existing key is NEVER regenerated. On purpose.
    Re-running the generator must not silently break every peer on the network."""
    # Rule one of keys: never regenerate. Rule two: see rule one. Rule three:
    # en serio.
    if ident not in ks:
        priv, pub = GENKEY()
        ks[ident] = {"private": priv, "public": pub}
    return ks[ident]


def _genpsk_wg():
    """Use wg(8) genpsk if available."""
    return subprocess.run(["wg", "genpsk"], capture_output=True, text=True,
                          check=True).stdout.strip()


def _genpsk_py():
    """Fallback: 32 random bytes, base64-encoded (same as wg genpsk)."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


GENPSK = _genpsk_wg if shutil.which("wg") else _genpsk_py


def psk_for(ks, ident):
    """Idempotent PSK for a tunnel. Keyed by a canonical tunnel identifier so
    both ends of the link resolve to the same PSK."""
    if ident not in ks:
        ks[ident] = {"psk": GENPSK()}
    elif "psk" not in ks[ident]:
        ks[ident]["psk"] = GENPSK()
    return ks[ident]["psk"]


def user_password_for(ks, user):
    """Idempotent throwaway password for a RouterOS account nobody logs into
    with a password.

    `/user/add` REQUIRES a password argument. Omitting it aborts the import
    with `missing value(s) of argument(s) password (/user/add)`, and because
    the apply path is reset-configuration + run-after-reset that means a wiped
    router with no firewall, no tunnels and no BGP. Measured on 7.24.

    So a password has to be supplied, and the question is which. `password=""`
    satisfies the parser and is fine while the account has an SSH key, because
    RouterOS refuses password auth for a user that has one. But the key import
    is the NEXT line, and if it fails the router is left holding a full-access
    account with a blank password on a public WAN. A random 32-char value costs
    nothing and removes that window entirely; nobody ever types it, and it's
    stable across rebuilds like every other secret here.

    Same alphabet reasoning as the SNMP passphrases below: token_urlsafe can
    never emit a `"`, `\\` or `$` that would break out of the quoting in the
    .rsc this lands in."""
    # A password nobody knows, for a user nobody types it for. It sounds like
    # security theatre. It's the one act in the play that actually matters.
    ident = f"userpw:{user}"
    e = ks.setdefault(ident, {})
    if not e.get("password"):
        e["password"] = secrets.token_urlsafe(24)
    return e["password"]


def snmp_secrets_for(ks, user):
    """Idempotent SNMPv3 auth + privacy passphrases for the fleet's one v3 user.

    Same contract as the WireGuard keys above, for the same reason: generated
    once, reused forever, replaced only by --rotate-keys. A silent rotation
    here doesn't fail loudly. It fails as every host in Zabbix going
    unreachable at once, on a day nobody touched the network.

    32 URL-safe characters (RouterOS wants 8 minimum). The alphabet is the
    point of using token_urlsafe: A-Za-z0-9_- can never contain the `"`, `\\`
    or `$` that would break out of the quoting in the .rsc these get rendered
    into, and breaking out of a quote in a file applied by /import after
    reset-configuration isn't a syntax error, it's a router."""
    ident = f"snmp:{user}"
    e = ks.setdefault(ident, {})
    for k in ("auth", "priv"):
        if not e.get(k):
            e[k] = secrets.token_urlsafe(24)
    return e


def bgp_md5_for(ks, peer_name):
    """Idempotent TCP-MD5 key for one external BGP session.

    This exists to stop `peers:` repeating the mistake `bgp_auth_key` already
    makes. topology.yml's own header says it holds no secrets; the two upstream
    MD5 keys sit in it in plaintext anyway, in a COMMITTED file. A peer entry
    therefore carries `md5: true`, a boolean, and the value is generated here
    into the keystore that's already gitignored and mode 600.

    Same alphabet reasoning as the passphrases above: token_urlsafe can never
    emit a `"`, `\\` or `$` that would break out of the quoting in the .rsc
    this is rendered into.

    The far end needs this value, and getting it to them is deliberately a
    separate manual step (`generate.py --show-peer-secrets <name>`) so an
    ordinary build never puts a third party's session key on stdout or in a CI
    job log."""
    ident = f"bgp-md5:{peer_name}"
    e = ks.setdefault(ident, {})
    if not e.get("key"):
        e["key"] = secrets.token_urlsafe(24)
    return e["key"]


# ---------------------------------------------------------------------
#  Derived topology
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
#  RouterOS time literals
# ---------------------------------------------------------------------
_TIME_UNITS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000}
_TIME_RE = re.compile(r"(\d+)(ms|s|m|h)")


def _time_ms(v):
    """Parse a RouterOS time literal ('200ms', '1s', '1s500ms') to milliseconds.

    Returns None if it's not one. The caller reports that as a validation
    error rather than shipping a value RouterOS will reject at import time,
    which on these boxes means a half-applied config after a reset."""
    s = str(v).strip().lower()
    # The literal must be ENTIRELY unit-suffixed numbers. A bare "200" is
    # rejected rather than assumed to be milliseconds: RouterOS reads an
    # unsuffixed number as SECONDS, so guessing here would be a 1000x error.
    # 200 seconds of BFD detect time: technically still "sub-hour failover".
    if not s or "".join(m.group(0) for m in _TIME_RE.finditer(s)) != s:
        return None
    return sum(int(n) * _TIME_UNITS[u] for n, u in _TIME_RE.findall(s))


# ---------------------------------------------------------------------
#  Traffic engineering: two independent axes, one per-BR block
# ---------------------------------------------------------------------
#  te.prepend    INGRESS. Extra copies of our own ASN on the aggregate as it
#                leaves THIS BR toward its upstream, so the DFZ prefers the
#                other one. Applied in ebgp-out-upstream on the BR itself.
#  te.local_pref EGRESS. The local-pref an ER or site stamps on the default
#                it hears FROM this BR, so the inside of the AS prefers it.
#                Applied in ibgp-in-lp<N> on the receiver, never here.
#
#  They are independent on purpose: set only prepend for ingress-only TE, only
#  local_pref for egress-only, both for both, neither (omit `te:`) for plain
#  ECMP multihoming. See docs/traffic-engineering.md.
#
#  This runs for EVERY router, not just BRs: er.rsc.j2 and site.rsc.j2 read
#  ibgp_in_chain off every peer in the mesh under StrictUndefined, and an ER
#  originates no default so there's nothing on it to weight.
TE_KEYS = ("prepend", "local_pref")

# RouterOS user-group policies. Listed so a typo is caught at build time: an
# unknown policy name makes /user/group/add fail, and that line runs on a box
# reset-configuration has already wiped.
# Read off the builtin groups of a live 7.24 router
# (`/user/group print`), not from documentation: an unknown policy name makes
# /user/group/add fail, and that line runs on a box reset-configuration has
# already wiped. If a future release adds one, this list is where to add it.
ROS_POLICIES = frozenset({
    "local", "telnet", "ssh", "ftp", "reboot", "read", "write", "policy",
    "test", "winbox", "password", "web", "sniff", "sensitive", "api",
    "romon", "rest-api",
})


# Stock /queue/type names, read off a live 7.24.1 (`/queue/export verbose`) and
# not from documentation: same sourcing rule as ROS_POLICIES above. wan_queue
# must name one of these or the custom type wan_aqm creates: the value goes
# verbatim into `/queue/interface set ... queue=`, and a name that doesn't
# resolve aborts the import on an already-wiped box.
ROS_QUEUE_TYPES = frozenset({
    "default", "default-small", "ethernet-default", "wireless-default",
    "synchronous-default", "hotspot-default", "pcq-upload-default",
    "pcq-download-default", "only-hardware-queue",
    "multi-queue-ethernet-default",
})

# Queue KINDS. Listed only so validate() can tell someone who wrote a kind where
# a type name belongs: `wan_queue: fq-codel` is the exact mistake, and without
# this the error would say "unknown name" and leave them guessing why.
ROS_QUEUE_KINDS = frozenset({
    "pfifo", "bfifo", "sfq", "red", "pcq", "none", "mq-pfifo", "fq-codel",
    "cake", "codel",
})


# ---------------------------------------------------------------------
#  External peering: three realms, one construct
# ---------------------------------------------------------------------
#  A peer is a third party. NOT a member of AS64500, NOT in the iBGP mesh,
#  NOT in OSPF, NOT in the `tunnels` interface list. That list is a
#  full-trust input grant (see the input chain in br.rsc.j2). A peer
#  terminates on a BORDER ROUTER only.
#
#  The realm decides WHERE THE ROUTES LAND, which is the only thing that
#  really differs between the three:
#
#    internet  the main table, via the existing `core` instance. Real traffic
#              follows these routes. Settlement-free: we announce our own
#              aggregates and accept that peer's cone, nothing more.
#    3p        a bilateral interconnect. The SAME exchange as `internet`.
#              Our real ASN, our real aggregates. But landed in its own
#              table, so a 3p peer can't influence how this AS forwards a
#              production packet. Announcements carry NO_EXPORT by default.
#    dn42      the DN42 overlay: its own ASN, its own space, its own table.
#
#  The tunnel derivation, keystore identities, port ladder, filter-chain
#  shape and max-prefix arithmetic are IDENTICAL across all three. Only the
#  per-realm constants differ, which is why this is one list with a
#  discriminator and not three parallel constructs that would drift apart.
PEER_REALMS = frozenset({"internet", "3p", "dn42"})

# Realms whose routes live in a VRF rather than the main table. `internet` is
# deliberately absent: its whole purpose is to affect production forwarding.
PEER_VRF_REALMS = frozenset({"3p", "dn42"})

# Transports. WireGuard is the default and the only one that traverses NAT;
# GRE is available because both BRs have public static addresses, which is the
# case docs/wireguard.md's rejection of GRE was never about.
PEER_TRANSPORTS = frozenset({"wireguard", "gre", "gre6"})

# DN42's registry-allocated ranges. A peer or a local prefix outside these is
# not a DN42 object, and accepting one would put non-DN42 space in the DN42
# table under DN42's filters.
DN42_ASN_MIN, DN42_ASN_MAX = 4242420000, 4242429999
DN42_V4 = "172.20.0.0/14"
DN42_V6 = "fd00::/8"

# Private ASN ranges (RFC 6996). An `internet` peer in one of these is
# refused: a settlement-free peer speaks a registered ASN, and a private one
# carries paths nobody outside this AS can interpret.
PRIVATE_ASN_RANGES = ((64512, 65534), (4200000000, 4294967294))

# Peer slots. index drives the WireGuard listen port and the /127 offset, the
# same way a site's index does. PEER_BR_SLOTS is how many BRs a single peer
# can be terminated on, which is what sizes the /127 arithmetic.
PEER_PORT_BASE = 52100
PEER_BR_SLOTS = 2
PEER_INDEX_MAX = 49          # 52100+49*2 stays clear of nothing in particular,
                             # but a bounded index keeps the port map readable
                             # and the /60 of /127s comfortably sufficient.

# Prefix-length ceilings for what a peer may advertise, per family. NOT the
# customer values (32/64 in build_claims): those describe a firewall carving up
# space we delegated to it, where a /32 VIP is the point. These are the
# conventional DFZ acceptance limits: anything longer isn't a route the rest
# of the internet would carry either, so accepting it buys nothing and costs
# table.
PEER_DELEG_MAX = {4: 24, 6: 48}

# Interface-name charset. `name` becomes a RouterOS interface name, a filter
# chain name fragment, a BGP session name and half a keystore identity. A name
# that's legal YAML and illegal to RouterOS aborts the import on a box
# reset-configuration has already wiped.
PEER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,11}$")


def _derive_te(r):
    te = r.get("te") or {}
    r["te_prepend"] = te.get("prepend") or 0
    r["te_local_pref"] = te.get("local_pref")
    # The chain name carries the VALUE, not the peer name: two BRs at the same
    # local-pref share one chain. Same reasoning as ibgp_out_class. A class,
    # not a per-peer copy of identical rules to keep in step. `None` keeps the
    # bare `ibgp-in` this file has always emitted, so a topology with no TE
    # renders the chain it used to.
    lp = r["te_local_pref"]
    r["ibgp_in_chain"] = f"ibgp-in-lp{lp}" if lp is not None else "ibgp-in"
    r["ibgp6_in_chain"] = f"ibgp6-in-lp{lp}" if lp is not None else "ibgp6-in"


def build(topo, ks):
    net = ipaddress.ip_network(topo["prefix"])
    base = int(net.network_address)

    def ip(n):
        return str(ipaddress.ip_address(base + n))

    # ---- IPv6: the same arithmetic, a different base ------------------
    # Every offset formula below is the v4 one UNCHANGED. A /127 consumes
    # two addresses exactly as a /31 does, so the index math transposes
    # without modification. Only the block base differs. This is why the v6
    # blocks were laid out the way they were; see docs/addressing-v6.md.
    v6 = bool(topo.get("prefix_v6"))

    def ip6(block, n):
        b = ipaddress.ip_network(topo["blocks_v6"][block])
        return str(ipaddress.ip_address(int(b.network_address) + n))

    brs = topo["border_routers"]
    ers = topo["edge_routers"]

    # Route distances. Change one and things break. See validate().
    #   eBGP-learned default  20   (RouterOS builtin)
    #   provider default      30   <- must BEAT iBGP, or a BR silently egresses
    #                                 through a sibling's transit and gets its
    #                                 own-sourced packets dropped at BCP38.
    #   iBGP                 200   (RouterOS builtin)
    #   anchor / loop guard  254
    topo.setdefault("provider_default_distance", 30)

    # BGP ECMP. Without it an ER holding two IDENTICAL defaults. Same
    # local-pref, same (empty) AS_PATH, same origin, and the same IGP metric,
    # because both BR loopbacks sit behind the one tun-wan1. Installs ONE of
    # them and the br1-vs-br2 choice falls to a router-id tie-break. That's a
    # pinned egress nobody chose.
    #
    # It's a COUNT, not a switch: /routing/bgp/instance multipath is typed
    # `num` ("install the specified number of ECMP routes"). `multipath=yes` is
    # a type error that ABORTS the import. And since the deploy path is
    # reset-configuration + run-after-reset, aborting means every /routing/bgp
    # object after that line never gets created and the router comes back with
    # no BGP at all. Default OFF for that reason: verify the property on YOUR
    # RouterOS version before turning it on. See docs/traffic-engineering.md.
    topo.setdefault("bgp_multipath", False)

    # BR WAN interface queue. See the long note in topology.yml: RouterOS
    # defaults ethernet to only-hardware-queue, which is right on real hardware
    # and wrong on an oversubscribed CHR guest, where it removes the shock
    # absorber in front of a virtio ring that stalls whenever the host
    # deschedules the vhost thread. Measured 3x on br1.ord1 at unchanged CPU.
    #
    # Resolved PER BR so two boxes on different providers can be measured
    # against each other without a second global.
    topo.setdefault("wan_queue", "virtual")
    aqm = topo.setdefault("wan_aqm", {})
    aqm.setdefault("name", "virtual")
    aqm.setdefault("target", "5ms")
    aqm.setdefault("interval", "100ms")
    aqm.setdefault("limit", 10240)
    aqm.setdefault("flows", 1024)
    aqm.setdefault("quantum", 1514)
    aqm.setdefault("memlimit", "32.0MiB")
    aqm.setdefault("ecn", True)
    # RouterOS wants yes/no, and PyYAML has already turned `yes` into a bool.
    aqm["ecn_ros"] = "yes" if aqm["ecn"] else "no"
    for r in topo["border_routers"]:
        r["wan_queue"] = r.get("wan_queue") or topo["wan_queue"]
        # Only emit the /queue/type add when this BR actually selects it. A BR
        # left on a stock type gets no dead type definition it never references.
        r["wan_aqm_create"] = (r["wan_queue"] == aqm["name"])

    # The v6 MSS clamp is DERIVED, and it's NOT the v4 clamp. MSS is the
    # payload left after the headers the tunnel has to carry:
    #     v4 inner:  wg_mtu - 20 (IPv4) - 20 (TCP) = wg_mtu - 40
    #     v6 inner:  wg_mtu - 40 (IPv6) - 20 (TCP) = wg_mtu - 60
    # Reusing 40 for v6 puts every large segment 20 bytes over the tunnel MTU
    # and makes the flow depend on ICMPv6 Packet Too Big. The exact dependency
    # the clamp exists to remove, and v6 routers may not fragment as a fallback.
    # Listing it in topology.yml is allowed but pointless; validate() rejects any
    # value other than this one rather than letting a hand-edit win silently.
    topo.setdefault("mss_clamp_v6", topo["wg_mtu"] - 60)

    # Loopback6 spells the router's role in hex: br -> ::b1, ::b2 / er -> ::e1,
    # ::e2. Still pure index arithmetic, but a traceroute names its own hops.
    # ibgp_out_class picks which er->peer output chain an ER uses. It's NOT the
    # role: a remote site is treated exactly like a BR on output (it gets the
    # /25 aggregate and none of the customer more-specifics), so giving it its
    # own chain would only be a second copy of ibgp-out-br to keep in step.
    for r in brs:
        r["role"] = "br"
        r["ibgp_out_class"] = "br"
        r["loopback"] = ip(240 + r["index"])
        if v6:
            r["loopback6"] = ip6("loopbacks", 0xB0 + r["index"])
        r["fqdn"] = f"{r['name']}.{r['site']}"
        _derive_te(r)
    for r in ers:
        r["role"] = "er"
        r["ibgp_out_class"] = "er"
        r["loopback"] = ip(248 + r["index"])
        if v6:
            r["loopback6"] = ip6("loopbacks", 0xE0 + r["index"])
        r["fqdn"] = f"{r['name']}.{r['site']}"
        _derive_te(r)

    wan_ids = ["wan1", "wan2"]

    # The BR's LISTEN port is what tells the ER which WAN a tunnel belongs to.
    # 518xx = wan1, 519xx = wan2 (docs/wireguard.md). er.rsc.j2 matches on that
    # port TWICE: the mangle mark that pins the outer flow to a WAN, and the
    # srcnat that makes the source address agree with it. So the mapping is
    # derived once, here, and handed to the template as a ready-made range.
    # Restating 51820/51920 in a template is how the two halves drift apart.
    #
    # Ten ports wide per WAN: one per ER, up to nine, with no renumbering.
    wan_port_base = {wid: 51800 + (w - 1) * 100 + 20
                     for w, wid in enumerate(wan_ids, start=1)}

    # Remote sites are the third tunnel class, so they get the next hundred:
    # 520xx. Same contract as the WAN bases above. The BR listens here, and
    # the site matches THIS range in both the mangle mark and the srcnat that
    # pins its outer flows to its WAN. Derived once, never restated.
    site_port_base = 52020

    # ---- BR <-> ER tunnels -------------------------------------------
    # /31 base = 192 + (br-1)*8 + (er-1)*4 + (wan-1)*2   [matches doc §5]
    br_er = []
    for br in brs:
        for er in ers:
            for w, wid in enumerate(wan_ids, start=1):
                # off6 is the SAME expression with the v4 base (192) removed.
                # The /127 lands at the identical index inside its own block.
                off6 = (br["index"] - 1) * 8 + (er["index"] - 1) * 4 + (w - 1) * 2
                off = 192 + off6
                br_if = f"wg-{er['name']}-{wid}"
                er_if = f"wg-{br['name']}-{wid}"
                # PSK keyed by canonical tunnel name (shared by both ends)
                psk_id = f"psk:{br['name']}-{er['name']}-{wid}"
                br_er.append({
                    "br": br["name"], "er": er["name"], "wan": wid,
                    "br_if": br_if, "er_if": er_if,
                    "br_ip": ip(off), "er_ip": ip(off + 1),
                    "br_ip6": ip6("br_er_p2p", off6) if v6 else None,
                    "er_ip6": ip6("br_er_p2p", off6 + 1) if v6 else None,
                    # BR listen port encodes the ER's WAN: 518xx=wan1, 519xx=wan2
                    "br_port": wan_port_base[wid] + er["index"],
                    "er_port": 51000 + (w - 1) * 100 + br["index"],
                    "br_key": key_for(ks, f"{br['fqdn']}:{br_if}"),
                    "er_key": key_for(ks, f"{er['fqdn']}:{er_if}"),
                    "psk": psk_for(ks, psk_id),
                })

    # ---- BR <-> BR backbone ------------------------------------------
    bb = []
    for i, (a, b) in enumerate(itertools.combinations(sorted(brs, key=lambda r: r["index"]), 2)):
        off = 160 + i * 2
        a_if, b_if = f"wg-{b['name']}", f"wg-{a['name']}"
        # PSK keyed by canonical pair (a.index < b.index by construction)
        psk_id = f"psk:{a['name']}-{b['name']}-backbone"
        bb.append({
            "a": a["name"], "b": b["name"],
            "a_if": a_if, "b_if": b_if,
            "a_ip": ip(off), "b_ip": ip(off + 1),
            "a_ip6": ip6("backbone", i * 2) if v6 else None,
            "b_ip6": ip6("backbone", i * 2 + 1) if v6 else None,
            # on br(x), the interface facing br(y) listens on 51100+y
            "a_port": 51100 + b["index"],
            "b_port": 51100 + a["index"],
            "a_endpoint": b["wan_address"], "b_endpoint": a["wan_address"],
            "a_key": key_for(ks, f"{a['fqdn']}:{a_if}"),
            "b_key": key_for(ks, f"{b['fqdn']}:{b_if}"),
            "psk": psk_for(ks, psk_id),
        })

    # ---- remote sites -------------------------------------------------
    # A remote site is ONE consolidated edge router with a tunnel to EVERY BR.
    # Deliberately not pinned to a primary/backup pair: the connectivity a site
    # forms is the same connectivity an ER forms, so it gets the same treatment:
    # full iBGP mesh, OSPF cost decides the path, losing one BR costs a
    # reconvergence and nothing else. There's no primary_br/backup_br here and
    # there should never be one.
    #
    # THE V4 BUDGET IS THE BINDING CONSTRAINT, and it's small. blocks.site_p2p
    # is a /28: eight /31s, and that's every site tunnel this AS can address in
    # v4. SITE_BR_SLOTS reserves a FIXED run per site so adding site2 can never
    # renumber site1's live links: at 2 slots that's 4 sites x 2 BRs, exactly
    # the four /29s site_deleg holds. A third BR overflows the block; validate()
    # refuses to render and says what the options are.
    SITE_BR_SLOTS = 2
    sites = topo.get("sites") or []
    topo["sites"] = sites

    # Offsets are taken from the blocks rather than restated as literals (the
    # 160/192 above predate them). off6 is then the SAME expression with the v4
    # base removed, exactly as it's for br_er.
    site_deleg_off = int(ipaddress.ip_network(
        topo["blocks"]["site_deleg"]).network_address) - base
    site_p2p_off = int(ipaddress.ip_network(
        topo["blocks"]["site_p2p"]).network_address) - base
    alloc6 = ipaddress.ip_network(topo["prefix_v6"]) if v6 else None

    site_br = []
    for s in sites:
        s["role"] = "sr"
        s["ibgp_out_class"] = "br"
        s["derive_errors"] = []
        _derive_te(s)
        s["router"] = s.get("router", "sr1")
        s["fqdn"] = f"{s['router']}.{s.get('name', '?')}"

        # Bounds FIRST, and hard: every formula below is index arithmetic on a
        # /24, so a bad index doesn't produce a wrong config. It produces an
        # exception, or an address in somebody else's network. A site that fails
        # here is left underived and validate() reports it; nothing renders.
        if not s.get("name") or not isinstance(s["name"], str):
            s["derive_errors"].append(
                f"name={s.get('name')!r} must be a short site code string. It "
                f"is the DNS label, the interface name on every BR "
                f"(wg-<name>), and half the keystore identity.")
            continue
        i = s.get("index")
        if not isinstance(i, int) or isinstance(i, bool) or not (1 <= i <= 9):
            s["derive_errors"].append(
                f"index={s.get('index')!r} must be an int in 1..9. It drives the "
                f"loopback (.244+index), the /29 delegation, the WireGuard "
                f"listen port ({site_port_base}+index) and the tunnel /31s -- "
                f"every one of those is a fixed slot, which is what lets a new "
                f"site be added without renumbering an existing one. Indexes are "
                f"allocated sequentially and NEVER reused.")
            continue

        s["loopback"] = ip(244 + i)
        if v6:
            # ::51, ::52 ... alongside the BRs' ::b1 and the ERs' ::e1. 5 is the
            # only nibble that reads as an 's'.
            s["loopback6"] = ip6("loopbacks", 0x50 + i)

        # The delegation IS the site LAN. Attached, not routed onward. The
        # device takes the first usable address as the inside default gateway;
        # the remaining five are the site's, routed directly with no NAT.
        s["delegation"] = f"{ip(site_deleg_off + (i - 1) * 8)}/29"
        s["lan_gateway"] = ip(site_deleg_off + (i - 1) * 8 + 1)
        if v6:
            # One /48 per site (RFC 6177), allocated off the /40 with hdc at 01.
            # See docs/addressing-v6.md. The LAN is the first /64 of it and
            # the device is ::1; the rest of the /48 stays available without a
            # re-render of anything but this site.
            d48 = ipaddress.ip_address(int(alloc6.network_address) + ((1 + i) << 80))
            s["delegation6"] = f"{d48}/48"
            s["lan_net6"] = f"{d48}/64"
            s["lan_gateway6"] = str(ipaddress.ip_address(int(d48) + 1))

        # One WAN today. The shape is a list because a second one is a data
        # change, not a redesign: but see the /31 budget above before adding
        # one: a second WAN doubles this site's tunnel count.
        for w in s.get("wans") or []:
            w["wg_ports"] = f"{site_port_base}-{site_port_base + 9}"

        for br in brs:
            off6 = ((i - 1) * SITE_BR_SLOTS + (br["index"] - 1)) * 2
            off = site_p2p_off + off6
            br_if = f"wg-{s['name']}"
            site_if = f"wg-{br['name']}"
            psk_id = f"psk:{br['name']}-{s['name']}-site"
            site_br.append({
                "br": br["name"], "site": s["name"],
                "br_if": br_if, "site_if": site_if,
                "br_ip": ip(off), "site_ip": ip(off + 1),
                "br_ip6": ip6("site_p2p", off6) if v6 else None,
                "site_ip6": ip6("site_p2p", off6 + 1) if v6 else None,
                # 520xx is the site class, the way 518xx/519xx are the ER WANs.
                "br_port": site_port_base + i,
                "site_port": 51200 + br["index"],
                "br_key": key_for(ks, f"{br['fqdn']}:{br_if}"),
                "site_key": key_for(ks, f"{s['fqdn']}:{site_if}"),
                "psk": psk_for(ks, psk_id),
            })

    # ---- per-router views (this is what the templates consume) --------
    # link_class is what the interface lists, the OSPF templates and the BFD
    # entries key off (tun-wan1 / tun-wan2 / tun-bb / tun-site). It's a
    # separate field from `wan` because a site tunnel has no WAN id on the BR
    # side: the class is the site class, full stop.
    for br in brs:
        br["tunnels"] = []
        for t in br_er:
            if t["br"] != br["name"]:
                continue
            br["tunnels"].append({
                "iface": t["br_if"], "wan": t["wan"],
                "link_class": t["wan"],
                "listen_port": t["br_port"],
                "address": f"{t['br_ip']}/31",
                "address6": f"{t['br_ip6']}/127" if v6 else None,
                "private": t["br_key"]["private"],
                "peer_public": t["er_key"]["public"],   # <- the cross-reference
                "psk": t["psk"],
                "peer_router": t["er"],
                "peer_name": f"{t['er']} via {t['wan']}",
            })
        # Site tunnels are appended to the SAME list, not kept beside it: from
        # the BR's point of view a site is an ER that happens to have one WAN.
        # No endpoint: the site is behind a consumer NAT and always initiates.
        for t in site_br:
            if t["br"] != br["name"]:
                continue
            br["tunnels"].append({
                "iface": t["br_if"], "wan": None,
                "link_class": "site",
                "listen_port": t["br_port"],
                "address": f"{t['br_ip']}/31",
                "address6": f"{t['br_ip6']}/127" if v6 else None,
                "private": t["br_key"]["private"],
                "peer_public": t["site_key"]["public"],
                "psk": t["psk"],
                "peer_router": t["site"],
                "peer_name": t["site"],
            })
        br["backbone"] = []
        for l in bb:
            if l["a"] == br["name"]:
                me, peer = "a", "b"
            elif l["b"] == br["name"]:
                me, peer = "b", "a"
            else:
                continue
            br["backbone"].append({
                "iface": l[f"{me}_if"],
                "link_class": "backbone",
                "listen_port": l[f"{me}_port"],
                "address": f"{l[f'{me}_ip']}/31",
                "address6": f"{l[f'{me}_ip6']}/127" if v6 else None,
                "endpoint": l[f"{me}_endpoint"],
                "endpoint_port": l[f"{peer}_port"],
                "private": l[f"{me}_key"]["private"],
                "peer_public": l[f"{peer}_key"]["public"],
                "psk": l["psk"],
                "peer_router": l[peer],
            })

    for er in ers:
        # Each WAN carries the outer-port range of the tunnels that ride it,
        # off the same base as br_port above. An unknown id leaves wg_ports
        # absent rather than raising: validate() reports it, and rendering
        # never happens on a failed validate.
        # NOT named `base`: that's the /24's integer base address, closed over
        # by ip() further up. Rebinding it here would quietly corrupt every
        # address ip() derives after this loop.
        for wan in er["wans"]:
            pbase = wan_port_base.get(wan["id"])
            if pbase is not None:
                wan["wg_ports"] = f"{pbase}-{pbase + 9}"

        er["tunnels"] = []
        for t in br_er:
            if t["er"] != er["name"]:
                continue
            br = next(b for b in brs if b["name"] == t["br"])
            er["tunnels"].append({
                "iface": t["er_if"], "wan": t["wan"],
                "link_class": t["wan"],
                "listen_port": t["er_port"],
                "address": f"{t['er_ip']}/31",
                "address6": f"{t['er_ip6']}/127" if v6 else None,
                "endpoint": br["wan_address"],
                "endpoint_port": t["br_port"],
                "private": t["er_key"]["private"],
                "peer_public": t["br_key"]["public"],
                "psk": t["psk"],
                "peer_router": t["br"],
                "peer_name": f"{t['br']} via {t['wan']}",
            })

    # ---- remote-site per-router views ---------------------------------
    # The mirror image of the BR view above: this end carries the endpoint and
    # the keepalive, because the site is the one that dials.
    for s in sites:
        if s["derive_errors"]:
            continue
        s["tunnels"] = []
        for t in site_br:
            if t["site"] != s["name"]:
                continue
            br = next(b for b in brs if b["name"] == t["br"])
            s["tunnels"].append({
                "iface": t["site_if"], "wan": None,
                "link_class": "site",
                "listen_port": t["site_port"],
                "address": f"{t['site_ip']}/31",
                "address6": f"{t['site_ip6']}/127" if v6 else None,
                "endpoint": br["wan_address"],
                "endpoint_port": t["br_port"],
                "private": t["site_key"]["private"],
                "peer_public": t["br_key"]["public"],   # <- the cross-reference
                "psk": t["psk"],
                "peer_router": t["br"],
                "peer_name": t["br"],
            })

    # ---- sibling BR public IPs: the WireGuard-endpoint recursion guard ----
    # A tunnel's OUTER destination must never resolve through a route that
    # could point INTO a tunnel. Without these /32s, br2's route to br1's
    # public falls back to the default. And once br1 advertises a default
    # over the backbone, that default's next-hop IS br1, reached via the very
    # tunnel whose outer packets we're trying to route. It flaps forever.
    for br in brs:
        br["sibling_publics"] = [
            {"name": o["name"], "wan_address": o["wan_address"]}
            for o in brs if o["name"] != br["name"]
        ]

    # ---- external peers ------------------------------------------------
    # DELIBERATELY a separate collection from br["tunnels"]. Everything in
    # br["tunnels"] is trusted AS64500 infrastructure: it lands in the
    # `tunnels` interface list, which the input chain accepts wholesale, and
    # it feeds the OSPF interface-templates and the BFD menu. A third party
    # must inherit none of that, and keeping the two lists apart is what makes
    # "must not" a property of the data rather than a rule in seven loops.
    realms = _derive_realms(topo)
    peers = _derive_peers(topo, brs, ks, v6, realms)
    for br in brs:
        br["peers"] = [l for p in peers for l in p["links"]
                       if l["br"] == br["name"]]
        # The same recursion guard the sibling publics get, for the same
        # reason: and here the failure is likelier, because a peer can
        # advertise a prefix that covers its OWN tunnel endpoint. Accept that
        # route and the outer destination resolves through the tunnel it's
        # carrying: a permanent flap that looks like the far end's fault.
        br["peer_endpoint_pins"] = [
            {"name": l["peer"], "address": ep,
             "family": ipaddress.ip_address(ep).version}
            for l in br["peers"]
            for ep in [_peer_endpoint(peers, l["peer"])]
            if ep
        ]

    # ---- ER home-link addresses (v6) ---------------------------------
    # The v4 equivalents are still computed in the template by string surgery on
    # the last octet. That trick has no v6 analog, so these are derived here.
    # Which is where they belonged anyway.
    if v6:
        h = topo["home"]
        xc6_base = int(ipaddress.ip_network(h["xc_net_v6"], strict=False).network_address)
        for er in ers:
            er["xc_ip6"] = str(ipaddress.ip_address(xc6_base + er["index"] - 1))
            er["transit_ip6"] = h[f"transit_er{er['index']}_v6"]

    # iBGP is a FULL MESH: every router peers with every other. No RR.
    # Remote sites are members of AS64500 and join it. That's the whole
    # point of not pinning them to one BR. A site with no derived addressing is
    # left out; validate() will refuse the build before any of this renders.
    allr = brs + ers + [s for s in sites if not s["derive_errors"]]
    for r in allr:
        r["ibgp_peers"] = [o for o in allr if o["loopback"] != r["loopback"]]
        r["guard_peers"] = [o["loopback"] for o in allr if o["loopback"] != r["loopback"]]

    # ---- customer firewalls: eBGP peers, ER-LOCAL ONLY -----------------
    # Deliberately NOT added to ibgp_peers/guard_peers/the BR context: these are
    # eBGP customers in a private ASN, not members of AS64500. They peer over
    # the local transit L2 to each ER, so there are no tunnels and no keys.
    fws = topo.get("firewalls", []) or []
    for fw in fws:
        fw.setdefault("local_pref", None)
        # Per-firewall BFD: use-bfd=yes on THIS firewall's eBGP connections.
        # Per firewall rather than global because the far end is a box this AS
        # doesn't administer: see the note in topology.yml. Defaults off, so
        # a topology.yml written before this feature renders unchanged.
        fw["bfd"] = bool(fw.get("bfd"))
        # Optional. Selects a peer-config dialect; absent means we render the
        # ER end only, exactly as before. Normalised here so `UniFi` and
        # `unifi` are the same answer and validate() reports one spelling.
        fw["type"] = (str(fw["type"]).strip().lower()
                      if fw.get("type") is not None else None)
        fw["claims"], fw["claims6"], fw["claim_errors"] = build_claims(fw)
        # Inbound route limits = the most routes this firewall could legitimately
        # send, plus headroom. Counted PER FAMILY, because RouterOS limits them
        # separately (input.limit-process-routes-ipv4 / -ipv6): one shared number
        # would let a v6 flood consume the v4 budget. An explicit max_routes /
        # max_routes_v6 in topology.yml wins.
        if fw.get("max_routes") is None:
            fw["max_routes"] = sum(c["capacity"] for c in fw["claims"]) + 5
        if fw.get("max_routes_v6") is None:
            fw["max_routes_v6"] = sum(c["capacity"] for c in fw["claims6"]) + 5
        # The firewall's OWN config, built from the same claims. None unless it
        # declared a `type:`, and rendered only after validate() has passed.
        # So this may be derived from a topology that's about to be refused.
        fw["peer"] = build_peer_config(fw, ers, topo, v6)

    for er in ers:
        # every firewall peers with EVERY ER: a VIP claim must survive one ER
        er["firewalls"] = fws

    # the union, for the er->br output filter that denies the more-specifics (4b)
    cust_claims, cust_claims6 = [], []
    seen_claims = set()
    for fw in fws:
        for c in fw["claims"] + fw["claims6"]:
            if c["key"] not in seen_claims:
                seen_claims.add(c["key"])
                (cust_claims if c["family"] == 4 else cust_claims6).append(c)

    # ---- BFD ----------------------------------------------------------
    # Defaults are OFF for both switches, so a topology.yml written before BFD
    # existed renders byte-identical config. `detect_ms` is derived here and
    # only used to put a human-readable detection time in the rendered comment.
    # The routers are configured from interval + multiplier, never from it.
    bfd = topo.setdefault("bfd", {}) or {}
    topo["bfd"] = bfd
    bfd.setdefault("configure", False)
    bfd.setdefault("use_ospf", False)
    bfd.setdefault("links", {})
    # `customer` is the ER<->firewall transit segment and is deliberately NOT a
    # member of `links`: links mirrors ospf_cost, and that segment runs no OSPF.
    # Absent (the default) keeps the forbid-bfd entry and renders byte-identical
    # config, same as the two switches above.
    bfd.setdefault("customer", None)
    for spec in list((bfd["links"] or {}).values()) + [bfd["customer"]]:
        if isinstance(spec, dict) and "interval" in spec and "multiplier" in spec:
            ms = _time_ms(spec["interval"])
            if ms is not None and isinstance(spec["multiplier"], int):
                spec["detect_ms"] = ms * spec["multiplier"]

    # ---- origination mode ---------------------------------------------
    # What anchor-guard on the BRs treats as "a customer I can deliver to".
    #   anchor  ANY active customer prefix, however it's reached. The /25
    #           over a sibling BR's backbone counts. 10-minute timer.
    #   home    the home /25 (and /48) reached over one of THIS BR's own ER
    #           tunnels. Disabling the ERs' tunnels to a BR withdraws that BR.
    # Defaults are today's behaviour (anchor, scheduler commented out), so a
    # topology.yml written before this block renders the same executable lines.
    # validate() checks the values; nothing here coerces them.
    orig = topo.get("origination")
    if orig is None:
        orig = {}
    elif not isinstance(orig, dict):
        # `origination: home` is the obvious typo. Keep the value for
        # validate() to name rather than failing here on .setdefault.
        orig = {"mode": orig, "shape_error": True}
    topo["origination"] = orig
    orig.setdefault("mode", "anchor")
    orig.setdefault("arm_guard", False)
    # Ticks of the 10 s scheduler before a failed customer signal withdraws.
    # anchor: 60 (10 min): nobody in the AS can deliver, a DFZ-level event.
    # home:    6 (60 s)  : same as isolation: a sibling BR can take it now.
    orig["cust_ticks"] = 6 if orig["mode"] == "home" else 60
    for br in brs:
        # The ER tunnels only. A site tunnel isn't a path home, and the
        # backbone is precisely the path home mode must refuse to count.
        br["home_tunnels"] = [x["iface"] for x in br["tunnels"]
                              if x["link_class"] != "site"]

    # ---- automation login ---------------------------------------------
    # Absent -> nothing rendered at all, so a topology written before CI
    # existed still produces byte-identical config. The keys are STATIC and
    # committed, unlike ssh.keys_url which is fetched: a machine account does
    # not churn, so it doesn't need an endpoint, and not needing one means the
    # render stays offline and reviewable.
    auto = topo.get("automation")
    if isinstance(auto, dict) and auto:
        auto.setdefault("user", "automation")
        auto.setdefault("group", "automation")
        auto.setdefault("keys", [])
        auto.setdefault("policies", ["ssh", "ftp", "read", "write", "test",
                                     "reboot", "policy"])
        # Everything else, denied BY NAME. RouterOS does deny an unlisted
        # policy, so this isn't correcting a default. It's removing the gap
        # between "what we declared" and "what the group actually holds". br1
        # was found granting `sensitive` from a render that never asked for it,
        # while the other three denied it correctly, so the two had drifted and
        # nothing was checking. Rendering the complement makes the effective
        # group provably equal to the declared one.
        auto["denied"] = sorted(ROS_POLICIES - set(auto["policies"]))
        # Built here rather than in the template: it's a rule about what the
        # group MEANS, it deserves a unit test, and Jinja has no regex_replace
        # outside Ansible.
        auto["policy_string"] = ",".join(
            list(auto["policies"]) + ["!" + d for d in auto["denied"]])
        # /user/add refuses to run without one. See user_password_for().
        auto["password"] = user_password_for(ks, auto["user"])

    # The human account needs one for the same reason. It has never bitten
    # because keep-users=yes preserves that user across reset-configuration, so
    # the create branch only fires on a router that has never been deployed.
    # Which is exactly when you least want the import to abort.
    ssh_block = topo.get("ssh")
    if isinstance(ssh_block, dict) and ssh_block.get("user"):
        ssh_block["password"] = user_password_for(ks, ssh_block["user"])

    # ---- SNMPv3 -------------------------------------------------------
    # Absent block -> nothing rendered at all, so a topology.yml written before
    # this feature existed still produces byte-identical config. PRESENT but
    # enabled=false is a different, deliberate state: the agent is turned OFF
    # explicitly and the default `public` community is neutralised, which is a
    # hardening step that stands on its own.
    #
    # The passphrases are pulled from the keystore HERE, next to the WireGuard
    # keys, and never from topology.yml. The file that promises it holds no
    # secrets isn't the place to put two of them.
    snmp = topo.get("snmp")
    if isinstance(snmp, dict) and snmp:
        snmp.setdefault("enabled", False)
        snmp.setdefault("user", "zabbix")
        snmp.setdefault("contact", "")
        snmp.setdefault("sources", [])
        # SHA1 + AES: the strongest pair MikroTik documents for
        # /snmp/community. See the note in topology.yml before raising either.
        snmp.setdefault("auth_protocol", "SHA1")
        snmp.setdefault("encryption_protocol", "AES")
        sec = snmp_secrets_for(ks, snmp["user"])
        snmp["auth_password"] = sec["auth"]
        snmp["priv_password"] = sec["priv"]

    # sysLocation, per router and DERIVED. A BR/ER carries its `site`, a
    # remote site router carries its own name. Set unconditionally (not only
    # when SNMP is on) because the templates read it under StrictUndefined.
    for r in brs + ers:
        r["snmp_location"] = r["site"]
    for r in sites:
        r["snmp_location"] = r.get("name", "?")

    # The DISTINCT local-pref values any BR carries. One ibgp-in-lp<N> chain
    # per value, emitted by every ER and site. Empty when no BR sets one, which
    # is what keeps a TE-less topology rendering the config it rendered before.
    ibgp_in_lps = sorted({r["te_local_pref"] for r in brs
                          if r["te_local_pref"] is not None})

    return {"brs": brs, "ers": ers, "sites": sites, "br_er": br_er,
            "site_br": site_br, "bb": bb, "ip": ip,
            "site_br_slots": SITE_BR_SLOTS,
            "firewalls": fws, "cust_claims": cust_claims,
            "cust_claims6": cust_claims6, "v6": v6,
            "ibgp_in_lps": ibgp_in_lps,
            "peers": peers, "realms": realms,
            "rpki": _derive_rpki(topo),
            "peer_br_slots": PEER_BR_SLOTS}


# ---------------------------------------------------------------------
#  Customer claims: allowed_vips and delegations, normalised
# ---------------------------------------------------------------------
#  A firewall may be granted space in two shapes, and they are NOT the same
#  trust decision:
#
#    allowed_vips: - 203.0.113.16/32     exact. This prefix, this length,
#                                          nothing else. Enumerated one by one.
#
#    delegations:  - prefix:  203.0.113.0/29
#                    max_len: 32           a BLOCK the firewall may carve up as
#                                          it likes, from the block itself down
#                                          to max_len. It's trusted with the
#                                          whole range, not with a list.
#
#  Both collapse to the same primitive (a prefix plus an accepted dst-len
#  RANGE) so everything downstream (the inbound security filter, the er->br
#  "stays home" filter, the home-anchor liveness guard) works on one shape and
#  never has to branch on which knob the operator used.
#  IPv6 uses the same two shapes (`allowed_vips_v6`, `delegations_v6`) and the
#  same primitive. Only two numbers differ, and both follow from a v6 LAN being
#  a /64: a delegation's max_len DEFAULTS to 64 and may not exceed it, because
#  SLAAC breaks on anything longer. A firewall that needs to advertise a single
#  service address advertises a /128, which is what allowed_vips_v6 is for.
#  So the two shapes still cover every legitimate case and nothing else.
def _make_claim(net, min_len, max_len, source):
    """One normalised grant: a prefix plus an accepted dst-len range.

    Shared by the customer grants (build_claims) and the external-peer cones
    (build_peer_claims) because the two must agree on what a grant MEANS. The
    `match` string is the security boundary in both cases (it's pasted
    verbatim into a RouterOS filter rule) so a divergence between the two
    callers would be a filter that accepts something the capacity arithmetic
    never budgeted for.
    """
    exact = (min_len == max_len == net.prefixlen)
    return {
        "prefix": str(net),
        "min_len": min_len,
        "max_len": max_len,
        "exact": exact,
        "source": source,
        "family": net.version,
        "key": f"{net}:{min_len}-{max_len}",
        # RouterOS routing-filter matcher. An exact claim keeps the `dst==`
        # form the enumerated VIPs have always used; a range claim uses
        # `dst in` plus explicit dst-len bounds. Both are usable verbatim in
        # an accept rule (cust-in) and a reject rule (ibgp-out-br).
        "match": (f"dst=={net} && dst-len=={net.prefixlen}" if exact else
                  f"dst in {net} && dst-len>={min_len} && dst-len<={max_len}"),
        # RouterOS /ip/route/find predicate for the home-anchor guard.
        "find": (f'dst-address="{net}"' if exact else f"dst-address in {net}"),
        # Dotted mask, for the `network <addr> mask <mask>` form FRR wants
        # in IPv4 (see the peer configs). None for v6, which has no such
        # form: there the prefix is written out whole.
        "netmask": str(net.netmask) if net.version == 4 else None,
        # Worst-case route count, for input.limit-process-routes-ipv4:
        # sum of 2^(l-min_len) for l in [min_len..max_len].
        "capacity": (1 if exact else 2 ** (max_len - min_len + 1) - 1),
    }


def build_claims(fw):
    """Normalise fw's allowed_vips + delegations into per-family claims lists.

    Returns (claims_v4, claims_v6, errors). Malformed entries land in `errors`
    rather than raising, so validate() can report every problem in the topology
    at once instead of dying on the first one.
    """
    out, errors = {4: [], 6: []}, []

    def add(net, min_len, max_len, source):
        out[net.version].append(_make_claim(net, min_len, max_len, source))

    # (vips key, delegations key, family, delegation max_len default+ceiling)
    for vk, dk, fam, deleg_max in (("allowed_vips",    "delegations",    4, 32),
                                   ("allowed_vips_v6", "delegations_v6", 6, 64)):
        for vip in fw.get(vk, []) or []:
            try:
                v = ipaddress.ip_network(vip, strict=False)
            except ValueError as e:
                errors.append(f"{vk} {vip!r} is not a valid prefix ({e})")
                continue
            if v.version != fam:
                errors.append(f"{vk} {vip!r} is an IPv{v.version} prefix; it "
                              f"belongs in {'allowed_vips' if v.version == 4 else 'allowed_vips_v6'}")
                continue
            add(v, v.prefixlen, v.prefixlen, "allowed_vips")

        for deleg in fw.get(dk, []) or []:
            if not isinstance(deleg, dict) or "prefix" not in deleg:
                errors.append(f"{dk} entry {deleg!r} must be a mapping with a "
                              f"'prefix' key (and optionally 'max_len')")
                continue
            try:
                p = ipaddress.ip_network(deleg["prefix"], strict=False)
            except ValueError as e:
                errors.append(f"{dk} prefix {deleg['prefix']!r} is not a "
                              f"valid prefix ({e})")
                continue
            if p.version != fam:
                errors.append(f"{dk} prefix {p} is an IPv{p.version} prefix; it "
                              f"belongs in {'delegations' if p.version == 4 else 'delegations_v6'}")
                continue
            # max_len defaults to the family ceiling: a delegation with no
            # explicit limit means "carve this block however you like", which is
            # the common case. For v6 that ceiling is 64, not 128. A customer
            # route longer than a /64 isn't a subnet, it's a host route, and
            # host routes are what allowed_vips_v6 exists to enumerate.
            max_len = deleg.get("max_len", deleg_max)
            if not isinstance(max_len, int) or not (p.prefixlen <= max_len <= deleg_max):
                errors.append(
                    f"{dk} {p}: max_len={max_len!r} must be an int in "
                    f"{p.prefixlen}..{deleg_max} (>= the delegation's own "
                    f"length, <= {deleg_max})")
                continue
            add(p, p.prefixlen, max_len, "delegations")

    if not out[4] and not out[6] and not errors:
        errors.append("has neither allowed_vips nor delegations (v4 or v6); it "
                      "would be granted nothing and every advertisement it sends "
                      "would be rejected. Give it space or remove it.")

    return out[4], out[6], errors


def build_peer_claims(peer):
    """Normalise an external peer's import.prefixes into per-family cones.

    Returns (claims_v4, claims_v6, errors). Same contract and same claim shape
    as build_claims: errors are collected, never raised, so validate() reports
    every problem in one pass.

    The shape is deliberately the delegation shape and not the VIP shape. A
    peer advertises BLOCKS it may carve up, never a hand-enumerated list of
    host routes: so one primitive (`{prefix, max_len}`) covers every real
    case, and `max_len` defaulting to the family's DFZ ceiling means the common
    entry is just a prefix.

    An EMPTY cone is legal here and isn't legal for a customer. A peer with a
    large cone is maintained by RPKI and a max-prefix limit rather than by a
    topology edit per prefix: validate() is what refuses the combination of
    no cone AND no limit, which is the one that would accept anything.
    """
    out, errors = {4: [], 6: []}, []

    for entry in peer.get("import", {}).get("prefixes", []) or []:
        # A bare string is accepted and means "this prefix, at this length".
        # The mapping form is what carries max_len.
        if isinstance(entry, str):
            entry = {"prefix": entry}
        if not isinstance(entry, dict) or "prefix" not in entry:
            errors.append(f"import.prefixes entry {entry!r} must be a prefix, or "
                          f"a mapping with a 'prefix' key (and optionally 'max_len')")
            continue
        try:
            net = ipaddress.ip_network(entry["prefix"], strict=False)
        except ValueError as e:
            errors.append(f"import.prefixes {entry['prefix']!r} is not a valid "
                          f"prefix ({e})")
            continue

        ceiling = PEER_DELEG_MAX[net.version]
        max_len = entry.get("max_len", ceiling)
        if not isinstance(max_len, int) or isinstance(max_len, bool) \
                or not (net.prefixlen <= max_len <= ceiling):
            errors.append(
                f"import.prefixes {net}: max_len={max_len!r} must be an int in "
                f"{net.prefixlen}..{ceiling} (>= the prefix's own length, and "
                f"<= {ceiling}, the longest IPv{net.version} prefix the DFZ "
                f"carries -- accepting a longer one costs table and buys "
                f"reachability nobody else has)")
            continue

        out[net.version].append(_make_claim(net, net.prefixlen, max_len,
                                            "import.prefixes"))

    return out[4], out[6], errors


# ---------------------------------------------------------------------
#  Peer configs: the CUSTOMER's half of the eBGP session
# ---------------------------------------------------------------------
#  A customer firewall session has two ends and this repo has only ever
#  rendered one of them. The ER end is the security boundary and always will
#  be: but leaving the other end hand-written means the grant exists twice,
#  in two syntaxes, maintained by two people, and the failure mode isn't a
#  broken session. It's a session that comes up and quietly carries less than
#  it should: a VIP the firewall was granted and never advertises, or a LAN it
#  advertises into a filter that drops it. Both look like "BGP is fine" from
#  every screen either operator is watching.
#
#  So the same claims that build cust-in-<fw> also build the firewall's own
#  config. One grant in topology.yml, two ends, rebuilt together.
#
#  `type:` on a firewall entry selects the dialect. It's OPTIONAL and absent
#  by default: a firewall we don't generate config for is still an ordinary
#  customer, which is what fwa and fwb have always been.
#
#      unifi    -> FRR, uploaded at Settings -> Routing -> BGP. UniFi's BGP
#                  IS FRR (help.ui.com/hc/en-us/articles/16271338193559), so
#                  this is a real FRR config, not a UniFi-shaped file.
#      pfsense  -> recognised, no renderer yet. Rendering nothing and SAYING
#                  SO beats failing the whole build: the ERs still render, and
#                  the operator is told at the one moment they are looking.
#
#  Adding a dialect is a template plus one line in this dict.
# ---------------------------------------------------------------------
#  External peering: realms and peers
# ---------------------------------------------------------------------
def _peer_endpoint(peers, name):
    """The declared outer address of one peer, or None if it never dials."""
    for p in peers:
        if p["name"] == name:
            ep = (p.get("remote") or {}).get("endpoint")
            if not ep:
                return None
            try:
                ipaddress.ip_address(str(ep))
            except ValueError:
                return None
            return str(ep)
    return None


def _derive_rpki(topo):
    """Normalise the top-level `rpki:` block into RTR group records.

    Absent or address-less -> no groups, no /routing/rpki, and no rpki-verify
    anywhere. Validation that looks configured and does nothing is worse than
    none at all, so a half-filled block is refused rather than rendered.
    """
    out = {}
    for group, raw in (topo.get("rpki") or {}).items():
        if not isinstance(raw, dict):
            continue
        addr = raw.get("address")
        out[group] = {
            "group": f"rpki-{group}",
            "address": addr,
            "port": raw.get("port", 3323),
            "vrf": raw.get("vrf"),
            "usable": bool(addr) and not str(addr).startswith("REPLACE-ME"),
        }
    return out


def _derive_realms(topo):
    """Normalise the `3p:` and `dn42:` blocks into per-realm records.

    Returns {realm_name: record} for EVERY realm, `internet` included. A realm
    whose block is missing or `enabled: false` still gets a record, flagged
    `enabled: False`, so validate() can say "peer/x is realm dn42 and dn42 is
    disabled" instead of dying on a KeyError. And so a topology with no
    peering renders exactly the file it rendered before.

    `internet` has no block because it has nothing to configure: it's the
    main table and the `core` instance that already exist.
    """
    realms = {
        "internet": {
            "name": "internet",
            "enabled": True,
            "vrf": None,               # main table
            "instance": "core",        # the instance that already exists
            "asn": topo["asn"],
            "errors": [],
        },
    }

    for name in ("3p", "dn42"):
        raw = topo.get(name) or {}
        if not isinstance(raw, dict):
            realms[name] = {"name": name, "enabled": False, "errors": [
                f"{name}: must be a mapping, not {type(raw).__name__}"]}
            continue

        r = {
            "name": name,
            "enabled": bool(raw.get("enabled")),
            "vrf": raw.get("vrf", name),
            "instance": name,
            # 3p speaks OUR ASN and announces OUR aggregates. That's what
            # separates it from dn42. What it doesn't do is put those routes
            # where production forwarding can see them.
            "asn": topo["asn"] if name == "3p" else raw.get("asn"),
            "errors": [],
            "raw": raw,
        }

        if name == "dn42" and r["enabled"]:
            # Loopback and router-id come out of the registered prefixes. A
            # BGP router-id is a 32-bit identifier and not an address, so a
            # v6-only DN42 presence still needs a v4-shaped one; `.1` of the
            # registered v4 block is the obvious source and is what every
            # other DN42 participant would recognise.
            for key, want6 in (("prefix", False), ("prefix_v6", True)):
                val = raw.get(key)
                if not val or str(val).startswith("REPLACE-ME"):
                    r["errors"].append(
                        f"dn42.{key} is {val!r}. Register the DN42 objects "
                        f"FIRST -- the ASN, the IPv4 block and the /48 are one "
                        f"application, and every filter here is keyed to them.")
                    continue
                try:
                    net = ipaddress.ip_network(val, strict=False)
                except ValueError as e:
                    r["errors"].append(f"dn42.{key} {val!r} is not a valid prefix ({e})")
                    continue
                if (net.version == 6) != want6:
                    r["errors"].append(
                        f"dn42.{key} {net} is an IPv{net.version} prefix")
                    continue
                r[key] = str(net)
                r["loopback6" if want6 else "loopback"] = str(net[1])

            r.setdefault("router_id", raw.get("router_id") or r.get("loopback"))
            rpki = raw.get("rpki") or {}
            r["rpki"] = ({"group": "rpki-dn42",
                          "address": rpki.get("address"),
                          "port": rpki.get("port", 8282),
                          "vrf": r["vrf"]}
                         if rpki.get("address")
                         and not str(rpki.get("address")).startswith("REPLACE-ME")
                         else None)

        realms[name] = r

    return realms


def _derive_peers(topo, brs, ks, v6, realms):
    """Derive every external peer, and one tunnel record per (peer, BR).

    Never raises. Anything wrong lands in p["derive_errors"] for validate() to
    report, the same contract the remote-site derivation follows. A topology
    with five problems should print five errors, not the first one.

    WHAT IS DERIVED HERE, and must never appear in topology.yml: the interface
    name, the listen port, our private key, the PSK, the MD5 key, our half of
    any /127 we number, every filter-chain name, the session name, and the
    instance/VRF the session belongs to.
    """
    peers = list(topo.get("peers") or [])
    by_name = {b["name"]: b for b in brs}

    peer_p2p = None
    if v6 and topo.get("blocks_v6", {}).get("peer_p2p"):
        peer_p2p = ipaddress.ip_network(topo["blocks_v6"]["peer_p2p"])

    for p in peers:
        errs = p.setdefault("derive_errors", [])
        # Snapshot the keys the OPERATOR wrote, before anything below adds a
        # derived one. validate() refuses a hand-written value that this
        # function would have computed, and it can only tell the two apart if
        # the question is asked before the answers are written down.
        p["_declared"] = frozenset(p)
        name = p.get("name")
        p["name"] = name = str(name) if name is not None else ""
        realm_name = p.setdefault("realm", "internet")
        p["realm_rec"] = realm = realms.get(realm_name)

        if not PEER_NAME_RE.match(name):
            errs.append(
                f"name {name!r} must be 2-12 characters of [a-z0-9-] starting "
                f"with a letter or digit. It becomes a RouterOS interface name, "
                f"a filter-chain name and a keystore identity -- a name that is "
                f"legal YAML and illegal to RouterOS aborts the import on a box "
                f"reset-configuration has already wiped.")

        index = p.get("index")
        if not isinstance(index, int) or isinstance(index, bool) \
                or not (1 <= index <= PEER_INDEX_MAX):
            errs.append(
                f"index {index!r} must be an int in 1..{PEER_INDEX_MAX}. It is a "
                f"FIXED SLOT: it drives the WireGuard listen port "
                f"({PEER_PORT_BASE}+slot) and the /127 offset. Allocate "
                f"sequentially and NEVER reuse one -- a decommissioned peer's "
                f"config and filters outlive your topology.")
            index = None

        if realm_name not in PEER_REALMS:
            errs.append(f"realm {realm_name!r} is not one of "
                        f"{', '.join(sorted(PEER_REALMS))}")
        elif realm and not realm.get("enabled"):
            errs.append(
                f"realm is {realm_name!r}, but the `{realm_name}:` block is "
                f"absent or enabled: false. That block carries the table, the "
                f"ASN and the ROA source this session's filters are built from; "
                f"there is nothing to attach the session to.")

        remote_probe = p.get("remote") or {}
        transport = p.setdefault("transport", "wireguard")
        if transport not in PEER_TRANSPORTS:
            errs.append(f"transport {transport!r} is not one of "
                        f"{', '.join(sorted(PEER_TRANSPORTS))}")

        # Grants. An empty cone is legal; validate() is what refuses the
        # combination of no cone and no limit.
        c4, c6, claim_errors = build_peer_claims(p)
        p["claims"], p["claims6"] = c4, c6
        p["claim_errors"] = claim_errors

        routers = p.get("routers") or []
        if isinstance(routers, str):
            routers = [routers]
        p["routers"] = routers
        if not routers:
            errs.append("routers is empty. A peer has to terminate somewhere, "
                        "and that somewhere is a border router.")

        # Which families this session runs. Derived from what is configured,
        # because that's unambiguous in every real case: v4 happens when the
        # peer numbers a v4 link (we have none to offer), v6 happens whenever
        # this AS does v6 at all. `families:` overrides, and is the only way to
        # say "no v6 with us" to a peer who would otherwise get one.
        fams = p.get("families")
        if fams is None:
            fams = []
            if remote_probe.get("address") and remote_probe.get("local"):
                fams.append(4)
            if v6:
                fams.append(6)
        elif isinstance(fams, (list, tuple)):
            fams = [f for f in fams if f in (4, 6)]
        else:
            errs.append(f"families {fams!r} must be a list of 4 and/or 6")
            fams = []
        p["families"] = sorted(set(fams))
        if 6 in p["families"] and not v6:
            errs.append(
                "families includes 6, but this topology has no prefix_v6 -- "
                "there is no IPv6 anywhere on these routers to peer with.")
            p["families"] = [f for f in p["families"] if f != 6]
        if not p["families"]:
            errs.append(
                "has no address family. v4 needs remote.address + remote.local "
                "(peer-supplied: `blocks:` leaves no v4 for a peering link), "
                "and v6 needs this topology's prefix_v6. A session carrying "
                "neither family is a tunnel with nothing in it.")

        p["is_vrf"] = realm_name in PEER_VRF_REALMS
        p["isolated"] = bool(p.get("isolated")) if realm_name == "3p" else False
        # NO_EXPORT on a bilateral interconnect is the default and not the
        # rule: it says the arrangement on the wire rather than trusting that
        # the far end won't re-announce our ARIN space from their ASN.
        p["no_export"] = (bool(p.get("no_export", True))
                          if realm_name == "3p" else bool(p.get("no_export")))

        if realm_name == "3p" and p["isolated"]:
            p["vrf"] = f"3p-{name}"
            p["instance"] = f"3p-{name}"
        elif realm and realm.get("enabled"):
            p["vrf"] = realm.get("vrf")
            p["instance"] = realm.get("instance")
        else:
            p["vrf"] = p["instance"] = None

        # Chain and session names. `name` is unique fleet-wide (it IS the
        # interface name) so one namespace across all three realms is safe.
        p["iface"] = f"ext-{name}"
        p["chains"] = {
            "in": f"peer-in-{name}", "in6": f"peer6-in-{name}",
            "nlri": f"peer-nlri-{name}", "nlri6": f"peer6-nlri-{name}",
            "out": f"peer-out-{name}", "out6": f"peer6-out-{name}",
            "tail": f"peer-out-{realm_name}", "tail6": f"peer6-out-{realm_name}",
        }
        p["session"], p["session6"] = f"peer-{name}", f"peer6-{name}"

        remote = p.setdefault("remote", {}) or {}
        p["remote"] = remote
        imp = p.setdefault("import", {}) or {}
        p["import"] = imp
        p["max_routes"] = imp.get("max_routes")
        p["max_routes_v6"] = imp.get("max_routes_v6")

        # One tunnel record per (peer, BR).
        p["links"] = []
        for rname in routers:
            br = by_name.get(rname)
            if br is None:
                errs.append(
                    f"routers names {rname!r}, which is not a border router. "
                    f"External peering terminates on a BR only: an ER has no "
                    f"public address to be dialled at, and a peer tunnel there "
                    f"would put a third party inside the home input chain.")
                continue
            if index is None:
                continue

            slot = (index - 1) * PEER_BR_SLOTS + (br["index"] - 1)
            link = {
                "peer": name,
                "br": br["name"],
                "br_fqdn": br["fqdn"],
                "iface": p["iface"],
                "listen_port": PEER_PORT_BASE + slot,
                "realm": realm_name,
                "transport": transport,
                "endpoint": remote.get("endpoint"),
                "endpoint_port": remote.get("endpoint_port"),
                # ALWAYS present, None when the family isn't run. br.rsc.j2
                # renders under StrictUndefined and uses selectattr on these,
                # which raises on a missing key rather than treating it as
                # falsy: so "absent" has to be spelled None, not omitted.
                "v4": None,
                "v6": None,
            }

            if transport == "wireguard":
                kp = key_for(ks, f"{br['fqdn']}:{p['iface']}")
                link["private"] = kp["private"]
                link["public"] = kp["public"]
                link["peer_public"] = remote.get("public_key")
                # One PSK per (peer, BR) pair, keyed canonically so both ends
                # of a rebuild resolve the same value.
                link["psk"] = (psk_for(ks, f"psk:{br['name']}-{name}-peer")
                               if p.get("psk") else None)

            # ONE MD5 key per peer, not per BR: the far end configures one
            # password for us, and asking a third party to hold two is friction
            # that buys nothing: the sessions are already distinguished by
            # address.
            link["md5"] = bgp_md5_for(ks, name) if p.get("md5") else None

            # --- v4: PEER-SUPPLIED ONLY ---------------------------------
            # blocks: allocates all 256 addresses of the /24. There's no v4
            # here to give, and there won't be one without renumbering live
            # links, so a v4 session happens when the peer numbers it.
            if 4 in p["families"] and remote.get("address") and remote.get("local"):
                link["v4"] = {"local": str(remote["local"]),
                              "remote": str(remote["address"])}

            # --- v6: ours by default ------------------------------------
            if 6 in p["families"]:
                if remote.get("address_v6") and remote.get("local_v6"):
                    link["v6"] = {"local": str(remote["local_v6"]),
                                  "remote": str(remote["address_v6"]),
                                  "len": 127, "ours": False}
                elif remote.get("address_v6", "").lower().startswith("fe80:"):
                    # DN42's convention: link-local on both ends, no numbering
                    # to agree on. RouterOS needs the %interface scope, the
                    # same construct the HostHatch fe80::1 gateway already uses.
                    link["v6"] = {"local": None,
                                  "remote": str(remote["address_v6"]),
                                  "len": None, "ours": False,
                                  "link_local": True}
                elif peer_p2p is not None:
                    off = slot * 2
                    base = int(peer_p2p.network_address) + off
                    link["v6"] = {"local": str(ipaddress.ip_address(base)),
                                  "remote": str(ipaddress.ip_address(base + 1)),
                                  "len": 127, "ours": True}

            # ---- denormalise the POLICY onto the link -------------------
            # The template iterates r.peers (links) and needs the peer's policy
            # in the same object, exactly as r.tunnels already carries
            # everything br.rsc.j2 asks of it. Two lookups in a Jinja loop under
            # StrictUndefined is how you get a render that fails on the fifth
            # peer and not the first.
            link.update(
                asn=p.get("asn"),
                families=p["families"],
                chains=p["chains"],
                session=p["session"],
                session6=p["session6"],
                instance=p["instance"],
                vrf=p["vrf"],
                no_export=p["no_export"],
                claims=p["claims"],
                claims6=p["claims6"],
                max_routes=p["max_routes"],
                max_routes_v6=p["max_routes_v6"],
                contact=p.get("contact"),
                # Per peer, because wg_mtu was measured against OUR underlays
                # and a peer's path is unmeasured. Defaulting to it's the
                # honest starting point, not a claim about their network.
                mtu=p.get("mtu", topo["wg_mtu"]),
                # WireGuard's allowed-address is a cryptographic ROUTING gate,
                # not a filter: a packet it drops is discarded before the
                # firewall or the routing table sees it, with no log line (the
                # BR<->ER block above says so at length). Narrowing it to the
                # peer's cone would therefore turn every prefix they add into a
                # silent blackhole, and would break PMTUD the moment an ICMP
                # error came from a router inside their network but outside
                # their cone. The trust boundary is the peer-in chain and the
                # peer-tun input policy, both of which fail VISIBLY.
                allowed_address=("0.0.0.0/0,::/0" if v6 else "0.0.0.0/0"),
            )
            p["links"].append(link)

    return peers


PEER_TYPES = {
    "unifi":   "peer-unifi.conf.j2",
    "pfsense": None,
}

#  Dialects whose renderer emits the far end of a BFD session. A firewall with
#  `bfd: true` and a RENDERED config that isn't in here is refused by
#  validate(): rendering both ends from one grant is worthless if the two ends
#  can disagree about whether there's a BFD session between them. A type with
#  no renderer at all (pfsense) isn't affected. That config is the
#  operator's, and so is matching the flag.
PEER_BFD_TYPES = frozenset()


def build_peer_config(fw, ers, topo, v6):
    """Derive the customer-side view of the sessions the ERs already run.

    Returns None when the firewall declares no `type`. Which is the default,
    and stays the default.
    """
    ftype = fw.get("type")
    if ftype is None:
        return None

    h = topo["home"]
    # v6 only when the whole AS has it, this firewall was granted v6 space, AND
    # it has an address to run the session from. Any one missing and the v6
    # half of the file would describe a session that can't exist. Validate()
    # already refuses grants-without-an-address, so this is the OTHER two cases.
    v6 = bool(v6 and fw["claims6"] and fw.get("peer_address_v6"))

    # Every firewall peers with EVERY ER (build() sets er["firewalls"] = fws),
    # so the neighbour list is simply the ERs. Read from topo["home"] rather
    # than the ER dicts because the v4 transit address is still assembled in
    # er.rsc.j2 by string surgery and has no derived counterpart to borrow.
    def _addr(a):
        # Normalised, so the neighbour lines and the prefix-lists agree on the
        # case of a hextet. topology.yml writes v6 in upper case; everything
        # derived through ipaddress comes back lower.
        return str(ipaddress.ip_address(a)) if a else None

    neighbors = [{
        "name":     er["fqdn"],
        "address":  _addr(h[f"transit_er{er['index']}"]),
        "address6": _addr(h.get(f"transit_er{er['index']}_v6")) if v6 else None,
    } for er in ers]

    claims6 = fw["claims6"] if v6 else []

    # `default_route`: who owns this gateway's default route.
    #   install (default) -> FRR installs the ERs' default, ECMP across both.
    #   ignore            -> the gateway's OWN WAN manager owns the default and
    #                        the transit is just one more WAN in its failover /
    #                        load-balance set. The ERs still send the default;
    #                        it's refused inbound so it never reaches the RIB.
    # Why `ignore` exists: on UniFi the BGP-learned default lands in the kernel
    # table ahead of the WAN manager's per-WAN routes, so with `install` every
    # other WAN goes idle the moment the session comes up. Distance 20 vs the
    # statics' 1 never gets compared, because they aren't in the same table.
    accept_default = fw.get("default_route", "install") == "install"

    def _summary(c):
        what = ("exact prefix (allowed_vips)" if c["exact"] else
                f"block, any more-specific to /{c['max_len']} (delegations)")
        return f"{c['prefix']:<34}  {what}"

    return {
        "type":      ftype,
        "template":  PEER_TYPES.get(ftype),
        # Type in the filename, not just the header: the day a second dialect
        # lands, one firewall may plausibly want both rendered side by side.
        "filename":  f"{fw['name']}.{ftype}.conf",
        # FRR's router-id is an IPv4 address and has no v6 equivalent. The
        # firewall's own transit address is the obvious one: unique by
        # construction (validate() rejects duplicates) and the address the ERs
        # already know it by.
        "router_id": fw.get("peer_address"),
        "peer_asn":  topo["asn"],
        "neighbors": neighbors,
        "v6":        v6,
        # Split by shape, because the two are advertised by different
        # mechanisms: an exact VIP is a `network` statement, a delegated block
        # is redistributed from connected and filtered back down to the grant.
        "networks":  [c for c in fw["claims"] if c["exact"]],
        "blocks":    [c for c in fw["claims"] if not c["exact"]],
        "networks6": [c for c in claims6 if c["exact"]],
        "blocks6":   [c for c in claims6 if not c["exact"]],
        "claims":    fw["claims"],
        "claims6":   claims6,
        "summary":   [_summary(c) for c in fw["claims"] + claims6],
        "default_desc": "0.0.0.0/0 and ::/0" if v6 else "0.0.0.0/0",
        # The ERs both originate the default, so a customer that installs one
        # path has silently un-multihomed its egress. Deliberately NOT
        # topo["bgp_multipath"]: that number is a RouterOS instance property
        # with its own type trap (see topology.yml), and how many next-hops
        # the CUSTOMER installs is a different question with a different
        # answer: it's however many ERs are advertising to it.
        "ecmp":      (len(neighbors) if len(neighbors) > 1 and accept_default
                      else None),
        "accept_default": accept_default,
        # Policy object names, derived so they carry the peer AS rather than
        # a house style nobody outside this repo can decode.
        "rm_in":     f"AS{topo['asn']}-IN",
        "rm_out":    f"AS{topo['asn']}-OUT",
        "rm_in6":    f"AS{topo['asn']}-IN6",
        "rm_out6":   f"AS{topo['asn']}-OUT6",
        "pl_in":     f"FROM-AS{topo['asn']}",
        "pl_out":    f"TO-AS{topo['asn']}",
        "pl_in6":    f"FROM-AS{topo['asn']}-V6",
        "pl_out6":   f"TO-AS{topo['asn']}-V6",
    }


# ---------------------------------------------------------------------
#  Validation: catch a topology typo before it reaches a router
# ---------------------------------------------------------------------
def validate(topo, d):
    # Where typos come to die. Better here than at 2 a.m. on a router with no BGP.
    errs = []
    v6 = d["v6"]
    # The containing aggregate, PER FAMILY. Checking a v6 address against the
    # v4 /24 (or vice versa) isn't merely wrong, it raises. So every
    # containment test below selects the net by the address's own version.
    nets = {4: ipaddress.ip_network(topo["prefix"])}
    if v6:
        nets[6] = ipaddress.ip_network(topo["prefix_v6"])

    def contains(addr):
        """Is addr inside this AS's aggregate for its OWN family?"""
        a = ipaddress.ip_address(addr)
        n = nets.get(a.version)
        return (None if n is None else a in n), n

    seen_ip = {}

    def note(addr, label):
        """Record an address, and report it if it collides or sits outside the
        aggregate for its own family.

        Everything with an address goes through here, including the `home:`
        block. That block used to SEED seen_ip without being checked against
        it, which made two of its own entries invisible to the sweep: setting
        transit_er2 to transit_er1's value simply overwrote the label, and an
        address outside the /24 was never containment-checked at all. Both
        render happily and fail on the wire. One as two ERs answering on one
        address, the other as an ER holding space this AS doesn't own."""
        inside, n = contains(addr)
        if inside is False:
            errs.append(f"{label}: {addr} is outside {n}")
        if addr in seen_ip:
            errs.append(f"DUPLICATE IP {addr}: {seen_ip[addr]} and {label}")
        else:
            seen_ip[addr] = label

    # home local-links addresses participate in the duplicate check too: a
    # firewall peer_address colliding with an ER transit address is exactly the
    # typo this pass exists to catch.
    home = topo.get("home", {})
    for label in ("transit_er1", "transit_er2",
                  "transit_er1_v6", "transit_er2_v6"):
        if home.get(label):
            note(home[label], f"home/{label}")
    for xc_key, suffix in (("xc_net", ""), ("xc_net_v6", "_v6")):
        if home.get(xc_key):
            xc_base = int(ipaddress.ip_network(home[xc_key], strict=False).network_address)
            for er in d["ers"]:
                addr = str(ipaddress.ip_address(xc_base + er["index"] - 1))
                note(addr, f"home/{xc_key}({er['name']})")

    # A site whose index never validated has no derived addressing at all, so it
    # is kept out of every sweep below and reported on its own terms.
    live_sites = [s for s in d["sites"] if not s.get("derive_errors")]

    for r in d["brs"] + d["ers"] + live_sites:
        addrs = [("loopback", r["loopback"])] + \
                [(t["iface"], t["address"].split("/")[0]) for t in r["tunnels"]] + \
                [(b["iface"], b["address"].split("/")[0]) for b in r.get("backbone", [])]
        if r.get("lan_gateway"):
            addrs.append(("lan", r["lan_gateway"]))
        if v6:
            addrs += [("loopback6", r["loopback6"])] + \
                     [(f"{t['iface']}/v6", t["address6"].split("/")[0]) for t in r["tunnels"]] + \
                     [(f"{b['iface']}/v6", b["address6"].split("/")[0]) for b in r.get("backbone", [])]
            if r.get("lan_gateway6"):
                addrs.append(("lan/v6", r["lan_gateway6"]))
        for label, addr in addrs:
            note(addr, f"{r['fqdn']}/{label}")

        ports = [t["listen_port"] for t in r["tunnels"]] + \
                [b["listen_port"] for b in r.get("backbone", [])]
        dupes = {p for p in ports if ports.count(p) > 1}
        if dupes:
            errs.append(f"{r['fqdn']}: duplicate WG listen ports {sorted(dupes)}")

    # every tunnel endpoint must have a distinct key, and the pairing must be symmetric
    for t in d["br_er"]:
        if t["br_key"]["public"] == t["er_key"]["public"]:
            errs.append(f"{t['br']}<->{t['er']}/{t['wan']}: both ends share a key")

    # ---- automation login ---------------------------------------------
    # This block grants a machine a login on every router in the AS. Every
    # check here is about the two ways that goes wrong: a login nobody can use,
    # or a login that isn't the one you meant.
    auto = topo.get("automation")
    if isinstance(auto, dict) and auto:
        user = auto.get("user")
        if not user or not isinstance(user, str):
            errs.append("automation.user must be a username string")
        elif user == (topo.get("ssh") or {}).get("user"):
            errs.append(
                f"automation.user '{user}' is the same account as ssh.user. "
                f"The whole point of the second user is that the two key sets "
                f"are revocable separately -- and ssh.keys_url CLEARS the "
                f"user's keys on every import, so sharing the account means "
                f"each build deletes the runner's key.")
        elif user == "admin":
            errs.append(
                "automation.user 'admin' is RouterOS's default account. Give "
                "the runner its own name so its access is visible in /user and "
                "revocable on its own.")

        keys = auto.get("keys") or []
        if not keys:
            errs.append(
                f"automation.keys is empty. Rendering a '{user}' account with "
                f"no key creates a login nothing can use and that no build "
                f"will notice -- CI would fail at the first ssh with a "
                f"permission error that looks like a network fault. Remove the "
                f"whole `automation:` block if you do not want CI access.")
        for k in keys:
            if not isinstance(k, str) or not k.strip():
                errs.append(f"automation.keys entry {k!r} is not a string")
                continue
            if k.strip().startswith("REPLACE-ME"):
                errs.append(
                    "automation.keys still contains the REPLACE-ME "
                    "placeholder. Generate a keypair and paste the PUBLIC half "
                    "(ssh-keygen -t ed25519 -f ~/.ssh/as64500-ci -N \"\").")
            elif not k.strip().startswith(("ssh-ed25519 ", "ssh-rsa ",
                                           "ecdsa-sha2-", "sk-ssh-ed25519")):
                errs.append(
                    f"automation.keys entry does not look like an SSH PUBLIC "
                    f"key: {k.strip()[:40]!r}. RouterOS will reject it at "
                    f"import and the account will exist with no way in.")
            elif "PRIVATE KEY" in k:
                errs.append(
                    "automation.keys contains a PRIVATE key. This file is "
                    "committed. Rotate that key immediately and paste the "
                    ".pub half instead.")

        # The group. `full` is the builtin; anything else is rendered from
        # `policies`, so an empty list would create a group that can't log in.
        if auto.get("group") != "full":
            pols = auto.get("policies") or []
            if not pols:
                errs.append(
                    f"automation.group '{auto.get('group')}' is a custom group "
                    f"but automation.policies is empty -- that renders a group "
                    f"with no rights at all.")
            unknown = [x for x in pols if x not in ROS_POLICIES]
            if unknown:
                errs.append(
                    f"automation.policies has unknown entries {unknown}. "
                    f"RouterOS rejects an unknown policy name and the /user/"
                    f"group line aborts the import -- on a box that has "
                    f"already been reset. Valid: {sorted(ROS_POLICIES)}")
            for required, why in (
                ("ssh", "the runner could not log in at all"),
                ("read", "every check in tests/functional reads state"),
                ("write", "the deploy applies config"),
                ("reboot", "reset-configuration and the reboot after it"),
                ("policy", "/system/reset-configuration is REFUSED without it "
                           "-- measured on a live router, not documented "
                           "anywhere. It is the deploy primitive, so without "
                           "this nothing rolls out at all"),
                ("ftp", "scp puts the .rsc on the router; RouterOS governs "
                        "SCP with the ftp policy"),
                ("test", "/ping backs the loopback-mesh and MTU checks"),
            ):
                if required not in pols:
                    errs.append(
                        f"automation.policies is missing '{required}': {why}. "
                        f"Add it, or set group: full.")

    # ---- BFD ----------------------------------------------------------
    # Three rules carry real weight here; the rest are typo-catchers.
    #
    # 1. use_ospf without configure. RouterOS FORBIDS BFD on anything not
    #    listed in /routing/bfd/configuration, so this combination puts
    #    use-bfd=yes on every tunnel while no router will answer a single BFD
    #    packet. Every adjacency in the AS would then be holding a session that
    #    can never come up. Refuse to render it.
    # 2. A floor on the detection time. These are hEX-class ERs and CHR guests
    #    on shared VPS hosts, talking through WireGuard. Sub-50ms detection on
    #    that stack doesn't detect failures, it detects scheduling jitter.
    #    And an OSPF adjacency that flaps every time a hypervisor deschedules a
    #    vCPU is strictly worse than the 20s dead-interval it replaced.
    bfd = topo.get("bfd", {}) or {}
    if bfd.get("use_ospf") and not bfd.get("configure"):
        errs.append(
            "bfd.use_ospf=true with bfd.configure=false: OSPF would ask for BFD "
            "sessions on every tunnel while /routing/bfd/configuration is empty "
            "-- and RouterOS forbids BFD on any interface not listed there. Set "
            "configure=true, deploy that everywhere FIRST, then arm use_ospf.")

    def _check_bfd_timers(label, spec):
        """interval + multiplier sanity, identical for every BFD menu entry."""
        if not isinstance(spec, dict):
            errs.append(f"{label} must be a mapping with 'interval' "
                        f"and 'multiplier'")
            return
        ms = _time_ms(spec.get("interval"))
        mult = spec.get("multiplier")
        if ms is None:
            errs.append(f"{label}.interval={spec.get('interval')!r} is "
                        f"not a RouterOS time literal (e.g. 200ms, 1s). An "
                        f"unsuffixed number means SECONDS to RouterOS.")
        elif not (10 <= ms <= 10_000):
            errs.append(f"{label}.interval={spec['interval']} = {ms}ms "
                        f"is outside 10ms..10s")
        if not isinstance(mult, int) or not (1 <= mult <= 50):
            errs.append(f"{label}.multiplier={mult!r} must be an int "
                        f"in 1..50")
        elif ms is not None and 10 <= ms <= 10_000 and ms * mult < 50:
            errs.append(
                f"{label}: {spec['interval']} x {mult} = {ms * mult}ms "
                f"detection is too aggressive for this network. These are "
                f"hEX-class ERs, shared-host CHRs and a general-purpose "
                f"firewall; below ~50ms you are detecting scheduling jitter "
                f"rather than failures, and the session flap that causes is "
                f"worse than the timer it replaced.")

    if bfd.get("configure"):
        want = set(topo["ospf_cost"])
        have = set(bfd.get("links") or {})
        for cls in sorted(want - have):
            errs.append(f"bfd.links.{cls} is missing; every ospf_cost class needs "
                        f"BFD timers or that link class silently keeps the "
                        f"{'40s' if cls in ('wan2', 'er_xc') else '20s'} OSPF "
                        f"dead-interval while the rest of the network is fast")
        for cls in sorted(have - want):
            errs.append(f"bfd.links.{cls} is not an ospf_cost link class "
                        f"({', '.join(sorted(want))}); nothing would render it")
        for cls in sorted(want & have):
            _check_bfd_timers(f"bfd.links.{cls}", bfd["links"][cls])
        if bfd.get("customer") is not None:
            _check_bfd_timers("bfd.customer", bfd["customer"])

    # 3. the customer transit segment. Same shape as rules 1 and 2, one menu
    #    down: `bfd.customer` renders the /routing/bfd/configuration entry that
    #    PERMITS BFD there, and a firewall's `bfd: true` is what asks for the
    #    session. Asking without permitting is the same dead-session state
    #    use_ospf-without-configure produces, except it lands on the segment
    #    carrying customer traffic instead of on a tunnel.
    if bfd.get("customer") is not None and not bfd.get("configure"):
        errs.append(
            "bfd.customer is set with bfd.configure=false: nothing renders "
            "/routing/bfd/configuration at all, so the transit entry it "
            "describes would not exist. Set configure=true.")

    if topo["mss_clamp"] != topo["wg_mtu"] - 40:
        errs.append(f"mss_clamp ({topo['mss_clamp']}) should be wg_mtu - 40 "
                    f"({topo['wg_mtu'] - 40})")

    # Derived in derive(); only reachable if topology.yml overrode it. The v6
    # header is 40 bytes, not 20. See the note there.
    if topo["mss_clamp_v6"] != topo["wg_mtu"] - 60:
        errs.append(f"mss_clamp_v6 ({topo['mss_clamp_v6']}) should be "
                    f"wg_mtu - 60 ({topo['wg_mtu'] - 60}): IPv6's header is 40 "
                    f"bytes, not 20. Remove it from topology.yml and let it be "
                    f"derived.")

    # The provider default MUST sit between eBGP (20) and iBGP (200).
    pdd = topo["provider_default_distance"]
    if not (20 < pdd < 200):
        errs.append(
            f"provider_default_distance={pdd} must be >20 (lose to the eBGP "
            f"default) and <200 (BEAT an iBGP default from a sibling BR). "
            f"At >=200 a BR egresses via a sibling's transit and its "
            f"own-sourced packets die at the sibling upstream's BCP38 filter "
            f"-- including your SSH to it.")

    # ---- BR WAN: static ether1 addressing ----------------------------
    # ether1 is configured statically (no DHCP ever). A wrong prefix or a
    # gateway outside the WAN subnet means the box comes back from a reset
    # unreachable except via provider console. So validate hard here.
    for br in d["brs"]:
        pfx = br.get("wan_prefix")
        if not isinstance(pfx, int) or not (0 < pfx <= 32):
            errs.append(f"{br['fqdn']}: wan_prefix={pfx!r} must be an int in 1..32 "
                        f"(the static netmask on ether1; no DHCP fallback exists)")
            continue
        try:
            wan_net = ipaddress.ip_network(f"{br['wan_address']}/{pfx}", strict=False)
            if ipaddress.ip_address(br["wan_gateway"]) not in wan_net:
                errs.append(f"{br['fqdn']}: wan_gateway {br['wan_gateway']} is not "
                            f"inside the WAN subnet {wan_net} (wan_address/{pfx}). "
                            f"Wrong prefix or gateway -> no default route after reset.")
        except ValueError as e:
            errs.append(f"{br['fqdn']}: bad WAN addressing ({e})")

    # ---- IPv6: allocation vs ANNOUNCED aggregate ----------------------
    # prefix_v6 is what ARIN allocated; aggregate_v6 is what the BRs originate.
    # They differ because part of the /40 is delegated to AWS BYOIP and
    # originated by AS16509. Everything downstream (the anchor, my-aggregate6,
    # the iBGP reject, the ER loop guard) follows aggregate_v6, so these checks
    # are what keep "what we announce" and "what we route" from drifting apart.
    if v6:
        alloc6 = nets[6]
        try:
            agg6 = ipaddress.ip_network(topo["aggregate_v6"])
        except (KeyError, ValueError) as e:
            errs.append(f"aggregate_v6 is missing or invalid ({e}); it is what "
                        f"the BRs originate and has no default")
            agg6 = None

        if agg6 is not None:
            if agg6.version != 6:
                errs.append(f"aggregate_v6 {agg6} is not IPv6")
            elif not agg6.subnet_of(alloc6):
                errs.append(f"aggregate_v6 {agg6} is not inside prefix_v6 "
                            f"{alloc6}; we cannot originate space ARIN did not "
                            f"allocate to us")

            # The AWS range is originated by AS16509, not by us. If the anchor
            # covered it, in-AS traffic to our own BYOIP space would hit the
            # blackhole and be dropped while the rest of the internet reached it
            # fine via AWS: a split-brain that only shows up from inside.
            aws6 = topo.get("aws_byoip_v6")
            if aws6:
                aws6 = ipaddress.ip_network(aws6)
                if not aws6.subnet_of(alloc6):
                    errs.append(f"aws_byoip_v6 {aws6} is not inside prefix_v6 {alloc6}")
                if agg6 is not None and agg6.overlaps(aws6):
                    errs.append(
                        f"aggregate_v6 {agg6} OVERLAPS aws_byoip_v6 {aws6}. The "
                        f"BRs would originate space AS16509 announces and would "
                        f"blackhole it internally: in-AS traffic to your own "
                        f"BYOIP /48s would be dropped at the BR while the rest "
                        f"of the internet reached them via AWS.")

            # THE CHECK THAT BITES LATER. Every block we actually address out
            # of must sit inside what we announce, or we route space the world
            # can't send us. Today it's trivially true; it stops being true
            # the day someone allocates a site at 0x40 without widening the
            # aggregate, and nothing else in this repo would notice.
            if agg6 is not None:
                for name, blk in sorted(topo.get("blocks_v6", {}).items()):
                    b = ipaddress.ip_network(blk)
                    if not b.subnet_of(agg6):
                        errs.append(
                            f"blocks_v6.{name} {b} is outside aggregate_v6 "
                            f"{agg6}. We would address hosts out of it but never "
                            f"announce it, so the outside world could not reach "
                            f"them. Widen aggregate_v6 (and add a matching ROA) "
                            f"or move the block inside it.")

                # Site /48s are the same check one object down, and they are the
                # ones that will actually trip it: sites count up from 02 and
                # the announced aggregate stops at 3F. A site allocated past
                # that renders perfectly and is unreachable from the internet.
                for s in live_sites:
                    d48 = ipaddress.ip_network(s["delegation6"])
                    if not d48.subnet_of(agg6):
                        errs.append(
                            f"site/{s['name']}: delegation6 {d48} (from index "
                            f"{s['index']}) is outside aggregate_v6 {agg6}. The "
                            f"site would be addressed out of space the BRs never "
                            f"announce. Widen aggregate_v6 and add the matching "
                            f"ROA before allocating this index.")
                    if aws6 and d48.overlaps(aws6):
                        errs.append(
                            f"site/{s['name']}: delegation6 {d48} overlaps "
                            f"aws_byoip_v6 {aws6}, which AWS originates from "
                            f"AS14618/AS16509. Two origins for one prefix.")
                    for name, blk in sorted(topo.get("blocks_v6", {}).items()):
                        b = ipaddress.ip_network(blk)
                        if d48.overlaps(b):
                            errs.append(
                                f"site/{s['name']}: delegation6 {d48} overlaps "
                                f"blocks_v6.{name} {b}")

    # ---- BR WAN: IPv6 -------------------------------------------------
    # Two provider styles, and the difference breaks things if ignored:
    #   gateway: ra        the provider only announces a default via Router
    #                      Advertisement (Vultr). The BR must be told to ACCEPT
    #                      RAs, which a forwarding router does NOT do by default.
    #                      See the template. There's no static v6 default.
    #   gateway: <addr>    a fixed next-hop (HostHatch uses fe80::1). A
    #                      link-local gateway MUST be interface-scoped
    #                      (fe80::1%ether1) or RouterOS can't resolve it.
    # Getting this wrong costs the box its v6 default route, which is silent:
    # v4 keeps working and nobody notices until a v6-only destination fails.
    for br in d["brs"]:
        w6 = br.get("wan_v6")
        if not v6:
            continue
        if not w6:
            errs.append(f"{br['fqdn']}: prefix_v6 is set but this BR has no "
                        f"wan_v6 block; it cannot peer or egress over IPv6")
            continue
        # Placeholders are caught by name, before they are parsed as addresses,
        # so the error names the thing the operator actually has to go and find.
        todo = [k for k in ("address", "gateway") if str(w6.get(k, "")).upper() == "REPLACE-ME"]
        if str(br.get("peer_v6_address", "")).upper() == "REPLACE-ME":
            todo.append("peer_v6_address")
        if todo:
            errs.append(f"{br['fqdn']}: {', '.join(todo)} still set to REPLACE-ME. "
                        f"Fill in the real values from the {br['provider']} panel "
                        f"before enabling prefix_v6.")
            continue
        pfx6 = w6.get("prefix")
        if not isinstance(pfx6, int) or not (0 < pfx6 <= 128):
            errs.append(f"{br['fqdn']}: wan_v6.prefix={pfx6!r} must be an int in 1..128")
            continue
        try:
            addr6 = ipaddress.ip_address(w6["address"])
            if addr6.version != 6:
                errs.append(f"{br['fqdn']}: wan_v6.address {addr6} is not IPv6")
                continue
            wan6 = ipaddress.ip_network(f"{addr6}/{pfx6}", strict=False)
        except (ValueError, KeyError) as e:
            errs.append(f"{br['fqdn']}: bad wan_v6 addressing ({e})")
            continue

        gw6 = str(w6.get("gateway", "")).strip()
        if gw6.lower() == "ra":
            continue                      # RA-discovered; nothing to check
        try:
            g = ipaddress.ip_address(gw6)
        except ValueError:
            errs.append(f"{br['fqdn']}: wan_v6.gateway {gw6!r} must be 'ra' "
                        f"(discover via Router Advertisement) or an IPv6 address")
            continue
        if g.version != 6:
            errs.append(f"{br['fqdn']}: wan_v6.gateway {g} is not IPv6")
        elif not g.is_link_local and g not in wan6:
            # A link-local gateway is legitimate and deliberately NOT range
            # checked: fe80::1 is outside every global subnet by definition.
            errs.append(f"{br['fqdn']}: wan_v6.gateway {g} is neither link-local "
                        f"nor inside the WAN subnet {wan6}; no v6 default route")

    # ---- customer firewalls ------------------------------------------
    # These peers are the ONLY untrusted BGP speakers inside the /24. Every rule
    # here is a security boundary, not a style check: refuse to render on any.
    # Per-family customer + infrastructure blocks. Both families enforce the
    # identical rules; only the numbers change.
    # Keyed off blocks_v6 rather than the prefix_v6 master switch, deliberately:
    # v6 grants must be checked for correctness while the plan is still staged,
    # not only once v6 goes live on the routers. Otherwise the first time anyone
    # validates the v6 delegations is the moment they are also being pushed.
    home_blocks = {4: ipaddress.ip_network(topo["blocks"]["customer_home"])}
    links_blocks = {4: ipaddress.ip_network(topo["blocks"]["local_links"])}
    if topo.get("blocks_v6"):
        home_blocks[6] = ipaddress.ip_network(topo["blocks_v6"]["customer_home"])
        links_blocks[6] = ipaddress.ip_network(topo["blocks_v6"]["local_links"])
    reserved_asns = {topo["asn"]} | {b["peer_asn"] for b in d["brs"]}
    vip_owners = {}

    for fw in d["firewalls"]:
        who = f"firewall/{fw['name']}"

        # 0. anything build_claims couldn't parse. Report and move on: the
        # per-claim checks below can't say anything useful about a claim that
        # never became a claim.
        for e in fw.get("claim_errors", []):
            errs.append(f"{who}: {e}")

        # 1. a firewall claims MORE-SPECIFICS, never the aggregate. This holds
        # identically for an enumerated VIP and for a delegated block: the
        # delegation is a sub-block of the /25 that the firewall may carve up,
        # never the /25 itself. If a firewall could claim the aggregate it would
        # own all of home, including addresses granted to another firewall.
        for c in fw["claims"] + fw["claims6"]:
            v = ipaddress.ip_network(c["prefix"])
            label = "allowed_vip" if c["source"] == "allowed_vips" else "delegation"
            home_block = home_blocks.get(v.version)
            links_f = links_blocks.get(v.version)
            if home_block is None:
                errs.append(f"{who}: {label} {v} is IPv{v.version}, but no "
                            f"IPv{v.version} customer block is configured")
                continue
            if not v.subnet_of(home_block):
                errs.append(f"{who}: {label} {v} is outside {home_block}")
            elif v.prefixlen <= home_block.prefixlen:
                errs.append(
                    f"{who}: {label} {v} has dst-len {v.prefixlen}; must be "
                    f"> {home_block.prefixlen}. A firewall claims more-specifics "
                    f"out of the block, it never claims the block itself.")
            # A delegation that swallows infrastructure addressing would let the
            # customer advertise a /32 for an ER's own transit address and pull
            # that traffic to itself. The blocks are laid out so this can't
            # happen by construction: assert it anyway, because the day
            # someone widens customer_home is the day it stops being true.
            if links_f is not None and v.overlaps(links_f):
                errs.append(f"{who}: {label} {v} overlaps the local-links block "
                            f"{links_f}; a customer must never be able to claim "
                            f"infrastructure addressing")
            vip_owners.setdefault(c["key"], []).append(fw)

        # 2. private ASN, and not one already meaningful in this AS.
        asn = fw.get("asn")
        if not (64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294):
            errs.append(f"{who}: asn {asn} is not in a private range "
                        f"(64512-65534 or 4200000000-4294967294)")
        if asn in reserved_asns:
            errs.append(f"{who}: asn {asn} collides with an ASN this AS already "
                        f"means something by (own AS or an upstream peer)")

        # 3. peer_address: in the local-links block, unique, no collision.
        # Both families, same rule. A firewall with v6 grants but no
        # peer_address_v6 has nowhere to peer from, so the grants would be
        # silently unreachable: refuse rather than render a dead session.
        for key in ("peer_address", "peer_address_v6"):
            pa = fw.get(key)
            if pa is None:
                if key == "peer_address_v6" and fw["claims6"]:
                    errs.append(f"{who}: has IPv6 grants but no peer_address_v6; "
                                f"there is no address to run the v6 session from")
                continue
            lb = links_blocks.get(ipaddress.ip_address(pa).version)
            if lb is None or ipaddress.ip_address(pa) not in lb:
                errs.append(f"{who}: {key} {pa} is outside the local-links "
                            f"block {lb}; it is NOT service space")
            if pa in seen_ip:
                errs.append(f"DUPLICATE IP {pa}: {seen_ip[pa]} and {who}/{key}")
            seen_ip[pa] = f"{who}/{key}"

        # 3b. `type`: the peer-config dialect. Optional. Absent means we
        # render the ER end only. A value we don't recognise is REFUSED
        # rather than ignored: silently skipping a typo'd `unfi` hands the
        # operator an ER waiting for a session whose other end was never built.
        ftype = fw.get("type")
        if ftype is not None:
            if ftype not in PEER_TYPES:
                errs.append(f"{who}: type {ftype!r} is not one of "
                            f"{sorted(PEER_TYPES)}")
            elif PEER_TYPES[ftype] and not fw.get("peer_address"):
                # A peer config needs an IPv4 router-id even on a v6-only
                # grant, and peer_address is the only v4 address we have for
                # this firewall. BGP has no IPv6 form of router-id.
                errs.append(f"{who}: type {ftype!r} needs a peer_address -- it "
                            f"is the router-id of the generated config, and "
                            f"there is no IPv6 substitute for one")

        # 3b'. `default_route`: install | ignore. Anything else is a typo, and
        # a typo here silently decides where all of the gateway's egress goes.
        dr = fw.get("default_route")
        if dr is not None and dr not in ("install", "ignore"):
            errs.append(f"{who}: default_route {dr!r} must be 'install' or "
                        f"'ignore'")

        # 3c. `bfd`: use-bfd=yes on this firewall's eBGP connections. Two ways
        # it can be wrong, and both produce a session asking for BFD that
        # nothing will answer: on the segment carrying customer traffic.
        if fw["bfd"]:
            if (topo.get("bfd") or {}).get("customer") is None:
                errs.append(f"{who}: bfd=true but bfd.customer is not set, so "
                            f"the ERs' transit interface still renders "
                            f"forbid-bfd=yes -- RouterOS would refuse the very "
                            f"session use-bfd=yes asks for. Set bfd.customer "
                            f"timers, deploy BOTH ERs, then flag the firewall.")
            rendered = ftype is not None and PEER_TYPES.get(ftype)
            if rendered and ftype not in PEER_BFD_TYPES:
                errs.append(f"{who}: bfd=true is not available for type "
                            f"{ftype!r} -- this build renders that firewall's "
                            f"own config, and its renderer emits no BFD stanza. "
                            f"The ER would ask for a session the generated far "
                            f"end was never told to answer. Either drop bfd, or "
                            f"teach {PEER_TYPES[ftype]} to render it.")

    # 4. a shared grant (the same VIP or the same delegation handed to more
    # than one firewall) is the ECMP / failover knob, and either outcome is
    # fine as long as it's INTENTIONAL:
    #   - all owners at equal/absent local_pref -> the ERs install ECMP (default)
    #   - all owners at distinct local_pref     -> deterministic primary/backup
    # The one thing that's NOT deterministic is a MIX: some owners with an
    # explicit local_pref and some without. RouterOS gives an unset peer the
    # default local-pref, so a "50 vs unset" pair is really "50 vs 100" by
    # accident: you meant one thing and got another. Refuse only that.
    for key, owners in vip_owners.items():
        if len(owners) < 2:
            continue
        prefs = [o.get("local_pref") for o in owners]
        names = ", ".join(o["name"] for o in owners)
        set_prefs = [p for p in prefs if p is not None]
        if set_prefs and len(set_prefs) != len(prefs):
            errs.append(
                f"Grant {key.split(':')[0]} is claimed by more than one firewall ({names}) with a "
                f"MIX of explicit and absent local_pref {prefs}. Set local_pref on "
                f"ALL of them (distinct -> primary/backup) or NONE of them (equal "
                f"-> ECMP); a partial set silently pairs your value against "
                f"RouterOS's default and picks a winner you did not intend.")

    # ---- external peers ------------------------------------------------
    # The security boundary for a peer is its inbound chain, exactly as it's
    # for a customer firewall: with one difference that changes the default:
    # a firewall is granted space WE delegated to it, so an empty grant is
    # obviously wrong. A peer advertises space we don't own, so the question
    # isn't "did we grant this" but "is there anything at all between this
    # session and our table". Every refusal below is one of those somethings.
    peers = d.get("peers") or []
    realms = d.get("realms") or {}

    # An ASN may belong to exactly one party. The upstreams and the customer
    # firewalls already reserve theirs; a peer reusing one would produce two
    # sessions RouterOS can't tell apart in a path.
    reserved = {topo["asn"]: "this AS"}
    for b in d["brs"]:
        if b.get("peer_asn"):
            reserved.setdefault(b["peer_asn"], f"{b['fqdn']} upstream")
    for fw in d["firewalls"]:
        if fw.get("asn"):
            reserved.setdefault(fw["asn"], f"firewall/{fw['name']}")

    def _private_asn(a):
        return any(lo <= a <= hi for lo, hi in PRIVATE_ASN_RANGES)

    # Realm-level problems, reported once rather than once per peer.
    for rname, rec in sorted(realms.items()):
        for e in rec.get("errors", []):
            errs.append(e)
        # A leak between a VRF realm and main is refused BY NAME rather than
        # ignored, because someone will eventually ask for it and the reason
        # it can't be had is specific: DN42's 172.20.0.0/14 already contains
        # this AS's own ER WAN addressing.
        raw = rec.get("raw") or {}
        for key in ("leak", "route_leak", "import_into_main", "leak_to_main"):
            if key in raw:
                errs.append(
                    f"{rname}.{key} is refused. The VRF is the whole safety "
                    f"property here: DN42's 172.20.0.0/14 contains this AS's "
                    f"own ER WAN addressing (172.20.101.11), so a route from "
                    f"that space in the main table would blackhole er1's own "
                    f"WAN. There is no supported way to open this table.")

    dn42 = realms.get("dn42") or {}
    if dn42.get("enabled"):
        asn = dn42.get("asn")
        if not isinstance(asn, int) or isinstance(asn, bool) \
                or not (DN42_ASN_MIN <= asn <= DN42_ASN_MAX):
            errs.append(
                f"dn42.asn {asn!r} must be an int in "
                f"{DN42_ASN_MIN}..{DN42_ASN_MAX}. Register the ASN in the DN42 "
                f"registry FIRST -- the IPv4 block, the /48 and every ROA are "
                f"keyed to it.")
        for key, space in (("prefix", DN42_V4), ("prefix_v6", DN42_V6)):
            val = dn42.get(key)
            if not val:
                continue
            net = ipaddress.ip_network(val, strict=False)
            outer = ipaddress.ip_network(space)
            if net.version != outer.version or not net.subnet_of(outer):
                errs.append(
                    f"dn42.{key} {net} is outside {space}. A prefix outside "
                    f"DN42's registry space is not a DN42 object, and putting "
                    f"it in the dn42 table means DN42's filters are guarding "
                    f"something DN42 never allocated.")
                continue
            # The collision that makes the VRF necessary. ER WAN addressing
            # lives outside the /24 so it never reaches the seen_ip sweep.
            # Which is exactly why it has to be checked here explicitly.
            for er in d["ers"]:
                for w in er.get("wans", []) or []:
                    if not w.get("address"):
                        continue
                    a = ipaddress.ip_interface(w["address"]).ip
                    if a.version == net.version and a in net:
                        errs.append(
                            f"dn42.{key} {net} contains {a} "
                            f"({er['fqdn']}/{w['id']} WAN). DN42's "
                            f"172.20.0.0/14 already overlaps this AS's own ER "
                            f"WAN addressing -- that is why DN42 lives in a "
                            f"VRF -- and your registered block must not make "
                            f"the collision worse by covering an address we "
                            f"actually forward to.")

    for group, rec in sorted((d.get("rpki") or {}).items()):
        if not rec["usable"]:
            errs.append(
                f"rpki.{group}: no cache address. `rpki-verify` against a group "
                f"with no source returns 'unknown' for every prefix, and these "
                f"chains accept 'unknown' -- so the validation would look "
                f"configured and do nothing. Give it an address or remove the "
                f"block.")

    seen_peer_name, seen_peer_index, seen_peer_port = {}, {}, {}
    our_v4 = ipaddress.ip_network(topo["prefix"])
    our_v6 = (ipaddress.ip_network(topo["aggregate_v6"])
              if topo.get("aggregate_v6") else None)
    dn42_nets = {4: ipaddress.ip_network(DN42_V4),
                 6: ipaddress.ip_network(DN42_V6)}

    for pr in peers:
        who = f"peer/{pr.get('name') or '?'}"

        # Anything build()/build_peer_claims couldn't make sense of. Reported
        # first and then moved past: the checks below can't say anything
        # useful about a peer that never became one.
        for e in pr.get("derive_errors", []):
            errs.append(f"{who}: {e}")
        for e in pr.get("claim_errors", []):
            errs.append(f"{who}: {e}")

        name, index = pr.get("name"), pr.get("index")
        if name:
            if name in seen_peer_name:
                errs.append(f"DUPLICATE peer name {name!r}")
            seen_peer_name[name] = True
        if isinstance(index, int) and not isinstance(index, bool):
            if index in seen_peer_index:
                errs.append(
                    f"{who}: index {index} is already used by "
                    f"peer/{seen_peer_index[index]}. An index is a FIXED SLOT "
                    f"driving the listen port and the /127 offset; allocate the "
                    f"next free one and never reuse a retired peer's.")
            else:
                seen_peer_index[index] = name

        realm = pr.get("realm")

        # --- ASN ---------------------------------------------------------
        asn = pr.get("asn")
        if not isinstance(asn, int) or isinstance(asn, bool) or not (1 <= asn <= 4294967294):
            errs.append(f"{who}: asn {asn!r} must be an integer AS number")
        else:
            if asn in reserved:
                errs.append(
                    f"{who}: asn {asn} is already {reserved[asn]}. One ASN, one "
                    f"party: two sessions claiming the same AS produce paths "
                    f"this router cannot tell apart.")
            if realm == "internet" and _private_asn(asn):
                errs.append(
                    f"{who}: realm 'internet' with asn {asn}, which is private "
                    f"(RFC 6996). A settlement-free peer whose routes enter the "
                    f"production table speaks a registered ASN -- a private one "
                    f"carries a path nobody outside this AS can interpret, and "
                    f"is not something an IRR or PeeringDB can be pointed at.")
            if realm == "dn42" and not (DN42_ASN_MIN <= asn <= DN42_ASN_MAX):
                errs.append(
                    f"{who}: realm 'dn42' with asn {asn}, outside "
                    f"{DN42_ASN_MIN}..{DN42_ASN_MAX}. A DN42 peer's ASN is a "
                    f"registry object; one outside that range is not in the "
                    f"registry and its routes will not be ROA-valid.")

        # --- keys that belong to a realm that isn't this one -------------
        declared = pr.get("_declared") or frozenset()
        for key in ("isolated", "no_export"):
            if key in declared and realm != "3p":
                errs.append(
                    f"{who}: `{key}` is a 3p key and this peer is realm "
                    f"{realm!r}. An internet peer's routes are in the main "
                    f"table by definition, and a dn42 peer's are in dn42's.")

        # --- secrets and derived values ----------------------------------
        for key in ("md5_key", "psk_key", "preshared_key", "private_key"):
            if key in declared or key in (pr.get("remote") or {}):
                errs.append(
                    f"{who}: `{key}` is a plaintext secret in a COMMITTED file. "
                    f"Set `md5: true` / `psk: true` instead -- the value is "
                    f"generated into keys.json (gitignored, mode 600) and "
                    f"rendered only into out/*.rsc. topology.yml's own header "
                    f"says it holds no secrets; bgp_auth_key already breaks "
                    f"that promise and is not a precedent to copy.")
        for key in ("listen_port", "interface", "iface"):
            if key in declared:
                errs.append(
                    f"{who}: `{key}` is DERIVED, not declared -- it falls out "
                    f"of `index`. Remove it; if you need a different value, "
                    f"change the index.")

        # --- transport ----------------------------------------------------
        remote = pr.get("remote") or {}
        transport = pr.get("transport")
        if transport in ("gre", "gre6") and not remote.get("endpoint"):
            errs.append(
                f"{who}: transport {transport!r} with no remote.endpoint. GRE "
                f"has no handshake and no NAT traversal, so the far end must be "
                f"a fixed reachable address. WireGuard is the transport for "
                f"anything that dials us.")
        if transport == "wireguard" and not remote.get("public_key"):
            errs.append(f"{who}: transport 'wireguard' with no "
                        f"remote.public_key -- there is nothing to encrypt to.")
        if remote.get("endpoint"):
            try:
                ipaddress.ip_address(str(remote["endpoint"]))
            except ValueError:
                errs.append(
                    f"{who}: remote.endpoint {remote['endpoint']!r} is not an IP "
                    f"address. It becomes a recursion-guard /32 and a firewall "
                    f"source, neither of which can hold a hostname.")

        # --- link addressing ----------------------------------------------
        for key in ("local", "address"):
            val = remote.get(key)
            if not val:
                continue
            try:
                a = ipaddress.ip_address(str(val))
            except ValueError:
                errs.append(f"{who}: remote.{key} {val!r} is not an IP address")
                continue
            if a.version == 4 and a in our_v4:
                errs.append(
                    f"{who}: remote.{key} {a} is inside {our_v4}. `blocks:` "
                    f"allocates all 256 addresses of that /24 -- there is no v4 "
                    f"left for a peering link and there will not be one without "
                    f"renumbering live links. Take the /31 from the peer, or "
                    f"run this session v6-only, which is a complete session.")

        # --- the cone -----------------------------------------------------
        claims = (pr.get("claims") or []) + (pr.get("claims6") or [])
        for c in claims:
            net = ipaddress.ip_network(c["prefix"])
            ours = our_v4 if net.version == 4 else our_v6
            if ours is not None and net.version == ours.version \
                    and (net.subnet_of(ours) or ours.subnet_of(net)):
                errs.append(
                    f"{who}: import prefix {net} overlaps our own {ours}. "
                    f"Accepting our own space back from a peer is a hijack of "
                    f"ourselves -- and with peer routes preferred over transit, "
                    f"it would win against our own origination.")
            in_dn42 = (net.version in dn42_nets
                       and net.subnet_of(dn42_nets[net.version]))
            if realm == "dn42" and not in_dn42:
                errs.append(
                    f"{who}: import prefix {net} is outside DN42's registry "
                    f"space. A dn42 session that accepts non-DN42 space puts it "
                    f"in the dn42 table under DN42's ROA filters, which have "
                    f"nothing to say about it.")
            if realm != "dn42" and in_dn42:
                errs.append(
                    f"{who}: import prefix {net} is inside DN42's "
                    f"{dn42_nets[net.version]} but this peer is realm {realm!r}. "
                    f"That space is not globally routable, and in the main "
                    f"table it would shadow this AS's own ER WAN addressing.")

        # A cone for a family this session doesn't run is dead config, and
        # the likeliest cause is the one worth naming: the operator wrote a v4
        # cone and forgot that a v4 link has to be peer-supplied, so the
        # session came out v6-only and the v4 grant does nothing.
        fams = pr.get("families") or []
        for fam, key in ((4, "claims"), (6, "claims6")):
            if (pr.get(key) or []) and fam not in fams:
                extra = ("" if fam != 4 else
                         " A v4 session needs remote.address + remote.local, "
                         "peer-supplied -- `blocks:` leaves no v4 in this AS "
                         "for a peering link.")
                errs.append(
                    f"{who}: import.prefixes has IPv{fam} entries but this "
                    f"session runs {fams or 'no family'}, so that grant is "
                    f"never applied to anything.{extra}")

        # --- the max-prefix limit ------------------------------------------
        # REQUIRED, never derived. For a customer, capacity arithmetic gives a
        # real bound because we delegated the block. For a peer it doesn't: a
        # /29 accepted to /48 has a worst case of 2^20 routes, which is a
        # formality and not a limit. How many prefixes a peer actually sends is
        # an operational fact they tell you, so this file has to hold it.
        for fam, key in ((4, "max_routes"), (6, "max_routes_v6")):
            if fam not in (pr.get("families") or []):
                continue
            lim = pr.get(key)
            if not isinstance(lim, int) or isinstance(lim, bool) or lim < 1:
                worst = sum(c["capacity"] for c in
                            (pr["claims"] if fam == 4 else pr["claims6"]))
                errs.append(
                    f"{who}: import.{key} is required for this IPv{fam} session "
                    f"and is {lim!r}. It is the only hard bound between this "
                    f"session and a CHR's RAM"
                    + (f" -- the declared cone's worst case is {worst} routes, "
                       f"which is a formality, not a limit" if worst else
                       " -- and with no cone declared there is nothing for the "
                       "pre-storage filter to match on either")
                    + ". State the number the peer told you, with headroom.")

        # --- listen ports are unique per BR ---------------------------------
        for l in pr.get("links", []):
            slot = (l["br"], l["listen_port"])
            if slot in seen_peer_port:
                errs.append(
                    f"{who}: listen port {l['listen_port']} on {l['br']} "
                    f"collides with peer/{seen_peer_port[slot]}")
            else:
                seen_peer_port[slot] = pr.get("name")

    # ---- traffic engineering ------------------------------------------
    # Two independent axes, both OPTIONAL, both ALL-OR-NOTHING across the BRs.
    #
    # The all-or-nothing rule is the same refusal the shared-grant check above
    # makes, for the same reason: a `te.local_pref: 200` on br1 and no `te` at
    # all on br2 does work, but only by pairing your number against RouterOS's
    # default of 100: a value you never wrote down and can't see in this
    # file. Making the loser state its 100 (or its `prepend: 0`) costs one line
    # and makes the intent readable at the point of change. The same goes for a
    # third BR added later: the check fails the build instead of silently
    # leaving the newcomer on defaults.
    #
    # What is deliberately NOT checked: whether ingress and egress prefer the
    # SAME BR. In via br1 and out via br2 is a supported configuration here.
    # Transit on the BRs is notrack'd so no BR holds state a return path could
    # miss, and the customer firewall stays on-path in both directions whichever
    # BR carries which half. See docs/traffic-engineering.md.
    for r in d["brs"]:
        te = r.get("te")
        if te is None:
            continue
        if not isinstance(te, dict):
            errs.append(f"{r['fqdn']}: te must be a mapping with keys "
                        f"{list(TE_KEYS)}, got {te!r}")
            continue
        for k in te:
            if k not in TE_KEYS:
                errs.append(f"{r['fqdn']}: unknown te key {k!r}; allowed keys "
                            f"are {list(TE_KEYS)}")
        pp = te.get("prepend")
        if pp is not None:
            # bool is an int in Python and `prepend: yes` is a plausible typo,
            # so it has to be excluded explicitly or it renders as prepend 1.
            if not isinstance(pp, int) or isinstance(pp, bool) or not (0 <= pp <= 10):
                errs.append(f"{r['fqdn']}: te.prepend={pp!r} must be an int in "
                            f"0..10. RouterOS accepts up to 16, but past ~5 you "
                            f"are adding AS_PATH length that no one acts on.")
        lp = te.get("local_pref")
        if lp is not None:
            if not isinstance(lp, int) or isinstance(lp, bool) or not (0 <= lp <= 4294967295):
                errs.append(f"{r['fqdn']}: te.local_pref={lp!r} must be an int "
                            f"in 0..4294967295")

    for key in TE_KEYS:
        have = [r["name"] for r in d["brs"]
                if isinstance(r.get("te"), dict) and r["te"].get(key) is not None]
        missing = [r["name"] for r in d["brs"] if r["name"] not in have]
        if have and missing:
            errs.append(
                f"te.{key} is set on {have} but not on {missing}. Set it on "
                f"EVERY border router or none of them -- including the explicit "
                f"losing value on the preferred one "
                f"({'prepend: 0' if key == 'prepend' else 'local_pref: 100'}), "
                f"so the comparison is written down instead of inherited from "
                f"a RouterOS default.")

    # origination.mode picks anchor-guard's customer signal, and a typo here
    # must not fall through to either branch: `Home` silently rendering anchor
    # mode is a kill switch that does nothing on the day it's pulled.
    orig = topo["origination"]
    if orig.get("shape_error"):
        errs.append(f"origination: {orig['mode']!r} must be a mapping, e.g. "
                    f"`origination: {{ mode: home, arm_guard: false }}`.")
    elif orig["mode"] not in ("anchor", "home"):
        errs.append(f"origination.mode={orig['mode']!r} must be 'anchor' or "
                    f"'home'.")
    if not isinstance(orig.get("arm_guard"), bool):
        errs.append(f"origination.arm_guard={orig.get('arm_guard')!r} must be "
                    f"true or false. It decides whether anchor-guard runs at "
                    f"all, so it is not a value to guess at.")

    # multipath is written to /routing/bgp/instance VERBATIM, and the property
    # is typed `num` there: a COUNT of ECMP routes to install, not a switch.
    # `true` is rejected rather than helpfully rendered as `yes`, because `yes`
    # is what the router refuses: the import aborts on that line and every
    # /routing/bgp object below it's silently never created. That failure
    # arrives AFTER reset-configuration has wiped the box, so it gets a
    # build-time error and a blunt message.
    mp = topo["bgp_multipath"]
    if mp is True:
        errs.append("bgp_multipath: true is not a value. /routing/bgp/instance "
                    "multipath is a COUNT (type `num`), so `yes` is a type "
                    "error that ABORTS the import -- and the box has already "
                    "been reset by then, so it comes back with no BGP at all. "
                    "Use the number of ECMP next-hops you want (2 for two BRs).")
    elif not (mp is False
              or (isinstance(mp, int) and not isinstance(mp, bool) and 2 <= mp <= 16)):
        errs.append(f"bgp_multipath={mp!r} must be false or an int in 2..16 "
                    f"(the number of ECMP next-hops to install). 1 is not a "
                    f"value: that is `false`.")

    # wan_queue is written VERBATIM into `/queue/interface set ... queue=`, and
    # a name that doesn't resolve to a real /queue/type FAILS AT IMPORT. On a
    # box reset-configuration has already wiped, so every line after it (all of
    # /routing/bgp, every tunnel) never runs and the BR comes back dark.
    #
    # The trap this exists to catch is specific and was hit during design:
    # `fq-codel` is a KIND, not a type name. There's no stock /queue/type
    # called `fq-codel`, so the obvious-looking `wan_queue: fq-codel` bricks the
    # router. Valid values are therefore exactly the stock names below, or the
    # custom type wan_aqm creates.
    #
    # ROS_QUEUE_TYPES is read off a live 7.24.1 (`/queue/export verbose`), not
    # from documentation: same sourcing rule as ROS_POLICIES above.
    aqm_name = topo["wan_aqm"]["name"]
    for r in d["brs"]:
        q = r["wan_queue"]
        if not isinstance(q, str) or not q.strip():
            errs.append(f"{r['fqdn']}: wan_queue={q!r} must be a non-empty "
                        f"string naming a /queue/type entry.")
        elif q not in ROS_QUEUE_TYPES and q != aqm_name:
            hint = ""
            if q in ROS_QUEUE_KINDS:
                hint = (f" `{q}` is a queue KIND, not a type NAME -- there is no "
                        f"stock /queue/type called that. Set wan_aqm.name to a "
                        f"type the template creates, or pick a stock name.")
            errs.append(f"{r['fqdn']}: wan_queue={q!r} is not a stock "
                        f"/queue/type and is not wan_aqm.name ({aqm_name!r}). "
                        f"It is written verbatim into `/queue/interface set`, "
                        f"and an unresolvable name aborts the import AFTER "
                        f"reset-configuration has wiped the box.{hint}")

    # Every WG endpoint a router dials must have a specific route on that router.
    for br in d["brs"]:
        for sib in br["sibling_publics"]:
            if not sib["wan_address"]:
                errs.append(f"{br['fqdn']}: sibling {sib['name']} has no "
                            f"wan_address; the backbone endpoint cannot be pinned")

    # Every ER WAN needs an outer-port range, or its tunnels are neither pinned
    # to that WAN nor source-corrected for it. See the mangle/srcnat pair in
    # er.rsc.j2. derive() only assigns one for ids it knows.
    for er in d["ers"]:
        for wan in er["wans"]:
            if "wg_ports" not in wan:
                errs.append(
                    f"{er['fqdn']}: WAN id {wan['id']!r} has no derived "
                    f"outer-port range. The 518xx/519xx bases come from "
                    f"wan_ids in derive(); a new WAN needs an entry there "
                    f"before it can be rendered.")

            # A static WAN needs BOTH halves or the box has no path off-site:
            # an address with no gateway routes nothing, a gateway with no
            # address is unreachable. Absent both = DHCP, which is fine.
            #
            # This one renders CLEAN and is invisible in the .rsc: address-only
            # gives you an address on the interface, no default in via-<id>, and.
            # Because the BR-public /32 pins are gated on wans[0].gateway.
            # No pins either. Same check the sites get below; the ERs went
            # without it until wan1 moved onto the ISP gateway's LAN (§25).
            if ("address" in wan) != ("gateway" in wan):
                errs.append(
                    f"{er['fqdn']}: wan {wan['id']!r} has "
                    f"{'address' if 'address' in wan else 'gateway'} but "
                    f"not the other. Set both (static) or neither "
                    f"(dhcp-client).")
            elif "address" in wan:
                # And if it IS static, the gateway has to be on-link. A typo
                # here survives the render and the import, then leaves the ER
                # with no route off the WAN at all. The BRs have had this
                # check since day one (see "BR WAN" above), the ERs haven't.
                try:
                    wan_net = ipaddress.ip_network(wan["address"], strict=False)
                    if ipaddress.ip_address(wan["gateway"]) not in wan_net:
                        errs.append(
                            f"{er['fqdn']}: wan {wan['id']!r} gateway "
                            f"{wan['gateway']} is not inside {wan_net} "
                            f"(from address {wan['address']}). Wrong prefix or "
                            f"wrong gateway -> no default route in via-"
                            f"{wan['id']} and no path off this WAN.")
                except ValueError as e:
                    errs.append(f"{er['fqdn']}: wan {wan['id']!r} bad "
                                f"addressing ({e})")

    # --- remote sites ---------------------------------------------------
    # A site router is a member of AS64500 with a tunnel to every BR and a
    # customer /29 hanging off it. The checks that matter are the ones that
    # can't be seen by reading the rendered config: the v4 tunnel budget, and
    # whether a delegation has landed on top of something else.
    sites = d["sites"]
    for s in sites:
        who = f"site/{s.get('name', '?')}"
        for e in s.get("derive_errors", []):
            errs.append(f"{who}: {e}")

    names = {}
    router_names = {r["name"] for r in d["brs"] + d["ers"]}
    site_codes = {r["site"] for r in d["brs"] + d["ers"]}
    indexes = {}
    for s in live_sites:
        who = f"site/{s['name']}"
        n = s["name"]
        if n in names:
            errs.append(f"DUPLICATE site name {n!r}: two entries in sites:")
        names[n] = s
        # The site code is a DNS label ({interface}.{router}.{site}) and the
        # keystore identity is built from it, so it may not shadow an existing
        # router name or an existing site code.
        if n in router_names:
            errs.append(f"{who}: name {n!r} is already a router name; the fqdn "
                        f"{s['fqdn']} and its DNS records would collide")
        if n in site_codes:
            errs.append(f"{who}: name {n!r} is already the site code of a BR or "
                        f"ER ({', '.join(sorted(site_codes))}); interface DNS "
                        f"names are {{interface}}.{{router}}.{{site}} and would "
                        f"land in the same zone branch")
        if s["index"] in indexes:
            errs.append(f"{who}: index {s['index']} is already used by "
                        f"{indexes[s['index']]}. Indexes are fixed slots, "
                        f"allocated sequentially and NEVER reused -- a "
                        f"decommissioned site's index stays burned.")
        indexes[s["index"]] = n

        # The delegation is the site LAN. It must be inside site_deleg and
        # nowhere near home or the infrastructure links: this is the one number
        # here that ends up on a wire full of untrusted client devices.
        deleg = ipaddress.ip_network(s["delegation"])
        sd = ipaddress.ip_network(topo["blocks"]["site_deleg"])
        if not deleg.subnet_of(sd):
            errs.append(f"{who}: delegation {deleg} is outside blocks.site_deleg "
                        f"{sd}. index {s['index']} is past the end of the block "
                        f"-- it holds {sd.num_addresses // 8} /29s.")
        for label in ("customer_home", "local_links", "backbone", "br_er_p2p",
                      "site_p2p", "loopbacks"):
            other = ipaddress.ip_network(topo["blocks"][label])
            if deleg.overlaps(other):
                errs.append(f"{who}: delegation {deleg} overlaps blocks.{label} "
                            f"{other}; client devices would be addressed out of "
                            f"infrastructure space")

        # One WAN per site today. Two would double this site's tunnel count and
        # the /28 below has no room for that, so say it here rather than let the
        # overflow check explain it in terms of /31s.
        wans = s.get("wans") or []
        if len(wans) != 1:
            errs.append(f"{who}: has {len(wans)} wans; exactly one is supported. "
                        f"A second WAN doubles this site's tunnel count and "
                        f"blocks.site_p2p ({topo['blocks']['site_p2p']}) cannot "
                        f"absorb that -- see the budget note in build().")
        wan_ifaces = set()
        for w in wans:
            if not w.get("interface"):
                errs.append(f"{who}: wan {w.get('id', '?')!r} has no interface")
                continue
            wan_ifaces.add(w["interface"])
            if "wg_ports" not in w:
                errs.append(f"{who}: wan {w.get('id', '?')!r} has no derived "
                            f"outer-port range; the mangle mark and the srcnat "
                            f"that pin its tunnels to it cannot be rendered")
            # A static WAN needs BOTH halves or the box has no path off-site:
            # an address with no gateway routes nothing, a gateway with no
            # address is unreachable. Absent both = DHCP, which is fine.
            if ("address" in w) != ("gateway" in w):
                errs.append(f"{who}: wan {w.get('id', '?')!r} has "
                            f"{'address' if 'address' in w else 'gateway'} but "
                            f"not the other. Set both (static) or neither "
                            f"(dhcp-client).")

        lan = s.get("lan_interfaces") or []
        if not lan:
            errs.append(f"{who}: lan_interfaces is empty. The delegation "
                        f"{s['delegation']} would have no interface to sit on "
                        f"and the site would route nothing.")
        for iface in lan:
            if iface in wan_ifaces:
                errs.append(f"{who}: {iface} is listed as both a WAN and a LAN "
                            f"port. Bridging the WAN into the site LAN puts the "
                            f"delegation on the ISP segment.")

    # THE V4 BUDGET. blocks.site_p2p is a /28 and every site->BR tunnel eats a
    # /31 of it. This is the check that stops a third BR silently renumbering
    # every live site link two years from now.
    if live_sites and len(d["brs"]) > d["site_br_slots"]:
        errs.append(
            f"{len(d['brs'])} border routers with {len(live_sites)} remote "
            f"site(s): sites reserve {d['site_br_slots']} /31 slot(s) each in "
            f"blocks.site_p2p ({topo['blocks']['site_p2p']}), so a BR beyond "
            f"{d['site_br_slots']} has nowhere to address its site tunnels. "
            f"Three ways out, and none of them is free: run fewer sites; "
            f"re-carve the /24 (nothing is spare -- every block is allocated); "
            f"or move site tunnels to v6-only addressing, where site_p2p is a "
            f"/60 and this constraint does not exist. Raising SITE_BR_SLOTS in "
            f"build() RENUMBERS every existing site link.")

    sp2p = ipaddress.ip_network(topo["blocks"]["site_p2p"])
    sp2p6 = ipaddress.ip_network(topo["blocks_v6"]["site_p2p"]) if topo.get("blocks_v6") else None
    for t in d["site_br"]:
        for label, addr in (("br", t["br_ip"]), ("site", t["site_ip"])):
            if ipaddress.ip_address(addr) not in sp2p:
                errs.append(f"site/{t['site']} <-> {t['br']}: {label} address "
                            f"{addr} is outside blocks.site_p2p {sp2p}")
        if sp2p6 is not None and t["br_ip6"]:
            for label, addr in (("br", t["br_ip6"]), ("site", t["site_ip6"])):
                if ipaddress.ip_address(addr) not in sp2p6:
                    errs.append(f"site/{t['site']} <-> {t['br']}: {label} v6 "
                                f"address {addr} is outside blocks_v6.site_p2p "
                                f"{sp2p6}")
        if t["br_key"]["public"] == t["site_key"]["public"]:
            errs.append(f"{t['br']}<->{t['site']}: both ends share a key")

    # --- management source prefixes -------------------------------------
    # This list IS the lock on every router. An empty or malformed entry does
    # not fail loudly at deploy time. It renders a device that has already
    # wiped itself via reset-configuration and now answers nobody.
    if "mgmt_prefix" in topo:
        errs.append("topology.yml still has the old scalar `mgmt_prefix`. It "
                    "is now a list, `mgmt_prefixes` (and the templates read "
                    "only the list). Rename it.")
    mgmt = topo.get("mgmt_prefixes")
    if not isinstance(mgmt, list) or not mgmt:
        errs.append("mgmt_prefixes must be a non-empty list. It is the source "
                    "ACL for SSH and winbox on every router; rendering zero "
                    "entries produces a fleet reachable only by console.")
    else:
        for p in mgmt:
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError as e:
                errs.append(f"mgmt_prefixes: {p!r} is not a valid prefix: {e}")
                continue
            if net.version != 4:
                errs.append(f"mgmt_prefixes: {p} is v6. The management plane "
                            f"is v4-only -- the v6 input chains carry no mgmt "
                            f"accept, so this entry would do nothing.")

    ref = topo.get("mgmt_refresh")
    if ref:
        if not topo.get("mgmt_prefixes_url"):
            errs.append("mgmt_refresh is configured but mgmt_prefixes_url is "
                        "not set; the on-router script has no endpoint to poll.")
        if not topo.get("ssh", {}).get("keys_url"):
            errs.append("mgmt_refresh is configured but ssh.keys_url is not "
                        "set; the on-router script has no endpoint to poll.")
        if not re.fullmatch(r"\d+[smhd]", str(ref.get("interval", ""))):
            errs.append(f"mgmt_refresh.interval {ref.get('interval')!r} is not "
                        f"a RouterOS interval (e.g. 30m, 1h, 1d).")

    # --- resolver + clock -----------------------------------------------
    # Both of these fail the same quiet way: the router imports cleanly, comes
    # up, routes fine, and only mgmt-refresh is dead. Because it can't
    # resolve the endpoint, or can't validate its cert against a skewed clock.
    # Guard 1 turns that into a no-op and one log line nobody is reading.
    # Cheaper to refuse to render.
    resolvers = topo.get("dns_servers")
    if not isinstance(resolvers, list) or not resolvers:
        errs.append("dns_servers must be a non-empty list. RouterOS /ip/dns is "
                    "a forwarding cache with no recursion, so a router with no "
                    "upstreams resolves nothing at all -- including "
                    "mgmt_prefixes_url and ssh.keys_url.")
    else:
        for s in resolvers:
            try:
                ipaddress.ip_address(str(s))
            except ValueError:
                errs.append(f"dns_servers: {s!r} is not a bare IP address. "
                            f"RouterOS wants addresses here, not prefixes or "
                            f"names; a bad entry fails the import partway "
                            f"through, on a router that has already run "
                            f"reset-configuration.")

    ntp = topo.get("ntp_servers")
    if not isinstance(ntp, list) or not ntp:
        errs.append("ntp_servers must be a non-empty list. Both fetch URLs run "
                    "check-certificate=yes, and an unsynced clock fails cert "
                    "validation on every one of them.")
    else:
        for s in ntp:
            s = str(s)
            try:
                ipaddress.ip_address(s)
                continue
            except ValueError:
                pass
            # RouterOS 7 takes hostnames here too. Only reject what would break
            # the comma-joined list or is plainly not a name.
            if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", s):
                errs.append(f"ntp_servers: {s!r} is neither an IP address nor a "
                            f"hostname.")

    # --- SNMPv3 -----------------------------------------------------------
    # Refusals, not warnings. This block opens a UDP port on routers whose WAN
    # faces the DFZ, and every way of getting it wrong ends somewhere worse
    # than "monitoring is broken": a v1 community, a cleartext passphrase, or a
    # source list wide enough to make a CHR somebody else's amplifier.
    snmp = topo.get("snmp")
    if snmp is not None and not isinstance(snmp, dict):
        errs.append(f"snmp must be a mapping or absent, not {type(snmp).__name__}. "
                    f"Omit the block entirely to render no SNMP at all.")
    elif snmp:
        if not isinstance(snmp.get("enabled"), bool):
            errs.append(f"snmp.enabled={snmp.get('enabled')!r} must be true or "
                        f"false. It is the arm switch for a listening service; "
                        f"a truthy string is not an answer to that question.")

        user = str(snmp.get("user", ""))
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", user):
            errs.append(f"snmp.user {user!r} must be 1-32 characters of "
                        f"[A-Za-z0-9._-] starting alphanumeric. It is rendered "
                        f"unquoted into /snmp/community and keys the passphrase "
                        f"pair in keys.json.")
        elif user.lower() == "public":
            errs.append("snmp.user 'public' is the name of the default v1/v2c "
                        "community, which the template neutralises BY NAME "
                        "(read-access=no). Naming your v3 user the same thing "
                        "would have every router disable it on import.")

        contact = str(snmp.get("contact", ""))
        if '"' in contact or "\\" in contact:
            errs.append(f"snmp.contact {contact!r} contains a quote or a "
                        f"backslash. It is rendered inside a quoted RouterOS "
                        f"string, and breaking out of that quoting does not "
                        f"produce a syntax error you find in review -- it "
                        f"produces a failed /import on a router that has "
                        f"already run reset-configuration.")

        # MD5 and DES are named individually because "not in the allowed set"
        # is the wrong error for them: they aren't typos, they are a choice,
        # and the answer isn't "pick another one" but "no".
        auth = str(snmp.get("auth_protocol", "")).upper()
        if auth == "MD5":
            errs.append("snmp.auth_protocol MD5 is refused. It is the RouterOS "
                        "default and it is the reason SNMPv3 has the reputation "
                        "it has. SHA1 costs nothing more, is equally documented, "
                        "and every poller including Zabbix speaks it.")
        elif auth not in ("SHA1", "SHA256", "SHA512"):
            errs.append(f"snmp.auth_protocol {snmp.get('auth_protocol')!r} is not "
                        f"one of SHA1, SHA256, SHA512. MikroTik documents only "
                        f"MD5|SHA1; SHA256/SHA512 exist on newer builds and must "
                        f"be verified on a live box before you commit them.")

        priv = str(snmp.get("encryption_protocol", "")).upper()
        if priv == "DES":
            errs.append("snmp.encryption_protocol DES is refused. 56-bit keys, "
                        "broken in public for thirty years, and it is what "
                        "RouterOS picks if you say nothing. AES is the only "
                        "other value MikroTik documents -- use it.")
        elif priv != "AES":
            errs.append(f"snmp.encryption_protocol {snmp.get('encryption_protocol')!r} "
                        f"is not AES. That is the only strong value MikroTik "
                        f"documents for /snmp/community, and Zabbix calls the "
                        f"same algorithm AES128.")

        srcs = snmp.get("sources")
        if not isinstance(srcs, list):
            errs.append("snmp.sources must be a list of IPv4 prefixes -- the "
                        "sources allowed to reach udp/161 in every input chain.")
        else:
            todo = [x for x in srcs if str(x).upper() == "REPLACE-ME"]
            real = [x for x in srcs if str(x).upper() != "REPLACE-ME"]
            if snmp.get("enabled") is True:
                if todo:
                    errs.append("snmp.sources still contains REPLACE-ME with "
                                "snmp.enabled=true. Put the poller's address "
                                "there -- as the ROUTERS see it -- before arming "
                                "the agent.")
                if not real:
                    errs.append("snmp.enabled=true with no source prefixes. The "
                                "input-chain accept would match nothing and every "
                                "poll would be dropped by the terminal rule; the "
                                "agent would listen for a poller that can never "
                                "arrive.")
            for pfx in real:
                try:
                    net = ipaddress.ip_network(str(pfx), strict=False)
                except ValueError as e:
                    errs.append(f"snmp.sources: {pfx!r} is not a valid prefix: {e}")
                    continue
                if net.version != 4:
                    errs.append(f"snmp.sources: {net} is v6. The v6 input chains "
                                f"carry no management hole by design -- this entry "
                                f"would punch the first one. Poll over v4; the "
                                f"loopbacks are reachable from everywhere inside "
                                f"the AS.")
                elif net.prefixlen == 0:
                    errs.append("snmp.sources: 0.0.0.0/0 is refused. udp/161 open "
                                "to the internet on a public-WAN CHR is an "
                                "amplification reflector, and authPriv does not "
                                "stop the traffic -- it only stops the answer "
                                "being useful. Name the poller.")

        # engine-id-suffix is the router's fqdn (see _snmp.j2). An engine-id
        # is at most 32 octets and RouterOS spends 5 on its prefix, so the
        # suffix gets 27. Uniqueness is the whole point of rendering it: two
        # routers with one engine-id is the "only one host answers Zabbix"
        # failure, and it looks like a firewall drop, not like this.
        if snmp.get("enabled") is True:
            seen = {}
            for r in d["brs"] + d["ers"] + d["sites"]:
                fq = r.get("fqdn", "")
                if len(fq.encode()) > 27:
                    errs.append(f"{fq}: {len(fq.encode())} octets is too long for "
                                f"the SNMPv3 engine-id-suffix (27 max after "
                                f"RouterOS's 5-octet prefix). Shorten the router "
                                f"or site name.")
                if fq in seen:
                    errs.append(f"{fq}: two routers share this identity, and with "
                                f"it an SNMPv3 engine-id. Zabbix can poll only "
                                f"one of them.")
                seen[fq] = True

    return errs


# ---------------------------------------------------------------------
#  DNS record generation
# ---------------------------------------------------------------------
DOMAIN = "example.net"


def build_dns_records(topo, d):
    """Derive forward (A) and reverse (PTR) DNS records from the topology.

    Returns a list of dicts: {name, type, value, zone}
      zone = 'forward' | 'reverse'
    PTRs are only generated for IPs inside the announced /24.
    """
    records = []
    domain = topo.get("domain", DOMAIN)
    nets = {4: ipaddress.ip_network(topo["prefix"])}
    if topo.get("prefix_v6"):
        nets[6] = ipaddress.ip_network(topo["prefix_v6"])

    def a(name, ip):
        """Add a forward record: A or AAAA, chosen by the address family.
        And, if the address is inside our aggregate for THAT family, the
        matching PTR.

        The PTR name comes from reverse_pointer rather than being sliced out of
        the address string. For the /24 that's byte-for-byte what the old
        hand-rolled version produced, but it's also correct for IPv6 (where
        the name is 32 nibbles) and it stops being silently wrong the day the
        v4 prefix changes length."""
        fqdn = f"{name}.{domain}" if not name.endswith(f".{domain}") else name
        addr = ipaddress.ip_address(ip)
        rtype = "AAAA" if addr.version == 6 else "A"
        records.append({"name": fqdn, "type": rtype, "value": ip, "zone": "forward"})
        n = nets.get(addr.version)
        if n is not None and addr in n:
            zone = "reverse6" if addr.version == 6 else "reverse"
            records.append({"name": addr.reverse_pointer, "type": "PTR",
                            "value": f"{fqdn}.", "zone": zone})

    brs = d["brs"]
    ers = d["ers"]
    sites = d.get("sites") or []

    # --- Loopbacks: canonical router names ---
    # Both families share ONE name: br1.ord1 gets an A and an AAAA. Nothing
    # gets a -v6 suffix, so a dual-stack client picks its own family and a
    # traceroute reads identically either way.
    v6 = d.get("v6")
    for r in brs + ers:
        a(f"{r['name']}.{r['site']}", r["loopback"])
        if v6:
            a(f"{r['name']}.{r['site']}", r["loopback6"])
    # A site router's name is {router}.{site} like everyone else's. The site
    # code is the second label, so sr1.sfo sits exactly where er1.hdc does.
    for s in sites:
        a(s["fqdn"], s["loopback"])
        if v6:
            a(s["fqdn"], s["loopback6"])

    # --- BR↔BR backbone ---
    for link in d["bb"]:
        br_a = next(r for r in brs if r["name"] == link["a"])
        br_b = next(r for r in brs if r["name"] == link["b"])
        # Low side: interface on router a named for router b
        a(f"{link['a_if']}.{br_a['name']}.{br_a['site']}", link["a_ip"])
        # High side: interface on router b named for router a
        a(f"{link['b_if']}.{br_b['name']}.{br_b['site']}", link["b_ip"])
        if v6:
            a(f"{link['a_if']}.{br_a['name']}.{br_a['site']}", link["a_ip6"])
            a(f"{link['b_if']}.{br_b['name']}.{br_b['site']}", link["b_ip6"])

    # --- BR↔ER tunnels ---
    for t in d["br_er"]:
        br = next(r for r in brs if r["name"] == t["br"])
        er = next(r for r in ers if r["name"] == t["er"])
        # BR side: wg-er{n}-wan{n}.br{n}.site
        a(f"{t['br_if']}.{br['name']}.{br['site']}", t["br_ip"])
        # ER side: wg-br{n}-wan{n}.er{n}.site
        a(f"{t['er_if']}.{er['name']}.{er['site']}", t["er_ip"])
        if v6:
            a(f"{t['br_if']}.{br['name']}.{br['site']}", t["br_ip6"])
            a(f"{t['er_if']}.{er['name']}.{er['site']}", t["er_ip6"])

    # --- BR↔site tunnels + the site LAN gateway ---
    for t in d.get("site_br") or []:
        br = next(r for r in brs if r["name"] == t["br"])
        site = next(s for s in sites if s["name"] == t["site"])
        # BR side: wg-{site}.br{n}.{site}   site side: wg-br{n}.sr1.{site}
        a(f"{t['br_if']}.{br['name']}.{br['site']}", t["br_ip"])
        a(f"{t['site_if']}.{site['fqdn']}", t["site_ip"])
        if v6:
            a(f"{t['br_if']}.{br['name']}.{br['site']}", t["br_ip6"])
            a(f"{t['site_if']}.{site['fqdn']}", t["site_ip6"])

    # The inside default gateway. This is the address every device at the site
    # is configured with, so it's the one name there that gets looked up by a
    # human under pressure.
    for s in sites:
        a(f"br-lan.{s['fqdn']}", s["lan_gateway"])
        if v6:
            a(f"br-lan.{s['fqdn']}", s["lan_gateway6"])

    # --- Home local links ---
    home = topo["home"]
    # ER interconnect (xc_net)
    xc = ipaddress.ip_network(home["xc_net"], strict=False)
    xc_hosts = list(xc.hosts())
    for i, er in enumerate(ers):
        a(f"{er.get('xc_interface', 'ether3')}.{er['name']}.{er['site']}", str(xc_hosts[i]))

    # Transit addresses
    a(f"ether4.{ers[0]['name']}.{ers[0]['site']}", home["transit_er1"])
    a(f"ether4.{ers[1]['name']}.{ers[1]['site']}", home["transit_er2"])

    if v6:
        xc6 = ipaddress.ip_network(home["xc_net_v6"], strict=False)
        xc6_base = int(xc6.network_address)
        for i, er in enumerate(ers):
            a(f"{er.get('xc_interface', 'ether3')}.{er['name']}.{er['site']}",
              str(ipaddress.ip_address(xc6_base + i)))
        a(f"ether4.{ers[0]['name']}.{ers[0]['site']}", home["transit_er1_v6"])
        a(f"ether4.{ers[1]['name']}.{ers[1]['site']}", home["transit_er2_v6"])

    # Customer firewalls: one record per firewall per family, at its transit
    # peer address.
    for fw in d.get("firewalls", []):
        a(f"{fw['name']}.hdc", fw["peer_address"])
        if v6 and fw.get("peer_address_v6"):
            a(f"{fw['name']}.hdc", fw["peer_address_v6"])

    # --- Provider WAN addresses (forward only; PTR is set at the provider) ---
    # The v6 WAN PTR matters exactly as much as the v4 one and is equally
    # outside our zone: a v6-sourced traceroute or SMTP connection shows this
    # address, not anything we can self-manage. Set it in the provider panel.
    # Yes, by hand, in a web UI. We contain multitudes.
    for br in brs:
        a(f"ether1.{br['name']}.{br['site']}", br["wan_address"])
        if v6 and br.get("wan_v6"):
            a(f"ether1.{br['name']}.{br['site']}", br["wan_v6"]["address"])

    return records


def write_dns_csv(records, outpath):
    """Write DNS records to a CSV file."""
    with open(outpath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "type", "value", "zone"])
        for r in sorted(records, key=lambda x: (x["zone"], x["type"], x["name"])):
            writer.writerow([r["name"], r["type"], r["value"], r["zone"]])
    print(f"  -> {_rel(outpath)} ({len(records)} records)")


def write_dns_zones(topo, outpath):
    """Write a shell-sourceable file with the Route 53 zone IDs."""
    dns = topo.get("dns", {})
    with open(outpath, "w") as f:
        f.write(f'FORWARD_ZONE_ID="{dns.get("forward_zone_id", "")}"\n')
        f.write(f'REVERSE_ZONE_ID="{dns.get("reverse_zone_id", "")}"\n')
        f.write(f'REVERSE_V6_ZONE_ID="{dns.get("reverse_v6_zone_id", "")}"\n')
    print(f"  -> {_rel(outpath)}")


def write_snmp_env(topo, d, outpath):
    """Write the SNMPv3 credentials under ZABBIX'S OWN MACRO NAMES.

    Not a convenience. The passphrases exist only in keys.json, and the one
    place they have to be typed a second time is Zabbix. So the build emits
    them in the exact form Zabbix consumes (Administration -> Macros, or the
    host's own macro tab) rather than leaving an operator to transcribe two
    32-character strings out of a JSON file by eye.

    Two names differ from RouterOS on purpose and are translated here, because
    getting either wrong presents as "SNMP times out" with nothing in any log:
      * AES        -> AES128.  Zabbix distinguishes AES128/192/256; RouterOS
                      says AES and means AES128.
      * security   -> authPriv. RouterOS calls the same level `private`.
    """
    snmp = topo["snmp"]
    with open(outpath, "w") as f:
        f.write("# SNMPv3 credentials for AS64500 -- SECRET, gitignored with the rest\n")
        f.write("# of out/. Generated from keys.json; stable across builds.\n")
        f.write("#\n")
        f.write("# Zabbix: define these as global macros (Administration -> Macros),\n")
        f.write("# give each router a host with an SNMPv3 interface on the address\n")
        f.write("# below, and reference the macros in the interface's own fields.\n")
        f.write("# Then attach the stock 'Mikrotik by SNMP' template.\n")
        f.write("#\n")
        f.write("# Poll the LOOPBACK, never a WAN or tunnel address: it is the one\n")
        f.write("# address that stays up while any single link is down, and it is\n")
        f.write("# what /system/identity and the DNS records already agree on.\n")
        for r in d["brs"] + d["ers"] + d["sites"]:
            f.write(f"#   {r['fqdn']:<24} {r['loopback']}\n")
        f.write(f'SNMP_USERNAME="{snmp["user"]}"\n')
        f.write('SNMP_SECURITYLEVEL="authPriv"\n')
        f.write(f'SNMP_AUTHPROTOCOL="{str(snmp["auth_protocol"]).upper()}"\n')
        f.write(f'SNMP_AUTHPASSPHRASE="{snmp["auth_password"]}"\n')
        priv = str(snmp["encryption_protocol"]).upper()
        f.write(f'SNMP_PRIVPROTOCOL="{"AES128" if priv == "AES" else priv}"\n')
        f.write(f'SNMP_PRIVPASSPHRASE="{snmp["priv_password"]}"\n')
    os.chmod(outpath, 0o600)
    print(f"  -> {_rel(outpath)} (SNMPv3 credentials, mode 600)")


# ---------------------------------------------------------------------
#  Management SSH keys
# ---------------------------------------------------------------------
def fetch_lines(url):
    """Fetch a one-entry-per-line document and return the surviving lines.
    Blank lines and `#` comments (e.g. the sshkeys endpoint's "# Last Sync"
    header) are dropped. Shared by the SSH key and mgmt prefix endpoints so
    the two have exactly one format between them."""
    # timeout=15: long enough for a sleepy endpoint, short enough that you
    # notice it's down before your coffee gets cold.
    req = urllib.request.Request(url, headers={"Accept": "text/plain"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode()
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def resolve_mgmt_prefixes(topo):
    """Fetch mgmt_prefixes_url and put the result in topo['mgmt_prefixes_fetched'],
    leaving topo['mgmt_prefixes'] (the committed floor) untouched.

    The two stay SEPARATE all the way into the templates, which is the whole
    reason this doesn't just return one merged list. The floor renders as
    comment="mgmt-static" and is baked into the on-router script's `$floor`
    literal; fetched entries render as comment="mgmt-dynamic". Merge them here
    and every address the endpoint happened to be serving at build time would
    become permanent on the router. Unprunable by mgmt-refresh, and silently
    re-added to the service ACL forever after the endpoint stopped listing it.
    Build-time and run-time have to agree on which entries are revocable.

    Union, never replace. The floor is the access you committed to git; the
    endpoint may only ADD to it. That asymmetry is what makes a broken or
    hostile endpoint a non-event: the worst it can do is fail to widen your
    access, never narrow it. The cost is that revoking a *committed* prefix
    needs an edit + rebuild + redeploy. Correct for break-glass entries,
    which is the only thing that belongs in the floor.

    A fetch failure is a WARNING, not a fatal error, for the same reason: the
    build degrades to the floor, which is by construction safe. Making it
    fatal would mean an unreachable endpoint blocks an emergency config push,
    which is exactly when you least want a new dependency."""
    floor = topo["mgmt_prefixes"]
    topo["mgmt_prefixes_fetched"] = []
    url = topo.get("mgmt_prefixes_url")
    if not url:
        return

    try:
        fetched = fetch_lines(url)
    except Exception as e:
        print(f"\n  !! mgmt: fetch from {url} FAILED: {e}\n"
              f"  !! Rendering with the committed floor ONLY "
              f"({', '.join(floor)}).\n"
              f"  !! Any address that exists only at the endpoint will NOT be\n"
              f"  !! able to reach these routers. Re-run once it is back.\n",
              file=sys.stderr)
        return

    # Validate before merging: a malformed entry renders an ACL RouterOS will
    # reject mid-import, which on this fleet means a half-configured router
    # you can only reach by console.
    added = []
    for entry in fetched:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError as e:
            print(f"mgmt: {url} returned an invalid prefix {entry!r}: {e}",
                  file=sys.stderr)
            sys.exit(1)
        if net.version != 4:
            print(f"mgmt: {url} returned a v6 prefix {entry}. The management "
                  f"plane is v4-only (the v6 input chains have no mgmt accept "
                  f"at all), so this would render an ACL that silently does "
                  f"nothing.", file=sys.stderr)
            sys.exit(1)
        if str(net) not in floor and str(net) not in added:
            added.append(str(net))

    topo["mgmt_prefixes_fetched"] = added
    print(f"mgmt: {len(floor)} committed + {len(added)} from {url} "
          f"= {len(floor) + len(added)} source prefix(es)")


# ---------------------------------------------------------------------
def main():
    global TOPOLOGY, KEYSTORE, OUTDIR

    ap = argparse.ArgumentParser()
    # --rotate-keys is the big red button. It's deliberately not spelled --refresh.
    ap.add_argument("--rotate-keys", action="store_true",
                    help="DESTRUCTIVE: regenerate all keys. Every peer breaks "
                         "until every router is reloaded.")
    ap.add_argument("--check", action="store_true", help="validate only")
    ap.add_argument("--force", action="store_true",
                    help="allow --rotate-keys while external peers exist. "
                         "Rotation breaks THEM too, and they will not be "
                         "watching.")
    ap.add_argument("--show-peer-secrets", metavar="NAME",
                    help="print the generated PSK and TCP-MD5 key for one "
                         "peer, for the out-of-band exchange. Deliberately a "
                         "separate invocation so an ordinary build never puts "
                         "a third party's session key on stdout or in a CI log.")

    # --- path overrides -------------------------------------------------
    # Defaults are unchanged; these exist so a test can render a MUTATED
    # topology, with a throwaway keystore, into a temp directory. Without them
    # the only way to test the validator is to edit the real topology.yml, and a
    # test suite that has to do that's one nobody runs.
    ap.add_argument("--topology", metavar="PATH",
                    help="topology file to read (default: ./topology.yml)")
    ap.add_argument("--keys", metavar="PATH",
                    help="keystore to read/write (default: ./keys.json). A "
                         "path that does not exist is CREATED, so pointing "
                         "this at a temp file gives you a throwaway fleet.")
    ap.add_argument("--out", metavar="PATH",
                    help="output directory (default: ./out)")

    # --- machine-readable validation ------------------------------------
    ap.add_argument("--json", action="store_true",
                    help="with --check, print the validation result as JSON "
                         "on stdout instead of prose. Exit status is unchanged.")

    # --- build-time fetch pinning ---------------------------------------
    # generate.py reaches out to two URLs while rendering: the management SSH
    # keys and the mgmt_prefixes endpoint. That's fine when one person renders
    # and immediately applies. It's NOT fine when a pipeline renders in one
    # job and deploys in another. The second render can pick up a different
    # answer, and the config that ships is then not the config that passed the
    # tests. Nobody would notice: both renders are individually correct.
    ap.add_argument("--pin", metavar="PATH",
                    help="write the values fetched during this render to PATH, "
                         "so a later render can reproduce it exactly.")
    ap.add_argument("--use-pin", metavar="PATH",
                    help="render from a previously written --pin file instead "
                         "of fetching. Refuses a pin taken against a different "
                         "topology.")
    args = ap.parse_args()

    if args.topology:
        TOPOLOGY = pathlib.Path(args.topology).resolve()
    if args.keys:
        KEYSTORE = pathlib.Path(args.keys).resolve()
    if args.out:
        OUTDIR = pathlib.Path(args.out).resolve()
    if args.pin and args.use_pin:
        print("--pin and --use-pin are mutually exclusive: one records a "
              "render, the other replays one.", file=sys.stderr)
        sys.exit(2)

    topo_text = TOPOLOGY.read_text()
    topo_sha = hashlib.sha256(topo_text.encode()).hexdigest()
    topo = yaml.safe_load(topo_text)

    # --- rotation is no longer only our problem --------------------------
    # Until there were peers, --rotate-keys broke a fleet we control and
    # redeploy in an afternoon. A peer holds our public key on their side, has
    # no idea we rebuilt anything, and finds out when the session has been
    # down long enough for someone to notice. That's a different decision, so
    # it takes a different flag.
    named_peers = [p for p in (topo.get("peers") or []) if isinstance(p, dict)]
    if args.rotate_keys and named_peers and not args.force:
        print("--rotate-keys REFUSED: this topology has external peers.\n\n"
              "Rotation regenerates our WireGuard keys, so every one of these "
              "sessions stops handshaking until the far end -- someone else's "
              "router, which nobody here administers -- is given the new public "
              "key. They will not be watching for it.\n",
              file=sys.stderr)
        for p in named_peers:
            contact = p.get("contact") or "no contact listed"
            print(f"  - {p.get('name', '?')} (AS{p.get('asn', '?')})  {contact}",
                  file=sys.stderr)
        print("\nTell them first, then re-run with --force.", file=sys.stderr)
        sys.exit(2)

    ks = load_keystore(rotate=args.rotate_keys)
    n_before = len(ks)

    if args.show_peer_secrets:
        want = args.show_peer_secrets
        if not any(p.get("name") == want for p in named_peers):
            print(f"no peer named {want!r} in {TOPOLOGY.name}", file=sys.stderr)
            sys.exit(1)
        # build() is what mints them, so run it before reading them back.
        build(topo, ks)
        save_keystore(ks)
        md5 = ks.get(f"bgp-md5:{want}", {}).get("key")
        print(f"peer {want} -- give these to the far end over a channel that "
              f"is not this repo:")
        for ident, entry in sorted(ks.items()):
            if ident.startswith("psk:") and f"-{want}-peer" in ident:
                print(f"  wireguard preshared-key  ({ident}): {entry['psk']}")
            if ident.endswith(f":ext-{want}"):
                print(f"  our public key           ({ident}): {entry['public']}")
        if md5:
            print(f"  tcp-md5-key                              : {md5}")
        return

    d = build(topo, ks)

    errs = validate(topo, d)
    if errs:
        if args.json:
            json.dump({"ok": False, "topology": str(TOPOLOGY),
                       "topology_sha256": topo_sha, "errors": errs},
                      sys.stdout, indent=2)
            print()
        else:
            print("VALIDATION FAILED:", file=sys.stderr)
            for e in errs:
                print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    n_new = len(ks) - n_before
    save_keystore(ks)
    if args.json and args.check:
        json.dump({"ok": True, "topology": str(TOPOLOGY),
                   "topology_sha256": topo_sha, "errors": [],
                   "routers": [r["fqdn"] for r in d["brs"] + d["ers"] + d["sites"]],
                   "keys": {"total": len(ks), "new": n_new, "reused": n_before}},
                  sys.stdout, indent=2)
        print()
        return
    print(f"keys: {len(ks)} total ({n_new} newly generated, "
          f"{n_before} reused)  [{KEYSTORE.name}, mode 600]")

    if args.check:
        print("validation OK; nothing rendered (--check)")
        return

    # --- replay a pinned render, or record this one ---------------------
    pin = None
    if args.use_pin:
        pin = json.loads(pathlib.Path(args.use_pin).read_text())
        # A pin taken against a different topology is worse than no pin: it
        # would render THIS commit's routers with THAT commit's management
        # access. Refuse rather than guess.
        if pin.get("topology_sha256") != topo_sha:
            print(f"--use-pin: {args.use_pin} was taken against a different "
                  f"topology.yml\n  pinned: {pin.get('topology_sha256')}\n  "
                  f"actual: {topo_sha}\nRe-run the build that produced the pin, "
                  f"or drop --use-pin to fetch fresh.", file=sys.stderr)
            sys.exit(1)
        print(f"pin: replaying the fetches from {args.use_pin} "
              f"(no network access this render)")

    # --- management SSH keys: fetched fresh at build time ----------------
    # Public keys, so they are pulled here rather than committed. Fetching is
    # gated behind rendering (skipped by --check) so validation stays offline.
    ssh = topo.get("ssh")
    if ssh:
        if not ssh.get("user") or not ssh.get("keys_url"):
            print("ssh: both 'user' and 'keys_url' are required", file=sys.stderr)
            sys.exit(1)
        if pin is not None:
            ssh["keys"] = pin.get("ssh_keys", [])
        else:
            try:
                ssh["keys"] = fetch_lines(ssh["keys_url"])
            except Exception as e:
                print(f"ssh: failed to fetch keys from {ssh['keys_url']}: {e}",
                      file=sys.stderr)
                sys.exit(1)
        if not ssh["keys"]:
            # The import clears the user's keys before re-adding. Rendering with
            # zero keys would wipe access and put nothing back. refuse.
            print(f"ssh: no public keys returned by {ssh['keys_url']}; refusing "
                  f"to render (would clear {ssh['user']}'s keys and add none)",
                  file=sys.stderr)
            sys.exit(1)
        print(f"ssh: {len(ssh['keys'])} public key(s) for user "
              f"'{ssh['user']}' from {ssh['keys_url']}")

    # --- management source prefixes: floor UNION endpoint -----------------
    # Same build-time-only placement as the SSH keys above, for the same
    # reason: --check stays offline. Unlike the keys this one tolerates a dead
    # endpoint (see resolve_mgmt_prefixes): the floor is always enough to
    # get back in.
    if pin is not None:
        # Same replay as the SSH keys above. The floor is never pinned. It's
        # in topology.yml, which is committed, so it comes from the file either
        # way; only the FETCHED half is frozen.
        topo["mgmt_prefixes_fetched"] = pin.get("mgmt_prefixes_fetched", [])
    else:
        resolve_mgmt_prefixes(topo)

    if args.pin:
        # Written AFTER both fetches and BEFORE any rendering, so the pin
        # describes exactly the inputs the files below are about to be built
        # from. Public keys and public prefixes only: this is an artifact, and
        # test_secrets.py asserts it stays one.
        pin_path = pathlib.Path(args.pin)
        pin_path.parent.mkdir(parents=True, exist_ok=True)
        pin_path.write_text(json.dumps({
            "topology_sha256": topo_sha,
            "ssh_keys": (topo.get("ssh") or {}).get("keys", []),
            "mgmt_prefixes_fetched": topo.get("mgmt_prefixes_fetched", []),
        }, indent=2, sort_keys=True) + "\n")
        print(f"  -> {pin_path} (build-time fetches, frozen)")

    # --- does the management ACL swallow a site's client LAN? ------------
    # `accept src-address-list=mgmt` sits above the terminal drop in every
    # input chain, so any prefix on that list is a management source no matter
    # which interface it arrives on. And the tunnels carry it to every other
    # router in the AS. At hdc that's academic: the /24 holds infrastructure
    # and VIPs behind pfSense. A remote site puts ORDINARY CLIENT DEVICES in
    # the same /24, so a broad entry here (or from the endpoint) quietly makes
    # every device someone plugs in at that site a management source.
    #
    # Computed here rather than in build() because the fetched half of the list
    # doesn't exist until now. It's a WARNING, not an error: the answer is to
    # narrow mgmt_prefixes_url, which isn't this build's call to make.
    mgmt_all = topo["mgmt_prefixes"] + topo.get("mgmt_prefixes_fetched", [])
    for s in d["sites"]:
        deleg = ipaddress.ip_network(s["delegation"])
        s["mgmt_overlap"] = [p for p in mgmt_all
                             if ipaddress.ip_network(p, strict=False).overlaps(deleg)]
        if s["mgmt_overlap"]:
            print(f"\n  !! site {s['name']}: its client LAN {deleg} is inside the "
                  f"management source list ({', '.join(s['mgmt_overlap'])}).\n"
                  f"  !! Anything plugged into that LAN is a management source "
                  f"for EVERY router in this AS.\n"
                  f"  !! Narrow mgmt_prefixes / mgmt_prefixes_url if that is not "
                  f"what you meant.\n", file=sys.stderr)

    env = Environment(loader=FileSystemLoader(ROOT / "templates"),
                      undefined=StrictUndefined,
                      trim_blocks=True, lstrip_blocks=True,
                      keep_trailing_newline=True)
    OUTDIR.mkdir(parents=True, exist_ok=True)

    for r in d["brs"]:
        out = OUTDIR / f"{r['fqdn']}.rsc"
        out.write_text(env.get_template("br.rsc.j2").render(r=r, t=topo, d=d))
        print(f"  -> {_rel(out)}")
    for r in d["ers"]:
        out = OUTDIR / f"{r['fqdn']}.rsc"
        out.write_text(env.get_template("er.rsc.j2").render(r=r, t=topo, d=d))
        print(f"  -> {_rel(out)}")
    for r in d["sites"]:
        out = OUTDIR / f"{r['fqdn']}.rsc"
        out.write_text(env.get_template("site.rsc.j2").render(r=r, t=topo, d=d))
        print(f"  -> {_rel(out)}")

    # --- customer firewall peer configs ---------------------------------
    # The OTHER end of the eBGP sessions the ERs above already carry, for any
    # firewall that declared a `type:`. Rendered from the same claims, so the
    # grant is stated once and both ends are rebuilt together.
    peer_files = []
    for fw in d["firewalls"]:
        p = fw.get("peer")
        if not p:
            continue
        if p["template"] is None:
            # A recognised dialect with no renderer yet. Say so loudly: the
            # alternative is an operator who asked for a file, got none, and
            # finds out at the console.
            print(f"\n  !! firewall/{fw['name']}: type '{p['type']}' is a known "
                  f"dialect but has no renderer yet -- no peer config written.\n"
                  f"  !! The ER side of this session rendered normally; the "
                  f"firewall side is still yours to write.\n", file=sys.stderr)
            continue
        out = OUTDIR / p["filename"]
        out.write_text(env.get_template(p["template"]).render(fw=fw, p=p,
                                                              t=topo, d=d))
        peer_files.append(out)
        print(f"  -> {_rel(out)}")

    # --- DNS records CSV ------------------------------------------------
    dns = build_dns_records(topo, d)
    write_dns_csv(dns, OUTDIR / "dns_records.csv")
    write_dns_zones(topo, OUTDIR / "dns_zones.env")

    # --- SNMPv3 credentials for the poller -------------------------------
    # Only once the agent is actually armed. Writing them during pass 1 would
    # put a live credential in out/ for a fleet that isn't yet configured to
    # accept it: and would invite someone to set Zabbix up against routers
    # that won't answer, which reads exactly like a broken firewall.
    if (topo.get("snmp") or {}).get("enabled"):
        write_snmp_env(topo, d, OUTDIR / "snmp_zabbix.env")

    # --- CI artifacts: inventory, test expectations, pipeline -------------
    # The same derived topology that just built the routers, rendered for the
    # things that DEPLOY and TEST them. Adding a border router should grow the
    # inventory, the assertion counts and the pipeline's job list on its own.
    # A fleet whose config is generated but whose tests are hand-maintained
    # drifts in exactly the place you find out about it last.
    #
    # None of these three may contain key material; see emit.py's header and
    # tests/unit/test_secrets.py, which enforces it.
    manifest = emit.build_manifest(topo, d, pinned={
        "ssh_key_count": len((topo.get("ssh") or {}).get("keys", [])),
        "mgmt_prefixes": topo["mgmt_prefixes"] + topo.get("mgmt_prefixes_fetched", []),
        "topology_sha256": topo_sha,
    })
    emit.write_manifest(manifest, OUTDIR / "manifest.json")
    print(f"  -> {_rel(OUTDIR / 'manifest.json')} "
          f"({len(manifest['routers'])} routers, test expectations)")
    emit.write_inventory(manifest, OUTDIR / "inventory.yml")
    print(f"  -> {_rel(OUTDIR / 'inventory.yml')} "
          f"(ansible; rollout order {' -> '.join(manifest['deploy_order'])})")
    emit.write_pipeline(manifest, OUTDIR / "pipeline.yml")
    print(f"  -> {_rel(OUTDIR / 'pipeline.yml')} "
          f"(gitlab child pipeline, {2 * len(manifest['deploy_order'])} rollout jobs)")

    # Customer BFD is the one feature here whose other end is a box this build
    # doesn't write. Say who is armed, at the moment the operator is looking.
    armed = [fw["name"] for fw in d["firewalls"] if fw["bfd"]]
    if armed:
        print(f"\nBFD armed toward: {', '.join(armed)}. Each of those firewalls "
              f"must already have BFD\nenabled toward BOTH ERs -- an ER asking "
              f"for a session nobody answers is the\nfailure this replaces. "
              f"Check with:  /routing/bfd/session/print")

    print("\nout/*.rsc contain PRIVATE KEYS. Never commit them.")
    if (topo.get("snmp") or {}).get("enabled"):
        print("out/snmp_zabbix.env holds the SNMPv3 passphrases (mode 600). "
              "Paste into Zabbix; do not commit.")
    print("Upload and apply:  /import file=<name>.rsc")
    print("out/manifest.json, out/inventory.yml and out/pipeline.yml hold NO "
          "keys\nand are the pipeline's artifacts. See docs/netdevops.md.")
    if peer_files:
        # Note: these are the one output here that's meant to leave
        # the building. They hold no keys. Only the grant the customer was
        # already given and the addresses it already peers with.
        print("\nout/*.conf are CUSTOMER configs: no keys, safe to hand over.")
        print("Upload:  UniFi Network -> Settings -> Routing -> BGP")


if __name__ == "__main__":
    main()
