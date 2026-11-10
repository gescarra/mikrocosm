"""
The rendered config, checked before it can reach a router.

The apply path is `reset-configuration ... run-after-reset=<fqdn>.rsc`: the box
is WIPED first and the script runs against an empty config. RouterOS stops at
the first line it rejects and everything after it never runs. So a single bad
line doesn't produce a config error. It produces a router with no firewall,
no BGP and possibly no SSH, that you can now only reach over the provider's VNC
console.

That's the failure these tests exist to catch, and it's why they check the
FILE rather than the generator's data structures. Everything here is cheap,
runs with no hardware, and gates every merge.
"""

import re

import pytest

# The order the recovery path depends on. Rendered configs must create the
# management address-list and the SSH service BEFORE they start doing anything
# that could plausibly fail: routing filters, BGP, scripts. If a later line
# blows up, at least the box is still reachable to fix it.
RECOVERY_MARKERS = ("/ip/firewall/address-list", "/ip/service")


@pytest.fixture
def fleet(built):
    return built.configs()


def code(text):
    """The config with prose removed: full-line `#` comments and the contents of
    `comment="..."` attributes.

    These templates are heavily commented, and the comments discuss exactly the
    mistakes the tests below look for. br.rsc.j2 explains at length why
    `multipath=yes` aborts an import. Grepping the raw file for a forbidden
    string therefore finds the warning against it. What we want to know is
    whether the string appears in a line RouterOS will EXECUTE."""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        out.append(re.sub(r'comment="[^"]*"', 'comment=""', line))
    return "\n".join(out)


def test_every_router_in_the_manifest_got_a_config(built, fleet):
    for fqdn in built.manifest()["routers"]:
        assert fqdn in fleet, f"{fqdn} is in the manifest but no .rsc was written"


def test_no_unrendered_jinja_survives(fleet):
    """A `{{ ... }}` reaching a router is a syntax error partway through a
    wiped box. StrictUndefined catches most of these at render time; this
    catches the ones that are syntactically valid Jinja and semantically
    nonsense, like a mis-escaped literal brace."""
    for name, text in fleet.items():
        for marker in ("{{", "{%", "{#"):
            assert marker not in text, (
                f"{name}.rsc contains an unrendered Jinja {marker}")


def test_no_placeholders_survive(fleet):
    """REPLACE-ME reaching a router is a config that reads as deliberate."""
    for name, text in fleet.items():
        low = code(text).lower()
        for marker in ("replace-me", "todo:", "fixme"):
            assert marker not in low, (
                f"{name}.rsc still contains {marker!r} on an executable line")


def test_no_python_none_leaked_into_a_config(fleet):
    """`None` is what a missing derived value renders as, and RouterOS will
    take `address=None` as far as a parse error mid-file."""
    for name, text in fleet.items():
        assert not re.search(r"=None\b", text), (
            f"{name}.rsc has a value that rendered as Python None")


def test_identity_matches_the_filename(built, fleet):
    """`deploy.yml` proves a config applied by reading /system/identity back
    and comparing it to inventory_hostname. That check is only meaningful if
    the identity in the file IS the filename."""
    for fqdn in built.manifest()["routers"]:
        assert f"/system/identity set name={fqdn}" in fleet[fqdn], (
            f"{fqdn}.rsc does not set its identity to {fqdn}; the post-deploy "
            f"verification would pass or fail for the wrong reason")


def test_management_access_is_established_before_anything_risky(built, fleet):
    """The way back in has to exist before the parts that can fail.

    Not a style preference. If a routing filter on line 700 is rejected by this
    RouterOS version, everything after it's skipped. And whether you can fix
    that over SSH or have to open a VNC console depends entirely on whether SSH
    was configured on line 40 or line 900."""
    for fqdn in built.manifest()["routers"]:
        text = fleet[fqdn]
        lines = text.splitlines()

        def first(pred):
            return next((i for i, l in enumerate(lines) if pred(l)), None)

        mgmt_at = min(
            (i for i in (first(lambda l: l.strip().startswith(m))
                         for m in RECOVERY_MARKERS) if i is not None),
            default=None)
        assert mgmt_at is not None, f"{fqdn}.rsc never configures management access"

        risky_at = first(lambda l: l.strip().startswith(
            ("/routing/filter", "/routing/bgp", "/system/scheduler")))
        assert risky_at is None or mgmt_at < risky_at, (
            f"{fqdn}.rsc configures routing/BGP (line {risky_at}) before "
            f"management access (line {mgmt_at}). A rejected line in between "
            f"leaves this box reachable only by console.")


def test_ssh_and_winbox_are_source_filtered(built, fleet):
    """Both are bound to mgmt_prefixes in the templates. An unfiltered
    management service on a router with a public WAN is the whole ballgame."""
    for fqdn, r in built.manifest()["routers"].items():
        text = fleet[fqdn]
        for svc in ("ssh", "winbox"):
            # Matches the !dynamic form the service block now uses; see
            # test_service_acls_are_set_by_non_dynamic_find for why the bare
            # `set ssh` spelling isn't safe on 7.19+.
            m = re.search(
                rf'^set \[find where !dynamic name="{svc}"\].*address=(\S+)',
                text, re.M)
            assert m, f"{fqdn}.rsc does not bind {svc} to a source list"
            assert m.group(1) not in ("0.0.0.0/0", ""), (
                f"{fqdn}.rsc leaves {svc} open to the world")


def test_multipath_is_a_count_never_a_boolean(fleet):
    """`multipath=yes` is a type error that aborts the import. The validator
    refuses it in topology.yml; this proves nothing downstream reintroduces it."""
    for name, text in fleet.items():
        assert "multipath=yes" not in code(text), (
            f"{name}.rsc contains multipath=yes, which aborts the import")


def test_the_anchor_is_a_blackhole_at_distance_254(built, fleet):
    """The origination switch. `output.network` only announces a prefix whose
    route resolves, so the anchor's PRESENCE is what makes the router announce.
    And its distance is what makes it lose to every real route."""
    for fqdn, r in built.manifest()["routers"].items():
        text = fleet[fqdn]
        for a in r["anchors"]:
            pattern = rf"add dst-address={re.escape(a['prefix'])} blackhole distance=254"
            assert re.search(pattern, text, re.I), (
                f"{fqdn}.rsc has no distance-254 blackhole for {a['prefix']} "
                f"(comment {a['comment']!r}). Without it this router either "
                f"announces nothing or announces unconditionally.")


def test_network_blackhole_is_disabled_on_originating_sessions(fleet):
    """RouterOS will invent its OWN blackhole for an announced network unless
    told not to: and that invented route makes the anchor, and therefore
    anchor-guard, a silent no-op. Every guarantee downstream rests on this
    one flag."""
    for name, text in fleet.items():
        if "output.network" not in text:
            continue
        assert "output.network-blackhole=no" in text, (
            f"{name}.rsc announces a network without network-blackhole=no; "
            f"anchor-guard would be unable to withdraw it")


def test_customer_filters_end_in_a_reject(built, fleet):
    """The inbound customer chain is a WHITELIST, and a whitelist without a
    terminal reject is an accept-all. This is the security boundary between a
    firewall's grant and the rest of the /25."""
    for fqdn, r in built.manifest()["routers"].items():
        if r["role"] != "er":
            continue
        text = fleet[fqdn]
        for c in r["customers"]:
            chain = f"cust-in-{c['name']}"
            rules = [l for l in text.splitlines() if f"chain={chain} " in l]
            assert rules, f"{fqdn}.rsc has no {chain} chain"
            assert 'rule="reject"' in rules[-1], (
                f"{fqdn}.rsc: {chain} does not end in a reject, so it accepts "
                f"anything {c['name']} advertises rather than only its grant")


def test_every_customer_grant_appears_in_its_filter(built, fleet):
    """A grant in topology.yml that never reaches the filter is a VIP the
    customer advertises and the ER silently drops. Which reads as 'BGP is
    up' from both ends."""
    for fqdn, r in built.manifest()["routers"].items():
        if r["role"] != "er":
            continue
        text = fleet[fqdn]
        for c in r["customers"]:
            for claim in c["claims"]:
                assert claim["prefix"] in text, (
                    f"{fqdn}.rsc: {c['name']}'s grant {claim['prefix']} does "
                    f"not appear in the rendered filters")


def test_mss_clamp_reaches_the_routers_that_forward_into_tunnels(built, fleet):
    """The value the validator guards is only worth guarding if it's used.

    Scoped to ERs and site routers, which is where it belongs: they are the
    boxes with a LAN on one side and a tunnel on the other, so they are the
    single point on the path that sees BOTH halves of a TCP handshake and can
    rewrite the MSS in each. A border router only ever forwards traffic that
    has already crossed one of them, so it has nothing to clamp."""
    m = built.manifest()
    clamped = 0
    for fqdn, r in m["routers"].items():
        if r["role"] not in ("er", "sr"):
            continue
        text = code(fleet[fqdn])
        assert f"new-mss={m['mss_clamp']}" in text, (
            f"{fqdn}.rsc never clamps to the v4 MSS ({m['mss_clamp']}). Ping "
            f"will be perfect and every large TCP flow over a tunnel will stall.")
        if m["v6"]:
            assert f"new-mss={m['mss_clamp_v6']}" in text, (
                f"{fqdn}.rsc never clamps to the v6 MSS ({m['mss_clamp_v6']})")
        clamped += 1
    assert clamped, "no router in this fleet forwards into a tunnel"


def test_customer_config_is_handed_over_without_keys(render, topology):
    """out/*.conf is the one output meant to leave the building. It carries the
    grant and the peer addresses and nothing else.

    The `type:` is added here rather than relied on: whether any firewall in
    topology.yml currently declares one is a live operational choice, and a
    test that quietly stops running when the last one is removed provides no
    coverage exactly when somebody is changing that code."""
    if not topology["firewalls"]:
        pytest.skip("no customer firewalls in this topology")
    topology["firewalls"][-1]["type"] = "unifi"
    topology["firewalls"][-1].pop("bfd", None)    # unifi refuses the flag
    r = render(topology)
    assert r.ok, r.output

    confs = list(r.out.glob("*.conf"))
    assert confs, "a firewall declared type: unifi but no peer config was rendered"
    for p in confs:
        text = p.read_text()
        assert "private-key" not in text.lower()
        assert "PRIVATE KEY" not in text
        assert not re.search(r"\b[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=", text), (
            f"{p.name} contains something shaped like a 32-byte base64 key")


def test_bfd_is_only_asked_for_where_it_is_permitted(built, fleet):
    """RouterOS forbids BFD on any interface not in /routing/bfd/configuration.
    `use-bfd=yes` without a matching permit is an adjacency holding a session
    that can never come up. The exact flap the feature exists to prevent."""
    for name, text in fleet.items():
        if "use-bfd=yes" not in text:
            continue
        assert "/routing/bfd/configuration" in text, (
            f"{name}.rsc asks for BFD but never permits it")


def test_no_find_predicate_compares_an_unset_boolean_to_no(fleet):
    """`find where ... blackhole=no` matches NOTHING, and says so silently.

    RouterOS leaves a boolean property UNSET on the rows where it doesn't
    apply, rather than setting it to `no`. So comparing it to `no` never
    matches: not even the healthy rows the predicate was written to find. The
    correct negation is `!blackhole`.

    This isn't a hypothetical. anchor-guard shipped with
    `dst-address=$c && active && blackhole=no` in its `delivered` loop, which
    made `delivered` permanently zero: the guard concluded no customer was
    reachable and would have withdrawn the /24 sixty ticks after anyone armed
    its scheduler. Verified on a live 7.24 border router. With the /25
    delivered by both edge routers, `blackhole=no` returned 0 and `!blackhole`
    returned 2.

    It survived review because it reads correctly in English and fails in the
    one direction nothing complains about: a silent zero.
    """
    import re

    # Only inside a `find`/`print` PREDICATE. `output.network-blackhole=no` is
    # a BGP output property, a completely different thing, and correct.
    pattern = re.compile(r"(?:find|print)[^\]\n]*?\bwhere\b[^\]\n]*?"
                         r"(?<![-\w.])(\w+)=no\b")
    offenders = []
    for name, text in fleet.items():
        for line in code(text).splitlines():
            for m in pattern.finditer(line):
                offenders.append(f"{name}.rsc: {m.group(1)}=no in `{line.strip()[:90]}`")

    assert not offenders, (
        "a find/print predicate compares a boolean property to `no`, which "
        "matches nothing:\n  " + "\n  ".join(offenders) +
        "\nUse `!<property>` instead.")


# ---------------------------------------------------------------------
#  The automation login, as it reaches the router
# ---------------------------------------------------------------------
def test_automation_user_and_key_reach_every_router(built, fleet, topology):
    """The runner needs an account on EVERY router, including any added later.
    The block lives in the shared _mgmt.j2 precisely so it can't be
    rendered on some templates and not others."""
    auto = topology.get("automation")
    if not auto:
        pytest.skip("no automation block in this topology")
    for name, text in fleet.items():
        body = code(text)
        assert f"/user add name={auto['user']}" in body, (
            f"{name}.rsc never creates the {auto['user']} account, so CI "
            f"cannot log in to this router")
        assert f"/user/ssh-keys/import user={auto['user']}" in body, (
            f"{name}.rsc creates {auto['user']} but imports no key for it -- "
            f"an account nothing can use")


def test_the_automation_group_carries_exactly_the_declared_policies(
        built, fleet, topology):
    auto = topology.get("automation")
    if not auto or auto.get("group") == "full":
        pytest.skip("builtin group")
    expected = ",".join(auto["policies"])
    for name, text in fleet.items():
        assert f"policy={expected}" in code(text), (
            f"{name}.rsc does not grant {auto['group']} the declared policy "
            f"list ({expected})")


def test_the_automation_group_grants_no_gui_or_api_path(built, fleet, topology):
    """What the narrower group actually buys. Stated honestly.

    It's NOT a security boundary. `policy` is required (RouterOS refuses
    /system/reset-configuration without it, measured on a live router), and
    `policy` is user management: this account can grant itself anything it's
    missing. An account that can run reset-configuration owns the router
    regardless.

    What the denials do buy is that a leaked key can't open WinBox, drive an
    API, capture traffic or dump secrets out of /export WITHOUT FIRST
    ESCALATING: which is a different and noisier act than doing it by
    default. That's worth having on those terms and no stronger ones.
    """
    auto = topology.get("automation")
    if not auto or auto.get("group") == "full":
        pytest.skip("builtin group")
    for closed in ("winbox", "web", "api", "rest-api", "romon", "sniff",
                   "sensitive", "password", "telnet", "local"):
        assert closed not in auto["policies"], (
            f"the automation group grants '{closed}'. If that is deliberate, "
            f"say so here; if not, it is a door the CI key should not open.")


def test_the_rendered_group_denies_everything_it_does_not_grant(built, fleet,
                                                                topology):
    """The effective group must equal the declared one, not merely include it.

    br1 was found granting `sensitive` from a render that never asked for it,
    while three other routers denied it correctly. So the group had drifted
    and nothing compared the two. Rendering the complement as explicit `!`
    denials removes the gap.
    """
    auto = topology.get("automation")
    if not auto or auto.get("group") == "full":
        pytest.skip("builtin group")
    import re
    for name, text in fleet.items():
        m = re.search(rf"/user/group add name={auto['group']} policy=(\S+)",
                      code(text))
        assert m, f"{name}.rsc does not create the {auto['group']} group"
        rendered = m.group(1).split(",")
        granted = {p for p in rendered if not p.startswith("!")}
        denied = {p[1:] for p in rendered if p.startswith("!")}
        assert granted == set(auto["policies"]), (
            f"{name}.rsc grants {sorted(granted)}, declared "
            f"{sorted(auto['policies'])}")
        assert not (granted & denied), "a policy is both granted and denied"
        for closed in ("sensitive", "winbox", "api", "rest-api", "sniff"):
            assert closed in denied, (
                f"{name}.rsc leaves '{closed}' unstated. Unstated is not the "
                f"same as denied when nobody reads the group back.")


def test_the_automation_account_survives_a_group_change(built, fleet, topology):
    """set-if-present, not add-only. Editing `group:` in topology.yml has to
    MOVE an existing account: an add-only line silently leaves the user where
    it was, and the config then disagrees with the router forever."""
    auto = topology.get("automation")
    if not auto:
        pytest.skip("no automation block in this topology")
    for name, text in fleet.items():
        body = code(text)
        assert f"/user set [find name={auto['user']}]" in body, (
            f"{name}.rsc creates {auto['user']} but never updates an existing "
            f"one, so a changed group would never take effect")


def test_no_pem_private_key_reaches_a_rendered_config(fleet):
    """The automation key is committed in topology.yml, so the one thing that
    must never happen is the wrong half being pasted there.

    Matches the PEM MARKER on executable lines, not the phrase: every rendered
    config opens with the header "CONTAINS PRIVATE KEYS. Don't commit.", which
    is a warning about the WireGuard keys further down and exactly the kind of
    prose the code() helper exists to skip."""
    for name, text in fleet.items():
        body = code(text)
        for marker in ("BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
                       "BEGIN EC PRIVATE KEY", "BEGIN PRIVATE KEY"):
            assert marker not in body, (
                f"{name}.rsc contains PEM private-key material ({marker})")


def test_every_user_add_supplies_a_password(fleet):
    """`/user/add` ABORTS THE IMPORT without a password argument.

    Measured on 7.24:
        Script Error: missing value(s) of argument(s) password (/user/add; line 144)

    That isn't a cosmetic error. reset-configuration has already wiped the box
    by the time this line runs, so an abort here leaves a router with no
    firewall, no tunnels, no BGP and (because the service ACL block may not
    have taken either) SSH open to the internet. It happened to br1.

    The trap is that the create branch is guarded by `:if ([:len [/user find
    name=X]] = 0)`, and keep-users=yes preserves accounts across the reset. So
    for an account that already exists the branch never fires and the missing
    argument stays invisible: for years, until somebody adds a NEW account
    and the first router to apply it's the one that breaks.
    """
    import re
    for name, text in fleet.items():
        for line in code(text).splitlines():
            for m in re.finditer(r"/user\s+add\s[^}]*", line):
                stanza = m.group(0)
                assert "password=" in stanza, (
                    f"{name}.rsc has a /user add with no password= argument, "
                    f"which aborts the import on a router that has already "
                    f"been wiped:\n  {stanza.strip()[:120]}")


def test_service_acls_are_set_by_non_dynamic_find(fleet):
    """`set ssh address=...` is a coin flip on RouterOS 7.19+.

    /ip/service became a PORT TABLE: it lists a dynamic row per live TCP/UDP
    port alongside the real service entries, including the SSH session the
    import is running over. A bare `set ssh` resolves to whichever row matches
    first, and when that's the dynamic one the real service silently keeps its
    default of every source address.

    Measured across the live fleet on 7.24, from identical config: er2 had the
    ACL applied; br1, br2 and er1 all had `address=[]` on both ssh and winbox.

    AD-LOG §21 documented this for the mgmt-refresh script and fixed it there.
    This block never got the same treatment.
    """
    import re
    for name, text in fleet.items():
        body = code(text)
        in_service = False
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("/ip/service"):
                in_service = True
                continue
            if stripped.startswith("/") and not stripped.startswith("/ip/service"):
                in_service = False
            if not in_service or not stripped.startswith("set "):
                continue
            assert re.search(r"set\s+\[find where !dynamic", stripped), (
                f"{name}.rsc addresses an /ip/service entry by bare name, "
                f"which may bind to a dynamic port row instead of the real "
                f"service and silently leave it open:\n  {stripped[:110]}")


def test_bandwidth_server_is_restricted_to_the_management_prefixes(
        built, fleet, topology):
    """btest defaults to enabled and open to every source address.

    That default is invisible while the input chain is intact (the terminal
    drop catches it) which is exactly why it went unstated here for so long.
    On br1, after an import aborted before the firewall block, it was the one
    thing genuinely listening to the internet.
    """
    if not topology.get("bandwidth_server", True):
        pytest.skip("bandwidth server disabled in this topology")
    mgmt = topology["mgmt_prefixes"]
    for name, text in fleet.items():
        body = code(text)
        assert "/tool/bandwidth-server" in body, (
            f"{name}.rsc never mentions the bandwidth server, so it runs at the "
            f"RouterOS default: enabled, open to every source address")
        for prefix in mgmt:
            assert prefix in body, (
                f"{name}.rsc does not restrict the bandwidth server to {prefix}")
        # Empty means EVERY v6 source, and the management plane here is v4-only.
        assert "allowed-addresses6=::1/128" in body, (
            f"{name}.rsc leaves the bandwidth server's v6 source list empty, "
            f"which permits every IPv6 address")


def test_bandwidth_server_can_be_turned_off_from_topology(render, topology):
    topology["bandwidth_server"] = False
    r = render(topology)
    assert r.ok, r.output
    body = r.config("br1.ord1")
    assert "/tool/bandwidth-server" in body
    assert "set enabled=no" in body


# ---------------------------------------------------------------------
#  Origination mode: what anchor-guard counts as "I can still deliver"
# ---------------------------------------------------------------------
def _guard(text):
    """The anchor-guard script body, from its `add name=` line to the closing
    brace that ends `source={`."""
    start = text.index("add name=anchor-guard")
    return text[start:text.index("\n}\n", start)]


def _hometun(guard):
    m = re.search(r':local hometun \{ ([^}]*) \}', guard)
    assert m, "home mode rendered no hometun list"
    return re.findall(r'"([^"]+)"', m.group(1))


def test_anchor_mode_counts_any_customer_however_it_is_reached(built, fleet):
    """The original design, unchanged: a /25 over the backbone still counts,
    and withdrawing takes 10 minutes."""
    for fqdn, r in built.manifest()["routers"].items():
        if r["role"] != "br":
            continue
        guard = _guard(fleet[fqdn])
        assert "immediate-gw" not in guard, (
            f"{fqdn}: anchor mode must not look at HOW the customer is reached")
        assert ":if ($agCustFail >= 60)" in guard


def test_home_mode_counts_only_this_brs_own_er_tunnels(render, topology):
    """The drain lever only works if a /25 that resolves through the backbone
    does NOT count. If the backbone or a site tunnel were in the list,
    disabling the ERs' tunnels to this BR would change nothing."""
    topology["origination"] = {"mode": "home", "arm_guard": False}
    r = render(topology)
    assert r.ok, r.output
    for fqdn, m in r.manifest()["routers"].items():
        if m["role"] != "br":
            continue
        guard = _guard(r.config(fqdn))
        tun = _hometun(guard)
        er_names = [er["name"] for er in topology["edge_routers"]]
        assert tun, f"{fqdn}: no ER tunnels to count"
        assert all(re.fullmatch(rf"wg-({'|'.join(er_names)})-wan\d", t)
                   for t in tun), (
            f"{fqdn}: hometun holds a non-ER interface: {tun}")
        assert len(tun) == len(set(tun))
        assert 'immediate-gw~("%$i")' in guard
        assert ":if ($agCustFail >= 6)" in guard


def test_home_mode_judges_v6_on_v6_evidence(render, topology):
    topology["origination"] = {"mode": "home", "arm_guard": False}
    r = render(topology)
    assert r.ok, r.output
    guard = _guard(r.config("br1.ord1"))
    home6 = topology["blocks_v6"]["customer_home"]
    assert (f'/ipv6/route/find where dst-address="{home6}" && active '
            f'&& !blackhole && immediate-gw~("%$i")') in guard
    assert ":if ($agCustFail6 >= 6)" in guard


@pytest.mark.parametrize("mode", ["anchor", "home"])
def test_arm_guard_controls_the_scheduler_line(render, topology, mode):
    """Unarmed, the scheduler appears only as a comment. The state every
    deploy before this flag shipped in. Armed, it's an executable line."""
    sched = ("/system/scheduler add name=anchor-guard interval=10s "
             "on-event=anchor-guard")
    for armed in (False, True):
        topology["origination"] = {"mode": mode, "arm_guard": armed}
        r = render(topology)
        assert r.ok, r.output
        for fqdn, m in r.manifest()["routers"].items():
            if m["role"] != "br":
                continue
            text = r.config(fqdn)
            assert (sched in code(text)) is armed, (
                f"{fqdn}: mode={mode} arm_guard={armed} but the scheduler is "
                f"{'missing' if armed else 'executable'}")
            assert sched in text
