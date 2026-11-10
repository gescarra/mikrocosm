"""
One router, after it has been deployed. Read-only.

This is the gate: in the pipeline, the next router isn't touched until every
test here passes for the current one. `deploy.yml` proves a router came back
and reports the right identity. A smoke test that a badly broken router
passes, because RouterOS stops at the first line it can't parse and skips
everything after it. These are the checks that would notice.

Everything asserted comes from out/manifest.json. Nothing here knows how many
routers there are or what the customers were granted.
"""

import ipaddress

import pytest

from .routeros import import_error_query, as_bool


def _addrs(sessions, key="remote.address"):
    """Established peer addresses, normalised for comparison.

    Split into a set rather than substring-matched against a blob: testing
    `"203.0.113.24" in output` is TRUE when the only established peer is
    203.0.113.241, which would report a dead session as healthy. That's the
    one direction an error here must never go.

    The `/len` strip and the lowercasing handle the two ways RouterOS and
    topology.yml can spell the same address.
    """
    out = set()
    for s in sessions:
        if not as_bool(s.get("established", False)):
            continue
        value = str(s.get(key, "")).split("/")[0].strip().lower()
        if value:
            out.add(value)
    return out


# ---------------------------------------------------------------------
#  Did the config actually apply?
# ---------------------------------------------------------------------
def test_identity_matches(router, state):
    """We are talking to the router we think we're."""
    assert state["identity"] == router, (
        f"Reached this address expecting {router}, but it calls itself "
        f"{state['identity']!r}. Either the inventory address is wrong or this "
        f"router never applied its config.")


def test_config_script_applied_without_errors(router, state):
    """The single most valuable check here, and the one nothing else covers.

    The apply path wipes the box and replays an add-only script. RouterOS stops
    at the first line it rejects and SKIPS EVERYTHING AFTER IT. A router that
    failed on line 700 comes back, answers SSH, reports the right identity, and
    has no BGP at all. And the log is the only place that says so.

    Counts only errors the IMPORT produced. Errors from an interactive session
    are excluded and reported separately: they say something about the person
    at the keyboard, not about the config on the router. See
    INTERACTIVE_MARK in routeros.py for why the two can be told apart.
    """
    count = int(state["logerr"])
    lines = "\n".join(
        f"  {e.get('time', '?')}  {e.get('message', e)}"
        for e in (state.get("logerr_msgs") or []))
    assert count == 0, (
        f"{router}: {count} script error(s) logged by the config import. The "
        f"import was REJECTED partway through, so every line after the failure "
        f"never ran. This router is partially configured even though it answers "
        f"SSH with the right identity.\n{lines}\n\n"
        f"  /log print where {import_error_query()}")


def test_report_adhoc_errors(router, state, record_property):
    """Never fails. Reports errors somebody typed, which the gate ignores.

    Worth surfacing anyway: a chaos run that couldn't arm its deadman, or a
    half-finished manual change, leaves its evidence here and nowhere else in
    this suite. It stopped being an assertion because it was failing the
    BASELINE of a healthy fleet. But silently dropping the signal would trade
    one bad outcome for another.
    """
    count = int(state.get("logerr_adhoc", 0))
    record_property("adhoc_log_errors", count)
    if count:
        print(f"\n{router}: {count} command error(s) from interactive "
              f"sessions -- not from the import, not gating. Inspect with:\n"
              f"  /log print where {import_error_query(interactive=True)}")


# ---------------------------------------------------------------------
#  WireGuard: the underlay
# ---------------------------------------------------------------------
def test_all_tunnel_interfaces_exist(router, expect, state):
    have = {i["name"] for i in state["wg_ifaces"]}
    want = {t["iface"] for t in expect["tunnels"]}
    assert want <= have, (
        f"{router} is missing WireGuard interface(s) {sorted(want - have)}. "
        f"The config did not create them, which means the import did not get "
        f"this far.")


def test_every_wireguard_peer_has_handshaked(router, expect, state):
    """A tunnel interface shows as *running* whether or not the far end has
    ever answered: WireGuard has no link state at all. The handshake is the
    only liveness signal there's, which is precisely why OSPF sits on top of
    it rather than trusting the interface.
    """
    configured = {p.get("interface") for p in state["wg_peers"]}
    # From the dedicated handshake probe, not from `print as-value`. That
    # menu returns only CONFIGURED properties and omits every runtime one,
    # so `last-handshake` is simply absent there. Verified on 7.24. Reading it
    # from the wrong place gave an empty value for every peer, which would have
    # failed this test on a completely healthy fleet.
    handshakes = state["wg_handshakes"]

    stale = []
    for t in expect["tunnels"]:
        if t["iface"] not in configured:
            stale.append(f"{t['iface']} (no peer configured)")
            continue
        age = handshakes.get(t["iface"], "").strip()
        # RouterOS leaves the property unset until the first handshake, so an
        # empty value is "never", not "just now".
        if not age:
            stale.append(f"{t['iface']} -> {t['peer_fqdn']} (never)")
    assert not stale, (
        f"{router}: WireGuard peers with no handshake: {', '.join(stale)}.\n"
        f"A tunnel with no handshake carries nothing and its interface still "
        f"shows as running. Check the peer's public key and endpoint -- a "
        f"wrong key produces exactly this, silently, on both ends:\n"
        f"  /interface/wireguard/peers print detail")


def test_wireguard_peer_keys_match_the_intended_peer(router, expect, state):
    """The cross-reference graph, checked on the LIVE router.

    tests/unit/test_crossref.py proves the rendered files agree. This proves
    the router is running the file we think it's. Which is a different
    claim, and the one that catches a half-applied config or somebody's manual
    edit.

    The manifest carries a truncated SHA-256 rather than the key itself, so
    that it can be a CI artifact.
    """
    import hashlib

    by_iface = {p.get("interface"): p for p in state["wg_peers"]}
    wrong = []
    for t in expect["tunnels"]:
        if not t.get("peer_key_fp"):
            continue
        peer = by_iface.get(t["iface"])
        if peer is None:
            continue
        live = peer.get("public-key", "")
        fp = hashlib.sha256(live.encode()).hexdigest()[:16] if live else None
        if fp != t["peer_key_fp"]:
            wrong.append(f"{t['iface']} (expected peer {t['peer_fqdn']})")
    assert not wrong, (
        f"{router}: WireGuard peer public key does not match the intended peer "
        f"on {', '.join(wrong)}. The running config is not the generated one. "
        f"This tunnel will come up and never handshake, and no log on either "
        f"box will say why.")


# ---------------------------------------------------------------------
#  OSPF: the only thing that notices a dead tunnel
# ---------------------------------------------------------------------
def test_ospf_adjacencies_are_full(router, expect, state, manifest):
    """Counted PER INSTANCE, which is per address family.

    `/routing/ospf/neighbor` returns v2 and v3 neighbours in one table.
    br1 shows 5 in instance `core` and 5 in `core6`. Counting the table as a
    whole and comparing it to the interface count passes with 10 >= 5, and
    would go on passing with IPv6 OSPF entirely dead. That's the failure this
    network is most likely to carry unnoticed for weeks, so it's exactly the
    one the count must not paper over.

    Instance NAMES aren't hardcoded: whatever instances the router reports are
    the ones checked, and the expected count is the same for each because both
    families run over the same interfaces.
    """
    want = expect["ospf_neighbors_expected"]
    by_instance = {}
    for n in state["ospf"]:
        inst = str(n.get("instance", "?"))
        by_instance.setdefault(inst, []).append(n)

    families = 2 if manifest["v6"] else 1
    assert len(by_instance) >= families, (
        f"{router}: OSPF neighbours in {len(by_instance)} instance(s) "
        f"({', '.join(sorted(by_instance)) or 'none'}), expected {families} "
        f"(one per address family). An entire family has no adjacency at all.")

    short = {
        inst: sum(1 for n in ns if str(n.get("state", "")).lower() == "full")
        for inst, ns in by_instance.items()
    }
    bad = {i: c for i, c in short.items() if c < want}
    assert not bad, (
        f"{router}: OSPF instance(s) below the expected {want} Full "
        f"adjacencies: {bad} "
        f"(interfaces: {', '.join(expect['ospf_interfaces'])}).\n"
        f"OSPF is the ONLY liveness detector on this network and every iBGP "
        f"next-hop resolves through it -- a missing adjacency is a set of "
        f"prefixes that will not install.\n"
        f"  /routing/ospf/neighbor print")


# ---------------------------------------------------------------------
#  iBGP: by peer, never by count
# ---------------------------------------------------------------------
def test_ibgp_sessions_are_established(router, expect, state):
    """A count isn't enough. Two sessions up and two down still counts as two,
    and which two is the entire question. A fleet where the border routers
    are talking to each other but neither reaches the edge carries no customer
    route at all and passes a count check.
    """
    up = _addrs(state["bgp"])
    down = [p for p in expect["ibgp"] if p["address"].lower() not in up]
    assert not down, (
        f"{router}: iBGP is DOWN to "
        f"{', '.join(p['peer_fqdn'] for p in down)}.\n"
        f"The mesh has no route reflector, so a missing session is not "
        f"redundancy lost -- it is prefixes that never arrive at that peer.\n"
        f"Established right now: {sorted(up) or 'nothing'}")


def test_ibgp6_sessions_are_established(router, expect, state, manifest):
    """Separate from v4 deliberately, because the sessions are separate. Half
    the network can be down for weeks with nothing else complaining."""
    if not manifest["v6"]:
        pytest.skip("topology is v4-only")
    up = _addrs(state["bgp"])
    down = [p for p in expect["ibgp"]
            if p["address6"] and p["address6"].lower() not in up]
    assert not down, (
        f"{router}: iBGP6 is DOWN to "
        f"{', '.join(p['peer_fqdn'] for p in down)}. IPv4 is unaffected, which "
        f"is exactly why this is its own assertion.\n"
        f"Established: {sorted(up) or 'nothing'}")


# ---------------------------------------------------------------------
#  eBGP: upstreams and customers
# ---------------------------------------------------------------------
def test_upstream_session_is_established(router, expect, state):
    if expect["role"] != "br":
        pytest.skip("border routers only")
    up = _addrs(state["bgp"])
    down = [e for e in expect["ebgp"] if e["address"].lower() not in up]
    assert not down, (
        f"{router}: eBGP to {expect['provider']} is DOWN "
        f"({', '.join(e['address'] for e in down)}).\n"
        f"This border router has no transit: it is neither announcing the "
        f"prefix nor receiving a default.\n"
        f"Note both upstreams peer at 169.254.169.254 with DIFFERENT ASNs -- a "
        f"session stuck in Active with nothing in the log is nearly always "
        f"that.")


def test_customer_sessions_are_established(router, expect, state):
    if expect["role"] != "er":
        pytest.skip("edge routers only")
    up = _addrs(state["bgp"])
    down = [c for c in expect["customers"] if c["address"].lower() not in up]
    assert not down, (
        f"{router}: customer session DOWN to "
        f"{', '.join(c['name'] for c in down)}.\n"
        f"That firewall's VIPs are withdrawn from this edge router right now. "
        f"If the other ER still has them the VIP is up on one path; if neither "
        f"does, the home-anchor guard stops originating the /25.\n\n"
        f"If that firewall has never been turned up, this is still the right "
        f"answer: topology.yml declares the session, so the ER is configured "
        f"and waiting for it. Either bring the far end up, or remove it from "
        f"`firewalls:` until you do -- a grant that exists in the config and "
        f"nowhere on the wire is exactly what this test is for.")


def test_customer_routes_are_actually_installed(router, expect, state,
                                                claim_prefixes):
    """An established session carrying nothing reads as healthy from both ends,
    and is exactly the failure the grant model exists to prevent: a VIP granted
    and never advertised, or advertised and dropped by `cust-in`.
    """
    if expect["role"] != "er" or not claim_prefixes:
        pytest.skip("edge routers with customer grants only")
    total = sum(len(state[f"claim{i}"]) for i in range(len(claim_prefixes)))
    assert total > 0, (
        f"{router}: the customer sessions are established but NOT ONE route "
        f"has been received into the granted space "
        f"({', '.join(claim_prefixes)}).\n"
        f"Both ends will report BGP as up. Check the firewall is advertising, "
        f"and that cust-in is not rejecting what it sends.")


# ---------------------------------------------------------------------
#  Origination
# ---------------------------------------------------------------------
def test_origination_anchors_are_present(router, expect, state):
    """The anchor's PRESENCE is the origination switch. `output.network` only
    announces a prefix whose route resolves. So this isn't a proxy for "are we
    announcing", it's the mechanism itself.
    """
    if not expect["anchors"]:
        pytest.skip("this router originates nothing")
    have = len(state["blackhole4"]) + len(state["blackhole6"])
    want = len(expect["anchors"])
    assert have >= want, (
        f"{router}: {have} of {want} anchor routes present "
        f"({', '.join(a['prefix'] for a in expect['anchors'])}).\n"
        f"A missing anchor means this router announces NOTHING for that "
        f"prefix, and nothing else on the box reports it: BGP is up, OSPF is "
        f"Full, the session is fine.\n"
        f"  /ip/route print where blackhole")


def test_report_withdrawn_anchors(router, expect, state, record_property):
    """Not a failure. anchor-guard disables an anchor deliberately when the
    space behind it's unreachable. But during a rollout you need to know it
    happened before the next router is touched, so it's recorded rather than
    swallowed."""
    if not expect["anchors"]:
        pytest.skip("this router originates nothing")
    off = [r for r in state["blackhole4"] + state["blackhole6"]
           if as_bool(r.get("disabled", False))]
    record_property("withdrawn_anchors", len(off))
    if off:
        print(f"\nNOTE {router}: {len(off)} anchor(s) are DISABLED. "
              f"anchor-guard does that on purpose when the space behind them "
              f"is unreachable, but it means this router is not announcing.\n"
              f'  /log print where message~"anchor-guard"')


# ---------------------------------------------------------------------
#  Egress
# ---------------------------------------------------------------------
def test_active_default_route_v4(router, expect, state):
    if not expect["expect_default"]["v4"]:
        pytest.skip("no v4 default expected here")
    active = [r for r in state["default4"] if as_bool(r.get("active", False))]
    hint = ("This border router is not receiving one from its upstream, so it "
            "has no egress at all."
            if expect["role"] == "br" else
            "An edge router learns its default over iBGP from the border "
            "routers -- so this is not a default-route problem, it is the "
            "whole stack underneath failing to deliver one.")
    assert active, f"{router} has no active IPv4 default route. {hint}"


def test_active_default_route_v6(router, expect, state):
    if not expect["expect_default"]["v6"]:
        pytest.skip("no v6 default expected here")
    active = [r for r in state["default6"] if as_bool(r.get("active", False))]
    assert active, (
        f"{router} has no active IPv6 default route. IPv4 is unaffected and "
        f"nothing else complains, which is why this is checked separately.")


# ---------------------------------------------------------------------
#  The data plane
# ---------------------------------------------------------------------
def test_reaches_every_other_loopback(router, expect, dev, manifest):
    """Everything above proves sessions and adjacencies. None of it proves a
    packet moves. iBGP next-hops resolve through OSPF, so this is what tells
    "the session is up" and "traffic works" apart.
    """
    failed = []
    for fqdn, lo in manifest["loopbacks"].items():
        if fqdn == router:
            continue
        if dev.ping(lo, src=expect["loopback"], count=3) == 0:
            failed.append(f"{fqdn} ({lo})")
    assert not failed, (
        f"{router} cannot reach {', '.join(failed)} over the loopback mesh, "
        f"sourced from its own loopback {expect['loopback']}.\n"
        f"Sessions can be established and packets still not move.")


def test_tunnel_mtu_is_exactly_what_the_config_claims(router, expect, dev,
                                                      manifest):
    """Proved, not assumed, and in both directions.

    A do-not-fragment packet of exactly `wg_mtu` must cross each tunnel, and
    one byte more must NOT. The second half is the real test: a tunnel that
    passes oversized DF traffic has an MTU that isn't what the config says,
    and every MSS clamp derived from it's therefore wrong. Which produces a
    network where ping is flawless and large TCP flows stall.

    The README is blunt that wg_mtu must be measured rather than trusted. This
    is that measurement, run on every deploy.
    """
    mtu = int(manifest["wg_mtu"])
    too_small, too_large = [], []
    for t in expect["tunnels"]:
        peer = t["peer_address"]
        if dev.ping(peer, size=mtu, df=True, count=3) == 0:
            too_small.append(t["iface"])
        if dev.ping(peer, size=mtu + 1, df=True, count=2) > 0:
            too_large.append(t["iface"])

    msg = []
    if too_small:
        msg.append(
            f"TOO SMALL on {', '.join(too_small)} -- the underlay hands out "
            f"less than wg_mtu+60 and a full-size packet is being dropped. "
            f"Binary-search the real figure with a DF ping to the border "
            f"router's public address and lower wg_mtu; the MSS clamps follow "
            f"it automatically.")
    if too_large:
        msg.append(
            f"TOO LARGE on {', '.join(too_large)} -- oversized DF traffic is "
            f"getting through, so the interface MTU is not the configured one "
            f"and every clamp derived from it is wrong.")
    assert not msg, (
        f"{router}: tunnel MTU does not match wg_mtu={mtu}.\n" + "\n".join(msg))


# ---------------------------------------------------------------------
#  BFD
# ---------------------------------------------------------------------
def test_no_bfd_session_is_stuck_down(router, expect, state):
    """`use-bfd=yes` with a session that never comes up is precisely the flap
    the feature exists to prevent, and it means the far end hasn't had pass 1
    deployed yet."""
    if not expect["bfd"]["expect_ospf_sessions"]:
        pytest.skip("BFD is not armed in this topology")
    down = [s for s in state["bfd"]
            if str(s.get("state", "")).lower() not in ("up", "")]
    assert not down, (
        f"{router}: {len(down)} BFD session(s) are DOWN while use-bfd is "
        f"armed. An OSPF adjacency holding a permanently-down BFD session is "
        f"worse than no BFD at all.\n"
        f"  /routing/bfd/session/print")


# ---------------------------------------------------------------------
#  Addressing sanity: cheap, and it catches a whole class of typo
# ---------------------------------------------------------------------
def test_loopback_is_inside_our_prefix(router, expect, manifest):
    net = ipaddress.ip_network(manifest["prefix"])
    assert ipaddress.ip_address(expect["loopback"]) in net, (
        f"{router}'s loopback {expect['loopback']} is outside {net}")


def test_the_live_group_matches_what_the_config_declares(router, dev, manifest):
    """Read the group back off the router, not out of the rendered file.

    The unit suite checks what the .rsc SAYS. This checks what the router HOLDS,
    and they aren't the same claim. br1 was found granting `sensitive` from a
    render that never asked for it while three other routers denied it
    correctly. Nothing compared the two, so the drift was invisible until
    somebody looked by hand.

    `policy` being in the granted set is expected and required: RouterOS refuses
    /system/reset-configuration without it. That also means this group isn't a
    security boundary: see test_the_automation_group_grants_no_gui_or_api_path
    in the unit suite for what the denials are actually worth.
    """
    import pytest

    auto = manifest.get("automation")
    if not auto or auto.get("group") == "full":
        pytest.skip("no custom automation group in this topology")

    raw = dev.run(
        f':put [:tostr [/user/group/get [find name={auto["group"]}] policy]]'
    ).strip()
    granted = {p for p in raw.split(";") if p and not p.startswith("!")}
    denied = {p[1:] for p in raw.split(";") if p.startswith("!")}

    assert "policy" in granted, (
        f"{router}: the {auto['group']} group lacks 'policy', so "
        f"/system/reset-configuration will be REFUSED and every deploy to this "
        f"router is a silent no-op -- the box does not even reboot. Measured "
        f"failure: 'not enough permissions (9) (/system/reset-configuration)'.")

    for closed in ("sensitive", "winbox", "api", "rest-api", "sniff"):
        assert closed in denied, (
            f"{router}: the {auto['group']} group does not deny '{closed}'. "
            f"The rendered config denies it by name, so this router has "
            f"drifted from its config.\n  live: {raw}")
