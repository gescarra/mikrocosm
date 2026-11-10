"""
External peering: the schema, the derivation, and every refusal.

A peer is the first construct in this topology that describes a router NOBODY
HERE ADMINISTERS. That changes what the tests have to prove. For a BR or an ER
the interesting question is "did we render what we meant"; for a peer it's
"can this session reach anything it wasn't granted". And the answers live in
a filter chain, an interface list, and a routing table, not in a session state.

So the assertions here are mostly NEGATIVE, and deliberately so:
  - a peer isn't in the `tunnels` interface list (that list is a full-trust
    input grant)
  - a peer isn't in OSPF and not in the iBGP mesh
  - a 3p or dn42 peer's routes aren't in the main table
  - DN42 space isn't in the production realm, and our space isn't in DN42's

Same shape as the rest of the suite: start from the REAL topology, change one
thing, assert the build refused and said why. A validator that rejects for the
wrong reason will reject the wrong thing later.
"""

import copy

import pytest

from .test_render import code
from .test_validation import assert_refused


# A syntactically plausible WireGuard public key that's nobody's. It only has
# to survive base64-shaped handling and land in a config.
# Decode it. It's very polite about not being a real key.
FAKE_WG_PUB = "aGVsbG8gdGhlcmUgdGhpcyBpcyBub3QgYSByZWFsIGtleSEhIQ="


def peer(**over):
    """A minimal peer that VALIDATES. Tests break one field of it.

    v6-only, because that's the honest default for this AS: `blocks:`
    allocates all 256 addresses of the /24, so a v4 peering link has to come
    from the peer and most sessions won't have one.
    """
    p = {
        "name": "globex",
        "index": 1,
        "realm": "internet",
        "routers": ["br1"],
        "asn": 64510,
        "transport": "wireguard",
        "contact": "noc@example.net",
        "remote": {"endpoint": "192.0.2.94", "endpoint_port": 51820,
                   "public_key": FAKE_WG_PUB},
        "import": {"prefixes": [{"prefix": "3fff:100::/29", "max_len": 48}],
                   "max_routes_v6": 50},
    }
    p.update(over)
    return p


def with_peers(topology, *peers, **blocks):
    topology["peers"] = [copy.deepcopy(p) for p in peers]
    for k, v in blocks.items():
        topology[k] = {**(topology.get(k) or {}), **v}
    return topology


# ---------------------------------------------------------------------
#  Zero blast radius: peering that isn't configured changes nothing
# ---------------------------------------------------------------------
def test_committed_topology_has_peering_disabled(topology):
    """Phase 1 ships the schema, not a peering. Everything off by default."""
    assert topology["peers"] == []
    assert topology["3p"]["enabled"] is False
    assert topology["dn42"]["enabled"] is False


def test_no_peers_renders_no_peering_config(built):
    """The master switches have to mean it. A `peers: []` topology that still
    emitted a VRF or an empty filter chain would be shipping four RouterOS
    constructs this fleet has never executed, on a deploy path where one
    rejected line leaves a wiped router."""
    for fqdn, text in built.configs().items():
        # Comments stripped: these templates DISCUSS peering at length, so a
        # raw grep finds the explanation rather than an executed line. Same
        # reasoning as test_render.code().
        executed = code(text)
        for never in ("/ip/vrf", "/routing/rpki", "=ext-", "peer-tun",
                      "peer-in-", "peer-out-", "rpki-verify"):
            assert never not in executed, (
                f"{fqdn}.rsc contains {never!r} with no peers configured")


# ---------------------------------------------------------------------
#  The happy paths, one per realm
# ---------------------------------------------------------------------
def test_an_internet_peer_validates(render, topology):
    r = render(with_peers(topology, peer()), args=["--check"])
    assert r.ok, r.output


def test_a_3p_peer_validates(render, topology):
    t = with_peers(topology, peer(name="acme", realm="3p", asn=64501),
                   **{"3p": {"enabled": True}})
    r = render(t, args=["--check"])
    assert r.ok, r.output


def test_a_dn42_peer_validates(render, topology):
    p = peer(name="burble", realm="dn42", asn=4242421080)
    p["import"] = {"prefixes": [{"prefix": "fd42:4242:2601::/48", "max_len": 48}],
                   "max_routes_v6": 50}
    t = with_peers(topology, p,
                   dn42={"enabled": True, "asn": 4242420000,
                         "prefix": "172.23.14.128/27",
                         "prefix_v6": "fd42:1:2::/48"})
    r = render(t, args=["--check"])
    assert r.ok, r.output


# ---------------------------------------------------------------------
#  Identity and slots
# ---------------------------------------------------------------------
def test_a_reused_index_is_refused(render, topology):
    """index is a fixed slot driving the listen port and the /127 offset. Two
    peers in one slot is two tunnels on one UDP port."""
    r = render(with_peers(topology, peer(), peer(name="other", asn=64999)))
    assert_refused(r, "index 1", "already used")


def test_an_illegal_name_is_refused(render, topology):
    """The name becomes a RouterOS interface name. One that's legal YAML and
    illegal to RouterOS aborts the import on an already-wiped box."""
    r = render(with_peers(topology, peer(name="Not A Valid Name!")))
    assert_refused(r, "name", "[a-z0-9-]")


def test_a_duplicate_name_is_refused(render, topology):
    a, b = peer(), peer(index=2, asn=64999)
    r = render(with_peers(topology, a, b))
    assert_refused(r, "duplicate peer name")


# ---------------------------------------------------------------------
#  Where a peer may terminate
# ---------------------------------------------------------------------
def test_a_peer_on_an_edge_router_is_refused(render, topology):
    """An ER has no public address to be dialled at, and a peer tunnel there
    would put a third party inside the home input chain."""
    r = render(with_peers(topology, peer(routers=["er1"])))
    assert_refused(r, "er1", "not a border router")


def test_a_peer_with_no_routers_is_refused(render, topology):
    r = render(with_peers(topology, peer(routers=[])))
    assert_refused(r, "routers is empty")


# ---------------------------------------------------------------------
#  ASNs
# ---------------------------------------------------------------------
@pytest.mark.parametrize("asn,label", [
    (64500, "this as"),
    (64515, "upstream"),
    (65010, "firewall/fwa"),
])
def test_an_asn_already_in_use_is_refused(render, topology, asn, label):
    r = render(with_peers(topology, peer(asn=asn)))
    assert_refused(r, f"asn {asn}", label)


def test_a_private_asn_on_an_internet_peer_is_refused(render, topology):
    """A settlement-free peer whose routes enter the production table speaks a
    registered ASN. A private one carries a path nobody outside this AS can
    interpret."""
    r = render(with_peers(topology, peer(asn=64999)))
    assert_refused(r, "private", "rfc 6996")


def test_a_dn42_peer_outside_the_dn42_asn_range_is_refused(render, topology):
    t = with_peers(topology,
                   peer(realm="dn42", asn=64510),
                   dn42={"enabled": True, "asn": 4242420000,
                         "prefix": "172.23.14.128/27",
                         "prefix_v6": "fd42:1:2::/48"})
    r = render(t)
    assert_refused(r, "4242420000..4242429999")


# ---------------------------------------------------------------------
#  Realms
# ---------------------------------------------------------------------
def test_a_peer_in_a_disabled_realm_is_refused(render, topology):
    """The realm block carries the table, the ASN and the ROA source the
    filters are built from. Without it there's nothing to attach to."""
    r = render(with_peers(topology, peer(realm="3p", asn=64501)))
    assert_refused(r, "3p", "enabled: false")


def test_an_unknown_realm_is_refused(render, topology):
    r = render(with_peers(topology, peer(realm="lab")))
    assert_refused(r, "realm 'lab'")


@pytest.mark.parametrize("key", ["isolated", "no_export"])
def test_a_3p_key_on_a_non_3p_peer_is_refused(render, topology, key):
    r = render(with_peers(topology, peer(**{key: True})))
    assert_refused(r, key, "3p key")


def test_a_leak_between_a_vrf_realm_and_main_is_refused_by_name(render, topology):
    """Someone will eventually ask for this, and the reason it can't be had is
    specific enough to say out loud: DN42's 172.20.0.0/14 already contains this
    AS's own ER WAN addressing."""
    t = copy.deepcopy(topology)
    t["dn42"] = {**t["dn42"], "enabled": True, "asn": 4242420000,
                 "prefix": "172.23.14.128/27", "prefix_v6": "fd42:1:2::/48",
                 "leak": ["172.23.14.128/27"]}
    r = render(t)
    assert_refused(r, "dn42.leak is refused", "172.20.101.11")


# ---------------------------------------------------------------------
#  Addressing: the /24 is full, and that's a hard constraint
# ---------------------------------------------------------------------
@pytest.mark.parametrize("key", ["local", "address"])
def test_a_v4_peering_link_inside_our_own_24_is_refused(render, topology, key):
    """`blocks:` allocates all 256 addresses. There's no v4 for a peering link
    and there won't be one without renumbering live links, so the error has
    to say that rather than 'out of range'."""
    p = peer()
    p["remote"][key] = "203.0.113.99"
    r = render(with_peers(topology, p))
    assert_refused(r, "203.0.113.99", "allocates all 256")


def test_the_v6_peering_block_does_not_overlap_anything(topology):
    """peer_p2p is a new /60 in the infra /48. If it ever overlapped another
    block, two unrelated links would be numbered on top of each other."""
    import ipaddress
    blocks = {k: ipaddress.ip_network(v)
              for k, v in topology["blocks_v6"].items()}
    peer_p2p = blocks.pop("peer_p2p")
    for name, net in blocks.items():
        assert not (peer_p2p.overlaps(net)), \
            f"blocks_v6.peer_p2p {peer_p2p} overlaps blocks_v6.{name} {net}"


def test_a_peer_with_no_address_family_is_refused(render, topology):
    r = render(with_peers(topology, peer(families=[])))
    assert_refused(r, "no address family")


# ---------------------------------------------------------------------
#  The cone, and the limit
# ---------------------------------------------------------------------
def test_accepting_our_own_space_back_is_refused(render, topology):
    """With peer routes preferred over transit, a peer advertising our own
    aggregate would beat our own origination. A hijack of ourselves."""
    p = peer()
    p["import"]["prefixes"] = [{"prefix": "203.0.113.0/24"}]
    p["import"]["max_routes"] = 5
    p["remote"].update(local="198.51.100.4", address="198.51.100.5")
    r = render(with_peers(topology, p))
    assert_refused(r, "203.0.113.0/24", "overlaps our own")


def test_dn42_space_on_an_internet_peer_is_refused(render, topology):
    """172.20.0.0/14 isn't globally routable, and in the main table it would
    shadow this AS's own ER WAN addressing."""
    p = peer()
    p["import"]["prefixes"] = [{"prefix": "172.21.0.0/16", "max_len": 24}]
    p["import"]["max_routes"] = 50
    p["families"] = [4, 6]
    p["remote"].update(local="198.51.100.4", address="198.51.100.5")
    r = render(with_peers(topology, p))
    assert_refused(r, "172.21.0.0/16", "realm 'internet'")


def test_non_dn42_space_on_a_dn42_peer_is_refused(render, topology):
    t = with_peers(topology,
                   peer(realm="dn42", asn=4242421080),
                   dn42={"enabled": True, "asn": 4242420000,
                         "prefix": "172.23.14.128/27",
                         "prefix_v6": "fd42:1:2::/48"})
    r = render(t)
    assert_refused(r, "outside dn42's registry space")


def test_a_missing_max_prefix_limit_is_refused(render, topology):
    """NOT derived, deliberately. A /29 accepted to /48 has a worst case of
    2^20 routes: a formality, not a limit. How many prefixes a peer actually
    sends is an operational fact they tell you."""
    p = peer()
    del p["import"]["max_routes_v6"]
    r = render(with_peers(topology, p))
    assert_refused(r, "import.max_routes_v6 is required")


def test_a_cone_for_a_family_the_session_does_not_run_is_refused(render, topology):
    """The likeliest cause is worth naming: a v4 cone was written and the v4
    link addresses were forgotten, so the session came out v6-only and the
    grant does nothing."""
    p = peer()
    p["import"]["prefixes"].append({"prefix": "192.0.2.0/24"})
    p["import"]["max_routes"] = 50
    r = render(with_peers(topology, p))
    assert_refused(r, "ipv4 entries", "never applied")


def test_a_prefix_longer_than_the_dfz_ceiling_is_refused(render, topology):
    p = peer()
    p["import"]["prefixes"] = [{"prefix": "3fff:100::/29", "max_len": 64}]
    r = render(with_peers(topology, p))
    assert_refused(r, "max_len=64", "29..48")


# ---------------------------------------------------------------------
#  Secrets, and values that are ours to derive
# ---------------------------------------------------------------------
@pytest.mark.parametrize("key", ["md5_key", "psk_key", "private_key"])
def test_a_literal_secret_in_the_topology_is_refused(render, topology, key):
    """topology.yml's header says it holds no secrets. bgp_auth_key already
    breaks that promise in a committed file and isn't a precedent to copy."""
    r = render(with_peers(topology, peer(**{key: "hunter2"})))
    assert_refused(r, key, "plaintext secret")


@pytest.mark.parametrize("key", ["listen_port", "interface", "iface"])
def test_a_hand_written_derived_value_is_refused(render, topology, key):
    r = render(with_peers(topology, peer(**{key: "wg-nope"})))
    assert_refused(r, key, "derived, not declared")


def test_peer_secrets_never_reach_the_manifest(render, topology):
    """Same contract every other secret in this repo has, and the reason is
    sharper here: a peer's session key is someone ELSE's secret too."""
    import json
    t = with_peers(topology, peer(psk=True, md5=True))
    r = render(t)
    assert r.ok, r.output
    keys = json.loads(r.keys_path.read_text())
    secrets = {v for e in keys.values() for k, v in e.items()
               if k in ("psk", "key", "private") and isinstance(v, str)}
    for artifact in ("manifest.json", "inventory.yml", "pipeline.yml"):
        text = (r.out / artifact).read_text()
        for s in secrets:
            assert s not in text, f"{artifact} contains key material"


# ---------------------------------------------------------------------
#  Transport
# ---------------------------------------------------------------------
def test_wireguard_without_a_public_key_is_refused(render, topology):
    p = peer()
    del p["remote"]["public_key"]
    r = render(with_peers(topology, p))
    assert_refused(r, "no remote.public_key")


def test_gre_without_an_endpoint_is_refused(render, topology):
    """GRE has no handshake and no NAT traversal, so the far end must be a
    fixed reachable address. WireGuard is the transport for anything that
    dials us."""
    p = peer(transport="gre")
    del p["remote"]["endpoint"]
    r = render(with_peers(topology, p))
    assert_refused(r, "gre", "no remote.endpoint")


def test_an_unknown_transport_is_refused(render, topology):
    r = render(with_peers(topology, peer(transport="tinc")))
    assert_refused(r, "transport 'tinc'")


# ---------------------------------------------------------------------
#  DN42's collision with this AS's own addressing
# ---------------------------------------------------------------------
def test_a_dn42_prefix_covering_an_er_wan_is_refused(render, topology):
    """The collision that makes the VRF necessary and not just tidy. The ER
    WANs sit on 172.20.101.11 and 172.20.102.11, inside DN42's 172.20.0.0/14.
    So a registered block covering one of them would put a DN42 route on top of
    an address this AS actually forwards to."""
    t = copy.deepcopy(topology)
    t["peers"] = []
    t["dn42"] = {**t["dn42"], "enabled": True, "asn": 4242420000,
                 "prefix": "172.20.101.0/27", "prefix_v6": "fd42:1:2::/48"}
    r = render(t)
    assert_refused(r, "172.20.101.11", "er1.hdc/wan1")


@pytest.mark.parametrize("key,bad", [
    ("prefix", "10.0.0.0/27"),
    ("prefix_v6", "2001:db8::/48"),
])
def test_a_dn42_prefix_outside_dn42_space_is_refused(render, topology, key, bad):
    t = copy.deepcopy(topology)
    t["peers"] = []
    t["dn42"] = {**t["dn42"], "enabled": True, "asn": 4242420000,
                 "prefix": "172.23.14.128/27", "prefix_v6": "fd42:1:2::/48",
                 key: bad}
    r = render(t)
    assert_refused(r, bad, "outside")


def test_an_unregistered_dn42_block_is_refused(render, topology):
    """REPLACE-ME is the same treatment automation.keys gets: a value only the
    future operator can supply must not be guessable by this file."""
    t = copy.deepcopy(topology)
    t["peers"] = []
    t["dn42"] = {**t["dn42"], "enabled": True, "asn": 4242420000}
    r = render(t)
    assert_refused(r, "replace-me", "register the dn42 objects")


# ---------------------------------------------------------------------
#  RPKI
# ---------------------------------------------------------------------
def test_an_rpki_group_with_no_cache_is_refused(render, topology):
    """Validation that looks configured and does nothing is worse than none:
    rpki-verify against a group with no source returns 'unknown' for every
    prefix, and these chains accept 'unknown'."""
    t = copy.deepcopy(topology)
    t["peers"] = []
    t["rpki"] = {"internet": {"port": 3323}}
    r = render(t)
    assert_refused(r, "rpki.internet", "no cache address")


# ---------------------------------------------------------------------
#  Rotation is no longer only our problem
# ---------------------------------------------------------------------
def test_rotating_keys_with_peers_configured_is_refused(render, topology):
    """Until there were peers, --rotate-keys broke a fleet we control. A peer
    holds our public key, has no idea we rebuilt anything, and finds out when
    the session has been down long enough for someone to notice."""
    r = render(with_peers(topology, peer(contact="noc@example.net")),
               args=["--rotate-keys"], use_pin=False)
    assert not r.ok
    assert "refused" in r.output.lower()
    assert "globex" in r.output and "noc@example.net" in r.output


def test_rotation_is_still_possible_with_force(render, topology):
    r = render(with_peers(topology, peer()), args=["--rotate-keys", "--force"])
    assert r.ok, r.output


# ---------------------------------------------------------------------
#  What actually reaches a router (phase 2: internet realm, WireGuard)
# ---------------------------------------------------------------------
@pytest.fixture
def peered(render, topology):
    """One rendered fleet with a single v6-only internet peer on br1."""
    r = render(with_peers(topology, peer()))
    assert r.ok, r.output
    return r


@pytest.fixture
def br1(peered):
    return code(peered.config("br1.ord1"))


def test_a_peer_is_not_in_the_tunnels_interface_list(br1):
    """`tunnels` is a FULL-TRUST grant: the input chain accepts everything
    arriving on it, and the OSPF templates and BFD menu are keyed to its
    members. A peer inheriting that would get the inside of the network."""
    line = [l for l in br1.splitlines() if "add name=tunnels include=" in l]
    assert len(line) == 1, "expected exactly one `tunnels` list definition"
    assert "peer-tun" not in line[0], (
        f"peer-tun is a member of `tunnels`, which hands a third party the "
        f"unconditional input accept and puts them in front of OSPF:\n{line[0]}")


def test_a_peer_gets_no_blanket_input_accept(br1):
    """The `tunnels` list has one. `accept in-interface-list=tunnels`, which
    is the full-trust grant. peer-tun must never appear in an accept at all:
    every hole for a peer is one protocol to one source or one interface.

    So the rule is simple and checkable. Every line that names peer-tun as an
    interface list is a DROP."""
    named = [l for l in br1.splitlines() if "in-interface-list=peer-tun" in l]
    assert named, "peer-tun is never referenced in a firewall rule at all"
    for line in named:
        assert "action=drop" in line, (
            f"a firewall rule names peer-tun and is not a drop. The only "
            f"traffic a peer may send this router is the sessions it was "
            f"granted, one rule each:\n{line}")


def test_the_ra_drop_covers_peer_interfaces_and_comes_first(br1):
    """br1 runs accept-router-advertisements=yes because Vultr hands it a
    default by RA. The drop rule is what makes that safe, and it was written
    when `tunnels` was every tunnel on the box. peer-tun is the first list
    outside it (and the untrusted one) so a peer could otherwise install
    itself as this router's default gateway."""
    lines = br1.splitlines()
    drops = [i for i, l in enumerate(lines) if "icmp-options=134:0" in l]
    blanket = [i for i, l in enumerate(lines)
               if "accept protocol=icmpv6" in l and "dst-port" not in l]
    assert any("peer-tun" in lines[i] for i in drops), (
        "no RA drop covers peer-tun; a peer can send a Router Advertisement "
        "and become this BR's default gateway")
    assert max(drops) < min(blanket), (
        "an RA drop sits BELOW the blanket ICMPv6 accept, so the accept wins "
        "and the drop never runs")


def test_a_peer_cannot_join_ospf_or_bfd(br1):
    """Both fall out of peer-tun being absent from every `tun-*` list the OSPF
    templates name, and of the BFD menu being deny-by-default. Asserted anyway:
    they are properties of the config, not of the intention."""
    for line in br1.splitlines():
        if line.startswith("add ") and ("area=" in line or "/routing/bfd" in line):
            assert "ext-" not in line and "peer-tun" not in line, (
                f"a peer interface reached OSPF or BFD:\n{line}")


def test_a_peer_is_not_in_the_ibgp_mesh(br1, peered):
    """A peer isn't a member of AS64500. If one turned up in the mesh it
    would be receiving the inside of the network's routing table."""
    for line in br1.splitlines():
        if "ibgp" in line:
            assert "globex" not in line, f"peer appears in an iBGP object:\n{line}"


def test_the_peer_endpoint_is_pinned_against_recursion(br1):
    """A peer can advertise a prefix covering its own tunnel endpoint. Accept
    that and the outer destination resolves through the tunnel carrying it.
    A permanent flap that reads as the far end's fault."""
    assert "dst-address=192.0.2.94/32" in br1, (
        "the peer's endpoint has no static /32; the same guard sibling_publics "
        "gets is missing on the link likelier to need it")


def test_the_peer_import_chain_rejects_a_default(br1):
    """Peer routes sit above the provider default in local-pref, so a peer
    sending a default would take every packet of egress with it."""
    nlri = [l for l in br1.splitlines() if "chain=peer6-nlri-globex" in l]
    assert any("dst-len==0" in l and "reject" in l for l in nlri), (
        "peer6-nlri-globex does not reject a default route")
    assert nlri[-1].endswith('rule="reject"'), (
        f"peer6-nlri-globex is a whitelist without a terminal reject, so it "
        f"accepts anything:\n{nlri[-1]}")


def test_the_peer_import_chain_rejects_our_own_space(br1):
    nlri = [l for l in br1.splitlines() if "chain=peer6-nlri-globex" in l]
    assert any("dst in 2001:DB8::/42" in l and "reject" in l for l in nlri), (
        "peer6-nlri-globex would accept our own aggregate back from the peer")


def test_the_peer_export_chain_announces_only_our_own_space(br1):
    """The settlement-free promise, as a whitelist. A route learned from one
    peer must not be announceable to another peer or to an upstream."""
    out = [l for l in br1.splitlines() if "chain=peer6-out-internet" in l]
    assert out, "no peer6-out-internet chain"
    assert out[-1].endswith('rule="reject"'), (
        f"peer6-out-internet does not end in a reject, so it is transit:\n{out[-1]}")
    accepts = [l for l in out if "accept" in l]
    assert len(accepts) == 1 and "2001:DB8::/42" in accepts[0], (
        f"peer6-out-internet accepts something other than our own aggregate:\n"
        f"{accepts}")


def test_the_peer_session_has_a_max_prefix_limit_and_an_nlri_filter(br1):
    """input.filter alone only marks a route filtered. It still occupies RAM
    on a CHR. Both of these are what stand between one peer and the memory."""
    assert "input.limit-process-routes-ipv6=50" in br1
    assert "input.filter-nlri=peer6-nlri-globex" in br1


def test_a_peer_may_not_source_from_our_own_space(br1):
    """The BR forward chain was empty because every tunnel belonged to us. A
    peer tunnel breaks that assumption, and an empty forward chain would route
    whatever source address the far end chose to write."""
    assert ("add chain=forward action=drop in-interface-list=peer-tun "
            "src-address=203.0.113.0/24") in br1, (
        "no BCP38 rule on peer tunnels; a peer can spoof our own space through "
        "this router")


def test_peering_config_renders_after_management_access(peered, br1):
    """Same rule the rest of the file follows. These are the newest constructs
    on the box, so a rejected line here must cost peering and not SSH."""
    text = peered.config("br1.ord1")
    lines = text.splitlines()
    first_peer_bgp = next(i for i, l in enumerate(lines)
                          if "chain=peer6-nlri-globex" in l)
    mgmt = next(i for i, l in enumerate(lines) if l.startswith("/user"))
    assert mgmt < first_peer_bgp


def test_only_border_routers_gain_peering_config(peered):
    """er.rsc.j2 and site.rsc.j2 are untouched by this feature. A peer
    terminates on a BR, and nothing else should have moved."""
    for fqdn, text in peered.configs().items():
        if fqdn.startswith("br"):
            continue
        executed = code(text)
        for never in ("ext-globex", "peer-tun", "peer6-in-", "peer6-out-"):
            assert never not in executed, f"{fqdn}.rsc gained {never!r}"


def test_the_second_br_gains_nothing_when_the_peer_is_on_br1(peered):
    """`routers: [br1]` means br1. A peer landing on both BRs because the
    template forgot to filter would double the session count silently."""
    executed = code(peered.config("br2.ord2"))
    assert "ext-globex" not in executed
    assert "peer-tun" not in executed
