"""
The cross-reference graph: the reason this repo exists at all.

From the README: "br1's peer stanza needs er1's PUBLIC key, and er1's needs
br1's. That's a cross-reference graph over 18 keypairs, and it has to stay
consistent on both ends of every tunnel. envsubst can't express it."

If the generator gets that wrong, the failure is silent in the worst way: the
interfaces come up, the routes are configured, OSPF sits in Init forever, and
nothing anywhere says "wrong key". These tests read both ends of every tunnel
out of the two rendered configs and check they agree. Which is the one thing
no amount of reading a single config can tell you.
"""

import re

import pytest


def wg_peers(config_text):
    """Every `/interface/wireguard/peers add ...` in a rendered config, as a
    dict of interface -> parsed attributes.

    Parsed out of the rendered text rather than out of the generator's own data
    structures, deliberately. Asserting that build() agrees with build() proves
    nothing; the question is whether the FILE that reaches the router carries
    the right key, and the template is between those two things.
    """
    peers = {}
    section = None
    for raw in config_text.splitlines():
        line = raw.strip()
        if line.startswith("/interface/wireguard/peers"):
            section = "peers"
            continue
        if line.startswith("/") and not line.startswith("/interface/wireguard/peers"):
            section = None
        if section != "peers" or not line.startswith("add "):
            continue
        attrs = dict(re.findall(r'(\S+?)=("[^"]*"|\S+)', line))
        attrs = {k: v.strip('"') for k, v in attrs.items()}
        if "interface" in attrs:
            peers[attrs["interface"]] = attrs
    return peers


def wg_interfaces(config_text):
    """interface name -> private-key, from `/interface/wireguard add ...`."""
    ifaces = {}
    section = None
    for raw in config_text.splitlines():
        line = raw.strip()
        if line.startswith("/interface/wireguard"):
            section = "wg" if not line.startswith("/interface/wireguard/peers") else None
            continue
        if line.startswith("/"):
            section = None
        if section != "wg" or not line.startswith("add "):
            continue
        attrs = dict(re.findall(r'(\S+?)=("[^"]*"|\S+)', line))
        attrs = {k: v.strip('"') for k, v in attrs.items()}
        if "name" in attrs:
            ifaces[attrs["name"]] = attrs
    return ifaces


def public_of(private_b64):
    """Derive the WireGuard public key from a private key, the same way
    wg(8) does. This is what makes the test independent of the generator: it
    never asks generate.py what the public key SHOULD be, it computes it."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)

    priv = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    return base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


@pytest.fixture
def fleet(built):
    """Every rendered router config, keyed by fqdn."""
    return {name: text for name, text in built.configs().items()}


def test_every_tunnel_pairs_the_right_keys(built, fleet):
    """The assertion that counts. For each tunnel, the public key the near end
    configures for its peer must be the public key derived from the FAR end's
    own private key: checked in both directions, from the rendered files."""
    m = built.manifest()
    checked = 0

    for fqdn, r in m["routers"].items():
        near_peers = wg_peers(fleet[fqdn])
        for t in r["tunnels"]:
            far = t["peer_fqdn"]
            iface = t["iface"]
            assert iface in near_peers, f"{fqdn}: no wireguard peer on {iface}"
            configured = near_peers[iface]["public-key"]

            # The far end's interface facing us, and the private key it holds.
            far_r = m["routers"][far]
            far_iface = next(
                (x["iface"] for x in far_r["tunnels"]
                 if x["peer_fqdn"] == fqdn
                 and x["link_class"] == t["link_class"]), None)
            assert far_iface, (
                f"{fqdn}/{iface} points at {far}, but {far} has no matching "
                f"{t['link_class']} tunnel back. The graph is asymmetric.")

            far_private = wg_interfaces(fleet[far])[far_iface]["private-key"]
            assert configured == public_of(far_private), (
                f"{fqdn}/{iface} configures a public key that is NOT derived "
                f"from {far}/{far_iface}'s private key. This tunnel will come "
                f"up and never hand-shake, and no log on either box will say so.")
            checked += 1

    assert checked >= 8, f"only checked {checked} tunnel ends; the fleet is bigger"


def test_both_ends_of_a_tunnel_share_a_preshared_key(built, fleet):
    """The PSK is symmetric by definition. A mismatch is the same silent
    failure as a wrong public key."""
    m = built.manifest()
    for fqdn, r in m["routers"].items():
        near = wg_peers(fleet[fqdn])
        for t in r["tunnels"]:
            far_r = m["routers"][t["peer_fqdn"]]
            far_iface = next(x["iface"] for x in far_r["tunnels"]
                             if x["peer_fqdn"] == fqdn
                             and x["link_class"] == t["link_class"])
            far = wg_peers(fleet[t["peer_fqdn"]])
            assert near[t["iface"]].get("preshared-key") == \
                far[far_iface].get("preshared-key"), (
                f"{fqdn}/{t['iface']} and {t['peer_fqdn']}/{far_iface} have "
                f"different preshared keys")


def test_no_interface_uses_its_own_public_key_as_the_peer(built, fleet):
    """A self-referential tunnel. Sounds impossible; is exactly what an
    off-by-one in the pairing index produces."""
    for fqdn, text in fleet.items():
        ifaces, peers = wg_interfaces(text), wg_peers(text)
        for name, peer in peers.items():
            own = public_of(ifaces[name]["private-key"])
            assert peer["public-key"] != own, (
                f"{fqdn}/{name} lists its OWN public key as the peer")


def test_endpoints_point_at_the_dialing_direction_only(built):
    """WireGuard NAT-piercing here is directional: the ER and the remote site
    DIAL, the BR LISTENS. A BR that grew an `endpoint` toward an ER means the
    direction got inverted, and the tunnel then depends on the ER's consumer
    address being reachable: which is the thing the design specifically
    refuses to depend on."""
    m = built.manifest()
    for fqdn, r in m["routers"].items():
        for t in r["tunnels"]:
            peer_role = m["routers"][t["peer_fqdn"]]["role"]
            if r["role"] == "br" and peer_role in ("er", "sr"):
                assert t["endpoint"] is None, (
                    f"{fqdn}/{t['iface']} has an endpoint toward {t['peer_fqdn']}. "
                    f"The border router must LISTEN on that link, not dial it.")
            if r["role"] in ("er", "sr") and peer_role == "br":
                assert t["endpoint"], (
                    f"{fqdn}/{t['iface']} has no endpoint toward {t['peer_fqdn']}; "
                    f"nothing would ever bring this tunnel up.")


def test_tunnel_31s_are_paired(built):
    """The two ends of a /31 must be the two addresses IN that /31."""
    import ipaddress

    m = built.manifest()
    for fqdn, r in m["routers"].items():
        for t in r["tunnels"]:
            far_r = m["routers"][t["peer_fqdn"]]
            far = next(x for x in far_r["tunnels"]
                       if x["peer_fqdn"] == fqdn
                       and x["link_class"] == t["link_class"])
            a = ipaddress.ip_address(t["address"])
            b = ipaddress.ip_address(far["address"])
            net = ipaddress.ip_network(f"{min(a, b)}/31", strict=False)
            assert a in net and b in net and a != b, (
                f"{fqdn}/{t['iface']} ({a}) and {t['peer_fqdn']}/{far['iface']} "
                f"({b}) are not the two halves of one /31")


def test_listen_ports_are_unique_per_router(built):
    for fqdn, r in built.manifest()["routers"].items():
        ports = [t["listen_port"] for t in r["tunnels"]]
        assert len(ports) == len(set(ports)), (
            f"{fqdn} reuses a WireGuard listen port: {sorted(ports)}")


def test_ibgp_is_a_full_mesh(built):
    """Every router peers with every other, both directions. A missing edge
    means a prefix that reaches half the fleet."""
    m = built.manifest()
    fleet = set(m["routers"])
    for fqdn, r in m["routers"].items():
        peers = {p["peer_fqdn"] for p in r["ibgp"]}
        assert peers == fleet - {fqdn}, (
            f"{fqdn}'s iBGP peer set is {sorted(peers)}, expected the whole "
            f"fleet minus itself")
        for p in r["ibgp"]:
            back = {q["peer_fqdn"] for q in m["routers"][p["peer_fqdn"]]["ibgp"]}
            assert fqdn in back, (
                f"{fqdn} peers with {p['peer_fqdn']} but not the reverse")


def test_ibgp_peers_at_loopbacks_never_at_link_addresses(built):
    """iBGP over a link address dies with the link. Over a loopback it survives
    any single tunnel failing, which is the entire reason the loopbacks exist."""
    m = built.manifest()
    loopbacks = set(m["loopbacks"].values())
    for fqdn, r in m["routers"].items():
        for p in r["ibgp"]:
            assert p["address"] in loopbacks, (
                f"{fqdn}/{p['session']} peers at {p['address']}, which is not "
                f"a loopback")
