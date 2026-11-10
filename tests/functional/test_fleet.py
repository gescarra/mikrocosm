"""
Questions no single router can answer about itself.

Every check in test_router.py asks a router about its own state, and every one
of them can pass while a NEIGHBOUR is broken. A wrong key on br1's
`wg-er1-wan1` leaves br1 with one dead tunnel out of four, which its own OSPF
count catches. A wrong LISTEN PORT leaves br1 perfectly happy (it's
listening, nothing is wrong from where it's standing) and er1 unable to
reach it. er1 isn't the host under test.

So after deploying a router, ask the rest of the fleet about it.
"""

import pytest


@pytest.fixture(scope="session")
def focus(pytestconfig, manifest):
    name = pytestconfig.getoption("--focus")
    if not name:
        return None
    if name not in manifest["routers"]:
        pytest.fail(f"--focus {name} is not in the manifest", pytrace=False)
    return name


def test_every_other_router_still_reaches_the_focused_one(
        focus, routers, manifest):
    """The check the pipeline runs after each deploy.

    Deliberately from every OTHER router rather than from the control node: the
    control node reaches an edge router on its transit address, which the input
    chain accepts by interface and which therefore works even when every tunnel
    is down. That's the right property for a break-glass path and the wrong
    one for a reachability test.
    """
    if not focus:
        pytest.skip("no --focus router given")

    target = manifest["loopbacks"][focus]
    unreachable = []
    for fqdn, dev in routers.items():
        if fqdn == focus:
            continue
        src = manifest["loopbacks"][fqdn]
        if dev.ping(target, src=src, count=3) == 0:
            unreachable.append(fqdn)

    assert not unreachable, (
        f"{', '.join(unreachable)} can no longer reach {focus} ({target}) over "
        f"the loopback mesh, even though {focus} passed every check about "
        f"itself.\n"
        f"A router can be entirely healthy from its own point of view and "
        f"unreachable from a peer -- a mismatched WireGuard listen port does "
        f"exactly that, and only the peer knows.\n"
        f"DO NOT DEPLOY THE NEXT ROUTER.")


def test_the_ibgp_mesh_is_complete_in_both_directions(routers, manifest,
                                                      pytestconfig):
    """A full mesh is only full if every edge exists from both ends.

    Skipped when a single router is selected: this needs the whole fleet, and
    running it during a per-router gate would fail on the routers that haven't
    been deployed yet: which is a fact about the rollout being in progress,
    not about anything being wrong.
    """
    if pytestconfig.getoption("--router"):
        pytest.skip("needs the whole fleet; run without --router")

    from .routeros import as_bool

    established = {}
    for fqdn, dev in routers.items():
        claims = []
        sessions = dev.probe(claims).get("bgp", [])
        established[fqdn] = {
            str(s.get("remote.address", "")).split("/")[0].strip().lower()
            for s in sessions if as_bool(s.get("established", False))
        }

    missing = []
    for fqdn, r in manifest["routers"].items():
        for peer in r["ibgp"]:
            if peer["address"].lower() not in established.get(fqdn, set()):
                missing.append(f"{fqdn} -> {peer['peer_fqdn']}")

    assert not missing, (
        f"iBGP mesh incomplete: {', '.join(missing)}.\n"
        f"There is no route reflector here, so every missing edge is a set of "
        f"prefixes that never reaches that router.")
