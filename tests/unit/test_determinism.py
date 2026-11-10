"""
Determinism and key idempotence.

Two properties the pipeline is built on top of, neither of which is obvious
enough to leave unasserted:

  1. Same topology + same keystore -> BYTE-IDENTICAL output. The whole
     change-detection scheme depends on it. `deploy.yml` decides whether to
     reset a router by comparing a fresh render's sha256 against a fingerprint
     stashed on the device; if rendering were nondeterministic, every router
     would look changed on every run and the pipeline would reset the entire
     fleet on a no-op commit. It also lets the build job and the deploy job
     render separately and still be talking about the same config.

  2. Re-running NEVER regenerates an existing key. This one is the big one: a silent rotation would bring every tunnel up with
     handshakes that fail, and nothing anywhere would say why.
"""

import json


def test_two_renders_are_byte_identical(render):
    """The second render reuses the first's keystore, exactly as a second
    ./build.sh does."""
    a = render()
    assert a.ok, a.output
    b = render()
    assert b.ok, b.output

    for name, text in a.configs().items():
        assert text == b.configs()[name], (
            f"{name}.rsc differs between two renders of an unchanged topology. "
            f"Change detection compares a fresh render against the fingerprint "
            f"on the device, so this makes every router look changed forever.")


def test_derived_artifacts_are_deterministic_too(render):
    """The inventory and the child pipeline are inputs to the rollout, not
    decoration: a nondeterministic job list is a nondeterministic rollout."""
    a, b = render(), render()
    assert (a.out / "inventory.yml").read_text() == (b.out / "inventory.yml").read_text()
    assert (a.out / "pipeline.yml").read_text() == (b.out / "pipeline.yml").read_text()


def test_existing_keys_are_never_regenerated(render):
    """The single most destructive thing a re-run could do."""
    a = render()
    assert a.ok, a.output
    first = json.loads(a.keys_path.read_text())
    assert first, "the first render should have created a keystore"

    b = render()
    assert b.ok, b.output
    second = json.loads(b.keys_path.read_text())

    assert first == second, (
        "a second render rotated keys. Every tunnel would come up and every "
        "handshake would fail, with nothing in any log to explain it.")


def test_adding_a_router_leaves_existing_keys_alone(render, topology):
    """Growth must be additive. Adding a border router regenerates every
    router's CONFIG (that's the point) but it must not touch a single
    existing key, or the new BR's rollout takes the whole fleet with it."""
    a = render()
    assert a.ok, a.output
    before = json.loads(a.keys_path.read_text())

    topology["border_routers"].append({
        "name": "br3", "site": "ord3", "index": 3,
        "provider": "test", "wan_address": "203.0.113.9", "wan_prefix": 24,
        "wan_gateway": "203.0.113.1", "static_default": True,
        "peer_address": "169.254.169.254", "peer_asn": 65550,
        "upstream_communities": [],
        "wan_v6": {"address": "2001:db8:113::9", "prefix": 64, "gateway": "fe80::1"},
    })
    # A third BR is a real topology change and may legitimately be refused for
    # reasons of its own (the /31 budget, a missing te: block). Either way the
    # KEYSTORE must not have lost anything.
    b = render(topology, keys=a.keys_path)
    after = json.loads(b.keys_path.read_text())

    for ident, key in before.items():
        assert after.get(ident) == key, (
            f"adding a router changed the existing key {ident!r}. Only NEW "
            f"interfaces may get new keys.")


def test_a_topology_edit_changes_the_config_it_should(render, topology):
    """The mirror of the determinism test, and just as necessary: output that
    is stable no matter what you feed it's not deterministic, it's broken."""
    a = render()
    topology["ospf_cost"]["wan2"] = 250
    b = render(topology, keys=a.keys_path)
    assert b.ok, b.output
    assert a.config("er1.hdc") != b.config("er1.hdc"), (
        "changing an OSPF cost produced an identical ER config")
    assert "cost=250" in b.config("er1.hdc")
