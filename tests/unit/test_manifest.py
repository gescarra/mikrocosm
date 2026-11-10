"""
The manifest, the inventory and the child pipeline.

These three files are what turns `topology.yml` into a deployment rather than
just a config. The functional tests assert against the manifest, Ansible reads
the inventory, and GitLab runs the pipeline. So a manifest that quietly
disagrees with the fleet is a set of green tests that prove nothing, which is
strictly worse than no tests.

The theme throughout: assert the DERIVATION, not the current numbers. A test
that hardcodes "4 routers" fails the day a third border router is added, which
teaches everyone to edit the test instead of reading it.
"""

import ipaddress

import pytest


def test_manifest_covers_exactly_the_rendered_fleet(built):
    m = built.manifest()
    rendered = set(built.configs())
    assert set(m["routers"]) == rendered
    assert set(m["deploy_order"]) == rendered
    assert len(m["deploy_order"]) == len(set(m["deploy_order"])), \
        "a router appears twice in the rollout order"


def test_rollout_alternates_border_and_edge(built):
    """The property the order exists for: one BR and one ER are up at every
    step, so the /24 anchor and the /25 are never both dark at once.

    Checked as a property rather than as a literal list, because the literal
    list changes the moment a router is added and the PROPERTY doesn't."""
    m = built.manifest()
    roles = [m["routers"][f]["role"] for f in m["deploy_order"]]
    core = [r for r in roles if r in ("br", "er")]

    # Sites are last: they depend on the core for reachability, so there's
    # nothing to interleave them with.
    assert roles[:len(core)] == core, "a remote site was scheduled before the core"

    n_br = core.count("br")
    n_er = core.count("er")
    # Same-role adjacency is only acceptable once the shorter list runs out.
    forced = abs(n_br - n_er)
    runs = sum(1 for a, b in zip(core, core[1:]) if a == b)
    assert runs <= forced, (
        f"the rollout deploys two routers of the same role back to back more "
        f"often than the {n_br} BR / {n_er} ER split forces ({runs} > {forced}). "
        f"That is a step where one role is entirely down.")


def test_every_router_is_reachable_at_an_address_it_actually_holds(built):
    """`ansible_host` is the address for a control node INSIDE the AS."""
    m = built.manifest()
    for fqdn, r in m["routers"].items():
        host = r["ansible_host"]
        if r["role"] == "er":
            assert host == r["transit_ip"], (
                f"{fqdn} must be reached on its transit address -- the one "
                f"path the ER input chain accepts by interface, which survives "
                f"every tunnel being down, and which works from inside the AS "
                f"without depending on the overlay")
        else:
            assert host == r["loopback"], (
                f"{fqdn} must be reached at its loopback from inside the AS")


def test_no_in_as_address_is_a_border_router_public(built):
    """The bug this replaced, asserted so it can't come back.

    A control node inside 203.0.113.0/24 CANNOT reach a border router at its
    provider WAN. The ERs statically route each BR's public /32 out their own
    WAN (a WireGuard endpoint must never resolve through a tunnel) so the
    request leaves via the ISP, while the BR answers an in-AS source down a
    tunnel using the /25 it learns over iBGP. The handshake never completes.

    Measured on the live fleet before this changed:
        er1 -> 198.51.100.57/32  via 172.20.101.1%ether1   (static)
        br1 -> 203.0.113.7      via wg-er2-wan1           (iBGP, dist 200)
        br1 -> 192.0.2.190       via 198.51.100.1%ether1   (default)

    The third line is why a laptop outside the AS worked throughout and an
    on-prem runner didn't.
    """
    m = built.manifest()
    ours = ipaddress.ip_network(m["prefix"])
    for fqdn, r in m["routers"].items():
        if r["role"] != "br":
            continue
        assert r["ansible_host"] != r["wan_address"], (
            f"{fqdn}'s in-AS address is its provider WAN. That path is "
            f"asymmetric for any source inside {ours} and will hang.")
        assert ipaddress.ip_address(r["ansible_host"]) in ours, (
            f"{fqdn}'s in-AS address {r['ansible_host']} is not inside {ours}, "
            f"so it is not reachable over the overlay")


def test_the_bootstrap_address_does_not_depend_on_the_overlay(built):
    """The failsafe has to be usable when the thing it's a failsafe for is
    down: so for a border router it must be the provider WAN, which exists
    before a single tunnel does."""
    m = built.manifest()
    for fqdn, r in m["routers"].items():
        if r["role"] == "br":
            assert r["bootstrap_host"] == r["wan_address"], (
                f"{fqdn}'s bootstrap address must be its provider WAN; a "
                f"loopback is exactly what is unavailable when you need this")
        else:
            assert r["bootstrap_host"] == r["ansible_host"], (
                f"{fqdn} already uses an address that survives the overlay "
                f"being down; the two should not diverge")


def test_edge_routers_are_never_reached_at_a_wan(built):
    """Stated separately because it's the break-glass property (AD-LOG 25),
    and it would be an easy 'simplification' to make."""
    m = built.manifest()
    for fqdn, r in m["routers"].items():
        if r["role"] != "er":
            continue
        link_addrs = {t["address"] for t in r["tunnels"]}
        assert r["ansible_host"] not in link_addrs


def test_ospf_expectations_match_the_ospf_speaking_interfaces(built):
    m = built.manifest()
    for fqdn, r in m["routers"].items():
        assert r["ospf_neighbors_expected"] == len(r["ospf_interfaces"])
        assert len(set(r["ospf_interfaces"])) == len(r["ospf_interfaces"]), \
            f"{fqdn} lists an OSPF interface twice"
        # Every tunnel runs OSPF; an ER additionally runs it over the physical
        # cross-connect to its sibling.
        expected = len(r["tunnels"]) + (1 if r["role"] == "er" else 0)
        assert r["ospf_neighbors_expected"] == expected


def test_ibgp_expectations_are_the_full_mesh(built):
    m = built.manifest()
    n = len(m["routers"])
    for fqdn, r in m["routers"].items():
        assert len(r["ibgp"]) == n - 1, (
            f"{fqdn} expects {len(r['ibgp'])} iBGP sessions in a {n}-router "
            f"full mesh")


def test_border_routers_expect_an_upstream_and_an_anchor(built):
    m = built.manifest()
    brs = [r for r in m["routers"].values() if r["role"] == "br"]
    assert brs, "a fleet with no border router originates nothing"
    for r in brs:
        assert r["ebgp"], f"{r['fqdn']} has no upstream session to verify"
        assert m["prefix"] in [a["prefix"] for a in r["anchors"]]
        assert m["prefix"] in r["originates"]
        assert r["expect_default"]["v4"] is True


def test_edge_routers_expect_customers_and_the_home_anchor(built):
    m = built.manifest()
    ers = [r for r in m["routers"].values() if r["role"] == "er"]
    assert ers
    for r in ers:
        assert r["customers"], f"{r['fqdn']} has no customer session to verify"
        assert m["customer_home"] in [a["prefix"] for a in r["anchors"]]
        # An ER has no default of its own. Expecting one is what makes the
        # functional test meaningful: it can only be there if the tunnels, OSPF
        # and iBGP all came up.
        assert r["expect_default"]["v4"] is True


def test_every_customer_grant_is_inside_the_home_block(built):
    """The security boundary, restated in the file the tests read. If a grant
    ever widened past the /25 the validator would refuse it. But the tests
    shouldn't be quietly asserting against a wider boundary either."""
    m = built.manifest()
    home = ipaddress.ip_network(m["customer_home"])
    home6 = ipaddress.ip_network(m["customer_home_v6"]) if m["v6"] else None
    for r in m["routers"].values():
        for c in r.get("customers", []):
            for claim in c["claims"]:
                net = ipaddress.ip_network(claim["prefix"])
                parent = home if claim["family"] == 4 else home6
                assert net.subnet_of(parent), (
                    f"{c['name']}'s grant {claim['prefix']} is outside {parent}")
                assert claim["min_len"] <= claim["max_len"]


def test_bfd_expectations_track_both_switches(built, render, topology):
    """`configure` permits sessions; `use_ospf` asks for them. A manifest that
    expected sessions after pass 1 would fail the rollout the two-pass process
    exists to make safe."""
    # Any router, not a named one. See the note on hardcoding above.
    any_router = next(iter(built.manifest()["routers"].values()))
    assert any_router["bfd"]["expect_ospf_sessions"] \
        is (topology["bfd"]["configure"] and topology["bfd"]["use_ospf"])

    topology["bfd"]["use_ospf"] = False
    r = render(topology)
    assert r.ok, r.output
    for entry in r.manifest()["routers"].values():
        assert entry["bfd"]["expect_ospf_sessions"] is False, (
            "pass 1 of the BFD rollout renders the permits and asks for no "
            "sessions; the tests must not expect any")


# ---------------------------------------------------------------------
#  The inventory
# ---------------------------------------------------------------------
def test_inventory_hosts_match_the_manifest_in_rollout_order(built):
    inv = built.inventory()
    hosts = list(inv["all"]["children"]["routers"]["hosts"])
    assert hosts == built.manifest()["deploy_order"], (
        "the inventory's host order IS the rollout order (serial:1 + "
        "order:inventory), so it has to be the order the manifest states")


def test_inventory_carries_the_address_and_role_ansible_needs(built):
    m = built.manifest()
    hosts = built.inventory()["all"]["children"]["routers"]["hosts"]
    for fqdn, vars_ in hosts.items():
        assert vars_["ansible_host"] == m["routers"][fqdn]["ansible_host"]
        assert vars_["bootstrap_host"] == m["routers"][fqdn]["bootstrap_host"]
        assert vars_["router_role"] == m["routers"][fqdn]["role"]
        assert vars_["loopback"] == m["routers"][fqdn]["loopback"]


def test_inventory_groups_by_role(built):
    """So a playbook can say `hosts: br` instead of re-deriving it from a
    variable, which is how a fleet ends up with two definitions of 'border
    router' that disagree."""
    m = built.manifest()
    inv = built.inventory()["all"]["children"]
    for role in ("br", "er"):
        expected = {f for f, r in m["routers"].items() if r["role"] == role}
        assert set(inv[role]["hosts"]) == expected


def test_inventory_carries_no_operational_tuning(built):
    """Timeouts and SSH options are decisions about how to drive a rollout, not
    facts about the topology. They live in group_vars, committed. Generating
    them would put a hand-tuned value in a file the next build overwrites."""
    inv = built.inventory()
    assert "vars" not in inv["all"], (
        "the generated inventory grew a vars block; those belong in "
        "ansible/group_vars/all.yml where they survive a rebuild")


# ---------------------------------------------------------------------
#  The child pipeline
# ---------------------------------------------------------------------
def test_pipeline_has_a_deploy_and_a_verify_job_per_router(built):
    m = built.manifest()
    p = built.pipeline()
    for fqdn in m["deploy_order"]:
        assert f"deploy:{fqdn}" in p, f"no deploy job for {fqdn}"
        assert f"verify:{fqdn}" in p, f"no verify job for {fqdn}"


def job_needs(job):
    """The JOB dependencies of a generated job.

    Filters out the `{pipeline:, job:}` entry, which isn't a gate. It only
    tells GitLab to fetch the parent pipeline's build artifacts. Mixing the two
    in one list is GitLab's shape, not ours; what matters here is which job
    must PASS before this one may start."""
    return [n for n in job.get("needs", []) if isinstance(n, str)]


def artifact_needs(job):
    return [n for n in job.get("needs", []) if isinstance(n, dict)]


def test_every_job_fetches_the_build_artifacts(built):
    """Each rollout job re-renders from the build job's pin and asserts against
    its manifest, so every one of them needs those artifacts. A job's own
    `needs:` REPLACES the inherited one, so this can't live in the template."""
    p = built.pipeline()
    for name, job in p.items():
        if name in ("include", "stages"):
            continue
        assert artifact_needs(job) == [
            {"pipeline": "$PARENT_PIPELINE_ID", "job": "build"}], (
            f"{name} does not pull the parent pipeline's build artifacts; it "
            f"would render from unpinned inputs or find no manifest at all")


def test_every_deploy_is_gated_on_the_previous_verify(built):
    """The gate the whole design turns on, expressed as a DAG edge rather than
    a check inside a script: if verify:<N> fails, deploy:<N+1> never becomes
    eligible, so router N+1 isn't touched."""
    m = built.manifest()
    p = built.pipeline()
    order = m["deploy_order"]

    assert job_needs(p[f"deploy:{order[0]}"]) == ["baseline"], (
        "the first deploy must be gated on the pre-flight health check")

    for prev, cur in zip(order, order[1:]):
        assert job_needs(p[f"deploy:{cur}"]) == [f"verify:{prev}"], (
            f"deploy:{cur} is not gated on verify:{prev}; the rollout would "
            f"continue past a router that failed its tests")

    for fqdn in order:
        assert job_needs(p[f"verify:{fqdn}"]) == [f"deploy:{fqdn}"]


def test_pipeline_ends_in_an_end_to_end_run(built):
    p = built.pipeline()
    order = built.manifest()["deploy_order"]
    assert job_needs(p["e2e"]) == [f"verify:{order[-1]}"]


def test_the_chaos_job_is_never_automatic(built, repo_root):
    """It breaks a live path on purpose. It must be something you choose."""
    import yaml
    p = built.pipeline()
    assert "chaos" in p
    jobs = yaml.safe_load((repo_root / "ci" / "child-jobs.yml").read_text())
    assert jobs[".chaos"]["when"] == "manual", (
        "the chaos job would run on its own; it disables live sessions")


def test_pipeline_delegates_job_bodies_to_a_committed_file(built):
    """Generated YAML isn't reviewed as carefully as committed YAML, so the
    generated half stays declarative: which routers, in what order. The shell
    that actually resets a router lives in a file that shows up in a diff."""
    p = built.pipeline()
    assert p["include"] == [{"local": "ci/child-jobs.yml"}]
    for name, job in p.items():
        if name in ("include", "stages"):
            continue
        assert "script" not in job, (
            f"generated job {name} carries an inline script; job bodies belong "
            f"in ci/child-jobs.yml")
        assert job["extends"].startswith(".")


def test_adding_a_router_grows_the_pipeline_without_anyone_editing_it(
        render, topology):
    """The point of generating the pipeline at all.

    A remote site is the cheapest router to add here (it needs one entry and
    derives the rest) so it's what this uses to prove the property."""
    topology["sites"] = [{
        "name": "sfo", "index": 1, "router": "sr1",
        "wans": [{"id": "wan1", "interface": "ether1"}],
        "lan_interfaces": ["ether2", "ether3"],
    }]
    r = render(topology)
    assert r.ok, r.output
    m, p = r.manifest(), r.pipeline()

    assert "sr1.sfo" in m["routers"]
    assert m["deploy_order"][-1] == "sr1.sfo", "a site must roll after the core"
    assert "deploy:sr1.sfo" in p and "verify:sr1.sfo" in p
    assert job_needs(p["e2e"]) == ["verify:sr1.sfo"]

    # And every existing router grew a tunnel and an iBGP session to it.
    for fqdn, entry in m["routers"].items():
        if fqdn == "sr1.sfo":
            continue
        if entry["role"] == "br":
            assert any(t["peer_fqdn"] == "sr1.sfo" for t in entry["tunnels"]), (
                f"{fqdn} did not gain a tunnel to the new site")
        assert any(i["peer_fqdn"] == "sr1.sfo" for i in entry["ibgp"]), (
            f"{fqdn} did not gain an iBGP session to the new site")


def test_every_needs_target_is_in_the_same_or_an_earlier_stage(built, repo_root):
    """GitLab's rule, which the generated chain violated.

    `needs:` may only reference a job in the SAME or an EARLIER stage. The
    rollout interleaves (deploy, verify, deploy, verify) so deploy and
    verify CANNOT be separate ordered stages: the second deploy would need a
    verify living in a later one, and GitLab refuses the whole pipeline at
    creation time with

        deploy:er1.hdc job: need verify:br1.ord1 isn't defined in current or
        prior stages

    That failure happens when the child pipeline is CREATED, so nothing runs
    and there's no job log to read. The entire rollout is simply absent.
    Cheap to assert here, invisible until production otherwise.
    """
    import yaml

    p = built.pipeline()
    bodies = yaml.safe_load((repo_root / "ci" / "child-jobs.yml").read_text())
    order = {name: i for i, name in enumerate(p["stages"])}

    def stage_of(job):
        # The generated jobs carry no `stage:` of their own. It comes from the
        # template they extend, which is why this has to read both files.
        body = p[job]
        if "stage" in body:
            return body["stage"]
        return bodies[body["extends"]]["stage"]

    for job, body in p.items():
        if job in ("include", "stages"):
            continue
        here = stage_of(job)
        assert here in order, f"{job} is in stage {here!r}, not declared in stages"
        for need in body.get("needs", []):
            if not isinstance(need, str):
                continue          # the parent-artifact entry, not a job edge
            there = stage_of(need)
            assert order[there] <= order[here], (
                f"{job} (stage {here}) needs {need} (stage {there}), which is "
                f"LATER. GitLab refuses the pipeline at creation.")


def test_the_functional_suite_understands_the_schema_this_build_emits(built):
    """emit.py's `schema` and the functional suite's MANIFEST_SCHEMA must agree.

    They live in two files with nothing but this test linking them, and the
    failure mode when they drift is expensive and late: `pytest` runs
    tests/unit, so a schema bump looks completely clean locally and on the
    lint stage, then every functional test errors out at the FIRST ROLLOUT JOB.
    After the build has been promoted and the pipeline is already touching
    routers. The guard is doing its job when that happens; it just finds out at
    the worst possible moment.

    Asserting it here moves the discovery to the suite that gates every merge
    and needs no hardware to run. Bumping the schema is fine; bumping it in
    only one of the two places is what this refuses.
    """
    from tests.functional.conftest import MANIFEST_SCHEMA

    emitted = built.manifest()["schema"]
    assert emitted == MANIFEST_SCHEMA, (
        f"emit.py emits manifest schema {emitted}, but "
        f"tests/functional/conftest.py understands {MANIFEST_SCHEMA}. The "
        f"functional suite would fail every test at the first rollout job. "
        f"Bump MANIFEST_SCHEMA and update any assertion whose keys moved.")
