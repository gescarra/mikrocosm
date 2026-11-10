"""
The validator, tested by breaking things.

`generate.py`'s `validate()` is the only thing standing between a typo in
`topology.yml` and a router that has already been wiped by
`reset-configuration` when the bad line is rejected. The repo README lists what
it refuses; this asserts that the list is true, one mutation at a time.

Every test here starts from the REAL topology and breaks exactly one thing.
Sounds minor. It isn't. A validator exercised only against purpose-
built fixtures keeps passing while the fleet it guards grows features the
fixtures never had. Breaking the live topology means these tests fail the day a
rule stops covering the network it's supposed to cover.

The shape is always the same. Mutate, render, assert the build REFUSED and
said why. Asserting on the message is deliberate: a validator that rejects for
the wrong reason is a validator that will reject the wrong thing later.
"""

import pytest


def assert_refused(r, *fragments):
    """The build failed, and its message names the actual problem."""
    assert not r.ok, (
        "expected the build to REFUSE this topology, but it rendered:\n"
        + r.output)
    out = r.output.lower()
    for f in fragments:
        assert f.lower() in out, (
            f"build refused, but never mentioned {f!r}. An error nobody can act "
            f"on is barely better than no error.\n{r.output}")


# ---------------------------------------------------------------------
#  The committed topology must pass. If this fails, nothing else means anything.
# ---------------------------------------------------------------------
def test_committed_topology_validates(render):
    r = render(args=["--check"])
    assert r.ok, f"the committed topology.yml no longer validates:\n{r.output}"


def test_check_json_is_machine_readable(render):
    """The pipeline reads this, so its shape is a contract."""
    import json
    r = render(args=["--check", "--json"])
    assert r.ok
    doc = json.loads(r.stdout)
    assert doc["ok"] is True
    assert doc["errors"] == []
    assert "br1.ord1" in doc["routers"]
    assert len(doc["topology_sha256"]) == 64


def test_check_json_reports_errors_as_data(render, topology):
    """A failing --check --json must still be parseable. A pipeline that has to
    scrape prose out of stderr to find out what broke will scrape it wrong."""
    import json
    topology["mss_clamp"] = 9999
    r = render(topology, args=["--check", "--json"])
    assert not r.ok
    doc = json.loads(r.stdout)
    assert doc["ok"] is False
    assert any("mss_clamp" in e for e in doc["errors"])


# ---------------------------------------------------------------------
#  Addressing
# ---------------------------------------------------------------------
def test_duplicate_address_is_refused(render, topology):
    """Two things on one address is the single most consequential typo
    available here, and the symptom on the wire isn't 'duplicate address'.
    It's one of the two silently never working."""
    topology["home"]["transit_er2"] = topology["home"]["transit_er1"]
    assert_refused(render(topology), "duplicate")


def test_address_outside_the_prefix_is_refused(render, topology):
    topology["home"]["transit_er1"] = "198.51.100.5"
    assert_refused(render(topology), "198.51.100.5")


def test_firewall_peer_colliding_with_infrastructure_is_refused(render, topology):
    topology["firewalls"][0]["peer_address"] = topology["home"]["transit_er1"]
    assert_refused(render(topology), "duplicate")


# ---------------------------------------------------------------------
#  MTU / MSS: the one that fails silently on the wire
#  (Pings are perfect, big downloads hang, and everybody blames the ISP.)
# ---------------------------------------------------------------------
def test_mss_clamp_must_match_wg_mtu(render, topology):
    """A wrong clamp gives you a network where ping is flawless and every TCP
    connection over ~1300 bytes stalls. Nothing on the router reports it."""
    topology["mss_clamp"] = topology["wg_mtu"] - 40 + 1
    assert_refused(render(topology), "mss_clamp")


def test_mss_clamp_v6_must_match_wg_mtu(render, topology):
    topology["mss_clamp_v6"] = topology["wg_mtu"] - 60 + 1
    assert_refused(render(topology), "mss_clamp_v6")


def test_mtu_change_alone_is_accepted_and_moves_both_clamps(render, topology):
    """The clamps are DERIVED. Changing the MTU and nothing else must work.
    Otherwise the validator's own rule becomes a reason not to fix an MTU."""
    topology["wg_mtu"] = 1300
    topology["mss_clamp"] = 1260
    topology.pop("mss_clamp_v6", None)   # derived; absent in the committed file
    r = render(topology, args=["--check"])
    assert r.ok, r.output


# ---------------------------------------------------------------------
#  Route distances: the ordering the whole design rests on
# ---------------------------------------------------------------------
@pytest.mark.parametrize("distance", [20, 10, 200, 254])
def test_provider_default_distance_bounds(render, topology, distance):
    """It has to LOSE to the eBGP default (20) and BEAT iBGP (200). Outside
    that window a border router silently egresses through a sibling's transit
    and gets its own-sourced packets dropped at that provider's BCP38 filter."""
    topology["provider_default_distance"] = distance
    assert_refused(render(topology), "provider_default_distance")


def test_provider_default_distance_inside_the_window_is_accepted(render, topology):
    topology["provider_default_distance"] = 100
    assert render(topology, args=["--check"]).ok


# ---------------------------------------------------------------------
#  BGP multipath: a type error that aborts the import mid-file
# ---------------------------------------------------------------------
def test_bgp_multipath_true_is_refused_by_name(render, topology):
    """`multipath` is a COUNT. `multipath=yes` is a type error RouterOS rejects,
    and because the apply path is reset-configuration + run-after-reset, a
    rejected line means every /routing/bgp statement after it never ran. On a
    box that has already been wiped."""
    topology["bgp_multipath"] = True
    assert_refused(render(topology), "multipath")


@pytest.mark.parametrize("value", [1, 17, "two"])
def test_bgp_multipath_out_of_range_is_refused(render, topology, value):
    topology["bgp_multipath"] = value
    assert_refused(render(topology), "multipath")


# ---------------------------------------------------------------------
#  Customer grants: the security boundary
# ---------------------------------------------------------------------
def test_grant_outside_the_home_block_is_refused(render, topology):
    """The inbound filter IS the security boundary. A grant outside the /25 is
    an ER configured to accept an advertisement for space that isn't the
    customer's to claim."""
    topology["firewalls"][0]["delegations"] = [
        {"prefix": "203.0.113.192/28", "max_len": 32}]
    assert_refused(render(topology), "203.0.113.192/28")


def test_granting_the_whole_home_aggregate_is_refused(render, topology):
    """A firewall claims more-specifics; the /25 aggregate is the ER's to
    originate. Granting it would let the customer originate the aggregate the
    home-anchor guard uses as its liveness signal."""
    topology["firewalls"][0]["delegations"] = [
        {"prefix": topology["blocks"]["customer_home"], "max_len": 32}]
    assert_refused(render(topology), topology["blocks"]["customer_home"])


def test_customer_asn_colliding_with_ours_is_refused(render, topology):
    topology["firewalls"][0]["asn"] = topology["asn"]
    assert_refused(render(topology), str(topology["asn"]))


def test_customer_asn_colliding_with_an_upstream_is_refused(render, topology):
    upstream = topology["border_routers"][0]["peer_asn"]
    topology["firewalls"][0]["asn"] = upstream
    assert_refused(render(topology), str(upstream))


def test_unknown_firewall_type_is_refused(render, topology):
    """A typo'd dialect must not leave an ER waiting on a session whose other
    end was never generated.

    Applied to whichever firewall happens to be last, never to a named one.
    An earlier version indexed `firewalls[2]` and broke the day a firewall was
    removed from topology.yml. The exact mistake test_manifest.py warns
    about, made in the file that should have known better."""
    if not topology["firewalls"]:
        pytest.skip("no customer firewalls in this topology")
    topology["firewalls"][-1]["type"] = "unfi"
    assert_refused(render(topology), "unfi")


# ---------------------------------------------------------------------
#  Traffic engineering: all border routers or none
# ---------------------------------------------------------------------
def test_te_set_on_some_border_routers_but_not_all_is_refused(render, topology):
    """A partial set is the failure this rule exists for: the unset BR quietly
    lands on RouterOS's default while the other is being steered, and the
    result looks like working traffic engineering that steers the wrong way.

    The partial set is built by CLEARING `te` off every BR first, never by
    assuming the committed topology has none. It shipped assuming that, and
    the day topology.yml grew real TE on both BRs the mutation stopped making
    a partial set at all. It overwrote one complete `te` with another, the
    build correctly rendered, and the test failed while the rule it guards was
    working perfectly."""
    if len(topology["border_routers"]) < 2:
        pytest.skip("all-or-nothing needs a second BR to be partial about")
    for br in topology["border_routers"]:
        br.pop("te", None)
    topology["border_routers"][0]["te"] = {"prepend": 3, "local_pref": 100}
    assert_refused(render(topology), "te")


def test_te_on_every_border_router_is_accepted(render, topology):
    for i, br in enumerate(topology["border_routers"]):
        br["te"] = {"prepend": i * 2, "local_pref": 200 - i * 50}
    r = render(topology, args=["--check"])
    assert r.ok, r.output


@pytest.mark.parametrize("prepend", [-1, 11])
def test_te_prepend_out_of_range_is_refused(render, topology, prepend):
    for br in topology["border_routers"]:
        br["te"] = {"prepend": prepend, "local_pref": 100}
    assert_refused(render(topology), "prepend")


def test_unknown_te_key_is_refused(render, topology):
    for br in topology["border_routers"]:
        br["te"] = {"prepend": 1, "local_pref": 100, "preprend": 4}
    assert_refused(render(topology), "preprend")


# ---------------------------------------------------------------------
#  SNMP: a monitoring plane that must not be the way in
# ---------------------------------------------------------------------
def test_snmp_md5_is_refused_by_name(render, topology):
    topology["snmp"]["auth_protocol"] = "MD5"
    assert_refused(render(topology), "md5")


def test_snmp_des_is_refused_by_name(render, topology):
    topology["snmp"]["encryption_protocol"] = "DES"
    assert_refused(render(topology), "des")


def test_snmp_source_open_to_the_world_is_refused(render, topology):
    topology["snmp"]["sources"] = ["0.0.0.0/0"]
    assert_refused(render(topology), "0.0.0.0/0")


def test_snmp_user_public_is_refused(render, topology):
    """`public` is the default v1/v2c community the templates NEUTRALISE. Using
    it as the v3 user name has every router disable your own user on import."""
    topology["snmp"]["user"] = "public"
    assert_refused(render(topology), "public")


def test_snmp_enabled_with_placeholder_sources_is_refused(render, topology):
    topology["snmp"]["enabled"] = True
    topology["snmp"]["sources"] = ["REPLACE-ME"]
    assert_refused(render(topology), "replace-me")


def test_snmp_engine_id_suffix_too_long_is_refused(render, topology):
    """The fqdn is the engine-id-suffix, and an engine-id has 27 octets left
    after RouterOS's prefix. Longer, and the last line of the import fails."""
    topology["snmp"]["enabled"] = True
    topology["border_routers"][0]["site"] = "a-very-long-site-name-xyz"
    assert_refused(render(topology), "engine-id-suffix")


def test_snmp_shared_engine_id_is_refused(render, topology):
    """Two routers, one engine-id: Zabbix polls only the first one it reached
    and reports a timeout for the other. The bug this check exists for."""
    topology["snmp"]["enabled"] = True
    a, b = topology["border_routers"][:2]
    b["name"], b["site"] = a["name"], a["site"]
    assert_refused(render(topology), "engine-id")


# ---------------------------------------------------------------------
#  BFD: asking for a session nothing can answer
# ---------------------------------------------------------------------
def test_bfd_use_ospf_without_configure_is_refused(render, topology):
    """`configure` PERMITS sessions; `use_ospf` ASKS for them. Asking without
    permitting is a router requesting BFD on interfaces where RouterOS forbids
    it: the exact state the documented two-pass rollout exists to avoid."""
    topology["bfd"]["configure"] = False
    topology["bfd"]["use_ospf"] = True
    assert_refused(render(topology), "bfd")


def test_customer_bfd_without_customer_timers_is_refused(render, topology):
    """`bfd: true` on a firewall renders use-bfd=yes on the ER's session, but
    the PERMIT comes from bfd.customer. Without it the ER asks the firewall for
    a session its own transit interface won't allow."""
    topology["bfd"]["customer"] = None
    assert_refused(render(topology), "bfd")


def test_customer_bfd_on_a_generated_peer_without_a_bfd_renderer_is_refused(
        render, topology):
    """A firewall whose OWN config this build renders, using a dialect that
    emits no BFD stanza, must not be allowed to set `bfd: true`. It would build
    an ER asking a generated peer for a session the generated peer was never
    told to answer: and the entire point of rendering both ends from one
    grant is that they can't disagree.

    The condition is CONSTRUCTED rather than looked up. Naming a specific
    firewall made this test a hostage to topology.yml's current contents, and
    it duly broke when that firewall was removed."""
    if not topology["firewalls"]:
        pytest.skip("no customer firewalls in this topology")
    victim = topology["firewalls"][-1]
    victim["type"] = "unifi"      # a real dialect whose renderer emits no BFD
    victim["bfd"] = True
    assert_refused(render(topology), victim["name"])


def test_bfd_interval_below_the_floor_is_refused(render, topology):
    topology["bfd"]["links"]["backbone"] = {"interval": "10ms", "multiplier": 3}
    assert_refused(render(topology), "backbone")


# ---------------------------------------------------------------------
#  Management access: the way back in
# ---------------------------------------------------------------------
def test_empty_mgmt_prefixes_is_refused(render, topology):
    """SSH and winbox are both bound to this list. Rendering it empty is
    rendering a fleet nobody can log into, applied by a flow that reboots each
    box as it goes."""
    topology["mgmt_prefixes"] = []
    assert_refused(render(topology), "mgmt_prefixes")


def test_zero_ssh_keys_is_refused(render, tmp_path, renderable_topology_text):
    """The import CLEARS the user's keys before re-adding them. Rendering with
    none would wipe access and put nothing back."""
    import hashlib
    import json
    import subprocess
    import sys
    from tests.conftest import ROOT

    work = tmp_path / "nokeys"
    work.mkdir()
    (work / "topology.yml").write_text(renderable_topology_text)
    (work / "pin.json").write_text(json.dumps({
        "topology_sha256": hashlib.sha256(renderable_topology_text.encode()).hexdigest(),
        "ssh_keys": [],
        "mgmt_prefixes_fetched": [],
    }))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "generate.py"),
         "--topology", str(work / "topology.yml"),
         "--keys", str(work / "k.json"),
         "--out", str(work / "out"),
         "--use-pin", str(work / "pin.json")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode != 0
    assert "refusing to render" in (proc.stdout + proc.stderr).lower()


# ---------------------------------------------------------------------
#  Pinning: the pipeline's reproducibility guarantee
# ---------------------------------------------------------------------
def test_a_pin_from_a_different_topology_is_refused(
        render, tmp_path, renderable_topology_text):
    """A pin taken against another commit would render THIS commit's routers
    with THAT commit's management access. Refusing is the only safe answer."""
    import hashlib
    import json
    import subprocess
    import sys
    from tests.conftest import FAKE_SSH_KEY, ROOT

    work = tmp_path / "stale"
    work.mkdir()
    (work / "topology.yml").write_text(renderable_topology_text)
    (work / "pin.json").write_text(json.dumps({
        "topology_sha256": hashlib.sha256(b"a different topology").hexdigest(),
        "ssh_keys": [FAKE_SSH_KEY],
        "mgmt_prefixes_fetched": [],
    }))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "generate.py"),
         "--topology", str(work / "topology.yml"),
         "--keys", str(work / "k.json"),
         "--out", str(work / "out"),
         "--use-pin", str(work / "pin.json")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode != 0
    assert "different topology" in (proc.stdout + proc.stderr).lower()


# ---------------------------------------------------------------------
#  The automation login: a machine account on every router in the AS
# ---------------------------------------------------------------------
def test_automation_placeholder_key_is_refused(render, topology):
    """The committed topology.yml ships REPLACE-ME deliberately: the private
    half has to be generated by whoever will hold it. Rendering the placeholder
    would create a `gitlab-runner` account with a key nothing holds."""
    topology["automation"]["keys"] = ["REPLACE-ME"]
    assert_refused(render(topology), "replace-me")


def test_automation_with_no_keys_is_refused(render, topology):
    """An account with no key is a login nothing can use, and nothing later
    notices: CI fails at the first ssh with a permission error that reads
    exactly like an unreachable router."""
    topology["automation"]["keys"] = []
    assert_refused(render(topology), "automation.keys")


def test_a_private_key_in_the_automation_block_is_refused(render, topology):
    """topology.yml is COMMITTED. Pasting the wrong half of the keypair is a
    one-keystroke mistake with a very long tail, so it's refused by name
    rather than merely failing to import on the router."""
    topology["automation"]["keys"] = [
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n-----END OPENSSH PRIVATE KEY-----"]
    assert_refused(render(topology), "private key")


def test_something_that_is_not_a_public_key_is_refused(render, topology):
    topology["automation"]["keys"] = ["hunter2"]
    assert_refused(render(topology), "public")


def test_automation_sharing_the_human_account_is_refused(render, topology):
    """Sharing one account defeats the entire point. And actively breaks:
    the human key import CLEARS that user's keys on every build, so each render
    would delete the runner's key."""
    topology["automation"]["user"] = topology["ssh"]["user"]
    assert_refused(render(topology), topology["ssh"]["user"])


def test_automation_as_admin_is_refused(render, topology):
    topology["automation"]["user"] = "admin"
    assert_refused(render(topology), "admin")


@pytest.mark.parametrize("missing", ["ssh", "read", "write", "reboot",
                                     "ftp", "test"])
def test_every_policy_the_pipeline_needs_is_required(render, topology, missing):
    """Each of these is something the deploy or the tests actually do, and a
    missing one fails partway through a rollout rather than at validation."""
    topology["automation"]["policies"] = [
        p for p in topology["automation"]["policies"] if p != missing]
    assert_refused(render(topology), missing)


def test_an_unknown_policy_name_is_refused(render, topology):
    """RouterOS rejects an unknown policy, and the /user/group line that
    carries it runs on a box reset-configuration has already wiped."""
    topology["automation"]["policies"].append("superuser")
    assert_refused(render(topology), "superuser")


def test_a_custom_group_with_no_policies_is_refused(render, topology):
    topology["automation"]["policies"] = []
    assert_refused(render(topology), "policies")


def test_group_full_needs_no_policy_list(render, topology):
    """`full` is a RouterOS builtin, so the policy list doesn't apply to it.
    Requiring one anyway would make the simple option the fiddly one."""
    topology["automation"]["group"] = "full"
    topology["automation"].pop("policies", None)
    r = render(topology, args=["--check"])
    assert r.ok, r.output


def test_dropping_the_automation_block_entirely_still_builds(render, topology):
    """A fleet with no CI is the state this repo was in before the pipeline
    existed, and removing CI's access must not be a change that fails to
    render: that's exactly the moment you want it to work."""
    topology.pop("automation", None)
    r = render(topology)
    assert r.ok, r.output
    assert "gitlab-runner" not in r.config("br1.ord1")


# ---------------------------------------------------------------------
#  origination: a typo must not quietly render the other mode
# ---------------------------------------------------------------------
def test_unknown_origination_mode_is_refused(render, topology):
    topology["origination"]["mode"] = "Home"
    assert_refused(render(topology), "origination.mode", "'Home'")


def test_origination_as_a_bare_string_is_refused(render, topology):
    topology["origination"] = "home"
    assert_refused(render(topology), "origination", "mapping")


def test_arm_guard_must_be_a_boolean(render, topology):
    topology["origination"]["arm_guard"] = "yes please"
    assert_refused(render(topology), "arm_guard")


def test_dropping_the_origination_block_renders_anchor_mode(render, topology):
    """A topology written before the flag existed is anchor mode, unarmed."""
    topology.pop("origination", None)
    r = render(topology)
    assert r.ok, r.output
    body = r.config("br1.ord1")
    assert "immediate-gw" not in body
    assert "\n/system/scheduler add name=anchor-guard" not in body
