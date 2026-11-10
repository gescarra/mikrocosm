"""
Fixtures for the functional suite. The tests that talk to live routers.

These are the deployment gate. The pipeline runs them after each router is
deployed, and the next router isn't touched until they pass.

    pytest tests/functional                         # the whole fleet
    pytest tests/functional --router br1.ord1       # one router
    pytest tests/functional --router br1.ord1 --focus br1.ord1
    pytest tests/functional -k mtu                  # one check, everywhere

WHERE THE EXPECTATIONS COME FROM
--------------------------------
`out/manifest.json`, which generate.py derives from topology.yml. Nothing here
knows how many routers exist, which sessions they should have, or what the
customers were granted. Adding a border router changes what these tests assert
without anyone editing them: which is the same reason the configs are
generated in the first place.

WHERE THE CREDENTIALS COME FROM
-------------------------------
`ansible/group_vars/all.yml`, the same committed file the deploy playbook uses.
Not duplicated here: two definitions of "which user do we log in as" is exactly
the drift this repo exists to remove, and it's worse in a test suite, where
the symptom of getting it wrong is a red pipeline that looks like an outage.
"""

import json
import os
import pathlib

import pytest
import yaml

from .routeros import Router

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
DEFAULT_MANIFEST = ROOT / "out" / "manifest.json"
GROUP_VARS = ROOT / "ansible" / "group_vars" / "all.yml"

# The manifest shape this suite asserts against. It MUST track emit.py's
# `"schema"` value, and tests/unit/test_manifest.py fails the build when the
# two drift: which is the only reason that check can be trusted: `pytest`
# runs tests/unit, so a bump made here or there without the other is caught by
# the suite that gates every merge rather than by the one that needs four live
# routers to run at all.
#
#   1  the original fleet manifest
#   2  adds the external-peering keys (peers/vrfs/rpki on a BR). Purely
#      additive: no key from 1 moved or changed meaning.
MANIFEST_SCHEMA = 2


def pytest_addoption(parser):
    g = parser.getgroup("as64500")
    g.addoption("--router", action="append", default=[],
                help="Limit to these routers by fqdn. Repeatable. "
                     "The pipeline passes the one it just deployed.")
    g.addoption("--focus", default=None,
                help="After checking the fleet, assert every OTHER router can "
                     "still reach this one. Set to the router just deployed.")
    g.addoption("--manifest", default=None,
                help=f"Path to manifest.json (default: {DEFAULT_MANIFEST})")
    g.addoption("--router-user", default=None,
                help="SSH user (default: router_user from "
                     "ansible/group_vars/all.yml, or $ROUTER_USER)")
    g.addoption("--bootstrap", action="store_true",
                help="Reach routers at bootstrap_host -- a border router's "
                     "provider WAN -- instead of the in-AS address. For a "
                     "control node OUTSIDE the AS, or when a BR's tunnels are "
                     "down. From inside the AS the default is correct and this "
                     "will time out: see ansible_host() in emit.py.")
    g.addoption("--no-e2e", action="store_true",
                help="Skip the end-to-end tests. Only correct when the control "
                     "node is NOT behind the customer firewalls, in which case "
                     "they would be testing somebody else's connection.")


# ---------------------------------------------------------------------
#  Inputs
# ---------------------------------------------------------------------
@pytest.fixture(scope="session")
def manifest(pytestconfig):
    path = pathlib.Path(pytestconfig.getoption("--manifest") or DEFAULT_MANIFEST)
    if not path.exists():
        pytest.fail(
            f"{path} not found. It is generated: run ./build.sh.\n"
            f"Without it these tests have no expectations to assert against, "
            f"and a functional suite that invents its own is one that passes "
            f"while the fleet drifts.", pytrace=False)
    doc = json.loads(path.read_text())
    if doc.get("schema") != MANIFEST_SCHEMA:
        pytest.fail(
            f"{path} is manifest schema {doc.get('schema')}; this suite "
            f"understands {MANIFEST_SCHEMA}. Rebuild, or check out the "
            f"matching commit -- silently skipping the assertions whose keys "
            f"moved would be worse than stopping.", pytrace=False)
    return doc


@pytest.fixture(scope="session")
def opvars():
    """Operational settings, read from the file Ansible reads."""
    if GROUP_VARS.exists():
        return yaml.safe_load(GROUP_VARS.read_text()) or {}
    return {}


@pytest.fixture(scope="session")
def router_user(pytestconfig, opvars):
    user = (pytestconfig.getoption("--router-user")
            or os.environ.get("ROUTER_USER")
            or opvars.get("router_user"))
    if not user:
        pytest.fail(
            "No SSH user: pass --router-user, set $ROUTER_USER, or define "
            "router_user in ansible/group_vars/all.yml.", pytrace=False)
    return user


@pytest.fixture(scope="session")
def selected(pytestconfig, manifest):
    """The routers under test, in rollout order."""
    limit = set(pytestconfig.getoption("--router"))
    order = manifest["deploy_order"]
    if not limit:
        return order
    unknown = limit - set(order)
    if unknown:
        pytest.fail(f"--router named {sorted(unknown)}, which are not in the "
                    f"manifest. Known: {order}", pytrace=False)
    return [f for f in order if f in limit]


@pytest.fixture(scope="session")
def routers(manifest, router_user, opvars, pytestconfig):
    """Every router in the manifest, connectable. Keyed by fqdn.

    The whole fleet, not just the selected ones: the cross-check needs to ask
    routers that aren't themselves under test whether they can still see the
    one that's.
    """
    port = opvars.get("ssh_port", 22)
    key = "bootstrap_host" if pytestconfig.getoption("--bootstrap") else "ansible_host"
    return {
        fqdn: Router(fqdn=fqdn, host=r[key], user=router_user,
                     port=port, role=r["role"])
        for fqdn, r in manifest["routers"].items()
    }


# ---------------------------------------------------------------------
#  Parametrisation: one test instance per router under test
# ---------------------------------------------------------------------
def pytest_generate_tests(metafunc):
    """Any test taking `router` runs once per selected router, named by fqdn.

    So a failure reads `test_ibgp_sessions_are_established[br2.ord2]` in
    GitLab's test tab: which router, which check, without opening the log.
    """
    if "router" not in metafunc.fixturenames:
        return
    cfg = metafunc.config
    path = pathlib.Path(cfg.getoption("--manifest") or DEFAULT_MANIFEST)
    if not path.exists():
        metafunc.parametrize("router", [], ids=[])
        return
    doc = json.loads(path.read_text())
    limit = set(cfg.getoption("--router"))
    order = [f for f in doc["deploy_order"] if not limit or f in limit]
    metafunc.parametrize("router", order, ids=order, scope="session")


@pytest.fixture(scope="session")
def expect(router, manifest):
    """What this router is supposed to look like."""
    return manifest["routers"][router]


@pytest.fixture(scope="session")
def dev(router, routers):
    """The connection to this router."""
    return routers[router]


@pytest.fixture(scope="session")
def claim_prefixes(expect):
    """The v4 customer grants this router should have routes inside.

    Empty on anything but an edge router, which is what keeps the probe from
    asking a border router about customer space it has no business holding.
    """
    seen, out = set(), []
    for c in expect.get("customers", []):
        for claim in c["claims"]:
            if claim["family"] == 4 and claim["prefix"] not in seen:
                seen.add(claim["prefix"])
                out.append(claim["prefix"])
    return out


@pytest.fixture(scope="session")
def state(dev, claim_prefixes):
    """This router's whole state, fetched once per session.

    One SSH round trip per router for every check in test_router.py. Beyond
    being faster, it makes the snapshot CONSISTENT: all of it's true at one
    instant, rather than smeared across a minute of reconnects during which the
    thing being tested may have changed.
    """
    return dev.probe(claim_prefixes)
