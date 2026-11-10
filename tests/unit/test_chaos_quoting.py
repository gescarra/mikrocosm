"""
The chaos deadman, rendered by the thing that actually renders it.

WHY THIS FILE USES ansible-playbook AND NOT jinja2

The deadman command was wrong twice in the same three characters.

    1.  on-event="... [find where name~"ebgp"]"      unescaped
        expected end of command (line 1 column 114)

    2.  on-event="... [find where name~\\"ebgp\\"]"    over-escaped
        expected end of command (line 1 column 116)

The second one is the interesting one. The fix for the first was
`replace('"', '\\\\"')`, which is correct in plain Jinja2. And Jinja2 is what
the first version of this test used to check it. Ansible does NOT process
backslash escapes inside Jinja string literals, so the same template renders
`\\"` under Jinja2 and `\\\\"` under Ansible. The test passed. Production failed.

A test that renders with a different engine than production isn't a weaker
test, it's a misleading one: it reported the exact command that had just
failed on a live router as correct. So this file shells out to
`ansible-playbook` and asserts on what Ansible really produced.

WHAT IS ASSERTED

That nothing needs escaping at all. The undo goes into a `source={...}` block,
where RouterOS treats quotes as ordinary script text, and the scheduler names
that script rather than quoting a command. Five layers (YAML, Jinja, Ansible,
ssh, RouterOS) each want a say in what a backslash means, and the only robust
answer is to hand none of them anything to escape.

Verified against live hardware (7.24 and 7.23.3, all four routers, as the CI
user): the stored script source is byte-for-byte the `undo` string, the
scheduler fires it, and re-arming over a leftover deadman succeeds.
"""

import json
import pathlib
import shutil
import subprocess
import tempfile

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
CHAOS = ROOT / "ansible" / "chaos.yml"


@pytest.fixture(scope="module")
def play():
    return yaml.safe_load(CHAOS.read_text())[0]


@pytest.fixture(scope="module")
def undos(play):
    """Every scenario's undo command, read out of the playbook.

    Not listed here, so a fourth scenario is covered the moment it's written.
    """
    found = {t["name"]: t["vars"]["undo"] for t in play["tasks"]
             if isinstance(t.get("vars"), dict) and "undo" in t["vars"]}
    assert found, "no chaos scenario defines an `undo` command"
    return found


@pytest.fixture(scope="module")
def rendered(play, undos):
    """{scenario: arm command}, as produced by Ansible itself.

    One playbook run for every scenario. This costs about a second, which is
    the price of testing the real renderer instead of a lookalike.
    """
    ansible = shutil.which("ansible-playbook")
    if not ansible:
        pytest.fail(
            "ansible-playbook is not on PATH, so the deadman command cannot be "
            "rendered the way production renders it.\n\n"
            "Install it: pip install -r requirements-dev.txt\n\n"
            "This is a failure and not a skip on purpose. Rendering with "
            "jinja2 instead is what let an over-escaped command reach a live "
            "router with a green test suite behind it.", pytrace=False)

    doc = [{
        "hosts": "localhost", "gather_facts": False, "connection": "local",
        "vars": {k: play["vars"][k]
                 for k in ("deadman_arm", "deadman_disarm", "deadman_minutes")},
        "tasks": [{"name": name, "vars": {"undo": undo},
                   "ansible.builtin.debug": {"msg": "{{ deadman_arm }}"}}
                  for name, undo in undos.items()]
                 + [{"name": "disarm",
                     "ansible.builtin.debug": {"msg": "{{ deadman_disarm }}"}}],
    }]

    with tempfile.TemporaryDirectory() as tmp:
        pb = pathlib.Path(tmp) / "render.yml"
        pb.write_text(yaml.safe_dump(doc, default_flow_style=False, width=10 ** 6))
        proc = subprocess.run([ansible, str(pb)], capture_output=True, text=True,
                              timeout=120, cwd=ROOT)
    assert proc.returncode == 0, f"ansible-playbook failed:\n{proc.stdout}\n{proc.stderr}"

    msgs = [json.loads(line.split('"msg": ', 1)[1])
            for line in proc.stdout.splitlines() if '"msg": ' in line]
    assert len(msgs) == len(undos) + 1, (
        f"expected {len(undos) + 1} rendered commands, got {len(msgs)}")
    out = dict(zip(undos, msgs))
    out["__disarm__"] = msgs[-1]
    return out


def test_nothing_in_the_deadman_is_escaped(rendered):
    """The invariant that replaces counting backslashes.

    Both historical bugs were a backslash count. One too few, then two too
    many. Neither is possible in a command that contains none.
    """
    for name, cmd in rendered.items():
        assert "\\" not in cmd, (
            f"{name}: the rendered command contains a backslash:\n  {cmd}\n\n"
            f"The deadman is built so that nothing needs escaping -- the undo "
            f"goes inside `source={{...}}` where RouterOS reads quotes as "
            f"script text. A backslash here means something reintroduced an "
            f"escaping layer, and YAML, Jinja, Ansible, ssh and RouterOS will "
            f"not agree on what it means.")


def test_the_deadman_runs_exactly_what_the_scenario_undoes(rendered, undos):
    """The undo must reach the router UNCHANGED.

    An escaping scheme can be self-consistent and still hand the scheduler a
    different command than the `always:` block runs. And then the automatic
    recovery and the manual recovery repair different things, which is the
    worst available outcome because the manual path is the one people test.
    """
    for name, undo in undos.items():
        cmd = rendered[name]
        assert f"source={{{undo}}}" in cmd, (
            f"{name}: the undo is not embedded verbatim.\n"
            f"  undo:     {undo}\n  rendered: {cmd}")


def test_the_scheduler_names_the_script_rather_than_quoting_it(rendered, undos):
    """`on-event=chaos-undo` is what removes the quoting problem. An inline
    command there's the shape both bugs had."""
    for name in undos:
        assert "on-event=chaos-undo" in rendered[name], (
            f"{name}: the scheduler does not reference the script by name. "
            f"Inlining the command into `on-event=` is what needed escaping.")


def test_the_deadman_can_do_what_it_is_scheduled_to_do(rendered, undos):
    """A scheduler runs with the policies it was CREATED with, not the
    creator's. `write` missing means it fires, fails silently, and the
    breakage stays."""
    for name in undos:
        assert "policy=read,write,test" in rendered[name], (
            f"{name}: enabling an interface or a BGP connection needs `write`")


def test_arming_works_on_a_router_that_is_already_armed(rendered, undos):
    """RouterOS `add` refuses a duplicate name:

        failure: item with this name already exists (/system/scheduler/add)

    So a deadman left behind by a crashed run made the NEXT run unable to arm.
    Failing precisely in the situation the deadman exists to cover.
    """
    for name in undos:
        cmd = rendered[name]
        first_add = cmd.index("/system/script add")
        for target in ("/system/script remove [find name=chaos-undo]",
                       "/system/scheduler remove [find name=chaos-deadman]"):
            assert target in cmd, f"{name}: arm never runs `{target}`"
            assert cmd.index(target) < first_add, (
                f"{name}: `{target}` runs AFTER the add, so a leftover from a "
                f"crashed run still blocks arming")


def test_disarm_removes_both_objects(rendered):
    """The arm creates a script AND a scheduler. Removing only the scheduler
    leaves the script behind to collide with the next run."""
    cmd = rendered["__disarm__"]
    for target in ("[find name=chaos-deadman]", "[find name=chaos-undo]"):
        assert target in cmd, f"disarm does not remove {target}:\n  {cmd}"


def test_no_scenario_arms_a_deadman_of_its_own(play, undos):
    """The three scenarios once armed three copy-pasted commands, and the
    quoting was wrong in two of them. The third had no quotes in its undo and
    armed perfectly well, so which half of the bug you saw depended on which
    scenario you ran first. One definition is the fix; this keeps it one."""
    inline = [t["name"] for t in play["tasks"]
              if "scheduler add" in str(t.get("ansible.builtin.command", ""))]
    assert not inline, (
        f"{inline} build a `scheduler add` inline instead of using the "
        f"play-level `deadman_arm`.")
