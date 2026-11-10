"""
The pipeline YAML, checked for SHAPE and not merely for parsing.

The bug that motivated this file:

    - test -n "$ROUTER_USER" || { echo "topology.yml has no automation: block"; exit 1; }

`yaml.safe_load` accepts that line happily. It just doesn't produce what
anybody reading it expects: the `: ` inside the message ends a YAML plain
scalar, so the list item becomes a MAPPING:

    {'test -n "$ROUTER_USER" || { echo "topology.yml has no automation':
     'block"; exit 1; }'}

and GitLab rejects the job with `script config should be a string or a nested
array of strings`. A shell one-liner is an unusually good source of YAML
hazards (colons, `{`, `[`, `*`, `#`, leading `%`) and every one of them
turns into a pipeline that fails at submission time, after a push, rather than
in front of whoever wrote it.

Asserting "the file parses" is what missed it. These assert what it parses INTO.
"""

import pathlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

# Keys whose value GitLab requires to be a string or a list of strings.
SCRIPT_KEYS = ("script", "before_script", "after_script")

# The committed pipeline files. out/pipeline.yml is generated and gets its own
# check in test_manifest.py, but it's included here too because it's the one
# that actually runs the rollout.
COMMITTED = (".gitlab-ci.yml", "ci/child-jobs.yml")


def _load(rel):
    path = ROOT / rel
    if not path.exists():
        pytest.skip(f"{rel} not present")
    return yaml.safe_load(path.read_text())


def _jobs(doc):
    """Every job and template in a pipeline document, including the hidden
    `.templates`. A malformed `script` in a template breaks every job that
    extends it, which is worse than breaking one."""
    skip = {"stages", "variables", "default", "include", "workflow", "image",
            "cache", "services"}
    return {k: v for k, v in doc.items()
            if isinstance(v, dict) and k not in skip}


@pytest.mark.parametrize("rel", COMMITTED)
def test_every_script_entry_is_a_string(rel):
    """The exact failure above, for every job in every pipeline file."""
    doc = _load(rel)
    problems = []
    for job, body in _jobs(doc).items():
        for key in SCRIPT_KEYS:
            value = body.get(key)
            if value is None or isinstance(value, str):
                continue
            if not isinstance(value, list):
                problems.append(f"{job}.{key} is {type(value).__name__}")
                continue
            for i, item in enumerate(value):
                if not isinstance(item, str):
                    problems.append(
                        f"{job}.{key}[{i}] parsed as {type(item).__name__}, "
                        f"not a string: {item!r}")
    assert not problems, (
        f"{rel}: GitLab requires these to be strings.\n  "
        + "\n  ".join(problems)
        + "\n\nAlmost always a shell line containing `: ` (colon-space), which "
          "ends a YAML plain scalar and turns the item into a mapping. Reword "
          "the message, or quote the whole item.")


# A source-scanning "near miss" check was here and was deleted. It flagged
# every `- if: $CI_COMMIT_REF_PROTECTED == "true"` under `rules:`, where a
# mapping is exactly what YAML should produce. And it earned nothing, because
# a `: ` inside a script item ALWAYS parses as a mapping and is therefore
# already caught above. Scoping it to script blocks would have been fiddly
# line-tracking for a case the parsed check covers exactly.


def test_no_job_depends_on_a_container_registry():
    """The pipeline must run on a GitLab with no container registry and a
    non-privileged runner.

    Both were assumed once and neither held: `$CI_REGISTRY` is unset unless the
    instance has the registry enabled, so `docker login "$CI_REGISTRY"` silently
    retries against Docker Hub and fails with `registry-1.docker.io:
    unauthorized`; and dind needs `privileged = true`, without which the service
    never starts and every job waiting on it times out.
    """
    for rel in COMMITTED:
        text = "\n".join(
            line for line in (ROOT / rel).read_text().splitlines()
            if not line.strip().startswith("#"))
        for token in ("CI_REGISTRY", "docker:2", "dind", "docker login"):
            assert token not in text, (
                f"{rel} references {token!r} outside a comment. The pipeline is "
                f"meant to need neither a container registry nor a privileged "
                f"runner -- see the note at the top of .gitlab-ci.yml.")


@pytest.mark.parametrize("rel", COMMITTED)
def test_jobs_that_touch_routers_install_an_ssh_client(rel):
    """Every router interaction is ssh/scp, and the base image has neither.

    A missing openssh-client doesn't fail at install time. It fails at the
    first scp, which in a rollout job is after the gate has already let it
    start.
    """
    doc = _load(rel)
    for job, body in _jobs(doc).items():
        steps = " ".join(body.get("script") or []) + " ".join(
            body.get("before_script") or [])
        if "ansible-playbook" not in steps and "tests/functional" not in steps:
            continue
        inherited = body.get("extends", "")
        inherited = [inherited] if isinstance(inherited, str) else inherited
        pool = steps + " ".join(
            " ".join(doc.get(t, {}).get("before_script") or [])
            for t in inherited)
        assert "openssh-client" in pool, (
            f"{rel}: job {job!r} drives routers but nothing in its script or "
            f"the templates it extends installs openssh-client")


def test_the_lint_stage_never_collects_the_functional_suite():
    """`pytest tests/` collects BOTH suites, and the functional one needs a
    manifest and live routers.

    That's what the unit job did: 153 unit tests passed and the job still
    failed, on 9 errors from functional tests refusing to run without a fleet
    they were never meant to touch in that stage. `pytest.ini` sets
    `testpaths = tests/unit` for exactly this reason, but a path argument on
    the command line overrides it. So the argument has to agree, and nothing
    but this test makes it.
    """
    doc = _load(".gitlab-ci.yml")
    for job, body in _jobs(doc).items():
        if body.get("stage") not in ("lint", "build"):
            continue
        for line in body.get("script") or []:
            if "pytest" not in line:
                continue
            assert "tests/functional" not in line, (
                f"{job} (stage {body.get('stage')}) runs the functional suite, "
                f"which needs out/manifest.json and routers")
            assert not any(tok in line.split() for tok in ("tests", "tests/")), (
                f"{job} (stage {body.get('stage')}) runs `pytest tests/`, which "
                f"collects tests/functional too. Use `pytest tests/unit`.")


def test_the_rollout_jobs_do_run_the_functional_suite():
    """The mirror of the above. Scoping the lint stage down is only correct
    if the gate still runs the thing that gates."""
    doc = _load("ci/child-jobs.yml")
    runners = [j for j, b in _jobs(doc).items()
               if any("tests/functional" in l for l in (b.get("script") or []))]
    assert {".baseline", ".verify_router", ".e2e"} <= set(runners), (
        f"the functional suite is only run by {runners}; baseline, the "
        f"per-router gate and the final e2e all need it")


# Secrets arrive as File-type CI variables, so the value is a PATH.
SECRETS = ("KEYS_JSON", "SSH_PRIVATE_KEY")


@pytest.mark.parametrize("rel", COMMITTED)
def test_every_job_checks_a_secret_is_set_before_using_it(rel):
    """An unset File-type variable expands to the empty string, so the first
    thing that touches it fails as

        install: can't stat '': No such file or directory

    an error about a missing file that names no variable, in a job whose own
    rule has already proved the ref is protected. Every plausible reading of
    that message is wrong.

    The child pipeline had this guard from the start and the parent didn't,
    which is exactly how `build` produced it. Requiring it in both is what stops
    the two drifting again.
    """
    doc = _load(rel)
    for job, body in _jobs(doc).items():
        steps = list(body.get("before_script") or []) + list(body.get("script") or [])
        blob = "\n".join(steps)
        for secret in SECRETS:
            if f"${secret}" not in blob:
                continue
            uses = next(i for i, l in enumerate(steps) if f"${secret}" in l)
            guards = [i for i, l in enumerate(steps)
                      if secret in l and ("test -n" in l or "test -f" in l)]
            assert guards, (
                f"{rel}: {job} uses ${secret} without ever checking it is set. "
                f"Add the preflight loop -- an unset variable here produces an "
                f"error that names neither the variable nor the job.")
            assert min(guards) <= uses, (
                f"{rel}: {job} checks ${secret} only AFTER using it")


@pytest.mark.parametrize("rel", COMMITTED)
def test_no_job_ever_prints_a_secret(rel):
    """The control that replaces masking.

    GitLab can only mask single-line values, and both secrets here are
    multi-line by nature: a formatted JSON keystore and a PEM private key.
    Masking is therefore unavailable, not merely unset.

    What it would have bought was redaction of exact string matches in job
    OUTPUT. So the equivalent guarantee is that nothing ever writes them to
    output: each is installed to a file, read by the tooling, and shredded in
    after_script. This is that guarantee, asserted. Because the day someone
    adds a `cat keys.json` to debug a render is the day the keystore is in a
    job log that anyone with project access can read.
    """
    doc = _load(rel)
    leaks = []
    for job, body in _jobs(doc).items():
        for key in SCRIPT_KEYS:
            for line in body.get(key) or []:
                if not isinstance(line, str):
                    continue
                for target in ("keys.json", "id_ed25519",
                               "$KEYS_JSON", "$SSH_PRIVATE_KEY"):
                    if target not in line:
                        continue
                    for printer in ("cat ", "echo $", 'echo "$', "head ",
                                    "tail ", "base64 ", "xxd ", "od "):
                        if printer in line:
                            leaks.append(f"{job}.{key}: {line.strip()[:90]}")
    assert not leaks, (
        f"{rel}: job step(s) that would print secret material into the job log, "
        f"which is NOT masked:\n  " + "\n  ".join(leaks))


@pytest.mark.parametrize("rel", COMMITTED)
def test_every_job_that_installs_a_secret_also_removes_it(rel):
    """The runner is on-prem and long-lived, so a keystore left in a build
    directory is a keystore sitting on a disk for the next job to find."""
    doc = _load(rel)
    for job, body in _jobs(doc).items():
        steps = " ".join(
            (body.get("before_script") or []) + (body.get("script") or []))
        # Keyed on the SECRET VARIABLE, not on the filename. `validate` runs
        # `generate.py --keys /tmp/ephemeral-keys.json`. A throwaway keystore
        # it generates itself, holding no fleet key and needing no cleanup.
        # And a substring match on "keys.json" flagged it. What actually
        # matters is whether the job was handed $KEYS_JSON.
        if "$KEYS_JSON" not in steps:
            continue
        cleanup = " ".join(body.get("after_script") or [])
        inherited = body.get("extends", "")
        inherited = [inherited] if isinstance(inherited, str) else inherited
        cleanup += " ".join(" ".join(doc.get(t, {}).get("after_script") or [])
                            for t in inherited)
        assert "keys.json" in cleanup, (
            f"{rel}: {job} writes keys.json but neither it nor the templates it "
            f"extends remove it in after_script")


def _resolved_before_script(doc, job, body, seen=None):
    """A job's before_script plus every template it extends, recursively.

    `extends:` chains (unit -> .python), so checking only the job's own keys
    reports every job as installing nothing at all.
    """
    seen = seen or set()
    out = list(body.get("before_script") or [])
    parents = body.get("extends", "")
    parents = [parents] if isinstance(parents, str) else parents
    for parent in parents:
        if parent in seen or parent not in doc:
            continue
        seen.add(parent)
        out += _resolved_before_script(doc, parent, doc[parent], seen)
    return out


def test_the_unit_job_installs_what_the_unit_suite_imports():
    """The unit suite needs ansible-core, and it's not obvious that it does.

    tests/unit/test_chaos_quoting.py renders ansible/chaos.yml by running real
    `ansible-playbook`, because Ansible doesn't process backslash escapes in
    Jinja string literals and plain Jinja2 does. So the two produce different
    commands from one template, and Jinja2's is the one that gets rejected by
    the router.

    The `unit` job used to install `requirements.txt pytest`, the generator's
    minimal set, on the reasoning that the lint stage never talks to a router.
    True, and beside the point: it renders a playbook. The result was six
    errors in a job that had been green, on a push whose only change was the
    test itself.
    """
    doc = _load(".gitlab-ci.yml")
    runners = [(job, body) for job, body in _jobs(doc).items()
               if any("pytest tests/unit" in line
                      for line in (body.get("script") or []))]
    assert runners, "no job in .gitlab-ci.yml runs `pytest tests/unit`"
    for job, body in runners:
        installs = " ".join(_resolved_before_script(doc, job, body))
        assert "requirements-dev.txt" in installs, (
            f"{job} runs the unit suite but installs: {installs.strip()!r}\n\n"
            f"The suite imports ansible-core (via ansible-playbook). "
            f"requirements.txt is the GENERATOR's dependency set and does not "
            f"include it.")
