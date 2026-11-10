"""
Secret hygiene, enforced rather than documented.

The repo README already states the trust levels: `topology.yml` and the
templates are committed, `keys.json` and `out/*.rsc` never are. Adding a
pipeline puts a third category in play. Files that are deliberately COPIED
OFF the build machine into GitLab's artifact store, where they sit for as long
as the expiry says and are downloadable by anyone with access to the project.

`manifest.json`, `inventory.yml`, `pipeline.yml` and `pin.json` are those files.
They exist so the deploy and test jobs don't need the keystore, which only
works if they genuinely contain nothing worth protecting. That's a property
somebody will break by accident the first time they add a field to the manifest
for convenience, so it's asserted here instead of trusted.

Trust is nice. Tests are nicer.
"""

import json
import re

import pytest

# The artifacts. Anything added to this list is asserted to be key-free.
ARTIFACTS = ("manifest.json", "inventory.yml", "pipeline.yml")

# 32 bytes, base64: a WireGuard private key, a public key, or a PSK. The last
# character of a 44-char base64 encoding of 32 bytes is constrained to this set,
# which is what keeps the pattern from matching arbitrary long tokens.
B64_KEY = re.compile(r"\b[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=")


def secret_values(keys_path):
    """Every literal secret in the keystore: private keys, public keys, PSKs,
    and the SNMPv3 passphrases."""
    out = set()
    for entry in json.loads(keys_path.read_text()).values():
        for v in entry.values():
            if isinstance(v, str) and v:
                out.add(v)
    return out


@pytest.mark.parametrize("artifact", ARTIFACTS)
def test_artifacts_contain_no_key_material(built, artifact):
    """Nothing from the keystore may appear verbatim in a CI artifact."""
    text = (built.out / artifact).read_text()
    for secret in secret_values(built.keys_path):
        assert secret not in text, (
            f"{artifact} contains a value from the keystore. These files are "
            f"uploaded to GitLab's artifact store; keys are not.")


@pytest.mark.parametrize("artifact", ARTIFACTS)
def test_artifacts_contain_nothing_shaped_like_a_key(built, artifact):
    """Belt and braces against a future field that derives something new from
    the keystore rather than copying a value out of it."""
    text = (built.out / artifact).read_text()
    found = B64_KEY.findall(text)
    assert not found, f"{artifact} contains {len(found)} base64 32-byte value(s)"


def test_the_pin_file_carries_only_public_material(render, tmp_path):
    """`pin.json` freezes the two build-time fetches so the deploy job can
    reproduce a render. Both are public by nature (SSH PUBLIC keys and source
    prefixes) which is the only reason it can be an artifact at all."""
    # use_pin=False: this test RECORDS a pin, which means a real fetch. It's
    # the one test here that touches the network, and it's skipped rather than
    # failed when that isn't available. An offline laptop shouldn't look
    # like a broken generator.
    r = render(args=["--pin", str(tmp_path / "pin-out.json")], use_pin=False)
    if not r.ok and ("failed to fetch" in r.output or "urlopen" in r.output):
        pytest.skip("no network: --pin needs a live fetch to record")
    assert r.ok, r.output
    text = (tmp_path / "pin-out.json").read_text()
    for secret in secret_values(r.keys_path):
        assert secret not in text
    assert "PRIVATE KEY" not in text
    doc = json.loads(text)
    assert set(doc) <= {"topology_sha256", "ssh_keys", "mgmt_prefixes_fetched"}
    for k in doc["ssh_keys"]:
        assert k.startswith(("ssh-", "ecdsa-")), (
            "pin.json holds SSH public keys; a private key here would be "
            f"published to the artifact store: {k[:24]}...")


def test_rendered_configs_do_contain_keys(built):
    """The inverse, and worth asserting: `out/*.rsc` genuinely IS secret. If
    this ever stopped being true the whole trust model would have quietly
    changed, and it would be far better to hear it here."""
    keys = secret_values(built.keys_path)
    blob = "".join(built.configs().values())
    assert any(k in blob for k in keys), (
        "no keystore value appears in any rendered config -- either the keys "
        "stopped being rendered, or this test is checking the wrong thing")


def test_gitignore_still_covers_the_secret_paths(repo_root):
    """The one control that stops a private key being committed. It's a file
    anybody can edit, so it gets a test."""
    ignored = (repo_root / ".gitignore").read_text().splitlines()
    for path in ("keys.json", "out/", ".env"):
        assert path in ignored, f".gitignore no longer ignores {path}"


def test_ci_artifacts_are_inside_the_ignored_out_directory(built, repo_root):
    """The artifacts are key-free, but they are still generated, and a
    generated file in git is a merge conflict waiting to happen. They live in
    out/, which is ignored wholesale."""
    for artifact in ARTIFACTS:
        assert (built.out / artifact).exists()
    assert "out/" in (repo_root / ".gitignore").read_text().splitlines()
