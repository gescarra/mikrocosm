#!/usr/bin/env bash
# Render the example topology.yml completely offline.
#
# A real build fetches management SSH keys and source prefixes from the two
# URLs in topology.yml (ssh.keys_url, mgmt_prefixes_url). The example points
# them at example.net, which doesn't resolve, so ./build.sh stops there.
#
# This writes a throwaway --use-pin file with a placeholder key and replays it,
# which is the same mechanism the unit suite uses to stay hermetic. Nothing is
# fetched; everything else is the real build. Output lands in out/ as usual.
#
# Don't deploy what this produces: the SSH key in it belongs to nobody.
# Literally nobody. You'd be locking yourself out with a key made of D's.
set -euo pipefail
cd "$(dirname "$0")"

PY=python3
if ! python3 -c "import jinja2, yaml, cryptography" 2>/dev/null; then
  echo "installing deps into a local venv..."
  python3 -m venv .venv
  ./.venv/bin/pip -q install -r requirements.txt
  PY=./.venv/bin/python
fi

mkdir -p out
"$PY" - <<'EOF'
import hashlib, json, pathlib
topo = pathlib.Path("topology.yml").read_text()
pathlib.Path("out/demo-pin.json").write_text(json.dumps({
    "topology_sha256": hashlib.sha256(topo.encode()).hexdigest(),
    "ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"
                 + "D" * 43 + " demo@example.net"],
    "mgmt_prefixes_fetched": [],
}, indent=2, sort_keys=True) + "\n")
EOF

exec "$PY" generate.py --use-pin out/demo-pin.json "$@"
