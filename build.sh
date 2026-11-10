#!/usr/bin/env bash
# AS64500 config build. macOS + Linux.
set -euo pipefail
cd "$(dirname "$0")"
# That's the whole bootstrap. If this ever grows a Makefile, something went wrong.

command -v python3 >/dev/null || { echo "need python3"; exit 1; }
python3 -c "import jinja2, yaml, cryptography" 2>/dev/null || {
  echo "installing deps into a local venv..."
  python3 -m venv .venv
  ./.venv/bin/pip -q install jinja2 pyyaml cryptography
  exec ./.venv/bin/python generate.py "$@"
}
exec python3 generate.py "$@"
