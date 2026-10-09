#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Fail early with an actionable message instead of a delayed import error.
python3 - <<'PY_CHECK'
try:
    import flask
except ModuleNotFoundError:
    raise SystemExit("Missing Flask. Install project dependencies with: ./install_dependencies.sh")
try:
    import bs4
except ModuleNotFoundError:
    raise SystemExit("Missing BeautifulSoup4. Install project dependencies with: ./install_dependencies.sh")
PY_CHECK

python3 webapp.py
