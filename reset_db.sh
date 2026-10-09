#!/usr/bin/env bash
# Осторожно: удаляет локальное состояние сканера (БД, офсеты, логи).
set -euo pipefail
cd "$(dirname "$0")"
if [ "${1:-}" != "--yes" ]; then
  echo "This will delete data/recon.db, state/* and logs/* . Re-run with --yes to confirm." >&2
  exit 1
fi
rm -rf -- state data logs
mkdir -p state data logs
 echo "State reset: state/, data/, logs/ recreated empty."
