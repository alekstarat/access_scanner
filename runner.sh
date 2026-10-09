#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

touch active_hosts.txt
mkdir -p state logs data

python3 database.py

./genip.sh >> logs/discovery.log 2>&1 &
DISCOVERY_PID=$!

# Основной лог worker'а — logs/worker.log (state/worker.log в worker.py
# используется только для хвоста статуса в UI).
python3 worker.py >> logs/worker.log 2>&1 &
WORKER_PID=$!

cleanup() {
    kill "$DISCOVERY_PID" "$WORKER_PID" 2>/dev/null || true
    wait "$DISCOVERY_PID" 2>/dev/null || true
    wait "$WORKER_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

if command -v tmux >/dev/null 2>&1 && [ -n "${TERM:-}" ]; then
    tmux new-session "less +F logs/discovery.log" \; split-window -h "less +F logs/worker.log"
else
    echo "discovery pid=$DISCOVERY_PID worker pid=$WORKER_PID (logs/discovery.log, logs/worker.log)"
    wait "$WORKER_PID"
fi
