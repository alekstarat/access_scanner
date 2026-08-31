#!/usr/bin/env bash

set -euo pipefail

touch active_hosts.txt
mkdir -p state logs

./genip.sh >> logs/discovery.log 2>&1 &
DISCOVERY_PID=$!

python3 worker.py >> logs/worker.log 2>&1 &
WORKER_PID=$!

trap 'kill "$DISCOVERY_PID" "$WORKER_PID" 2>/dev/null || true' INT TERM EXIT

wait "$WORKER_PID"