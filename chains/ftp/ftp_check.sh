#!/bin/bash

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>" >&2
    exit 1
fi

timeout 120 nmap -sV -p21 -sC "$TARGET"

timeout 10 ncat -vn "$TARGET" 21 </dev/null

exit 0
