#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <target>" >&2
    exit 1
else
    TARGET="$1"
    timeout 180 nmap -p 445 --script smb-enum-shares,smb-enum-users "$TARGET"
fi
