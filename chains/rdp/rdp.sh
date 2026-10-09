#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <target>" >&2
    exit 1
else
    TARGET="$1"
    timeout 180 nmap -p 3389 --script=rdp-enum-encryption --script=rdp-ntlm-info --script=rdp-vuln-ms12-020 "$TARGET"
fi
