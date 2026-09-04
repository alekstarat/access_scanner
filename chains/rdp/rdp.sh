#!/bin/bash

if [ -z "$1" ]; then
    echo "Аргумент $1 не передан"
    exit 1
else
    TARGET="$1"
    nmap -p 3389 --script=rdp-enum-encryption --script=rdp-ntlm-info --script=rdp-vuln-ms12-020 "$TARGET"
fi