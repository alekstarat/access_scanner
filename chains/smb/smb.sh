#!/bin/bash

if [ -z "$1" ]; then
    echo "Аргумент $1 не передан"
    exit 1
else
    TARGET="$1"
    nmap -p 445 --script smb-enum-shares,smb-enum-users "$TARGET"
fi

