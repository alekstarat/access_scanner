#!/bin/bash

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>" >&2
    exit 1
fi

dig +short version.bind CHAOS TXT @"$TARGET"

exit 0
