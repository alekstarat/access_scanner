#!/bin/bash

OUTPUT_FILE="active_hosts.txt"

generate_octet() {
	echo $((RANDOM % 256 ))
}

echo "Started scanning. Successful wil appear in $OUTPUT_HOSTS"

while true; do
	o1=$(generate_octet)
	o2=$(generate_octet)
	o3=$(generate_octet)
	o4=$(generate_octet)

	if [ $o1 -eq 0 ] ||
	   [ $o1 -eq 10 ] ||
	   [ $o1 -eq 127 ] ||
	   [ $o1 -eq 224 ] ||
	   [ $o1 -ge 240 ] ||
	   { [ $o1 -eq 100 ] && [ $o2 -ge 64 ] && [ $o2 -le 127 ]; } ||
	   { [ $o1 -eq 169 ] && [ $o2 -ge 254 ]; } ||
	   { [ $o1 -eq 172 ] && [ $o2 -ge 16 ] && [ $o2 -le 31 ]; } ||
	   { [ $o1 -eq 192 ] && [ $o2 -eq 168 ]; }
	then
		continue
	fi

	TARGET_IP="$o1.$o2.$o3.$o4"
	echo "============================================"
	echo "Target IP: $TARGET_IP"
	echo "============================================"

	NMAP_RESULT=$(nmap -F --open "$TARGET_IP")

	if echo "$NMAP_RESULT" | grep -q "Host is up" && echo "$NMAP_RESULT" | grep -q "open"; then
		PORTS=$(echo "$NMAP_RESULT" | grep "open" | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')

		RECORD="$TARGET_IP $PORTS"

		echo "[FOUND] $RECORD"
		echo "$RECORD" >> "$OUTPUT_FILE"
	fi
done