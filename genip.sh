#!/bin/bash

OUTPUT_FILE="active_hosts.txt"

generate_octet() {
	echo $((RANDOM % 256))
}

echo "Started scanning. Successful will appear in $OUTPUT_FILE"

while true; do
	o1=$(generate_octet)
	o2=$(generate_octet)
	o3=$(generate_octet)
	o4=$(generate_octet)

	# Skip special/reserved/private ranges:
	# 0/8, 10/8, 127/8, 224+/4 (multicast+reserved),
	# 100.64/10 CGNAT, 169.254/16 link-local,
	# 172.16/12, 192.168/16,
	# 192.0.2/24, 198.51.100/24, 203.0.113/24 (TEST-NET, documentation)
	if [ "$o1" -eq 0 ] ||
	   [ "$o1" -eq 10 ] ||
	   [ "$o1" -eq 127 ] ||
	   [ "$o1" -ge 224 ] ||
	   { [ "$o1" -eq 100 ] && [ "$o2" -ge 64 ] && [ "$o2" -le 127 ]; } ||
	   { [ "$o1" -eq 169 ] && [ "$o2" -eq 254 ]; } ||
	   { [ "$o1" -eq 172 ] && [ "$o2" -ge 16 ] && [ "$o2" -le 31 ]; } ||
	   { [ "$o1" -eq 192 ] && [ "$o2" -eq 168 ]; } ||
	   { [ "$o1" -eq 192 ] && [ "$o2" -eq 0 ] && [ "$o3" -eq 2 ]; } ||
	   { [ "$o1" -eq 192 ] && [ "$o2" -eq 0 ] && [ "$o3" -eq 0 ]; } ||
	   { [ "$o1" -eq 198 ] && [ "$o2" -ge 18 ] && [ "$o2" -le 19 ]; } ||
	   { [ "$o1" -eq 198 ] && [ "$o2" -eq 51 ] && [ "$o3" -eq 100 ]; } ||
	   { [ "$o1" -eq 203 ] && [ "$o2" -eq 0 ] && [ "$o3" -eq 113 ]; }
	then
		continue
	fi

	TARGET_IP="$o1.$o2.$o3.$o4"
	echo "============================================"
	echo "Target IP: $TARGET_IP"
	echo "============================================"

	NMAP_RESULT=$(timeout 120 nmap -F --open "$TARGET_IP")

	if echo "$NMAP_RESULT" | grep -q "Host is up" && echo "$NMAP_RESULT" | grep -q "open"; then
		PORTS=$(echo "$NMAP_RESULT" | grep open | awk '{print $1}' | paste -sd ' ' - | sed 's/ /,/g')

		RECORD="$TARGET_IP $PORTS"

		echo "[FOUND] $RECORD"
		echo "$RECORD" >> "$OUTPUT_FILE"
	fi

	sleep 1
done
