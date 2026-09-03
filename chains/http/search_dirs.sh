#!/bin/bash

IP=""
PORT=""
TLS=false
PROTOCOL="http"

run() {
  if [[ $TLS == true ]]; then
    PROTOCOL="https"
  fi

  ffuf -w /home/arch/Desktop/wordlists/api-endpoints.txt -fc 401,403 -X 'GET' -u "$PROTOCOL://$IP:$PORT/FUZZ"
}

show_help() {
  echo "Использование: $0 -i <ip> -p <порт> [--tls]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i)
            if [[ -n "$2" && "$2" != -* ]]; then
                IP="$2"
                shift 2
            else
                echo "Ошибка: Параметр -i требует указания значения (IP)." >&2
                exit 1
            fi
            ;;
        -p)
            if [[ -n "$2" && "$2" != -* ]]; then
                PORT="$2"
                shift 2
            else
                echo "Ошибка: Параметр -p требует указания значения (порт)." >&2
                exit 1
            fi
            ;;
        --tls)
            TLS=true
            shift 1
            ;;
        -h|--help)
            show_help
            exit 1
            ;;
        *)
            echo "Ошибка: Неизвестный параметр: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

# Проверка обязательных параметров
if [[ -z "$IP" || -z "$PORT" ]]; then
    echo "Ошибка: Параметры -i (IP) и -p (порт) являются обязательными." >&2
    show_help
    exit 1
fi

run