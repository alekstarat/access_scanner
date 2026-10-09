#!/bin/bash

# Имя проверяемого файла
FILE="active_hosts.txt"
# Директория для бэкапов
BACKUP_DIR="backup"

# Проверяем, существует ли файл и является ли он обычным файлом
if [ -f "$FILE" ]; then
    # Создаем директорию для бэкапов, если она еще не существует
    mkdir -p "$BACKUP_DIR"

    # Формируем метку времени в формате ГГГГММДД_ЧЧММСС
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

    # Переносим файл в папку бэкапов с добавлением timestamp
    mv "$FILE" "$BACKUP_DIR/active_hosts_$TIMESTAMP.txt"
    echo "Файл $FILE успешно перенесен в $BACKUP_DIR/active_hosts_$TIMESTAMP.txt"
else
    echo "Файл $FILE не найден в текущей директории. Будет создан новый."
fi

# Пересоздаем (создаем пустой) файл active_hosts.txt
touch "$FILE"
echo "Файл $FILE пересоздан."
