#!/usr/bin/env bash
set -Eeuo pipefail

# Корень проекта — каталог, в котором находится этот скрипт
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "[+] Поиск скриптов в: $PROJECT_ROOT"

count=0

while IFS= read -r -d '' file; do
    chmod +x -- "$file"
    printf '[+] %s\n' "${file#"$PROJECT_ROOT"/}"
    ((count += 1))
done < <(
    find "$PROJECT_ROOT" \
        -type f \
        \( \
            -name '*.sh' \
            -o -name '*.bash' \
            -o -name '*.py' \
            -o -name '*.pl' \
            -o -name '*.rb' \
            -o -name '*.php' \
            -o -name '*.command' \
        \) \
        -not -path '*/.git/*' \
        -not -path '*/.venv/*' \
        -not -path '*/venv/*' \
        -not -path '*/node_modules/*' \
        -print0
)

echo
echo "[✓] Готово. Обработано файлов: $count"
