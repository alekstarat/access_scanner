#!/usr/bin/env python3
"""
Worker: читает active_hosts.txt в режиме append-only.

Discovery (genip.sh) только дописывает строки.
Worker хранит byte-offset в state/worker.offset и подхватывает
только новые данные. Если новых строк нет — ждёт, не завершаясь.
"""

import fcntl
import os
import re
import subprocess
import time
from pathlib import Path

QUEUE = Path("active_hosts.txt")
OFFSET_FILE = Path("state/worker.offset")
POLL_INTERVAL = 1.0  # секунды между проверками, когда новых данных нет

# Строка вида: "1.2.3.4 - Ports: 22/tcp,80/tcp,443/tcp"
LINE_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*Ports:\s*(.+)$",
    re.IGNORECASE,
)


def load_offset() -> int:
    """Читает сохранённый byte-offset. При ошибке/отсутствии — 0."""
    try:
        text = OFFSET_FILE.read_text(encoding="utf-8").strip()
        if not text:
            return 0
        return max(0, int(text))
    except (OSError, ValueError):
        return 0


def save_offset(offset: int) -> None:
    """Атомарно записывает byte-offset."""
    OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = OFFSET_FILE.with_suffix(".tmp")
    tmp.write_text(str(offset) + "\n", encoding="utf-8")
    os.replace(tmp, OFFSET_FILE)


def read_new_chunk(offset: int) -> tuple[bytes, int]:
    """
    Читает байты начиная с offset до текущего конца файла.
    Возвращает (data, file_size_at_read).
    Файл открывается только на чтение — discovery может спокойно append'ить.
    """
    if not QUEUE.exists():
        return b"", offset

    with open(QUEUE, "rb") as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        try:
            f.seek(0, os.SEEK_END)
            size = f.tell()

            if offset > size:
                # файл обрезали / пересоздали — начинаем с начала
                offset = 0

            if offset >= size:
                return b"", size

            f.seek(offset)
            data = f.read()
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)

    return data, offset + len(data)


def parse_line(line: str) -> tuple[str, list[str]] | None:
    """
    Парсит строку discovery.
    Возвращает (ip, ["22/tcp", "80/tcp", ...]) или None.
    """
    line = line.strip()
    if not line or line.startswith("=") or line.startswith("Started"):
        return None

    m = LINE_RE.match(line)
    if not m:
        return None

    ip = m.group(1)
    ports_raw = m.group(2)
    ports = [p.strip() for p in ports_raw.split(",") if p.strip()]
    if not ports:
        return None
    return ip, ports


def process(ip: str, ports: list[str]) -> None:
    """Вызывает main.py (port-hub) для IP и списка портов."""
    print(f"[*] Processing {ip}  ports={ports}", flush=True)

    cmd = ["python3", "main.py", ip, *ports]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.stdout:
            print(result.stdout.rstrip(), flush=True)
        if result.stderr:
            print(result.stderr.rstrip(), flush=True)
        if result.returncode != 0:
            print(f"[!] {ip}: exit code {result.returncode}", flush=True)
    except subprocess.TimeoutExpired:
        print(f"[!] {ip}: timeout", flush=True)
    except Exception as exc:
        print(f"[!] {ip}: {exc}", flush=True)


def main() -> None:
    OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
    QUEUE.touch(exist_ok=True)

    offset = load_offset()
    print(f"[*] Worker started, offset={offset}", flush=True)

    while True:
        data, end_pos = read_new_chunk(offset)

        if not data:
            time.sleep(POLL_INTERVAL)
            continue

        # Ищем последнюю полную строку (заканчивается на \n)
        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            # Нет ни одного \n — ждём дописывания строки, offset не двигаем
            time.sleep(POLL_INTERVAL)
            continue

        complete = data[: last_nl + 1]
        # байты после последнего \n — неполная строка, их пока не трогаем
        consumed = len(complete)

        text = complete.decode("utf-8", errors="replace")
        for line in text.splitlines():
            parsed = parse_line(line)
            if parsed is None:
                continue
            ip, ports = parsed
            try:
                process(ip, ports)
            except Exception as exc:
                print(f"[!] {ip}: {exc}", flush=True)

        offset = offset + consumed
        save_offset(offset)


if __name__ == "__main__":
    main()