"""
Оптимальный запуск deep-цепочек (в т.ч. долгих bash-скриптов).

Конфигурация (env или аргументы worker):
  DEEP_WORKERS          — потоков Python для deep (default 4)
  DEEP_BASH_LIMIT       — сколько bash/subprocess одновременно (default 2)
  DEEP_TIMEOUT          — таймаут одной задачи, сек (default 300)
  DEEP_BATCH            — сколько pending забирать за раз (default 20)

Тяжёлые цепочки (ffuf, hydra, msf) идут через run_bash() с kill process group
при timeout. Лёгкие Python-handlers — через общий thread pool.

Почему ThreadPool + subprocess, а не ProcessPool:
  - DB sqlite и ctx уже собраны в main thread
  - bash и так отдельный процесс
  - меньше overhead и проще kill всей process group
"""

from __future__ import annotations

import concurrent.futures
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


DEEP_WORKERS = _int_env("DEEP_WORKERS", 4)
DEEP_BASH_LIMIT = _int_env("DEEP_BASH_LIMIT", 2)
DEEP_TIMEOUT = _int_env("DEEP_TIMEOUT", 300)
DEEP_BATCH = _int_env("DEEP_BATCH", 20)

# Цепочки, которые считаются «тяжёлыми» (занимают bash-слот)
HEAVY_CHAINS = {
    "http_dirs",
    "https_dirs",
    "ssh_bruteforce",
    "telnet_info",
    "smb_info",
    "ftp_info",
}


# ── Internal state ────────────────────────────────────────────

_executor: concurrent.futures.ThreadPoolExecutor | None = None
_bash_sem: threading.Semaphore | None = None
_lock = threading.Lock()


def configure(
    workers: int | None = None,
    bash_limit: int | None = None,
    timeout: int | None = None,
    batch: int | None = None,
):
    """Вызвать до start() / первого submit. Пересоздаёт пул при необходимости."""
    global DEEP_WORKERS, DEEP_BASH_LIMIT, DEEP_TIMEOUT, DEEP_BATCH
    global _executor, _bash_sem

    with _lock:
        if workers is not None:
            DEEP_WORKERS = max(1, workers)
        if bash_limit is not None:
            DEEP_BASH_LIMIT = max(1, bash_limit)
        if timeout is not None:
            DEEP_TIMEOUT = max(5, timeout)
        if batch is not None:
            DEEP_BATCH = max(1, batch)

        # пересоздаём, если уже был
        if _executor is not None:
            _executor.shutdown(wait=False)
            _executor = None
        _bash_sem = threading.Semaphore(DEEP_BASH_LIMIT)


def start():
    global _executor, _bash_sem
    with _lock:
        if _bash_sem is None:
            _bash_sem = threading.Semaphore(DEEP_BASH_LIMIT)
        if _executor is None:
            _executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=DEEP_WORKERS,
                thread_name_prefix="deep",
            )


def shutdown(wait: bool = True):
    global _executor
    with _lock:
        if _executor is not None:
            _executor.shutdown(wait=wait)
            _executor = None


def stats() -> dict:
    return {
        "workers": DEEP_WORKERS,
        "bash_limit": DEEP_BASH_LIMIT,
        "timeout": DEEP_TIMEOUT,
        "batch": DEEP_BATCH,
        "heavy_chains": sorted(HEAVY_CHAINS),
    }


# ── Safe bash runner ──────────────────────────────────────────

def run_bash(
    cmd: list[str] | str,
    *,
    timeout: int | None = None,
    cwd: str | Path | None = None,
    env: dict | None = None,
    input_text: str | None = None,
) -> dict[str, Any]:
    """
    Запуск внешней команды с:
      - лимитом параллельных bash (DEEP_BASH_LIMIT)
      - kill process group по timeout
      - захватом stdout/stderr

    Возвращает:
      {
        "ok": bool,
        "returncode": int | None,
        "stdout": str,
        "stderr": str,
        "duration": float,
        "error": str | None,   # timeout / spawn error
      }
    """
    timeout = timeout if timeout is not None else DEEP_TIMEOUT
    start()

    if isinstance(cmd, str):
        shell = True
        args = cmd
    else:
        shell = False
        args = list(cmd)

    def _run() -> dict:
        t0 = time.monotonic()
        proc = None
        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_text is not None else None,
                text=True,
                cwd=str(cwd) if cwd else None,
                env={**os.environ, **(env or {})},
                shell=shell,
                start_new_session=True,  # отдельная process group
            )
            try:
                stdout, stderr = proc.communicate(
                    input=input_text,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                _kill_process_group(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except Exception:
                    stdout, stderr = "", ""
                return {
                    "ok": False,
                    "returncode": proc.returncode,
                    "stdout": stdout or "",
                    "stderr": stderr or "",
                    "duration": time.monotonic() - t0,
                    "error": f"timeout after {timeout}s",
                }

            return {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout or "",
                "stderr": stderr or "",
                "duration": time.monotonic() - t0,
                "error": None if proc.returncode == 0 else f"exit={proc.returncode}",
            }
        except FileNotFoundError as e:
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "duration": time.monotonic() - t0,
                "error": f"not found: {e}",
            }
        except Exception as e:
            if proc is not None:
                _kill_process_group(proc)
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "duration": time.monotonic() - t0,
                "error": f"{type(e).__name__}: {e}",
            }

    # Глобальный лимит одновременных bash
    assert _bash_sem is not None
    with _bash_sem:
        return _run()


def _kill_process_group(proc: subprocess.Popen):
    """Убивает весь process group (bash + ffuf/hydra children)."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        return

    try:
        proc.wait(timeout=3)
        return
    except Exception:
        pass

    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# ── Submit deep tasks ─────────────────────────────────────────

def submit(fn: Callable, *args, **kwargs) -> concurrent.futures.Future:
    """Отправить callable в thread pool."""
    start()
    assert _executor is not None
    return _executor.submit(fn, *args, **kwargs)


def run_with_timeout(
    fn: Callable[[], Any],
    timeout: int | None = None,
) -> tuple[Any | None, str | None]:
    """
    Выполнить fn() в пуле с timeout.
    Возвращает (result, error).
    Важно: при timeout поток продолжает работать до конца fn —
    поэтому тяжёлую работу внутри fn делай через run_bash (killable).
    """
    timeout = timeout if timeout is not None else DEEP_TIMEOUT
    fut = submit(fn)
    try:
        return fut.result(timeout=timeout), None
    except concurrent.futures.TimeoutError:
        return None, f"timeout after {timeout}s"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def is_heavy(chain: str) -> bool:
    return chain in HEAVY_CHAINS
