"""Execution layer for deep tasks: bounded pools, killable process groups and task logs."""
from __future__ import annotations

import concurrent.futures
import os
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


DEEP_WORKERS = _int_env("DEEP_WORKERS", 4)
DEEP_BASH_LIMIT = _int_env("DEEP_BASH_LIMIT", 2)
DEEP_TIMEOUT = _int_env("DEEP_TIMEOUT", 300)
DEEP_BATCH = _int_env("DEEP_BATCH", 20)
TASK_CANCEL_POLL = max(0.1, float(os.environ.get("TASK_CANCEL_POLL", "0.25")))

HEAVY_CHAINS = {
    # Реально долгие bash-цепи (nmap/ffuf/msf). Стабы *_info без run_bash
    # сюда не входят — иначе семафор занимается впустую.
    "http_dirs", "https_dirs", "ssh_bruteforce", "rdp_info",
}

ROOT = Path(__file__).resolve().parent
TASK_LOG_DIR = ROOT / "logs" / "tasks"
TASK_CANCEL_DIR = ROOT / "state" / "task_cancel"
RUNTIME_FILE = ROOT / "state" / "deep_runtime.json"

_executor: concurrent.futures.ThreadPoolExecutor | None = None
_bash_sem: threading.Semaphore | None = None
_lock = threading.Lock()
_tls = threading.local()
_active_procs = {}
_active_lock = threading.Lock()


def _write_runtime():
    import json
    import tempfile
    RUNTIME_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _active_lock:
        procs = [dict(v) for v in _active_procs.values()]
    payload = {"updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "processes": procs}
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    # Каждый поток пишет в СВОЙ tmp-файл: общий deep_runtime.tmp приводил
    # к гонке «not found ...tmp -> ...json», когда один поток делал
    # os.replace, а второй в этот момент только создал tmp заново.
    fd, tmp_name = tempfile.mkstemp(
        dir=str(RUNTIME_FILE.parent),
        prefix=RUNTIME_FILE.stem + ".",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp_name, RUNTIME_FILE)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def runtime_stats():
    with _active_lock:
        processes = [dict(v) for v in _active_procs.values()]
    return {"active_processes": processes, "active_count": len(processes)}


def configure(workers=None, bash_limit=None, timeout=None, batch=None):
    global DEEP_WORKERS, DEEP_BASH_LIMIT, DEEP_TIMEOUT, DEEP_BATCH, _executor, _bash_sem
    with _lock:
        if workers is not None: DEEP_WORKERS = max(1, workers)
        if bash_limit is not None: DEEP_BASH_LIMIT = max(1, bash_limit)
        if timeout is not None: DEEP_TIMEOUT = max(5, timeout)
        if batch is not None: DEEP_BATCH = max(1, batch)
        if _executor is not None:
            _executor.shutdown(wait=False, cancel_futures=False)
            _executor = None
        _bash_sem = threading.Semaphore(DEEP_BASH_LIMIT)


def start():
    global _executor, _bash_sem
    with _lock:
        if _bash_sem is None:
            _bash_sem = threading.Semaphore(DEEP_BASH_LIMIT)
        if _executor is None:
            _executor = concurrent.futures.ThreadPoolExecutor(max_workers=DEEP_WORKERS, thread_name_prefix="deep")


def shutdown(wait=True):
    global _executor
    with _lock:
        if _executor is not None:
            _executor.shutdown(wait=wait, cancel_futures=False)
            _executor = None


def stats():
    return {"workers": DEEP_WORKERS, "bash_limit": DEEP_BASH_LIMIT, "timeout": DEEP_TIMEOUT,
            "batch": DEEP_BATCH, "heavy_chains": sorted(HEAVY_CHAINS)}


def get_timeout() -> int:
    return DEEP_TIMEOUT


def set_task_context(task_id: int | None):
    _tls.task_id = task_id


def current_task_id() -> int | None:
    return getattr(_tls, "task_id", None)


def _task_log_path(task_id: int) -> Path:
    TASK_LOG_DIR.mkdir(parents=True, exist_ok=True)
    return TASK_LOG_DIR / f"{task_id}.log"


def task_log(task_id: int | None, stream: str, text: str):
    if task_id is None or not text:
        return
    path = _task_log_path(task_id)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with path.open("a", encoding="utf-8", errors="replace") as f:
        for line in text.splitlines() or [""]:
            f.write(f"[{stamp}] [{stream}] {line}\n")
        f.flush()


def task_log_tail(task_id: int, limit=100_000) -> str:
    path = _task_log_path(task_id)
    if not path.exists():
        return ""
    data = path.read_text(encoding="utf-8", errors="replace")
    return data[-limit:]


def request_cancel_marker(task_id: int):
    TASK_CANCEL_DIR.mkdir(parents=True, exist_ok=True)
    _task_cancel_path(task_id).touch()


def clear_cancel_marker(task_id: int):
    try:
        _task_cancel_path(task_id).unlink()
    except FileNotFoundError:
        pass


def _task_cancel_path(task_id: int) -> Path:
    return TASK_CANCEL_DIR / str(task_id)


def is_cancel_requested(task_id: int | None) -> bool:
    return bool(task_id is not None and _task_cancel_path(task_id).exists())


def _kill_process_group(proc: subprocess.Popen):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception:
        try: proc.kill()
        except Exception: pass
        return
    try:
        proc.wait(timeout=3)
        return
    except Exception:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try: proc.kill()
        except Exception: pass


def run_bash(cmd: list[str] | str, *, timeout=None, cwd=None, env=None, input_text=None) -> dict[str, Any]:
    """Run a shell command with live logs, cancellation, timeout and reliable cleanup."""
    timeout = timeout if timeout is not None else DEEP_TIMEOUT
    start()
    task_id = current_task_id()
    if isinstance(cmd, str):
        shell, args = True, cmd
        display_cmd = cmd
    else:
        shell, args = False, list(cmd)
        display_cmd = " ".join(map(str, args))

    def _run():
        t0 = time.monotonic()
        proc = None
        stdout_parts, stderr_parts = [], []
        sel = None
        task_log(task_id, "runner", f"$ {display_cmd}")
        try:
            proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_text is not None else None,
                text=False, cwd=str(cwd) if cwd else None,
                env={**os.environ, **(env or {})}, shell=shell,
                start_new_session=True,
            )
            with _active_lock:
                _active_procs[proc.pid] = {
                    "pid": proc.pid, "task_id": task_id, "command": display_cmd,
                    "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            _write_runtime()

            if input_text is not None and proc.stdin is not None:
                try:
                    proc.stdin.write(input_text.encode())
                finally:
                    proc.stdin.close()

            import selectors
            sel = selectors.DefaultSelector()
            if proc.stdout is not None:
                sel.register(proc.stdout, selectors.EVENT_READ, "stdout")
            if proc.stderr is not None:
                sel.register(proc.stderr, selectors.EVENT_READ, "stderr")

            cancelled = False
            timed_out = False
            kill_started = None

            while sel.get_map():
                now = time.monotonic()
                if now - t0 >= timeout and not timed_out:
                    timed_out = True
                    kill_started = now
                    _kill_process_group(proc)
                if is_cancel_requested(task_id) and not cancelled:
                    cancelled = True
                    kill_started = now
                    _kill_process_group(proc)

                events = sel.select(timeout=TASK_CANCEL_POLL)
                for key, _ in events:
                    stream = key.data
                    try:
                        chunk = key.fileobj.read1(8192) if hasattr(key.fileobj, "read1") else key.fileobj.read(8192)
                    except (OSError, ValueError):
                        chunk = b""
                    if not chunk:
                        try:
                            sel.unregister(key.fileobj)
                        except Exception:
                            pass
                        continue
                    text = chunk.decode("utf-8", errors="replace")
                    if stream == "stdout":
                        stdout_parts.append(text)
                    else:
                        stderr_parts.append(text)
                    task_log(task_id, stream, text)

                # Once the process is dead, don't wait forever for a pipe held
                # by an accidental grandchild. Give pipes a short grace period,
                # then close them and finish the task.
                if proc.poll() is not None:
                    if not sel.get_map():
                        break
                    if kill_started is None:
                        kill_started = time.monotonic()
                    elif time.monotonic() - kill_started >= 1.0:
                        for key in list(sel.get_map().values()):
                            try: sel.unregister(key.fileobj)
                            except Exception: pass
                            try: key.fileobj.close()
                            except Exception: pass
                        break

            try:
                rc = proc.wait(timeout=2)
            except Exception:
                rc = proc.returncode

            stdout, stderr = "".join(stdout_parts), "".join(stderr_parts)
            if cancelled:
                error = "cancelled"
            elif timed_out:
                error = f"timeout after {timeout}s"
            else:
                error = None if rc == 0 else f"exit={rc}"
            duration = time.monotonic() - t0
            task_log(task_id, "runner", f"exit={rc} duration={duration:.1f}s error={error or '-'}")
            return {"ok": rc == 0 and not cancelled and not timed_out, "returncode": rc,
                    "stdout": stdout, "stderr": stderr, "duration": duration, "error": error}
        except FileNotFoundError as e:
            err = f"not found: {e}"
            task_log(task_id, "stderr", err)
            return {"ok": False, "returncode": None, "stdout": "".join(stdout_parts),
                    "stderr": "".join(stderr_parts), "duration": time.monotonic()-t0, "error": err}
        except Exception as e:
            if proc is not None:
                _kill_process_group(proc)
            err = f"{type(e).__name__}: {e}"
            task_log(task_id, "stderr", err)
            return {"ok": False, "returncode": None, "stdout": "".join(stdout_parts),
                    "stderr": "".join(stderr_parts), "duration": time.monotonic()-t0, "error": err}
        finally:
            if sel is not None:
                try: sel.close()
                except Exception: pass
            if proc is not None:
                try:
                    if proc.poll() is None:
                        _kill_process_group(proc)
                except Exception:
                    pass
                with _active_lock:
                    _active_procs.pop(proc.pid, None)
                _write_runtime()

    assert _bash_sem is not None
    with _bash_sem:
        return _run()

def submit(fn: Callable, *args, **kwargs) -> concurrent.futures.Future:
    start(); assert _executor is not None
    return _executor.submit(fn, *args, **kwargs)


def run_with_timeout(fn: Callable[[], Any], timeout=None, cancel_event=None):
    """Запускает fn в пуле и ждёт timeout секунд.

    ВАЖНО: зависший поток ThreadPoolExecutor убить нельзя — он продолжит
    жить и может позже записать результат поверх статуса timeout.
    Поэтому для deep-задач используйте _run_deep_task с проверкой флага:
    после таймаута задача помечается timeout и её поздняя запись
    игнорируется (см. mark_deep_done с expected_status).
    """
    timeout = timeout if timeout is not None else DEEP_TIMEOUT
    fut = submit(fn)
    try:
        return fut.result(timeout=timeout), None
    except concurrent.futures.TimeoutError:
        # Не блокируемся: отменяем future если он ещё не стартовал.
        # Уже бегущий тред продолжит работу — его результат должен
        # игнорироваться вызывающей стороной по статусу задачи.
        try:
            fut.cancel()
        except Exception:
            pass
        if cancel_event is not None:
            try:
                cancel_event.set()
            except Exception:
                pass
        return None, f"timeout after {timeout}s"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def is_heavy(chain: str) -> bool:
    return chain in HEAVY_CHAINS
