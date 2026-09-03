import subprocess
import logging
from pathlib import Path

log = logging.getLogger(__name__)

SCRIPT = Path(__file__).resolve().parent / "search_dirs.sh"
# таймаут на ffuf (секунды)
FFUF_TIMEOUT = 120


def search_dirs(ip: str, port: int, tls: bool = False) -> str:
    if not SCRIPT.is_file():
        return f"error: script not found: {SCRIPT}"

    cmd = [str(SCRIPT), "-i", str(ip), "-p", str(port)]
    if tls:
        cmd.append("--tls")

    log.info("search_dirs: %s", " ".join(cmd))

    try:
        # start_new_session=True — дочерний процесс в своей сессии,
        # Ctrl+C / сигналы IDE не убивают его вместе с worker'ом так же жёстко
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=FFUF_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return f"error: timeout after {FFUF_TIMEOUT}s\n{stderr or ''}"

        if proc.returncode != 0:
            return f"error: exit={proc.returncode}\n{stderr or stdout or ''}"

        return stdout or ""

    except FileNotFoundError as e:
        return f"error: {e}"
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"