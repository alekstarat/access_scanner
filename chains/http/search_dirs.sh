#!/bin/bash

set -u

IP=""
PORT=""
TLS=false
HOST_HEADER=""
WORDLIST="${FFUF_WORDLIST:-}"
THREADS="${FFUF_THREADS:-20}"
REQ_TIMEOUT="${FFUF_TIMEOUT:-5}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_WORDLISTS=(
  "$SCRIPT_DIR/../../rcs/api-endpoints.txt"
  "$SCRIPT_DIR/../../wordlists/api-endpoints.txt"
  "/home/arch/Desktop/wordlists/api-endpoints.txt"
  "/usr/share/seclists/Discovery/Web-Content/common.txt"
  "/usr/share/wordlists/dirb/common.txt"
)

show_help() {
  echo "Usage: $0 -i <ip|host> -p <port> [--tls] [-H host] [-w wordlist]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i) IP="${2:-}"; shift 2 ;;
    -p) PORT="${2:-}"; shift 2 ;;
    --tls) TLS=true; shift ;;
    -H|--host) HOST_HEADER="${2:-}"; shift 2 ;;
    -w|--wordlist) WORDLIST="${2:-}"; shift 2 ;;
    -h|--help) show_help; exit 1 ;;
    *) echo "Unknown option: $1" >&2; show_help; exit 1 ;;
  esac
done

if [[ -z "$IP" || -z "$PORT" ]]; then
  echo '{"ok":false,"error":"-i and -p are required","results":[]}'
  exit 1
fi

if [[ -z "$WORDLIST" ]]; then
  for candidate in "${DEFAULT_WORDLISTS[@]}"; do
    if [[ -f "$candidate" ]]; then
      WORDLIST="$candidate"
      break
    fi
  done
fi

if [[ -z "$WORDLIST" || ! -f "$WORDLIST" ]]; then
  echo '{"ok":false,"error":"wordlist not found","results":[]}'
  exit 2
fi

if ! command -v ffuf >/dev/null 2>&1; then
  echo '{"ok":false,"error":"ffuf not found in PATH","results":[]}'
  exit 127
fi

PROTOCOL="http"
[[ "$TLS" == true ]] && PROTOCOL="https"
URL="${PROTOCOL}://${IP}:${PORT}/FUZZ"

OUT_JSON="$(mktemp /tmp/ffuf_XXXXXX.json)"
ERR_LOG="$(mktemp /tmp/ffuf_err_XXXXXX.txt)"
trap 'rm -f "$OUT_JSON" "$ERR_LOG"' EXIT

FFUF_ARGS=(
  -u "$URL"
  -w "$WORDLIST"
  -t "$THREADS"
  -timeout "$REQ_TIMEOUT"
  -mc 200,201,204,301,302,307,308,401,403,405,500
  -fc 404
  -s
  -noninteractive
  -o "$OUT_JSON"
  -of json
)

if [[ -n "$HOST_HEADER" ]]; then
  FFUF_ARGS+=(-H "Host: ${HOST_HEADER}")
fi
if [[ "$TLS" == true ]]; then
  FFUF_ARGS+=(-k)
fi

ffuf "${FFUF_ARGS[@]}" >"$ERR_LOG" 2>&1
RC=$?

export OUT_JSON ERR_LOG URL WORDLIST HOST_HEADER RC
export TLS_FLAG=0
[[ "$TLS" == true ]] && TLS_FLAG=1

python3 <<'PY'
import json, os, sys
from pathlib import Path

out_path = Path(os.environ["OUT_JSON"])
err_path = Path(os.environ["ERR_LOG"])
url = os.environ["URL"]
wordlist = os.environ["WORDLIST"]
host_header = os.environ.get("HOST_HEADER") or None
tls = os.environ.get("TLS_FLAG") == "1"
rc = int(os.environ.get("RC", "1"))
err_text = ""
if err_path.is_file():
    err_text = err_path.read_text(encoding="utf-8", errors="replace")[:2000]

if not out_path.is_file() or out_path.stat().st_size == 0:
    print(json.dumps({
        "ok": False,
        "returncode": rc,
        "error": "ffuf produced no JSON output",
        "stderr": err_text,
        "url": url,
        "wordlist": wordlist,
        "results": [],
        "count": 0,
    }, ensure_ascii=False))
    sys.exit(0)

try:
    data = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
except Exception as e:
    print(json.dumps({
        "ok": False,
        "returncode": rc,
        "error": f"json parse: {e}",
        "stderr": err_text,
        "url": url,
        "results": [],
        "count": 0,
    }, ensure_ascii=False))
    sys.exit(0)

results = []
for r in data.get("results") or []:
    inp = r.get("input")
    path = None
    if isinstance(inp, dict):
        path = inp.get("FUZZ")
    elif inp is not None:
        path = str(inp)
    results.append({
        "url": r.get("url"),
        "path": path,
        "status": r.get("status"),
        "length": r.get("length"),
        "words": r.get("words"),
        "lines": r.get("lines"),
        "redirectlocation": r.get("redirectlocation") or "",
    })

def rank(x):
    st = x.get("status") or 0
    prio = 0 if st in (200, 201, 204) else (1 if st in (301, 302, 307, 308) else 2)
    return (prio, st, x.get("path") or "")

results.sort(key=rank)

print(json.dumps({
    "ok": True,
    "returncode": rc,
    "url": url,
    "host_header": host_header,
    "tls": tls,
    "wordlist": wordlist,
    "count": len(results),
    "results": results[:500],
    "stderr": err_text if rc != 0 else "",
}, ensure_ascii=False))
PY

exit 0
