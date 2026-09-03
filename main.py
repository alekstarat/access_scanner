import importlib
from database import init_db, save_result
from risk_engine import update_host_score, risk_level
from scanners.common import result

HTTP_PORTS = {
    80,
    3000,
    5000,
    8000,
    8008,
    8080,
    8081,
    8088,
    8888,
    9000,
}

HTTPS_PORTS = {
    443,
    4443,
    8443,
    9443,
}


def process_result(ip, data):
    host_id = save_result(ip, data)
    score = update_host_score(host_id)
    level = risk_level(score)
    return score, level


def load_module(port, proto):
    """
    Priority:
        1. HTTP family  (for ports in HTTP_PORTS)
        2. HTTPS family (for ports in HTTPS_PORTS)
        3. scanners.port_<port>
    """
    if proto == "tcp" and port in HTTP_PORTS:
        return importlib.import_module("scanners.http")

    if proto == "tcp" and port in HTTPS_PORTS:
        return importlib.import_module("scanners.https")

    try:
        return importlib.import_module(f"scanners.port_{port}")
    except ModuleNotFoundError:
        return None


def run_module(ip, port, proto):
    module = load_module(port, proto)

    if module is None:
        return result(
            service="unknown",
            port=port,
            protocol=proto,
        )

    if not hasattr(module, "run"):
        raise RuntimeError(f"Module {module.__name__} has no run()")

    data = module.run(ip, port, proto)

    # Defensive: if a module still returns a string, wrap it.
    if isinstance(data, str):
        return result(
            service="unknown",
            port=port,
            protocol=proto,
            observations={"raw": data},
            findings=[],
        )

    if not isinstance(data, dict):
        raise TypeError(
            f"Module {module.__name__}.run() must return dict, got {type(data)}"
        )
    return data


def format_result(ip, data):
    """
    Human-readable output.
    Database layer сможет использовать исходный dict напрямую.
    """
    if not isinstance(data, dict):
        return f"[!] {ip}: invalid result type {type(data)}"

    service = data.get("service", "unknown")
    port = data.get("port", "?")
    proto = data.get("protocol", "?")

    lines = [f"[+] {ip}:{port}/{proto} [{service}]"]

    observations = data.get("observations", {}) or {}
    for key, value in observations.items():
        if value is not None:
            lines.append(f"    {key}: {value}")

    findings = data.get("findings", []) or []
    if findings:
        lines.append("    findings:")
        for item in findings:
            if not isinstance(item, dict):
                lines.append(f"      {item}")
                continue
            severity = item.get("severity", 0)
            title = item.get("title", "unknown")
            evidence = item.get("evidence", "")
            line = f"      [{severity}] {title}"
            if evidence:
                line += f" — {evidence}"
            lines.append(line)

    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("ip")
    parser.add_argument("port", type=int)
    parser.add_argument("proto")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        data = run_module(args.ip, args.port, args.proto)
        score, level = process_result(args.ip, data)

        print(format_result(args.ip, data))
        print(f"    risk: {score}/100 [{level}]")

        if args.json:
            print(json.dumps(data, indent=2, ensure_ascii=False))

    except Exception as exc:
        import traceback
        print(f"[!] Module error: {exc}")
        traceback.print_exc()
        raise SystemExit(1)
