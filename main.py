import argparse
import importlib
from concurrent.futures import ThreadPoolExecutor, as_completed


HTTP_PORTS = {
    80, 3000, 5000, 8000, 8008,
    8080, 8081, 8088, 8888, 9000,
}

HTTPS_PORTS = {
    443, 4443, 8443, 9443,
}

def parse_ports(ports):
    """
    Преобразует:
        22/tcp 80/tcp 443/tcp

    в:
        [(22, "tcp"), (80, "tcp"), (443, "tcp")]
    """
    result = set()

    if len(ports) >= 10: raise Exception("[Possible honeypot]\nskipping...")

    for item in ports:
        try:
            port, proto = item.lower().split("/", 1)
            port = int(port)

            if proto not in ("tcp", "udp"):
                raise ValueError

            if not 1 <= port <= 65535:
                raise ValueError

            result.add((port, proto))

        except ValueError:
            print(f"[!] Invalid port: {item}")

    return sorted(result)


def run_module(ip, port, proto):
    """
    Загружает modules.port_<port> и вызывает run().
    """

    module_name = f"scanners.port_{port}"

    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError:
        if port not in HTTP_PORTS and port not in HTTPS_PORTS:
            return (
                f"[{ip}:{port}/{proto}] "
                f"no scanner ({module_name})"
            )
        elif port in HTTP_PORTS:
            module = importlib.import_module("scanners.port_80")
        elif port in HTTPS_PORTS:
            module = importlib.import_module("scanners.port_443")

    if not hasattr(module, "run"):
        return (
            f"[{ip}:{port}/{proto}] "
            f"module has no run()"
        )

    try:
        result = module.run(ip, port, proto)

        if result is None:
            result = "done"

        return f"[{ip}:{port}/{proto}] {result}"

    except Exception as exc:
        return (
            f"[{ip}:{port}/{proto}] "
            f"module error: {exc}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Small port-based module hub"
    )

    parser.add_argument(
        "ip",
        help="Target IP address"
    )

    parser.add_argument(
        "ports",
        nargs="+",
        help="Open ports, e.g. 22/tcp 80/tcp 443/tcp"
    )

    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=4,
        help="Number of parallel modules (default: 4)"
    )

    args = parser.parse_args()

    ports = parse_ports(args.ports)

    if not ports:
        print("[!] No valid ports supplied")
        return 1

    print(f"[*] Target: {args.ip}")
    print(f"[*] Ports: {', '.join(f'{p}/{proto}' for p, proto in ports)}")
    print()

    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = [
            executor.submit(run_module, args.ip, port, proto)
            for port, proto in ports
        ]

        for future in as_completed(futures):
            print(future.result())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())