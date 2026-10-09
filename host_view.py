#!/usr/bin/env python3
"""
CLI / quick view of the host-centric model.

Examples:
    python host_view.py 1.2.3.4
    python host_view.py --id 42
    python host_view.py --list
    python host_view.py 1.2.3.4 --json
"""

from __future__ import annotations

import argparse
import json
import sys

from models import get_host_by_ip, get_host_by_id, list_host_summaries


def print_host(host, as_json: bool = False):
    if host is None:
        print("Host not found", file=sys.stderr)
        sys.exit(1)

    if as_json:
        print(host.to_json())
        return

    print(f"═══ Host {host.ip} (id={host.id})  risk={host.risk_score}/100")
    print(f"    first_seen: {host.first_seen}")
    print(f"    last_seen:  {host.last_seen}")

    if host.domains:
        print("  Domains:")
        for d in host.domains:
            print(f"    • {d.name}  [{d.source}]")

    if host.geo:
        g = host.geo
        loc = ", ".join(filter(None, [g.city, g.region, g.country]))
        print(f"  Geo: {loc or '—'}  ASN={g.asn}  {g.org or ''}")

    print(f"  Services ({len(host.services)}):")
    for svc in host.services:
        print(f"    ┌─ {svc.port}/{svc.protocol}  [{svc.service or 'unknown'}]")
        if svc.version:
            print(f"    │  version: {svc.version}")
        if svc.banner:
            print(f"    │  banner:  {svc.banner[:120]}")
        if svc.findings:
            print(f"    │  findings ({len(svc.findings)}):")
            for f in svc.findings:
                print(f"    │    [{f.severity}] {f.title} — {f.evidence}")
        if svc.deep_tasks:
            print(f"    │  deep tasks:")
            for t in svc.deep_tasks:
                status = t.status
                err = f" err={t.error}" if t.error else ""
                print(f"    │    • {t.chain} [{status}]{err}")
                for r in t.results:
                    val_preview = str(r.value)[:80]
                    print(f"    │        {r.key}: {val_preview}")
        if svc.deep and not svc.deep_tasks:
            # fallback if only aggregated
            print(f"    │  deep: {list(svc.deep.keys())}")
        print(f"    └─")

    summary = host.to_dict()["summary"]
    print(f"  Summary: ports={summary['ports_open']}  "
          f"services={summary['services']}  "
          f"findings={summary['findings_count']}  "
          f"max_sev={summary['max_severity']}")


def main():
    parser = argparse.ArgumentParser(description="Host-centric view of recon data")
    parser.add_argument("ip", nargs="?", help="IP address")
    parser.add_argument("--id", type=int, help="Host ID")
    parser.add_argument("--list", action="store_true", help="List host summaries")
    parser.add_argument("--json", action="store_true", help="Output full JSON")
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()

    if args.list:
        rows = list_host_summaries(limit=args.limit)
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        else:
            for r in rows:
                print(f"{r['id']:4d}  {r['ip']:15s}  risk={r['risk_score']:3d}  "
                      f"ports={r['ports']:2d}  findings={r['findings']:3d}  "
                      f"{','.join(r['services'][:6])}")
        return

    if args.id is not None:
        host = get_host_by_id(args.id)
    elif args.ip:
        host = get_host_by_ip(args.ip)
    else:
        parser.print_help()
        sys.exit(1)

    print_host(host, as_json=args.json)


if __name__ == "__main__":
    main()
