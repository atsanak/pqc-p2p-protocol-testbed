#!/usr/bin/env python3
"""Use case — RESOLVE (node side): where a peer is, how this node gets there, and what it has
cached in case the Server goes away. Read-only; the peer is never contacted.

Usage: python3 02_resolve.py <peer-name> [more-names...]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from p2p_api import P2PAPI, errors   # noqa: E402 — `errors` re-exported by the facade,
                                     # which is also what puts p2p/ on sys.path: importing
                                     # `common` directly here would run before that happens

OUT = os.path.join(HERE, "outputs")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    a = P2PAPI()
    results = {}
    for peer in sys.argv[1:]:
        try:
            p = a.path(peer)
            results[peer] = p
            stale = f"  [STALE {p['stale_age_s']}s]" if p.get("stale") else ""
            print(f"{peer}\n  ip {p.get('ip')}  cross_tenant={p.get('cross_tenant')}{stale}\n"
                  f"  {' -> '.join(h or '?' for h in p.get('hops') or [])}")
        except errors.ResolveError as e:
            results[peer] = {"error": str(e)}
            print(f"{peer}\n  ResolveError: {e}")

    cache = a.resolve_cache()
    print(f"\n== resolve_cache ({len(cache)} entries) ==")
    for e in cache:
        verdict = "usable" if e["usable"] else f"TOO OLD (max {e['max_age_s']}s)"
        print(f"  {e['name']:<55} {str(e['ip']):<12} {e['age_s']:>5}s  {verdict}")

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "resolve.json"), "w", encoding="utf-8") as f:
        json.dump({"paths": results, "cache": cache}, f, indent=2)
    print(f"\n[ok] saved to {OUT}/resolve.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
