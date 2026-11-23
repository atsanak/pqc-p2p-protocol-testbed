#!/usr/bin/env python3
"""Example — RESOLVE: how this node reaches a named peer, and what it has cached about that.

Read-only. Sends nothing to the peer — the only party contacted is the Server, and only to ask.

Usage: python3 02_resolve.py <peer-name> [another-peer-name]"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from p2p_api import P2PAPI, errors   # noqa: E402 — `errors` re-exported by the facade,
                                     # which is also what puts p2p/ on sys.path: importing
                                     # `common` directly here would run before that happens


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    a = P2PAPI()
    for peer in sys.argv[1:]:
        print(f"== path({peer!r}) ==")
        try:
            p = a.path(peer)
        except errors.ResolveError as e:
            # The honest failure: an unknown name, or a Server this node cannot reach AND no cache
            # young enough to stand in for it.
            print(f"  ResolveError: {e}\n")
            continue
        print(f"  ip           {p.get('ip')}")
        print(f"  tenant/role  {p.get('tenant')} / {p.get('role')}")
        print(f"  cross-tenant {p.get('cross_tenant')}")
        print(f"  hops         {' -> '.join(h or '?' for h in p.get('hops') or [])}")
        if p.get("stale"):
            print(f"  ** STALE: served from a {p['stale_age_s']}s-old local cache — the Server "
                  f"was unreachable, this route may no longer be true **")
        print()

    print("== resolve_cache() — what this node could still answer with if the Server went down ==")
    cache = a.resolve_cache()
    if not cache:
        print("  (empty — nothing resolved yet, or an older p2p build with no degrade cache)")
    for e in cache:
        verdict = "usable" if e["usable"] else f"TOO OLD (max {e['max_age_s']}s)"
        print(f"  {e['name']:<55} {str(e['ip']):<12} {e['age_s']:>5}s  {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
