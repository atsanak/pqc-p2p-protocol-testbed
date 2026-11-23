#!/usr/bin/env python3
"""Example — IDENTITY: does this box have a usable P2P identity, and can it prove it?

Entirely read-only and offline (no Server, no peer, no env required) except `peer_cert`, which is
not used here. Safe to run on any node at any time — this is the call to make FIRST when a node's
P2P has gone quiet, because a cert problem looks identical to a network problem from the outside.

Usage: python3 01_identity.py"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from p2p_api import P2PAPI                                                  # noqa: E402


def main():
    a = P2PAPI()
    print(f"== identity_status() — this node is {a.name!r} ==")
    st = a.identity_status()
    print(json.dumps(st, indent=2))
    if st.get("present"):
        # The one field worth reading before any of the others: a cached ca.crt that no longer
        # verifies the live fleet CA makes every future exchange fail, and nothing else reports it
        # until a peer connection has already failed.
        print(f"\n  -> chains to its own cached CA: {st.get('chains_to_cached_ca')}"
              f"   (expires in {st.get('days_left')} days)")

    print("\n== pqc_status() — can this node do --tech pqc? ==")
    print(json.dumps(a.pqc_status(), indent=2))

    print("\n== identity_headers() — the proof-of-possession this node attaches to control-plane calls ==")
    h = a.identity_headers()
    print("  " + (json.dumps({k: f"<{len(v)} b64 chars>" for k, v in h.items()})
                  if h else "{} — no cached identity, so calls fall back to bootstrap-secret-only"))

    print("\n== check_freshness() — the replay window both certless transports apply first ==")
    import time
    print("  now       ->", a.check_freshness(int(time.time())))
    print("  120s ago  ->", a.check_freshness(int(time.time()) - 120))

    print("\n== fetch_identity() without confirm (always refused — safe to run) ==")
    print(" ", a.fetch_identity())


if __name__ == "__main__":
    main()
