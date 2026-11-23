#!/usr/bin/env python3
"""Use case — POLICY (node side): the per-pair verdict, in both directions, for a list of peers.
Read-only, and it asks only the Server — the peers themselves are never contacted.

Usage: python3 03_policy.py <peer-name> [more-names...]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from p2p_api import P2PAPI                                                  # noqa: E402

OUT = os.path.join(HERE, "outputs")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    a = P2PAPI()
    print(f"this node: {a.name}\n")
    print(f"{'peer':<55} {'me->them':<10} {'them->me':<10} reason (outbound)")
    rows = {}
    for peer in sys.argv[1:]:
        out_ok, out_reason = a.policy_check(a.name, peer)
        in_ok, in_reason = a.would_accept(peer)
        rows[peer] = {"outbound": {"allowed": out_ok, "reason": out_reason},
                      "inbound": {"allowed": in_ok, "reason": in_reason},
                      "asymmetric": out_ok != in_ok}
        print(f"{peer:<55} {'ALLOW' if out_ok else 'DENY':<10} "
              f"{'ALLOW' if in_ok else 'DENY':<10} {out_reason}")

    # A Server this node cannot reach is a DENY here, not an error and not an allow -- the check
    # that proves it, run against a name nothing could ever authorize.
    closed = a.policy_check("NO-SUCH-NODE", a.name)
    print(f"\nfail-closed check (unknown sender): {closed}")

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "policy.json"), "w", encoding="utf-8") as f:
        json.dump({"node": a.name, "pairs": rows, "fail_closed_probe": closed}, f, indent=2)
    print(f"[ok] saved to {OUT}/policy.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
