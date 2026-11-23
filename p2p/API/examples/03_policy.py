#!/usr/bin/env python3
"""Example — POLICY: the per-pair question every use case on every tech passes through first.

Read-only, and it contacts only the Server (never the peer), so asking about a pair leaves no trace
on the other node. Note what a Server this box cannot reach produces: NOT an error and NOT an
allow — a deny, with the reason saying so. That fail-closed behaviour is the thing worth seeing.

Usage: python3 03_policy.py <peer-name> [more-peer-names...]"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from p2p_api import P2PAPI                                                  # noqa: E402


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    a = P2PAPI()
    print(f"this node: {a.name}\n")
    for peer in sys.argv[1:]:
        out_allowed, out_reason = a.policy_check(a.name, peer)
        in_allowed, in_reason = a.would_accept(peer)
        print(f"== {peer} ==")
        print(f"  me -> them   {'ALLOW' if out_allowed else 'DENY ':<6}  {out_reason}")
        print(f"  them -> me   {'ALLOW' if in_allowed else 'DENY ':<6}  {in_reason}")
        # The two directions are separate questions and can legitimately disagree — a cross-tenant
        # pair needs BOTH sides to have said yes, and the policy table records each side's answer.
        if out_allowed != in_allowed:
            print("  ** asymmetric: one direction is open and the other is not **")
        print()

    print("== a name the Server has never heard of (proves fail-closed, safe to run) ==")
    print(" ", a.policy_check("NO-SUCH-NODE", a.name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
