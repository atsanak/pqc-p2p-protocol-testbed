#!/usr/bin/env python3
"""Example — RECEIVER GATES: what THIS node refuses on its own, before the network is consulted.

Entirely local: no Server, no peer, no cert needed. These two switches are unreachable from the
network by design, which is also why nothing outside this box can report their effective state — a
peer that gets refused learns only that this node declines.

Usage: python3 05_receiver_gates.py [command-to-test] [ml-method-to-test]"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from p2p_api import P2PAPI                                                  # noqa: E402


def main():
    a = P2PAPI()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "systemctl status p2p-receiver"
    method = sys.argv[2] if len(sys.argv) > 2 else "run_model"

    print(f"== rm_gate({cmd!r}) — would a peer's command run here? ==")
    g = a.rm_gate(cmd)
    print(json.dumps(g, indent=2))
    if not g.get("would_refuse"):
        # Worth stating plainly, because it is the stock configuration: P2P_RM_ENABLED defaults on
        # and the in-tenant policy default is allow, so every peer in the tenant can run this.
        print("  ** this node would RUN that command for any policy-admitted peer **")

    print(f"\n== ml_gate({method!r}) — would a peer's ML call run here? ==")
    m = a.ml_gate(method)
    print(json.dumps(m, indent=2))
    if m.get("unrecognised_in_config"):
        print(f"  ** P2P_ML_ALLOW names {m['unrecognised_in_config']}, which are not ML_METHODS — "
              f"they are silently dropped, narrowing this node's surface without saying so **")

    print("\n== ml_spool() — is anything actually servicing peer-driven ML on this node? ==")
    print(json.dumps(a.ml_spool(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
