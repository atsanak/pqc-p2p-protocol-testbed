#!/usr/bin/env python3
"""Use case — RECEIVER GATES (local): this node's own kill switches and its ML spool's health.
Entirely local — no Server, no peer, no certificate needed, so this is the one unit that still
answers on a box whose P2P is otherwise completely broken.

Usage: python3 05_receiver_gates.py [--cmd "command"] [--method ml_method]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from p2p_api import P2PAPI                                                  # noqa: E402

OUT = os.path.join(HERE, "outputs")


def _flag(name, default):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def main():
    a = P2PAPI()
    cmd = _flag("--cmd", "systemctl status p2p-receiver")
    method = _flag("--method", "run_model")

    rm = a.rm_gate(cmd)
    ml = a.ml_gate(method)
    spool = a.ml_spool()

    print("== rm_gate ==")
    print(json.dumps(rm, indent=2))
    print("\n== ml_gate ==")
    print(json.dumps(ml, indent=2))
    print("\n== ml_spool ==")
    print(json.dumps(spool, indent=2))

    print("\n== summary ==")
    print(f"  peer-driven RM : {'ON' if rm['enabled'] else 'OFF'}"
          f"{'  (allow-list: ' + ', '.join(rm['allow_prefixes']) + ')' if rm['allow_prefixes'] else '  (no allow-list — anything the policy admits)'}")
    print(f"  {cmd!r} -> {'REFUSED: ' + str(rm.get('reason')) if rm.get('would_refuse') else 'WOULD RUN'}")
    print(f"  peer-driven ML : {'ON' if ml['enabled'] else 'OFF'}  "
          f"({len(ml['allowed_methods'])}/{len(ml['all_methods'])} methods allowed)")
    print(f"  {method!r} -> {'REFUSED: ' + str(ml.get('reason')) if ml.get('would_refuse') else 'WOULD RUN'}")
    if ml.get("unrecognised_in_config"):
        print(f"  ** P2P_ML_ALLOW contains non-methods {ml['unrecognised_in_config']} — silently "
              f"dropped by handlers/ml.py's intersection **")
    print(f"  ML agent servicing the spool: {spool.get('agent_servicing')}"
          f"{'  — ' + spool['detail'] if spool.get('detail') else ''}")

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "receiver_gates.json"), "w", encoding="utf-8") as f:
        json.dump({"rm_gate": rm, "ml_gate": ml, "ml_spool": spool}, f, indent=2)
    print(f"\n[ok] saved to {OUT}/receiver_gates.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
