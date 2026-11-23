#!/usr/bin/env python3
"""Example — EXCHANGE: everything a sender can do to a peer, stopping short of changing it.

Safe to run as-is: every call here either reads (`peer_health`, `preflight`, `get_status`), builds
something locally without sending it (`build_envelope`), or demonstrates a `confirm=True` gate by
hitting the refusal. The real gated paths are in `src/04_exchange.py --send`, which is deliberately
a separate, opt-in script — see `docs/04_exchange.md` for what each one actually changes on the
receiving box.

Usage: python3 04_exchange.py <peer-name> [--tech mtls|https|pqc|coap-enc]"""
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
    peer = sys.argv[1]
    tech = sys.argv[sys.argv.index("--tech") + 1] if "--tech" in sys.argv else "mtls"
    a = P2PAPI()

    print(f"== preflight({peer!r}, tech={tech!r}) — the four things a failure could mean ==")
    pf = a.preflight(peer, tech=tech)
    print(json.dumps(pf, indent=2))
    if not pf.get("would_succeed"):
        print("\n  -> preflight says this exchange would not succeed; stopping here rather than "
              "producing a second, less informative failure.")
        return 1

    print(f"\n== peer_health({peer!r}) — the one ungated route, plus the sender's CN/SAN checks ==")
    print(json.dumps(a.peer_health(peer, tech=tech), indent=2))

    print(f"\n== get_status({peer!r}) — the read-only use case, full stack, no confirmation needed ==")
    print(json.dumps(a.get_status(peer, tech=tech), indent=2))

    print("\n== build_envelope('message', tech='https') — what would go on the wire, unsent ==")
    try:
        env = a.build_envelope("message", {"hello": "world"}, tech="https")
        print(json.dumps({k: v for k, v in env.items() if k != "envelope"}, indent=2))
        print(f"  -> this node can produce an envelope its peers will accept: "
              f"{env['verified'] and env['chains'] and env['cn_matches_claim'] and env['fresh']}")
    except errors.IdentityError as e:
        print(f"  IdentityError: {e}")

    print("\n== the confirm=True gates (refusals — safe to run) ==")
    print("  send_message     ->", a.send_message(peer, {"x": 1}))
    print("  deliver_file     ->", a.deliver_file(peer, b"x", "demo.bin"))
    print("  ml_op run_model  ->", a.ml_op(peer, "run_model"))
    print("\n== ml_op, a READ-ONLY verb — no confirmation needed, this really runs ==")
    print(json.dumps(a.ml_op(peer, "list_models"), indent=2)[:600])
    return 0


if __name__ == "__main__":
    sys.exit(main())
