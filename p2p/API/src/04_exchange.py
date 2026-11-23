#!/usr/bin/env python3
"""Use case — EXCHANGE (sender side): preflight, health, status, envelope-build — and, only with
`--send`, the gated real writes.

Without `--send` nothing on the peer changes: preflight opens and closes a TLS connection, /health
and /status read, and the envelope is built and verified locally without being sent.

With `--send` the script performs the two gated write use cases for real, against an
obviously-named throwaway target, and prints what to check on the receiver afterwards:
  * `send_message`  appends ONE record to the peer's /var/lib/p2p/messages.log
  * `deliver_file`  writes ONE file into the peer's /var/lib/p2p/received/ (name below), and the
                    script verifies the receiver's own sha256 against the bytes it sent
Both are additive and confined; neither disturbs anything else on that box. See
docs/04_exchange.md for the full blast-radius reasoning and what was verified live.

`rm` (arbitrary remote command execution on the peer) is NOT available from this package at all —
see p2p_api.py's module docstring.

Usage: python3 04_exchange.py <peer-name> [--tech mtls|https|pqc|coap-enc] [--send]
"""
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from p2p_api import P2PAPI, errors   # noqa: E402 — `errors` re-exported by the facade,
                                     # which is also what puts p2p/ on sys.path: importing
                                     # `common` directly here would run before that happens

OUT = os.path.join(HERE, "outputs")
PROBE_NAME = "local-api-sweep-probe.bin"


def main():
    if len(sys.argv) < 2 or sys.argv[1].startswith("--"):
        print(__doc__)
        return 2
    peer = sys.argv[1]
    tech = sys.argv[sys.argv.index("--tech") + 1] if "--tech" in sys.argv else "mtls"
    a = P2PAPI()
    report = {"peer": peer, "tech": tech}

    print(f"== preflight({peer}, {tech}) ==")
    report["preflight"] = a.preflight(peer, tech=tech)
    print(json.dumps(report["preflight"], indent=2))
    if not report["preflight"].get("would_succeed"):
        print("\n[stop] preflight says this pair would not succeed — not going further.")
        _save(report)
        return 1

    print("\n== peer_health ==")
    report["health"] = a.peer_health(peer, tech=tech)
    print(json.dumps(report["health"], indent=2))

    print("\n== get_status (read-only use case, ungated) ==")
    report["status"] = a.get_status(peer, tech=tech)
    print(json.dumps(report["status"], indent=2))

    print("\n== build_envelope (local only, nothing sent) ==")
    try:
        env = a.build_envelope("message", {"probe": "local-api-sweep"}, tech="https")
        report["envelope"] = {k: v for k, v in env.items() if k != "envelope"}
        print(json.dumps(report["envelope"], indent=2))
    except errors.IdentityError as e:
        report["envelope"] = {"error": str(e)}
        print(f"  IdentityError: {e}")

    print("\n== ml_op list_models (read-only verb, ungated, real) ==")
    report["ml_list"] = a.ml_op(peer, "list_models")
    print(json.dumps(report["ml_list"], indent=2)[:800])

    print("\n== confirm gates (refusals) ==")
    report["refusals"] = {
        "send_message": a.send_message(peer, {"x": 1}, tech=tech),
        "deliver_file": a.deliver_file(peer, b"x", "demo.bin", tech=tech),
        "ml_op_run_model": a.ml_op(peer, "run_model", tech=tech),
    }
    for k, v in report["refusals"].items():
        print(f"  {k}: {v}")

    if "--send" in sys.argv:
        print(f"\n== REAL send_message(confirm=True) -> {peer} ==")
        report["sent_message"] = a.send_message(
            peer, {"probe": "local-api-sweep", "ts": int(time.time())}, tech=tech, confirm=True)
        print(json.dumps(report["sent_message"], indent=2))

        blob = f"local-api-sweep probe {time.time()}".encode()
        print(f"\n== REAL deliver_file(confirm=True) -> {peer}:{PROBE_NAME} ==")
        r = a.deliver_file(peer, blob, PROBE_NAME, tech=tech, confirm=True)
        r["local_sha256"] = hashlib.sha256(blob).hexdigest()
        r["sha256_matches"] = r.get("sha256") == r["local_sha256"]
        report["sent_file"] = r
        print(json.dumps(r, indent=2))
        print(f"\n  verify on the receiver, then clean up:\n"
              f"    tail -1 /var/lib/p2p/messages.log\n"
              f"    ls -l /var/lib/p2p/received/{PROBE_NAME} && rm /var/lib/p2p/received/{PROBE_NAME}")

    _save(report)
    return 0


def _save(report):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "exchange.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[ok] saved to {OUT}/exchange.json")


if __name__ == "__main__":
    sys.exit(main())
