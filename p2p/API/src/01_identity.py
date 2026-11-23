#!/usr/bin/env python3
"""Use case — IDENTITY (local): is this box's P2P identity present, sound and provable?

Read-only and offline. `--enrol-scratch` additionally exercises the REAL `fetch_identity(
confirm=True)` path against a throwaway directory: on a node that already holds a cert the Server
answers 401 (its anti-key-handout rule), which proves the gate and the real call without minting
anything — and the script then confirms the node's real cache is byte-identical afterwards. See
docs/01_identity.md.

Usage: python3 01_identity.py [--enrol-scratch]
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from p2p_api import P2PAPI                                                  # noqa: E402

OUT = os.path.join(HERE, "outputs")


def _cache_digest(cache_dir):
    out = {}
    for f in ("peer.crt", "peer.key", "ca.crt"):
        p = os.path.join(cache_dir, f)
        if os.path.exists(p):
            with open(p, "rb") as fh:
                out[f] = hashlib.md5(fh.read()).hexdigest()
    return out


def main():
    a = P2PAPI()
    status = a.identity_status()
    pqc = a.pqc_status()
    headers = a.identity_headers()
    print("== identity_status ==")
    print(json.dumps(status, indent=2))
    print("\n== pqc_status ==")
    print(json.dumps(pqc, indent=2))
    print("\n== identity_headers ==")
    print("  " + (", ".join(f"{k}=<{len(v)} chars>" for k, v in headers.items()) or "(none)"))

    print("\n== fetch_identity refusal (always safe) ==")
    refused = a.fetch_identity()
    print(f"  {refused}")

    enrol = None
    if "--enrol-scratch" in sys.argv:
        before = _cache_digest(a.cache_dir)
        scratch = tempfile.mkdtemp(prefix=".enrol-scratch-")
        try:
            print(f"\n== REAL fetch_identity(confirm=True) into {scratch} ==")
            enrol = a.fetch_identity(cache_dir=scratch, confirm=True)
            print(f"  {enrol}")
            after = _cache_digest(a.cache_dir)
            enrol = {"result": enrol, "real_cache_untouched": before == after,
                     "scratch_left": sorted(os.listdir(scratch))}
            print(f"  real cache untouched: {enrol['real_cache_untouched']}")
            print(f"  scratch contents    : {enrol['scratch_left']}")
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "identity.json"), "w", encoding="utf-8") as f:
        json.dump({"status": status, "pqc": pqc,
                   "headers": {k: len(v) for k, v in headers.items()},
                   "refusal": refused, "enrol": enrol}, f, indent=2)
    print(f"\n[ok] saved to {OUT}/identity.json")


if __name__ == "__main__":
    main()
