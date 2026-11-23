"""p2p/receiver-role/handlers/status — the mode-1 "device status" use case
(p2p-requirements.md: "sender requested to be done by the tenant-admin-user-pc ... status of a
device: active, IP, role").

Deliberately minimal for this pass: liveness + identity (if this handler answers, the node is up),
not the full per-model ML breakdown TB/the server already show in Device Status today (that needs
deep integration with each device's own ML pipeline state — real future work, not done here). The
mechanism (Tenant-Admin RMs the sender, sender P2P-queries the receiver, receiver answers this
handler) is the real, functional part this proves.
"""
import sys
import time
from pathlib import Path

STARTED_AT = time.time()


def details():
    """2026-10-02 (Network Map parity): this node's map row (ip, real_ip, role, lifecycle state,
    segment, parent, hops, via_chain) from its own on-board API — only when the sender asked for it
    (`details`), so a plain status probe (also used for timing) stays as cheap as before."""
    root = str(Path(__file__).resolve().parent.parent.parent)        # p2p/ root, for `common`
    if root not in sys.path:
        sys.path.insert(0, root)
    from common import onboard
    return onboard.map_details()


def handle(sender_cn) -> dict:
    return {"ok": True, "requested_by": sender_cn, "active": True,
            "uptime_s": int(time.time() - STARTED_AT), "ts": int(time.time())}
