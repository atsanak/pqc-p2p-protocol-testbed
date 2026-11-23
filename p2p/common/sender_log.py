"""p2p/common/sender_log — the sender's OWN authoritative local record of every P2P exchange
attempt (monitor.md §12.7, D26).

WHY THIS FILE EXISTS
  The receiver already has one: every use case's handler appends to its own
  `/var/lib/p2p/{ml,rm,messages}.log` BEFORE dispatching the call, so a call that crashes the
  receiver mid-flight still leaves a record. The sender had no equivalent — its only reports are
  `comm_log.report()`'s MIRROR to the Server (explicitly "never a source of truth", best-effort,
  spooled-not-lost but still Server-shaped) and the cert cache. That inverts the property a
  monitor needs: on the sender, the on-box evidence was empty exactly when everything was
  working, and non-empty only when reporting itself was failing. See §12.7 for the live incident
  (Rpi51 sending to Rpi53) that found this.

  This module is that missing local record, same shape as the receiver's logs: one JSON line per
  event, append-only, written by the caller BEFORE the exchange is attempted (`record("attempt",
  ...)`) and again once it resolves (`record("result", ...)`), independent of whether the Server
  ever hears about it. `client.py` is the only caller.

NOT A GATE, NOT AN AUTHORITY OVER THE EXCHANGE ITSELF
  Same rule every audit log in this codebase follows (`receiver-role/handlers/ml.py`'s own
  docstring): an unwritable log must not stop or slow the exchange it is describing. `record()`
  never raises.
"""
import json
import os
import time
from pathlib import Path

LOG_FILE = Path(os.environ.get("P2P_SENT_LOG", "/var/lib/p2p/sent.log"))


def record(phase, exchange_id, receiver, use_case, tech, **extra):
    """Append one line: `phase` is `"attempt"` (written before any network I/O) or `"result"`
    (written once the exchange resolves, success or failure — `extra` then carries `ok`,
    `status_code`, `duration_ms`, `bytes`, `reason`). Never raises."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": int(time.time() * 1000), "phase": phase,
                                "id": exchange_id, "receiver": receiver, "use_case": use_case,
                                "tech": tech, **extra}, default=str) + "\n")
    except OSError:
        pass          # a record, not a gate -- an unwritable log must not stop the exchange
