"""p2p/receiver-role/handlers/events — the tail-able event spool behind `on_p2p` (on-dev-api P9.7).

What it is. One JSON line per SUCCESSFUL incoming P2P call of the four hookable use cases
(`message`, `deliver`, `ml`, `status`), appended to a local file that a script on the box tails
(`DeviceAPI.on_p2p` / `GatewayAPI.on_p2p`, API/on_dev_hooks.py).

Why it is safe to hand to node code. `emit()` is called by server.py / coap_server.py only AFTER
the sender's certificate/signature was verified and the Server's per-pair policy allowed the call
(`_identify` + `_authorized_or_403`) and after the use case itself ran. A refused or failed call
never reaches it. There is no new port: the consumer reads a file, exactly as it already may read
`messages.log`.

What an event carries — the same summary the receiver already mirrors to the Server's comm log
(never a file's bytes, never an ML result): message -> the payload; deliver -> dest filename +
sha256 + byte count; ml -> the method and whether it worked; status -> the status answer.

Bounded and never fatal: the file rotates to `.1` past MAX_BYTES, a payload is capped, and any
error here is swallowed — a hook feed must never turn a delivered message into a 500.

  P2P_EVENTS_ENABLED  default on; `0` writes nothing.
  P2P_EVENTS_FILE     default /var/lib/p2p/events/p2p-events.jsonl
"""
import json
import os
import threading
import time
from pathlib import Path

EVENTS_FILE = Path(os.environ.get("P2P_EVENTS_FILE", "/var/lib/p2p/events/p2p-events.jsonl"))
MAX_BYTES = 1_000_000
MAX_PAYLOAD_JSON = 8192
HOOKED = ("message", "deliver", "ml", "status")
_ALIAS = {"file": "deliver"}          # the receiver calls the deliver use case "file" internally
_lock = threading.Lock()


def enabled() -> bool:
    return os.environ.get("P2P_EVENTS_ENABLED", "1").strip() not in ("0", "false", "no", "off")


def build(use_case, sender, tech, payload, nbytes=None):
    """-> the event dict, or None if this use case is not hookable."""
    uc = _ALIAS.get(use_case, use_case)
    if uc not in HOOKED:
        return None
    body = payload if isinstance(payload, dict) else {"value": payload}
    try:
        if len(json.dumps(body, default=str)) > MAX_PAYLOAD_JSON:
            body = {"truncated": True, "keys": sorted(body)[:50]}
    except (TypeError, ValueError):
        body = {"unserializable": True}
    evt = {"use_case": uc, "sender": sender, "tech": tech, "ts": int(time.time() * 1000),
           "bytes": nbytes, "payload": body}
    if uc == "deliver":
        evt["dest"] = body.get("dest_filename")
        evt["sha256"] = body.get("sha256")
    return evt


def emit(use_case, sender, tech, payload, nbytes=None) -> bool:
    """Append one event. -> True if written. Never raises."""
    try:
        if not enabled():
            return False
        evt = build(use_case, sender, tech, payload, nbytes)
        if evt is None:
            return False
        line = json.dumps(evt, default=str) + "\n"
        with _lock:
            EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
            try:
                if EVENTS_FILE.stat().st_size > MAX_BYTES:
                    os.replace(EVENTS_FILE, str(EVENTS_FILE) + ".1")
            except OSError:
                pass
            with EVENTS_FILE.open("a", encoding="utf-8") as f:
                f.write(line)
            try:
                os.chmod(EVENTS_FILE, 0o644)
            except OSError:
                pass
        return True
    except Exception:                                           # noqa: BLE001 — a feed, never fatal
        return False
