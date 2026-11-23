"""p2p/receiver-role/handlers/message — Stage A's message-delivery use case (a sensor
value/actuator state, per p2p-requirements.md's CoAP/HTTP use cases — HTTP now, CoAP in Stage D).

Kept intentionally dumb for Stage A: append-only local log, not a dispatch into any device-role
logic (device-role code — ML, MQTT — is explicitly untouched by this plan, §3.1).
"""
import hashlib
import json
import time
from pathlib import Path

LOG_FILE = Path("/var/lib/p2p/messages.log")


def handle(sender_cn, payload: dict, tech: str = None) -> dict:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    # `tech`/`envelope_verified` (monitor.md D17, 2026-08-21): the caller (server.py/
    # coap_server.py) already knows which tech carried this call and, by the time `handle()` runs,
    # has ALREADY verified it (mtls transport, or an envelope signature for every other tech) --
    # `envelope_verified` records WHICH kind of proof this was, not whether it passed (a call that
    # failed verification never reaches this handler at all). `None` when an older caller doesn't
    # pass `tech` yet, never guessed.
    envelope_verified = None if tech is None else (tech not in ("mtls", "pqc"))
    rec = {"from": sender_cn, "payload": payload, "ts": int(time.time()),
           "tech": tech, "envelope_verified": envelope_verified}
    with LOG_FILE.open("a") as f:
        f.write(json.dumps(rec) + "\n")

    # 2026-08-11: the reply used to be `"received": payload` -- it echoed the DECRYPTED payload
    # straight back. Proven on the wire: with `--tech coap-enc` the request is properly encrypted
    # (envelope carries `encrypted`, no `payload` key) and then this response carried the same
    # content in the clear on udp/5683, so anyone who could not read the request could read the
    # reply. Confidentiality was defeated for every echoed payload.
    #
    # A digest keeps what the echo was actually useful for -- the sender can still confirm exactly
    # what arrived -- without reproducing the content. This is the convention `deliver_file` already
    # uses (it returns the sha256 of what it stored as the delivery proof), so callers have a
    # familiar shape rather than a new one.
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return {"ok": True, "from": sender_cn,
            "sha256": hashlib.sha256(body).hexdigest(),
            "bytes": len(body)}
