"""p2p/common/wire — the on-the-wire envelope for the P2P peer protocol.

HTTP/1.1 + REST over TLS 1.3 (p2p-plan..md §3.2), plain stdlib — no framework. Two request shapes,
picked by the `X-P2P-Type` header:

  file     POST /deliver    X-P2P-Type: file     X-P2P-Filename: <name>   X-P2P-Dest-Path: <path>
                             body = raw bytes (Content-Length-framed)
  message  POST /message    X-P2P-Type: message   Content-Type: application/json
                             body = JSON {"topic": "...", "value": ...}

Every response is JSON: {"ok": bool, ...}. `X-P2P-Sender` on the request is informational only —
the RECEIVER never trusts it for identity (§4.3): the TLS peer cert's CN is the only identity that
counts. It's included so a plaintext-identity run (before Stage B mTLS is turned on for a given
node) still carries an explicit claimed sender, clearly logged as a claim rather than a proof.
"""
import json


def write_json(handler, status, obj):
    body = json.dumps(obj).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    return handler.rfile.read(length) if length else b""


def read_json_body(handler):
    raw = read_body(handler)
    return json.loads(raw) if raw else {}
