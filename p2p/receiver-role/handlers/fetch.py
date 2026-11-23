"""p2p/receiver-role/handlers/fetch — the PULL use case (on-dev-api P4.1, 2026-09-29).

Every other use case moves data TOWARD the receiver (`file` writes, `message` appends) or asks it a
fixed question (`status`). This one lets a peer READ one file back off this node: the sender names
a path, the receiver answers with the bytes (base64) and their sha256. It is a use case, not an
`rm` call running `cat`, for the same reason `ml` is: a read-only, enumerated operation deserves a
narrower door than a shell — `P2P_RM_ENABLED=0` on a node must not also mean "nobody may read the
result file my job produced", and a node that allows fetch must not thereby allow commands.

Gates, in order (a refusal says which one fired, like rm/ml):

  identity + policy   server.py/coap_server.py, BEFORE this handler — the SAME per-pair check every
                      use case passes. There is no per-use-case policy; a pair that may `message`
                      may also `fetch`, which is exactly as true of `rm` today.
  P2P_FETCH_ENABLED   node-local kill switch, default on. 0 = refuse every fetch, with a reason.
  P2P_FETCH_ROOTS     comma-separated directories a peer may read under. Default:
                      /var/lib/p2p/share (a dedicated outbox), /var/lib/p2p/received and
                      /var/lib/p2p/jobs (what peers already pushed here), /home/rmssh (the RM
                      account's home — the P4 plan's "readable paths" default). Resolved with
                      realpath BEFORE the containment check, so `..` and symlinks that point out of
                      a root are refused, not followed.
  hidden components   any path component starting with "." is refused (`.ssh/`, `.env`, a
                      `.part` upload) — a root such as a home dir must not leak its dotfiles.
  P2P_FETCH_MAX_BYTES default 8 MiB. The bytes ride base64 INSIDE the JSON reply (and, on CoAP,
                      block-wise), so a very large file belongs on a different path; refused with
                      the size rather than truncated.

Every request is appended to /var/lib/p2p/fetch.log BEFORE the file is read (who asked, for what,
and the verdict), same audit posture as rm.log/ml.log.
"""
import base64
import hashlib
import json
import os
import time
from pathlib import Path

LOG_FILE = Path("/var/lib/p2p/fetch.log")
DEFAULT_ROOTS = ("/var/lib/p2p/share", "/var/lib/p2p/received", "/var/lib/p2p/jobs", "/home/rmssh",
                 "/opt/testbed-device/role-live")
DEFAULT_MAX_BYTES = 8 * 1024 * 1024


def _enabled():
    return os.environ.get("P2P_FETCH_ENABLED", "1").strip().lower() not in ("0", "false", "no", "")


def _roots():
    raw = os.environ.get("P2P_FETCH_ROOTS", "").strip()
    roots = [p.strip() for p in raw.split(",") if p.strip()] if raw else list(DEFAULT_ROOTS)
    return [os.path.realpath(r) for r in roots]


def _max_bytes():
    try:
        return int(os.environ.get("P2P_FETCH_MAX_BYTES") or DEFAULT_MAX_BYTES)
    except ValueError:
        return DEFAULT_MAX_BYTES


def _audit(rec):
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass          # an unwritable audit file must not deny a policy-admitted request silently


def gate(path):
    """Would this node serve `path` to a policy-admitted peer? -> (real_path | None, reason | None).
    Pure: reads the environment and stats the file, reads no content. Shared by handle() and by
    P2PAPI.fetch_gate() so the local answer and the live one cannot drift."""
    if not _enabled():
        node = os.environ.get("P2P_NODE_NAME")
        return None, f"{node} does not serve peer file fetches (P2P_FETCH_ENABLED=0)"
    if not path or not isinstance(path, str) or not path.startswith("/"):
        return None, "remote_path must be an absolute path"
    if any(part.startswith(".") for part in Path(path).parts[1:]):
        return None, "hidden path components ('.x', '..') are not served"
    real = os.path.realpath(path)
    roots = _roots()
    if not any(real == r or real.startswith(r.rstrip("/") + "/") for r in roots):
        return None, f"{path} is not under a readable root ({', '.join(roots)}; P2P_FETCH_ROOTS)"
    if any(part.startswith(".") for part in Path(real).parts[1:]):
        return None, "hidden path components ('.x', '..') are not served"
    if not os.path.isfile(real):
        return None, f"no such file: {path}"
    size = os.path.getsize(real)
    if size > _max_bytes():
        return None, f"{path} is {size} bytes, over P2P_FETCH_MAX_BYTES={_max_bytes()}"
    return real, None


def handle(sender_cn, payload: dict, tech: str = None) -> dict:
    """Read `payload['path']` for `sender_cn`. -> {ok, path, bytes, sha256, data_b64, ...}, or
    {ok: False, refused: True, reason} when a node-local gate says no (distinct from a policy
    denial, which never reaches here)."""
    path = (payload or {}).get("path")
    base = {"requested_by": sender_cn, "node": os.environ.get("P2P_NODE_NAME"),
            "ts": int(time.time()), "tech": tech,
            "envelope_verified": None if tech is None else (tech not in ("mtls", "pqc"))}
    real, reason = gate(path)
    if real is None:
        _audit({**base, "path": path, "refused": reason})
        return {**base, "ok": False, "refused": True, "path": path, "reason": reason}
    _audit({**base, "path": path, "real_path": real})
    data = Path(real).read_bytes()
    return {**base, "ok": True, "refused": False, "path": path, "bytes": len(data),
            "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            "data_b64": base64.b64encode(data).decode()}
