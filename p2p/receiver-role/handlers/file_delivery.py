"""p2p/receiver-role/handlers/file_delivery — Stage A's file-delivery use case.

p2p-requirements.md's "Test it with delivery of file, packets or something similar to verify that
is working." Writes the delivered bytes under a receiver-local drop directory, keyed by the
CLAIMED dest path but confined to that directory (no `..` escape) — the sender picks a name, not a
filesystem location outside the drop area.

2026-09-26 — PUT_FILE mode (command & control, plaintext + classical columns): when the sender
attaches `put` meta ({job_id, sha256, size?, mode?}) the same bytes land in a per-job folder instead
of the flat drop dir, with the same contract as rm_agent.put_file on the ThingsBoard path — sha256
MANDATORY and checked before anything is written, size checked if given, file mode applied,
idempotent by sha256+path (a matching file already there is `cached`, not rewritten). The ack uses
rm_agent's status words (delivered / checksum_mismatch / size_mismatch / error) so a caller reads
one shape whichever path carried the file. A follow-up P2P `rm` exec runs it by the returned `path`.
It rides the existing `file` use case on purpose: every tech already carries a file's bytes (inline
in the signed envelope, block-wise on CoAP), so put_file needs no route of its own.
"""
import hashlib
import os
import re
from pathlib import Path

DROP_DIR = Path("/var/lib/p2p/received")
JOBS_DIR = Path(os.environ.get("P2P_JOBS_DIR", "/var/lib/p2p/jobs"))
_JOB_ID_OK = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def put_file(sender_cn, dest_path, data: bytes, put: dict) -> dict:
    job_id = str(put.get("job_id") or "").strip()
    want = str(put.get("sha256") or "").strip()
    base = {"from": sender_cn, "job_id": job_id, "bytes": len(data)}
    if not _JOB_ID_OK.match(job_id) or job_id in (".", ".."):
        return {**base, "ok": False, "status": "error", "reason": f"invalid job_id {job_id!r}"}
    if not want:
        return {**base, "ok": False, "status": "error", "reason": "sha256 is required"}
    want = want if want.startswith("sha256:") else "sha256:" + want
    safe_name = Path(dest_path).name
    if not safe_name or safe_name in (".", ".."):
        return {**base, "ok": False, "status": "error", "reason": "empty or invalid destination filename"}
    out = JOBS_DIR / job_id / safe_name
    got = _sha(data)
    if got != want:
        detail = f"expected={want} got={got}"
        return {**base, "ok": False, "status": "checksum_mismatch", "path": str(out),
                "detail": detail, "reason": f"checksum_mismatch: {detail}"}
    size = put.get("size")
    if size is not None and len(data) != int(size):
        detail = f"expected={size} got={len(data)}"
        return {**base, "ok": False, "status": "size_mismatch", "path": str(out),
                "detail": detail, "reason": f"size_mismatch: {detail}"}
    mode = put.get("mode")
    if out.is_file() and _sha(out.read_bytes()) == want:
        return {**base, "ok": True, "status": "delivered", "cached": True, "path": str(out),
                "sha256": want}
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{safe_name}.part")
    tmp.write_bytes(data)
    if mode is not None:
        os.chmod(tmp, int(mode, 8) if isinstance(mode, str) else int(mode))
    os.replace(tmp, out)
    return {**base, "ok": True, "status": "delivered", "cached": False, "path": str(out),
            "sha256": want}


def handle(sender_cn, dest_path, data: bytes, put: dict = None) -> dict:
    if put:
        return put_file(sender_cn, dest_path, data, put)
    DROP_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(dest_path).name  # basename only — confines writes to DROP_DIR, no path escape
    if not safe_name or safe_name in (".", ".."):
        raise ValueError("empty or invalid destination filename")
    out = DROP_DIR / safe_name
    out.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    return {"ok": True, "from": sender_cn, "written_to": str(out),
            "bytes": len(data), "sha256": digest}
