"""p2p/receiver-role/handlers/rm — the DEVICE→DEVICE remote-management use case
(management/fix.md 2026-07-28: "a device X can do remote management to dev Y (in/cross-tenant based
on the policy) normally ... I want in sender/receiver pieces of code").

This is the handler management/P2P.md §5 listed as the one genuine gap: "no receiver-role handler
executes a command sent by another device". Two things already existed and are NOT this:

  * `/p2p-rm-exec` on the Server — the SERVER SSHes into a node. Server→device, and it needs the
    node's SSH account and the tenant's rm_ssh key.
  * `/status` — device→device, but a fixed question with a fixed answer. A query, not management.

What runs here is a command that ANOTHER DEVICE sent, executed by this node, with no SSH, no shared
key, and no Server in the data path. The Server is still asked "may this sender talk to me" exactly
as it is for every other use case (server.py::_authorized_or_403 runs before this handler is
reached), so in-tenant and cross-tenant RM are governed by the same P2P policy table as messages
and files — which is what "based on the policy" asks for.

THE TRUST STATEMENT, plainly: executing a peer's command is the strongest thing a receiver can do
for a sender, and it rides on exactly one barrier — the mTLS peer certificate, plus the per-pair
policy. That is deliberate (the fabric is any-to-any; the cert IS the boundary), but it means the
in-tenant default of ALLOW makes every device in a tenant able to run commands on every other one.
Three things are here because of that:

  P2P_RM_ENABLED    node-local kill switch. Default on ("normally", per the ask); set it to 0 in
                    /opt/p2p/.env to make a node refuse peer-driven RM outright, whatever the
                    policy says. A node that opts out says so in the refusal, so the sender learns
                    "that node does not accept RM", not "your command failed".
  P2P_RM_ALLOW      optional allow-list of command prefixes (comma-separated). Unset = anything the
                    policy admits. Set = a node that only answers, say, `systemctl status,journalctl`.
  /var/lib/p2p/rm.log   every command, its sender, its exit code — appended before the reply is
                    sent, so the audit trail survives a command that kills the node.

The reply carries the exit code and both streams; `ok` is the COMMAND's verdict (rc == 0), while
the exchange's own ok — the one the comm-log mirrors — stays true, because a command that ran and
returned 3 is a delivered exchange with a failing command, and conflating the two would make a
policy denial and a false `grep` look identical in the log.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))   # p2p/ root, for `common`
from common.rm_limits import DEFAULT_TIMEOUT, MAX_TIMEOUT  # noqa: E402

LOG_FILE = Path("/var/lib/p2p/rm.log")

MAX_OUTPUT = 64 * 1024      # per stream; the rest is dropped and flagged, never silently truncated


def _enabled():
    return os.environ.get("P2P_RM_ENABLED", "1").strip().lower() not in ("0", "false", "no", "")


def _allowed_prefixes():
    raw = os.environ.get("P2P_RM_ALLOW", "").strip()
    return [p.strip() for p in raw.split(",") if p.strip()] if raw else None


def _clip(b: bytes):
    """-> (text, was_clipped). Decoded leniently: a command's output is whatever it printed, and a
    stray non-UTF-8 byte must not turn a successful exchange into a 500."""
    clipped = len(b) > MAX_OUTPUT
    return b[:MAX_OUTPUT].decode("utf-8", "replace"), clipped


def _audit(rec):
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass          # an unwritable audit file must not deny a policy-admitted request silently


def handle(sender_cn, payload: dict, tech: str = None) -> dict:
    """Run `payload['cmd']` on this node on behalf of `sender_cn`.

    -> {ok, rc, stdout, stderr, ...}. A refusal (node opted out, command not on the allow-list,
    empty command) comes back as `ok=False` with `refused=True` and a reason — distinguishable from
    a command that ran and failed, which has an `rc` and no `refused`."""
    cmd = (payload or {}).get("cmd")
    started = time.time()
    # `tech`/`envelope_verified` (monitor.md D17, 2026-08-21) — see message.py's own note: the
    # caller has already verified this call by the time it reaches `handle()`; this just records
    # WHICH kind of proof (transport mtls vs a per-message envelope signature) carried it.
    envelope_verified = None if tech is None else (tech not in ("mtls", "pqc"))
    base = {"requested_by": sender_cn, "node": os.environ.get("P2P_NODE_NAME"), "ts": int(started),
           "tech": tech, "envelope_verified": envelope_verified}

    if not cmd or not isinstance(cmd, str) or not cmd.strip():
        return {**base, "ok": False, "refused": True, "reason": "no command given"}
    if not _enabled():
        rec = {**base, "cmd": cmd, "refused": "P2P_RM_ENABLED=0"}
        _audit(rec)
        return {**base, "ok": False, "refused": True,
                "reason": f"{base['node']} does not accept peer-driven remote management "
                          f"(P2P_RM_ENABLED=0)"}
    prefixes = _allowed_prefixes()
    if prefixes is not None and not any(cmd.strip().startswith(p) for p in prefixes):
        rec = {**base, "cmd": cmd, "refused": "not on P2P_RM_ALLOW"}
        _audit(rec)
        return {**base, "ok": False, "refused": True,
                "reason": f"command is not on {base['node']}'s P2P_RM_ALLOW list ({', '.join(prefixes)})"}

    try:
        timeout = min(int((payload or {}).get("timeout") or DEFAULT_TIMEOUT), MAX_TIMEOUT)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT

    # Audit BEFORE running: if the command takes the node down (`reboot`, `systemctl stop`), the
    # line that says who asked for it is already on disk.
    _audit({**base, "cmd": cmd, "timeout": timeout})

    try:
        p = subprocess.run(["/bin/sh", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout)
        rc, out, err = p.returncode, p.stdout, p.stderr
        timed_out = False
    except subprocess.TimeoutExpired as e:
        rc, out, err, timed_out = None, e.stdout or b"", e.stderr or b"", True

    stdout, out_clipped = _clip(out)
    stderr, err_clipped = _clip(err)
    duration_ms = round((time.time() - started) * 1000, 2)
    _audit({**base, "cmd": cmd, "rc": rc, "timed_out": timed_out, "duration_ms": duration_ms})
    return {**base, "ok": (rc == 0), "refused": False, "cmd": cmd, "rc": rc,
            "stdout": stdout, "stderr": stderr, "timed_out": timed_out,
            "truncated": out_clipped or err_clipped, "duration_ms": duration_ms,
            "reason": (f"timed out after {timeout}s" if timed_out else None)}
