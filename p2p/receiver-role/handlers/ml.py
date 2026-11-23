"""p2p/receiver-role/handlers/ml — the ML use case (management/fix.md 2026-07-29).

What it is. A SENDER node asks this node to perform one ML operation on itself — list its models,
deliver one, run it, read a file out of it, change its parameters, report whether a run is alive.
The four ML GUI subtabs (Delivery · Execution · Inference/DB-ML · Parameters) are exactly these
operations, so "the sender does it, the tenant admin only coordinates" reduces to: the Tenant-Admin
tells the sender WHICH operation and WHICH receiver, and the sender makes this call.

Why it is a use case and not a shortcut through `rm`. Running the ML surface through the generic
remote-management route would work — it is a shell — and would be a mistake: every ML click would
become an arbitrary command on a peer, gated by a kill switch meant for something else, and the
comm log would show `rm` where the operator asked to see ML. As its own use case it gets its own
row in the mirror, its own kill switch, and — the point — an ENUMERATED verb list instead of a
shell. `ML_METHODS` below is the entire attack surface.

How it reaches the ML implementation. The ML operations live in the device/gateway agent inside
this node's container (`device.py`'s `RPC_HANDLERS`); this process runs on the VM. It does not
reimplement them — reimplementation is how two paths drift, and a managed run is a process the
agent owns, not a fact on disk. It hands the call to the agent over a bind-mounted spool directory
and waits for the agent's own answer. `Device-PC/Device/p2p_ml_agent.py` is the other half and
documents the protocol.

Two node-local controls, neither reachable from the network (same shape as the `rm` use case's):

  P2P_ML_ENABLED   default on. `0` makes this node refuse peer-driven ML outright, whatever the
                   policy says, and say so — the sender learns "that node does not accept ML",
                   not "your call failed".
  P2P_ML_ALLOW     optional comma-separated narrowing of `ML_METHODS` (e.g. read-only:
                   `list_models,get_model,read_model_file,run_status`). Unset = all of them.

Every call is appended to `/var/lib/p2p/ml.log` BEFORE it is dispatched, so a `run_model` that
takes the node down still leaves the record of who asked for it — the same rule `rm` follows, for
the same reason.
"""
import json
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))   # p2p/ root, for `common`
from common.ml_limits import DEFAULT_TIMEOUT, MAX_TIMEOUT  # noqa: E402

SPOOL_DIR = Path(os.environ.get("P2P_ML_SPOOL", "/var/lib/p2p/ml-spool"))
LOG_FILE = Path("/var/lib/p2p/ml.log")

# The ML verbs a peer may ask for — the whole of them. Deliberately the subset of the agent's RPC
# handler table that the four ML subtabs actually drive: registry + delivery + run + parameters.
# `exec`/`put_file`/`cancel`/`set_policy` are NOT here on purpose — those are the remote-management
# surface, and they already have their own use case with its own gate.
ML_METHODS = (
    # Delivery subtab
    "list_models", "get_model", "read_model_file", "deliver_model",
    "deliver_model_chunk",     # inline delivery (2026-09-26): model bytes over THIS channel
    # Execution subtab
    "run_model", "start_run", "stop_run", "run_status",
    # Parameters subtab
    "set_params", "load_model",
    # Inference / DB-ML subtab
    "run_benchmark", "start_inference", "stop_inference",
    # FL subtab (2026-09-26)
    "train_step",
)

POLL = 0.1


def _enabled():
    return os.environ.get("P2P_ML_ENABLED", "1").strip().lower() not in ("0", "false", "no", "")


def _allowed_methods():
    raw = os.environ.get("P2P_ML_ALLOW", "").strip()
    if not raw:
        return set(ML_METHODS)
    return {m.strip() for m in raw.split(",") if m.strip()} & set(ML_METHODS)


def _audit(sender, method, rid, tech=None):
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        # `tech`/`envelope_verified` (monitor.md D17, 2026-08-21) — see message.py's own note.
        envelope_verified = None if tech is None else (tech not in ("mtls", "pqc"))
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": int(time.time() * 1000), "sender": sender,
                                "method": method, "id": rid, "tech": tech,
                                "envelope_verified": envelope_verified}) + "\n")
    except OSError:
        pass          # an unwritable audit file must not stop the node answering; it is a record,
                      # not a gate (the gate is the cert + the policy, already applied upstream)


def _refuse(reason, method=None):
    """A node-local refusal. `refused=True` is deliberately distinct from a policy denial (which is
    a 403 the sender sees as AuthorizationDenied) and from an operation that ran and failed."""
    return {"ok": False, "refused": True, "reason": reason, "method": method}


def handle(sender_cn, body, tech: str = None):
    """-> the agent's own RPC payload, wrapped. `ok` is the CALL's verdict, not the exchange's:
    an ML operation that ran and reported `status: not_found` is a delivered exchange carrying a
    negative answer, and flattening the two would make a policy denial and a missing model look
    identical in the comm log."""
    method = str((body or {}).get("method") or "").strip()
    params = (body or {}).get("params") or {}
    if not isinstance(params, dict):
        return _refuse("params must be a JSON object", method)
    if not _enabled():
        return _refuse("this node does not accept peer-driven ML (P2P_ML_ENABLED=0)", method)
    allowed = _allowed_methods()
    if method not in allowed:
        known = "unknown" if method not in ML_METHODS else "not on this node's P2P_ML_ALLOW list"
        return _refuse(f"ML method '{method}' is {known}", method)

    try:
        timeout = min(int((body or {}).get("timeout") or DEFAULT_TIMEOUT), MAX_TIMEOUT)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT

    rid = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
    _audit(sender_cn, method, rid, tech=tech)

    try:
        SPOOL_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return _refuse(f"ML spool {SPOOL_DIR} unavailable: {e}", method)

    req = SPOOL_DIR / f"{rid}.req.json"
    res = SPOOL_DIR / f"{rid}.res.json"
    tmp = req.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"id": rid, "sender": sender_cn, "method": method,
                               "params": params, "ts": int(time.time() * 1000)}), encoding="utf-8")
    try:
        os.chmod(tmp, 0o666)      # the agent runs in the container, possibly as another uid
    except OSError:
        pass
    tmp.replace(req)              # atomic: the agent never sees a half-written request

    deadline = time.time() + timeout
    t0 = time.time()
    while time.time() < deadline:
        if res.exists():
            try:
                answer = json.loads(res.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                res.unlink(missing_ok=True)
                return {"ok": False, "method": method, "reason": f"unreadable ML response: {e}"}
            res.unlink(missing_ok=True)
            out = {"ok": bool(answer.get("ok")), "method": method,
                   "ms": round((time.time() - t0) * 1000, 1)}
            if answer.get("ok"):
                out["result"] = answer.get("result")
            else:
                out["reason"] = answer.get("error") or "the ML agent reported no reason"
            return out
        time.sleep(POLL)

    # Nothing picked the request up (or it outran the budget). Withdraw it, so an agent that comes
    # back later does not execute an operation whose caller stopped listening minutes ago.
    still_queued = req.exists()
    req.unlink(missing_ok=True)
    if still_queued:
        return _refuse(
            f"no ML agent is servicing {SPOOL_DIR} on this node — the device/gateway container is "
            f"down, or was built without p2p_ml_agent.py", method)
    return {"ok": False, "method": method, "timed_out": True,
            "reason": f"the ML agent accepted '{method}' but did not answer within {timeout}s"}
