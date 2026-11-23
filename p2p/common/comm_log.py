"""p2p/common/comm_log — best-effort telemetry MIRROR (operator-directed 2026-07-26): the sender
AND the receiver of every P2P exchange each report their OWN record of it to the Server, which
appends it to a durable log and relays it into ThingsBoard as read-only telemetry.

This is a MIRROR for dashboard visibility ONLY — never a source of truth (the operator was
explicit about this). Policy/authorization decisions (p2p_policy.json) and each node's own
/var/lib/p2p/*.log stay authoritative. Reporting a record is fire-and-forget: a Server/TB hiccup
must never break, block, or even meaningfully slow the actual P2P exchange it's describing.

2026-08-08, unreachable-Server degrade: a record that can't be delivered live is spooled to disk
(bounded, swept — same shape as p2p_ml_agent.py's request/response spool) instead of being lost
outright. The spool is only ever drained right after a LIVE report just succeeded (i.e. the
Server is known reachable at that moment) — never on the failure path itself, so a down Server
never costs a P2P exchange a second timeout on top of the one it already tolerates.
"""
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from . import identity

SPOOL_DIR = Path(os.environ.get("P2P_COMM_LOG_SPOOL", "/var/lib/p2p/comm-log-spool"))
MAX_SPOOL_AGE_S = 86400       # drop-oldest past 24h, matches p2p_ml_agent.py's MAX_RESPONSE_AGE order of magnitude
MAX_SPOOL_FILES = 2000        # hard cap regardless of age, so a long outage can't fill the disk
MAX_FLUSH_PER_CALL = 50       # bound how long one report() call's post-success flush can take


def _spool(fields):
    try:
        SPOOL_DIR.mkdir(parents=True, exist_ok=True)
        path = SPOOL_DIR / f"{fields.get('ts', int(time.time()))}-{uuid.uuid4().hex}.json"
        path.write_text(json.dumps(fields, default=str), encoding="utf-8")
        _evict_excess()
    except OSError:
        pass   # the spool itself is best-effort too -- a full/unwritable disk must not raise


def _evict_excess():
    files = sorted(SPOOL_DIR.glob("*.json"))
    now = time.time()
    for f in files:
        try:
            if now - f.stat().st_mtime > MAX_SPOOL_AGE_S:
                f.unlink(missing_ok=True)
        except OSError:
            pass
    files = sorted(SPOOL_DIR.glob("*.json"))
    for f in files[:-MAX_SPOOL_FILES] if len(files) > MAX_SPOOL_FILES else []:
        try:
            f.unlink(missing_ok=True)
        except OSError:
            pass


def _flush_spool(server_api, secret):
    """Only called right after a live report just succeeded -- the Server is known reachable."""
    _evict_excess()   # age out records the Server never took (an idle device spools nothing new, so nothing else would)
    try:
        files = sorted(SPOOL_DIR.glob("*.json"))
    except OSError:
        return
    for f in files[:MAX_FLUSH_PER_CALL]:
        try:
            fields = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            f.unlink(missing_ok=True)
            continue
        if _send(server_api, secret, fields):
            f.unlink(missing_ok=True)
        else:
            break   # Server went unreachable again mid-flush -- stop, don't keep timing out


# HTTP statuses that mean "this record itself is unacceptable, retrying can never help" (schema 400/422, too large 413). Found LIVE
# 2026-10-10 on T-pash: a spooled record with a string payload got 422 for 15 days, and because every error counted as "Server
# unreachable" it sat at the head of the spool forever (flush stops at the first failure), blocking everything queued behind it.
_PERMANENT_REJECT = (400, 413, 422)


def _normalize(fields):
    """The Server's model wants `payload` to be a dict. Callers (and old spooled records) sometimes hand a string/None."""
    p = fields.get("payload")
    if p is None:
        fields["payload"] = {}
    elif not isinstance(p, dict):
        fields["payload"] = {"text": p if isinstance(p, (str, int, float, bool)) else str(p)}
    return fields


def _send(server_api, secret, fields):
    """-> True when there is nothing left to retry: delivered (2xx) OR permanently rejected by the Server (400/413/422 -- the record
    is dropped, not retried forever). False when the Server could not be reached or failed transiently (network, 5xx, 401/403/404/429)."""
    fields = _normalize(dict(fields))
    body = json.dumps(fields, default=str).encode()
    headers = {"Content-Type": "application/json", "X-Bootstrap-Secret": secret}
    try:
        headers.update(identity.node_identity_headers(fields["node"]))
    except Exception:                                     # noqa: BLE001
        pass
    req = urllib.request.Request(
        f"{server_api}/p2p-comm-log", data=body, headers=headers, method="POST")
    try:
        urllib.request.urlopen(req, timeout=5).close()
        return True
    except urllib.error.HTTPError as e:
        return e.code in _PERMANENT_REJECT
    except (urllib.error.URLError, OSError, ValueError):
        return False


def report(server_api, secret, **fields):
    fields.setdefault("ts", int(time.time()))
    if _send(server_api, secret, fields):
        _flush_spool(server_api, secret)
    else:
        _spool(fields)   # best-effort mirror -- never break the P2P call it's describing
