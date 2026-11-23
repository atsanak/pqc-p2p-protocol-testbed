#!/usr/bin/env python3
"""comm_log spool: a record the Server permanently rejects (422) must not wedge the spool; transient failures keep the record.
OFFLINE: a local HTTP server stands in for the Server. Run: python3 p2p/tests/test_comm_log_spool.py  (exit 1 on any FAIL)"""
import json, os, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

TMP = tempfile.mkdtemp(); os.environ["P2P_COMM_LOG_SPOOL"] = str(Path(TMP) / "spool")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # p2p/ so `common` imports as on the devices
from common import comm_log                                      # noqa: E402

MODE = {"status": 200}; GOT = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
        st = MODE["status"]
        if st == 200 and (not isinstance(body.get("payload"), dict) or body.get("bad")): st = 422   # the real model: payload: dict; "bad" = any other schema reject
        if st == 200: GOT.append(body)
        self.send_response(st); self.end_headers(); self.wfile.write(b"{}")
srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
API = f"http://127.0.0.1:{srv.server_port}"
FAIL = 0
def ok(name, cond):
    global FAIL; print(("PASS " if cond else "FAIL ") + name); FAIL += 0 if cond else 1
def rec(i, **kw): return dict({"node": "n", "sender": "n", "receiver": "m", "reported_by": "sender", "ts": int(time.time()) + i, "payload": {"i": i}}, **kw)
def spool_files(): return sorted(comm_log.SPOOL_DIR.glob("*.json"))
def reset():
    GOT.clear()
    for f in spool_files(): f.unlink()

# 1 a permanently rejected record at the head of the spool does not wedge it
reset(); MODE["status"] = 500
comm_log.report(API, "s", **rec(0, bad=True))                       # spooled while the Server is down; the Server will 422 it forever
comm_log.report(API, "s", **rec(1))                                 # good record queued behind it
ok("both spooled while the Server is down", len(spool_files()) == 2)
MODE["status"] = 200
comm_log.report(API, "s", **rec(2))                                 # live success -> flush
ok("good record behind the poison one is delivered", any(g.get("payload") == {"i": 1} for g in GOT))
ok("poison record dropped, spool empty", len(spool_files()) == 0)

# 2 string/None payloads are normalised, not rejected
reset(); MODE["status"] = 200
comm_log.report(API, "s", **rec(3, payload="hello"))
ok("string payload delivered as {'text': ...}", GOT and GOT[-1]["payload"] == {"text": "hello"})
reset(); comm_log.report(API, "s", **rec(4, payload=None))
ok("None payload delivered as {}", GOT and GOT[-1]["payload"] == {})

# 3 a permanent 422 is dropped (not spooled) on the live path
reset(); MODE["status"] = 422
comm_log.report(API, "s", **rec(5))
ok("live 422 is dropped, not spooled", len(spool_files()) == 0)

# 4 transient failures keep the record
for st in (500, 503, 401, 403):
    reset(); MODE["status"] = st
    comm_log.report(API, "s", **rec(6))
    ok(f"HTTP {st} keeps the record spooled", len(spool_files()) == 1)
reset(); comm_log.report("http://127.0.0.1:1", "s", **rec(7))
ok("unreachable Server keeps the record spooled", len(spool_files()) == 1)

# 5 transient failure mid-flush stops the flush (no hammering), later records stay in order
reset(); MODE["status"] = 500
comm_log.report(API, "s", **rec(8)); comm_log.report(API, "s", **rec(9))
MODE["status"] = 200
comm_log.report(API, "s", **rec(10))
ok("recovered Server drains the whole backlog", len(spool_files()) == 0 and sorted(g["payload"]["i"] for g in GOT) == [8, 9, 10])
ok("backlog delivered oldest first", [g["payload"]["i"] for g in GOT if g["payload"]["i"] in (8, 9)] == [8, 9])

# 6 an aged-out record is evicted at flush even though nothing new was spooled
reset(); MODE["status"] = 500
comm_log.report(API, "s", **rec(11)); old = spool_files()[0]
t = time.time() - comm_log.MAX_SPOOL_AGE_S - 60; os.utime(old, (t, t))
MODE["status"] = 500; comm_log.report(API, "s", **rec(12))       # spools one more (evicts the old one on spool)
reset(); MODE["status"] = 500; comm_log.report(API, "s", **rec(13)); old = spool_files()[0]; os.utime(old, (t, t))
MODE["status"] = 200; comm_log.report(API, "s", **rec(14))        # live success; the aged file must be gone after the flush
ok("aged-out record evicted at flush", len(spool_files()) == 0 and not any(g["payload"].get("i") == 13 for g in GOT))
print("FAILS:", FAIL); sys.exit(1 if FAIL else 0)
