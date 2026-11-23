#!/usr/bin/env python3
"""Loopback test of the eight P2P techs added 2026-10-02, against the REAL listeners.

  hybrid / hybrid-mutual                  stunnel + the private OpenSSL 3.4 (PQC-bench/p2p-proxy sections)
  quic-hybrid / quic-hybrid-mutual        quic_pqc_relay.py, QUIC_CERT_MODE=classical
  quic-classical / quic-classical-mutual  quic_pqc_relay.py, QUIC_GROUPS=X25519
  coap-dtls / coap-dtls-mutual            coap_dtls_pqc_relay.py (needs wolfSSL + aiocoap; skipped, and
                                          SAID to be skipped, when this box cannot run it)

The sender side is the real `p2p/sender-role/client.py` (`Client._connect` -> the connection classes ->
the aioquic helper / openssl s_client), pointed at a throwaway PKI (root -> intermediate -> leaf, the same
shape as the fleet's, with SAN IP 127.0.0.1) and a trivial HTTP backend standing in for server.py. Nothing
here talks to a Server, a real fleet identity or the network.

Each tech gets a positive exchange plus the negatives that make it mean what its name says: wrong CA,
wrong name, no client certificate on a mutual port, and -- the one that proves a tier is a tier -- a client
offering the OTHER key-exchange group is refused on the hybrid / classical-only ports.

Run:  python3 p2p/tests/test_new_techs_local.py        (exit 0 = all pass; skips are listed)
Needs: /opt/pqc-libs/{openssl-priv,liboqs-priv,quic-pqc-venv}, /opt/PQC-bench/{ca,oqs-openssl-priv.cnf}, stunnel.
"""
import http.server
import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "p2p"))

PRIV_LIB = "/opt/pqc-libs/liboqs-priv/lib:/opt/pqc-libs/openssl-priv/lib64"
PRIV_OPENSSL = "/opt/pqc-libs/openssl-priv/bin/openssl"
QUIC_PY = "/opt/pqc-libs/quic-pqc-venv/bin/python3"
OQS_CNF = "/opt/PQC-bench/oqs-openssl-priv.cnf"

results = []          # (status, name)
procs = []


def check(ok, name, detail=""):
    results.append(("PASS" if ok else "FAIL", name))
    print(("PASS " if ok else "FAIL ") + name + (f"   [{detail}]" if detail and not ok else ""), flush=True)


def skip(name, why):
    results.append(("SKIP", name))
    print(f"SKIP {name}   [{why}]", flush=True)


def free_port(udp=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, udp=False, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if udp:
            return True               # UDP has no listen state to probe; the caller retries on use
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def sh(*a, **k):
    return subprocess.run(a, check=True, capture_output=True, text=True, **k)


# ── throwaway PKI: root -> intermediate -> leaf, SAN IP 127.0.0.1 (the fleet's shape) ─────────────────
def make_pki(root: Path):
    root.mkdir(parents=True, exist_ok=True)

    def key(name):
        sh("openssl", "genrsa", "-out", str(root / f"{name}.key"), "2048")

    def ca(name, cn, issuer=None, pathlen=None):
        key(name)
        ext = root / f"{name}.ext"
        ext.write_text("basicConstraints=critical,CA:TRUE" + (f",pathlen:{pathlen}" if pathlen is not None else "")
                       + "\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
        sh("openssl", "req", "-new", "-key", str(root / f"{name}.key"), "-subj", f"/CN={cn}",
           "-out", str(root / f"{name}.csr"))
        if issuer is None:
            sh("openssl", "x509", "-req", "-in", str(root / f"{name}.csr"), "-signkey", str(root / f"{name}.key"),
               "-days", "30", "-extfile", str(ext), "-out", str(root / f"{name}.crt"))
        else:
            sh("openssl", "x509", "-req", "-in", str(root / f"{name}.csr"), "-CA", str(root / f"{issuer}.crt"),
               "-CAkey", str(root / f"{issuer}.key"), "-CAcreateserial", "-days", "30", "-extfile", str(ext),
               "-out", str(root / f"{name}.crt"))

    def leaf(name, cn, issuer):
        key(name)
        ext = root / f"{name}.ext"
        ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=serverAuth,clientAuth\n"
                       f"subjectAltName=IP:127.0.0.1,DNS:{cn}\n")      # fleet certs: IP SANs + DNS:<node name>
        sh("openssl", "req", "-new", "-key", str(root / f"{name}.key"), "-subj", f"/CN={cn}",
           "-out", str(root / f"{name}.csr"))
        sh("openssl", "x509", "-req", "-in", str(root / f"{name}.csr"), "-CA", str(root / f"{issuer}.crt"),
           "-CAkey", str(root / f"{issuer}.key"), "-CAcreateserial", "-days", "30", "-extfile", str(ext),
           "-out", str(root / f"{name}.crt"))

    for tag in ("good", "evil"):                 # `evil` = an unrelated PKI, for the wrong-CA negatives
        ca(f"{tag}-root", f"{tag}-root")
        ca(f"{tag}-int", f"{tag}-int", issuer=f"{tag}-root", pathlen=0)
        leaf(f"{tag}-recv", "recv", f"{tag}-int")
        leaf(f"{tag}-sndr", "sndr", f"{tag}-int")
    # the layout the fleet uses: peer.crt = leaf + intermediate, ca.crt = root
    for who in ("recv", "sndr"):
        d = root / who
        d.mkdir(exist_ok=True)
        (d / "peer.crt").write_text((root / f"good-{who}.crt").read_text() + (root / "good-int.crt").read_text())
        shutil.copy(root / f"good-{who}.key", d / "peer.key")
        shutil.copy(root / "good-root.crt", d / "ca.crt")
    (root / "evil-ca.crt").write_text((root / "evil-root.crt").read_text())
    # an evil-signed server, to stand in front of the sender (wrong-CA negative)
    d = root / "evilrecv"
    d.mkdir(exist_ok=True)
    (d / "peer.crt").write_text((root / "evil-recv.crt").read_text() + (root / "evil-int.crt").read_text())
    shutil.copy(root / "evil-recv.key", d / "peer.key")
    shutil.copy(root / "evil-root.crt", d / "ca.crt")


# ── backend standing in for p2p server.py's plain listener ───────────────────────────────────────────
class Backend(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        out = json.dumps({"ok": True, "path": self.path, "n": len(body),
                          "tech": self.headers.get("X-P2P-Tech")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = _reply


def start_backend():
    port = free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


# ── the sender: the real client.py with no Server behind it ─────────────────────────────────────────
def load_client():
    spec = importlib.util.spec_from_file_location("p2p_client", REPO / "p2p/sender-role/client.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_sender(mod, pki, ports, ca="good"):
    cl = mod.Client.__new__(mod.Client)
    cl.name, cl.server_api, cl.secret = "sndr", "http://unused", "x"
    cl._cert_path = str(pki / "sndr" / "peer.crt")
    cl._key_path = str(pki / "sndr" / "peer.key")
    cl._ca_path = str(pki / ("evil-ca.crt" if ca == "evil" else "sndr/ca.crt"))
    for k, v in ports.items():
        setattr(cl, k, v)
    return cl


def attempt(mod, cl, tech, name="recv"):
    """Run ONE exchange the way _http_exchange does (connect, request, read). -> (status|None, error-text)."""
    mod.identity.resolve = lambda *a, **k: {"ip": "127.0.0.1"}
    try:
        conn, _res, _tls = cl._connect(name, tech, 25, timing=mod._Timing(tech))
        conn.request("POST", "/message", body=b'{"hello":"world"}', headers={"X-P2P-Tech": tech})
        r = conn.getresponse()
        body = json.loads(r.read() or b"{}")
        return r.status, body
    except Exception as e:                                           # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def sh_env(extra=None):
    e = dict(os.environ)
    e["LD_LIBRARY_PATH"] = PRIV_LIB
    e["OPENSSL_CONF"] = OQS_CNF
    e.update(extra or {})
    return e


def spawn(argv, env=None, log=None):
    p = subprocess.Popen(argv, env=env or os.environ, stdout=log or subprocess.DEVNULL, stderr=subprocess.STDOUT,
                         start_new_session=True)
    procs.append(p)
    return p


def cleanup():
    for p in procs:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass


def main():
    missing = [p for p in (PRIV_OPENSSL, QUIC_PY, OQS_CNF) if not os.path.exists(p)] + \
              ([] if shutil.which("stunnel") else ["stunnel"])
    if missing:
        print("cannot run here, missing:", missing)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="p2p-newtechs-"))
    pki = tmp / "pki"
    make_pki(pki)
    backend, bport = start_backend()
    mod = load_client()
    ports = dict(hybrid_port=free_port(), hybrid_mutual_port=free_port(),
                 quic_hybrid_port=free_port(True), quic_hybrid_mutual_port=free_port(True),
                 quic_classical_port=free_port(True), quic_classical_mutual_port=free_port(True),
                 coap_dtls_port=free_port(True), coap_dtls_mutual_port=free_port(True))
    cl = make_sender(mod, pki, ports)
    cl_evil = make_sender(mod, pki, ports, ca="evil")

    # ── hybrid: the REAL repo stunnel sections, ports rewritten, cert dir pointed at the test PKI ────
    conf_src = (REPO / "PQC-bench/p2p-proxy/p2p-pqc-proxy.conf").read_text()
    sections = {}
    cur = None
    for line in conf_src.splitlines():
        if line.startswith("[") and line.rstrip().endswith("]"):
            cur = line.strip()[1:-1]
            sections[cur] = []
        elif cur:
            sections[cur].append(line)
    check("p2p-hybrid" in sections and "p2p-hybrid-mutual" in sections,
          "p2p-pqc-proxy.conf defines the [p2p-hybrid] and [p2p-hybrid-mutual] sections")
    conf = [f"pid = {tmp}/stunnel.pid", "foreground = yes", "sslVersion = TLSv1.3", "stack = 4194304", ""]
    for sec, port in (("p2p-hybrid", ports["hybrid_port"]), ("p2p-hybrid-mutual", ports["hybrid_mutual_port"])):
        conf.append(f"[{sec}]")
        for line in sections[sec]:
            if line.startswith(("accept", "connect")):
                line = (f"accept = 127.0.0.1:{port}" if line.startswith("accept")
                        else f"connect = 127.0.0.1:{bport}")
            line = (line.replace("/var/lib/p2p/certs/peer.crt", f"{pki}/recv/peer.crt")
                    .replace("/var/lib/p2p/certs/peer.key", f"{pki}/recv/peer.key")
                    .replace("/var/lib/p2p/certs/ca.crt", f"{pki}/recv/ca.crt"))
            if line.strip() and not line.startswith(";"):
                conf.append(line)
        conf.append("")
    (tmp / "stunnel.conf").write_text("\n".join(conf))
    spawn(["stunnel", str(tmp / "stunnel.conf")], env=sh_env(), log=open(tmp / "stunnel.log", "w"))
    ok1 = wait_port(ports["hybrid_port"]) and wait_port(ports["hybrid_mutual_port"])
    check(ok1, "stunnel (private OpenSSL) is listening on both hybrid ports",
          open(tmp / "stunnel.log").read()[-400:])
    if ok1:
        st, body = attempt(mod, cl, "hybrid")
        check(st == 200 and isinstance(body, dict) and body.get("tech") == "hybrid",
              "hybrid: hybrid X25519MLKEM768 + classical certs -> 200 through to the backend", str(body))
        st, body = attempt(mod, cl_evil, "hybrid")
        check(st is None and "identity" in str(body).lower(), "hybrid: a server signed by another CA is refused", str(body))
        st, body = attempt(mod, cl, "hybrid", name="someone-else")
        check(st is None, "hybrid: a certificate for another name is refused", str(body))
        st, body = attempt(mod, cl, "hybrid-mutual")
        check(st == 200, "hybrid-mutual: client certificate presented (leaf + intermediate chain) -> 200", str(body))
        # a client with NO certificate against the mutual port
        conn = mod._HybridTlsConnection("127.0.0.1", ports["hybrid_mutual_port"], "recv",
                                        str(pki / "sndr/ca.crt"), 20, label="hybrid-mutual")
        conn.request("POST", "/message", body=b"{}", headers={})
        try:
            r = conn.getresponse()
            check(False, "hybrid-mutual: no client certificate is refused", f"got status {r.status}")
        except Exception as e:                                       # noqa: BLE001
            check(True, "hybrid-mutual: no client certificate is refused")
        # a classical-only client: no hybrid group offered -> the hybrid port must refuse it
        r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{ports['hybrid_port']}",
                            "-groups", "X25519", "-tls1_3", "-CAfile", str(pki / "sndr/ca.crt"), "-brief"],
                           input="", capture_output=True, text=True, timeout=20)
        check(r.returncode != 0 and "handshake failure" in (r.stdout + r.stderr),
              "hybrid: a classical-only (X25519) client gets 'handshake failure' (no silent downgrade)",
              (r.stdout + r.stderr)[-200:])

    # ── QUIC relays: the real quic_pqc_relay.py, in the venv, one process per tech ───────────────────
    quic = {
        "quic-hybrid": (ports["quic_hybrid_port"], 0, "X25519MLKEM768"),
        "quic-hybrid-mutual": (ports["quic_hybrid_mutual_port"], 1, "X25519MLKEM768"),
        "quic-classical": (ports["quic_classical_port"], 0, "X25519"),
        "quic-classical-mutual": (ports["quic_classical_mutual_port"], 1, "X25519"),
    }
    for tech, (port, mutual, groups) in quic.items():
        spawn([QUIC_PY, str(REPO / "p2p/receiver-role/quic_pqc_relay.py")],
              env=dict(os.environ, P2P_QUIC_PQC_PORT=str(port), QUIC_CERT_MODE="classical",
                       QUIC_CLASSICAL_CERT_DIR=str(pki / "recv"), QUIC_GROUPS=groups,
                       P2P_QUIC_PQC_MUTUAL=str(mutual), P2P_HTTP_PORT=str(bport),
                       QUIC_PQC_CERT_DIR=str(tmp / "unused-quic-dir")),
              log=open(tmp / f"{tech}.log", "w"))
    time.sleep(2.5)
    mod._QuicPqcConnection.QUIC_PQC_PYTHON = QUIC_PY
    mod._QuicPqcConnection.QUIC_PQC_HELPER = str(REPO / "PQC-bench/aioquic-patch/quic_pqc_client_helper.py")
    works = {}
    for tech in quic:
        st, body = attempt(mod, cl, tech)
        works[tech] = st == 200 and isinstance(body, dict) and body.get("tech") == tech
        check(works[tech], f"{tech}: handshake + HTTP/3 request through to the backend -> 200", str(body)[:300])

    def refused(cond, name, detail=""):
        """A negative only means something when the positive for the same listener passed."""
        if cond is None:
            check(False, name + " (cannot judge: the positive exchange on this listener failed)")
        else:
            check(cond, name, detail)

    st, body = attempt(mod, cl_evil, "quic-hybrid")
    refused(st is None if works["quic-hybrid"] else None, "quic-hybrid: a server signed by another CA is refused", str(body)[:200])
    st, body = attempt(mod, cl, "quic-classical", name="someone-else")
    refused(st is None if works["quic-classical"] else None, "quic-classical: a certificate for another name is refused", str(body)[:200])
    # the proof a tier is a tier: the OTHER key-exchange offered to the same port must fail
    for label, port, kex, tech in (("hybrid offer -> quic-classical port", ports["quic_classical_port"], "hybrid", "quic-classical"),
                                   ("classical offer -> quic-hybrid port", ports["quic_hybrid_port"], "classical", "quic-hybrid")):
        c = mod._QuicPqcConnection("127.0.0.1", port, "recv", str(pki / "sndr/ca.crt"), 20,
                                   kex=kex, certs="classical", label="probe")
        c.request("POST", "/message", body=b"{}", headers={})
        try:
            r = c.getresponse()
            refused(False if works[tech] else None, f"{label} is refused", f"got status {r.status}")
        except Exception as e:                                       # noqa: BLE001
            refused(True if works[tech] else None, f"{label} is refused")
    # mutual without a client certificate
    c = mod._QuicPqcConnection("127.0.0.1", ports["quic_classical_mutual_port"], "recv",
                               str(pki / "sndr/ca.crt"), 20, kex="classical", certs="classical",
                               label="probe")
    c.request("POST", "/message", body=b"{}", headers={})
    try:
        r = c.getresponse()
        refused(r.status == 403 if works["quic-classical-mutual"] else None,
                "quic-classical-mutual: no client certificate -> no forward (403 or refused)", f"status {r.status}")
    except Exception:                                                # noqa: BLE001
        refused(True if works["quic-classical-mutual"] else None,
                "quic-classical-mutual: no client certificate -> no forward (403 or refused)")

    # ── coap-dtls: needs wolfSSL + aiocoap in ONE interpreter; run its own script with the first one found ─
    import site
    user_site = site.getusersitepackages()
    candidates = [("/opt/pqc-libs/dtls-srtp-venv/bin/python3", user_site), (sys.executable, "")]
    ran = False
    for py, extra in candidates:
        if not os.path.exists(py):
            continue
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(x for x in (extra, os.environ.get("PYTHONPATH", "")) if x))
        env.pop("LD_LIBRARY_PATH", None)
        if subprocess.run([py, "-c", "import wolfssl, aiocoap; assert hasattr(wolfssl,'WOLFSSL_X25519MLKEM768')"],
                          capture_output=True, env=env).returncode != 0:
            continue
        ran = True
        r = subprocess.run([py, str(REPO / "p2p/tests/test_new_techs_dtls_local.py")], capture_output=True,
                           text=True, env=env, timeout=280)
        for line in r.stdout.splitlines():
            if line.startswith(("PASS ", "FAIL ")):
                results.append((line[:4], line[5:]))
                print(line, flush=True)
        if r.returncode != 0 and not any(l.startswith("FAIL ") for l in r.stdout.splitlines()):
            check(False, "coap-dtls script ran to completion", (r.stdout + r.stderr)[-400:])
        break
    if not ran:
        skip("coap-dtls / coap-dtls-mutual end to end",
             "no interpreter on this box has both the patched wolfssl and aiocoap")

    cleanup()
    backend.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)
    n = {k: sum(1 for s, _ in results if s == k) for k in ("PASS", "FAIL", "SKIP")}
    print(f"\n{n['PASS']} passed, {n['FAIL']} failed, {n['SKIP']} skipped")
    return 1 if n["FAIL"] else 0


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        cleanup()
    sys.exit(rc)
