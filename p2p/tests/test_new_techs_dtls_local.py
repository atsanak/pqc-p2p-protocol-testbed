#!/usr/bin/env python3
"""coap-dtls / coap-dtls-mutual (and the older coap-dtls-pqc as a regression), end to end on loopback.

Needs ONE interpreter that has both the patched `wolfssl` binding (X25519MLKEM768 + group selection) and
`aiocoap`. test_new_techs_local.py finds one and runs this file with it; run by hand with e.g.

  PYTHONPATH=~/.local/lib/python3.12/site-packages /opt/pqc-libs/dtls-srtp-venv/bin/python3 \
      p2p/tests/test_new_techs_dtls_local.py

What runs: a mini aiocoap backend standing in for coap_server.py, the REAL coap_dtls_pqc_relay.py accept loop
(one per port: classical X25519-only, classical mutual, hybrid), and the REAL sender
`Client._coap_dtls_exchange` (signing, DTLS handshake in the worker process, peer CN/SAN check) with only the
Server lookup and the comm-log writes stubbed. Prints PASS/FAIL lines; exit 0 = all pass.
"""
import asyncio
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def _reexec_with_wolfssl():
    """Run by hand with a plain `python3` that lacks the patched wolfssl, this file used to report 3 FAILs that were not
    failures of anything. Find the interpreter test_new_techs_local.py would use and re-run under it; if there is none,
    say SKIP and exit 0 rather than fail."""
    try:
        import wolfssl, aiocoap  # noqa: F401
        if hasattr(wolfssl, "WOLFSSL_X25519MLKEM768"):
            return
    except ImportError:
        pass
    if os.environ.get("_DTLS_TEST_REEXEC"):
        print("SKIP coap-dtls end to end: no interpreter on this box has both the patched wolfssl and aiocoap")
        sys.exit(0)
    import site
    for py, extra in (("/opt/pqc-libs/dtls-srtp-venv/bin/python3", site.getusersitepackages()), (sys.executable, "")):
        if not os.path.exists(py):
            continue
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(x for x in (extra, os.environ.get("PYTHONPATH", "")) if x), _DTLS_TEST_REEXEC="1")
        env.pop("LD_LIBRARY_PATH", None)
        if subprocess.run([py, "-c", "import wolfssl, aiocoap; assert hasattr(wolfssl,'WOLFSSL_X25519MLKEM768')"],
                          capture_output=True, env=env).returncode == 0:
            os.execve(py, [py, str(Path(__file__).resolve())] + sys.argv[1:], env)
    print("SKIP coap-dtls end to end: no interpreter on this box has both the patched wolfssl and aiocoap")
    sys.exit(0)


_reexec_with_wolfssl()
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "p2p"))
sys.path.insert(0, str(REPO / "PQC-bench/wolfssl-py-patch"))
os.environ.setdefault("COAP_DTLS_PQC_MODULE_PATH", str(REPO / "PQC-bench/wolfssl-py-patch"))

import test_new_techs_local as T          # noqa: E402  (PKI + the sender loader live there)

fails = []


def check(ok, name, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"   [{detail}]" if detail and not ok else ""), flush=True)
    if not ok:
        fails.append(name)


# ── processes ───────────────────────────────────────────────────────────────────────────────────────
def backend_proc(coap_port):
    """A CoAP server answering POST /message like coap_server.py would, as plain JSON."""
    import aiocoap
    import aiocoap.resource as resource

    class Msg(resource.Resource):
        async def render_post(self, request):
            body = json.dumps({"ok": True, "n": len(request.payload)}).encode()
            return aiocoap.Message(code=aiocoap.CONTENT, payload=body)

    async def run():
        root = resource.Site()
        root.add_resource(["message"], Msg())
        await aiocoap.Context.create_server_context(root, bind=("127.0.0.1", coap_port))
        await asyncio.get_running_loop().create_future()

    asyncio.run(run())


def relay_proc(port, coap_port, cert, key, mutual, ca, require_group, host="127.0.0.1"):
    if require_group:
        os.environ["P2P_COAP_DTLS_REQUIRE_GROUP"] = require_group
    import importlib.util
    spec = importlib.util.spec_from_file_location("relay", REPO / "p2p/receiver-role/coap_dtls_pqc_relay.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m._accept_loop(host, port, coap_port, cert, key, mutual=mutual, ca_path=ca)


def free_udp():
    return T.free_port(udp=True)


def sender(mod, pki, ports):
    cl = T.make_sender(mod, pki, ports)
    cl.coap_require_signed_response = False
    cl._report = lambda *a, **k: None                      # no comm-log writes
    cl._verify_coap_response = lambda *a, **k: None        # the stub backend does not sign
    mod.sender_log.record = lambda *a, **k: None
    mod.identity.resolve = lambda *a, **k: {"ip": "127.0.0.1", "via_chain": []}
    return cl


def run(cl, tech, name="recv"):
    try:
        r = cl._coap_dtls_exchange("message", name, {"x": 1}, b"", tech=tech, timeout=25)
        return r, None
    except Exception as e:                                  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def main():
    tmp = Path(tempfile.mkdtemp(prefix="p2p-dtls-"))
    pki = tmp / "pki"
    T.make_pki(pki)
    mod = T.load_client()
    cp = free_udp()
    ports = dict(coap_dtls_port=free_udp(), coap_dtls_mutual_port=free_udp(),
                 coap_dtls_pqc_port=free_udp(), coap_dtls_pqc_mutual_port=free_udp())
    recv = pki / "recv"
    jobs = [("backend", backend_proc, (cp,)),
            ("coap-dtls relay", relay_proc,
             (ports["coap_dtls_port"], cp, str(recv / "peer.crt"), str(recv / "peer.key"), False, None, "X25519")),
            ("coap-dtls-mutual relay", relay_proc,
             (ports["coap_dtls_mutual_port"], cp, str(recv / "peer.crt"), str(recv / "peer.key"), True,
              str(recv / "ca.crt"), "X25519")),
            ]
    # coap-dtls-pqc (2026-10-23): pure ML-KEM-768 + ML-DSA-65 certificates. Uses this box's own PQC identity
    # (the local test PKI is RSA-only), so it runs only where /var/lib/p2p/certs-pqc is readable.
    pq = Path(os.environ.get("P2P_PQC_CACHE_DIR", "/var/lib/p2p/certs-pqc"))
    pq_ok = all(os.access(pq / f, os.R_OK) for f in ("peer.crt", "peer.key", "ca.crt"))
    # served on the IP the certificate's SAN names (the sender checks it), when this box has that address
    import ipaddress, socket as _s, subprocess as _sp
    san = _sp.run(["openssl", "x509", "-in", str(pq / "peer.crt"), "-noout", "-ext", "subjectAltName"],
                  capture_output=True, text=True).stdout if pq_ok else ""
    pq_ip = next((t.split(":", 1)[1] for t in san.replace(",", " ").split() if t.startswith("Address:")), None)
    try:
        _b = _s.socket(_s.AF_INET, _s.SOCK_DGRAM); _b.bind((pq_ip, 0)); _b.close()
    except (OSError, TypeError):
        pq_ip = None
    pq_ok = pq_ok and pq_ip is not None and ipaddress.ip_address(pq_ip).version == 4
    if pq_ok:
        jobs.append(("coap-dtls-pqc relay", relay_proc,
                     (ports["coap_dtls_pqc_port"], cp, str(pq / "peer.crt"), str(pq / "peer.key"), False, None, "",
                      pq_ip)))
    procs = []
    for label, fn, args in jobs:
        p = multiprocessing.Process(target=fn, args=args, daemon=True, name=label)
        p.start()
        procs.append(p)
    time.sleep(3)
    cl = sender(mod, pki, ports)
    try:
        r, err = run(cl, "coap-dtls")
        check(r is not None and r.get("ok") is True, "coap-dtls: DTLS 1.3 X25519 + RSA certs -> backend answered", str(err))
        r, err = run(cl, "coap-dtls-mutual")
        check(r is not None and r.get("ok") is True, "coap-dtls-mutual: client certificate presented -> answered", str(err))
        r, err = run(cl, "coap-dtls", name="someone-else")
        check(r is None, "coap-dtls: a certificate for another name is refused", str(err))

        # a hybrid offer to the X25519-only port must be refused (the REQUIRE_GROUP pin)
        cl2 = sender(mod, pki, dict(ports, coap_dtls_pqc_port=ports["coap_dtls_port"]))
        r, err = run(cl2, "coap-dtls-pqc")
        check(r is None, "coap-dtls port: a hybrid X25519MLKEM768 offer is NOT served (REQUIRE_GROUP=X25519)", str(r))

        if pq_ok:
            import subprocess
            pq_cn = subprocess.run(["openssl", "x509", "-in", str(pq / "peer.crt"), "-noout", "-subject",
                                    "-nameopt", "multiline"], capture_output=True, text=True).stdout
            pq_cn = next((l.split("=", 1)[1].strip() for l in pq_cn.splitlines() if "commonName" in l), "")
            clp = sender(mod, pki, ports)
            clp._pqc_material = (str(pq / "peer.crt"), str(pq / "peer.key"), str(pq / "ca.crt"))
            clp._pqc = lambda: clp._pqc_material
            clp._require_pqc_reply = lambda *a, **k: None   # the stub backend signs nothing (checked live)
            mod.identity.resolve = lambda *a, **k: {"ip": pq_ip, "via_chain": []}
            r, err = run(clp, "coap-dtls-pqc", name=pq_cn)
            mod.identity.resolve = lambda *a, **k: {"ip": "127.0.0.1", "via_chain": []}
            check(r is not None and r.get("ok") is True,
                  "coap-dtls-pqc: ML-KEM-768 + ML-DSA-65 relay certificate -> answered", str(err))
            # the PQC port refuses a classical and a hybrid key exchange inside the handshake
            for share in ("x25519", "hybrid"):
                async def offer(share=share):
                    import aiocoap
                    from aiocoap_wolfdtls import MessageInterfaceWolfDTLS
                    ctx = await aiocoap.Context.create_client_context(transports=["udp6"])
                    await ctx._append_tokenmanaged_messagemanaged_transport(
                        lambda mman: MessageInterfaceWolfDTLS.create_client_transport_endpoint(
                            mman, log=ctx.log, loop=ctx.loop, ca_path=str(pq / "ca.crt"), key_share=share))
                    try:
                        req = aiocoap.Message(code=aiocoap.POST, payload=b"{}", transport_tuning=aiocoap.Unreliable,
                                              uri=f"coaps://{pq_ip}:{ports['coap_dtls_pqc_port']}/message")
                        return await asyncio.wait_for(ctx.request(req, handle_blockwise=False).response, 15)
                    finally:
                        await ctx.shutdown()
                try:
                    import asyncio
                    got = asyncio.run(offer())
                except Exception:                                   # noqa: BLE001 -- refused = the point
                    got = None
                check(got is None, f"coap-dtls-pqc port: a {share} key exchange is refused (ML-KEM-768 only)", str(got))
        else:
            print(f"SKIP coap-dtls-pqc: no readable PQC identity at {pq} bound to an address of this box", flush=True)

        # a classical offer to the mutual port without a certificate: build it by hand through the transport
        import aiocoap
        from aiocoap_wolfdtls import MessageInterfaceWolfDTLS

        async def nocert():
            ctx = await aiocoap.Context.create_client_context(transports=["udp6"])
            await ctx._append_tokenmanaged_messagemanaged_transport(
                lambda mman: MessageInterfaceWolfDTLS.create_client_transport_endpoint(
                    mman, log=ctx.log, loop=ctx.loop, ca_path=str(pki / "sndr/ca.crt"), key_share="x25519"))
            try:
                req = aiocoap.Message(code=aiocoap.POST, uri=f"coaps://127.0.0.1:{ports['coap_dtls_mutual_port']}/message",
                                      payload=b"{}", transport_tuning=aiocoap.Unreliable)
                return await asyncio.wait_for(ctx.request(req, handle_blockwise=False).response, timeout=15)
            finally:
                await ctx.shutdown()
        try:
            asyncio.run(nocert())
            check(False, "coap-dtls-mutual: no client certificate is refused", "got an answer")
        except Exception:                                   # noqa: BLE001
            check(True, "coap-dtls-mutual: no client certificate is refused")
    finally:
        for p in procs:
            p.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    multiprocessing.set_start_method("fork")
    sys.exit(main())
