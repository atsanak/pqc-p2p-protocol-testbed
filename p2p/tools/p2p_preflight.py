#!/usr/bin/env python3
"""p2p_preflight.py -- is THIS box ready for the 13 HTTP / CoAP P2P configurations? (2026-10-23, atsanak)

Run ON the box as root (the P2P keys are root-only):   sudo python3 /opt/p2p/tools/p2p_preflight.py [--json] [--role both|sender|receiver]
Exit 0 only when every configuration is READY for the requested role. Nothing is changed on the box.

Written for the day the Raspberry Pis are swapped: a fresh box can look fine (units "active") and still fail one config
in a way that only shows up as a refusal on the wire -- e.g. Rpi50's ML-DSA certificate was bound to 10.2.1.10 while
its P2P address is 10.2.2.1, so every PQC handshake to it was (correctly) refused. Every such requirement is checked
here, mapped to the configurations it breaks, and the PQC listener is proven with a real ML-KEM-768 + ML-DSA-65
handshake against itself.

Configurations: HTTP https mtls pqc quic-classical quic-classical-mutual quic-pqc quic-pqc-mutual;
                CoAP coap-enc coap-pqc coap-dtls coap-dtls-mutual coap-dtls-pqc coap-dtls-pqc-mutual."""
import argparse, glob, hashlib, json, os, re, shutil, socket, ssl, subprocess, sys

P2P = os.environ.get("P2P_DIR", "/opt/p2p")
BENCH = os.environ.get("PQC_BENCH_DIR", "/opt/PQC-bench")
CL = os.environ.get("P2P_PREFLIGHT_CL", "/var/lib/p2p/certs")
PQ = os.environ.get("P2P_PREFLIGHT_PQ", "/var/lib/p2p/certs-pqc")
QPQ = os.environ.get("P2P_PREFLIGHT_QPQ", "/var/lib/p2p/certs-quic-pqc")   # overridable for tests
QUIC_PY = "/opt/pqc-libs/quic-pqc-venv/bin/python3"
WOLF_LIB = "/opt/pqc-libs/wolfssl-dtls/lib"
KEM_OPENSSL = ("/opt/pqc-libs/openssl35/bin/openssl", "/opt/pqc-libs/openssl35/lib64")

HTTP = ["https", "mtls", "pqc", "quic-classical", "quic-classical-mutual", "quic-pqc", "quic-pqc-mutual"]
COAP = ["coap-enc", "coap-pqc", "coap-dtls", "coap-dtls-mutual", "coap-dtls-pqc", "coap-dtls-pqc-mutual"]
ALL = HTTP + COAP
PQC = {"pqc", "quic-pqc", "quic-pqc-mutual", "coap-pqc", "coap-dtls-pqc", "coap-dtls-pqc-mutual"}
QUIC = {t for t in ALL if t.startswith("quic")}
DTLS = {t for t in ALL if t.startswith("coap-dtls")}
# receiver side: config -> (systemd unit or None, port/proto)
RECV = {"https": ("p2p-receiver", "8444/tcp"), "mtls": ("p2p-receiver", "8443/tcp"), "pqc": ("p2p-receiver", "8446/tcp"),
        "quic-classical": ("p2p-quic-classical-relay", "4443/udp"),
        "quic-classical-mutual": ("p2p-quic-classical-mutual-relay", "4444/udp"),
        "quic-pqc": ("p2p-quic-pqc-relay", "4433/udp"), "quic-pqc-mutual": ("p2p-quic-pqc-mutual-relay", "4434/udp"),
        "coap-enc": ("p2p-coap-receiver", "5683/udp"), "coap-pqc": ("p2p-coap-receiver", "5683/udp"),
        "coap-dtls": ("p2p-coap-dtls-relay", "5687/udp"), "coap-dtls-mutual": ("p2p-coap-dtls-mutual-relay", "5688/udp"),
        "coap-dtls-pqc": ("p2p-coap-dtls-pqc-relay", "5685/udp"),
        "coap-dtls-pqc-mutual": ("p2p-coap-dtls-pqc-mutual-relay", "5686/udp")}

checks = []          # {name, ok, detail, affects: [configs], role}


def check(name, ok, detail, affects, role="both"):
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300], "affects": list(affects), "role": role})
    return bool(ok)


def run(argv, env=None, timeout=20, inp=None):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, input=inp)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:                                   # noqa: BLE001
        return 99, f"{type(e).__name__}: {e}"


def load_env():
    env = {}
    try:
        for line in open(os.path.join(P2P, ".env")):
            m = re.match(r"\s*([A-Z0-9_]+)\s*=\s*(.*)", line)
            if m:
                env[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    except OSError:
        pass
    return env


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--role", choices=("both", "sender", "receiver"), default="both")
    ap.add_argument("--manifest", help="JSON {relative path: sha256} of the code that must be deployed (TenantAPI passes the repo's)")
    a = ap.parse_args()
    sys.path.insert(0, P2P); sys.path.insert(0, os.path.join(P2P, "sender-role"))
    env = load_env()
    name = env.get("P2P_NODE_NAME") or os.environ.get("P2P_NODE_NAME", "")

    # ── platform ────────────────────────────────────────────────────────────────────────────────────────────
    check("root", os.geteuid() == 0, "run as root (the node's P2P keys are root-only)", ALL)
    check("python >= 3.11", sys.version_info >= (3, 11), sys.version.split()[0], ALL)
    ov = ssl.OPENSSL_VERSION_INFO
    check("system OpenSSL >= 3.5 (native ML-KEM-768 / ML-DSA-65; Debian 13 trixie)", ov >= (3, 5),
          ssl.OPENSSL_VERSION, ["pqc", "quic-pqc", "quic-pqc-mutual", "coap-pqc", "coap-dtls-pqc", "coap-dtls-pqc-mutual"])
    check("/opt/p2p/.env has P2P_NODE_NAME, SERVER_API_BASE, BOOTSTRAP_SECRET",
          all(env.get(k) for k in ("P2P_NODE_NAME", "SERVER_API_BASE", "BOOTSTRAP_SECRET")),
          {k: bool(env.get(k)) for k in ("P2P_NODE_NAME", "SERVER_API_BASE", "BOOTSTRAP_SECRET")}, ALL)
    try:
        from common import identity
        import client as C
        ok_imp = True
    except Exception as e:                                   # noqa: BLE001
        ok_imp = False; identity = C = None
        check("p2p code imports (common.identity, sender-role/client)", False, e, ALL)
    if ok_imp:
        check("p2p code imports (common.identity, sender-role/client)", True, P2P, ALL)
        missing = [t for t in ALL if t not in C.TECHS]
        check("sender knows all 13 configurations", not missing, missing or "all 13", missing or [])
    if not a.manifest and os.path.isfile(os.path.join(P2P, "MANIFEST.json")):   # written by deploy_p2p_box.sh
        a.manifest = os.path.join(P2P, "MANIFEST.json")
    if a.manifest:
        man = json.load(open(a.manifest))
        bad = []
        for rel, sha in man.items():
            p = os.path.join("/opt", rel)
            try:
                if hashlib.sha256(open(p, "rb").read()).hexdigest() != sha:
                    bad.append(rel)
            except OSError:
                bad.append(rel + " (missing)")
        check(f"deployed code == repo ({len(man)} files)", not bad, bad[:8] or "identical", ALL if bad else [])

    # ── identities ──────────────────────────────────────────────────────────────────────────────────────────
    def cert_facts(path):
        try:
            from cryptography import x509
            c = x509.load_pem_x509_certificate(open(path, "rb").read())
            cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            try:
                ips = [str(i) for i in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)]
            except x509.ExtensionNotFound:
                ips = []
            return {"cn": cn[-1].value if cn else None, "ips": ips, "sigalg": c.signature_algorithm_oid.dotted_string,
                    "not_after": c.not_valid_after_utc.isoformat()}
        except Exception as e:                               # noqa: BLE001
            return {"error": f"{type(e).__name__}: {e}"}

    have_cl = all(os.path.isfile(os.path.join(CL, f)) for f in ("peer.crt", "peer.key", "ca.crt"))
    clf = cert_facts(os.path.join(CL, "peer.crt")) if have_cl else {}
    check("classical identity /var/lib/p2p/certs (peer.crt, peer.key, ca.crt)", have_cl, CL,
          [t for t in ALL if t not in ("pqc",)])
    if have_cl:
        check("classical leaf CN == P2P_NODE_NAME", clf.get("cn") == name, f"cn={clf.get('cn')} node={name}",
              [t for t in ALL if t != "pqc"])
        check("classical leaf carries an IP SAN", bool(clf.get("ips")), clf.get("ips"), [t for t in ALL if t != "pqc"])
        if identity:
            check("classical leaf chains to its CA", identity.verify_chain(os.path.join(CL, "ca.crt"), open(os.path.join(CL, "peer.crt")).read()),
                  "openssl verify", [t for t in ALL if t != "pqc"])
    node_ips = set(clf.get("ips") or [])

    pq_conf = ["pqc", "quic-pqc", "quic-pqc-mutual", "coap-pqc", "coap-dtls-pqc", "coap-dtls-pqc-mutual"]
    have_pq = all(os.path.isfile(os.path.join(PQ, f)) for f in ("peer.crt", "peer.key", "ca.crt"))
    check("PQC identity /var/lib/p2p/certs-pqc (peer.crt, peer.key, ca.crt)", have_pq, PQ,
          ["pqc", "quic-pqc", "quic-pqc-mutual", "coap-pqc", "coap-dtls-pqc", "coap-dtls-pqc-mutual"])
    if have_pq:
        pqf = cert_facts(os.path.join(PQ, "peer.crt"))
        check("PQC leaf signed with ML-DSA-65", pqf.get("sigalg") == "2.16.840.1.101.3.4.3.18", pqf.get("sigalg"), pq_conf)
        check("PQC leaf CN == P2P_NODE_NAME", pqf.get("cn") == name, f"cn={pqf.get('cn')} node={name}", pq_conf)
        missing_ips = sorted(node_ips - set(pqf.get("ips") or []))
        check("PQC leaf SAN covers every IP of the classical leaf (else peers refuse it: the Rpi50 bug)", not missing_ips,
              f"pqc={pqf.get('ips')} classical={sorted(node_ips)} missing={missing_ips}", pq_conf)
        if identity:
            lib = identity._libcrypto()
            check("in-process ML-DSA-65 (system libcrypto)", lib is not None, "OpenSSL >= 3.5 libcrypto" if lib else "falls back to the slow CLI", [])
            try:
                msg = os.urandom(64)
                sig = identity.sign_payload_pqc(os.path.join(PQ, "peer.key"), msg)
                ok = len(sig) == 3309 and identity.verify_payload_signature_pqc(open(os.path.join(PQ, "peer.crt")).read(), msg, sig)
            except Exception as e:                           # noqa: BLE001
                ok, sig = False, e
            check("ML-DSA-65 sign + verify with this box's PQC key (3309 B signature)", ok,
                  f"{len(sig)} B" if isinstance(sig, bytes) else sig, pq_conf)
            check("PQC leaf chains to the PQC CA", identity.verify_chain_pqc(os.path.join(PQ, "ca.crt"), open(os.path.join(PQ, "peer.crt")).read()),
                  "PQC CA", pq_conf)
    kem_ok = os.path.isfile(os.path.join(PQ, "kem", "own.key")) and os.path.isfile(os.path.join(PQ, "kem", "own.pub"))
    peers = sorted(os.path.basename(p)[:-4] for p in glob.glob(os.path.join(PQ, "kem-peers", "*.pub")))
    check("ML-KEM-768 keypair kem/own.key + own.pub (coap-pqc receiver)", kem_ok, PQ + "/kem", ["coap-pqc"], "receiver")
    check("peers' ML-KEM public keys in kem-peers/ (coap-pqc sender)", bool(peers), f"{len(peers)} peers: {peers[:6]}", ["coap-pqc"], "sender")
    rc, out = run([KEM_OPENSSL[0], "version"], env=dict(os.environ, LD_LIBRARY_PATH=KEM_OPENSSL[1]))
    check("OpenSSL 3.5 for ML-KEM encap/decap (/opt/pqc-libs/openssl35)", rc == 0 and "3.5" in out, out[:60], ["coap-pqc"])

    have_q = all(os.path.isfile(os.path.join(QPQ, f)) for f in ("peer.crt", "peer.key", "ca.crt"))
    check("QUIC-PQC identity /var/lib/p2p/certs-quic-pqc", have_q, QPQ, ["quic-pqc", "quic-pqc-mutual"])
    if have_q:
        qf = cert_facts(os.path.join(QPQ, "peer.crt"))
        miss = sorted(node_ips - set(qf.get("ips") or []))
        check("QUIC-PQC leaf CN == node and SAN covers the classical IPs", qf.get("cn") == name and not miss,
              f"cn={qf.get('cn')} ips={qf.get('ips')} missing={miss}", ["quic-pqc", "quic-pqc-mutual"])
        # the leaf (peer.crt; server.crt is what the relay serves) must be SIGNED by the CA peers trust -- a receiver only
        # holds a stub ca.key, and a leaf signed with it fails every handshake (happened once, 2026-10-23)
        code = ("from cryptography import x509; import sys; L=lambda p: x509.load_pem_x509_certificate(open(p,'rb').read()); "
                f"ca=L('{QPQ}/ca.crt'); bad=[] \n"
                f"for f in ('peer.crt','server.crt'):\n"
                f"    try: L('{QPQ}/'+f).verify_directly_issued_by(ca)\n"
                f"    except FileNotFoundError: pass\n"
                f"    except Exception as e: bad.append(f+': '+type(e).__name__)\n"
                "print('ok' if not bad else 'BAD '+'; '.join(bad))")
        rc, out = run([QUIC_PY, "-c", code])
        check("QUIC-PQC leaf (peer.crt, server.crt) signed by the quic-pqc CA", rc == 0 and out.strip() == "ok", out[-200:],
              ["quic-pqc", "quic-pqc-mutual"])

    # ── stacks ──────────────────────────────────────────────────────────────────────────────────────────────
    if ok_imp and ov >= (3, 5):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            identity.pin_tls_groups(ctx, "MLKEM768"); ok, det = True, "MLKEM768 pinned through libssl"
        except Exception as e:                               # noqa: BLE001
            ok, det = False, e
        check("TLS group pinning works (pqc = ML-KEM-768 only, https/mtls = X25519 only)", ok, det, ["https", "mtls", "pqc"])
    rc, out = run([QUIC_PY, "-c", "from aioquic.tls import Group, SignatureAlgorithm as S; import aioquic; "
                   "print(aioquic.__version__, hex(Group.MLKEM768), hex(Group.X25519MLKEM768), hex(S.MLDSA65))"])
    check("aioquic venv with the pure ML-KEM-768 group + ML-DSA-65 (add_mlkem768.py applied)", rc == 0 and "0x201" in out,
          out[-160:], sorted(QUIC))
    helper = os.path.join(BENCH, "aioquic-patch", "quic_pqc_client_helper.py")
    check("QUIC client helper present", os.path.isfile(helper), helper, sorted(QUIC), "sender")
    wolf = os.path.join(BENCH, "wolfssl-py-patch")
    code = ("import sys,socket; sys.path.insert(0,%r); import wolfssl, aiocoap_wolfdtls as W; "
            "c=wolfssl.SSLContext(wolfssl.PROTOCOL_DTLSv1_3); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
            "x=c.wrap_socket(s,do_handshake_on_connect=False); W.pin_groups(x,b'ML_KEM_768'); W.pin_groups(x,b'X25519'); "
            "W.set_handshake_retransmit_max(x,4); print('ok', W.REDUNDANT_MAX_CHUNKS)") % wolf
    rc, out = run([sys.executable, "-c", code], env=dict(os.environ, LD_LIBRARY_PATH=WOLF_LIB))
    check("wolfSSL DTLS 1.3 binding: ML-KEM-768 / X25519 pinning, back-off cap, reply redundancy", rc == 0 and out.startswith("ok"),
          out[-200:], sorted(DTLS))

    # ── receiver: units, ports, firewall, a live PQC handshake ────────────────────────────────────────────────────
    if a.role in ("both", "receiver"):
        rc, ss_out = run(["ss", "-Hlnptu"])
        ufw_rc, ufw = run(["ufw", "status"]) if shutil.which("ufw") else (1, "")
        ufw_active = ufw_rc == 0 and "Status: active" in ufw
        for t in ALL:
            unit, port = RECV[t]
            rc, st = run(["systemctl", "is-active", unit])
            check(f"[{t}] receiver unit {unit} active", st.strip() == "active", st, [t], "receiver")
            num, proto = port.split("/")
            listening = any(re.search(rf"^{proto}\s.*:{num}\s", l) for l in ss_out.splitlines())
            check(f"[{t}] listening on {port}", listening, port, [t], "receiver")
            if ufw_active:
                allowed = any(re.match(rf"^{num}(/{proto})?\s+ALLOW", l.strip()) for l in ufw.splitlines())
                check(f"[{t}] ufw allows {port}", allowed, "ufw active", [t], "receiver")
        if ok_imp and have_pq and node_ips and ov >= (3, 5):
            ip = sorted(node_ips)[0]
            try:
                ctx = identity.build_pqc_client_context(os.path.join(PQ, "peer.crt"), os.path.join(PQ, "peer.key"),
                                                        os.path.join(PQ, "ca.crt"))
                s = ctx.wrap_socket(socket.create_connection((ip, 8446), timeout=8))
                g = identity.negotiated_group(s); peer = s.getpeercert(binary_form=True)
                s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); ans = s.recv(40); s.close()
                ok = g == "MLKEM768" and ans.startswith(b"HTTP/1.1 200")
                det = f"group={g}, answered {ans[:15]!r}"
            except Exception as e:                           # noqa: BLE001
                ok, det = False, f"{type(e).__name__}: {e}"
            check("live: pqc handshake against itself (ML-KEM-768 + ML-DSA-65 both sides) on :8446", ok, det, ["pqc"], "receiver")

    # ── verdict per configuration ──────────────────────────────────────────────────────────────────────────────
    role_ok = lambda c: c["role"] == "both" or a.role == "both" or c["role"] == a.role
    configs = {}
    for t in ALL:
        bad = [c["check"] for c in checks if not c["ok"] and t in c["affects"] and role_ok(c)]
        configs[t] = {"family": "CoAP" if t.startswith("coap") else "HTTP", "ready": not bad, "blocking": bad}
    ready = all(v["ready"] for v in configs.values())
    out = {"node": name, "role": a.role, "ready": ready, "openssl": ssl.OPENSSL_VERSION,
           "configs": configs, "checks": checks}
    if a.json:
        print(json.dumps(out))
    else:
        for c in checks:
            print(("ok    " if c["ok"] else "FAIL  ") + c["check"] + ("" if c["ok"] else f"   [{c['detail']}]"))
        print()
        for fam, lst in (("HTTP", HTTP), ("CoAP", COAP)):
            for t in lst:
                v = configs[t]
                print(f"{fam:4s} {t:22s} {'READY' if v['ready'] else 'NOT READY: ' + '; '.join(v['blocking'])[:160]}")
        print(f"\n{name}: {'ALL 13 CONFIGURATIONS READY' if ready else 'NOT READY'} (role {a.role})")
    sys.exit(0 if ready else 1)


if __name__ == "__main__":
    main()
