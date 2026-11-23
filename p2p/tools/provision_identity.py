#!/usr/bin/env python3
"""provision_identity.py -- issue a box's post-quantum identity with the REAL CA and install it on the box (2026-10-23, atsanak).

  --kind pqc   the ML-DSA-65 leaf in /var/lib/p2p/certs-pqc (configs pqc, coap-pqc, coap-dtls-pqc, coap-dtls-pqc-mutual),
               signed by the PQC CA (default --ca-dir PQC-bench/ca/pki) with the oqs-provider OpenSSL (pqc_ca.py)
  --kind quic  the ML-DSA-65 leaf in /var/lib/p2p/certs-quic-pqc (quic-pqc, quic-pqc-mutual), signed by the quic-pqc CA
               (default --ca-dir /var/lib/p2p/certs-quic-pqc on the CA holder) with cryptography (quic_pqc_ca.py)

Run on the CA HOLDER, as root (it reads the CA key). Example, for a replaced Pi:
  sudo TESTBED_SSH_PASS=... python3 p2p/tools/provision_identity.py --kind pqc  --name T1-Rpi50-subgw-T1 --ips 10.2.2.1,10.2.1.10 --tenant T1 --ssh rpi50@10.2.1.10
  sudo TESTBED_SSH_PASS=... /opt/pqc-libs/quic-pqc-venv/bin/python3 p2p/tools/provision_identity.py --kind quic --name ... (same args)

--ips: EVERY address peers may dial -- all IP SANs of the box's classical /var/lib/p2p/certs/peer.crt (p2p_preflight.py prints
them and fails until the PQC leaves cover them). The CA key never leaves this host; the leaf key exists here only in a 0700 temp
dir that is shredded. The box's copy is checked to chain to the CA, and the services that load it are restarted."""
import argparse, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_CA = os.path.normpath(os.path.join(HERE, "..", "..", "PQC-bench", "ca"))
ap = argparse.ArgumentParser()
ap.add_argument("--kind", choices=("pqc", "quic"), required=True)
ap.add_argument("--name", required=True)
ap.add_argument("--ips", required=True)
ap.add_argument("--tenant", required=True)
ap.add_argument("--ca-dir")
ap.add_argument("--ssh", required=True, help="user@host of the box")
ap.add_argument("--ssh-pass-env", default="TESTBED_SSH_PASS")
a = ap.parse_args()
sys.path[:0] = [REPO_CA, "/opt/PQC-bench/ca"]

if a.kind == "quic":
    ca_dir = a.ca_dir or "/var/lib/p2p/certs-quic-pqc"
    box_dir, units = "/var/lib/p2p/certs-quic-pqc", "p2p-quic-pqc-relay p2p-quic-pqc-mutual-relay"
    files = {"nodes/{n}.crt": "crt", "nodes/{n}.key": "key", "peer.crt": "crt", "peer.key": "key", "server.crt": "crt", "server.key": "key"}
    verify = ("/opt/pqc-libs/quic-pqc-venv/bin/python3 - <<'PY'\nfrom cryptography import x509\nL=lambda p: x509.load_pem_x509_certificate(open(p,'rb').read())\n"
              f"L('{box_dir}/peer.crt').verify_directly_issued_by(L('{box_dir}/ca.crt'))\nprint('installed; chains to the quic-pqc CA')\nPY")
else:
    ca_dir = a.ca_dir or os.path.join(REPO_CA, "pki")
    box_dir = "/var/lib/p2p/certs-pqc"
    units = "p2p-receiver p2p-coap-receiver p2p-coap-dtls-pqc-relay p2p-coap-dtls-pqc-mutual-relay"
    files = {"peer.crt": "crt", "peer.key": "key", "ca.crt": "ca"}
    verify = ("cd /opt/p2p && python3 -c \"from common import identity; import sys; "
              f"ok=identity.verify_chain_pqc('{box_dir}/ca.crt', open('{box_dir}/peer.crt').read()); "
              "print('installed; chains to the PQC CA' if ok else 'DOES NOT CHAIN'); sys.exit(0 if ok else 1)\"")
    os.environ.update(PATH="/opt/pqc-libs/openssl-priv/bin:" + os.environ.get("PATH", ""),
                      LD_LIBRARY_PATH="/opt/pqc-libs/liboqs-priv/lib:/opt/pqc-libs/openssl-priv/lib64",
                      OPENSSL_CONF=os.environ.get("OPENSSL_CONF", "/opt/PQC-bench/oqs-openssl-priv.cnf"))

tmp = tempfile.mkdtemp(prefix="pqid-"); os.chmod(tmp, 0o700)
try:
    for f in ("ca.crt", "ca.key"):
        os.symlink(os.path.abspath(os.path.join(ca_dir, f)), os.path.join(tmp, f))
    if a.kind == "quic":
        import quic_pqc_ca
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization as s
        pub = lambda o: o.public_bytes(s.Encoding.DER, s.PublicFormat.SubjectPublicKeyInfo)
        if pub(s.load_pem_private_key(open(os.path.join(ca_dir, "ca.key"), "rb").read(), None).public_key()) != pub(
                x509.load_pem_x509_certificate(open(os.path.join(ca_dir, "ca.crt"), "rb").read()).public_key()):
            sys.exit(f"{ca_dir}/ca.key is not the key of its ca.crt (a stub) -- run this on the real CA holder")
        crt, key = quic_pqc_ca.issue(tmp, a.name, a.ips, a.tenant)
    else:
        import pqc_ca
        crt, key = (x.encode() for x in pqc_ca.issue(tmp, a.name, a.ips, a.tenant))
    blobs = {"crt": crt, "key": key, "ca": open(os.path.join(ca_dir, "ca.crt"), "rb").read()}
    print(f"issued {a.kind} leaf for {a.name}, SAN IPs {a.ips}")
    pw = os.environ.get(a.ssh_pass_env)
    pre = ["sshpass", "-p", pw] if pw else []
    sudo = f"echo {pw!r} | sudo -S -p ''" if pw else "sudo -n"
    stage = os.path.join(tmp, "stage"); os.mkdir(stage)
    for kind in ("crt", "key", "ca"):
        open(os.path.join(stage, kind), "wb").write(blobs[kind])
    lines = ["set -e", f"S=/tmp/pqid-{a.name}", f"mkdir -p {box_dir}/nodes"]
    for dst, kind in files.items():
        mode = "600" if kind == "key" else "644"
        lines.append(f"install -m {mode} $S/{kind} {box_dir}/{dst.format(n=a.name)}")
    lines += ["shred -u $S/key; rm -rf $S", f"systemctl restart {units} 2>/dev/null || true", "sleep 3", verify]
    open(os.path.join(stage, "install.sh"), "w").write("\n".join(lines) + "\n")
    subprocess.run(pre + ["ssh", a.ssh, f"rm -rf /tmp/pqid-{a.name}; mkdir -m 700 /tmp/pqid-{a.name}"], check=True)
    subprocess.run(pre + ["scp", "-q"] + [os.path.join(stage, f) for f in ("crt", "key", "ca", "install.sh")]
                   + [f"{a.ssh}:/tmp/pqid-{a.name}/"], check=True)
    r = subprocess.run(pre + ["ssh", a.ssh, f"{sudo} bash /tmp/pqid-{a.name}/install.sh"], capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip()[-400:]); sys.exit(r.returncode)
finally:
    for root, _d, fs in os.walk(tmp):
        for f in fs:
            p = os.path.join(root, f)
            if f.endswith(".key") or f == "key":
                if not os.path.islink(p):
                    subprocess.run(["shred", "-u", p])
    shutil.rmtree(tmp, ignore_errors=True)
