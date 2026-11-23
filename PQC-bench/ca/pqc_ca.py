"""pqc_ca — the PQC-benchmark-only certificate authority (pqc-plan..md Phase 2).

A FORK of `Server-PC/Server/app/mtls_ca.py`'s conceptual shape (root+intermediate-free short
chain, per-node leaf, idempotent issue), not an extension of it: separate key material, separate
on-disk path, never imported by or sharing state with the production CA. Per R2.3, the production
CA and its live rollout (`verify-rollout.py` 16/16) must stay byte-identical in behavior — this
file has zero import/runtime coupling to it.

Signs with ML-DSA-65 (oqs-provider) instead of the production CA's classical RSA, so every
openssl invocation here needs oqs-provider active. Callers must run with:
    OPENSSL_CONF=/opt/pqc-libs/oqs-openssl.cnf
(see ../oqs-openssl.cnf) — this script does not set it itself, so it's obvious from the
environment, not hidden magic, whether a given call is PQC-capable.

CN/SAN convention matches mtls_ca.py's (R2.2): CN=node name, SAN=IP:<overlay /32>,DNS:<name> —
reusing the *convention* only, read straight from netplan.json by the caller, not this module.
"""
import ipaddress
import re
import os
import subprocess
import tempfile
from pathlib import Path

SIGALG = "mldsa65"          # Q2 default: ML-DSA-65 (NIST-standardized, mature oqs-provider support)


def _run(args, stdin=None):
    if "OPENSSL_CONF" not in os.environ:
        raise RuntimeError("pqc_ca requires OPENSSL_CONF pointing at PQC-bench/oqs-openssl.cnf "
                            "(oqs-provider must be active) — see module docstring")
    return subprocess.run(args, input=stdin, capture_output=True, text=True, check=True)


def ensure_ca(ca_dir):
    """Mint the PQC-bench root CA once (ML-DSA-65 self-signed); return the CA cert PEM. Idempotent.

    `-addext basicConstraints`/`keyUsage` are explicit (found live, 2026-07-26): OPENSSL_CONF here
    is the minimal oqs-provider-activation config (no `[req]` section at all -- it only exists to
    turn oqs-provider on, per the module docstring), so `req -x509` has no default `x509_extensions`
    to fall back on the way it would against a normal system openssl.cnf. Without these, the root
    comes out with NO CA:TRUE at all, and every `openssl verify` against it fails
    `error 79: invalid CA certificate` -- confirmed live, not theoretical."""
    d = Path(ca_dir)
    d.mkdir(parents=True, exist_ok=True)
    key, crt = d / "ca.key", d / "ca.crt"
    if key.exists() and crt.exists():
        return crt.read_text()
    _run(["openssl", "req", "-x509", "-new", "-newkey", SIGALG, "-nodes",
          "-keyout", str(key), "-out", str(crt), "-days", "3650",
          "-addext", "basicConstraints=critical,CA:TRUE",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign",
          "-subj", "/CN=PQC-bench Root CA/O=testbed PQC-bench"])
    key.chmod(0o600)
    return crt.read_text()


def ca_cert(ca_dir):
    return ensure_ca(ca_dir)


def issue(ca_dir, name, ip, tenant, days=825):
    """Sign a per-node leaf with the PQC-bench CA: CN=name, SAN=IP:<overlay /32>+DNS:name,
    O=tenant, leaf keypair + signature both ML-DSA-65. Cached + idempotent, same shape as
    mtls_ca.issue(). Returns (cert_pem, key_pem)."""
    d = Path(ca_dir)
    nd = d / "nodes"
    nd.mkdir(parents=True, exist_ok=True)
    ensure_ca(ca_dir)
    key, csr, crt, ext = nd / f"{name}.key", nd / f"{name}.csr", nd / f"{name}.crt", nd / f"{name}.ext"
    # 2026-10-23 (atsanak): `ip` may name several addresses ("a,b" or a list); the cached leaf is reused only while
    # its SAN covers all of them, else it is re-minted (Rpi50's leaf named 10.2.1.10 while peers dial 10.2.2.1).
    ips = [ipaddress.ip_address(x.strip()) for x in (ip.split(",") if isinstance(ip, str) else ip) if str(x).strip()]
    if key.exists() and crt.exists():
        have = set(re.findall(r"IP Address:([0-9a-fA-F.:]+)", subprocess.run(
            ["openssl", "x509", "-noout", "-ext", "subjectAltName"], input=crt.read_text(), capture_output=True,
            text=True).stdout))
        if {str(i) for i in ips} <= have:
            return crt.read_text(), key.read_text()
    ext.write_text(
        "[v3]\n"
        f"subjectAltName={','.join(f'IP:{i}' for i in ips)},DNS:{name}\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth,serverAuth\n"
        "basicConstraints=critical,CA:FALSE\n")
    _run(["openssl", "req", "-new", "-newkey", SIGALG, "-nodes", "-keyout", str(key), "-out", str(csr),
          "-subj", f"/CN={name}/O={tenant}"])
    _run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(d / "ca.crt"),
          "-CAkey", str(d / "ca.key"), "-CAcreateserial", "-days", str(days),
          "-out", str(crt), "-extfile", str(ext), "-extensions", "v3"])
    key.chmod(0o600)
    return crt.read_text(), key.read_text()


def verify_chain(ca_dir, cert_pem):
    ca_crt = Path(ca_dir) / "ca.crt"
    if not ca_crt.exists():
        return False
    p = subprocess.run(["openssl", "verify", "-CAfile", str(ca_crt)], input=cert_pem,
                        capture_output=True, text=True, env=os.environ)
    return p.returncode == 0 and "OK" in p.stdout


def leaf_identity(cert_pem):
    """Read back (CN, [SAN entries]) — same shape as mtls_ca.leaf_identity().

    Deliberately NOT routed through `_run()`, i.e. NOT gated on OPENSSL_CONF/oqs-provider. Parsing
    `subject`/`subjectAltName` out of an already-issued cert is a pure structural read: it never
    touches the ML-DSA-65 signature, so a stock openssl answers it correctly. Gating it meant this
    module refused to report a cert's CN on any box without the PQC toolchain provisioned — a
    false negative on a question that has nothing to do with PQC. `verify_chain()` below already
    established this exact split (it calls subprocess.run directly for the same reason)."""
    txt = subprocess.run(["openssl", "x509", "-noout", "-subject", "-ext", "subjectAltName"],
                         input=cert_pem, capture_output=True, text=True, check=True).stdout
    cn, sans = None, []
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("subject=") and "CN" in line:
            cn = line.split("CN")[-1].lstrip(" =").split(",")[0].strip()
        if line.startswith("IP Address:") or "IP Address:" in line or line.startswith("DNS:"):
            sans += [p.strip() for p in line.replace("IP Address:", "IP:").split(",") if ":" in p]
    return cn, sans


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 5 or sys.argv[1] != "issue":
        print("usage: OPENSSL_CONF=.../oqs-openssl.cnf python3 pqc_ca.py issue <name> <ip> <tenant>",
              file=sys.stderr)
        sys.exit(1)
    _, _, name, ip, tenant = sys.argv
    crt, _ = issue(str(Path(__file__).parent / "pki"), name, ip, tenant)
    print(crt)
