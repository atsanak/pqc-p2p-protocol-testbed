"""quic_pqc_ca — pure-Python ML-DSA-65 CA for the quic-pqc tech, via `cryptography`'s NATIVE
mldsa module (>=45.0, confirmed present in 50.0.1). Deliberately a FOURTH, separate toolchain
from pqc_ca.py (oqs-provider), pqc_kem.py (openssl35 CLI): confirmed live that oqs-provider's
ML-DSA-65 PRIVATE KEY PEM encoding is NOT interoperable with cryptography's native mldsa loader
(ASN.1 parsing error loading an existing peer.key) even though the PUBLIC key/cert (SPKI/X.509)
IS byte-compatible both ways. No subprocess, no LD_LIBRARY_PATH/OPENSSL_CONF gymnastics, no
external openssl build at all -- everything here runs through `cryptography` directly, which is
why this one can be a single `pip install cryptography>=45 aioquic` instead of a compiled
toolchain like every earlier PQC tech in this project needed.
"""
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.x509.oid import NameOID


def ensure_ca(ca_dir):
    d = Path(ca_dir)
    d.mkdir(parents=True, exist_ok=True)
    key_path, crt_path = d / "ca.key", d / "ca.crt"
    if key_path.exists() and crt_path.exists():
        return crt_path.read_bytes()
    key = mldsa.MLDSA65PrivateKey.generate()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "quic-pqc Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "testbed PQC-bench"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .sign(key, algorithm=None)  # ML-DSA has no separate digest -- signs the message directly
    )
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    key_path.chmod(0o600)
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert.public_bytes(serialization.Encoding.PEM)


def issue(ca_dir, name, ip, tenant, days=825):
    """Idempotent, matches pqc_ca.issue()'s own contract. -> (crt_pem: bytes, key_pem: bytes)."""
    d = Path(ca_dir)
    ensure_ca(ca_dir)
    ca_key = serialization.load_pem_private_key((d / "ca.key").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((d / "ca.crt").read_bytes())

    nodes = d / "nodes"
    nodes.mkdir(exist_ok=True)
    key_path, crt_path = nodes / f"{name}.key", nodes / f"{name}.crt"
    # 2026-10-23 (atsanak): `ip` may name SEVERAL addresses ("a,b" or a list) -- a box reachable on two (a sub-gateway's
    # anchor and its own /32) must be bound to both, else a sender that dials the other one refuses the certificate
    # (found on Rpi50). The cached leaf is reused only while it covers every requested address; otherwise it is
    # re-minted, under a lock so two relays starting together cannot interleave one's certificate with the other's key.
    import fcntl
    import ipaddress
    ips = [ipaddress.ip_address(x.strip()) for x in (ip.split(",") if isinstance(ip, str) else ip) if str(x).strip()]
    lock = open(d / ".issue.lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX)
    if key_path.exists() and crt_path.exists():
        try:
            have = set(x509.load_pem_x509_certificate(crt_path.read_bytes()).extensions
                       .get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress))
        except Exception:                                         # noqa: BLE001 -- unreadable: re-mint
            have = set()
        pub = lambda o: o.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        real_ca = pub(ca_key.public_key()) == pub(ca_cert.public_key())
        if set(ips) <= have or not real_ca:
            # a receiver holds only a STUB ca.key (pqc-stacks-all.sh --relay-ca-key stub: the real CA key stays on the CA
            # holder). Signing with it would produce a leaf nobody trusts (done once, 2026-10-23, on Rpi50) -- so a box
            # without the real key never re-mints; re-issue on the CA holder (p2p/tools/provision_quic_identity.py).
            if not set(ips) <= have:
                print(f"[quic_pqc_ca] {name}: cached leaf lacks {sorted(map(str, set(ips) - have))} but ca.key is not the "
                      f"real CA key here -- keeping it; re-issue on the CA holder", flush=True)
            lock.close()
            return crt_path.read_bytes(), key_path.read_bytes()

    key = mldsa.MLDSA65PrivateKey.generate()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, tenant),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(i) for i in ips] + [x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .sign(ca_key, algorithm=None)
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)
    crt_path.write_bytes(crt_pem)
    lock.close()
    return crt_pem, key_pem


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 5 or sys.argv[1] != "issue":
        print("usage: python3 quic_pqc_ca.py issue <name> <ip> <tenant>", file=sys.stderr)
        sys.exit(1)
    _, _, name, ip, tenant = sys.argv
    crt, _ = issue(str(Path(__file__).parent / "pki"), name, ip, tenant)
    print(crt.decode())
