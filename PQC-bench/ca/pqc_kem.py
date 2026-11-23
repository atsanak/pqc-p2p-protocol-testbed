"""pqc_kem — ML-KEM-768 keypairs and encapsulate/decapsulate for `coap-enc`'s PQC upgrade
(2026-09-27, closing the gap PQC-bench/API/README.md's "PQC-bench" sweep first hit).

SEPARATE from pqc_ca.py deliberately: pqc_ca.py's `_run()` is hardwired to oqs-provider's
activation convention (`OPENSSL_CONF` pointing at ../oqs-openssl-priv.cnf, "openssl" on PATH) --
correct for ML-DSA-65 signing, which oqs-provider handles fully (encode+decode both work). It is
the WRONG tool for ML-KEM: confirmed live, 2026-09-27 (see management/pqc/ for the investigation)
that oqs-provider 0.11.0 registers ZERO encoders for any standalone KEM algorithm -- keygen
succeeds, writing the key to a file fails ("No encoders were found"), a documented upstream
limitation (open-quantum-safe/oqs-provider#84, #589), not a config mistake. OpenSSL 3.5+ has
ML-KEM as a NATIVE algorithm in its own "default" provider (no oqs-provider involved at all) with
full keygen/encode/encap/decap support -- verified live the same day: a real encapsulate/decapsulate
round-trip on a freshly built OpenSSL 3.5.8 produces the IDENTICAL shared secret both sides.

So this module needs a THIRD private openssl build, alongside the existing two (packaged
oqs-openssl.cnf for pqc_ca.py, private oqs-openssl-priv.cnf build for p2p's `pqc`/`pqkex` techs):
a plain OpenSSL 3.5+ build, no oqs-provider, no special OPENSSL_CONF at all -- ML-KEM/ML-DSA are
just there. See ../install-openssl35.sh.
"""
import os
import subprocess
from pathlib import Path

# A box can override this the same way PQC_OPENSSL_BIN overrides identity.py's private build --
# same idiom, different toolchain, never the system `openssl` (still can't do any of this).
KEM_OPENSSL = os.environ.get("PQC_KEM_OPENSSL_BIN", "/opt/pqc-libs/openssl35/bin/openssl")
KEM_LD_LIBRARY_PATH = os.environ.get("PQC_KEM_LD_LIBRARY_PATH", "/opt/pqc-libs/openssl35/lib64")
ALG = "ML-KEM-768"


def kem_env():
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = KEM_LD_LIBRARY_PATH
    # Deliberately no OPENSSL_CONF override -- ML-KEM/ML-DSA live in this build's OWN default
    # provider, unlike the oqs-provider bolt-on the other two toolchains need activated explicitly.
    env.pop("OPENSSL_CONF", None)
    return env


def kem_available() -> bool:
    return Path(KEM_OPENSSL).exists()


def _run(args, stdin=None):
    if not kem_available():
        raise RuntimeError(f"pqc_kem requires an OpenSSL 3.5+ build at {KEM_OPENSSL} "
                           f"(see PQC-bench/install-openssl35.sh) -- not the oqs-provider build")
    return subprocess.run([KEM_OPENSSL] + args, input=stdin, capture_output=True,
                          env=kem_env(), check=True)


def issue_kem(kem_dir, name):
    """Mint `name`'s ML-KEM-768 keypair into `kem_dir/<name>.key` (private, 0600) and
    `kem_dir/<name>.pub` (public -- this is the file that gets DISTRIBUTED to every peer that
    wants to encrypt to `name`, same shape as a cert but there is no CA/chain here: a raw KEM
    public key has nothing to sign, and the fleet CA already vouches for the classical/ML-DSA
    identity this key is provisioned ALONGSIDE, not standing alone). Idempotent, like
    `pqc_ca.issue()` -- an existing keypair is returned untouched, never re-minted (a peer that
    already has your old public key would silently fail to decrypt to a re-minted one)."""
    d = Path(kem_dir)
    d.mkdir(parents=True, exist_ok=True)
    key, pub = d / f"{name}.key", d / f"{name}.pub"
    if key.exists() and pub.exists():
        return str(key), str(pub)
    _run(["genpkey", "-algorithm", ALG, "-out", str(key)])
    os.chmod(key, 0o600)
    _run(["pkey", "-in", str(key), "-pubout", "-out", str(pub)])
    return str(key), str(pub)


def encapsulate(peer_pub_path):
    """-> (shared_secret: bytes, ciphertext: bytes). The SENDER's half: encapsulate a fresh shared
    secret TO the peer's public key -- only the matching private key can recover it."""
    secret_path, ct_path = None, None
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        secret_path, ct_path = Path(td) / "secret.bin", Path(td) / "ct.bin"
        _run(["pkeyutl", "-encap", "-inkey", str(peer_pub_path), "-pubin",
              "-secret", str(secret_path), "-out", str(ct_path)])
        return secret_path.read_bytes(), ct_path.read_bytes()


def decapsulate(own_key_path, ciphertext: bytes):
    """-> shared_secret: bytes. The RECEIVER's half: recover the secret the sender encapsulated,
    using this node's own ML-KEM-768 private key."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        ct_path, secret_path = Path(td) / "ct.bin", Path(td) / "secret.bin"
        ct_path.write_bytes(ciphertext)
        _run(["pkeyutl", "-decap", "-inkey", str(own_key_path),
              "-secret", str(secret_path), "-in", str(ct_path)])
        return secret_path.read_bytes()
