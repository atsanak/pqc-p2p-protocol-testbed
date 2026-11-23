"""p2p/common/coap_crypto — CoAP payload CONFIDENTIALITY (2026-07-26, security-hardening pass).

CoAP's envelope (cert+sig, see coap_server.py's own docstring for why: no TLS handshake to lean on)
already gave INTEGRITY -- a forged sender is caught -- but the payload itself travelled in
cleartext, readable by anyone who can see the UDP traffic. This module adds confidentiality on top,
without touching that existing sig/identity check at all: hybrid encryption, RSA-2048-OAEP wrapping
a fresh AES-256-GCM key per message (standard hybrid scheme -- RSA alone can't encrypt an
arbitrary-length JSON payload; AES alone has no public-key story for "encrypt to a peer I only
have the CERT for, not a shared secret").

Isolated in its OWN module, not identity.py: this is the only place in the whole P2P codebase that
needs the third-party `cryptography` package (everything else shells out to openssl-CLI, per
mtls_ca.py's own docstring on why -- the CoAP-role device/gateway VMs have `cryptography` installed
already, unlike the Server's container). Keeping the import here means a `cryptography` problem on
some box only breaks CoAP encryption, never the signing/chain-verification identity.py the whole
rest of P2P depends on.
"""
import base64
import os
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_KEY_BYTES = 32      # AES-256
NONCE_BYTES = 12        # standard GCM nonce size

# ── PQC coap-enc (2026-09-27): ML-KEM-768 replacing RSA-OAEP for the key-wrap step ─────────────
# Needs a THIRD private openssl build, distinct from both PQC-bench's oqs-provider ones
# (identity.py's PQC_OPENSSL / pqc_ca.py's packaged config): oqs-provider registers ZERO encoders
# for any standalone KEM algorithm (confirmed live, upstream-documented --
# open-quantum-safe/oqs-provider#84/#589), so it can mint an ML-KEM-768 key but never write it to
# a file. OpenSSL 3.5+ has ML-KEM as a NATIVE algorithm in its own default provider -- no
# oqs-provider involved, full keygen/export/encapsulate/decapsulate. This shells out to it exactly
# the way identity.py shells out to its own private build, for the same reason (no Python binding
# for either toolchain exists here) -- see PQC-bench/ca/pqc_kem.py for the CA-side keypair minting
# this pairs with (deliberately NOT imported here; p2p/common never imports PQC-bench's Python,
# only shells out to the same openssl binaries it also uses -- see identity.py's own PQC section).
KEM_OPENSSL = os.environ.get("PQC_KEM_OPENSSL_BIN", "/opt/pqc-libs/openssl35/bin/openssl")
KEM_LD_LIBRARY_PATH = os.environ.get("PQC_KEM_LD_LIBRARY_PATH", "/opt/pqc-libs/openssl35/lib64")
# Own KEM identity is looked up relative to the SAME cache dir the classical/ML-DSA-65 PQC material
# already lives under (`identity.PQC_CACHE_DIR_DEFAULT`) -- a peer's cert-vs-KEM-key split is a
# provisioning detail, not something callers should have to know two different paths for.
KEM_CACHE_DIR_DEFAULT = "/var/lib/p2p/certs-pqc"


def kem_available() -> bool:
    return Path(KEM_OPENSSL).exists()


def _kem_env():
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = KEM_LD_LIBRARY_PATH
    env.pop("OPENSSL_CONF", None)   # native provider, unlike the oqs-provider builds -- no config needed
    return env


def own_kem_key_path(cache_dir=None) -> str:
    return str(Path(cache_dir or KEM_CACHE_DIR_DEFAULT) / "kem" / "own.key")


def peer_kem_pub_path(peer_name: str, cache_dir=None) -> str:
    """Where a PEER's public key lives once provisioned -- see PQC-bench/ca/pqc_kem.py's own
    docstring on why this is a raw public key file, not embedded in their signing cert."""
    return str(Path(cache_dir or KEM_CACHE_DIR_DEFAULT) / "kem-peers" / f"{peer_name}.pub")


_KEY_CACHE = {}


def load_private_key(path):
    """This node's own private key, parsed ONCE per process (re-parsed if the file changes).

    `load_pem_private_key()` re-validates an RSA key on every load (primality of p and q): 218 ms on a Pi 5,
    and the old `decrypt_with()` paid it on EVERY coap-enc message (receiver `decrypt_ms` 223 ms against 4 ms
    for coap-pqc). The key is this node's own file, issued by the fleet CA and read from a 0600 path, so the
    validation only repeats work done at issuance: skipped (`unsafe_skip_rsa_key_validation`) and the parsed
    key kept in memory, which the receiver process holds for the same purpose anyway."""
    st = os.stat(path)
    stamp = (st.st_mtime_ns, st.st_size)
    hit = _KEY_CACHE.get(path)
    if hit and hit[0] == stamp:
        return hit[1]
    with open(path, "rb") as f:
        pem = f.read()
    try:
        key = serialization.load_pem_private_key(pem, password=None, unsafe_skip_rsa_key_validation=True)
    except TypeError:               # a cryptography too old to know the flag: the stock (slow) load
        key = serialization.load_pem_private_key(pem, password=None)
    _KEY_CACHE[path] = (stamp, key)
    return key


def encrypt_for(peer_cert_pem: str, plaintext: bytes) -> dict:
    """-> {"wrapped_key": b64, "nonce": b64, "ciphertext": b64} — encrypt `plaintext` with a fresh
    AES-256-GCM key, then wrap that key with `peer_cert_pem`'s RSA public key (OAEP/SHA-256).
    Only the holder of the matching PRIVATE key (the peer this cert belongs to) can recover the
    AES key and therefore the plaintext."""
    pub = x509.load_pem_x509_certificate(_first_cert(peer_cert_pem).encode()).public_key()
    aes_key = os.urandom(AES_KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped_key = pub.encrypt(aes_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return {
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_with(own_key_path: str, envelope: dict) -> bytes:
    """-> the original plaintext, using THIS node's own private key (own_key_path) to unwrap the
    AES key, then AES-GCM to decrypt+authenticate the ciphertext. Raises on any tamper (wrong key,
    flipped ciphertext bit, wrong nonce) -- AES-GCM's own tag check, not a separate step."""
    priv = load_private_key(own_key_path)
    aes_key = priv.decrypt(base64.b64decode(envelope["wrapped_key"]), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


def encrypt_for_kem(peer_pub_path: str, plaintext: bytes) -> dict:
    """PQC coap-enc's `encrypt_for()`: -> {"kem_ct": b64, "nonce": b64, "ciphertext": b64}.
    ML-KEM-768 encapsulate a fresh shared secret TO `peer_pub_path` (their standalone KEM public
    key file, see `peer_kem_pub_path()`), HKDF-SHA256 it into a clean AES-256 key (a raw KEM
    secret is never used directly as a symmetric key -- standard hybrid-PKE hygiene, and cheap:
    one HKDF call), then the identical AES-256-GCM step `encrypt_for()` already does. Same
    envelope SHAPE as `encrypt_for()` (nonce/ciphertext keys), only `wrapped_key` becomes `kem_ct`
    -- deliberately a different key name, so a receiver that gets the wrong tech's envelope by
    mistake fails on a missing dict key immediately, not on a garbled RSA-unwrap attempt."""
    if not kem_available():
        raise RuntimeError(f"PQC coap-enc requires an OpenSSL 3.5+ build at {KEM_OPENSSL} "
                           f"(see PQC-bench/install-openssl35.sh)")
    with tempfile.TemporaryDirectory() as td:
        secret_path, ct_path = Path(td) / "secret.bin", Path(td) / "ct.bin"
        subprocess.run([KEM_OPENSSL, "pkeyutl", "-encap", "-inkey", peer_pub_path, "-pubin",
                       "-secret", str(secret_path), "-out", str(ct_path)],
                      env=_kem_env(), capture_output=True, check=True)
        shared_secret, kem_ct = secret_path.read_bytes(), ct_path.read_bytes()
    aes_key = HKDF(algorithm=hashes.SHA256(), length=AES_KEY_BYTES, salt=None,
                   info=b"p2p-pqc-coap-enc-2026-09-27").derive(shared_secret)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    return {
        "kem_ct": base64.b64encode(kem_ct).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_with_kem(own_kem_key_path: str, envelope: dict) -> bytes:
    """PQC coap-enc's `decrypt_with()`: recover the shared secret this node's own ML-KEM-768
    private key can decapsulate from `envelope["kem_ct"]`, derive the SAME AES key via the
    identical HKDF call `encrypt_for_kem()` used, then AES-GCM decrypt+authenticate. Raises on any
    tamper, exactly like `decrypt_with()` -- AES-GCM's own tag check."""
    if not kem_available():
        raise RuntimeError(f"PQC coap-enc requires an OpenSSL 3.5+ build at {KEM_OPENSSL} "
                           f"(see PQC-bench/install-openssl35.sh)")
    with tempfile.TemporaryDirectory() as td:
        ct_path, secret_path = Path(td) / "ct.bin", Path(td) / "secret.bin"
        ct_path.write_bytes(base64.b64decode(envelope["kem_ct"]))
        subprocess.run([KEM_OPENSSL, "pkeyutl", "-decap", "-inkey", own_kem_key_path,
                       "-secret", str(secret_path), "-in", str(ct_path)],
                      env=_kem_env(), capture_output=True, check=True)
        shared_secret = secret_path.read_bytes()
    aes_key = HKDF(algorithm=hashes.SHA256(), length=AES_KEY_BYTES, salt=None,
                   info=b"p2p-pqc-coap-enc-2026-09-27").derive(shared_secret)
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


def _first_cert(cert_pem: str) -> str:
    """A cert_pem may be a leaf+intermediate bundle (see mtls_ca._chain_pem) -- the public key we
    need to encrypt against is the LEAF's (the actual peer), always the first cert in the file."""
    marker = "-----END CERTIFICATE-----"
    idx = cert_pem.find(marker)
    return cert_pem if idx == -1 else cert_pem[:idx + len(marker)]
