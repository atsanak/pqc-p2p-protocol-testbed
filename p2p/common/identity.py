"""p2p/common/identity — TLS 1.3 mTLS setup + the real resolve()/authorize() calls (no stand-in, §0b).

Certs are issued by the SAME CA as the Router-PC/announce system (p2p-plan..md §7 Q6 — reuse, not a
second CA): `fetch_own_cert()` calls the Server's POST /p2p-cert once, then caches cert/key/ca PEMs
locally so every later start is a pure disk read, not a network call. Built with stdlib `ssl` (an
OpenSSL binding) + `urllib` on purpose — per p2p-requirements.md's "openssl tls 1.3" ask, hand-rolled
rather than adding a framework dependency neither Device-PC nor Gateway-PC declare today.
"""
import base64
import fcntl
import json
import os
import re
import ssl
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from . import errors


def _post(server_api_base, path, body, bootstrap_secret, timeout=10, extra_headers=None):
    headers = {"Content-Type": "application/json", "X-Bootstrap-Secret": bootstrap_secret}
    headers.update(extra_headers or {})
    req = urllib.request.Request(
        server_api_base.rstrip("/") + path, data=json.dumps(body).encode(),
        headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _get(server_api_base, path, bootstrap_secret, timeout=10, extra_headers=None):
    headers = {"X-Bootstrap-Secret": bootstrap_secret}
    headers.update(extra_headers or {})
    req = urllib.request.Request(server_api_base.rstrip("/") + path, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def node_identity_headers(name, cache_dir=None):
    """-> {"X-Node-Cert": b64, "X-Node-Sig": b64} if `name` has a cached P2P identity (its own
    peer.crt/peer.key), else {} (falls back to bootstrap-secret-only, unchanged behavior).

    2026-07-26, control-plane hardening: lets `resolve()`/comm-log reporting prove identity via
    signature instead of relying on the fleet-wide shared secret alone, once a node has enrolled --
    reuses the server's already-established `_check_node_identity` idiom (same one `/node-bundle`
    has used since Phase 3 J), just extended to two more call sites. Signs the BARE `name` (matches
    `_check_node_identity`'s expected payload exactly -- no colon a node name could ever contain,
    so this can never collide with the `announcer:anchor` shape `/announce` signs instead).
    Best-effort: any failure here (e.g. a mid-rotation cert) falls back to secret-only rather than
    breaking the call outright -- the bootstrap secret remains a valid fallback, this only ever
    ADDS a stronger option on top."""
    d = Path(cache_dir or os.environ.get("P2P_CACHE_DIR", "/var/lib/p2p/certs"))
    cert_path, key_path = d / "peer.crt", d / "peer.key"
    if not (cert_path.exists() and key_path.exists()):
        return {}
    try:
        sig = sign_payload(str(key_path), name.encode())
        return {"X-Node-Cert": base64.b64encode(cert_path.read_bytes()).decode(),
                "X-Node-Sig": base64.b64encode(sig).decode()}
    except Exception:                                     # noqa: BLE001 -- best-effort, see docstring
        return {}


def fetch_own_cert(server_api_base, bootstrap_secret, name, cache_dir):
    """-> (cert_path, key_path, ca_path). Idempotent: a cached leaf is reused untouched (the
    server's mtls_ca.issue() is itself cache-backed too, so this is safe to call on every boot).

    BUG FIX (2026-08-23, found live doing a real build_first_time.sh round trip on virtual-vm2):
    every node runs at least TWO independent processes that call this at cold start against the
    SAME cache_dir/name -- p2p-receiver.service and p2p-coap-receiver.service, started by systemd
    within moments of each other, neither aware of the other. With no cache on disk yet, both used
    to race the server's POST /p2p-cert concurrently. The server's own issue() is cache-backed and
    idempotent (fine on its own), but /p2p-cert's SECURITY contract is not: the FIRST call mints a
    fresh, non-revoked cert; the SECOND call arrives moments later and is flatly rejected 401
    ("already holds a valid P2P cert ... present the node's own cert") -- which it doesn't have,
    since it never got a response of its own. That process then crash-loops on 401 FOREVER, even
    though the cache_dir it's about to write to already holds everything it needs, written by its
    sibling process a moment before. Confirmed live: stopping both, clearing the cache, and
    starting them ONE AT A TIME (not concurrently) let both enrol cleanly using the exact same
    code path -- proving this is a pure cold-start race, not a server-side defect. A local flock
    over cache_dir serializes the two ON THIS BOX ONLY: the loser blocks until the winner has
    finished writing, then re-checks the cache instead of racing the network call a second time.
    Does not change behavior for the (overwhelmingly common) single-caller case beyond one extra
    uncontended flock."""
    d = Path(cache_dir)
    d.mkdir(parents=True, exist_ok=True)
    cert_path, key_path, ca_path = d / "peer.crt", d / "peer.key", d / "ca.crt"
    if cert_path.exists() and key_path.exists() and ca_path.exists():
        return str(cert_path), str(key_path), str(ca_path)
    lock_path = d / ".fetch_own_cert.lock"
    with open(lock_path, "w") as lockf:
        fcntl.flock(lockf, fcntl.LOCK_EX)
        try:
            # Re-check: a sibling process (e.g. the other of p2p-receiver/p2p-coap-receiver) may
            # have already won the race and populated the cache while we were waiting on the lock.
            if cert_path.exists() and key_path.exists() and ca_path.exists():
                return str(cert_path), str(key_path), str(ca_path)
            try:
                r = _post(server_api_base, "/p2p-cert", {"name": name}, bootstrap_secret)
            except Exception as e:
                raise errors.IdentityError(f"could not fetch a P2P cert for '{name}' from {server_api_base}: {e}")
            cert_path.write_text(r["cert_pem"])
            key_path.write_text(r["key_pem"])
            key_path.chmod(0o600)
            ca_path.write_text(r["ca_pem"])
            return str(cert_path), str(key_path), str(ca_path)
        finally:
            fcntl.flock(lockf, fcntl.LOCK_UN)


def fetch_peer_cert(server_api_base, bootstrap_secret, name):
    """-> another node's PUBLIC cert PEM (never a private key -- see /p2p-peer-cert's docstring).
    2026-07-26, CoAP confidentiality: the sender needs this to wrap a payload's AES key with the
    RECEIVER's RSA public key. Not cached client-side (unlike fetch_own_cert) -- a peer's cert
    could change (revoke + re-issue) between messages, and this is a lightweight lookup, not a
    per-boot identity fetch."""
    try:
        r = _post(server_api_base, "/p2p-peer-cert", {"name": name}, bootstrap_secret)
    except Exception as e:
        raise errors.IdentityError(f"could not fetch {name}'s public cert from {server_api_base}: {e}")
    return r["cert_pem"]


RESOLVE_CACHE_MAX_AGE_S = 900  # matches Server-PC/Server/app/router_routes.py's MAX_AGE_S precedent


def _resolve_cache_path(name, cache_dir=None):
    d = Path(cache_dir or os.environ.get("P2P_CACHE_DIR", "/var/lib/p2p/certs")) / "resolve-cache"
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return d / f"{safe}.json"


def resolve(server_api_base, bootstrap_secret, name, frm=None, cache_dir=None):
    """The real GET /resolve — no netplan.json stand-in (p2p-plan..md §0b: "Stage A no longer waits
    on Router-PC Stage 2/3", so there's nothing to stand in for). -> {ip, via_chain, ...}.
    When `frm` is given, also attaches a cert-proof of `frm`'s identity if one is cached (2026-07-26
    control-plane hardening — see `node_identity_headers`); the bootstrap secret is still sent
    either way, so an older/not-yet-enrolled caller is unaffected.

    2026-08-08, unreachable-Server degrade: a live answer is cached locally on every success; if
    the Server can't be reached, a cache younger than RESOLVE_CACHE_MAX_AGE_S is served instead of
    refusing the exchange outright, with "stale"/"stale_age_s" added so the caller can log it
    rather than silently trust it. Past that age, or with no cache at all, behavior is unchanged
    (raise, refuse) -- this only ever narrows a real outage window, never masks a stale route
    indefinitely."""
    path = f"/resolve?name={name}" + (f"&from={frm}" if frm else "")
    extra = node_identity_headers(frm) if frm else None
    cache_path = _resolve_cache_path(name, cache_dir)
    try:
        r = _get(server_api_base, path, bootstrap_secret, extra_headers=extra)
    except Exception as e:
        try:
            age = time.time() - cache_path.stat().st_mtime
            if age <= RESOLVE_CACHE_MAX_AGE_S:
                cached = json.loads(cache_path.read_text())
                cached["stale"] = True
                cached["stale_age_s"] = int(age)
                return cached
        except (OSError, ValueError):
            pass
        raise errors.ResolveError(f"resolve('{name}') failed against {server_api_base}: {e}")
    if not r.get("ok"):
        raise errors.ResolveError(f"resolve('{name}') returned not-ok: {r}")
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(r))
    except OSError:
        pass
    return r


def authorize(server_api_base, bootstrap_secret, sender, receiver, use_case=None):
    """The real GET /p2p-authorize — the §4.3 join, evaluated server-side so every peer sees the
    same live policy state. -> (allowed: bool, reason: str). `use_case` (optional) lets the Server
    apply its per-use-case cross-tenant blocklist; an older Server ignores it."""
    path = f"/p2p-authorize?sender={sender}&receiver={receiver}"
    if use_case:
        path += f"&use_case={use_case}"
    r = _get(server_api_base, path, bootstrap_secret)
    return bool(r.get("allowed")), r.get("reason", "")


# 2026-10-23, found on the wire: the classical techs (mtls, https) were NOT classical on the Pis -- their system
# OpenSSL 3.5 offers X25519MLKEM768 first by default, so every mtls/https handshake negotiated the hybrid. The
# classical contexts now pin classical groups: the sender offers X25519 only; the receiver accepts X25519 / P-256 /
# P-384 (classical clients that cannot do X25519 still connect, a hybrid-only client is refused). The PQC builders
# below re-pin to ML-KEM-768.
CLASSICAL_CLIENT_GROUPS = "X25519"
CLASSICAL_SERVER_GROUPS = "X25519:P-256:P-384"


def _pin_classical(ctx, groups):
    try:
        return pin_tls_groups(ctx, groups)
    except errors.IdentityError:
        if ssl.OPENSSL_VERSION_INFO >= (3, 5):   # this OpenSSL would quietly offer the hybrid: refuse instead
            raise
        return ctx                                  # older OpenSSL: its defaults are classical anyway


def build_server_context(cert_path, key_path, ca_path):
    """TLS 1.3, mutual auth, receiver side (§3.2). CERT_REQUIRED means the handshake itself refuses
    a certless or wrong-CA peer — before any application/policy code runs at all."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.load_verify_locations(cafile=ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return _pin_classical(ctx, CLASSICAL_SERVER_GROUPS)


def build_client_context(cert_path, key_path, ca_path, client_cert=True):
    """TLS 1.3, mutual auth, sender side. `check_hostname=False` because the CN is the node NAME
    (§3.2), not a DNS hostname a client connecting by IP would match — identity is verified
    explicitly by CN after the handshake — see sender-role/client.py:_connect(), which calls
    peer_identity() and additionally binds the cert's SAN IP to the resolved /32. (2026-07-28: that
    check genuinely exists now; before then this docstring described an intention, not the code.)

    `client_cert=False` (2026-07-28) is the `https` tech: send NO client certificate, so the
    handshake authenticates the receiver only and the sender's identity has to come from a signed
    envelope in the body instead. Everything about how we verify THEM is unchanged — same CA, same
    CERT_REQUIRED, same post-handshake CN/SAN binding. Only our own half is dropped."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca_path)
    if client_cert:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return _pin_classical(ctx, CLASSICAL_CLIENT_GROUPS)


def build_https_server_context(cert_path, key_path):
    """TLS 1.3, receiver side, SERVER-AUTHENTICATED ONLY — the `https` tech's listener (2026-07-28).

    CERT_NONE, deliberately and only here: this port's whole point is to serve peers that present
    no client certificate, so the handshake cannot be the identity gate. The gate moves into the
    application instead — receiver-role/server.py refuses any request on this listener that does not
    carry a signed envelope whose cert chains to the fleet CA and whose CN is the claimed sender,
    and the ordinary per-pair policy check then runs exactly as it does on the mTLS port.

    This is strictly weaker than build_server_context() (a stranger reaches the application before
    being refused, instead of being refused by OpenSSL), which is why it is a SEPARATE listener:
    the mTLS port keeps its handshake-level gate untouched."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.verify_mode = ssl.CERT_NONE
    return _pin_classical(ctx, CLASSICAL_SERVER_GROUPS)


# ── in-process fast paths (2026-10-23 audit) ────────────────────────────────────────────────────
# Every envelope tech (https, pqc, coap-*) used to cost the receiver 40-65 ms per request in `verify_ms`
# and the sender ~10 ms per signature, almost all of it process spawns: `openssl verify`, `openssl x509
# -subject`, `openssl x509 -pubkey` + `openssl dgst -verify` (4 forks) per request, `openssl dgst -sign`
# per signature. The classical checks below now run in-process with the `cryptography` package when it is
# importable (it is on every peer image; the Server container may lack it -- see coap_crypto.py's note),
# and fall back to the original openssl CLI calls otherwise OR whenever the fast path cannot give a
# definite answer. The PQC variants (their own openssl binary / provider env) are untouched.
#   * sign / verify of a payload: RSA PKCS#1 v1.5 + SHA-256 and ECDSA + SHA-256 -- byte-for-byte what
#     `openssl dgst -sha256 -sign/-verify` does with those keys.
#   * CN / SAN-IP of a leaf: read from the parsed certificate.
#   * chain verification: NOT re-implemented (cryptography's verifier applies purpose/EKU rules that
#     `openssl verify` does not, which would change who is accepted). The openssl verdict is CACHED instead:
#     only a "chains to the CA" True, keyed by (CA file stamp, certificate bytes), for at most
#     P2P_CHAIN_CACHE_TTL_S (300 s) and never past the leaf's own notAfter. Neither path checks revocation.
_CRYPTO = None


def _crypto():
    """-> the cryptography bits the fast paths need, or None (cached)."""
    global _CRYPTO
    if _CRYPTO is None:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
            _CRYPTO = (x509, hashes, serialization, padding, rsa, ec)
        except Exception:                                   # noqa: BLE001 -- any import problem = no fast path
            _CRYPTO = False
    return _CRYPTO or None


def _fast_ok(openssl_bin, env, digest=None):
    """The fast paths cover the classical default only: the plain `openssl` binary with the process env."""
    return openssl_bin == "openssl" and env is None and digest in (None, "-sha256") and _crypto() is not None


_PARSED_CERTS = {}


def _first_cert(cert_pem):
    """The first certificate of a PEM (bundle), parsed once (small bounded cache); None if unparseable."""
    c = _crypto()
    key = cert_pem if isinstance(cert_pem, str) else None
    if key is not None and key in _PARSED_CERTS:
        return _PARSED_CERTS[key]
    m = _CERT_RE.search(cert_pem or "")
    cert = None
    if m:
        try:
            cert = c[0].load_pem_x509_certificate(m.group(0).encode())
        except Exception:                                   # noqa: BLE001
            cert = None
    if key is not None and cert is not None:
        if len(_PARSED_CERTS) >= 256:
            _PARSED_CERTS.clear()
        _PARSED_CERTS[key] = cert
    return cert


_SIGN_KEYS = {}


def _sign_key(key_path):
    """The signing key, parsed once per (path, mtime, size). RSA keys skip the primality re-validation that
    costs ~218 ms per load on a Pi (see coap_crypto.load_private_key)."""
    c = _crypto()
    st = os.stat(key_path)
    stamp = (st.st_mtime_ns, st.st_size)
    hit = _SIGN_KEYS.get(key_path)
    if hit and hit[0] == stamp:
        return hit[1]
    with open(key_path, "rb") as f:
        pem = f.read()
    try:
        key = c[2].load_pem_private_key(pem, password=None, unsafe_skip_rsa_key_validation=True)
    except TypeError:
        key = c[2].load_pem_private_key(pem, password=None)
    _SIGN_KEYS[key_path] = (stamp, key)
    return key


def _fast_sign(key_path, payload):
    c = _crypto()
    key = _sign_key(key_path)
    if isinstance(key, c[4].RSAPrivateKey):
        return key.sign(payload, c[3].PKCS1v15(), c[1].SHA256())
    if isinstance(key, c[5].EllipticCurvePrivateKey):
        return key.sign(payload, c[5].ECDSA(c[1].SHA256()))
    raise TypeError("key type not covered by the fast path")


def _fast_verify(cert_pem, payload, signature):
    """True / False for RSA and EC leaves; None when it cannot decide (caller falls back to openssl)."""
    c = _crypto()
    cert = _first_cert(cert_pem)
    if cert is None:
        return None
    pub = cert.public_key()
    try:
        if isinstance(pub, c[4].RSAPublicKey):
            pub.verify(signature, payload, c[3].PKCS1v15(), c[1].SHA256())
        elif isinstance(pub, c[5].EllipticCurvePublicKey):
            pub.verify(signature, payload, c[5].ECDSA(c[1].SHA256()))
        else:
            return None
        return True
    except Exception as e:                                  # noqa: BLE001
        from cryptography.exceptions import InvalidSignature
        return False if isinstance(e, InvalidSignature) else None


def sign_payload(key_path, payload: bytes, openssl_bin="openssl", digest="-sha256", env=None) -> bytes:
    """Sign `payload` with this node's own private key -- the CoAP transport's identity proof
    (§3.2's "same identity ... different codec"): aiocoap's CoAP-over-TLS support is explicitly
    early-WIP upstream, so CoAP doesn't get a literal handshake-level peer cert the way the HTTP
    transport does. Same idiom the codebase already uses for exactly this situation
    (api_server.py's `_check_announcer_identity` proves identity over plain HTTP via cert+signature
    rather than a TLS client-cert handshake) -- reused here, not invented fresh.

    `openssl_bin`/`env`/`digest` are overridable so the SAME function serves the PQC path (see
    `sign_payload_pqc` below) -- a different openssl binary + provider env, and no external digest
    (ML-DSA is a "pure" signature scheme, FIPS 204 -- it hashes internally, same idiom as Ed25519
    already needs via this exact command with no -shaNNN flag)."""
    if digest == "-sha256" and _fast_ok(openssl_bin, env, digest):
        try:
            return _fast_sign(key_path, payload)
        except Exception:                                   # noqa: BLE001 -- openssl below gives the real error
            pass
    args = [openssl_bin, "dgst"] + ([digest] if digest else []) + ["-sign", key_path]
    return subprocess.run(args, input=payload, capture_output=True, check=True, env=env).stdout


_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


_CHAIN_OK = {}      # (ca stamp, sha256(cert_pem)) -> expiry (epoch s); only successes are kept
CHAIN_CACHE_TTL_S = float(os.environ.get("P2P_CHAIN_CACHE_TTL_S", "300"))


def _chain_cache_key(ca_path, cert_pem, openssl_bin, env):
    if CHAIN_CACHE_TTL_S <= 0 or openssl_bin != "openssl" or env is not None or _crypto() is None:
        return None
    try:
        st = os.stat(ca_path)
    except OSError:
        return None
    import hashlib
    return (ca_path, st.st_mtime_ns, st.st_size, hashlib.sha256(cert_pem.encode()).hexdigest())


def _chain_cache_put(key, leaf_pem):
    """Remember a verified chain until the TTL or the leaf's notAfter, whichever is first."""
    expiry = time.time() + CHAIN_CACHE_TTL_S
    try:
        cert = _first_cert(leaf_pem)
        na = getattr(cert, "not_valid_after_utc", None)      # cryptography >= 42
        if na is None:                                       # older: naive datetime, UTC
            import datetime
            na = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        expiry = min(expiry, na.timestamp())
    except Exception:                                       # noqa: BLE001 -- unknown expiry: do not cache
        return
    if len(_CHAIN_OK) >= 512:
        _CHAIN_OK.clear()
    _CHAIN_OK[key] = expiry


def verify_chain(ca_path, cert_pem: str, openssl_bin="openssl", env=None) -> bool:
    """True if `cert_pem` chains to our CA (a self-signed impostor with a matching-looking CN
    fails this even though `leaf_cn()` would still read a CN off it).

    `cert_pem` may be a single leaf OR a leaf+intermediate(s) bundle concatenated together
    (2026-07-26+: `mtls_ca.issue()`/`pqc_ca.issue()` hand back the full chain whenever a leaf was
    signed via an intermediate, since the TLS transports' own handshake needs it). This function
    has no TLS handshake to lean on -- it's the receiver-role application-level check the CoAP
    transport uses instead (see coap_server.py's docstring) -- so it must split the bundle itself:
    verify ONLY the first (leaf) cert, offering any remaining certs to `-untrusted` as chain-
    building candidates, exactly what a TLS stack would do automatically with a peer-presented
    chain. Verifying just the split-out leaf (not the whole multi-cert blob) matters: `openssl
    verify` given multiple certs on one input checks EACH one independently and prints one result
    per cert, so a naive `"OK" in output` check across the whole bundle could pass on a fine
    intermediate while missing that the actual leaf failed."""
    certs = _CERT_RE.findall(cert_pem)
    if not certs:
        return False
    cache_key = _chain_cache_key(ca_path, cert_pem, openssl_bin, env)
    if cache_key is not None:
        exp = _CHAIN_OK.get(cache_key)
        if exp is not None and exp > time.time():
            return True
    leaf = certs[0]
    args = [openssl_bin, "verify", "-CAfile", ca_path]
    untrusted_path = None
    if len(certs) > 1:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as tf:
            tf.write("\n".join(certs[1:]))
            untrusted_path = tf.name
        args += ["-untrusted", untrusted_path]
    try:
        p = subprocess.run(args, input=leaf, text=True, capture_output=True, env=env)
        ok = p.returncode == 0 and "OK" in p.stdout
    finally:
        if untrusted_path:
            os.unlink(untrusted_path)
    if ok and cache_key is not None:
        _chain_cache_put(cache_key, certs[0])
    return ok


def verify_payload_signature(cert_pem: str, payload: bytes, signature: bytes,
                              openssl_bin="openssl", digest="-sha256", env=None) -> bool:
    """True if `signature` verifies against `cert_pem`'s public key -- proof the sender holds the
    matching PRIVATE key, not merely a copy of someone else's public cert."""
    if _fast_ok(openssl_bin, env, digest) and digest == "-sha256":
        verdict = _fast_verify(cert_pem, payload, signature)
        if verdict is not None:
            return verdict
    pub = subprocess.run([openssl_bin, "x509", "-pubkey", "-noout"], input=cert_pem, text=True,
                        capture_output=True, check=True, env=env).stdout
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pub") as pf, \
         tempfile.NamedTemporaryFile(suffix=".sig") as sf:
        pf.write(pub); pf.flush()
        sf.write(signature); sf.flush()
        args = [openssl_bin, "dgst"] + ([digest] if digest else []) + \
               ["-verify", pf.name, "-signature", sf.name]
        p = subprocess.run(args, input=payload, capture_output=True, env=env)
        return p.returncode == 0


def leaf_cn(cert_pem: str, openssl_bin="openssl", env=None) -> str | None:
    """-> the CN a leaf cert asserts, for the identity check after chain+signature both pass."""
    if _fast_ok(openssl_bin, env):
        cert = _first_cert(cert_pem)
        if cert is not None:
            try:
                cns = cert.subject.get_attributes_for_oid(_crypto()[0].NameOID.COMMON_NAME)
                return cns[-1].value if cns else None
            except Exception:                               # noqa: BLE001 -- openssl below decides
                pass
    txt = subprocess.run([openssl_bin, "x509", "-noout", "-subject"], input=cert_pem, text=True,
                         capture_output=True, check=True, env=env).stdout
    for line in txt.splitlines():
        if line.startswith("subject=") and "CN" in line:
            return line.split("CN")[-1].lstrip(" =").split(",")[0].strip()
    return None


def leaf_san_ips(cert_pem: str, openssl_bin="openssl", env=None) -> list[str]:
    """-> every SAN IP a leaf cert carries -> [str, ...] (never raises; [] on any parse failure).

    monitor.md §3.8.2 phase 0/1: the SAN-IP binding is read off a LIVE TLS socket for mtls/https
    (`_cert_facts()` above) -- CoAP has no socket, only a PEM, so this is the CoAP-side equivalent.
    Same idiom `verify_chain()`/`leaf_cn()` already use (the openssl CLI, not the `cryptography`
    package, so this has no new dependency): `openssl x509 -ext subjectAltName` on the FIRST PEM
    block (a leaf+intermediate bundle's own leaf, exactly what `leaf_cn()` already reads for the
    same input).  The PQC binary takes the parsed-certificate path too (2026-10-23): reading a SAN needs no
    key support, and cryptography parses ML-DSA certificates."""
    if _fast_ok(openssl_bin, env) or (openssl_bin == PQC_OPENSSL and _crypto() is not None):
        cert = _first_cert(cert_pem)
        if cert is not None:
            try:
                x509 = _crypto()[0]
                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                except x509.ExtensionNotFound:
                    return []
                ips = san.get_values_for_type(x509.IPAddress)
                if all(ip.version == 4 for ip in ips):      # IPv6 text differs from openssl's: use openssl
                    return [str(ip) for ip in ips]
            except Exception:                               # noqa: BLE001 -- openssl below decides
                pass
    try:
        r = subprocess.run([openssl_bin, "x509", "-noout", "-ext", "subjectAltName"],
                           input=cert_pem, text=True, capture_output=True, env=env)
    except OSError:
        return []
    if r.returncode != 0:
        return []
    ips = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if "IP Address:" not in line:
            continue
        ips.extend(v.split("IP Address:", 1)[1].strip() for v in line.split(",")
                  if v.strip().startswith("IP Address:"))
    return ips


# ── replay protection (2026-07-26, security-hardening pass) ────────────────────────────────────
# Applies to the PQC and CoAP envelopes specifically -- neither rides a live, per-connection TLS
# handshake the way classical HTTP mTLS does, so a captured valid envelope (sniffed off the wire,
# or read back out of the comm-log mirror) could otherwise be replayed verbatim and would still
# pass chain+signature+CN checks. Binding a timestamp INTO what's signed closes this: forging a new
# timestamp on a replay requires forging a new signature too, which requires the private key.
MAX_ENVELOPE_AGE_S = 60


def signable_with_ts(payload_bytes: bytes, ts: int) -> bytes:
    """Canonical bytes to sign/verify for a freshness-bound envelope. `ts` rides ALONGSIDE the
    payload in what gets signed, not folded into the application-level payload dict itself."""
    return payload_bytes + b"|ts:" + str(ts).encode()


def check_freshness(ts, max_age=MAX_ENVELOPE_AGE_S):
    """-> (ok, reason). True if `ts` (unix seconds) is within `max_age` of now, either direction --
    a little clock skew is normal; anything past the window is either a stale retry or a
    captured-and-replayed envelope, and either way it's no longer within its legitimate window."""
    delta = abs(time.time() - ts)
    if delta > max_age:
        return False, f"envelope timestamp is {delta:.0f}s from now (max {max_age}s) — stale or replayed"
    return True, None


# ── PQC mode (2026-07-26, operator-directed override of pqc-requirements.md's "stays separate" ──
# scope): a user-selectable ADDITION, not a replacement. Classical mTLS above still carries every
# connection (transport encryption + the primary peer-identity gate, unchanged, still the default);
# PQC mode layers an ML-DSA-65-signed envelope of the payload on top, verified independently. Full
# PQC-native TLS 1.3 isn't reachable from here: Python's stdlib `ssl` binds to the SYSTEM OpenSSL
# (3.0.20), which pqc-progress.md already proved cannot serve/verify provider-native PQC certs at
# all (`unknown certificate type`, ssl_rsa.c:240) -- rebuilding CPython's _ssl against a different
# OpenSSL is out of scope. So PQC here reuses the SAME sign/verify idiom the CoAP transport already
# needed for exactly this reason (no handshake-level peer cert available) via PQC-bench's private
# OpenSSL 3.4 + oqs-provider build (see PQC-bench/pqc_ca.py, pqc-progress.md) -- a second,
# independent, quantum-resistant proof of authenticity/integrity riding alongside the classical one,
# not standing in for it.
PQC_OPENSSL = os.environ.get("PQC_OPENSSL_BIN", "/opt/pqc-libs/openssl-priv/bin/openssl")
PQC_OPENSSL_CONF = os.environ.get("PQC_OPENSSL_CONF", "/opt/PQC-bench/oqs-openssl-priv.cnf")
PQC_LD_LIBRARY_PATH = os.environ.get(
    "PQC_LD_LIBRARY_PATH", "/opt/pqc-libs/liboqs-priv/lib:/opt/pqc-libs/openssl-priv/lib64")
PQC_CACHE_DIR_DEFAULT = "/var/lib/p2p/certs-pqc"   # separate from the classical cache -- different CA


def pqc_env():
    """Env for every PQC-flavored openssl subprocess call: activates oqs-provider (OPENSSL_CONF)
    and makes the loader pick up liboqs-priv/openssl-priv FIRST (run-gateway-proxy.sh's own
    comment: oqsprovider.so has no embedded RPATH, so without this it silently picks up whatever
    liboqs happens to be on the system's default library path -- an ABI mismatch that segfaults on
    the first real use, not a clean error)."""
    env = dict(os.environ)
    env["OPENSSL_CONF"] = PQC_OPENSSL_CONF
    env["LD_LIBRARY_PATH"] = PQC_LD_LIBRARY_PATH
    return env


def pqc_available() -> bool:
    """Best-effort capability check -- PQC mode is opt-in per node (not every P2P node has the
    toolchain built), so callers should check this before offering/using it rather than crashing."""
    return Path(PQC_OPENSSL).exists() and Path(PQC_OPENSSL_CONF).exists()


def load_pqc_material(cache_dir=None):
    """-> (cert_path, key_path, ca_path) for THIS node's PQC identity. Unlike `fetch_own_cert()`
    there is no live issuance endpoint for PQC certs (pqc_ca.py is a bolt-on script, not a server
    route, per pqc-requirements.md's "separate, additive harness" framing) -- a leaf gets minted
    once (PQC-bench/ca/pqc_ca.py issue <name> <ip> <tenant>) and its cert+key+the CA root are
    provisioned into `cache_dir` out of band. Raises IdentityError with a clear, actionable message
    if that hasn't happened yet, rather than a bare FileNotFoundError."""
    d = Path(cache_dir or PQC_CACHE_DIR_DEFAULT)
    cert_path, key_path, ca_path = d / "peer.crt", d / "peer.key", d / "ca.crt"
    if not (cert_path.exists() and key_path.exists() and ca_path.exists()):
        raise errors.IdentityError(
            f"no PQC identity cached at {d} -- mint one with PQC-bench/ca/pqc_ca.py issue "
            f"<name> <ip> <tenant> and provision peer.crt/peer.key/ca.crt here first")
    return str(cert_path), str(key_path), str(ca_path)


# ── PQC fast paths (2026-10-23) ─────────────────────────────────────────────────────────────────────
# Found while proving the v2 metrics: every ML-DSA-65 envelope cost 4-5 `openssl` PROCESSES (sign; chain, CN,
# pubkey + verify) -- receiver verify_ms 26.8 ms on quic-pqc vs 0.9 ms for the classical envelope, which has had
# in-process sign/verify + a cached chain verdict since the fast-path pass above. That is process-spawn cost, not
# ML-DSA cost, and it was being reported as "PQC overhead". Same fast-path shape as the classical one now:
#   * ML-DSA-65 sign / verify in-process through the system libcrypto (OpenSSL >= 3.5 implements FIPS 204
#     natively -- the library Python's ssl already uses for the `pqc` handshake). Pure ML-DSA, empty context:
#     byte-compatible with `openssl dgst -sign` under oqs-provider, proven both ways on the Pis 2026-10-23.
#   * CN read from the parsed certificate (cryptography parses ML-DSA certificates; only the key object is not
#     available to it, which is why libcrypto does the signature).
#   * the chain verdict cached exactly as the classical one (successes only, TTL, never past notAfter).
# Anything the fast path cannot decide (no OpenSSL 3.5, a key type other than ML-DSA, a parse/library error)
# falls back to the oqs-provider CLI exactly as before -- never to "accept".
_LIBCRYPTO = None
_PQC_KEYS = {}        # key_path -> ((mtime_ns, size), EVP_PKEY*)
_PQC_PUBS = {}        # cert_pem -> (X509*, EVP_PKEY* borrowed from it)


def _libcrypto():
    """The system libcrypto bound for ML-DSA via ctypes, or None (cached) when it is not OpenSSL >= 3.5."""
    global _LIBCRYPTO
    if _LIBCRYPTO is None:
        try:
            import ctypes
            lib = ctypes.CDLL("libcrypto.so.3")
            P, I, S, C = ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t, ctypes.c_char_p
            for fn, args, res in (("OpenSSL_version_num", [], ctypes.c_ulong), ("BIO_new_mem_buf", [C, I], P),
                                  ("BIO_free", [P], I), ("PEM_read_bio_PrivateKey", [P, P, P, P], P),
                                  ("PEM_read_bio_X509", [P, P, P, P], P), ("X509_get0_pubkey", [P], P),
                                  ("X509_free", [P], None), ("EVP_PKEY_get0_type_name", [P], C),
                                  ("EVP_MD_CTX_new", [], P), ("EVP_MD_CTX_free", [P], None),
                                  ("EVP_DigestSignInit_ex", [P, P, C, P, C, P, P], I),
                                  ("EVP_DigestSign", [P, P, ctypes.POINTER(S), C, S], I),
                                  ("EVP_DigestVerifyInit_ex", [P, P, C, P, C, P, P], I),
                                  ("EVP_DigestVerify", [P, C, S, C, S], I)):
                f = getattr(lib, fn)
                f.argtypes, f.restype = args, res
            _LIBCRYPTO = lib if lib.OpenSSL_version_num() >= 0x30500000 else False
        except Exception:                                   # noqa: BLE001 -- no usable libcrypto: CLI path
            _LIBCRYPTO = False
    return _LIBCRYPTO or None


def _is_mldsa(lib, pkey):
    name = lib.EVP_PKEY_get0_type_name(pkey) if pkey else None
    return bool(name) and name.startswith(b"ML-DSA")


def _pqc_fast_sign(key_path, payload):
    """-> the ML-DSA signature, or None when the fast path cannot do it."""
    import ctypes
    lib = _libcrypto()
    if lib is None:
        return None
    st = os.stat(key_path)
    stamp = (st.st_mtime_ns, st.st_size)
    hit = _PQC_KEYS.get(key_path)
    if hit and hit[0] == stamp:
        pkey = hit[1]
    else:
        with open(key_path, "rb") as f:
            pem = f.read()
        bio = lib.BIO_new_mem_buf(pem, len(pem))
        pkey = lib.PEM_read_bio_PrivateKey(bio, None, None, None)
        lib.BIO_free(bio)
        if not _is_mldsa(lib, pkey):
            return None
        _PQC_KEYS[key_path] = (stamp, pkey)
    ctx = lib.EVP_MD_CTX_new()
    try:
        n = ctypes.c_size_t(0)
        if lib.EVP_DigestSignInit_ex(ctx, None, None, None, None, pkey, None) != 1 or \
                lib.EVP_DigestSign(ctx, None, ctypes.byref(n), payload, len(payload)) != 1:
            return None
        buf = ctypes.create_string_buffer(n.value)
        if lib.EVP_DigestSign(ctx, buf, ctypes.byref(n), payload, len(payload)) != 1:
            return None
        return buf.raw[:n.value]
    finally:
        lib.EVP_MD_CTX_free(ctx)


def _pqc_fast_verify(cert_pem, payload, signature):
    """True / False for an ML-DSA leaf (the first certificate of the PEM); None when it cannot decide."""
    lib = _libcrypto()
    m = _CERT_RE.search(cert_pem or "")
    if lib is None or not m:
        return None
    hit = _PQC_PUBS.get(cert_pem)
    if hit is None:
        leaf = m.group(0).encode()
        bio = lib.BIO_new_mem_buf(leaf, len(leaf))
        x509 = lib.PEM_read_bio_X509(bio, None, None, None)
        lib.BIO_free(bio)
        if not x509:
            return None
        pub = lib.X509_get0_pubkey(x509)
        if not _is_mldsa(lib, pub):
            lib.X509_free(x509)
            return None
        if len(_PQC_PUBS) >= 256:
            for x, _p in _PQC_PUBS.values():
                lib.X509_free(x)
            _PQC_PUBS.clear()
        hit = _PQC_PUBS[cert_pem] = (x509, pub)
    ctx = lib.EVP_MD_CTX_new()
    try:
        if lib.EVP_DigestVerifyInit_ex(ctx, None, None, None, None, hit[1], None) != 1:
            return None
        r = lib.EVP_DigestVerify(ctx, signature, len(signature), payload, len(payload))
        return True if r == 1 else (False if r == 0 else None)
    finally:
        lib.EVP_MD_CTX_free(ctx)


def sign_payload_pqc(key_path, payload: bytes) -> bytes:
    try:
        sig = _pqc_fast_sign(key_path, payload)
        if sig:
            return sig
    except Exception:                                       # noqa: BLE001 -- the CLI below gives the real error
        pass
    return sign_payload(key_path, payload, openssl_bin=PQC_OPENSSL, digest=None, env=pqc_env())


def verify_chain_pqc(ca_path, cert_pem: str) -> bool:
    key = _chain_cache_key(ca_path, cert_pem, "openssl", None)       # same key scheme, tagged as the PQC CA's
    key = ("pqc",) + key if key is not None else None
    if key is not None:
        exp = _CHAIN_OK.get(key)
        if exp is not None and exp > time.time():
            return True
    ok = verify_chain(ca_path, cert_pem, openssl_bin=PQC_OPENSSL, env=pqc_env())
    if ok and key is not None:
        certs = _CERT_RE.findall(cert_pem)
        if certs:
            _chain_cache_put(key, certs[0])
    return ok


def verify_payload_signature_pqc(cert_pem: str, payload: bytes, signature: bytes) -> bool:
    try:
        verdict = _pqc_fast_verify(cert_pem, payload, signature)
        if verdict is not None:
            return verdict
    except Exception:                                       # noqa: BLE001 -- the CLI below decides
        pass
    return verify_payload_signature(cert_pem, payload, signature,
                                    openssl_bin=PQC_OPENSSL, digest=None, env=pqc_env())


def leaf_cn_pqc(cert_pem: str) -> str | None:
    if _crypto() is not None:
        cert = _first_cert(cert_pem)
        if cert is not None:
            try:
                cns = cert.subject.get_attributes_for_oid(_crypto()[0].NameOID.COMMON_NAME)
                return cns[-1].value if cns else None
            except Exception:                               # noqa: BLE001 -- openssl below decides
                pass
    return leaf_cn(cert_pem, openssl_bin=PQC_OPENSSL, env=pqc_env())


# ── PQC TLS 1.3 over TCP: the `pqc` tech (2026-10-23) ──────────────────────────────────
# The owner's rule: "pqc" means ML-KEM-768 key establishment AND ML-DSA-65 authentication in the protocol
# itself. Python's own `ssl` does both here -- the Pis' system OpenSSL is 3.5 (native ML-KEM and ML-DSA) and
# loads the ML-DSA-65 PKI in /var/lib/p2p/certs-pqc -- but Python 3.13 has no API to choose the key-exchange
# group, and OpenSSL 3.5's default list prefers the X25519MLKEM768 hybrid. So the group list is set through
# libssl itself (SSL_CTX_set1_groups_list), on the SSL_CTX the SSLContext wraps, and every handshake's
# negotiated group is read back (SSL_get_negotiated_group) and asserted by both ends. Both pointers are
# sanity-checked against what Python reports before use, so a layout mismatch raises instead of pinning
# nothing.
PQC_TLS_GROUP = "MLKEM768"
_SSL_CTRL_SET_GROUPS_LIST = 92
_SSL_CTRL_GET_NEGOTIATED_GROUP = 134
_LIBSSL = None


def _libssl():
    global _LIBSSL
    if _LIBSSL is None:
        import ctypes
        lib = ctypes.CDLL("libssl.so.3")          # the libssl the `_ssl` module already loaded
        P, I, L = ctypes.c_void_p, ctypes.c_int, ctypes.c_long
        for fn, args, res in (("SSL_CTX_ctrl", [P, I, L, P], L), ("SSL_ctrl", [P, I, L, P], L),
                              ("SSL_CTX_get_verify_mode", [P], I), ("SSL_CTX_get_options", [P], ctypes.c_uint64),
                              ("SSL_get_SSL_CTX", [P], P), ("SSL_get_version", [P], ctypes.c_char_p),
                              ("SSL_group_to_name", [P, I], ctypes.c_char_p)):
            f = getattr(lib, fn)
            f.argtypes, f.restype = args, res
        _LIBSSL = lib
    return _LIBSSL


def _ctx_ptr(ctx):
    """SSL_CTX* of a Python SSLContext (CPython: the first field after PyObject_HEAD), verified."""
    import ctypes
    lib = _libssl()
    head = ctypes.sizeof(ctypes.c_ssize_t) + ctypes.sizeof(ctypes.c_void_p)
    ptr = ctypes.c_void_p.from_address(id(ctx) + head).value
    want_mode = {ssl.CERT_NONE: 0, ssl.CERT_OPTIONAL: 1, ssl.CERT_REQUIRED: 3}[ctx.verify_mode]
    if not ptr or lib.SSL_CTX_get_verify_mode(ptr) & 1 != want_mode & 1 \
            or lib.SSL_CTX_get_options(ptr) != int(ctx.options):
        raise errors.IdentityError("cannot locate the SSL_CTX behind this SSLContext -- refusing to run "
                                   "a PQC handshake without its ML-KEM-768 group pin")
    return ptr


def pin_tls_groups(ctx, groups=PQC_TLS_GROUP):
    """Restrict an SSLContext's key-exchange groups (e.g. "MLKEM768"). Raises if OpenSSL refuses."""
    if _libssl().SSL_CTX_ctrl(_ctx_ptr(ctx), _SSL_CTRL_SET_GROUPS_LIST, 0, groups.encode()) != 1:
        raise errors.IdentityError(f"this OpenSSL ({ssl.OPENSSL_VERSION}) refused the group list {groups!r}")
    return ctx


def negotiated_group(sslsocket):
    """The key-exchange group a finished TLS handshake negotiated ("MLKEM768", "x25519", ...), or None."""
    import ctypes
    try:
        obj = sslsocket._sslobj
        lib = _libssl()
        head = ctypes.sizeof(ctypes.c_ssize_t) + ctypes.sizeof(ctypes.c_void_p)
        ptr = ctypes.c_void_p.from_address(id(obj) + head + ctypes.sizeof(ctypes.c_void_p)).value
        if not ptr or lib.SSL_get_SSL_CTX(ptr) != _ctx_ptr(sslsocket.context) \
                or (lib.SSL_get_version(ptr) or b"").decode() != sslsocket.version():
            return None
        name = lib.SSL_group_to_name(ptr, lib.SSL_ctrl(ptr, _SSL_CTRL_GET_NEGOTIATED_GROUP, 0, None))
        return name.decode() if name else None
    except Exception:                                       # noqa: BLE001 -- None = "could not tell"
        return None


def build_pqc_client_context(cert_path, key_path, ca_path, client_cert=True):
    """`pqc` (client_cert=True): TLS 1.3, ML-KEM-768 only, the receiver's ML-DSA-65 certificate checked against
    the PQC CA, and this node's ML-DSA-65 leaf presented as its identity. The CN /
    SAN check of who answered is the caller's, exactly as for mtls/https (client.py `_connect`)."""
    ctx = build_client_context(cert_path, key_path, ca_path, client_cert=client_cert)
    return pin_tls_groups(ctx)


def build_pqc_server_context(cert_path, key_path, ca_path, mutual):
    """The receiver's `pqc` listener (mutual=True: an ML-DSA-65 client certificate from the PQC CA is REQUIRED
    by the handshake; mutual=False builds a server-auth-only variant, unused by the P2P techs): TLS 1.3, ML-KEM-768 only, this node's ML-DSA-65 leaf."""
    ctx = build_server_context(cert_path, key_path, ca_path) if mutual \
        else build_https_server_context(cert_path, key_path)
    return pin_tls_groups(ctx)


def tls_info(sslsocket):
    """-> the negotiated facts of one live TLS connection, or {} if the socket can't tell us
    (a plain socket, or one already closed).

        tls_version   "TLSv1.3"
        tls_cipher    "TLS_AES_256_GCM_SHA384"
        tls_bits      256                     — the cipher's symmetric strength
        tls_lib       "OpenSSL 3.0.20 …"      — the library that ran the handshake
        tls_ca        "MARNE-P2P-CA"          — CN of the issuer of the PEER's cert
        tls_peer_key  "RSA-2048"              — the peer cert's public key type/size
        tls_peer_sig  "sha256WithRSAEncryption" — how that cert is signed

    2026-07-28, management/fix.md "Third fixes": the GUI's `tech` column used to say a bare `mtls`,
    and the operator asked it to "show more details e.g. TLS: openssl 1.3", then (same day) that
    mTLS still showed "no details of implementation". These are facts that can only be read HERE —
    off the negotiated connection itself, by whichever peer is holding it — not reconstructed later
    from the record. Reported into the comm-log mirror, so `tech` states what the exchange actually
    negotiated rather than what the code was configured to prefer.

    The last three describe the certificate that made this mTLS rather than plain TLS: WHICH CA
    vouched for the peer, and what key/signature that vouching actually uses. Every field is
    individually optional — an older peer, a pre-handshake failure, or a build without
    `cryptography` simply reports fewer of them and the GUI degrades to what it was given.
    """
    try:
        version = sslsocket.version()
        cipher = sslsocket.cipher()
        peercert = sslsocket.getpeercert()
        peerder = sslsocket.getpeercert(binary_form=True)
    except (AttributeError, OSError, ValueError):
        return {}
    if not version:
        return {}
    info = {"tls_version": version,
            "tls_cipher": cipher[0] if cipher else None,
            # cipher is (name, protocol, secret_bits) — the third element is the symmetric strength
            # actually negotiated, not the strength the suite name merely implies.
            "tls_bits": cipher[2] if cipher and len(cipher) > 2 else None,
            "tls_lib": ssl.OPENSSL_VERSION}
    info.update(_cert_facts(peercert, peerder))
    return {k: v for k, v in info.items() if v is not None}


# ML-DSA (FIPS 204) OIDs: the same OID names the public key and the certificate's signature algorithm.
_MLDSA_OIDS = {"2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
               "2.16.840.1.101.3.4.3.19": "ML-DSA-87"}


def _rdn_cn(rdns):
    """CN out of getpeercert()'s subject/issuer shape: ((("commonName", "x"),), (("O", "y"),))."""
    for rdn in rdns or ():
        for attr, value in rdn:
            if attr == "commonName":
                return value
    return None


def _cert_facts(peercert, peerder):
    """The mTLS half of tls_info: who signed the peer's cert, and with what.

    The issuer CN comes out of the stdlib's own parse (no dependency). The key type/size and
    signature algorithm need a real X.509 parse, so they go through `cryptography` — present on
    every peer image today, but imported inside the try so a build without it loses these two
    fields instead of losing the whole record's TLS detail."""
    facts = {"tls_ca": _rdn_cn((peercert or {}).get("issuer"))}
    if not peerder:
        return facts
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
        cert = x509.load_der_x509_certificate(peerder)
        oid = cert.signature_algorithm_oid
        facts["tls_peer_sig"] = _MLDSA_OIDS.get(oid.dotted_string) or getattr(oid, "_name", None) or oid.dotted_string
        try:
            pub = cert.public_key()
        except Exception:                 # an ML-DSA key on a `cryptography` too old to load one (43 on the Pis)
            key_oid = getattr(cert, "public_key_algorithm_oid", None)
            facts["tls_peer_key"] = _MLDSA_OIDS.get(getattr(key_oid, "dotted_string", None))
            return facts
        if isinstance(pub, rsa.RSAPublicKey):
            facts["tls_peer_key"] = f"RSA-{pub.key_size}"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            facts["tls_peer_key"] = f"EC-{pub.curve.name}"
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            facts["tls_peer_key"] = "Ed25519"
        else:
            facts["tls_peer_key"] = type(pub).__name__
    except Exception:
        pass          # descriptive only — never let a cert-parsing quirk break an exchange's report
    return facts


def cert_facts_from_pem(cert_pem):
    """tls_ca / tls_peer_key / tls_peer_sig of the first certificate in a PEM -- the same facts `tls_info`
    reads off a live TLS socket, for the transports whose handshake runs in a helper process (QUIC, DTLS)
    and hands back only the peer's certificate. {} if it cannot be parsed."""
    c = _crypto()
    cert = _first_cert(cert_pem) if c else None
    if cert is None:
        return {}
    try:
        cns = cert.issuer.get_attributes_for_oid(c[0].NameOID.COMMON_NAME)
        issuer = ((("commonName", cns[0].value),),) if cns else ()
        facts = _cert_facts({"issuer": issuer}, cert.public_bytes(c[2].Encoding.DER))
    except Exception:                                       # noqa: BLE001 -- descriptive only
        return {}
    return {k: v for k, v in facts.items() if v is not None}


def peer_identity(sslsocket):
    """-> CN of the TLS peer's cert, the ONLY identity authorize() at the transport layer trusts
    (p2p-plan..md §4.3 — "the identity comes from the peer certificate, never the request body")."""
    cert = sslsocket.getpeercert()
    if not cert:
        raise errors.IdentityError("no peer certificate presented")
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    raise errors.IdentityError("peer certificate has no CN")
