#!/usr/bin/env python3
"""quic_pqc_relay.py — the receiver side of `quic-pqc` (2026-09-28, Stack 5) and
`quic-pqc-mutual` (2026-09-28, Stack 6): terminates a real hybrid-PQC TLS 1.3 handshake INSIDE a
real QUIC connection (X25519MLKEM768 + ML-DSA-65 server cert, and in mutual mode a client cert
too), then a real HTTP/3 request over it, and forwards the decoded request as a genuine HTTP/1.1
request to `server.py`'s own plain `http` listener (P2P_HTTP_PORT, :8442) — the SAME plaintext
backend `http`/`https`/`pqkex`/`pqkex-mutual` already forward to, one way or another. server.py
never sees anything different about this tech: headers (including the X-P2P-* envelope headers
every certless tech already relies on) pass through verbatim.

MUTUAL MODE (`P2P_QUIC_PQC_MUTUAL=1`, own port 4434) -- same additive shape every other mutual
variant here uses (pqkex-mutual, coap-dtls-pqc-mutual): `quic-pqc`'s own :4433 stays server-auth
only, untouched. Two things this needed that Stack 5 didn't:
  1. `_request_client_certificate = True` on the server's tls.Context -- aioquic's OWN TLS 1.3
     CertificateRequest/Certificate/CertificateVerify flow (already generic over key type, no
     patch needed: `_check_certificate_verify_signature` already covers MLDSA65 from the Stack 5
     patch) is there but OFF by default ("For test purposes only" in aioquic's own source).
  2. Confirmed live: aioquic verifies the client cert's SIGNATURE server-side (proves the client
     holds the matching private key) but never its CHAIN to a CA -- `verify_certificate()` is
     called ONLY on the client's own path (`_client_handle_certificate_verify`), nowhere in the
     server's (`_server_handle_certificate_verify`). This is an aioquic gap, not a patch
     regression: unlike TLS libraries that make server-side client-cert-chain-verification
     automatic, aioquic leaves it as the app's job here. So this relay does its OWN chain+CN
     check against the quic-pqc CA after HandshakeCompleted, before forwarding anything --
     same "transport does structural verification, app does identity check" split this project's
     other mutual techs already use, just with an extra step aioquic doesn't do for you.

Runs under the dedicated `/opt/pqc-libs/quic-pqc-venv` interpreter (aioquic + cryptography,
hybrid-PQC patched) — own process, own port, same "separate toolchain, separate process" shape
every other real-handshake PQC tech here uses (p2p-pqc-proxy's stunnel, coap_dtls_pqc_relay.py).

CLASSICAL-CERT MODE (`QUIC_CERT_MODE=classical`, 2026-09-29, video streaming's "hybrid HTTP/3" cell):
OPT-IN, default unchanged. Keeps the hybrid X25519MLKEM768 key exchange but authenticates with the
fleet's CLASSICAL RSA leaf (`$QUIC_CLASSICAL_CERT_DIR`, default /var/lib/p2p/certs: peer.crt =
leaf+intermediate, peer.key, ca.crt = root) instead of an ML-DSA cert minted from the quic-pqc CA.
The cert files are loaded READ-ONLY -- nothing is minted or written in this mode (the default mode
overwrites server.crt/key in its cert dir on every start). In mutual mode the client's leaf is
verified (chain + dates, aioquic.tls.verify_certificate) against that directory's ca.crt, and the
signature algorithms offered are the stock RSA/ECDSA ones instead of MLDSA65 only.

Usage:  /opt/pqc-libs/quic-pqc-venv/bin/python3 quic_pqc_relay.py
Env:    P2P_QUIC_PQC_PORT (default 4433, or 4434 if P2P_QUIC_PQC_MUTUAL=1), P2P_HTTP_PORT
        (default 8442), QUIC_PQC_CERT_DIR (default /var/lib/p2p/certs-quic-pqc),
        P2P_QUIC_PQC_MUTUAL (0/1, default 0), QUIC_CERT_MODE (pqc|classical, default pqc),
        QUIC_CLASSICAL_CERT_DIR (default /var/lib/p2p/certs; classical mode only)
"""
import asyncio
import http.client
import json
import os
import sys

sys.path.insert(0, "/opt/PQC-bench/ca")
# quic_pqc_ca mints the ML-DSA certificate of the DEFAULT mode only. Classical-cert mode
# (QUIC_CERT_MODE=classical) loads the fleet's RSA leaf read-only and never calls it, so a box that
# only serves the classical / hybrid ports does not need the module to exist (2026-10-02: found when
# the new quic-hybrid / quic-classical relays were tested on a box with an older /opt/PQC-bench/ca).

from aioquic import tls as aioquic_tls
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from cryptography import x509
from cryptography.x509.oid import NameOID

CERT_DIR = os.environ.get("QUIC_PQC_CERT_DIR", "/var/lib/p2p/certs-quic-pqc")
MUTUAL = os.environ.get("P2P_QUIC_PQC_MUTUAL", "0") == "1"
QUIC_PORT = int(os.environ.get("P2P_QUIC_PQC_PORT", "4434" if MUTUAL else "4433"))
HTTP_PORT = int(os.environ.get("P2P_HTTP_PORT", "8442"))
CLASSICAL = os.environ.get("QUIC_CERT_MODE", "pqc") == "classical"
CLASSICAL_DIR = os.environ.get("QUIC_CLASSICAL_CERT_DIR", "/var/lib/p2p/certs")
# QUIC_GROUPS (opt-in, default unset = unchanged): comma list of aioquic Group names this relay's SERVER
# side will accept (e.g. "X25519" = a genuinely CLASSICAL listener that refuses an X25519MLKEM768-only
# client; video streaming's classical HTTP/3 tier, :4439/:4440).
QUIC_GROUPS = [g.strip().upper() for g in os.environ.get("QUIC_GROUPS", "").split(",") if g.strip()]
if QUIC_GROUPS == ["*"]:          # explicit opt-out: accept whatever the client's first key share is
    QUIC_GROUPS = []
elif not QUIC_GROUPS and not CLASSICAL:
    # 2026-10-23 audit: the ML-DSA relay (`quic-pqc`, `quic-pqc-mutual`) used to leave this unset, and
    # aioquic's server takes the client's FIRST key share without consulting its own supported groups, so
    # a classical X25519-only client completed a "post-quantum" handshake with it. Pinned to the hybrid
    # group by default now, exactly as the quic-hybrid / quic-classical units pin theirs.
    # 2026-10-23 (owner: "PQC always means ML-KEM-768 and ML-DSA-65"): the PURE ML-KEM-768 group, not the hybrid.
    QUIC_GROUPS = ["MLKEM768"]

if QUIC_GROUPS:
    # aioquic's server takes the client's FIRST key_share without consulting its own supported groups,
    # so the restriction filters the parsed ClientHello: only key shares in QUIC_GROUPS survive, and a
    # client offering none of them (e.g. an X25519MLKEM768-only client) gets a handshake failure. The
    # transcript hash is computed from the raw bytes, so filtering the parsed list changes nothing else.
    _orig_pull_client_hello = aioquic_tls.pull_client_hello
    _missing = [g for g in QUIC_GROUPS if not hasattr(aioquic_tls.Group, g)]
    if _missing:
        sys.exit(f"[quic-pqc-relay] this aioquic has no group {_missing} -- apply "
                 f"PQC-bench/aioquic-patch/tls.py.patch (or add_mlkem768.py for MLKEM768) first")
    _ALLOWED_GROUPS = [getattr(aioquic_tls.Group, g) for g in QUIC_GROUPS]

    def _restricted_pull_client_hello(buf):
        hello = _orig_pull_client_hello(buf)
        if hello.key_share is not None:
            hello.key_share = [ks for ks in hello.key_share if ks[0] in _ALLOWED_GROUPS]
            if not hello.key_share:
                raise aioquic_tls.AlertHandshakeFailure("no acceptable key exchange group")
        return hello

    aioquic_tls.pull_client_hello = _restricted_pull_client_hello

# What THIS (server) side of each handshake observed, for the receiver's own log row: the group the client's
# first surviving key share names (that is the one aioquic's server uses), recorded by wrapping the ClientHello
# parser and read back by the Context subclass right after it handled the hello. Synchronous and single-threaded
# (one asyncio loop), so a module-level scratch dict cannot interleave two handshakes.
_HELLO_SEEN = {}
_pull_before_recording = aioquic_tls.pull_client_hello


def _recording_pull_client_hello(buf):
    hello = _pull_before_recording(buf)
    try:
        _HELLO_SEEN["group"] = aioquic_tls.Group(hello.key_share[0][0]).name
    except (TypeError, ValueError, IndexError):
        _HELLO_SEEN["group"] = None
    return hello


aioquic_tls.pull_client_hello = _recording_pull_client_hello
_BaseContext = aioquic_tls.Context


class _ObservingContext(_BaseContext):
    def _server_handle_hello(self, *a, **kw):
        _HELLO_SEEN.clear()
        super()._server_handle_hello(*a, **kw)
        self.observed_group = _HELLO_SEEN.get("group")


aioquic_tls.Context = _ObservingContext

_SIG_NAMES = {"2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
              "2.16.840.1.101.3.4.3.19": "ML-DSA-87"}


def _tls_facts(quic):
    """The receiver-side facts of one finished handshake, in the comm-log's tls_* vocabulary (+ `group`)."""
    tls = quic.tls
    facts = {"tls_version": "TLSv1.3", "group": getattr(tls, "observed_group", None)}
    try:
        cs = tls.key_schedule.cipher_suite
        facts["tls_cipher"] = "TLS_" + cs.name
        facts["tls_bits"] = 256 if ("256" in cs.name or "CHACHA20" in cs.name) else 128
    except Exception:  # noqa: BLE001 -- descriptive only
        pass
    cert = getattr(tls, "_peer_certificate", None)          # the CLIENT's leaf, on a mutual port
    if cert is not None:
        try:
            cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            facts["tls_ca"] = cn[0].value if cn else None
            oid = cert.signature_algorithm_oid.dotted_string
            facts["tls_peer_sig"] = _SIG_NAMES.get(oid) or getattr(cert.signature_algorithm_oid, "_name", oid)
            from cryptography.hazmat.primitives.asymmetric import rsa
            pub = cert.public_key()
            facts["tls_peer_key"] = f"RSA-{pub.key_size}" if isinstance(pub, rsa.RSAPublicKey) else _SIG_NAMES.get(oid)
        except Exception:  # noqa: BLE001
            pass
    return {k: v for k, v in facts.items() if v is not None}


def _verify_client_chain(cert, chain):
    """Chain check of a client leaf (raises on any failure). The one implementation behind BOTH the
    handshake-level enforcement in `_RequireClientCertContext` and `RelayProtocol._check_client_cert`."""
    if CLASSICAL:
        # RSA leaf + intermediate (sent in the handshake) -> the fleet root in ca.crt
        aioquic_tls.verify_certificate(cert, chain=list(chain), cafile=f"{CLASSICAL_DIR}/ca.crt")
    else:
        ca_cert = x509.load_pem_x509_certificate(open(f"{CERT_DIR}/ca.crt", "rb").read())
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        # 2026-10-23 (v2): the signature check above says WHO issued the leaf, not WHEN it is valid -- an
        # expired (or not-yet-valid) ML-DSA client certificate was accepted. The classical branch gets this
        # from aioquic's verify_certificate; the ML-DSA one checks it here, with the same alert.
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise aioquic_tls.AlertCertificateExpired(
                f"client certificate valid {cert.not_valid_before_utc:%Y-%m-%d} .. {cert.not_valid_after_utc:%Y-%m-%d}, "
                f"not now")


if MUTUAL:
    _OrigContext = aioquic_tls.Context

    class _RequireClientCertContext(_OrigContext):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            if not self._is_client:
                self._request_client_certificate = True
                # CertificateRequest advertises self._signature_algorithms as what it will
                # ACCEPT from the client -- the stock default list has no MLDSA65 entry, so
                # without this the client's negotiate() silently finds no match and sends an
                # EMPTY certificate (found live, 2026-09-28: "no client certificate presented"
                # even though the client's cert/key were loaded and valid).
                # (classical-cert mode keeps the stock RSA/ECDSA list: the client leaf is RSA)
                if not CLASSICAL:
                    self._signature_algorithms = [aioquic_tls.SignatureAlgorithm.MLDSA65]

        # 2026-10-23 audit: stock aioquic lets a client that sends NO certificate (or one that does not
        # chain to the CA) finish the handshake; this relay then refused it only at the HTTP layer with
        # a 403. Both are now refused INSIDE the handshake (TLS alert bad_certificate), so a stranger
        # never gets a connection at all. `_check_client_cert` below stays as a second line.
        def _server_handle_certificate(self, input_buf, output_buf):
            super()._server_handle_certificate(input_buf, output_buf)
            if self._peer_certificate is None:
                print("[quic-pqc-relay-mutual] REFUSED in handshake: no client certificate", flush=True)
                raise aioquic_tls.AlertBadCertificate("client certificate required")

        def _server_handle_certificate_verify(self, input_buf, output_buf):
            try:
                _verify_client_chain(self._peer_certificate, self._peer_certificate_chain)
            except Exception as e:  # noqa: BLE001 -- any failure is a refusal
                print(f"[quic-pqc-relay-mutual] REFUSED in handshake: client cert chain does not "
                      f"verify: {e}", flush=True)
                raise aioquic_tls.AlertBadCertificate("client certificate does not verify")
            super()._server_handle_certificate_verify(input_buf, output_buf)

    aioquic_tls.Context = _RequireClientCertContext

def _write_file(path, data, mode):
    """Write `data` to `path` with permissions `mode` (2026-10-03): a temp file created with that mode, then
    os.replace(). A plain open(path, "wb") left server.key world-readable (0644 under the default umask) and
    kept an older file's mode; the rename gives a new inode, so an existing 0644 key becomes 0600 at the
    next start. The rename is atomic, so the plain and mutual relays, which both write this same file at
    start, never read a half-written one."""
    tmp = f"{path}.{os.getpid()}.{os.urandom(4).hex()}.tmp"   # unique per call, not only per process
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(fd, mode)          # os.open's mode is filtered by the umask; set it exactly
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)


def _relay_tech():
    """The tech this relay instance IS, from how it was started (not from anything a client sent):
    ML-DSA certs -> quic-pqc; classical certs + X25519-only -> quic-classical; classical certs + hybrid
    group -> quic-hybrid; `-mutual` when it demands a client certificate. QUIC_RELAY_TECH overrides."""
    forced = os.environ.get("QUIC_RELAY_TECH", "").strip()
    if forced:
        return forced
    base = ("quic-pqc" if not CLASSICAL
            else "quic-classical" if QUIC_GROUPS == ["X25519"] else "quic-hybrid")
    return base + ("-mutual" if MUTUAL else "")


RELAY_TECH = _relay_tech()
RELAY_TECH_HEADER = "X-P2P-Relay-Tech"
RELAY_TLS_HEADER = "X-P2P-Relay-Tls"


def _forward(method, path, headers, body, tls_facts=None):
    """Genuine HTTP/1.1 request to server.py's plain backend -- the exact same call shape
    _http_exchange()'s own http.client call already makes, just proxied through this process.

    One addition (2026-10-23 audit): `X-P2P-Relay-Tech: <this relay's tech>`. The plain backend cannot
    tell a QUIC delivery from a plaintext one -- it saw `http` and logged every quic-* transfer as the
    plaintext tech. server.py honours this header ONLY on a loopback connection (this process), and
    only for the relay-fronted tech names, so a network client cannot use it to name its own tech. Any
    copy of the header a QUIC client sent is dropped first."""
    headers = {k: v for k, v in headers.items()
               if k.lower() not in (RELAY_TECH_HEADER.lower(), RELAY_TLS_HEADER.lower())}
    headers[RELAY_TECH_HEADER] = RELAY_TECH
    if tls_facts:       # what this relay's handshake observed: server.py puts it in the receiver's log row
        headers[RELAY_TLS_HEADER] = json.dumps(tls_facts, separators=(",", ":"))
    conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=30)
    try:
        conn.request(method, path, body=body or None, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class RelayProtocol(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._http = H3Connection(self._quic)
        self._req_headers = {}
        self._req_body = {}
        # None until HandshakeCompleted; then True/False -- see _check_client_cert().
        self._client_verified = None

    def quic_event_received(self, event):
        if MUTUAL and isinstance(event, HandshakeCompleted):
            self._client_verified = self._check_client_cert()
        for http_event in self._http.handle_event(event):
            self.h3_event_received(http_event)

    def _check_client_cert(self):
        """The chain+CN check aioquic itself does NOT do server-side (see module docstring) --
        this relay's own equivalent of `_client_handle_certificate_verify`'s `verify_certificate()`
        call, plus the CN==claimed-sender check `pqkex`/`coap-dtls-pqc`'s OWN client-side app code
        already runs against the server it connects to (same idea, opposite direction here)."""
        cert = self._quic.tls._peer_certificate
        if cert is None:
            print("[quic-pqc-relay-mutual] REJECTED: no client certificate presented", flush=True)
            return False
        try:
            _verify_client_chain(cert, self._quic.tls._peer_certificate_chain)
        except Exception as e:  # noqa: BLE001 -- any verify failure is a REJECT, not a crash
            print(f"[quic-pqc-relay-mutual] REJECTED: client cert chain does not verify: {e}",
                  flush=True)
            return False
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        print(f"[quic-pqc-relay-mutual] client cert verified: CN={cn}", flush=True)
        return True

    def h3_event_received(self, event):
        if isinstance(event, HeadersReceived):
            stream_id = event.stream_id
            headers = {}
            method = path = None
            for k, v in event.headers:
                k, v = k.decode(), v.decode()
                if k == ":method":
                    method = v
                elif k == ":path":
                    path = v
                elif not k.startswith(":"):
                    headers[k] = v
            self._req_headers[stream_id] = (method, path, headers)
            self._req_body.setdefault(stream_id, b"")
            if event.stream_ended:
                self._dispatch(stream_id)
        elif isinstance(event, DataReceived):
            stream_id = event.stream_id
            self._req_body[stream_id] = self._req_body.get(stream_id, b"") + event.data
            if event.stream_ended:
                self._dispatch(stream_id)

    def _dispatch(self, stream_id):
        method, path, headers = self._req_headers.pop(stream_id, (None, None, {}))
        body = self._req_body.pop(stream_id, b"")
        if method is None:
            return
        if MUTUAL and not self._client_verified:
            # Refuse to forward at all -- the handshake itself already logged why in
            # _check_client_cert(). Never reaches server.py's own auth layer with an
            # unverified transport identity behind it.
            status, resp_body = 403, b'{"error":"client certificate did not verify"}'
        else:
            try:
                status, resp_body = _forward(method, path, headers, body, _tls_facts(self._quic))
            except Exception as e:  # noqa: BLE001 -- reported as a 502, not a crashed relay
                status, resp_body = 502, str(e).encode()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[(b":status", str(status).encode())],
            end_stream=not resp_body,
        )
        if resp_body:
            self._http.send_data(stream_id=stream_id, data=resp_body, end_stream=True)
        self.transmit()

def _local_ipv4_addrs():
    """This box's global-scope IPv4 addresses (`ip -4 -o addr show scope global`); [] when `ip` fails."""
    import subprocess
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope", "global"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    addrs = []
    for line in out.splitlines():
        parts = line.split()
        if "inet" in parts and parts.index("inet") + 1 < len(parts):
            addrs.append(parts[parts.index("inet") + 1].split("/")[0])
    return sorted(set(addrs))


async def _serve_each_address(port, configuration, create_protocol, tag, bind_env):
    """Serve QUIC on `port` with one socket PER local IPv4 address (+ 127.0.0.1), never the 0.0.0.0
    wildcard (2026-10-03). A wildcard UDP socket answers from whatever source the ROUTE picks: on a
    gateway a client that dialled its anchor 10.2.1.1 got the handshake back from 10.2.0.10 (its wg0
    address), and aioquic never completed it ("ConnectionError" on T1-Rpi51 -> T1-Protectli2). Same
    cause and same fix as coap_dtls_pqc_relay.py ("Multi-homed reply address"). Addresses that appear
    later (wg0 after a slow boot) are picked up by a rescan every 60 s. $<bind_env>: "auto" (default),
    or a comma list of addresses ("0.0.0.0" restores the old wildcard). Never returns."""
    want = os.environ.get(bind_env, "auto").strip() or "auto"
    if want != "auto":
        for h in [x.strip() for x in want.split(",") if x.strip()]:
            await serve(h, port, configuration=configuration, create_protocol=create_protocol)
        print(f"[{tag}] bound {want} :{port} (from ${bind_env})", flush=True)
        await asyncio.Event().wait()
    bound, failed = set(), set()
    while True:
        for h in ["127.0.0.1"] + _local_ipv4_addrs():
            if h in bound:
                continue
            try:
                await serve(h, port, configuration=configuration, create_protocol=create_protocol)
                bound.add(h)
                failed.discard(h)
                print(f"[{tag}] bound {h}:{port}", flush=True)
            except OSError as e:          # vanished meanwhile, or in use: retried at the next scan
                if h not in failed:
                    print(f"[{tag}] cannot bind {h}:{port}: {e} (retrying every 60 s)", flush=True)
                failed.add(h)
        if not bound:
            raise SystemExit(f"[{tag}] could not bind any address on :{port}")
        await asyncio.sleep(60)


def _node_ips(configured):
    """configured IP(s) + every IP SAN of /var/lib/p2p/certs/peer.crt, de-duplicated; 0.0.0.0 only if nothing is known."""
    ips = [x.strip() for x in configured.split(",") if x.strip() and x.strip() != "0.0.0.0"]
    try:
        from cryptography import x509 as _x
        c = _x.load_pem_x509_certificate(open(f"{CLASSICAL_DIR}/peer.crt", "rb").read())
        ips += [str(i) for i in c.extensions.get_extension_for_class(_x.SubjectAlternativeName).value.get_values_for_type(_x.IPAddress)]
    except Exception:                                             # noqa: BLE001 -- no classical leaf yet
        pass
    return ",".join(dict.fromkeys(ips)) or "0.0.0.0"


def _refresh_own_client_identity(crt, key):
    """The box's own QUIC client identity (peer.crt/.key, used when it SENDS quic-pqc-mutual) is the same leaf. Replace it
    only when it is missing or does not cover the addresses the fresh leaf covers (a deficient one, as Rpi50's was)."""
    try:
        from cryptography import x509 as _x
        san = lambda b: set(_x.load_pem_x509_certificate(b).extensions.get_extension_for_class(_x.SubjectAlternativeName)
                            .value.get_values_for_type(_x.IPAddress))
        cur = open(f"{CERT_DIR}/peer.crt", "rb").read() if os.path.exists(f"{CERT_DIR}/peer.crt") else None
        if cur is None or not san(crt) <= san(cur):
            _write_file(f"{CERT_DIR}/peer.key", key, 0o600)
            _write_file(f"{CERT_DIR}/peer.crt", crt, 0o644)
    except Exception as e:                                        # noqa: BLE001 -- never stop the relay for this
        print(f"[quic-pqc-relay] could not refresh {CERT_DIR}/peer.crt: {e}", flush=True)


async def main():
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    if CLASSICAL:
        # read-only: the fleet's own RSA leaf, never minted/written here
        config.load_cert_chain(f"{CLASSICAL_DIR}/peer.crt", f"{CLASSICAL_DIR}/peer.key")
        shown_dir = CLASSICAL_DIR
    else:
        import quic_pqc_ca  # noqa: E402
        # 2026-10-23 (atsanak): bind the server certificate to the configured IP AND every IP of the box's classical
        # leaf (the Server issues that one with the addresses peers really dial): a box with two addresses, or a replaced
        # box whose drop-in names only one, still presents a certificate for the address it is dialled on.
        crt, key = quic_pqc_ca.issue(
            CERT_DIR, os.environ.get("QUIC_PQC_NODE_NAME", os.uname().nodename),
            _node_ips(os.environ.get("QUIC_PQC_NODE_IP", "")),
            os.environ.get("QUIC_PQC_TENANT", "T1"),
        )
        _write_file(f"{CERT_DIR}/server.crt", crt, 0o644)
        _write_file(f"{CERT_DIR}/server.key", key, 0o600)
        _refresh_own_client_identity(crt, key)
        config.load_cert_chain(f"{CERT_DIR}/server.crt", f"{CERT_DIR}/server.key")
        shown_dir = CERT_DIR
    print(f"[quic-pqc-relay{'-mutual' if MUTUAL else ''}] listening on :{QUIC_PORT} (each local IPv4 address)"
          f"{' (client cert REQUIRED)' if MUTUAL else ''}, forwarding to "
          f"127.0.0.1:{HTTP_PORT}, CA at {shown_dir}/ca.crt"
          f"{' (classical RSA certs' if CLASSICAL else ''}"
          f"{(', KEX ' + '/'.join(QUIC_GROUPS) + ' only') if CLASSICAL and QUIC_GROUPS else (', hybrid KEX' if CLASSICAL else '')}"
          f"{')' if CLASSICAL else ''}", flush=True)
    await _serve_each_address(QUIC_PORT, config, RelayProtocol,
                              f"quic-pqc-relay{'-mutual' if MUTUAL else ''}", "QUIC_PQC_BIND")


if __name__ == "__main__":
    asyncio.run(main())
