#!/usr/bin/env python3
"""quic_pqc_client_helper.py — the `quic-pqc` tech's actual exchange, run under the dedicated
`/opt/pqc-libs/quic-pqc-venv` interpreter (aioquic + cryptography, hybrid-PQC patched) as a
subprocess from `p2p/sender-role/client.py`'s own (system) interpreter — same shape as
`_PQKexConnection` shelling out to `openssl s_client`: the tech's toolchain and the main P2P
process's interpreter are never the same one, so this is a subprocess boundary everywhere else
in this project already needs too.

Protocol: one JSON object on stdin --
  {"host", "port", "server_name", "ca_path", "method", "path", "headers": {...}, "body_b64",
   "kex", "certs", "cert_path"?, "key_path"?, "expect"?: {"group", "peer_key_prefix", "peer_ip"}}
-> one JSON object on stdout --
  {"ok": true, "status": int, "body_b64": str, "negotiated": {...},
   "timing": {"handshake_ms", "request_ms", "handshake_cpu_ms", "handshake_bytes_out", "handshake_bytes_in",
              "rtt_ms", "retransmits"}}
  {"ok": false, "error": "PeerUnreachable"|"IdentityError", "reason": str}
"""
import asyncio
import base64
import json
import os
import sys
import time
from collections import deque

from aioquic import tls as aioquic_tls
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from aioquic.quic.connection import QuicConnection
from aioquic.tls import Group, SignatureAlgorithm

_OrigContext = aioquic_tls.Context

# What the ClientHello offers (2026-10-02). The defaults are the original `quic-pqc` behaviour; `run()`
# sets them from the request ("kex": "hybrid"|"classical", "certs": "mldsa"|"classical") BEFORE the
# connection is built, which is when the context reads them. One request per process, so a module
# global is safe.
KEX = "hybrid"
CERTS = "mldsa"


class _HybridOnlyContext(_OrigContext):
    """Offer ONLY the hybrid group / MLDSA65 signature — no classical fallback — so a completed
    handshake unambiguously proves that group/algorithm was what got negotiated. Same
    "offer only the thing under test" methodology `pqkex`/`coap-dtls-pqc` already use.

    `kex="classical"` offers only X25519, and `certs="classical"` keeps aioquic's stock RSA/ECDSA
    signature list so the fleet's RSA certificates verify (`quic-hybrid`, `quic-classical`)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        if self._is_client:
            # "classical" -> X25519, "mlkem" -> pure ML-KEM-768 (quic-pqc*, 2026-10-23; needs add_mlkem768.py
            # applied to aioquic -- looked up only then, so the other modes run on an aioquic without it)
            if KEX == "classical":
                self._supported_groups = [Group.X25519]
            elif KEX == "mlkem":
                self._supported_groups = [Group.MLKEM768]
            else:
                self._supported_groups = [Group.X25519MLKEM768]
            if CERTS == "mldsa":
                self._signature_algorithms = [SignatureAlgorithm.MLDSA65]


aioquic_tls.Context = _HybridOnlyContext

# What the handshake ACTUALLY negotiated, read off the ServerHello the client received (not what this
# helper was told to offer): the sender checks it against the tech's requirement and reports it, so a row
# says "X25519MLKEM768" because the server answered with that group, not because a table says so.
_OBSERVED = {}
_orig_pull_server_hello = aioquic_tls.pull_server_hello


def _recording_pull_server_hello(buf):
    hello = _orig_pull_server_hello(buf)
    try:
        _OBSERVED["group"] = Group(hello.key_share[0]).name
    except (TypeError, ValueError, IndexError):
        _OBSERVED["group"] = str(hello.key_share[0] if hello.key_share else None)
    try:
        _OBSERVED["cipher"] = "TLS_" + aioquic_tls.CipherSuite(hello.cipher_suite).name
    except ValueError:
        _OBSERVED["cipher"] = f"0x{hello.cipher_suite:04x}"
    return hello


aioquic_tls.pull_server_hello = _recording_pull_server_hello

_SIG_NAMES = {"2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
              "2.16.840.1.101.3.4.3.19": "ML-DSA-87"}


def _negotiated(protocol):
    """-> the observed facts of the finished handshake, shaped like p2p/common/identity.tls_info() plus `group`."""
    out = {"tls_version": "TLSv1.3", "group": _OBSERVED.get("group"), "tls_cipher": _OBSERVED.get("cipher"),
           "alpn": "h3"}
    cipher = out["tls_cipher"] or ""
    out["tls_bits"] = 256 if ("256" in cipher or "CHACHA20" in cipher) else 128 if "128" in cipher else None
    try:
        import cryptography
        import aioquic
        out["tls_lib"] = f"aioquic {aioquic.__version__} / cryptography {cryptography.__version__}"
    except Exception:  # noqa: BLE001
        pass
    cert = getattr(protocol._quic.tls, "_peer_certificate", None)
    if cert is not None:
        try:
            from cryptography.x509.oid import NameOID
            cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            out["tls_ca"] = cn[0].value if cn else None
        except Exception:  # noqa: BLE001
            pass
        oid = cert.signature_algorithm_oid.dotted_string
        out["tls_peer_sig"] = _SIG_NAMES.get(oid) or getattr(cert.signature_algorithm_oid, "_name", oid)
        try:
            from cryptography.hazmat.primitives.asymmetric import ec, rsa
            pub = cert.public_key()
            out["tls_peer_key"] = (f"RSA-{pub.key_size}" if isinstance(pub, rsa.RSAPublicKey)
                                   else f"EC-{pub.curve.name}" if isinstance(pub, ec.EllipticCurvePublicKey)
                                   else _SIG_NAMES.get(oid, type(pub).__name__))
        except Exception:  # noqa: BLE001
            out["tls_peer_key"] = _SIG_NAMES.get(oid)
    return {k: v for k, v in out.items() if v is not None}


class _CountingTransport:
    """The datagram transport, unchanged, except that every datagram handed to `sendto` is counted first."""

    def __init__(self, transport, io):
        self._t, self._io = transport, io

    def sendto(self, data, addr=None):
        self._io["bytes_out"] += len(data)
        return self._t.sendto(data, addr)

    def __getattr__(self, name):
        return getattr(self._t, name)


class HandshakeAborted(Exception):
    """The QUIC connection ended before its handshake completed; carries the CONNECTION_CLOSE code and reason."""

    def __init__(self, code, reason):
        self.code, self.reason = code, reason
        tls = (f"TLS alert {code - 0x100}" if isinstance(code, int) and 0x100 <= code <= 0x1ff
               else f"error {code:#x}" if isinstance(code, int) else "connection closed")
        super().__init__(f"handshake aborted ({tls}): {reason or 'no reason given'}")

    @property
    def is_tls_alert(self):
        return isinstance(self.code, int) and 0x100 <= self.code <= 0x1ff


def _peer_ip_sans(cert):
    """The IP addresses in a certificate's subjectAltName, as strings ([] when it has none)."""
    from cryptography import x509
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]


class _H3Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._http = H3Connection(self._quic)
        self._events = deque()
        self._waiter = None
        # 2026-10-23 (v2): why the connection ended, when it did. A handshake our OWN side aborts (the server
        # certificate names another node: aioquic's hostname check, TLS alert 0x12a) used to surface as a
        # bare ConnectionError with an EMPTY message, i.e. "PeerUnreachable: ''" -- the wrong class and no
        # reason. Kept here so run() can say what happened and main() can classify it.
        self.terminated = None
        # Transport-payload bytes this endpoint sent and received (UDP payloads: QUIC packets
        # incl. their headers, padding and AEAD tags; no IP/UDP headers). Counted where the datagrams cross
        # the socket, so nothing about how they are sent changes.
        self.io = {"bytes_out": 0, "bytes_in": 0}
        self.lost_packets = 0

    def connection_made(self, transport):
        super().connection_made(transport)
        self._transport = _CountingTransport(self._transport, self.io)

    def datagram_received(self, data, addr):
        self.io["bytes_in"] += len(data)
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.terminated = (event.error_code, event.reason_phrase or "")
            # The peer closed on us (e.g. a mutual port refusing our certificate INSIDE the handshake, TLS
            # alert bad_certificate = 0x12a): fail the pending request now instead of waiting out its
            # 25 s timeout, and keep the peer's reason so the caller can tell a refusal from a dead path.
            if self._waiter is not None and not self._waiter.done():
                self._waiter.set_exception(ConnectionError(
                    f"connection closed by peer: error {event.error_code:#x} {event.reason_phrase}".strip()))
        for http_event in self._http.handle_event(event):
            self._events.append(http_event)
            if isinstance(http_event, (HeadersReceived, DataReceived)) and http_event.stream_ended:
                if self._waiter is not None and not self._waiter.done():
                    self._waiter.set_result(True)

    async def exchange(self, method, path, authority, headers, body):
        stream_id = self._quic.get_next_available_stream_id()
        h3_headers = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
        ] + [(k.lower().encode(), str(v).encode()) for k, v in headers.items()]
        self._http.send_headers(stream_id=stream_id, headers=h3_headers, end_stream=not body)
        if body:
            self._http.send_data(stream_id=stream_id, data=body, end_stream=True)
        self.transmit()

        self._waiter = asyncio.get_event_loop().create_future()
        await asyncio.wait_for(self._waiter, timeout=25)

        status, chunks = 502, []
        for ev in self._events:
            if isinstance(ev, HeadersReceived):
                for k, v in ev.headers:
                    if k == b":status":
                        status = int(v)
            elif isinstance(ev, DataReceived):
                chunks.append(ev.data)
        return status, b"".join(chunks)


def _load_own_identity(config, cert_path, key_path):
    """`config.load_cert_chain()` with ONE difference: an RSA private key is loaded with
    `unsafe_skip_rsa_key_validation=True`. aioquic calls `load_pem_private_key()` plainly, and for an
    RSA key OpenSSL then re-validates the key (primality of p and q): measured 218 ms on a Pi 5 for the
    fleet's own leaf key, on every run of this one-shot helper -- the whole of the extra ~220 ms that
    made `quic-classical-mutual` look slower than `quic-classical` (the ML-DSA key of `quic-pqc-mutual`
    has no such check, so it never showed). The key is this node's own file, minted by the fleet CA
    and read from a 0600 path, so the validation only repeats work that was done when it was issued.
    Everything else (certificate parsing, chain split, ML-DSA keys) is what load_cert_chain does."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509 import load_pem_x509_certificates
    with open(cert_path, "rb") as fp:
        certificates = load_pem_x509_certificates(fp.read().split(b"\n-----BEGIN PRIVATE KEY-----\n")[0])
    config.certificate = certificates[0]
    config.certificate_chain = certificates[1:]
    with open(key_path, "rb") as fp:
        pem = fp.read()
    try:
        config.private_key = serialization.load_pem_private_key(
            pem, password=None, unsafe_skip_rsa_key_validation=True)
    except (TypeError, ValueError):
        # a key type/format the skip does not apply to (ML-DSA): the stock path, unchanged
        config.load_cert_chain(cert_path, key_path)


async def run(req):
    global KEX, CERTS
    KEX, CERTS = req.get("kex", "hybrid"), req.get("certs", "mldsa")
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                               server_name=req["server_name"])
    config.load_verify_locations(cafile=req["ca_path"])
    # `quic-pqc-mutual` (2026-09-28, Stack 6): this node's own ML-DSA-65 leaf, presented during
    # the handshake -- aioquic's OWN TLS 1.3 CertificateRequest/Certificate/CertificateVerify
    # flow, already generic over key type (the SAME signature_algorithm_params()/
    # _signature_algorithms_for_private_key() this patch's Stack 5 work already made MLDSA65-aware
    # needed no further changes for the client side). `quic-pqc` (non-mutual) never sets these.
    if req.get("cert_path") and req.get("key_path"):
        _load_own_identity(config, req["cert_path"], req["key_path"])
    connection = QuicConnection(configuration=config)

    import socket
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _H3Client(connection, stream_handler=None), sock=sock
    )
    # Packets the loss detector declares lost (each one's frames are then retransmitted): counted per
    # connection by wrapping this connection's own recovery object, so the count is this exchange's only.
    loss = connection._loss
    _orig_lost = loss._on_packets_lost

    def _counting_lost(*, now, packets, space):
        packets = list(packets)
        protocol.lost_packets += len(packets)
        return _orig_lost(now=now, packets=packets, space=space)

    loss._on_packets_lost = _counting_lost
    try:
        # Phase clocks (monotonic, this process): the caller subtracts them from its own wall
        # clock around the whole subprocess to separate "the protocol" (handshake, request) from
        # "starting an interpreter" (spawn + imports + this orderly close).
        t_start = time.perf_counter()
        c_start = time.process_time()      # this process's CPU (user+sys); the helper is single-threaded
        protocol.connect((req["host"], req["port"]))
        protocol.transmit()
        try:
            await asyncio.wait_for(protocol.wait_connected(), timeout=10)
        except ConnectionError:
            # the connection ended before the handshake finished: say why (our own certificate check, the
            # peer's alert, a refused group) instead of an empty ConnectionError
            code, why = protocol.terminated or (None, "")
            close = getattr(connection, "_close_event", None)
            if close is not None and not why:
                code, why = close.error_code, close.reason_phrase
            raise HandshakeAborted(code, why)
        t_connected = time.perf_counter()
        c_connected = time.process_time()
        hs_io = dict(protocol.io)
        negotiated = _negotiated(protocol)
        # The gate: refuse BEFORE any application data leaves if the handshake did not negotiate what this
        # tech is defined by (the caller passes `expect`). The words below are what main() classifies as an
        # IdentityError.
        expect = req.get("expect") or {}
        if expect.get("group") and negotiated.get("group") != expect["group"]:
            raise RuntimeError(f"handshake negotiated group {negotiated.get('group')!r}, "
                               f"this tech requires {expect['group']!r}")
        if expect.get("peer_key_prefix") and not str(negotiated.get("tls_peer_key") or "").startswith(
                expect["peer_key_prefix"]):
            raise RuntimeError(f"handshake: the server certificate key is {negotiated.get('tls_peer_key')!r}, "
                               f"this tech requires {expect['peer_key_prefix']}*")
        # 2026-10-23 (v2): aioquic checked the certificate's NAME (server_name) in the handshake; the address we
        # dialled must also be one the certificate is bound to -- the same SAN-IP binding the mtls/https path
        # checks after its handshake. Refused before any data leaves.
        peer_cert = getattr(protocol._quic.tls, "_peer_certificate", None)
        if expect.get("peer_ip") and peer_cert is not None:
            ips = _peer_ip_sans(peer_cert)
            if ips and expect["peer_ip"] not in ips:
                raise RuntimeError(f"identity: the server certificate is bound to {sorted(ips)}, "
                                   f"but we connected to {expect['peer_ip']}")
        body = base64.b64decode(req["body_b64"]) if req.get("body_b64") else b""
        authority = f"{req['host']}:{req['port']}"
        status, resp_body = await protocol.exchange(
            req["method"], req["path"], authority, req.get("headers", {}), body
        )
        t_done = time.perf_counter()
        rtt_min = getattr(loss, "_rtt_min", None)
        return {"ok": True, "status": status, "body_b64": base64.b64encode(resp_body).decode(),
                "negotiated": negotiated,
                "timing": {"handshake_ms": round((t_connected - t_start) * 1000, 3),
                           "request_ms": round((t_done - t_connected) * 1000, 3),
                           # what the handshake cost on the wire and on this CPU (UDP payload bytes, i.e. QUIC
                           # packets incl. padding; up to and including our Finished), and the path as the
                           # transport saw it over the whole exchange
                           "handshake_cpu_ms": round((c_connected - c_start) * 1000, 3),
                           "handshake_bytes_out": hs_io["bytes_out"], "handshake_bytes_in": hs_io["bytes_in"],
                           "rtt_ms": (round(rtt_min * 1000, 3) if isinstance(rtt_min, float)
                                      and rtt_min != float("inf") else None),
                           "retransmits": protocol.lost_packets}}
    finally:
        protocol.close()
        # 2026-10-23: was `await asyncio.sleep(0.1)` -- 100 ms of every call (the largest single part of
        # the helper's start-up overhead). protocol.close() already queued CONNECTION_CLOSE and sent it
        # (UDP sendto is immediate); one loop turn lets the write finish before the transport is closed.
        await asyncio.sleep(0)
        transport.close()


def main():
    req = json.loads(sys.stdin.read())
    try:
        result = asyncio.run(run(req))
    except asyncio.TimeoutError:
        result = {"ok": False, "error": "PeerUnreachable",
                  "reason": f"quic-pqc handshake/exchange to {req['host']}:{req['port']} timed out"}
    except HandshakeAborted as e:
        # A TLS alert (CONNECTION_CLOSE 0x100-0x1ff) is an identity/negotiation refusal by one side or the
        # other (certificate name or chain, missing client certificate, no common group); anything else
        # ended the connection for a transport reason.
        result = {"ok": False, "error": "IdentityError" if e.is_tls_alert else "PeerUnreachable",
                  "reason": str(e)}
    except Exception as e:  # noqa: BLE001 -- reported to the parent process, not raised bare
        # A TLS handshake failure (bad cert, wrong hostname, group not negotiated) is the
        # IdentityError family everywhere else in this project; anything else (connection
        # refused, unreachable) is PeerUnreachable. Heuristic on the exception text, same as
        # every other subprocess-shaped tech here (_PQKexConnection.getresponse()) has to do.
        reason = str(e)
        is_identity = any(w in reason.lower() for w in
                          ("certificate", "hostname", "handshake", "verify", "tls"))
        result = {"ok": False, "error": "IdentityError" if is_identity else "PeerUnreachable",
                  "reason": reason}
    print(json.dumps(result))
    # 2026-10-23: skip interpreter teardown (module/GC finalisation of asyncio + cryptography + aioquic):
    # ~55 ms of every call on a Pi 5, for a one-shot process whose only output is the line above.
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
