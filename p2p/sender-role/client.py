"""p2p/sender-role/client — the P2P sender (p2p-plan..md §3.1/§3.2).

`resolve() -> connect -> request`, exactly as §3.1 names it. Uses the real GET /resolve (§0b, no
stand-in) to find the receiver's /32, then connects DIRECTLY to it — the Server is consulted for
name resolution and policy, never as a data-plane hop (peer-to-peer, not a relay).

TWO INDEPENDENT AXES (2026-07-28, operator-directed: "a use case is different than a tech — a use
case e.g. message can be sent with each tech, and not only with a specific one"):

  USE CASE   what is exchanged   `message` (a JSON body) · `file` (raw bytes) · `status` (ask the
                                 receiver about itself) · `rm` (run a command ON the receiver —
                                 device→device remote management, 2026-07-28)
  TECH       how it is protected `mtls` · `https` · `pqc` · `coap-enc` · `coap`

Every use case works on every tech.

PQC RULE (2026-10-23, owner): a tech whose name contains "pqc" uses ML-KEM-768 (FIPS 203, the PURE group,
no X25519 half) for key establishment AND ML-DSA-65 (FIPS 204) for every authentication and signature in it:
the handshake certificates, the sender's signed envelope and (CoAP) the receiver's signed reply. No classical
or hybrid fallback anywhere; `PQC_TECHS` lists them, and the entries below that predate the rule say so where
they changed. The techs:

  mtls      TLS 1.3 mutual auth on :P2P_PORT. The peer certificate IS the identity (§4.3) — the
            handshake itself refuses a certless or wrong-CA peer, before any application code runs.
            The default, and the strongest of the four.
  pqc       mtls with every algorithm post-quantum (owner, 2026-10-23: "PQC means ML-KEM-768 + ML-DSA-65, not an
            envelope"): TLS 1.3 over TCP on :P2P_PQC_PORT (8446), ML-KEM-768 key exchange ONLY, ML-DSA-65
            certificates on BOTH sides (PQC CA). The client certificate IS the sender's identity, exactly as on
            mtls: raw body, no envelope. Python's own ssl on the system OpenSSL 3.5 runs the handshake; the group
            is pinned through libssl (identity.build_pqc_client_context). Until 2026-10-23 `pqc` was the mtls
            handshake + an ML-DSA envelope (classical transport) -- retired; the receiver refuses that header.
  https     TLS 1.3 with SERVER authentication only, on :P2P_HTTPS_PORT — the sender presents no
            client certificate, so the transport cannot say who it is and the sender's identity is
            an RSA-signed envelope in the body instead (the same idiom the CoAP transport uses, for
            the same reason). This is **strictly weaker than mtls**: the receiver still authenticates
            every request and policy is still enforced per sender→receiver pair, but the handshake
            no longer rejects strangers before the application sees them. It is a SEPARATE PORT on
            purpose — accepting certless clients on the mTLS port would weaken every other tech
            along with it. Use it for the "plain HTTPS peer" case, not as a default.
  coap-enc  CoAP/UDP with a hybrid-encrypted payload (AES-256-GCM under the receiver's RSA public
            key) and an RSA-signed ciphertext. The constrained/datagram transport.
  coap-pqc  CoAP/UDP, `coap-enc`'s exact shape with ML-KEM-768 encapsulation replacing the RSA-OAEP
            key-wrap (2026-09-27), AES-256-GCM payload. Since 2026-10-23 the envelope is ML-DSA-65-signed
            (PQC CA) and the receiver's reply must be ML-DSA-65-signed too (`_require_pqc_reply`). The peer's KEM public key comes
            from a local, offline-provisioned cache (PQC-bench/ca/pqc_kem.py), never a live Server
            fetch — there is no issuance endpoint for it, same as the ML-DSA-65 material `pqc` uses.
  coap      CoAP/UDP with NO encryption (2026-08-10) — RFC 7252's NoSec mode, but keeping the signed
            cert envelope, so the payload is CLEARTEXT on the wire while the sender's identity and
            the per-pair policy check are exactly as strong as coap-enc's. Confidentiality is the
            only thing given up, deliberately: a constrained node that cannot afford RSA-OAEP+
            AES-GCM per message can still prove who it is. Weakest of the five on privacy; identical
            to coap-enc on authenticity.
  http      Plain HTTP/TCP on :P2P_HTTP_PORT, NO TLS AT ALL (2026-09-26) — the benchmark doc's
            "plaintext" tier for the HTTP family, the one still missing next to `coap`'s already
            -existing plaintext option. Same signed-envelope idiom as `https`/`pqc`/`coap` carries
            the sender's identity in the body, since there is no handshake to hang it on. Unlike
            every other tech, THE SENDER CANNOT VERIFY THE RECEIVER here — `https`/`mtls`/`pqc`
            check the peer's certificate CN/SAN after connecting (see `_connect`); with no TLS
            session at all there is nothing to check, so a sender using `http` trusts DNS/routing
            alone to have reached the right box. The receiver still authenticates the SENDER (the
            envelope's signature) and still enforces the per-pair policy — only the transport-level
            "who did I just connect to" guarantee is gone, the same trade `coap`'s NoSec mode
            already accepts for the identical reason (no session to authenticate over).
  pqkex     Real hybrid-PQ-KEX TLS 1.3 (X25519MLKEM768, ML-DSA-65 SERVER cert) on
            :P2P_PQKEX_PORT (2026-09-27) — the ACTUAL handshake `pqc` cannot do (Python's `ssl`
            binds the system OpenSSL, no oqs-provider). Reaches a real stunnel front door
            (PQC-bench/p2p-proxy/) fronting the SAME plaintext backend `http` uses, via PQC-bench's
            private OpenSSL 3.4 build run as a subprocess (`_PQKexConnection`) since nothing in
            this process's own Python can speak that TLS group. The RECEIVER cannot tell this
            apart from `http` — the proxy decrypts before the request ever reaches
            receiver-role/server.py, exactly as designed (Q5's "reverse proxy, zero risk to
            existing app code paths") — so identity is the SAME classical signed envelope `http`
            uses, not a PQC one: making it a PQC envelope would need the receiver's `_identify()`
            to check for a PQC header on the NON-mutual listener too, which it deliberately does
            not (see server.py's own docstring on that dispatch — mutual-listener-only, by design).
            This tech is genuinely PQC at the TRANSPORT layer (verified independently: the
            handshake fails if the hybrid group isn't negotiated, or if the peer's cert doesn't
            verify+match by hostname) and classical at the envelope layer — an honest "PQ-KEX
            transport, classical app-identity" combination, not a compromise.
  coap-dtls-pqc  (2026-10-23: now pure ML-KEM-768 + ML-DSA-65 certificates on both ends, ML-DSA-65
            envelope and reply -- the paragraph below describes the 2026-09-27 hybrid/RSA original.)
            Real hybrid-PQ-KEX DTLS 1.3 (X25519MLKEM768) on :P2P_COAP_DTLS_PQC_PORT
            (2026-09-27) — `pqkex`'s idea (a real PQ-KEX handshake, via a dedicated front-door
            process, fronting an UNCHANGED plaintext backend) applied to the UDP/CoAP side instead
            of TCP/HTTP: `p2p/receiver-role/coap_dtls_pqc_relay.py` decrypts and forwards the raw
            CoAP bytes to the SAME plain listener `coap`/`coap-enc`/`coap-pqc` already run
            (coap_server.py), which cannot tell this tech apart from `coap` — the forwarded
            envelope is `coap`'s exact cleartext shape (real confidentiality now comes from the
            DTLS transport itself; layering `coap-pqc`'s own KEM encryption UNDER it too would be
            redundant, the same reasoning `pqkex` gives for reusing `http`'s plain envelope under
            its own real transport encryption). Built on `PQC-bench/wolfssl-py-patch/` (a patched
            `wolfssl` Python binding + a real aiocoap `MessageInterface`, `aiocoap_wolfdtls.py`),
            since neither the private OpenSSL 3.4 build `pqkex` shells out to, nor the private
            OpenSSL 3.5 build `coap-pqc` uses, has a DTLS 1.3 story at all — that gap is the whole
            reason that patch exists. The RECEIVER's server certificate is verified for real
            (`CERT_REQUIRED` against the fleet CA, then the SAME CN==receiver_name + SAN-IP check
            `_connect()` runs for `mtls`/`https`/`pqkex` — see `_coap_dtls_exchange`); the
            SENDER's identity is still the classical signed envelope inside the forwarded bytes,
            checked by coap_server.py exactly as it already does for `coap`. Genuinely PQC at the
            TRANSPORT layer, classical everywhere else — the same honest split `pqkex` already
            established, just over CoAP/UDP instead of HTTP/TCP.

  The next eight techs (2026-10-02) fill the matrix cells the video stacks already had. They split
  the two things a handshake can make post-quantum -- the KEY EXCHANGE and the CERTIFICATES -- so a
  benchmark can price each one separately: classical/classical (`https`, `mtls`, `coap-enc`),
  hybrid KEX + classical certs (the "PQ-KEX only" stage), hybrid KEX + ML-DSA certs (`pqkex`,
  `quic-pqc`). Every one reuses a listener/relay that already exists; only the offered group and
  the certificate set differ. The sender's identity inside the request is the SAME classical
  signed envelope the other certless techs carry.

  hybrid / hybrid-mutual
            TLS 1.3 over TCP with the hybrid X25519MLKEM768 key exchange and the fleet's CLASSICAL
            RSA certificate (not the ML-DSA one `pqkex` presents), :P2P_HYBRID_PORT /
            :P2P_HYBRID_MUTUAL_PORT. Same stunnel process and private OpenSSL as `pqkex`, two more
            sections in front of the same plaintext `http` listener. Mutual adds the sender's own
            classical leaf (`verify = 2` on the receiver).
  quic-hybrid / quic-hybrid-mutual
            HTTP/3 over QUIC, hybrid X25519MLKEM768 + classical RSA certificates, :P2P_QUIC_HYBRID_PORT
            / :P2P_QUIC_HYBRID_MUTUAL_PORT. `quic_pqc_relay.py` in `QUIC_CERT_MODE=classical`.
  quic-classical / quic-classical-mutual
            HTTP/3 over QUIC, classical X25519 + RSA certificates -- no post-quantum algorithm at
            all (the classical QUIC baseline). The relay refuses a client that offers no X25519
            key share (`QUIC_GROUPS=X25519`).
  coap-dtls / coap-dtls-mutual
            CoAP over DTLS 1.3 with a classical X25519 key share and the fleet's RSA certificate
            (the classical DTLS baseline for `coap-dtls-pqc`), :P2P_COAP_DTLS_PORT /
            :P2P_COAP_DTLS_MUTUAL_PORT. The same `coap_dtls_pqc_relay.py`, told to require X25519
            (`P2P_COAP_DTLS_REQUIRE_GROUP`) so a hybrid offer is refused on these ports.
"""
import base64
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # p2p/ root, for `common`
from common import comm_log, errors, identity, ml_limits, rm_limits, sender_log  # noqa: E402

def _env_pos_float(name, default):
    """A positive float from the environment, or `default` when unset / empty / not a number / <= 0 / nan / inf
    (a bad value must never turn into a zero or infinite wait)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        v = float(raw)
    except ValueError:
        return default
    return v if 0 < v < 1e6 else default


# The four techs, and the CoAP resource each use case is served at (the resource path carries the
# use case there, the way the HTTP route does on the other three).
TECHS = ("mtls", "https", "pqc", "coap-enc", "coap", "http", "pqkex", "coap-pqc", "coap-dtls-pqc",
         "pqkex-mutual", "quic-pqc", "coap-dtls-pqc-mutual", "quic-pqc-mutual",
         # 2026-10-02 (FL protocol picker gaps): the key-exchange x certificate combinations the
         # video stacks already had but P2P did not. See the module docstring's last four entries.
         "hybrid", "hybrid-mutual", "quic-hybrid", "quic-hybrid-mutual",
         "quic-classical", "quic-classical-mutual", "coap-dtls", "coap-dtls-mutual")

# 2026-10-23, owner's rule: a tech named "pqc" uses ML-KEM-768 for key establishment AND ML-DSA-65 for every
# authentication / signature in it -- the handshake's certificates, the sender's signed envelope and (CoAP)
# the receiver's signed reply. No classical signature and no classical or hybrid key exchange anywhere in it.
PQC_TECHS = ("pqc", "quic-pqc", "quic-pqc-mutual", "coap-pqc", "coap-dtls-pqc",
             "coap-dtls-pqc-mutual")
PQC_GROUP = "MLKEM768"
CLASSICAL_GROUP = "X25519"         # the only group mtls / https offer (identity.CLASSICAL_CLIENT_GROUPS)             # what each PQC transport must report it negotiated (wolfSSL: ML_KEM_768)


def tech_family(tech):
    """The transport a tech runs on: CoAP for every coap* tech, else HTTP (incl. QUIC/HTTP-3)."""
    return "CoAP" if str(tech).startswith("coap") else "HTTP"


def tech_listing(techs=None):
    """`HTTP: mtls | https ... ; CoAP: coap | coap-enc ...` -- techs grouped by transport."""
    techs = TECHS if techs is None else techs
    return "; ".join(f"{fam}: " + " | ".join(t for t in techs if tech_family(t) == fam)
                     for fam in ("HTTP", "CoAP") if any(tech_family(t) == fam for t in techs))


# `coap-dtls-pqc` (2026-09-27): where the patched wolfSSL toolchain and its aiocoap transport
# module (PQC-bench/wolfssl-py-patch/) live, same override-with-a-sane-default pattern
# identity.py's PQC_OPENSSL/PQC_OPENSSL_CONF already use. Only consulted inside
# `_coap_dtls_exchange` -- a box that never uses this tech never needs either to exist.
COAP_DTLS_PQC_WOLFSSL_LIB = os.environ.get(
    "COAP_DTLS_PQC_WOLFSSL_LIB", "/opt/pqc-libs/wolfssl-dtls/lib")
COAP_DTLS_PQC_MODULE_PATH = os.environ.get(
    "COAP_DTLS_PQC_MODULE_PATH", "/opt/PQC-bench/wolfssl-py-patch")


class _Timing:
    """Per-exchange phase clock (2026-09-30, benchmarking — func11-benchmarking-readiness.md; reshaped
    2026-10-23 v2).

    Every exchange returns a `timing` block with the SAME keys whatever the tech, so a plaintext,
    a classical and a PQC run can be put side by side. Phases are laps of one monotonic clock
    (`perf_counter`, never the wall clock), taken on THIS box, so no clock sync is involved. The
    phases are ADDITIVE on every tech: total_ms == the sum of the non-None phases below.

      resolve_ms        the sender's GET /resolve (a Server hop, or the local cache)
      peer_cert_ms      coap-enc only: fetching the receiver's cert from the Server to encrypt for
      tcp_connect_ms    TCP connect (http/https/mtls/pqc); None where there is no TCP of ours (QUIC,
                        CoAP, and pqkex*/hybrid*, whose TCP connect is inside handshake_ms)
      handshake_ms      the handshake INCLUDING the check of who answered (CN + SAN IP / name), on every
                        tech that has one. https/mtls/pqc: measured here around wrap_socket + the check.
                        quic-*, coap-dtls*: measured inside the client helper / worker process.
                        pqkex*/hybrid*: from the openssl subprocess's own progress lines (its TCP
                        connect included). None where there is no handshake (http, coap, coap-enc, coap-pqc)
      prepare_ms        building the request: signing, and on coap-enc/coap-pqc encrypting
      client_overhead_ms  quic-*, coap-dtls*, pqkex*, hybrid*: starting / stopping the helper process,
                        worker or openssl subprocess (spawn, imports, provider load, orderly close).
                        None on every other tech
      exchange_ms       request out -> reply fully read (includes the receiver's own work); never the
                        handshake or a helper's start-up
      receiver_ms       the receiver's own work, as IT measured it (`receiver_timing` in the
                        reply); None against a receiver that predates this
      network_ms        exchange_ms - receiver_ms: the wire both ways plus any local front door / relay
      total_ms          first lap to last

    Plus what the transport saw (None where a tech's transport does not let us observe it -- never 0):
      handshake_bytes_out / handshake_bytes_in   transport payload bytes this side sent / received until
                        its handshake completed (TCP: TLS records, from TCP_INFO; QUIC: UDP payloads, counted
                        in the helper; pqkex*/hybrid*: TLS records, from openssl's message trace)
      handshake_cpu_ms  CPU time (user+sys) the client spent in the handshake (thread / helper / worker CPU
                        clock) -- the compute share of handshake_ms, the rest is waiting for the network/peer
      rtt_ms            the transport's minimum observed round-trip time for this connection (TCP_INFO
                        min_rtt / QUIC min RTT)
      retransmits       segments (TCP) / packets declared lost (QUIC) / CON messages (CoAP) this side re-sent

    A handshake that failed verification and is retried after an identity refresh is REWOUND: the block then
    describes the retried attempt alone (see `rewind`)."""

    NET_KEYS = ("handshake_bytes_out", "handshake_bytes_in", "handshake_cpu_ms", "rtt_ms", "retransmits")
    # receiver-block keys an OLDER receiver still sends that this block no longer carries (the totals are
    # hoisted into receiver_ms; receive_body_ms / mirror_ms were retired 2026-10-23 v2)
    _RECEIVER_DROP = ("total_ms", "clock", "receive_body_ms", "mirror_ms")

    def __init__(self, tech):
        self.tech = tech
        self._start = self._mark = time.perf_counter()
        self.ms = {}
        self.wire_ms = None          # request->reply phase alone, when a helper process reports it
        self.net = {}

    def note(self, handshake_ms=None, wire_ms=None):
        """Record phases a helper/worker process measured on its own clock (quic-*, coap-dtls*, pqkex*, hybrid*)."""
        if handshake_ms is not None:
            self.ms["handshake_ms"] = round(float(handshake_ms), 3)
        if wire_ms is not None:
            self.wire_ms = round(float(wire_ms), 3)

    def note_net(self, **facts):
        """Record transport observations (NET_KEYS); a None value is ignored, never stored as 0."""
        for k, v in facts.items():
            if k in self.NET_KEYS and v is not None:
                self.net[k] = round(float(v), 3) if k.endswith("_ms") else int(v)

    def lap(self, phase):
        now = time.perf_counter()
        self.ms[phase] = round(self.ms.get(phase, 0.0) + (now - self._mark) * 1000, 3)
        self._mark = now

    def snapshot(self):
        return dict(self.ms), dict(self.net), self._mark

    def rewind(self, snap):
        """Forget everything since `snap`: a failed attempt that is being retried (the identity refresh in
        `_connect`). Its phases are dropped and the clock's start moves forward by the time it took, so the
        block describes the retried attempt alone and its phases still add up to total_ms. The comm-log /
        sent.log `duration_ms` (wall clock around the whole call) still includes it."""
        ms, net, mark = snap
        now = time.perf_counter()
        self.ms, self.net = dict(ms), dict(net)
        self._start += now - mark
        self._mark = now

    def block(self, request_bytes=None, response_bytes=None, receiver=None):
        ms = self.ms
        rt = ({k: v for k, v in receiver.items() if k not in self._RECEIVER_DROP}
              if isinstance(receiver, dict) else None)
        receiver_ms = receiver.get("total_ms") if rt is not None else None
        full = ms.get("exchange_ms")
        hs = ms.get("handshake_ms")
        if self.wire_ms is not None and full is not None:
            # a helper / worker / subprocess ran the protocol: its handshake and request->reply phases are
            # its own clock's; what is left of the wall time around it is starting and stopping it
            exchange = self.wire_ms
            overhead = round(full - (hs or 0.0) - self.wire_ms, 3)
        else:
            exchange, overhead = full, None
        return {
            "tech": self.tech,
            "resolve_ms": ms.get("resolve_ms"),
            "peer_cert_ms": ms.get("peer_cert_ms"),
            "tcp_connect_ms": ms.get("tcp_connect_ms"),
            "handshake_ms": hs,
            "prepare_ms": ms.get("prepare_ms"),
            "client_overhead_ms": overhead,
            "exchange_ms": exchange,
            "receiver_ms": receiver_ms,
            "network_ms": (round(exchange - receiver_ms, 3)
                           if exchange is not None and receiver_ms is not None else None),
            "total_ms": round((self._mark - self._start) * 1000, 3),
            "request_bytes": request_bytes,
            "response_bytes": response_bytes,
            **{k: self.net.get(k) for k in self.NET_KEYS},
            "receiver": rt,
        }


def _tcp_info(sock):
    """The kernel's TCP_INFO for a connected TCP socket (plain or TLS-wrapped), the fields the timing block
    uses, or None (not Linux, not TCP, an older kernel without tcpi_bytes_sent). Read-only: it changes
    nothing about the connection. Offsets are `struct tcp_info` (include/uapi/linux/tcp.h), verified live
    on the Pi 5 kernels 2026-10-23 (bytes_sent == the request written, bytes_received == the reply + FIN)."""
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
    except (OSError, AttributeError, ValueError):
        return None
    if len(raw) < 216:
        return None
    return {"total_retrans": struct.unpack_from("=I", raw, 100)[0],
            "bytes_received": struct.unpack_from("=Q", raw, 128)[0],
            "notsent_bytes": struct.unpack_from("=I", raw, 144)[0],
            "min_rtt_us": struct.unpack_from("=I", raw, 148)[0],
            "bytes_sent": struct.unpack_from("=Q", raw, 200)[0],
            "bytes_retrans": struct.unpack_from("=Q", raw, 208)[0]}


def _note_tcp_end(timing, sock):
    """rtt_ms + retransmits of a TCP connection, read just before it is closed."""
    ti = _tcp_info(sock)
    if ti:
        timing.note_net(rtt_ms=ti["min_rtt_us"] / 1000 if ti["min_rtt_us"] else None,
                        retransmits=ti["total_retrans"])


class _PQKexResponse:
    """Just enough of `http.client.HTTPResponse` for `_http_exchange()` to read: `.status`, `.read()`."""

    def __init__(self, raw: bytes):
        head, _, self._body = raw.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0]
        parts = status_line.split(b" ", 2)
        # 502, not an exception, on a malformed/empty head -- the caller (`_http_exchange`) already
        # has a uniform `except Exception` around the whole request/response pair; a response object
        # that just reports a bad-gateway-shaped status is easier to reason about at that call site
        # than a second, unrelated exception type only this tech can raise.
        self.status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 502

    def read(self):
        return self._body


class _PQKexConnection:
    """A `pqkex`-tech "connection". Python's stdlib `ssl` cannot negotiate a hybrid PQ-KEX group
    (system libssl, no oqs-provider) -- the same gap that forced `pqc` to be an envelope instead of
    a real handshake (see the module docstring's PQC section). `pqkex` IS a real handshake, so it
    shells out to PQC-bench's private OpenSSL 3.4 build (`identity.PQC_OPENSSL`) as a subprocess and
    speaks raw HTTP/1.1 over its stdin/stdout, exposing just `.request()`/`.getresponse()`/`.close()`
    so it slots into `_http_exchange()` completely unchanged.

    ONE openssl invocation per exchange, not two: an earlier version ran a separate data-free
    handshake first to fail fast before the envelope was even built. Found live (2026-09-27) that
    `openssl s_client` does not exit on a data-free stdin close -- it keeps waiting for the PEER to
    send something, which a request-less probe never triggers, so that "fail fast" call just hung
    for the full timeout instead. `-verify_return_error` already aborts the connection immediately
    on a chain/hostname mismatch, before our request bytes are even sent, so folding verification
    into the SAME real request (in `getresponse()`) gets the identical guarantee with one round trip
    instead of two, and without the hang. The one behavioural change from every other tech's
    `_connect()`: a pqkex PeerUnreachable/IdentityError surfaces at `getresponse()` time, after the
    envelope has already been built and signed (harmless -- nothing was sent yet at that point)."""

    LABEL = "pqkex"          # the tech name used in error text; `_HybridTlsConnection` overrides it

    def __init__(self, ip, port, receiver_name, ca_path, timeout):
        self.ip, self.port, self.receiver_name, self.ca_path = ip, port, receiver_name, ca_path
        self.timeout = timeout
        self._method = self._path = self._body = None
        self._headers = {}

    def _openssl_argv(self):
        return [identity.PQC_OPENSSL, "s_client", "-connect", f"{self.ip}:{self.port}",
                "-groups", "X25519MLKEM768", "-tls1_3", "-CAfile", self.ca_path,
                "-verify_hostname", self.receiver_name, "-verify_return_error", "-quiet"]

    @staticmethod
    def _last_stderr_line(proc):
        lines = proc.stderr.decode(errors="replace").strip().splitlines()
        return lines[-1] if lines else f"exit {proc.returncode}"

    def request(self, method, path, body=None, headers=None):
        self._method, self._path = method, path
        self._body = body if isinstance(body, (bytes, bytearray)) else (body or b"")
        self._headers = dict(headers or {})

    def getresponse(self):
        lines = [f"{self._method} {self._path} HTTP/1.1", f"Host: {self.ip}:{self.port}",
                 "Connection: close", f"Content-Length: {len(self._body)}"]
        lines += [f"{k}: {v}" for k, v in self._headers.items()]
        req = ("\r\n".join(lines) + "\r\n\r\n").encode() + self._body
        try:
            r = subprocess.run(self._openssl_argv(), input=req, capture_output=True,
                               timeout=self.timeout, env=identity.pqc_env())
        except subprocess.TimeoutExpired as e:
            raise errors.PeerUnreachable(
                f"{self.LABEL} request to {self.receiver_name} timed out: {e}")
        if r.returncode != 0:
            reason = self._last_stderr_line(r)
            if "verify" in reason.lower() or "hostname" in reason.lower():
                raise errors.IdentityError(f"{self.receiver_name}'s {self.LABEL} identity did not verify: {reason}")
            raise errors.PeerUnreachable(
                f"could not reach {self.receiver_name} ({self.ip}:{self.port}) over {self.LABEL}: {reason}")
        return _PQKexResponse(r.stdout)

    def close(self):
        pass  # each exchange is one openssl subprocess, already exited by the time this is called


class _PQKexMutualConnection(_PQKexConnection):
    """`pqkex-mutual` (2026-09-27) — Stack 2 (mutual PQC TLS): the ONE thing `pqkex` deliberately
    does not do (its own docstring: "this node's own cert/key are irrelevant to pqkex"). Same real
    hybrid-PQ-KEX handshake, same private-OpenSSL subprocess shape, ONE difference: `-cert`/`-key`
    added to the openssl invocation so THIS node's own ML-DSA-65 leaf is presented too, and a
    SEPARATE front door (`PQC-bench/p2p-proxy/p2p-pqc-proxy.conf`'s `[p2p-pqc-mutual]` section,
    port 9447) that sets `verify = 2` + `CAfile` — refusing the TLS handshake outright if the
    client cert doesn't chain to the same CA, before a single plaintext byte reaches the backend.
    `pqkex`'s own :9444 front door is untouched (no `verify =` there at all: still server-auth
    only) — this is a genuinely separate, additive port+tech, not a flag on the existing one, so an
    already-provisioned `pqkex` install (client cert never needed) keeps working exactly as before.

    The backend (`receiver-role/server.py`, the SAME plain :8442 `http` listener `pqkex` already
    fronts) sees IDENTICAL plaintext either way and needs no changes: by the time a request reaches
    it, stunnel has already refused any connection whose client cert didn't verify, so mutual
    authentication is a strictly-additive transport-layer guarantee on top of the classical signed
    envelope `pqkex`'s own message format already carries for application-layer sender identity."""

    def __init__(self, ip, port, receiver_name, ca_path, cert_path, key_path, timeout):
        super().__init__(ip, port, receiver_name, ca_path, timeout)
        self.cert_path, self.key_path = cert_path, key_path

    def _openssl_argv(self):
        return super()._openssl_argv() + ["-cert", self.cert_path, "-key", self.key_path]


class _HybridTlsConnection(_PQKexConnection):
    """`hybrid` / `hybrid-mutual` (2026-10-02): the hybrid X25519MLKEM768 key exchange with the
    fleet's CLASSICAL certificate -- the "PQ-KEX only" stage. Same private-OpenSSL subprocess as
    `pqkex`; what differs is the trust: the peer's RSA leaf is verified against the fleet CA
    (CN == receiver, and the connected IP must be in its SAN, the same two checks `https` makes),
    and in mutual mode this node presents its own classical leaf, with the intermediate supplied
    as the chain so the receiver can build it to the root it trusts."""

    def __init__(self, ip, port, receiver_name, ca_path, timeout, label="hybrid",
                 cert_path=None, key_path=None):
        super().__init__(ip, port, receiver_name, ca_path, timeout)
        self.LABEL = label
        self.cert_path, self.key_path = cert_path, key_path

    def _openssl_argv(self):
        argv = super()._openssl_argv() + ["-verify_ip", self.ip]
        if self.cert_path and self.key_path:
            argv += ["-cert", self.cert_path, "-key", self.key_path, "-cert_chain", self.cert_path]
        return argv


class _QuicPqcResponse:
    """Just enough of `http.client.HTTPResponse` for `_http_exchange()` to read."""

    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self):
        return self._body


class _QuicPqcConnection:
    """`quic-pqc` tech (2026-09-28) — Stack 5: a REAL hybrid-PQC TLS 1.3 handshake INSIDE a real
    QUIC connection (X25519MLKEM768 + ML-DSA-65 server cert), then a real HTTP/3 request over it.
    `pqkex`'s idea applied to QUIC/UDP instead of a stunnel front door over TCP — but unlike
    EVERY other real-handshake PQC tech here, no private OpenSSL/wolfSSL C toolchain: `aioquic`
    implements TLS 1.3 itself in pure Python via `cryptography`, which ships native ML-KEM-768/
    ML-DSA-65 support already (see PQC-bench/aioquic-patch/README.md for the full story).

    The toolchain lives in its OWN venv (`/opt/pqc-libs/quic-pqc-venv`), never this process's
    interpreter — same reasoning `_PQKexConnection` shells out to `openssl s_client` instead of
    importing anything: the right toolchain for a given PQC tech is essentially never the process
    already running. `quic_pqc_client_helper.py` does the actual exchange as a subprocess, one
    JSON request in on stdin, one JSON response out on stdout."""

    QUIC_PQC_PYTHON = os.environ.get(
        "QUIC_PQC_PYTHON", "/opt/pqc-libs/quic-pqc-venv/bin/python3")
    QUIC_PQC_HELPER = os.environ.get(
        "QUIC_PQC_HELPER", "/opt/PQC-bench/aioquic-patch/quic_pqc_client_helper.py")

    def __init__(self, ip, port, receiver_name, ca_path, timeout, cert_path=None, key_path=None,
                 kex="hybrid", certs="mldsa", label="quic-pqc", expect=None):
        self.ip, self.port, self.receiver_name, self.ca_path = ip, port, receiver_name, ca_path
        self.timeout = timeout
        # `quic-pqc-mutual` (2026-09-28, Stack 6): both None for plain `quic-pqc`.
        self.cert_path, self.key_path = cert_path, key_path
        # 2026-10-02: what this connection OFFERS. `quic-pqc` = hybrid KEX + ML-DSA certs (the
        # default, unchanged); `quic-hybrid` = hybrid KEX + the fleet's RSA certs; `quic-classical`
        # = X25519 + RSA certs. The helper offers ONLY that, so a completed handshake proves it.
        self.kex, self.certs, self.label = kex, certs, label
        # 2026-10-23: what the handshake must have negotiated for this to BE this tech; the helper checks it
        # before sending any data. {"group": ..., "peer_key_prefix": "RSA" | "ML-DSA"}
        self.expect = expect
        self.helper_negotiated = None
        self.helper_timing = None
        self.helper_net = None
        self._method = self._path = self._body = None
        self._headers = {}

    def request(self, method, path, body=None, headers=None):
        self._method, self._path = method, path
        self._body = body if isinstance(body, (bytes, bytearray)) else (body or b"")
        self._headers = dict(headers or {})

    def getresponse(self):
        req = {
            "host": self.ip, "port": self.port, "server_name": self.receiver_name,
            "ca_path": self.ca_path, "method": self._method, "path": self._path,
            "headers": self._headers,
            "body_b64": base64.b64encode(self._body).decode() if self._body else "",
            "kex": self.kex, "certs": self.certs,
        }
        if self.expect:
            req["expect"] = self.expect
        if self.cert_path and self.key_path:
            req["cert_path"], req["key_path"] = self.cert_path, self.key_path
        try:
            r = subprocess.run([self.QUIC_PQC_PYTHON, self.QUIC_PQC_HELPER],
                               input=json.dumps(req), capture_output=True, text=True,
                               timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            raise errors.PeerUnreachable(
                f"{self.label} request to {self.receiver_name} timed out: {e}")
        try:
            result = json.loads(r.stdout)
        except (json.JSONDecodeError, ValueError):
            raise errors.PeerUnreachable(
                f"{self.label} helper for {self.receiver_name} produced no result "
                f"(rc={r.returncode}): {(r.stderr or '').strip()[-300:]}")
        if not result.get("ok"):
            if result.get("error") == "IdentityError":
                raise errors.IdentityError(
                    f"{self.receiver_name}'s {self.label} identity did not verify: {result.get('reason')}")
            raise errors.PeerUnreachable(
                f"could not reach {self.receiver_name} ({self.ip}:{self.port}) over {self.label}: "
                f"{result.get('reason')}")
        # The helper's own phase clocks (handshake / request->reply), for _Timing.note(), and what its
        # transport saw (handshake bytes / CPU, RTT, lost packets), for _Timing.note_net(): what the
        # caller cannot see from outside the subprocess.
        self.helper_timing = result.get("timing")
        self.helper_net = {k: (self.helper_timing or {}).get(k) for k in _Timing.NET_KEYS}
        self.helper_negotiated = result.get("negotiated")
        return _QuicPqcResponse(result["status"], base64.b64decode(result["body_b64"]))

    def close(self):
        pass  # each exchange is one subprocess, already exited by the time this is called

# `coap` (2026-08-10, operator-directed: "allow coap with no encryption too"). CoAP/UDP with the
# SAME signed identity envelope as `coap-enc`, minus the hybrid encryption — the payload travels in
# cleartext. This is RFC 7252's NoSec mode with authenticity kept on top, and it is the honest
# constrained-device option: an MCU that cannot afford RSA-OAEP+AES-GCM per message can still prove
# who it is.
#
# What is given up, precisely: CONFIDENTIALITY, and only that. Anyone who can see the UDP traffic
# reads the payload. What is NOT given up is identity or authorisation — the cert+signature envelope
# and the per-pair policy check are byte-for-byte the same as `coap-enc`'s, because dropping those
# would make the receiver unable to say who is talking to it and would render the policy table
# decorative. Same reasoning `https` follows for being weaker-but-still-authenticated than `mtls`.
COAP_RESOURCE = {"message": "message", "file": "deliver", "status": "status", "rm": "rm-exec",
                 "ml": "ml-op", "fetch": "fetch"}

# The comm-log's OLD `type` vocabulary, which conflated the two axes ("message-coap" is a use case
# and a transport in one token). Still written on every record so nothing that reads it breaks, but
# `use_case` + `tech` are the fields to read now.
LEGACY_TYPE = {"message": "message", "file": "deliver", "status": "status", "rm": "rm-exec"}


def legacy_type(use_case, tech):
    if str(tech).startswith("coap") and use_case == "message":
        return "message-coap"
    return LEGACY_TYPE.get(use_case, use_case)


def coap_status_code(code):
    """A CoAP response code as the HTTP-style integer the receiver's half of the comm-log uses (2.04 -> 204,
    4.01 -> 401), so both halves of one exchange carry the same status. The CLI result keeps aiocoap's raw
    integer (2.04 == 68) in `status`, unchanged for its existing readers."""
    c = int(code)
    return (c >> 5) * 100 + (c & 0x1F)


_TS_SEEN = {}


def _unique_ts(payload_bytes: bytes) -> int:
    """The signed envelope's ts, never the same twice for the same payload bytes in this process.

    RSA-PKCS1v15 is deterministic and the signature covers only payload+ts (xid is NOT signed), so two separate
    exchanges with the same payload inside one wall-clock second would be byte-identical on the wire, which a
    receiver's replay ring (bare-metal p2p_receiver.c 4b) cannot tell from a retransmit. Bump by 1 s per reuse
    (freshness tolerates +-60 s). Bounded: entries older than 120 s are dropped."""
    now = int(time.time())
    for k in [k for k, v in _TS_SEEN.items() if now - v > 120]:
        del _TS_SEEN[k]
    key = hashlib.sha256(payload_bytes).digest()
    ts = now
    last = _TS_SEEN.get(key)
    if last is not None and ts <= last:
        ts = last + 1
    _TS_SEEN[key] = ts
    return ts


class Client:
    def __init__(self, name=None, server_api_base=None, bootstrap_secret=None, cache_dir=None, port=None,
                 pqc_cache_dir=None, https_port=None):
        self.name = name or os.environ["P2P_NODE_NAME"]
        self.server_api = server_api_base or os.environ["SERVER_API_BASE"]
        self.secret = bootstrap_secret or os.environ["BOOTSTRAP_SECRET"]
        self.cache_dir = cache_dir or os.environ.get("P2P_CACHE_DIR", "/var/lib/p2p/certs")
        self.port = port or int(os.environ.get("P2P_PORT", "8443"))
        # A second port for the `https` tech (2026-07-28) — see the module docstring for why it is
        # not just CERT_OPTIONAL on the mTLS port.
        self.https_port = https_port or int(os.environ.get("P2P_HTTPS_PORT", "8444"))
        # `http` (2026-09-26): a THIRD port, same reasoning `https` already gives for not reusing
        # the mTLS port — a plaintext listener on the mTLS or https port would mean either of THOSE
        # ports has to accept an unencrypted connection too, weakening both.
        self.http_port = int(os.environ.get("P2P_HTTP_PORT", "8442"))
        self.coap_port = int(os.environ.get("P2P_COAP_PORT", "5683"))
        # `pqkex` (2026-09-27): the hybrid-TLS front door PQC-bench/p2p-proxy/ installs per node,
        # fronting this SAME node's plaintext `http_port` -- a different port because it is a
        # separate stunnel process, not a mode of the plain listener above.
        self.pqkex_port = int(os.environ.get("P2P_PQKEX_PORT", "9444"))
        # `pqc` (2026-10-23): the receiver's own ML-KEM-768 + ML-DSA-65 mutual TLS listener (server.py) --
        # see build_pqc_*_context in identity.py.
        self.pqc_port = int(os.environ.get("P2P_PQC_PORT", "8446"))
        # `pqkex-mutual` (2026-09-27): a SEPARATE stunnel section (same conf file, `verify = 2`)
        # fronting the SAME plaintext http_port -- a different port so `pqkex`'s own server-auth-only
        # 9444 never starts demanding a client cert an already-provisioned pqkex-only node lacks.
        self.pqkex_mutual_port = int(os.environ.get("P2P_PQKEX_MUTUAL_PORT", "9447"))
        # `quic-pqc` (2026-09-28): the quic_pqc_relay.py process's own UDP port on the receiver --
        # a separate listener (real QUIC, not a stunnel front door), same "own port, own process"
        # reasoning as every other real-handshake tech here.
        self.quic_pqc_port = int(os.environ.get("P2P_QUIC_PQC_PORT", "4433"))
        # `quic-pqc-mutual` (2026-09-28, Stack 6): a SEPARATE relay port with
        # _request_client_certificate=True -- `quic-pqc`'s own :4433 untouched, same additive
        # shape every other mutual variant here uses.
        self.quic_pqc_mutual_port = int(os.environ.get("P2P_QUIC_PQC_MUTUAL_PORT", "4434"))
        # `coap-dtls-pqc` (2026-09-27): coap_dtls_pqc_relay.py's own dedicated port -- a different
        # port from `coap_port` for the same reason pqkex_port differs from http_port: a separate
        # process (the relay), not a mode of the plain CoAP listener.
        self.coap_dtls_pqc_port = int(os.environ.get("P2P_COAP_DTLS_PQC_PORT", "5685"))
        # `coap-dtls-pqc-mutual` (2026-09-28, Stack 4): a SEPARATE relay instance/port with
        # `verify_mode = CERT_REQUIRED` -- `coap-dtls-pqc`'s own :5685 stays untouched (no client
        # cert demanded), same additive shape `pqkex-mutual`/`p2p-pqc-mutual` already established.
        self.coap_dtls_pqc_mutual_port = int(os.environ.get("P2P_COAP_DTLS_PQC_MUTUAL_PORT", "5686"))
        # 2026-10-02: the eight techs that pair a key exchange with the other certificate set. Each
        # has its OWN port (a different listener or relay instance), for the same reason every
        # mutual variant above does: nothing already deployed on the older ports changes behaviour.
        self.hybrid_port = int(os.environ.get("P2P_HYBRID_PORT", "9454"))
        self.hybrid_mutual_port = int(os.environ.get("P2P_HYBRID_MUTUAL_PORT", "9455"))
        self.quic_hybrid_port = int(os.environ.get("P2P_QUIC_HYBRID_PORT", "4441"))
        self.quic_hybrid_mutual_port = int(os.environ.get("P2P_QUIC_HYBRID_MUTUAL_PORT", "4442"))
        self.quic_classical_port = int(os.environ.get("P2P_QUIC_CLASSICAL_PORT", "4443"))
        self.quic_classical_mutual_port = int(os.environ.get("P2P_QUIC_CLASSICAL_MUTUAL_PORT", "4444"))
        self.coap_dtls_port = int(os.environ.get("P2P_COAP_DTLS_PORT", "5687"))
        self.coap_dtls_mutual_port = int(os.environ.get("P2P_COAP_DTLS_MUTUAL_PORT", "5688"))
        # §3.8.2 phase 3 (2026-08-21): sender-local, per-box opt-in -- correctly NOT a fleet-wide
        # flag (unlike the bootstrap-secret rotation this design deliberately avoids repeating,
        # see monitor.md's own comparison table). Default "0" (observe mode) so a box's own
        # node-agent.timer catching up its coap_signing self-report is never what silently starts
        # enforcing -- this is a separate, explicit opt-in, read once per process the same way
        # every other env-derived setting on this object already is.
        self.coap_require_signed_response = os.environ.get(
            "P2P_COAP_REQUIRE_SIGNED_RESPONSE", "0").strip().lower() in ("1", "true", "yes")
        cert, key, ca = identity.fetch_own_cert(self.server_api, self.secret, self.name, self.cache_dir)
        self._cert_path, self._key_path, self._ca_path = cert, key, ca
        # 2026-10-23 (v2): load the signing key (and the `cryptography` import behind it) NOW, once per process.
        # The first /resolve signs this node's name with it, so a fresh process used to book that one-time
        # ~45 ms import into the first exchange's resolve_ms (HTTP techs 80 ms vs CoAP 35 ms for the same hop).
        try:
            identity.sign_payload(key, self.name.encode())
        except Exception:                                   # noqa: BLE001 -- best-effort warm-up only
            pass
        self._ctx = identity.build_client_context(cert, key, ca)
        # `https`: verify the RECEIVER exactly as strictly as mtls does (same fleet CA, same
        # post-handshake CN + SAN checks) but send no client certificate of our own. Only the
        # sender's half of the mutual authentication is given up — never the receiver's.
        self._ctx_https = identity.build_client_context(cert, key, ca, client_cert=False)
        # PQC (2026-07-26, operator-directed): a selectable ADDITION on top of the classical mTLS
        # connection above, not a second transport -- see identity.py's PQC section header comment
        # for why (Python's ssl can't do a PQC handshake at all). Loaded lazily/best-effort: most
        # nodes won't have a PQC identity provisioned, and that's fine until a caller actually asks
        # for pqc=True.
        self._pqc_cache_dir = pqc_cache_dir or os.environ.get(
            "P2P_PQC_CACHE_DIR", identity.PQC_CACHE_DIR_DEFAULT)
        self._pqc_material = None   # lazy: (cert_path, key_path, ca_path), or "unavailable"
        self._pqc_ctx = {}          # client_cert(bool) -> pinned PQC TLS context, built on first use

    def _pqc(self):
        """-> (cert_path, key_path, ca_path) for this node's PQC identity, or raises IdentityError
        with a clear reason (no toolchain / no minted cert) -- never a silent fallback to classical,
        since a caller that explicitly asked for pqc=True should know if it didn't happen."""
        if self._pqc_material is None:
            if not identity.pqc_available():
                raise errors.IdentityError(
                    f"PQC requested but the toolchain isn't installed on {self.name} "
                    f"(expected {identity.PQC_OPENSSL})")
            self._pqc_material = identity.load_pqc_material(self._pqc_cache_dir)
        return self._pqc_material

    def _pqc_tls_context(self, mutual):
        if mutual not in self._pqc_ctx:
            cert, key, ca = self._pqc()
            self._pqc_ctx[mutual] = identity.build_pqc_client_context(cert, key, ca, client_cert=mutual)
        return self._pqc_ctx[mutual]

    def _refresh_identity(self):
        # 2026-08-02, found live: fetch_own_cert()'s cache ("if all 3 files exist, reuse
        # untouched") has no staleness detection at all, same class of bug as device.py's old
        # rc=5 stale-token issue -- if the server's fleet CA gets reissued/reset (e.g. after a
        # full-clean-recreate), a cached ca.crt can never verify a live peer again, and every
        # exchange fails forever with SSLCertVerificationError until someone notices and clears
        # the cache by hand. Refetch so a verify failure below can self-heal once instead of
        # wedging permanently.
        #
        # MUST fetch into a scratch dir first and only swap it in on success -- found live: an
        # earlier version of this wiped self.cache_dir up front, then a legitimate 401 from
        # /p2p-cert (the server already has a non-revoked cert on file for us and now demands
        # proof of possession, not just the bootstrap secret -- api_server.py's documented
        # 2026-07-27 anti-key-handout fix) left the node with NO local identity at all, worse
        # off than before the refresh was attempted. This can still fail (that 401 case isn't
        # handled -- would need node_identity_headers() built from the STILL-cached, possibly
        # CA-orphaned-but-still-server-recognized cert, passed as proof; not done here), but a
        # failure now cleanly raises with the OLD cache untouched, instead of destroying it.
        tmp_dir = tempfile.mkdtemp(prefix=".refresh-", dir=os.path.dirname(self.cache_dir.rstrip("/")) or None)
        try:
            cert, key, ca = identity.fetch_own_cert(self.server_api, self.secret, self.name, tmp_dir)
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        shutil.rmtree(self.cache_dir, ignore_errors=True)
        shutil.move(tmp_dir, self.cache_dir)
        cert = os.path.join(self.cache_dir, os.path.basename(cert))
        key = os.path.join(self.cache_dir, os.path.basename(key))
        ca = os.path.join(self.cache_dir, os.path.basename(ca))
        self._cert_path, self._key_path, self._ca_path = cert, key, ca
        self._ctx = identity.build_client_context(cert, key, ca)
        self._ctx_https = identity.build_client_context(cert, key, ca, client_cert=False)

    def _connect(self, receiver_name, tech="mtls", timeout=None, _retried=False, timing=None):
        """Open the connection for an HTTP-family tech. `https` goes to its own port with a
        certless client context; `mtls`/`pqc` share the mutual-auth port and context. The RECEIVER
        is verified identically either way — the checks below are not relaxed for https. `http`
        (2026-09-26) is a genuinely separate case, handled first and returned early: no TLS
        session exists at all, so none of the peer-certificate verification below applies — see
        the module docstring's `http` entry for exactly what that gives up.

        `timing` (2026-09-30): a `_Timing` to lap resolve / TCP connect / handshake into. The TLS
        techs do HTTPSConnection.connect()'s two steps by hand (TCP, then wrap_socket) so the
        handshake can be timed on its own — the same two calls, in the same order."""
        timing = timing or _Timing(tech)
        snap = timing.snapshot()            # rewound to, if this attempt fails verification and is retried
        resolved = identity.resolve(self.server_api, self.secret, receiver_name, frm=self.name)
        timing.lap("resolve_ms")
        if resolved.get("stale"):
            print(f"[p2p-client:{self.name}] resolve('{receiver_name}') served from a "
                  f"{resolved['stale_age_s']}s-old cache -- Server unreachable", file=sys.stderr, flush=True)
        ip = resolved.get("ip")
        if not ip:
            raise errors.ResolveError(f"resolve('{receiver_name}') had no /32")
        if tech == "http":
            try:
                conn = http.client.HTTPConnection(ip, self.http_port, timeout=timeout or self.SOCKET_TIMEOUT)
                conn.connect()
            except OSError as e:
                raise errors.PeerUnreachable(f"could not reach {receiver_name} ({ip}:{self.http_port}): {e}")
            timing.lap("tcp_connect_ms")
            return conn, resolved, identity.tls_info(conn.sock)
        if tech == "pqkex":
            # Needs a PQC identity of our OWN only to locate the CA (`_pqc()` also raises the same
            # clear IdentityError `pqc` does if this node has no PQC toolchain/material -- correct
            # here too, since verifying the PEER's ML-DSA-65 cert needs the same CA root). This
            # node's own cert/key are irrelevant to pqkex (the envelope is classical, see the
            # module docstring) -- only `ca` is used below.
            _cert, _key, ca = self._pqc()
            conn = _PQKexConnection(ip, self.pqkex_port, receiver_name, ca,
                                    timeout or self.SOCKET_TIMEOUT)
            return conn, resolved, {"tls_version": "TLSv1.3", "group": "X25519MLKEM768",
                                    "peer_cert_sigalg": "mldsa65", "port": self.pqkex_port}
        if tech == "pqkex-mutual":
            # Unlike `pqkex`, THIS node's own cert/key are load-bearing: the mutual front door
            # (`[p2p-pqc-mutual]`, port 9447) refuses the handshake outright without them.
            cert, key, ca = self._pqc()
            conn = _PQKexMutualConnection(ip, self.pqkex_mutual_port, receiver_name, ca, cert, key,
                                          timeout or self.SOCKET_TIMEOUT)
            return conn, resolved, {"tls_version": "TLSv1.3", "group": "X25519MLKEM768",
                                    "peer_cert_sigalg": "mldsa65", "client_cert": "mldsa65",
                                    "port": self.pqkex_mutual_port}
        if tech in ("hybrid", "hybrid-mutual"):
            # Hybrid KEX + the CLASSICAL fleet certificate: nothing PQC is provisioned for the
            # certificates, so only the private OpenSSL (for the hybrid group) is needed here.
            mutual = tech == "hybrid-mutual"
            port = self.hybrid_mutual_port if mutual else self.hybrid_port
            conn = _HybridTlsConnection(ip, port, receiver_name, self._ca_path,
                                        timeout or self.SOCKET_TIMEOUT, label=tech,
                                        cert_path=self._cert_path if mutual else None,
                                        key_path=self._key_path if mutual else None)
            return conn, resolved, {"tls_version": "TLSv1.3", "group": "X25519MLKEM768",
                                    "peer_cert_sigalg": "rsa",
                                    **({"client_cert": "rsa"} if mutual else {}), "port": port}
        if tech in ("quic-hybrid", "quic-hybrid-mutual", "quic-classical", "quic-classical-mutual"):
            # Classical RSA certificates, so the fleet CA and this node's own fleet leaf -- not the
            # separate ML-DSA quic-pqc CA the `quic-pqc` branch below needs.
            mutual = tech.endswith("-mutual")
            classical_kex = tech.startswith("quic-classical")
            port = {"quic-hybrid": self.quic_hybrid_port,
                    "quic-hybrid-mutual": self.quic_hybrid_mutual_port,
                    "quic-classical": self.quic_classical_port,
                    "quic-classical-mutual": self.quic_classical_mutual_port}[tech]
            conn = _QuicPqcConnection(ip, port, receiver_name, self._ca_path,
                                      timeout or self.SOCKET_TIMEOUT,
                                      cert_path=self._cert_path if mutual else None,
                                      key_path=self._key_path if mutual else None,
                                      kex="classical" if classical_kex else "hybrid",
                                      certs="classical", label=tech,
                                      expect={"group": "X25519" if classical_kex else "X25519MLKEM768",
                                              "peer_key_prefix": "RSA", "peer_ip": ip})
            return conn, resolved, {}
        if tech in ("quic-pqc", "quic-pqc-mutual"):
            # A separate CA (quic_pqc_ca.py, not self._pqc()'s oqs-provider one) -- confirmed live
            # the private key encodings aren't cross-compatible, see
            # PQC-bench/aioquic-patch/README.md.
            ca = os.environ.get("QUIC_PQC_CA_PATH", "/var/lib/p2p/certs-quic-pqc/ca.crt")
            if not os.path.exists(ca):
                raise errors.IdentityError(
                    f"no quic-pqc CA at {ca} -- provision it first (PQC-bench/aioquic-patch/)")
            mutual = tech == "quic-pqc-mutual"
            cert_path = key_path = None
            if mutual:
                # `quic-pqc-mutual` (2026-09-28, Stack 6): THIS node's own ML-DSA-65 leaf, minted
                # by quic_pqc_ca.py (same CA as the CA-verification above) -- a SEPARATE identity
                # from self._pqc()'s, for the same reason the CA is separate. Required for the
                # relay's `[quic-pqc-mutual]` port (4434) to accept the handshake at all.
                cert_path = os.environ.get("QUIC_PQC_CERT_PATH",
                                           "/var/lib/p2p/certs-quic-pqc/peer.crt")
                key_path = os.environ.get("QUIC_PQC_KEY_PATH",
                                          "/var/lib/p2p/certs-quic-pqc/peer.key")
                if not (os.path.exists(cert_path) and os.path.exists(key_path)):
                    raise errors.IdentityError(
                        f"no quic-pqc identity for {self.name} at {cert_path}/{key_path} -- "
                        f"mint one first (PQC-bench/ca/quic_pqc_ca.py issue {self.name} <ip> <tenant>)")
            port = self.quic_pqc_mutual_port if mutual else self.quic_pqc_port
            # PQC = pure ML-KEM-768 (2026-10-23) + the relay's ML-DSA-65 certificate (+ ours on -mutual)
            conn = _QuicPqcConnection(ip, port, receiver_name, ca, timeout or self.SOCKET_TIMEOUT,
                                      cert_path=cert_path, key_path=key_path, kex="mlkem",
                                      expect={"group": PQC_GROUP, "peer_key_prefix": "ML-DSA",
                                              "peer_ip": ip})
            return conn, resolved, {}
        if tech == "pqc":
            port = self.pqc_port
            ctx = self._pqc_tls_context(True)     # our ML-DSA-65 client certificate is our identity
        else:
            port = self.https_port if tech == "https" else self.port
            ctx = self._ctx_https if tech == "https" else self._ctx
        try:
            conn = http.client.HTTPSConnection(ip, port, context=ctx,
                                               timeout=timeout or self.SOCKET_TIMEOUT)
            # HTTPSConnection.connect() is exactly these two steps (no proxy tunnel is ever set
            # here); done by hand so the TLS handshake is timed apart from the TCP connect.
            http.client.HTTPConnection.connect(conn)
            timing.lap("tcp_connect_ms")
            cpu0 = time.thread_time()           # OpenSSL runs the handshake in this thread
            conn.sock = ctx.wrap_socket(conn.sock, server_hostname=conn.host)
            hs_cpu_ms = (time.thread_time() - cpu0) * 1000
            # what the handshake put on the wire, read right after our Finished went out (before any
            # NewSessionTicket can arrive): TLS records this side wrote / read, retransmissions excluded
            ti = _tcp_info(conn.sock)
        except ssl.SSLCertVerificationError as e:
            if tech == "pqc":
                # the PQC identity is provisioned offline: there is no /p2p-cert refresh to retry with
                raise errors.IdentityError(f"{receiver_name}'s ML-DSA-65 certificate did not verify: {e}")
            if _retried:
                raise errors.PeerUnreachable(
                    f"could not reach {receiver_name} ({ip}:{port}): cert refresh didn't help: {e}")
            self._refresh_identity()
            # The failed attempt and the refresh are not this exchange's cost: the block describes the retry.
            timing.rewind(snap)
            print(f"[p2p-client:{self.name}] {tech} handshake to {receiver_name} failed verification; "
                  f"identity refreshed and retried (the timing block covers the retry)", file=sys.stderr, flush=True)
            return self._connect(receiver_name, tech=tech, timeout=timeout, _retried=True,
                                 timing=timing)
        except OSError as e:
            raise errors.PeerUnreachable(f"could not reach {receiver_name} ({ip}:{port}): {e}")
        # 2026-07-28 security review: verify WHO answered. build_client_context() sets
        # check_hostname=False and its docstring promises "identity is verified explicitly by CN
        # after the handshake (peer_identity())" -- but peer_identity() was only ever called on the
        # RECEIVER side. The sender checked nothing. CERT_REQUIRED against the fleet CA only proves
        # the peer holds *a* valid fleet certificate, and every node has one, so any node could
        # answer for any other: on this deliberately any-to-any fabric an attacker that takes the
        # victim's /32 (added as a secondary address, or after a victim reboot) receives the payload,
        # completes the handshake, and returns whatever it likes -- and the sender's own comm-log
        # entry records a perfectly normal successful exchange.
        # The certs already carry SAN IP:<the /32> (mtls_ca.issue), so both bindings below are free.
        try:
            peer_cn = identity.peer_identity(conn.sock)
        except Exception as e:
            conn.close()
            raise errors.IdentityError(f"could not read {receiver_name}'s certificate: {e}")
        if peer_cn != receiver_name:
            conn.close()
            raise errors.IdentityError(
                f"peer at {ip}:{port} presented cert for {peer_cn!r}, expected {receiver_name!r}")
        san_ips = {v for k, v in (conn.sock.getpeercert() or {}).get("subjectAltName", ())
                   if k == "IP Address"}
        if san_ips and ip not in san_ips:
            conn.close()
            raise errors.IdentityError(
                f"{receiver_name}'s cert is bound to {sorted(san_ips)}, but we connected to {ip}")
        # the tech is defined by its key exchange: pqc = ML-KEM-768 only; https/mtls = classical X25519 only (2026-10-23:
        # without the pin they negotiated the X25519MLKEM768 hybrid on OpenSSL 3.5). Offered alone, so a mismatch means
        # a pin did not apply: refuse before any data is written.
        neg_group = identity.negotiated_group(conn.sock)
        want_group = PQC_GROUP if tech == "pqc" else CLASSICAL_GROUP
        if neg_group is not None and neg_group.lower() != want_group.lower() or (neg_group is None and tech == "pqc"):
            conn.close()
            raise errors.IdentityError(f"{tech}: the handshake negotiated {neg_group!r}, not {want_group}")
        neg_group = want_group if neg_group is not None else None     # one spelling across stacks ("x25519" -> "X25519")
        # 2026-10-23 (v2): the handshake phase ends HERE, after the check of who answered -- as on QUIC
        # (aioquic checks the name inside its handshake) and DTLS (the worker checks before writing data).
        # The separate verify_peer_ms (a constant ~0.2 ms) is retired.
        if ti:
            timing.note_net(handshake_bytes_out=ti["bytes_sent"] - ti["bytes_retrans"] + ti["notsent_bytes"],
                            handshake_bytes_in=ti["bytes_received"])
        timing.note_net(handshake_cpu_ms=hs_cpu_ms)
        timing.lap("handshake_ms")
        # What this connection actually negotiated (2026-07-28, management/fix.md's "in the tech
        # column show more details e.g. TLS: openssl 1.3"). Read now, while the socket is live —
        # every caller below closes the connection before it reports.
        info = identity.tls_info(conn.sock)
        if neg_group:
            conn.negotiated = {**{k: v for k, v in info.items() if k.startswith("tls_")}, "group": neg_group}
        return conn, resolved, info

    @staticmethod
    def _new_exchange_id():
        """One id per exchange, minted by the sender and echoed back by the receiver (2026-07-28,
        management/fix.md). It is what lets the Server's mirror join the sender's "I put N bytes on
        the wire" against the receiver's "I took M bytes off it" -- without it, the two reports of
        one exchange are only correlatable by guessing from (sender, receiver, type, ~timestamp).
        Carries no authority: identity is still the mTLS peer cert, and the id is echoed by the
        peer, so it is a correlation hint for a log that is explicitly a mirror, nothing more."""
        return uuid.uuid4().hex

    def _report(self, use_case, tech, receiver_name, t0, ok, status_code=None, nbytes=0,
               payload=None, reason=None, exchange_id=None, tls=None, peer_verified=None,
               timing=None, negotiated=None):
        # Operator-directed (2026-07-26): mirror EVERY P2P send attempt -- message, timing, outcome
        # -- to the Server, best-effort (comm_log.report never raises). See comm_log.py's docstring
        # for why this is a mirror, not the authoritative record.
        # `use_case` + `tech` are reported SEPARATELY (2026-07-28, operator-directed) because they
        # are separate questions. `type` is still written alongside them, in its old vocabulary
        # ("message"/"deliver"/"status"/"message-coap"), so every existing reader keeps working --
        # but it is the legacy field now, and anything new should read the two explicit ones.
        # `tls` (identity.tls_info()) is what the connection actually negotiated; absent on a
        # failure that never got as far as a handshake, which is itself the honest answer there.
        comm_log.report(self.server_api, self.secret,
                        reported_by="sender", node=self.name, sender=self.name,
                        receiver=receiver_name, use_case=use_case, tech=tech,
                        type=legacy_type(use_case, tech), pqc=(tech in PQC_TECHS), ok=ok,
                        status_code=status_code,
                        duration_ms=round((time.time() - t0) * 1000, 2), bytes=nbytes,
                        exchange_id=exchange_id, payload=payload or {}, reason=reason,
                        **(tls or {}))
        # 2026-08-20 (monitor.md §12.7, D26): THIS box's own authoritative record of the outcome,
        # independent of whether the mirror above ever reaches the Server -- see sender_log.py's
        # own docstring. Pairs with the "attempt" line written before the exchange started.
        # `peer_verified` (§3.8.2 phase 2, 2026-08-21): None on every tech but coap-enc/coap today
        # (only the CoAP receiver signs responses so far) -- True/False/None, never gates the
        # exchange itself, see `_verify_coap_response()`'s own docstring.
        sender_log.record("result", exchange_id, receiver_name, use_case, tech, ok=ok,
                          status_code=status_code,
                          duration_ms=round((time.time() - t0) * 1000, 2), bytes=nbytes,
                          reason=reason, peer_verified=peer_verified,
                          **({"timing": timing} if timing else {}),
                          **({"negotiated": negotiated} if negotiated else {}))
        # `timing` (2026-09-30) goes to THIS box's own log only, not the Server mirror: the mirror
        # is Server-shaped and its schema is not ours to widen from here.
        # No `bytes_expected` here on purpose: for the SENDER attempted == what it wrote, so a
        # self-comparison would always pass and would render as a byte-verified tick on a record
        # nothing has actually corroborated. Only the receiver knows a second, independent number
        # (the framing length it was promised), and only the sender+receiver join answers
        # "delivered == attempted" -- see p2p_comm_log.annotate_bytes.

    # ── use case × tech ──────────────────────────────────────────────────────
    # 2026-07-28, operator-directed: "a use case e.g. message can be sent with each `tech`, and not
    # only with a specific one". Before this, the two were tangled — file delivery existed on mTLS
    # only, `status` had no CoAP form, and the CoAP transport carried messages and nothing else. The
    # USE CASES (what is being exchanged) and TECHS (how it is protected) are independent axes, and
    # every one of the sixteen combinations works:
    #
    #            | mtls | https | pqc | coap-enc
    #   message  |  ✓   |   ✓   |  ✓  |    ✓
    #   file     |  ✓   |   ✓   |  ✓  |    ✓
    #   status   |  ✓   |   ✓   |  ✓  |    ✓
    #   rm       |  ✓   |   ✓   |  ✓  |    ✓
    #   ml       |  ✓   |   ✓   |  ✓  |    ✓
    #
    # `rm` joined them on 2026-07-28 (management/fix.md's "a device X can do remote management to
    # dev Y") and it is a use case like any other precisely BECAUSE it is the strongest one: adding
    # it as a fourth route means it inherits the identity gate, the per-pair policy check and the
    # mirror from the same code path as a message, instead of growing a second, weaker door.
    #
    # The public methods below are named for the USE CASE and take `tech=` — never the reverse.
    # `fetch` (2026-09-29, on-dev-api P4.1) is the one PULL use case — see fetch_file().
    USE_CASES = ("message", "file", "status", "rm", "ml", "fetch")
    ROUTES = {"message": ("POST", "/message"), "file": ("POST", "/deliver"),
              "status": ("GET", "/status"), "rm": ("POST", "/rm-exec"),
              "ml": ("POST", "/ml-op"), "fetch": ("POST", "/fetch")}

    def _tech(self, tech, pqc):
        """Resolve the tech for one call. `pqc=True` is the pre-2026-07-28 spelling of
        `tech="pqc"`; it is still accepted (cli.py's --pqc, the GUI toggle, existing callers) and
        means the same thing. Conflicting arguments are an error rather than a silent winner."""
        if pqc and tech not in (None, "pqc"):
            raise ValueError(f"pqc=True conflicts with tech={tech!r}")
        tech = tech or ("pqc" if pqc else "mtls")
        if tech not in TECHS:
            raise ValueError(f"unknown tech {tech!r} — one of {tech_listing()}")
        return tech

    def deliver_file(self, receiver_name, data: bytes, dest_filename, tech=None, pqc=False, timeout=None):
        """Use case FILE: deliver raw bytes, to be written under the receiver's own received/ dir.
        Works on every tech (2026-07-28) — on the envelope techs the bytes ride base64 inside the
        SIGNED payload, so the signature covers the file itself, not just its name."""
        return self._exchange("file", receiver_name, self._tech(tech, pqc),
                              payload={"dest_filename": dest_filename}, data=data, timeout=timeout)

    def put_file(self, receiver_name, data: bytes, path, job_id=None, mode=None, tech=None,
                 pqc=False, timeout=None):
        """Command & control PUT_FILE (2026-09-26): the `file` use case with rm_agent.put_file's
        contract -- the bytes land in the receiver's per-job folder (JOBS_DIR/<job_id>/<basename>),
        sha256-checked BEFORE the write, `mode` applied, idempotent by sha256+path. The bytes travel
        inline over whichever tech carries the call (no side-channel pull), which is the point.

        -> {ok, status: delivered|checksum_mismatch|size_mismatch|error, job_id, path, sha256,
        bytes, cached}. Run it afterwards with remote_exec(receiver, <path>)."""
        put = {"job_id": job_id or f"put-{int(time.time())}-{uuid.uuid4().hex[:6]}",
               "sha256": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data)}
        if mode is not None:
            put["mode"] = mode
        return self._exchange("file", receiver_name, self._tech(tech, pqc),
                              payload={"dest_filename": path, "put_file": put}, data=data, timeout=timeout)

    def send_message(self, receiver_name, payload: dict, tech=None, pqc: bool = False):
        """Use case MESSAGE: deliver a JSON body (a sensor value, an actuator command)."""
        return self._exchange("message", receiver_name, self._tech(tech, pqc), payload=payload)

    def get_status(self, receiver_name, tech=None, pqc: bool = False, details: bool = False):
        """Use case STATUS: ask the receiver about itself. Carries no payload of its own; on the
        envelope techs it still sends a signed empty envelope, purely as an identity/integrity
        proof (that is what the receiver authenticates on those techs).
        `details=True` (2026-10-02): the reply also carries `details`, the receiver's Network Map row
        (its on-board API's map_details_self: ip, real_ip, role, lifecycle state, segment, parent,
        hops, via_chain). Asked with header X-P2P-Details on mtls, with a signed `details` flag in
        the envelope on every other tech. A receiver on older code ignores it (no `details` key)."""
        return self._exchange("status", receiver_name, self._tech(tech, pqc),
                              payload={"details": True} if details else {})

    def remote_exec(self, receiver_name, cmd, timeout=None, tech=None, pqc: bool = False):
        """Use case RM (2026-07-28) — DEVICE→DEVICE remote management: run `cmd` ON THE RECEIVER and
        get back its exit code and both streams. This is management/fix.md's "a device X can do
        remote management to dev Y (in/cross-tenant based on the policy)".

        No SSH, no key exchange, no Server in the data path: the receiver decides whether to run it
        from the same two facts it uses for a message — this sender's certificate, and the Server's
        per-pair policy verdict. Which is why cross-tenant RM needs no new machinery at all; it is
        the cross-tenant policy pair, and it is denied by default like every other cross pair.

        -> {ok, rc, stdout, stderr, refused, timed_out, via_chain, ...}. `ok` is the COMMAND's
        verdict (rc == 0). A `refused=True` reply is the receiver declining to run it at all (it has
        P2P_RM_ENABLED=0, or an allow-list the command is not on) — deliberately distinct from a
        command that ran and exited non-zero, and from an AuthorizationDenied, which is the POLICY
        refusing and still raises the way it does for every other use case."""
        return self._exchange("rm", receiver_name, self._tech(tech, pqc),
                              payload={"cmd": cmd, "timeout": timeout}, timeout=timeout)

    def ml_op(self, receiver_name, method, params=None, timeout=None, tech=None, pqc: bool = False):
        """Use case ML (2026-07-29) — run ONE enumerated ML operation on the receiver and get the
        receiver agent's own answer back. This is management/fix.md's "tenant admin user clicks or
        executes something -> this sends a code to the sender saying how to execute that with target
        the receiver": the click happens in the Tenant-Admin GUI, the CALL happens here, on the
        sender, over the same identity gate and the same per-pair policy as every other use case.

        `method` is one of receiver-role/handlers/ml.py's `ML_METHODS` — an enumerated verb, never a
        command — and `params` is the same params dict the identical ThingsBoard RPC takes, so a
        P2P `run_model` and a Tenant-Admin `run_model` are the same operation and not two dialects
        of one.

        -> {ok, method, result|reason, refused?, timed_out?, ...}. `ok` is the ML CALL's verdict; a
        policy refusal still raises AuthorizationDenied the way it does everywhere else."""
        return self._exchange("ml", receiver_name, self._tech(tech, pqc),
                              payload={"method": method, "params": params or {},
                                       "timeout": timeout},
                              timeout=timeout)

    def fetch_file(self, receiver_name, remote_path, tech=None, pqc: bool = False):
        """Use case FETCH (2026-09-29, on-dev-api P4.1) — the PULL counterpart of deliver_file():
        read ONE file off the receiver. Same identity gate and the same per-pair policy as every
        other use case; the receiver then applies its own node-local gates (P2P_FETCH_ENABLED,
        P2P_FETCH_ROOTS, no hidden components, P2P_FETCH_MAX_BYTES — receiver-role/handlers/
        fetch.py). The bytes come back base64 inside the reply, which on the envelope techs is the
        receiver's signed response.

        -> the receiver's reply plus `data` (the decoded bytes) and `sha256_ok` (the digest the
        receiver sent, recomputed here over what actually arrived). `ok` is False with
        `refused=True` when a receiver gate said no; a policy refusal raises AuthorizationDenied
        as it does everywhere else; a receiver that predates this use case answers 404."""
        r = self._exchange("fetch", receiver_name, self._tech(tech, pqc),
                           payload={"path": remote_path})
        blob = r.pop("data_b64", None)
        if r.get("ok") and blob is not None:
            data = base64.b64decode(blob)
            got = "sha256:" + hashlib.sha256(data).hexdigest()
            r["data"], r["sha256_ok"] = data, (got == r.get("sha256"))
            if not r["sha256_ok"]:
                r["ok"], r["reason"] = False, f"sha256 mismatch: receiver said {r.get('sha256')}, got {got}"
        return r

    def send_message_coap(self, receiver_name, payload: dict):
        """Kept as the name the CoAP transport was introduced under; `send_message(..., tech="coap-enc")`
        is the same call."""
        return self._exchange("message", receiver_name, "coap-enc", payload=payload)

    def path(self, receiver_name):
        """"Find the path" (management/fix.md: "through router-pc or p2p to find the path"), without
        sending anything — the same `GET /resolve` every send above makes first, surfaced on its own.

        The hop chain is computed by the Server from `netplan.json` (p2p_resolve.via_chain): a
        same-segment pair is two hops and no turn-around, a cousin pair turns at its shared
        (sub-)gateway or at the tenant's ROUTER-PC, and a cross-tenant pair climbs to each side's
        Router-PC and turns around at the global WireGuard hub. That is the answer to "how does X
        reach Y", and it is the same answer the data then follows — the Server is a name/authorize
        oracle here, never a relay.

        -> {ip, via_chain: [{name, ip, role}], hops: [name], cross_tenant, ...}."""
        r = identity.resolve(self.server_api, self.secret, receiver_name, frm=self.name)
        if r.get("stale"):
            print(f"[p2p-client:{self.name}] resolve('{receiver_name}') served from a "
                  f"{r['stale_age_s']}s-old cache -- Server unreachable", file=sys.stderr, flush=True)
        return {**r, "hops": [h.get("name") for h in (r.get("via_chain") or [])]}

    # ── the one exchange path ────────────────────────────────────────────────
    # How long to wait on the socket. 10s covers every use case whose work is a read or an append;
    # `rm` is the one whose work is arbitrary, so it waits for the command's own budget plus a
    # margin for the handshake and the reply — otherwise the sender would give up on a command the
    # receiver is still legitimately running, and report unreachable for something that worked.
    SOCKET_TIMEOUT = 10
    RM_TIMEOUT_MARGIN = 10

    def _socket_timeout(self, use_case, timeout):
        # OPTIONAL override (2026-10-01): an explicit `timeout` on the file / put-file use cases raises
        # the 10 s floor to that many seconds (cli.py `deliver|put-file --timeout S`). Not given -> the
        # unchanged flat 10 s, so existing callers behave exactly as before.
        if use_case == "file" and timeout:
            return max(self.SOCKET_TIMEOUT, int(timeout))
        # `ml` waits alongside `rm`: a `run_model` legitimately runs for seconds, and the receiver's
        # own wait on its agent is bounded by the SAME budget — so a sender that gave up at 10s
        # would report unreachable for an operation that was still running correctly.
        if use_case not in ("rm", "ml"):
            return self.SOCKET_TIMEOUT
        limits = ml_limits if use_case == "ml" else rm_limits
        return min(int(timeout or limits.DEFAULT_TIMEOUT),
                   limits.MAX_TIMEOUT) + self.RM_TIMEOUT_MARGIN

    def _exchange(self, use_case, receiver_name, tech, payload=None, data=b"", timeout=None):
        if tech in ("coap-enc", "coap", "coap-pqc"):
            return self._coap_exchange(use_case, receiver_name, payload or {}, data,
                                       tech=tech, timeout=timeout)
        if tech in ("coap-dtls-pqc", "coap-dtls-pqc-mutual", "coap-dtls", "coap-dtls-mutual"):
            return self._coap_dtls_exchange(use_case, receiver_name, payload or {}, data,
                                            tech=tech, timeout=timeout)
        return self._http_exchange(use_case, receiver_name, tech, payload or {}, data,
                                   timeout=timeout)

    def _signed_payload(self, use_case, payload, data):
        """What the envelope techs actually sign: the use case's payload, with a FILE's bytes folded
        in base64 so the signature covers the content. Deliberately one shape for all three use
        cases — the receiver verifies the same way regardless of what it is about to do with it."""
        if use_case == "file":
            return {**payload, "data_b64": base64.b64encode(data).decode()}
        return payload

    def _envelope(self, tech, signed_payload, xid):
        """The signed identity envelope the certless techs authenticate with.

        `https` signs with this node's CLASSICAL key and ships its classical cert; `pqc` signs with
        the ML-DSA-65 key and ships the PQC cert. Same shape, same freshness window, same "the cert
        must chain and its CN must be the claimed sender" rule on the far side — only the algorithm
        and the CA differ, which is exactly what makes them separate techs and not separate
        protocols."""
        payload_bytes = json.dumps(signed_payload, sort_keys=True).encode()
        ts = _unique_ts(payload_bytes)
        signable = identity.signable_with_ts(payload_bytes, ts)
        if tech in PQC_TECHS:
            cert_path, key_path, _ca = self._pqc()
            sig = identity.sign_payload_pqc(key_path, signable)
        else:
            cert_path, key_path = self._cert_path, self._key_path
            sig = identity.sign_payload(key_path, signable)
        return {"sender": self.name,
                "cert": base64.b64encode(Path(cert_path).read_bytes()).decode(),
                "sig": base64.b64encode(sig).decode(),
                "payload": signed_payload, "ts": ts, "xid": xid}

    def _coap_signature(self, tech, signed_over, ts):
        """-> (cert_pem_b64, signature_b64) for a CoAP envelope: ML-DSA-65 with this node's PQC leaf on the
        PQC techs (coap-pqc, coap-dtls-pqc*), RSA with the fleet leaf on the others."""
        if tech in PQC_TECHS:
            cert_path, key_path, _ca = self._pqc()
            sig = identity.sign_payload_pqc(key_path, identity.signable_with_ts(signed_over, ts))
        else:
            cert_path = self._cert_path
            sig = identity.sign_payload(self._key_path, identity.signable_with_ts(signed_over, ts))
        return base64.b64encode(Path(cert_path).read_bytes()).decode(), base64.b64encode(sig).decode()

    def _require_pqc_reply(self, tech, receiver_name, peer_verified):
        """A PQC CoAP tech's reply must carry a valid ML-DSA-65 signature of the receiver (2026-10-23): with no
        (coap-pqc) or only a transport-level check of the relay (coap-dtls-pqc*), it is the receiver's own proof."""
        if tech in PQC_TECHS and peer_verified is not True:
            raise errors.IdentityError(
                f"{receiver_name}'s {tech} reply is not signed with its ML-DSA-65 key "
                f"(peer_verified={peer_verified!r}) -- refused")

    def _http_exchange(self, use_case, receiver_name, tech, payload, data, timeout=None):
        """mtls | https | pqc | http — all four are HTTP-family; three run over TLS 1.3 and differ
        in WHO the handshake authenticates, `http` runs over NO transport security at all:

          mtls   mutual handshake on :P2P_PORT — the peer cert IS the identity (the primary gate)
          pqc    the same mutual handshake, PLUS an ML-DSA-65-signed envelope the receiver checks
                 against the classical CN, so forging either half alone is not enough
          https  server-authenticated only, on :P2P_HTTPS_PORT — the sender presents no client
                 cert, so its identity is the RSA-signed envelope instead. Strictly weaker than
                 mtls (see the module docstring) and it is a SEPARATE port for exactly that reason:
                 opening the mTLS port to certless clients would weaken every other tech with it.
          http   plain TCP on :P2P_HTTP_PORT, no TLS session of any kind — identity is the SAME
                 signed envelope https uses, but the sender also cannot verify who answered (see
                 `_connect`). The plaintext tier's HTTP-family member, same idea as `coap` for UDP.
        """
        method, path = self.ROUTES[use_case]
        t0, xid, tls = time.time(), self._new_exchange_id(), None
        # Written BEFORE anything is attempted (monitor.md §12.7, D26) -- a send that never
        # completes (this box crashes, the connect hangs) is still visible on THIS box afterward.
        sender_log.record("attempt", xid, receiver_name, use_case, tech)
        timing = _Timing(tech)
        try:
            conn, resolved, tls = self._connect(receiver_name, tech,
                                                self._socket_timeout(use_case, timeout),
                                                timing=timing)
            headers = {"X-P2P-Sender": self.name, "X-P2P-Exchange": xid,
                       "X-P2P-Use-Case": use_case, "X-P2P-Tech": tech}
            if tech in ("mtls", "pqc"):      # the TLS client certificate IS the identity
                if use_case == "file":
                    body = data
                    headers["X-P2P-Dest-Path"] = payload.get("dest_filename", "delivered.bin")
                    headers["Content-Type"] = "application/octet-stream"
                    if payload.get("put_file"):
                        headers["X-P2P-Put-File"] = json.dumps(payload["put_file"])
                elif use_case in ("message", "rm", "ml", "fetch"):
                    body = json.dumps(payload).encode()
                    headers["Content-Type"] = "application/json"
                else:
                    body = None
                    if use_case == "status" and payload.get("details"):
                        headers["X-P2P-Details"] = "1"
            else:
                body = json.dumps(
                    self._envelope(tech, self._signed_payload(use_case, payload, data), xid)).encode()
                headers["Content-Type"] = "application/json"
                headers["X-P2P-SIG"] = "1"
            timing.lap("prepare_ms")
            conn.request(method, path, body=body, headers=headers)
            sock = getattr(conn, "sock", None)  # http/https/mtls/pqc: our own TCP socket (None for subprocess techs)
            resp = conn.getresponse()
            raw_resp = resp.read() or b"{}"
            timing.lap("exchange_ms")
            if sock is not None:
                _note_tcp_end(timing, sock)     # RTT + retransmissions of this connection
            neg = getattr(conn, "helper_negotiated", None) or getattr(conn, "negotiated", None)
            if neg:         # quic-*, pqc*: what the handshake OBSERVABLY negotiated replaces the assumed facts
                tls = {**(tls or {}), **neg}
            ht = getattr(conn, "helper_timing", None)
            if ht:          # quic-*: the helper timed its own handshake and request
                timing.note(handshake_ms=ht.get("handshake_ms"), wire_ms=ht.get("request_ms"))
            timing.note_net(**(getattr(conn, "helper_net", None) or {}))
            rbody = json.loads(raw_resp)
            conn.close()
            if resp.status in (401, 403):
                raise errors.AuthorizationDenied(rbody.get("reason", "denied"))
            # `bytes` is the exchange's CONTENT length, not the framing length: for a file that is
            # the file, whatever wrapping carried it, so the attempted-vs-delivered join in
            # p2p_comm_log.annotate_bytes compares like with like across techs.
            nbytes = len(data) if use_case == "file" else len(body or b"")
            tblock = timing.block(request_bytes=len(body or b""), response_bytes=len(raw_resp),
                                  receiver=rbody.pop("receiver_timing", None))
            self._report(use_case, tech, receiver_name, t0, ok=200 <= resp.status < 300,
                        status_code=resp.status, nbytes=nbytes, exchange_id=xid, tls=tls,
                        payload=self._reported_payload(use_case, payload, rbody), timing=tblock,
                        negotiated=neg)
            return {"status": resp.status, "via_chain": resolved.get("via_chain"), **rbody,
                    "timing": tblock, **({"negotiated": neg} if neg else {})}
        except Exception as e:
            self._report(use_case, tech, receiver_name, t0, ok=False,
                        nbytes=len(data) if use_case == "file" else 0, exchange_id=xid,
                        payload=payload, reason=str(e), tls=tls)
            raise

    @staticmethod
    def _reported_payload(use_case, payload, rbody):
        """What goes in the mirror's `payload` — never the file's bytes (the log is a dashboard,
        not a content store): a file reports its destination name and the receiver's sha256, which
        is what makes the row checkable."""
        if use_case == "file":
            return {"dest_filename": payload.get("dest_filename"), "sha256": rbody.get("sha256"),
                    **({"job_id": rbody.get("job_id"), "status": rbody.get("status")}
                       if payload.get("put_file") else {})}
        if use_case == "status":
            return {k: v for k, v in rbody.items() if k != "details"}   # log row stays small
        if use_case == "rm":
            # The command and how it ended — never its output. Same rule the receiver applies to
            # its own half of the record (receiver-role/server.py::_run says why); keeping the two
            # halves symmetric is what lets the mirror's join compare them.
            return {"cmd": payload.get("cmd"), "rc": rbody.get("rc"),
                    "refused": rbody.get("refused"), "timed_out": rbody.get("timed_out")}
        if use_case == "fetch":
            # Which file and its digest — never the bytes (same rule as `file`, other direction).
            return {"path": payload.get("path"), "sha256": rbody.get("sha256"),
                    "bytes": rbody.get("bytes"), "refused": rbody.get("refused")}
        if use_case == "ml":
            # Which ML operation and how it ended — never the operation's own result, which can be
            # a whole manifest or a run's inference output. Symmetric with the receiver's half.
            return {"method": payload.get("method"), "ok": rbody.get("ok"),
                    "refused": rbody.get("refused"), "timed_out": rbody.get("timed_out")}
        return payload

    def _verify_coap_response(self, receiver_name, ip, body, pqc=False):
        """§3.8.2 phase 2, OBSERVE MODE ONLY (2026-08-21): mirrors the receiver's OWN inbound
        checks onto the response we just got back -- chain to the CA, CN == receiver_name, SAN
        carries `ip`, freshness, signature -- against `resp_cert`/`resp_sig`/`resp_ts` (phase 1).
        -> True (verified) / False (present but failed a check) / None (`resp_sig` absent -- an
        old receiver, or phase 1 not yet deployed there). NEVER RAISES and never gates the
        exchange -- phase 3 (`self.coap_require_signed_response`, built 2026-08-21 once C57/S28
        showed fleet-wide uniformity) is the only phase allowed to fail a call on this, in
        `_coap_exchange` right after this method returns; this method itself still only records,
        unconditionally, regardless of which phase is active."""
        if not isinstance(body, dict) or not body.get("resp_sig"):
            return None
        try:
            resp_cert_pem = base64.b64decode(body["resp_cert"]).decode()
            resp_sig = base64.b64decode(body["resp_sig"])
            resp_ts = body["resp_ts"]
            resp_xid = body.get("xid", "")
            stripped = {k: v for k, v in body.items()
                       if k not in ("resp_cert", "resp_sig", "resp_ts", "xid")}
            signed_over = f"{resp_xid}|".encode() + json.dumps(stripped, sort_keys=True).encode()
            fresh_ok, _ = identity.check_freshness(resp_ts)
            signable = identity.signable_with_ts(signed_over, resp_ts)
            if pqc:     # the PQC techs: the reply must be ML-DSA-65-signed by a leaf of the PQC CA
                chain_ok = identity.verify_chain_pqc(self._pqc()[2], resp_cert_pem)
                cn_ok = identity.leaf_cn_pqc(resp_cert_pem) == receiver_name
                san_ips = identity.leaf_san_ips(resp_cert_pem, openssl_bin=identity.PQC_OPENSSL,
                                                env=identity.pqc_env())
                sig_ok = identity.verify_payload_signature_pqc(resp_cert_pem, signable, resp_sig)
            else:
                chain_ok = identity.verify_chain(self._ca_path, resp_cert_pem)
                cn_ok = identity.leaf_cn(resp_cert_pem) == receiver_name
                san_ips = identity.leaf_san_ips(resp_cert_pem)
                sig_ok = identity.verify_payload_signature(resp_cert_pem, signable, resp_sig)
            san_ok = bool(san_ips) and ip in san_ips
            return bool(fresh_ok and chain_ok and cn_ok and san_ok and sig_ok)
        except Exception:                                      # noqa: BLE001 -- observe mode: a
            return False                                        # verification bug is a fact to
                                                                  # record, never a raise

    # CoAP's wait budget (2026-09-26, found live on the cross-room path to T-pash/T-theo, ~100 ms
    # RTT): it was a flat 10 s for every exchange. Block-wise transfer is stop-and-wait — one
    # 1 KiB block per round trip — so a 60 KB put-file needs ~80 RTTs (~8 s at 100 ms) before the
    # receiver even starts, and it timed out as a misleading PeerUnreachable while the same file
    # took 1.2 s on the 8 ms local path. The flat 10 s also cut `rm`/`ml` over CoAP at 10 s even
    # though their HTTP forms wait for the command's own budget. Now: the same per-use-case budget
    # the HTTP techs use (_socket_timeout), plus COAP_PER_BLOCK_S for every 1 KiB block on the wire.
    COAP_BLOCK = 1024
    # 2026-10-01 (found live: a 20 KB cc delivery = 40 KB envelope = ~40 blocks -> 10 + 0.5*40 = 30 s, and a
    # slow link / QEMU receiver needs more): env P2P_COAP_PER_BLOCK_S overrides the 0.5 s per-block allowance.
    # Unset / empty / not a positive number -> 0.5, i.e. the budget is unchanged unless an operator opts in.
    COAP_PER_BLOCK_S = _env_pos_float("P2P_COAP_PER_BLOCK_S", 0.5)

    def _coap_budget(self, use_case, timeout, wire_len):
        blocks = -(-wire_len // self.COAP_BLOCK)
        return self._socket_timeout(use_case, timeout) + (
            self.COAP_PER_BLOCK_S * blocks if blocks > 1 else 0)

    def _coap_exchange(self, use_case, receiver_name, payload, data, tech="coap-enc", timeout=None):
        """coap-enc | coap-pqc | coap — CoAP/UDP, three envelope shapes over one transport.

        All three use cases ride it (2026-07-28): the resource path carries the use case, the
        envelope is identical (modulo which key `body` carries), and the payload is whatever
        `_signed_payload` built. aiocoap does block-wise transfer for a payload bigger than one
        datagram, so a file is not a special case here either — though the HTTP techs remain the
        sane choice for a large one.

        `coap-pqc` (2026-09-27) swaps `coap-enc`'s RSA-OAEP key-wrap for ML-KEM-768 encapsulation
        (see coap_crypto.encrypt_for_kem / PQC-bench/ca/pqc_kem.py) -- everything else about the
        envelope (AES-256-GCM payload, classical signature over the ciphertext) is identical, so
        the receiver's identity/policy checks don't change at all, only which decrypt function
        `render_post` calls. The peer's KEM public key is looked up from a LOCAL, offline-
        provisioned cache (`coap_crypto.peer_kem_pub_path`), not fetched live from the Server the
        way a classical cert is -- there is no live issuance endpoint for it, same reasoning
        identity.py's PQC section already gives for the ML-DSA-65 material `pqc`/`pqkex` use."""
        import asyncio
        import aiocoap
        from common import coap_crypto

        t0, xid = time.time(), self._new_exchange_id()
        tech_name = tech
        # Written BEFORE anything is attempted (monitor.md §12.7, D26) -- see the http path's own
        # comment above for why.
        sender_log.record("attempt", xid, receiver_name, use_case, tech_name)
        timing = _Timing(tech)                  # no handshake on these three: handshake_ms stays None
        try:
            resolved = identity.resolve(self.server_api, self.secret, receiver_name, frm=self.name)
            timing.lap("resolve_ms")
            if resolved.get("stale"):
                print(f"[p2p-client:{self.name}] resolve('{receiver_name}') served from a "
                      f"{resolved['stale_age_s']}s-old cache -- Server unreachable", file=sys.stderr, flush=True)
            ip = resolved.get("ip")
            if not ip:
                raise errors.ResolveError(f"resolve('{receiver_name}') had no /32")
            # task10 B2: honour a receiver-specific CoAP port from /resolve (a co-located
            # bare-metal container listens on a non-default port so it never collides with its
            # host's own p2p-coap-receiver). Falls back to this sender's P2P_COAP_PORT / 5683.
            port = resolved.get("coap_port") or self.coap_port

            plain = self._signed_payload(use_case, payload, data)
            payload_bytes = json.dumps(plain, sort_keys=True).encode()
            ts = _unique_ts(payload_bytes)
            if tech == "coap-enc":
                peer_cert_pem = identity.fetch_peer_cert(self.server_api, self.secret, receiver_name)
                timing.lap("peer_cert_ms")
                # §3.8.2 phase 0 (2026-08-21): assert the peer cert we are about to encrypt FOR is
                # actually bound to the /32 we are about to dial -- refuses BEFORE the payload is
                # encrypted/transmitted, the one half of peer authentication that prevents rather
                # than detects (phase 1+ signs the RESPONSE, which only catches a mismatch after
                # the request already went out). Same SAN-IP binding check the mtls/https path
                # already makes post-handshake (client.py's own note above `_connect`), applied
                # here where there is no handshake to lean on -- only a PEM.
                san_ips = identity.leaf_san_ips(peer_cert_pem)
                if san_ips and ip not in san_ips:
                    raise errors.IdentityError(
                        f"{receiver_name}'s cert is bound to {sorted(san_ips)}, but we resolved "
                        f"to {ip} -- refusing to encrypt for this cert")
                encrypted = coap_crypto.encrypt_for(peer_cert_pem, payload_bytes)
                # sig covers the CIPHERTEXT (what is actually on the wire) -- see the receiver's note
                signed_over = encrypted["ciphertext"].encode()
                body = {"encrypted": encrypted}
            elif tech == "coap-pqc":
                # No SAN-IP binding check here (unlike coap-enc above): a raw KEM public key file
                # carries no SAN of its own to check against -- the offline provisioning step that
                # put it at this path is the trust anchor, the same way a manually-provisioned
                # `pqc`/`pqkex` identity is (see PQC-bench/ca/pqc_kem.py's own docstring).
                peer_pub_path = coap_crypto.peer_kem_pub_path(receiver_name)
                if not Path(peer_pub_path).exists():
                    raise errors.IdentityError(
                        f"no PQC KEM public key cached for {receiver_name} at {peer_pub_path} -- "
                        f"mint+provision one with PQC-bench/ca/pqc_kem.py issue_kem() first")
                encrypted_pqc = coap_crypto.encrypt_for_kem(peer_pub_path, payload_bytes)
                signed_over = encrypted_pqc["ciphertext"].encode()
                body = {"encrypted_pqc": encrypted_pqc}
            else:
                # `coap`: no peer cert fetch and no encryption at all. The signature covers the
                # cleartext payload bytes instead -- the same thing the `https` tech signs, so the
                # receiver's verification is the identical four checks in the identical order.
                signed_over = payload_bytes
                body = {"payload": plain}
            cert_b64, sig_b64 = self._coap_signature(tech, signed_over, ts)
            envelope = {"sender": self.name, "cert": cert_b64, "sig": sig_b64, **body, "ts": ts,
                       # Correlation only, deliberately OUTSIDE the signed ciphertext: it names no
                       # identity and grants nothing, so covering it would buy nothing, and a
                       # receiver that echoes a tampered id just fails to join in the mirror.
                       "xid": xid, "use_case": use_case}
            wire_len = len(json.dumps(envelope).encode())
            timing.lap("prepare_ms")

            retransmits = [0]

            async def _send():
                ctx = await aiocoap.Context.create_client_context()
                # Count the CON retransmissions THIS context's message layer makes (a block lost or late on
                # the stop-and-wait block-wise path): each one is a datagram re-sent after an ACK timeout.
                for tman in getattr(ctx, "request_interfaces", ()):
                    mman = getattr(tman, "token_interface", None)
                    orig = getattr(mman, "_retransmit", None)
                    if orig is not None:
                        def _counting(message, timeout_, counter, _orig=orig):
                            if counter < message.transport_tuning.MAX_RETRANSMIT:
                                retransmits[0] += 1
                            return _orig(message, timeout_, counter)
                        mman._retransmit = _counting
                try:
                    uri = f"coap://{ip}:{port}/{COAP_RESOURCE[use_case]}"
                    wire = json.dumps(envelope).encode()
                    req = aiocoap.Message(code=aiocoap.POST, uri=uri, payload=wire)
                    budget = self._coap_budget(use_case, timeout, len(wire))
                    try:
                        resp = await asyncio.wait_for(ctx.request(req).response, timeout=budget)
                    except (OSError, asyncio.TimeoutError) as e:
                        raise errors.PeerUnreachable(
                            f"could not reach {receiver_name} ({ip}:{port}) within {budget:.0f}s "
                            f"({len(wire)} bytes on the wire): {e}")
                    return resp
                finally:
                    await ctx.shutdown()

            resp = asyncio.run(_send())
            timing.lap("exchange_ms")
            timing.note_net(retransmits=retransmits[0])
            body = json.loads(resp.payload) if resp.payload else {}
            # §3.8.2 phase 2, OBSERVE MODE: verify if the receiver signed (phase 1), record either
            # way, never gate on it here -- see _verify_coap_response()'s own docstring for why.
            peer_verified = self._verify_coap_response(receiver_name, ip, body, pqc=tech in PQC_TECHS)
            self._require_pqc_reply(tech, receiver_name, peer_verified)
            # §3.8.2 phase 3 (2026-08-21): the enforce flip. Checked BEFORE the FORBIDDEN branch
            # below -- phase 1 signs all seven of the receiver's exit points including its own
            # refusals, so an enforcing sender must catch an unsigned/failed-verification FORBIDDEN
            # too, not just an unsigned 200. `peer_verified is True` is the only passing value --
            # `False` (present but failed a check) and `None` (absent -- an old receiver, or one
            # this box has not yet resolved to a cert for) both fail closed under enforce, exactly
            # as observe mode already distinguished them for recording.
            if self.coap_require_signed_response and peer_verified is not True:
                raise errors.IdentityError(
                    f"{receiver_name}'s CoAP response was not verifiably signed by its own key "
                    f"(peer_verified={peer_verified!r}) -- refusing under enforce mode "
                    f"(P2P_COAP_REQUIRE_SIGNED_RESPONSE=1)")
            # 4.01 (the receiver could not establish WHO sent this: bad signature, stale timestamp, cert that
            # does not chain) is a denial exactly like 4.03 (policy) -- the HTTP path has always raised for
            # both 401 and 403. Before 2026-10-23 only 4.03 raised, so a CoAP delivery the receiver refused
            # with 4.01 came back as an ordinary result and was logged ok=True.
            if resp.code in (aiocoap.FORBIDDEN, aiocoap.UNAUTHORIZED):
                raise errors.AuthorizationDenied(body.get("reason", "denied"))
            nbytes = len(data) if use_case == "file" else len(payload_bytes)
            tblock = timing.block(request_bytes=wire_len, response_bytes=len(resp.payload or b""),
                                  receiver=body.pop("receiver_timing", None))
            self._report(use_case, tech_name, receiver_name, t0, ok=bool(resp.code.is_successful()),
                        status_code=coap_status_code(resp.code), nbytes=nbytes, exchange_id=xid,
                        payload=self._reported_payload(use_case, payload, body),
                        peer_verified=peer_verified, timing=tblock)
            return {"status": int(resp.code), "via_chain": resolved.get("via_chain"), **body,
                    "timing": tblock, "peer_verified": peer_verified}
        except Exception as e:
            self._report(use_case, tech_name, receiver_name, t0, ok=False,
                        nbytes=len(data) if use_case == "file" else 0, exchange_id=xid,
                        payload=payload, reason=str(e))
            raise

    def _coap_dtls_exchange(self, use_case, receiver_name, payload, data, tech="coap-dtls-pqc",
                            timeout=None):
        """coap-dtls-pqc (2026-09-27) -- real hybrid PQ-KEX DTLS 1.3, `coap`'s exact cleartext
        envelope shape (see the module docstring's coap-dtls-pqc entry for why: confidentiality
        now comes from the DTLS transport itself). Goes to `coap_dtls_pqc_relay.py`'s dedicated
        port, never coap_server.py's plain port directly -- the relay is what speaks DTLS at all.

        Built on PQC-bench/wolfssl-py-patch's `aiocoap_wolfdtls` (a real aiocoap
        interfaces.MessageInterface, CLIENT side only), imported LAZILY here and nowhere else in
        this module -- most nodes won't have the wolfSSL toolchain installed, and this tech is
        opt-in, the same reasoning `_pqc()` already gives for its own lazy PQC-material loading."""
        try:
            if COAP_DTLS_PQC_MODULE_PATH not in sys.path:
                sys.path.insert(0, COAP_DTLS_PQC_MODULE_PATH)
            import aiocoap
            from aiocoap_wolfdtls import MessageInterfaceWolfDTLS
        except ImportError as e:
            raise errors.IdentityError(
                f"coap-dtls-pqc requested but the wolfSSL toolchain isn't installed on {self.name} "
                f"(expected the patched 'wolfssl' package importable, with LD_LIBRARY_PATH pointing "
                f"at {COAP_DTLS_PQC_WOLFSSL_LIB}): {e}")
        import asyncio

        t0, xid = time.time(), self._new_exchange_id()
        tech_name = tech
        sender_log.record("attempt", xid, receiver_name, use_case, tech_name)
        timing = _Timing(tech)
        try:
            resolved = identity.resolve(self.server_api, self.secret, receiver_name, frm=self.name)
            timing.lap("resolve_ms")
            if resolved.get("stale"):
                print(f"[p2p-client:{self.name}] resolve('{receiver_name}') served from a "
                      f"{resolved['stale_age_s']}s-old cache -- Server unreachable", file=sys.stderr, flush=True)
            ip = resolved.get("ip")
            if not ip:
                raise errors.ResolveError(f"resolve('{receiver_name}') had no /32")
            mutual = tech in ("coap-dtls-pqc-mutual", "coap-dtls-mutual")
            classical_kex = tech in ("coap-dtls", "coap-dtls-mutual")
            port = {"coap-dtls-pqc": self.coap_dtls_pqc_port,
                    "coap-dtls-pqc-mutual": self.coap_dtls_pqc_mutual_port,
                    "coap-dtls": self.coap_dtls_port,
                    "coap-dtls-mutual": self.coap_dtls_mutual_port}[tech]

            # `coap`'s exact envelope shape -- no encryption, no peer-cert fetch: see the module
            # docstring's coap-dtls-pqc entry for why (the DTLS transport already carries
            # confidentiality; a second, application-layer encryption would be redundant).
            plain = self._signed_payload(use_case, payload, data)
            payload_bytes = json.dumps(plain, sort_keys=True).encode()
            ts = _unique_ts(payload_bytes)
            cert_b64, sig_b64 = self._coap_signature(tech, payload_bytes, ts)
            envelope = {"sender": self.name, "cert": cert_b64, "sig": sig_b64, "payload": plain, "ts": ts,
                       "xid": xid, "use_case": use_case}
            # coap-dtls-pqc*: ML-DSA-65 certificates on both ends of the DTLS handshake (the relay's server
            # cert checked against the PQC CA; on -mutual our own PQC leaf) and the pure ML-KEM-768 group.
            pqc = tech in PQC_TECHS
            if pqc:
                dtls_cert, dtls_key, dtls_ca = self._pqc()
            else:
                dtls_cert, dtls_key, dtls_ca = self._cert_path, self._key_path, self._ca_path
            wire_len = len(json.dumps(envelope).encode())
            timing.lap("prepare_ms")

            async def _send():
                ctx = await aiocoap.Context.create_client_context(transports=["udp6"])
                # `coap-dtls-pqc-mutual` (2026-09-28, Stack 4): this node's OWN classical leaf --
                # the SAME identity `https`'s envelope already uses, matching the relay's OWN
                # cert being classical too (see the module docstring's coap-dtls-pqc entry). The
                # relay's `--mutual` mode refuses the handshake outright without it.
                cert_path = dtls_cert if mutual else None
                key_path = dtls_key if mutual else None
                await ctx._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: MessageInterfaceWolfDTLS.create_client_transport_endpoint(
                        mman, log=ctx.log, loop=ctx.loop, ca_path=dtls_ca,
                        cert_path=cert_path, key_path=key_path,
                        key_share="x25519" if classical_kex else "mlkem768",
                        # 2026-10-23 (v2): who must answer, checked by the worker BEFORE it writes the request
                        expect_cn=receiver_name, expect_ip=ip))
                try:
                    uri = f"coaps://{ip}:{port}/{COAP_RESOURCE[use_case]}"
                    wire = json.dumps(envelope).encode()
                    req = aiocoap.Message(code=aiocoap.POST, uri=uri, payload=wire,
                                          transport_tuning=aiocoap.Unreliable)
                    budget = self._coap_budget(use_case, timeout, len(wire))
                    # handle_blockwise=False -- found live, 2026-09-27: the envelope ALWAYS carries
                    # this node's own base64-encoded certificate (envelope["cert"], typically
                    # ~1-2 KB alone), which reliably exceeds aiocoap's default blockwise threshold
                    # (RFC 7959 SZX=6, 1024 bytes) even for the smallest use case (`status`, empty
                    # payload) -- so blockwise activates on EVERY exchange, not as an edge case.
                    # `aiocoap_wolfdtls`'s transport is a single write()/read() with no Block1/
                    # Block2 continuation logic (see its own docstring), so a chunked request just
                    # gets "2.31 Continue" back and stops, and aiocoap's client-side retry then
                    # resends a DIFFERENT block against an already-closed DTLS session --
                    # deterministic failure, not a timing race. Unlike a real UDP/CoAP transport,
                    # this one is NOT limited to ~1 KB datagrams (DTLS records comfortably carry
                    # the whole envelope, and the relay/coap_server.py round trip handles it as one
                    # piece) -- so there is no reason to chunk it at all; disabling blockwise
                    # client-side sends the complete message in one shot, which coap_server.py (only
                    # ever chunking in RESPONSE to a client-initiated Block1) accepts as a normal,
                    # if larger-than-usual, complete request.
                    try:
                        resp = await asyncio.wait_for(
                            ctx.request(req, handle_blockwise=False).response, timeout=budget)
                    except (OSError, asyncio.TimeoutError, aiocoap.error.NetworkError) as e:
                        # NetworkError is what aiocoap raises when the DTLS worker reports a failure (handshake
                        # refused, group not accepted, peer closed): it is a failed exchange, not a crash.
                        root = getattr(e, "__cause__", None) or e
                        if type(root).__name__ == "PeerIdentityError":
                            # the server certificate names another node / another address: nothing was sent
                            raise errors.IdentityError(f"{receiver_name}'s {tech} identity did not verify: {root}")
                        cause = f"{e} ({e.__cause__})" if getattr(e, "__cause__", None) else str(e)
                        within = f" within {budget:.0f}s" if isinstance(e, asyncio.TimeoutError) else ""
                        raise errors.PeerUnreachable(
                            f"could not reach {receiver_name} ({ip}:{port}) over {tech}{within} "
                            f"({len(wire)} bytes on the wire): {cause or type(e).__name__}")
                    # The relay's OWN server certificate, verified for real: the SAME
                    # CN==receiver_name + SAN-IP check `_connect()` runs for mtls/https/pqkex,
                    # applied to the DTLS peer cert instead of a TLS socket's (see the module
                    # docstring's coap-dtls-pqc entry). aiocoap_wolfdtls already did the CHAIN
                    # verification (CERT_REQUIRED against ca_path) during the handshake itself --
                    # a bad chain never gets this far, it fails at the handshake with a clear
                    # PeerUnreachable-style error above. This is the CN/SAN half only.
                    peer_pem = resp.remote.peer_cert_pem if resp.remote else None
                    if not peer_pem:
                        raise errors.IdentityError(
                            f"{receiver_name}'s coap-dtls-pqc relay presented no verifiable "
                            f"certificate")
                    peer_cn = identity.leaf_cn_pqc(peer_pem) if pqc else identity.leaf_cn(peer_pem)
                    if peer_cn != receiver_name:
                        raise errors.IdentityError(
                            f"coap-dtls-pqc relay at {ip}:{port} presented cert for {peer_cn!r}, "
                            f"expected {receiver_name!r}")
                    san_ips = identity.leaf_san_ips(peer_pem)
                    if san_ips and ip not in san_ips:
                        raise errors.IdentityError(
                            f"{receiver_name}'s coap-dtls-pqc relay cert is bound to "
                            f"{sorted(san_ips)}, but we connected to {ip}")
                    return resp
                finally:
                    await ctx.shutdown()

            resp = asyncio.run(_send())
            timing.lap("exchange_ms")
            wt = getattr(resp.remote, "timing", None)
            neg = None
            if wt:      # the worker process measured its own DTLS handshake and request->reply
                timing.note(handshake_ms=wt.get("handshake_ms"), wire_ms=wt.get("request_ms"))
                timing.note_net(handshake_cpu_ms=wt.get("handshake_cpu_ms"))
                # ...and observed what the handshake negotiated (the worker already refused a wrong group
                # before sending any data); the peer cert facts are read from the cert it handed back.
                # one name per group across the stacks: wolfSSL says ML_KEM_768 where OpenSSL/aioquic say MLKEM768
                neg = {"tls_version": wt.get("version") or "DTLSv1.3",
                       "group": {"ML_KEM_768": PQC_GROUP}.get(wt.get("group"), wt.get("group")),
                       **identity.cert_facts_from_pem(getattr(resp.remote, "peer_cert_pem", None) or "")}
                neg = {k: v for k, v in neg.items() if v is not None}
            body = json.loads(resp.payload) if resp.payload else {}
            # §3.8.2 phase 2/3: the SAME receiver-signed-response verification `coap`/`coap-enc`/
            # `coap-pqc` use -- coap_dtls_pqc_relay.py forwards to the identical coap_server.py,
            # which signs its response exactly the same way regardless of which tech carried the
            # request, so this check is unchanged. On coap-dtls-pqc* the reply is ML-DSA-65-signed (2026-10-23).
            peer_verified = self._verify_coap_response(receiver_name, ip, body, pqc=pqc)
            self._require_pqc_reply(tech, receiver_name, peer_verified)
            if self.coap_require_signed_response and peer_verified is not True:
                raise errors.IdentityError(
                    f"{receiver_name}'s CoAP response was not verifiably signed by its own key "
                    f"(peer_verified={peer_verified!r}) -- refusing under enforce mode "
                    f"(P2P_COAP_REQUIRE_SIGNED_RESPONSE=1)")
            # 4.01 (the receiver could not establish WHO sent this: bad signature, stale timestamp, cert that
            # does not chain) is a denial exactly like 4.03 (policy) -- the HTTP path has always raised for
            # both 401 and 403. Before 2026-10-23 only 4.03 raised, so a CoAP delivery the receiver refused
            # with 4.01 came back as an ordinary result and was logged ok=True.
            if resp.code in (aiocoap.FORBIDDEN, aiocoap.UNAUTHORIZED):
                raise errors.AuthorizationDenied(body.get("reason", "denied"))
            nbytes = len(data) if use_case == "file" else len(payload_bytes)
            tblock = timing.block(request_bytes=wire_len, response_bytes=len(resp.payload or b""),
                                  receiver=body.pop("receiver_timing", None))
            self._report(use_case, tech_name, receiver_name, t0, ok=bool(resp.code.is_successful()),
                        status_code=coap_status_code(resp.code), nbytes=nbytes, exchange_id=xid,
                        payload=self._reported_payload(use_case, payload, body),
                        peer_verified=peer_verified, timing=tblock, tls=neg, negotiated=neg)
            return {"status": int(resp.code), "via_chain": resolved.get("via_chain"), **body,
                    "timing": tblock, "peer_verified": peer_verified, **({"negotiated": neg} if neg else {})}
        except Exception as e:
            self._report(use_case, tech_name, receiver_name, t0, ok=False,
                        nbytes=len(data) if use_case == "file" else 0, exchange_id=xid,
                        payload=payload, reason=str(e))
            raise
