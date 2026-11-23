"""aiocoap_wolfdtls — a real hybrid PQ-KEX DTLS 1.3 CLIENT transport for aiocoap (2026-09-27).

Closes the LAST gap in this testbed's PQC work: p2p's `coap`/`coap-enc`/`coap-pqc` all use
aiocoap, whose only DTLS support (`aiocoap.transports.tinydtls`) is DTLS 1.2 via tinydtls, with no
PQ group of any kind. This module is aiocoap's own `interfaces.MessageInterface` contract,
implemented on top of the patched `wolfssl` binding (`key-share-group.patch`) instead of tinydtls
-- the same real X25519MLKEM768 handshake `dtls_pqkex_test.py` already proved works from Python.

Scope, deliberately matching tinydtls's own precedent (its module docstring says outright: "This
currently only implements the client side"): CLIENT ONLY. A receiver-side aiocoap transport is a
separate, larger piece of work (a real asyncio DTLS SERVER accepting many peers, not one blocking
socket per outbound request) -- not attempted here.

Integration model: wolfssl-py's `SSLSocket` is a BLOCKING wrapper (unlike tinydtls's
callback-driven, natively-async C library) -- `do_handshake()`/`read()`/`write()` all block on the
underlying UDP socket. Rather than hand-rolling a non-blocking retry loop against wolfSSL's C API
(WOLFSSL_ERROR_WANT_READ handling -- a much bigger, more fragile undertaking), each exchange runs
via `loop.run_in_executor()` against a `ProcessPoolExecutor` -- the standard way to bridge a
blocking library into asyncio without stalling the event loop for the handshake's duration.

THE actual root cause chased down live, 2026-09-27, across many dead ends (recorded here because
every one of the plausible-sounding alternatives turned out to be wrong, and the real one wasn't):
`_blocking_exchange`'s raw UDP socket must NEVER have `sock.settimeout()` called on it. Python's
`settimeout(n)` for any n other than `None`/`0` puts the underlying fd into `O_NONBLOCK` and
emulates the timeout with its own `select()` loop -- but that fd is handed to wolfSSL via
`wolfSSL_set_fd()`, which then drives it directly with its own C-level I/O callbacks, entirely
bypassing Python's socket wrapper. A non-blocking fd there made this build's DTLS 1.3 client path
send its ClientHello flight TWICE back to back and then fail its own `do_handshake()` locally with
a deterministic `SOCKET_ERROR_E` (-308) -- confirmed by direct comparison: every isolated repro
that used a genuinely blocking socket (no `settimeout()` call at all, matching what
`dtls_pqkex_test.py` always did) passed every time; the real end-to-end proof only started failing
once `_blocking_exchange` added a `settimeout()` call that neither of those working scripts had.
There is deliberately no timeout enforcement in `_blocking_exchange` as a result -- a hung peer
blocks the worker process indefinitely; a real receiver-side integration would need a different
mechanism (e.g. `SO_RCVTIMEO` via `setsockopt`, which keeps the fd itself blocking at the fcntl
level while still bounding `recv()`, unlike Python's `settimeout()`) rather than reintroducing this.

Also applied, alongside the fix above, as a straightforward correctness simplification rather than
an independently-proven-necessary fix: both `_blocking_exchange` (client) and the server half in
`dtls_pqkex_client_proof.py` pre-`connect()` their raw socket before `wrap_socket()`, which makes
wolfssl-py's `SSLSocket.__init__` treat the socket as already connected and (with the default
`do_handshake_on_connect=True`) drive an IMPLICIT handshake right there -- so the explicit
`do_handshake()` call that follows would otherwise be a second, redundant one on the same SSL
object. Both sides now pass `do_handshake_on_connect=False` and call `do_handshake()` exactly
once. (For the record: an EARLIER hypothesis during this same investigation was that `import
wolfssl` had to happen inside the forked worker function rather than at this module's top level,
citing a fork-safety/copy-on-write hazard for the underlying C library. That was never actually
confirmed -- a direct isolated test with `import wolfssl` at module level, forked via plain
`multiprocessing.Process` on both the client and server side, passed reliably. The local import
inside `_blocking_exchange` is kept anyway, since it's harmless and there's no reason to revert a
working, already-isolated piece of code, but the fork-safety CLAIM itself should not be repeated
as a confirmed finding -- the settimeout()/non-blocking-fd issue above was the real cause.)

Registered under the REAL `coaps` scheme -- aiocoap's `message.py` hardcodes a whitelist of valid
schemes (`coap_schemes`); an invented scheme like `coaps+pqkex` silently gets treated as a
forward-proxy URI instead of ever populating `.remote` (found live, 2026-09-27 -- no exception, just
a request that can never be sent). Using the real `coaps` scheme sidesteps that entirely, with no
need to patch aiocoap's source at all: construct the Context WITHOUT the `tinydtls` transport
(`transports=["udp6"]`, explicit -- bypasses `get_default_clienttransports()`, which would
otherwise auto-select tinydtls), so nothing else claims `coaps://` in that Context, then attach
this transport as the one that does. Attached via the same (semi-private but stable, used by every
built-in transport) `Context._append_tokenmanaged_messagemanaged_transport()` hook every one of
aiocoap's own transports uses in `protocol.py`'s `create_client_context()`:

    ctx = await aiocoap.Context.create_client_context(transports=["udp6"])
    from aiocoap_wolfdtls import MessageInterfaceWolfDTLS
    await ctx._append_tokenmanaged_messagemanaged_transport(
        lambda mman: MessageInterfaceWolfDTLS.create_client_transport_endpoint(
            mman, log=ctx.log, loop=ctx.loop))
    response = await ctx.request(Message(code=GET, uri="coaps://host:port/status")).response

A Context that also needs classical DTLS 1.2 (tinydtls) at the SAME time can't have both bound to
plain `coaps://` -- that's a real design question for whenever this gets wired into p2p's actual
`--tech` selection (mirroring how `pqkex`/`coap-pqc` sit alongside `mtls`/`coap-enc` as distinct
techs, not scheme collisions), not resolved here.

See `dtls_pqkex_client_proof.py` for the actual live-verified proof (a real `aiocoap.Message`
round-trip through this transport, against a raw wolfSSL DTLS server) -- PASSES as of 2026-09-27.

Peer verification (2026-09-27, added when this got wired into p2p's `coap-dtls-pqc` tech): OPT-IN
via `ca_path=` on `create_client_transport_endpoint()`/`MessageInterfaceWolfDTLS.__init__` --
`None` (the default, what `dtls_pqkex_client_proof.py` still uses) keeps `CERT_NONE`, unverified,
exactly as before. When set, the handshake requires the peer's chain to verify against that CA
(`CERT_REQUIRED` + `load_verify_locations`) and the peer's leaf certificate (DER, converted to PEM
via stdlib `ssl.DER_cert_to_PEM_cert`) is stashed on the `WolfDTLSRemote` as `.peer_cert_pem` --
readable by the caller off `response.remote` after the exchange (`Message.decode(data, remote)`
sets `.remote`, and aiocoap's dispatch hands the same object back through to the awaited
response). Deliberately does NOT do hostname/CN matching itself -- wolfSSL's own `check_hostname`
machinery is built for DNS names, and this fleet's convention is CN == node name with the IP as a
SAN entry (see p2p/sender-role/client.py's `_connect()`), which is a p2p-specific policy, not a
generic transport one. The caller (`client.py`'s `_coap_dtls_exchange`) does that check itself,
against `.peer_cert_pem`, using the SAME `identity.py` helpers (`leaf_cn`/`leaf_san_ips`) every
other tech's `_connect()` already uses -- one CN/SAN policy, in one place, regardless of tech.
"""
import asyncio
import socket
from concurrent.futures import ProcessPoolExecutor

# `wolfssl` is deliberately NOT imported here at module level -- see this module's own docstring:
# the local import inside `_blocking_exchange` is kept as a harmless precaution even though the
# fork-safety theory that originally motivated it was never actually confirmed.

from aiocoap import interfaces, error
from aiocoap.message import Message
from aiocoap.util import hostportjoin, hostportsplit

SCHEME = "coaps"
DEFAULT_PORT = 5684  # RFC 7252's "coaps" default; this scheme reuses it absent a reason not to

# Message-level chunking over raw wolfSSL DTLS writes/reads -- found live, 2026-09-27, wiring this
# into p2p's `coap-dtls-pqc` tech: a single `ssock.write()` bigger than ~1200-1400 bytes in this
# wolfSSL build fails outright with DTLS_SIZE_ERROR (-439, "trying to send too much data") -- and
# p2p's own envelope ALWAYS carries the sender's base64-encoded certificate (well over 1 KB alone),
# so this is not an edge case, it is every exchange. CoAP's OWN blockwise transfer (RFC 7959) is
# not an option either: this transport is a single write()/read() with no Block1/Block2
# continuation state, so the client side disables it (`handle_blockwise=False`, see
# p2p/sender-role/client.py's own comment) rather than half-implementing it. `write_framed`/
# `read_framed` below are the replacement: a trivial 1-byte more-flag per chunk, relying on DTLS/
# UDP's own message-boundary-preserving semantics (one write() == one read() on the far side,
# unlike a TCP byte stream, so no length field is needed, just a stop signal). CHUNK_SIZE=1024 is
# comfortably under the failure boundary found by direct probing (1200 bytes wrote fine, 1400
# didn't, in this exact build) -- not standardized anywhere, just empirically safe here. Used by
# BOTH ends of this tech: `_blocking_exchange` below, and `coap_dtls_pqc_relay.py`'s receiver side
# (imported from here rather than reimplemented, so the two ends can never drift out of sync).
CHUNK_SIZE = 1024

# DTLS MTU (2026-09-27, found live wiring this into p2p's coap-dtls-pqc tech on the REAL fleet --
# every earlier proof of this whole transport ran over loopback, which never exercises this): the
# ClientHello's hybrid X25519MLKEM768 keyshare makes wolfSSL's own handshake flight bigger than
# one small datagram, and wolfSSL's own default DTLS fragmentation threshold (WOLFSSL_MAX_MTU,
# 1400) plus its own record + UDP + IP header overhead exceeds the 1420-byte MTU of the
# WireGuard tunnel these two real boxes talk over -- the resulting oversized datagram is silently
# dropped (DF set, no PMTU signal makes it back through the tunnel), and the handshake fails with
# a LOCAL-ONLY SOCKET_ERROR_E that never reaches the peer at all (confirmed live: the receiver's
# own log showed nothing whatsoever for the failing attempts). DTLS_MTU, comfortably under 1420
# after wolfSSL's own record/UDP/IP overhead, fixes it -- set on BOTH ends (this module's own
# `_blocking_exchange`, and coap_dtls_pqc_relay.py's server-side wrap_socket, importing this
# constant rather than duplicating it, for the same never-drift-apart reason CHUNK_SIZE is
# imported instead of reimplemented). Not standardized anywhere -- just empirically safe under
# this specific tunnel's MTU; a deployment with a smaller path MTU would need this lowered too.
DTLS_MTU = 1350


# Chunk header (2026-10-01): 1-byte more-flag + 4-byte big-endian sequence number. Found live over the
# real WireGuard overlay (Protectli2 -> Protectli1): DTLS application records are plain UDP
# datagrams -- NOT retransmitted, NOT ordered -- so an unpaced burst of a ~300 KB message (~293
# chunks) lost 65 chunks and reordered others, and the old header-less framing silently joined
# what arrived -> corrupt bytes -> the envelope's signature check failed (the "300 KB fails
# signature verification" limitation). Loopback never showed it. Two layers: (1) a short pause
# between chunks (CHUNK_PACE_S, env CHUNK_PACE_S overrides; 2 ms cleared 300 KB in the live test),
# (2) sequence numbers so the reader reassembles reordered chunks and raises on a real gap
# instead of returning a corrupt message. WIRE-FORMAT CHANGE: sender and relay must be deployed
# together (an old peer's 1-byte header is not understood).
import os as _os
import struct as _struct
import time as _time

CHUNK_PACE_S = float(_os.environ.get("CHUNK_PACE_S", "0.002"))
_HDR = _struct.Struct(">BI")
# messages of at most this many chunks are sent twice (see write_framed); 0 disables
REDUNDANT_MAX_CHUNKS = int(_os.environ.get("DTLS_REDUNDANT_MAX_CHUNKS", "32"))  # 32 KiB: a PQC reply (ML-DSA sig + cert) is ~15 chunks
REDUNDANT_GAP_S = float(_os.environ.get("DTLS_REDUNDANT_GAP_S", "0.005"))


class FramingError(IOError):
    """A framed message could not be reassembled (chunk lost, or the peer cut off)."""


def _is_legacy_first_chunk(chunk: bytes) -> bool:
    """Pre-ea681b73 framing (`[more:1] + data`, no sequence number) vs the current `[more:1][seq:4]`.
    The first chunk of a current message has seq 0, so its byte 1 is 0x00; a legacy chunk's byte 1
    is the first byte of the CoAP message, version 1 => 0x40..0x7F. (2026-10-02: the telemetry
    relays on the Server still ran the legacy framing while devices got the new one, so every
    coap-dtls-pqc telemetry/ML record was dropped as "Protocol Version must be 1". Accepting both,
    and answering in the framing the peer used, lets either side be upgraded first.)"""
    return len(chunk) >= 2 and chunk[1] >> 6 == 1


def write_framed(ssock, data: bytes, chunk_size=CHUNK_SIZE, pace_s=None):
    pace = CHUNK_PACE_S if pace_s is None else pace_s
    if getattr(ssock, "_legacy_framing", False):    # the peer spoke legacy framing: answer in it
        n = max(1, (len(data) + chunk_size - 1) // chunk_size)
        for i in range(n):
            ssock.write(bytes([1 if i < n - 1 else 0]) + data[i * chunk_size:(i + 1) * chunk_size])
        return
    n = max(1, (len(data) + chunk_size - 1) // chunk_size)   # an empty payload is one empty chunk
    frames = [_HDR.pack(1 if seq < n - 1 else 0, seq) + data[seq * chunk_size:(seq + 1) * chunk_size]
              for seq in range(n)]
    for seq, frame in enumerate(frames):
        ssock.write(frame)
        if pace and seq < n - 1:
            _time.sleep(pace)
    # 2026-10-23, found by the independent verification: DTLS application data is unreliable, and a reply is
    # usually a few chunks (~15 with an ML-DSA-65 signature + certificate) -- one datagram lost on Wi-Fi turned a delivered file into "closed without a reply"
    # (~1 in 100 calls). A short message (every reply, every small request) is therefore sent a second time a
    # few ms later; the reader keeps the first copy of each seq (`parts.setdefault`), so this is invisible to
    # it -- including readers that predate this change. Both copies must be lost now. Long messages are not
    # doubled (bandwidth); their loss still fails the exchange within the caller's budget.
    if n <= REDUNDANT_MAX_CHUNKS:
        _time.sleep(max(pace or 0, REDUNDANT_GAP_S))
        for seq, frame in enumerate(frames):
            ssock.write(frame)
            if pace and seq < n - 1:
                _time.sleep(pace)


def read_framed(ssock, chunk_size=CHUNK_SIZE, max_chunks=4096):
    parts, last, reads = {}, None, 0
    while True:
        if last is not None and len(parts) == last + 1:
            return b"".join(parts[i] for i in range(last + 1))
        if reads >= max_chunks + 64:
            raise FramingError("too many chunks without a complete message")
        reads += 1
        try:
            chunk = ssock.read(chunk_size + _HDR.size)
        except Exception as e:                      # recv timeout / closed
            raise FramingError(_missing_msg(parts, last, e))
        if not chunk:
            raise FramingError(_missing_msg(parts, last, "peer closed"))
        if reads == 1 and _is_legacy_first_chunk(chunk):
            return _read_legacy(ssock, chunk, chunk_size, max_chunks)
        if len(chunk) < _HDR.size:
            raise FramingError("runt chunk (%d bytes)" % len(chunk))
        more, seq = _HDR.unpack_from(chunk)
        if seq >= max_chunks:
            raise FramingError("chunk seq %d out of range" % seq)
        parts.setdefault(seq, chunk[_HDR.size:])      # a duplicate datagram is ignored
        if more == 0:
            last = seq


def _read_legacy(ssock, first, chunk_size, max_chunks):
    """The rest of a legacy-framed message (see _is_legacy_first_chunk); marks the socket so the
    reply goes back in legacy framing too."""
    try:
        ssock._legacy_framing = True
    except AttributeError:
        pass
    parts, chunk = [], first
    for _ in range(max_chunks):
        if not chunk:
            break
        parts.append(chunk[1:])
        if chunk[0] == 0:
            break
        chunk = ssock.read(chunk_size + 1)
    return b"".join(parts)


def _missing_msg(parts, last, why):
    top = last if last is not None else (max(parts) if parts else -1)
    missing = [i for i in range(top + 1) if i not in parts]
    return "incomplete message (%s): got %d chunks, missing %s%s" % (
        why, len(parts), missing[:10], "..." if len(missing) > 10 else "")


class PeerIdentityError(IOError):
    """The DTLS server's certificate does not name the peer we meant to reach (CN) or is not bound to the
    address we dialled (SAN IP). Raised by the worker before any application data is written."""


# key_share -> (wolfSSL group id to offer, the name negotiated_group() must then report, the name for
# wolfSSL_set1_groups_list). 2026-10-23 (PQC = ML-KEM-768 + ML-DSA-65): "mlkem768" is the PURE ML-KEM-768
# group (TLS codepoint 0x0201), no X25519 half -- what every `*-pqc` CoAP tech now negotiates.
# 2026-10-23 (wire check): "x25519" pins the group LIST too -- with only the key share chosen, the classical
# coap-dtls ClientHello still advertised every hybrid / ML-KEM group wolfSSL has in supported_groups.
KEY_SHARES = {"x25519": (29, "X25519", b"X25519"),
              "hybrid": (4588, "X25519MLKEM768", None),
              "mlkem768": (513, "ML_KEM_768", b"ML_KEM_768")}


def _binding_lib():
    """ctypes handle on the wolfssl binding's OWN compiled module (_ffi*.so statically links its wolfSSL --
    /opt/pqc-libs/wolfssl-dtls is a different copy whose WOLFSSL struct is not this one), and a function
    turning an SSLSocket into its WOLFSSL* for it."""
    import ctypes
    import glob
    import wolfssl
    from wolfssl._ffi import ffi as _wffi
    so = glob.glob(_os.path.join(_os.path.dirname(wolfssl.__file__), "_ffi*.so"))
    if not so:
        raise IOError("cannot locate the wolfssl binding's _ffi module")
    return ctypes.CDLL(so[0]), (lambda ssock: int(_wffi.cast("uintptr_t", ssock.native_object)))


def pin_groups(ssock, groups_list: bytes):
    """Restrict an SSLSocket's supported_groups to `groups_list` (wolfSSL_set1_groups_list), before the
    handshake. Needed for pure ML-KEM-768: wolfSSL_UseKeyShare() only chooses the key SHARE sent; the
    default supported_groups list still advertises the hybrid group, and a server that prefers it answers
    with a HelloRetryRequest -- found live 2026-10-23: a "mlkem768" client ended up on X25519MLKEM768.
    The binding exposes no groups API, so it is called through ctypes on the binding's OWN compiled
    module (_ffi*.so statically links its wolfSSL -- /opt/pqc-libs/wolfssl-dtls is a different copy whose
    WOLFSSL struct is not this one). Raises if wolfSSL refuses, so a pin can never silently not happen."""
    import ctypes
    lib, ptr = _binding_lib()
    lib.wolfSSL_set1_groups_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.wolfSSL_set1_groups_list.restype = ctypes.c_int
    rc = lib.wolfSSL_set1_groups_list(ptr(ssock), groups_list)
    if rc != 1:
        raise IOError(f"wolfSSL_set1_groups_list({groups_list!r}) failed (rc={rc})")


def set_handshake_retransmit_max(ssock, seconds):
    """Cap wolfSSL's DTLS handshake retransmission back-off (wolfSSL_dtls_set_timeout_max; default 64 s).
    2026-10-23, found by the refusal battery: the relay serves ONE peer per address by connect()ing its only
    socket to it; a ClientHello from a peer that has already gone (an aborted handshake's retransmission) kept
    the relay waiting through the whole back-off -- about a minute in which every other client on that address
    got ICMP port-unreachable (client: wolfSSL -308). With max=4 s the worst case is 1+2+4 s."""
    import ctypes
    lib, ptr = _binding_lib()
    lib.wolfSSL_dtls_set_timeout_max.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.wolfSSL_dtls_set_timeout_max.restype = ctypes.c_int
    rc = lib.wolfSSL_dtls_set_timeout_max(ptr(ssock), int(seconds))
    if rc != 1:
        raise IOError(f"wolfSSL_dtls_set_timeout_max({seconds}) failed (rc={rc})")


def _peer_identity_problem(der, expect_cn, expect_ip):
    """-> None when the leaf certificate (DER) has CN == expect_cn and, if it carries IP SANs at all, includes
    expect_ip; else a sentence saying what is wrong. The same two bindings p2p's mtls/https path checks."""
    if not der:
        return "the DTLS peer presented no certificate"
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    cert = x509.load_der_x509_certificate(der)
    if expect_cn:
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cns[-1].value if cns else None
        if cn != expect_cn:
            return f"the DTLS peer presented a certificate for {cn!r}, expected {expect_cn!r}"
    if expect_ip:
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            ips = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            ips = []
        if ips and expect_ip not in ips:
            return f"the DTLS peer's certificate is bound to {sorted(ips)}, but we connected to {expect_ip}"
    return None


class WolfDTLSRemote(interfaces.EndpointAddress):
    scheme = SCHEME
    is_multicast = False
    is_multicast_locally = False
    # A concrete class-level default, NOT just an instance attribute set in __init__ -- abc's
    # abstractmethod check on the inherited `hostinfo` property only counts as "overridden" if
    # the class itself has a non-abstract attribute of that name (same trick tinydtls's own
    # DTLSClientConnection uses); an instance attribute alone still leaves the class abstract.
    hostinfo = None

    def __init__(self, host, port, transport):
        self._host = host
        self._port = port
        self._transport = transport
        self.hostinfo = hostportjoin(host, None if port == DEFAULT_PORT else port)
        # Set by `_exchange()` after a successful handshake, only when the transport was built
        # with `ca_path=` -- see this module's own docstring, "Peer verification". None otherwise
        # (unverified, or the exchange hasn't completed yet).
        self.peer_cert_pem = None
        # Set by `_exchange()` alongside peer_cert_pem: {"handshake_ms", "request_ms"} measured
        # INSIDE the worker process (monotonic clock there), so the caller can tell the DTLS
        # handshake and the request->reply phase apart from process start-up. None until done.
        self.timing = None

    # No meaningful distinct local identity for a one-shot client socket -- same value both ways.
    hostinfo_local = property(lambda self: self.hostinfo)
    uri_base = property(lambda self: f"{SCHEME}://" + self.hostinfo)
    uri_base_local = uri_base
    blockwise_key = property(lambda self: (self._host, self._port))

    def send(self, encoded: bytes):
        asyncio.ensure_future(self._transport._exchange(self, encoded))


class MessageInterfaceWolfDTLS(interfaces.MessageInterface):
    def __init__(self, ctx: interfaces.MessageManager, log, loop, ca_path=None,
                cert_path=None, key_path=None, key_share="hybrid", expect_cn=None, expect_ip=None):
        self.ctx = ctx
        self.log = log
        self.loop = loop
        # None (default): CERT_NONE, unverified -- what dtls_pqkex_client_proof.py uses. Set: the
        # peer's chain must verify against this CA -- see the module docstring's "Peer
        # verification" section.
        self.ca_path = ca_path
        # `coap-dtls-pqc-mutual` (2026-09-28, Stack 4): when BOTH are set, this node's own leaf is
        # presented during the handshake too -- see coap_dtls_pqc_relay.py's `--mutual` mode,
        # which sets `verify_mode = CERT_REQUIRED` server-side and refuses the handshake without
        # it. `coap-dtls-pqc` (non-mutual) never sets these -- same additive shape pqkex-mutual
        # already established for the HTTP-family tech.
        self.cert_path = cert_path
        self.key_path = key_path
        # 2026-10-02: which key share the ClientHello offers. "hybrid" (default, unchanged) =
        # X25519MLKEM768, what `coap-dtls-pqc` has always sent; "x25519" = the classical baseline
        # (`coap-dtls`). Offered ALONE either way, so a completed handshake proves the group.
        self.key_share = key_share
        # 2026-10-23 (v2): WHO the server certificate must name (CN) and which address it must be bound to (SAN
        # IP). Checked INSIDE the worker right after the handshake and BEFORE any application data is written.
        # The caller used to run this check only after the exchange, i.e. after the (DTLS-only-protected,
        # otherwise cleartext) envelope had already been delivered to whichever fleet node answered. None =
        # not checked here (the proof script).
        self.expect_cn = expect_cn
        self.expect_ip = expect_ip
        # A real, separate OS process per exchange -- NOT a thread. wolfssl-py's do_handshake()/
        # read()/write() are blocking calls; running them in a thread would stall the event loop
        # for the handshake's duration same as running them inline would. One process at a time
        # is enough to prove the integration; a busier receiver would want a warm pool sized to
        # expected concurrency.
        self._executor = ProcessPoolExecutor(max_workers=1)
        self._inflight = set()      # concurrent futures of exchanges submitted to the worker (see shutdown())

    @classmethod
    async def create_client_transport_endpoint(cls, ctx: interfaces.MessageManager, log, loop,
                                                ca_path=None, cert_path=None, key_path=None,
                                                key_share="hybrid", expect_cn=None, expect_ip=None):
        return cls(ctx, log, loop, ca_path=ca_path, cert_path=cert_path, key_path=key_path,
                   key_share=key_share, expect_cn=expect_cn, expect_ip=expect_ip)

    async def recognize_remote(self, remote):
        return isinstance(remote, WolfDTLSRemote)

    async def determine_remote(self, request):
        if request.requested_scheme != SCHEME:
            return None
        if request.unresolved_remote:
            host, port = hostportsplit(request.unresolved_remote)
            port = port or DEFAULT_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            port = request.opt.uri_port or DEFAULT_PORT
        else:
            raise ValueError("No location found to send message to")
        return WolfDTLSRemote(host, port, self)

    def send(self, message):
        message.remote.send(message.encode())

    async def _exchange(self, remote: WolfDTLSRemote, encoded: bytes):
        try:
            cf = self._executor.submit(
                self._blocking_exchange, remote._host, remote._port, encoded,
                self.ca_path, self.cert_path, self.key_path, self.key_share, self.expect_cn, self.expect_ip)
            self._inflight.add(cf)
            res = await asyncio.wrap_future(cf, loop=self.loop)
            reply_bytes, group, peer_cert_pem = res[:3]
            remote.timing = res[3] if len(res) > 3 else None
        except Exception as e:
            self.log.warning("wolfdtls exchange with %s failed: %s", remote.hostinfo, e)
            self.ctx.dispatch_error(e, remote)
            return
        self.log.info("wolfdtls exchange with %s negotiated group %s", remote.hostinfo, group)
        remote.peer_cert_pem = peer_cert_pem
        if not reply_bytes:
            # 2026-10-23: used to `return` silently, so the request then sat out its whole budget (20 s) before
            # failing with no reason. The peer closed after the handshake without answering -- a relay refusing
            # (wrong key-exchange group, no certificate) or failing -- say so now.
            self.ctx.dispatch_error(IOError("DTLS peer closed the session without a reply (the relay refused "
                                            "or failed this request)"), remote)
            return
        try:
            reply = Message.decode(reply_bytes, remote)
        except error.UnparsableMessage:
            self.log.warning("Ignoring unparsable reply from %s", remote.hostinfo)
            return
        self.ctx.dispatch_message(reply)

    @staticmethod
    def _blocking_exchange(host, port, data: bytes, ca_path=None, cert_path=None, key_path=None,
                           key_share="hybrid", expect_cn=None, expect_ip=None):
        """Runs in a worker PROCESS -- everything here is wolfssl-py's BLOCKING API. One UDP
        socket, one DTLS 1.3 handshake requesting the hybrid group, one write, one read, closed.
        No connection reuse/pooling (unlike tinydtls's pool) -- a correctness proof, not yet
        optimized for a chatty receiver.

        No `sock.settimeout()` call, deliberately -- see this module's own docstring for why: it
        puts the fd wolfSSL drives directly into non-blocking mode and breaks the handshake.

        `ca_path=None` (default): CERT_NONE, unverified -- what dtls_pqkex_client_proof.py's own
        proof still uses. `ca_path` set: CERT_REQUIRED against that CA; the peer's leaf cert is
        returned as a PEM string (None if unverified) for the caller to run its OWN CN/SAN check
        against -- see the module docstring's "Peer verification" section for why that check lives
        in the caller and not here.

        `cert_path`/`key_path` (2026-09-28, `coap-dtls-pqc-mutual`): when set, this node's own
        leaf is presented too -- load_cert_chain() before wrap_socket(), same call wolfSSL's
        server side already makes, just on the client. A `coap-dtls-pqc` (non-mutual) exchange
        never sets these; the peer's `verify_mode` decides whether it was required."""
        import ssl as _stdlib_ssl  # DER_cert_to_PEM_cert only -- a pure format conversion, no TLS
        import wolfssl
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((host, port))
        ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_DTLSv1_3, server_side=False)
        if ca_path:
            ctx.verify_mode = wolfssl.CERT_REQUIRED
            ctx.load_verify_locations(ca_path)
        else:
            ctx.verify_mode = wolfssl.CERT_NONE
        if cert_path and key_path:
            ctx.load_cert_chain(cert_path, key_path)
        # do_handshake_on_connect=False: the socket is already connect()'ed above, so
        # wrap_socket() would otherwise ALSO drive an implicit wolfSSL_connect() itself (see
        # SSLSocket.__init__'s own `if connected: ... self.do_handshake()`) -- see this module's
        # docstring; a single explicit call below is enough.
        # "x25519" -> wolfSSL's group id 29 (WOLFSSL_ECC_X25519, the value rtp_dtls_srtp_sender.py
        # already uses for the classical tier); "hybrid" -> X25519MLKEM768; "mlkem768" -> pure ML-KEM-768.
        group_id, expected_group, pin = KEY_SHARES.get(key_share, KEY_SHARES["hybrid"])
        ssock = ctx.wrap_socket(sock, key_share_group=group_id,
                                dtls_mtu=DTLS_MTU, do_handshake_on_connect=False)
        if pin:
            pin_groups(ssock, pin)
        t_hs = _time.perf_counter()
        c_hs = _time.process_time()        # this worker process's CPU (user+sys); it is single-threaded
        ssock.do_handshake()
        t_connected = _time.perf_counter()
        c_connected = _time.process_time()
        group = ssock.negotiated_group()
        # 2026-10-23: the tech is defined by the group it negotiates. Offered ALONE already (see
        # key_share_group above), so a completed handshake proves it; this makes the check explicit and
        # BEFORE any application data is written, and reports what was observed.
        if str(group) != expected_group:
            ssock.close()
            raise IOError(f"DTLS handshake negotiated group {str(group)!r}, this tech requires "
                          f"{expected_group!r}")
        try:
            dtls_version = ssock.version()
        except Exception:                                   # noqa: BLE001
            dtls_version = None
        peer_cert_pem = None
        if ca_path:
            der = ssock.getpeercert(binary_form=True)
            if der:
                peer_cert_pem = _stdlib_ssl.DER_cert_to_PEM_cert(der)
        if expect_cn or expect_ip:
            # The identity gate, before a single application byte is written (see __init__'s note).
            problem = _peer_identity_problem(der if ca_path else ssock.getpeercert(binary_form=True),
                                             expect_cn, expect_ip)
            if problem:
                ssock.close()
                raise PeerIdentityError(problem)
        t_verified = _time.perf_counter()
        write_framed(ssock, data)
        try:
            reply = read_framed(ssock)
        except Exception:
            reply = None
        t_done = _time.perf_counter()
        ssock.close()
        return reply, group, peer_cert_pem, {
            # the handshake INCLUDING the identity check above (as on every other tech), then request -> reply
            "handshake_ms": round((t_verified - t_hs) * 1000, 3),
            "request_ms": round((t_done - t_verified) * 1000, 3),
            "handshake_cpu_ms": round((c_connected - c_hs) * 1000, 3),
            "group": str(group), "version": dtls_version}

    async def shutdown(self):
        # wait=True, deliberately (found live, 2026-09-27): a Context that creates a FRESH
        # MessageInterfaceWolfDTLS per exchange (client.py's `_coap_dtls_exchange`, matching
        # `_coap_exchange`'s own fresh-Context-per-call pattern) leaks one live worker OS process
        # per exchange over a long-running client's lifetime if this doesn't actually wait for it
        # to exit -- `wait=False` returns immediately but leaves the (idle, but still-alive)
        # ProcessPoolExecutor worker running; Python's own interpreter shutdown then blocks trying
        # to reap it anyway, just deferred to process-exit time instead of here, and a long-running
        # client that never exits would just accumulate them. The worker has at most one
        # already-completed task by the time shutdown() is called (this transport's Context is
        # never reused across exchanges), so waiting for it to exit is fast in practice.
        # 2026-10-23, found live (a 1 MiB coap-dtls transfer hung 20 min under --timeout 120): when the caller's
        # budget expires, the worker can still be blocked in recv() -- after the handshake wolfSSL resets the
        # socket's SO_RCVTIMEO to "forever", and a DTLS record lost on the air leaves both ends waiting for each
        # other. wait=True then waited forever too. A worker whose exchange is still running is killed first,
        # so the budget the caller gave is the budget it gets.
        if any(not f.done() for f in self._inflight):
            for proc in list((getattr(self._executor, "_processes", None) or {}).values()):
                try:
                    proc.kill()
                except Exception:                          # noqa: BLE001 -- already gone
                    pass
        self._executor.shutdown(wait=True, cancel_futures=True)
