#!/usr/bin/env python3
"""p2p/receiver-role/coap_dtls_pqc_relay -- the receiver half of the `coap-dtls-pqc` tech
(2026-09-27): a real hybrid PQ-KEX DTLS 1.3 (X25519MLKEM768, via the patched `wolfssl` binding --
see PQC-bench/wolfssl-py-patch/) front door for the SAME plain CoAP backend `coap`/`coap-enc`/
`coap-pqc` already run (coap_server.py on P2P_COAP_PORT), the same shape pqkex's stunnel front
door already uses for the HTTP family: decrypt, forward, relay the reply back encrypted.
coap_server.py never sees anything different about this tech -- the envelope inside the forwarded
bytes is `coap`'s exact cleartext-payload shape (real confidentiality now comes from the DTLS
transport itself; layering coap-pqc's KEM encryption UNDER it too would be redundant, the same
reasoning pqkex gives for reusing `http`'s plain envelope under its own real transport encryption).

NOT a byte-for-byte pipe, unlike pqkex's stunnel proxy -- found live, 2026-09-27: coap_server.py is
a real, standards-compliant aiocoap server, and it Block2-chunks (RFC 7959) ANY response over its
own default ~1 KB threshold UNPROMPTED, regardless of how the request arrived or what carried it --
p2p's own signed-response envelope (resp_cert alone is a whole certificate) reliably exceeds that
threshold on ordinary use cases, not just `file`. A raw `send()`/`recv()` pair only ever sees the
FIRST block and silently forwards a truncated reply (found live as a cut-off JSON string on the
sender side). So this relay decodes the (now-decrypted, DTLS-framed) request bytes into a real
`aiocoap.Message` and re-issues it as a genuine aiocoap CLIENT request to coap_server.py -- full
blockwise REQUEST *and* RESPONSE handling, both directions, for free, the same machinery `coap`/
`coap-enc`/`coap-pqc` already rely on. The ORIGINAL sender's `mid`/`token` are preserved on the way
back (matching them by hand is what makes token-based correlation on the SENDER's own aiocoap
Context resolve the pending request instead of timing out) -- the relay's OWN request to
coap_server.py gets its own independent mid/token, unrelated to the original ones; only the reply
sent back over DTLS needs to wear the sender's.

Why a hand-rolled DTLS front door and not stunnel (pqkex's own choice): stunnel is TCP-oriented and
this is UDP/DTLS; the private OpenSSL 3.4 build pqkex's proxy uses has no DTLS 1.3 story at all,
which is the entire reason PQC-bench/wolfssl-py-patch/ exists (see its own README). This relay is
that patched wolfSSL, used as a server, instead.

Scope, deliberately: SEQUENTIAL, single peer at a time PER LOCAL ADDRESS (see "multi-homed reply
address" below for why it's per-address) -- no async multi-peer server (that is the "receiver-side
DTLS server transport" work aiocoap_wolfdtls.py's own docstring calls out as separate, larger,
unstarted). A hung/malicious peer's handshake is bounded by SO_RCVTIMEO (a KERNEL-level receive
timeout that leaves the fd genuinely blocking -- NOT Python's own `sock.settimeout()`, which flips
the fd to O_NONBLOCK and is exactly the bug aiocoap_wolfdtls.py's own docstring documents chasing
down for the client side of this same transport) so one bad peer delays, but does not permanently
wedge, every peer after it.

Multi-homed reply address (found live, 2026-09-27, on the REAL fleet -- every earlier proof of
this tech ran over loopback, which never exposed it): a socket bound to the wildcard `0.0.0.0`
receives a request fine regardless of which of this box's local addresses it arrived on, but a
REPLY sent back out on that same wildcard socket gets its SOURCE address chosen by the kernel's
own routing table for the destination -- not necessarily the address the request arrived on. On a
single-homed box those are always the same address, so this never shows up; on a multi-homed
GATEWAY box (this relay's actual deployment target) they can differ, and the sender's `connect()`ed
DTLS socket only accepts a reply from the EXACT address:port it connected to -- a reply from the
"wrong" local address is silently dropped by the kernel, and the sender just retransmits into the
same failure forever. Confirmed live: a sender resolved this node at `10.2.1.1` (its downstream
address), but the wildcard socket's reply routed out via `10.2.0.10` (its uplink) instead.
aiocoap's own UDP transport solves this exact problem with `IPV6_PKTINFO`/`recvmsg`/`sendmsg` (see
`aiocoap/transports/udp6.py`) -- not available here, since wolfSSL drives the raw fd directly via
its own internal C-level `send()`/`recv()` callbacks once `wolfSSL_set_fd()` is called, with no
hook to override the reply's source address per-packet. The fix instead: `main()` binds one
listener PER local IPv4 address (`_local_ipv4_addrs()`), each in its own thread -- a socket bound
to a SPECIFIC address (never the wildcard) always replies from that same address, no PKTINFO
needed, because there is no ambiguity left for the kernel to resolve.

No client-certificate verification at this layer: same asymmetric trust model pqkex's proxy uses
-- the SENDER verifies THIS box's server certificate (real fleet CA, real CN/SAN check, done by
the sender's own `_coap_dtls_exchange`), but the SENDER's identity is still the classical signed
envelope INSIDE the forwarded bytes, checked by coap_server.py exactly as it already does for
`coap`. Adding client-cert verification here would duplicate that check at a different layer for
no real gain, the same reasoning server.py's own mTLS-vs-https split already documents.

wolfSSL is not used concurrently from multiple threads (found live, 2026-09-27, on the real fleet
-- multiple per-address threads is exactly what put this at risk, and it was never exercised
locally: every earlier proof of this tech, including the local integration test, bound a single
address, hence a single thread). This build was never configured for multi-threaded use
(no --enable-mutex or equivalent), and this C library's own global state is not documented as
safe for concurrent access from independent Python threads regardless -- two per-address threads
both inside wolfSSL at once (one mid-handshake, another just starting) is a real, live-reproduced
way to corrupt that shared state, and manifested as the WHOLE relay PROCESS periodically dying
(not just one thread), restarted by systemd's Restart=on-failure, with the very next exchange
succeeding cleanly (fresh process, fresh state) and the one after THAT failing again once a second
thread became concurrently active -- consistent with genuine memory corruption, not a logic bug in
this module's own Python code. `_WOLFSSL_LOCK` below serializes every wolfSSL C call across all
threads; each thread's OWN 90-second MSG_PEEK wait for a peer on ITS OWN address stays
independent (the lock is acquired only once a real peer has actually shown up, not while idle), so
this doesn't undo the "one thread per address" design above -- it just means, correctly, that only
ONE actual exchange is ever mid-flight through wolfSSL at a time, matching this module's own
already-documented "sequential, single peer at a time" scope, now enforced for real.
"""
import asyncio
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # p2p/ root, for `common`
from common import identity  # noqa: E402

# Serializes every wolfSSL C call across all per-address threads -- see this module's own
# docstring, "wolfSSL is not used concurrently from multiple threads", for why.
_WOLFSSL_LOCK = threading.Lock()

# PQC-bench/wolfssl-py-patch/, for `aiocoap_wolfdtls`'s write_framed/read_framed -- same
# override-with-a-sane-default pattern client.py's own COAP_DTLS_PQC_MODULE_PATH uses. The
# systemd unit (p2p-coap-dtls-pqc-relay.service) already sets this via PYTHONPATH=; this is a
# fallback for running the script directly (e.g. this module's own local integration tests).
_WOLFDTLS_MODULE_PATH = os.environ.get(
    "COAP_DTLS_PQC_MODULE_PATH", "/opt/PQC-bench/wolfssl-py-patch")
if _WOLFDTLS_MODULE_PATH not in sys.path:
    sys.path.insert(0, _WOLFDTLS_MODULE_PATH)

RECV_BUF = 65536
# P2P_COAP_DTLS_REQUIRE_GROUP (2026-10-02, opt-in): refuse a handshake whose negotiated key-exchange
# group is not this one (e.g. "X25519" on the classical `coap-dtls` ports). Unset = accept any.
REQUIRE_GROUP = os.environ.get("P2P_COAP_DTLS_REQUIRE_GROUP", "").strip()
if REQUIRE_GROUP == "*":            # explicit opt-out: accept whichever group the client offered
    REQUIRE_GROUP = ""
elif not REQUIRE_GROUP:
    # 2026-10-23 audit: the PQC relay (`coap-dtls-pqc`, `coap-dtls-pqc-mutual`) used to leave this unset and
    # so also completed a handshake with a client that offered only classical X25519 -- a "post-quantum"
    # port answering a classical downgrade. Pinned by default, as the classical ports pin theirs to X25519.
    # 2026-10-23 (owner: "PQC always means ML-KEM-768 and ML-DSA-65"): the pin is the PURE ML-KEM-768 group,
    # not the X25519MLKEM768 hybrid, and PQC_MODE below switches the certificates to ML-DSA-65.
    REQUIRE_GROUP = "ML_KEM_768"
# The `coap-dtls-pqc*` instances: ML-KEM-768 key exchange AND ML-DSA-65 certificates (this node's own PQC
# leaf from /var/lib/p2p/certs-pqc as the server certificate, and the PQC CA to verify a mutual client's).
# The classical `coap-dtls*` instances (REQUIRE_GROUP=X25519) keep the fleet RSA identity.
PQC_MODE = REQUIRE_GROUP == "ML_KEM_768"
# How long a single peer's handshake/request/forward round trip may take before this relay gives
# up on it and goes back to accepting the next one. Generous: a hybrid-PQC DTLS handshake plus a
# full coap_server.py round trip (which itself can run rm/ml for up to their own MAX_TIMEOUT) is
# not fast -- see p2p/sender-role/client.py's own _coap_budget for the equivalent sender-side
# reasoning. This relay does not attempt per-use-case budgets the way the sender does; one flat,
# generous ceiling, since exceeding it just means the NEXT peer waits a bit longer, not data loss.
PEER_TIMEOUT_S = 90
# DTLS handshake retransmission back-off cap (s): bounds how long a peer that left mid-handshake holds the address
HANDSHAKE_RETRANSMIT_MAX_S = int(os.environ.get("P2P_COAP_DTLS_HS_RETRANSMIT_MAX_S", "4"))


def _set_rcvtimeo(sock, seconds):
    """A KERNEL-level receive timeout (SO_RCVTIMEO) -- NOT Python's `sock.settimeout()`, which
    puts the fd into O_NONBLOCK and breaks wolfSSL's own C-level I/O callbacks (see
    aiocoap_wolfdtls.py's docstring for the exact bug this caused on the client side of this same
    transport). SO_RCVTIMEO bounds a blocking recv() without touching the fd's blocking mode at
    all -- the right tool for exactly this job."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("qq", seconds, 0))


def _relay_tech(mutual):
    """The DTLS tech this relay instance IS, from how it was started (never from a client): the
    X25519-pinned instances are `coap-dtls`, the hybrid ones `coap-dtls-pqc`; `-mutual` when it
    demands a client certificate. P2P_COAP_DTLS_TECH overrides."""
    forced = os.environ.get("P2P_COAP_DTLS_TECH", "").strip()
    if forced:
        return forced
    return ("coap-dtls-pqc" if PQC_MODE else "coap-dtls") + ("-mutual" if mutual else "")


# coap_server.py's RELAY_TECH_OPTION: a private elective option naming the tech, honoured there only
# for a loopback peer (this process).
RELAY_TECH_OPTION = 65008
# ...and one more (65010, elective) carrying a small JSON object of what THIS relay's DTLS session observed
# (version, negotiated group, and on a mutual port the client certificate's issuer / key / signature), for the
# receiver's own log row. coap_server.py trusts it under the same loopback-only rule.
RELAY_TLS_OPTION = 65010


def _session_facts(ssock, group, mutual):
    """What the DTLS 1.3 session observably negotiated, in the comm-log's tls_* vocabulary (+ `group`).
    wolfSSL does not expose the cipher suite, so tls_cipher is left out rather than guessed."""
    facts = {"tls_version": "DTLSv1.3", "group": str(group)}
    if mutual:
        try:
            import ssl as _ssl
            der = ssock.getpeercert(binary_form=True)
            if der:
                facts.update(identity.cert_facts_from_pem(_ssl.DER_cert_to_PEM_cert(der)))
        except Exception:                                   # noqa: BLE001 -- descriptive only
            pass
    return facts


async def _forward_via_coap(coap_port, req_bytes, tech=None, facts=None):
    """Decode the (now-decrypted) request bytes as a real aiocoap.Message, re-issue it as a
    genuine aiocoap CLIENT request against coap_server.py's plain listener -- full blockwise
    handling both directions, see this module's own docstring for why that's necessary rather
    than a raw byte forward -- and return (their_response, our_original_mid, our_original_token)
    so the caller can build the reply the ORIGINAL sender is actually waiting on."""
    import aiocoap
    from aiocoap.message import Message

    req = Message.decode(req_bytes)
    uri = f"coap://127.0.0.1:{coap_port}/" + "/".join(req.opt.uri_path)
    fwd_req = aiocoap.Message(code=req.code, uri=uri, payload=req.payload)
    if tech:        # decoded `req` is NOT copied wholesale, so a client-sent copy of the option is dropped
        from aiocoap.optiontypes import StringOption
        fwd_req.opt.add_option(StringOption(RELAY_TECH_OPTION, tech))
        if facts:
            fwd_req.opt.add_option(StringOption(RELAY_TLS_OPTION, json.dumps(facts, separators=(",", ":"))))
    ctx = await aiocoap.Context.create_client_context()
    try:
        their_resp = await asyncio.wait_for(ctx.request(fwd_req).response, timeout=PEER_TIMEOUT_S)
    finally:
        await ctx.shutdown()
    return their_resp, req.mid, req.token


def _handle_one_peer(bind_host, dtls_port, coap_port, cert_path, key_path, mutual=False,
                     ca_path=None):
    import wolfssl
    from aiocoap.message import Message
    from aiocoap.numbers.types import Type
    # `write_framed`/`read_framed` are imported from aiocoap_wolfdtls, not reimplemented here, so
    # the two ends of this tech's wire format can never drift out of sync -- see that module's own
    # docstring ("Message-level chunking...") for the full DTLS_SIZE_ERROR story this fixes.
    from aiocoap_wolfdtls import write_framed, read_framed, DTLS_MTU, pin_groups, set_handshake_retransmit_max

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Deliberately NO SO_REUSEADDR here -- found live, 2026-09-27, on the real fleet: an EARLIER
    # version of this function set it as a defensive measure against a leaked socket wedging the
    # next bind(), but for UDP on Linux, SO_REUSEADDR lets MULTIPLE sockets be simultaneously
    # bound to the exact same (address, port), and the kernel then delivers each INCOMING packet
    # to only ONE of them by its own internal choice -- not necessarily the one this specific
    # iteration is actually reading from. If the previous iteration's `listen_sock` had not
    # FULLY released the port yet at the exact moment the next one bound (a real, if narrow,
    # timing window -- close() is not synchronous with the kernel's own socket teardown), later
    # ClientHellos could be silently delivered to that already-abandoned socket instead, with no
    # error anywhere: exactly the "one exchange succeeds, every later one on the same address
    # times out with nothing logged" symptom this produced live. `listen_sock` is now
    # unconditionally closed in `finally` below regardless (see that comment), which is the real
    # fix for the leak SO_REUSEADDR was trying to paper over -- a plain, un-reused bind is the
    # correct default once the leak itself is actually fixed rather than compensated for.
    listen_sock.bind((bind_host, dtls_port))
    _set_rcvtimeo(listen_sock, PEER_TIMEOUT_S)
    ssock = None
    addr = None
    watchdog = None
    try:
        # Loop, not a single peek -- found live, 2026-09-27, on the real fleet: after ONE
        # exchange completes, the sender's wolfSSL socket sends a trailing DTLS record (an Alert
        # -- almost certainly close_notify, from the teardown at the end of the exchange) from
        # the SAME source port that just finished. A plain MSG_PEEK can't tell that apart from a
        # genuine new peer's ClientHello -- both are "some datagram from some address" -- so the
        # OLD code connect()'ed to it and called do_handshake() on it, which then blocked for the
        # FULL SO_RCVTIMEO window (the sender has nothing more to say; it isn't a handshake) WHILE
        # HOLDING _WOLFSSL_LOCK -- starving every other, genuinely new peer for up to 90 seconds
        # with nothing logged (do_handshake() was still "in progress", not yet failed). Every
        # DTLS record's first byte is its content type (RFC 6347): 22 (0x16) is Handshake, which
        # is the only type worth treating as "a new peer" here; anything else (21/Alert is the
        # one actually seen live, but this doesn't special-case it) is drained via a REAL
        # recvfrom() -- MSG_PEEK never removes a datagram from the queue, so leaving it there
        # would just re-peek the same stale record forever -- and the loop goes back to waiting,
        # within the SAME overall SO_RCVTIMEO budget (a kernel-tracked deadline on the socket,
        # not something this loop resets).
        while True:
            try:
                peeked, addr = listen_sock.recvfrom(RECV_BUF, socket.MSG_PEEK)
            except (socket.timeout, BlockingIOError):
                # found live, 2026-09-27, on the real fleet: a KERNEL-level SO_RCVTIMEO expiry
                # (what `_set_rcvtimeo` uses, deliberately NOT Python's own settimeout()) raises
                # BlockingIOError (errno 11, EAGAIN) -- NOT socket.timeout, which is reserved for
                # Python's OWN settimeout()-based timeout mechanism specifically. Catching only
                # socket.timeout here let every idle-window expiry -- on EVERY address, including
                # the active one, whose own window re-arms after each exchange -- fall through as
                # a logged "failed" instead of a silent, expected "no peer yet, try again".
                return  # nothing showed up within the budget -- go back and bind fresh, nothing to log
            if peeked and peeked[0] == 0x16:  # DTLS Handshake content type -- a real ClientHello
                break
            try:                                # drain the non-handshake record (a trailing
                listen_sock.recvfrom(RECV_BUF)  # Alert, most likely) so it doesn't sit in the
            except (socket.timeout, BlockingIOError):  # queue forever, then keep waiting
                return
        listen_sock.connect(addr)
        # 2026-10-23, found live: once the handshake is done wolfSSL resets SO_RCVTIMEO to "forever", so
        # PEER_TIMEOUT_S never fired and a DTLS record lost on the air held this address (and _WOLFSSL_LOCK, i.e.
        # every address) indefinitely. A watchdog shuts the socket down at the budget: the blocked recv() returns,
        # wolfSSL fails the read, and the finally below frees the address.
        watchdog = threading.Timer(PEER_TIMEOUT_S, _wake_socket, args=(listen_sock, addr))
        watchdog.daemon = True
        watchdog.start()

        # _WOLFSSL_LOCK held for the whole exchange, deliberately -- see this module's own
        # docstring, "wolfSSL is not used concurrently from multiple threads", for why this is
        # correctness, not just throughput tuning: this build was never configured/verified for
        # concurrent multi-threaded use, and letting two threads both be inside wolfSSL at once
        # was reproduced live crashing the whole relay process. Acquired only now, AFTER a real
        # peer was already found (not around the 90s idle MSG_PEEK wait above) -- so each
        # address's own idle wait stays independent; only actual exchanges serialize.
        with _WOLFSSL_LOCK:
            ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_DTLSv1_3, server_side=True)
            ctx.load_cert_chain(cert_path, key_path)
            # `coap-dtls-pqc-mutual` (2026-09-28, Stack 4): a SEPARATE port/process (see main())
            # sets this, refusing the handshake outright without a verified client cert. The
            # DEFAULT (non-mutual, `coap-dtls-pqc`) path below is unchanged -- see this module's
            # own docstring for why no client-cert verification there.
            if mutual:
                ctx.verify_mode = wolfssl.CERT_REQUIRED
                ctx.load_verify_locations(ca_path)
            #
            # `ctx.wrap_socket()` itself is now INSIDE this try (found live, 2026-09-27: it used
            # to run before the try/finally even started -- if IT raised, for any reason,
            # `listen_sock` was never closed at all, since only `ssock.close()` ran in the old
            # `finally`, and `ssock` would not even exist yet. A leaked socket, still bound to
            # this exact address:port, silently absorbs every later ClientHello sent there --
            # read by nothing, forever, with no error anywhere -- which is exactly the "sender
            # times out, relay logs nothing at all" symptom this bug produced live on the fleet.)
            ssock = ctx.wrap_socket(listen_sock, server_side=True, dtls_mtu=DTLS_MTU,
                                    do_handshake_on_connect=False)
            # a vanished peer may hold this address for the handshake back-off only (aiocoap_wolfdtls docstring)
            set_handshake_retransmit_max(ssock, HANDSHAKE_RETRANSMIT_MAX_S)
            if PQC_MODE:
                # offer ONLY ML-KEM-768: a hybrid or classical key share is refused inside the handshake
                # (wolfSSL: "Key Share data contains a group which is invalid"), not after it
                pin_groups(ssock, b"ML_KEM_768")
            ssock.do_handshake()
            group = ssock.negotiated_group()
            # 2026-10-02: a port can be pinned to one key-exchange group. The classical `coap-dtls`
            # relay (X25519) sets this so a hybrid offer is refused rather than quietly accepted --
            # otherwise a "classical" benchmark row could be answered by a hybrid handshake. Unset
            # (every pre-existing relay) = unchanged.
            if REQUIRE_GROUP and str(group) != REQUIRE_GROUP:
                print(f"[coap-dtls-pqc-relay] {addr[0]}:{addr[1]} -- negotiated group {group!r}, "
                      f"this port requires {REQUIRE_GROUP!r}: refused", flush=True)
                return
            req_bytes = read_framed(ssock)
            if not req_bytes:
                return
            their_resp, orig_mid, orig_token = asyncio.run(
                _forward_via_coap(coap_port, req_bytes, tech=_relay_tech(mutual),
                                  facts=_session_facts(ssock, group, mutual)))
            # mtype=NON to match this transport's own convention (see p2p/sender-role/client.py's
            # coap-dtls-pqc entry) -- the ORIGINAL sender's mid/token, NOT this relay's own
            # request to coap_server.py, which had its own independent ones (see
            # _forward_via_coap's docstring).
            resp = Message(code=their_resp.code, mtype=Type.NON, mid=orig_mid, token=orig_token,
                           payload=their_resp.payload)
            reply_bytes = resp.encode()
            write_framed(ssock, reply_bytes)
        print(f"[coap-dtls-pqc-relay] {addr[0]}:{addr[1]} -- {len(req_bytes)}B request -> "
              f"{len(reply_bytes)}B reply, group={group}", flush=True)
    except Exception as e:                        # noqa: BLE001 -- one peer's failure must not
        who = f"{addr[0]}:{addr[1]}" if addr else f"{bind_host}:{dtls_port}"
        print(f"[coap-dtls-pqc-relay] {who} -- failed: {e}", flush=True)
        traceback.print_exc()                      # take the relay process down for the next one
    finally:
        # Close BOTH, unconditionally, regardless of how far this attempt got -- `ssock.close()`
        # alone used to be the only cleanup, which left `listen_sock` open (leaked, still bound
        # to this exact address:port) whenever the failure happened before `ssock` was ever
        # assigned (see the `ctx.wrap_socket()` comment above for why that was a real, live bug).
        if watchdog is not None:
            watchdog.cancel()
        if ssock is not None:
            try:
                ssock.close()
            except Exception:                      # noqa: BLE001 -- already in a failure path
                pass
        try:
            listen_sock.close()
        except Exception:                          # noqa: BLE001 -- already in a failure path
            pass


def _local_ipv4_addrs():
    """All this box's global-scope IPv4 addresses (never loopback) -- see this module's own
    docstring, "Multi-homed reply address", for why binding to each of these individually (never
    to the 0.0.0.0 wildcard) is what makes a reply's source address come out correct on a
    multi-homed gateway box."""
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope", "global"],
                         capture_output=True, text=True, check=True).stdout
    addrs = []
    for line in out.splitlines():
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "inet" and i + 1 < len(parts):
                addrs.append(parts[i + 1].split("/")[0])
                break
    return sorted(set(addrs))


def _wake_socket(sock, addr):
    print(f"[coap-dtls-pqc-relay] {addr[0]}:{addr[1]} -- no progress for {PEER_TIMEOUT_S}s: socket shut down", flush=True)
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _accept_loop(bind_host, dtls_port, coap_port, cert_path, key_path, mutual=False, ca_path=None):
    """One address's accept loop -- run in its own thread per address, see main()."""
    while True:
        try:
            _handle_one_peer(bind_host, dtls_port, coap_port, cert_path, key_path,
                             mutual=mutual, ca_path=ca_path)
        except Exception as e:                     # noqa: BLE001 -- the ACCEPT loop itself must
            print(f"[coap-dtls-pqc-relay] accept-loop error on {bind_host}: {e}",  # never die on
                  flush=True)                                            # one bad peer/packet
            traceback.print_exc()
            time.sleep(1)


def main():
    name = os.environ["P2P_NODE_NAME"]
    server_api = os.environ["SERVER_API_BASE"]
    secret = os.environ["BOOTSTRAP_SECRET"]
    # "auto" (the default): bind one listener per local IPv4 address, discovered live -- see this
    # module's own docstring, "Multi-homed reply address". A comma-separated list overrides it
    # (e.g. to exclude an address on purpose); the old single-wildcard "0.0.0.0" is still accepted
    # for a genuinely single-homed box, but is no longer the default.
    bind_env = os.environ.get("P2P_COAP_DTLS_PQC_BIND", "auto")
    if bind_env == "auto":
        bind_hosts = _local_ipv4_addrs()
        if not bind_hosts:
            raise RuntimeError("P2P_COAP_DTLS_PQC_BIND=auto found no local IPv4 addresses")
    else:
        bind_hosts = [h.strip() for h in bind_env.split(",") if h.strip()]
    # `coap-dtls-pqc-mutual` (2026-09-28, Stack 4): a SEPARATE process/port, driven by this same
    # env-var-toggle-selects-a-process-instance idiom -- not two threads in one process serving
    # different ports with different verify_mode, matching the "own port, own process" shape
    # every other mutual variant here (pqkex-mutual, MQTT_MODE=pqc-mutual) already uses.
    mutual = os.environ.get("P2P_COAP_DTLS_PQC_MUTUAL", "0") == "1"
    default_port = "5686" if mutual else "5685"
    dtls_port = int(os.environ.get("P2P_COAP_DTLS_PQC_PORT", default_port))
    coap_port = int(os.environ.get("P2P_COAP_PORT", "5683"))
    cache_dir = os.environ.get("P2P_CACHE_DIR", "/var/lib/p2p/certs")
    # This node's OWN classical identity -- the same cert/key coap_server.py and server.py already
    # use, reused here as the DTLS server certificate (see this module's docstring: the hybrid
    # KEX is the PQC transport layer, server authentication stays classical/same fleet CA, and
    # sender identity is the classical envelope forwarded through unchanged -- three layers, one
    # PQC, matching the project's established "additive PQC" pattern the `pqc` tech's own
    # docstring already describes). `ca_path` was discarded here before `coap-dtls-pqc-mutual`
    # existed -- now used to verify the CLIENT's cert too, when `mutual`.
    cert_path, key_path, ca_path = identity.fetch_own_cert(server_api, secret, name, cache_dir)
    if PQC_MODE:
        # ML-DSA-65 server certificate + the PQC CA for a mutual client's certificate (2026-10-23).
        cert_path, key_path, ca_path = identity.load_pqc_material(os.environ.get("P2P_PQC_CACHE_DIR"))
    print(f"[coap-dtls-pqc-relay{'-mutual' if mutual else ''}] {name} listening on "
          f"{bind_hosts}:{dtls_port} (DTLS 1.3, {REQUIRE_GROUP or 'any group'}, {'ML-DSA-65' if PQC_MODE else 'RSA'} certs"
          f"{', client cert REQUIRED' if mutual else ''}) "
          f"-> forwarding to plain CoAP on 127.0.0.1:{coap_port}", flush=True)
    threads = [threading.Thread(target=_accept_loop,
                                args=(bh, dtls_port, coap_port, cert_path, key_path),
                                kwargs={"mutual": mutual, "ca_path": ca_path},
                                name=f"accept-{bh}", daemon=True)
              for bh in bind_hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
