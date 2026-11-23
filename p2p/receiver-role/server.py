#!/usr/bin/env python3
"""p2p/receiver-role/server — the peer server (p2p-plan..md §3.1/§3.2).

TLS 1.3, stdlib `http.server` + `ssl` (an OpenSSL binding) — no framework, per
p2p-requirements.md's "openssl tls 1.3" ask. Runs on EVERY node (device / direct / gateway /
sub-gateway); a separate process, separate ports from MQTT/TB, no shared config (requirement:
"don't affect the MQTT TB functionality").

TWO LISTENERS, one process (2026-07-28 — the `https` tech):

  :P2P_PORT (8443)        TLS 1.3 MUTUAL auth. The sender's identity is the TLS peer certificate's
                          CN, never a request header or body (§4.3) — the handshake itself refuses
                          a certless or wrong-CA peer, before any application code runs. Serves the
                          `mtls` and `pqc` techs.
  :P2P_HTTPS_PORT (8444)  TLS 1.3, SERVER auth only — the `https` tech. The sender presents no
                          client certificate, so the handshake cannot say who it is; identity is an
                          RSA-signed envelope in the body instead, verified against the same fleet
                          CA (the same idiom coap_server.py already uses, for the same reason).

THREE LISTENERS as of 2026-09-26 (the `http` tech, the benchmark doc's plaintext tier for HTTP):

  :P2P_HTTP_PORT (8442)   NO TLS AT ALL. Same signed-envelope identity check as `https` (this
                          listener sets mutual=False too), on a plaintext socket instead of a TLS
                          one. `coap`'s NoSec mode already accepts the identical trade for UDP;
                          this is that same trade for TCP/HTTP. See `_identify`'s docstring for how
                          this and `https` are told apart despite sharing one code path.

The two non-mutual listeners are **strictly weaker** and deliberately isolated: a stranger reaches
the application before being refused, instead of being refused by OpenSSL (or, for `http`, there is
no handshake to refuse them at all). Keeping them on their own ports means the mTLS port's
handshake gate is untouched — nothing that was true of `mtls` yesterday became less true today.
Every request on every listener still passes the identical per-pair policy check (§4.3) before a
handler runs, and an `https`/`http` request without a verifiable envelope is 401'd with no handler
reached at all.

USE CASE × TECH (2026-07-28, operator-directed: "a use case is different than a tech"): all four
use cases — `message` (/message), `file` (/deliver), `status` (/status) and `rm` (/rm-exec, the
device→device remote management added 2026-07-28) — are served on every tech. On the envelope
techs (`https`, `pqc`, and CoAP's `coap-enc`) a file's bytes ride base64 INSIDE the signed payload,
so the signature covers the content and not merely its name.

Env (matches the DEVICE_NAME/GATEWAY_NAME/SERVER_API_BASE/BOOTSTRAP_SECRET pattern already used by
Device-PC/.env and Gateway-PC/.env — see p2p/.env.example):
  P2P_NODE_NAME     this node's registry name, e.g. PASH-Dev-4
  SERVER_API_BASE   e.g. http://10.30.0.10:18000 (direct) or the gateway-relayed base (routed)
  BOOTSTRAP_SECRET  same root-of-trust as every other box->server call (used only to fetch the cert)
  P2P_PORT          default 8443   (mutual-auth listener)
  P2P_HTTPS_PORT    default 8444   (server-auth-only listener; set empty to not run it at all)
  P2P_HTTP_PORT     default 8442   (plaintext, no-TLS listener; set empty to not run it at all)
  P2P_CACHE_DIR     default /var/lib/p2p/certs
"""
import base64
import http.server
import json
import os
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # p2p/ root, for `common`

from common import comm_log, errors, identity, wire  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))  # this dir, for `handlers`/`policy_client`
from handlers import events, fetch, file_delivery, message, ml, rm, status  # noqa: E402
from policy_client import check as policy_check  # noqa: E402

# Route -> USE CASE. One route per use case, served identically on every tech (2026-07-28) — the
# route says WHAT is being exchanged, the listener + envelope say HOW it was authenticated.
# `/rm-exec` (2026-07-28) is DEVICE→DEVICE remote management — a command another node sent, run
# here. Note the name: the Server's own `/p2p-rm-exec` is a different thing entirely (the SERVER
# SSHing into a node); this one has no SSH and no Server in the data path. See handlers/rm.py.
# `/ml-op` (2026-07-29) is the ML use case — one enumerated ML operation another node asked this
# one to perform on itself. See handlers/ml.py for why it is a use case rather than an `rm` call.
# `/fetch` (2026-09-29, on-dev-api P4.1) is the PULL use case — a peer reads one file back off this
# node, under P2P_FETCH_ROOTS only. See handlers/fetch.py for its node-local gates.
ROUTES = {"/message": "message", "/deliver": "file", "/status": "status", "/rm-exec": "rm",
          "/ml-op": "ml", "/fetch": "fetch"}

# The comm-log's legacy `type` vocabulary, kept in step with the sender's own (sender-role/
# client.py:legacy_type) so both halves of one exchange still file it identically.
LEGACY_TYPE = {"message": "message", "file": "deliver", "status": "status", "rm": "rm-exec",
               "ml": "ml-op", "fetch": "fetch"}


def legacy_type(use_case, tech):
    if tech == "coap-enc" and use_case == "message":
        return "message-coap"
    return LEGACY_TYPE.get(use_case, use_case)


# the techs whose sender is the TLS client certificate itself: the body is the raw request, not an envelope
CERT_IDENTIFIED = ("mtls", "pqc")

# the techs that are ML-KEM-768 + ML-DSA-65 end to end (2026-10-23; the sender's client.PQC_TECHS)
PQC_TECHS = ("pqc", "quic-pqc", "quic-pqc-mutual", "coap-pqc", "coap-dtls-pqc",
             "coap-dtls-pqc-mutual")

# stunnel section -> the loopback port its `connect =` names (override: P2P_BACKEND_PORT_<TECH>, empty = off)
FRONTED_BACKENDS = {"pqkex": 8452, "pqkex-mutual": 8453, "hybrid": 8454, "hybrid-mutual": 8455}

# 2026-10-23 (v2): the Server mirror POST (~150-165 ms on a Pi) used to run synchronously in the request thread,
# AFTER the reply was written but BEFORE the handler returned -- so the connection stayed open for it. A client
# that reads its reply until the connection closes (openssl s_client behind pqkex*/hybrid*) waited the whole
# mirror out: ~165 ms added to every pqkex/hybrid exchange. The POST now runs here, off the request thread; the
# facts that need the live connection are captured before it is handed over.
_MIRROR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="p2p-mirror")


class TLSHTTPServer(http.server.ThreadingHTTPServer):
    """Wraps each accepted connection in a TLS 1.3 context — see module docstring. A failed
    handshake (no cert / wrong CA on the mutual listener) raises inside `get_request()`;
    socketserver's own loop already catches `OSError` there (`ssl.SSLError` is one) and just skips
    that connection, so one rejected peer never takes the server down.

    `mutual` says which listener this is, and therefore where a request's identity comes from: the
    peer certificate (True) or a signed envelope in the body (False).

    ThreadingHTTPServer, not HTTPServer (2026-07-28): `daemon_threads = True` below was set from the
    start but did nothing, because the plain HTTPServer handles one connection at a time. That was
    survivable while every use case was a sub-second read or append — it stopped being survivable
    with `/rm-exec`, where one peer's command legitimately runs for seconds and would otherwise
    freeze this node's receiver, including its /health probe, for the duration."""

    daemon_threads = True

    # 2026-08-02: shared across BOTH listeners this process may run (mutual + https) -- they read
    # the same on-disk identity, so a refresh triggered by one must not race a refresh triggered
    # by the other. Rate-limited (module-level, not per-instance) so a burst of failed handshakes
    # from many peers at once can't hammer /p2p-cert.
    _refresh_lock = threading.Lock()
    _last_refresh_ts = 0.0

    def __init__(self, addr, handler_cls, ssl_context, own_name, pqc_ca_path=None, ca_path=None,
                 mutual=True, ctx_builder=None, tls=True, pqc=False):
        super().__init__(addr, handler_cls)
        self.ssl_context = ssl_context
        self.own_name = own_name
        self.pqc_ca_path = pqc_ca_path   # None => this node has no PQC identity; PQC mode 401s
        self.ca_path = ca_path           # the fleet CA, for verifying an `https` envelope's cert
        self.mutual = mutual
        # () -> fresh ssl.SSLContext, or None if this listener doesn't support self-healing
        # (kept optional rather than required so a caller that doesn't wire one up just keeps the
        # old crash-on-every-connection behavior, not a new failure mode).
        self.ctx_builder = ctx_builder
        # `http` (2026-09-26): a THIRD listener, no TLS at all — the plaintext tier's HTTP-family
        # member, same idea `coap`'s NoSec mode already is for UDP. `mutual=False` on this instance
        # too, so `_identify()` takes the SAME envelope-only path `https` already uses (it never
        # looks at `self.tls` — identity there comes from the body either way, and `https`'s
        # envelope check is transport-agnostic by construction). `tls` only governs get_request().
        self.tls = tls
        # `pqc` (2026-10-23): a listener whose handshake is ML-KEM-768 + ML-DSA-65 on both sides (identity.py
        # build_pqc_server_context). The sender IS its ML-DSA-65 client certificate's CN, as on mtls.
        self.pqc = pqc

    # 2026-08-07: found live — a client that completes the TCP handshake and then never sends a
    # TLS ClientHello (e.g. killed mid-connect, as a forcefully-timed-out mesh-verification run
    # does to whatever `incus exec`/ssh session it had in flight) wedged this receiver FOREVER.
    # wrap_socket() below is called from the single accept loop, BEFORE ThreadingHTTPServer hands
    # the connection to its own worker thread — a handshake that never completes blocks every
    # later connection from ever being accepted, not just the stuck one. A bounded timeout here
    # only bounds the HANDSHAKE; it is cleared before the request handler runs, so `/rm-exec`'s
    # multi-second commands (the reason this is Threading, not plain, HTTPServer) are unaffected.
    HANDSHAKE_TIMEOUT_S = 15

    def get_request(self):
        sock, addr = super().get_request()
        if not self.tls:
            return sock, addr             # `http`: no handshake to wrap, hand the raw socket back
        sock.settimeout(self.HANDSHAKE_TIMEOUT_S)
        try:
            tls_sock = self.ssl_context.wrap_socket(sock, server_side=True)
            tls_sock.settimeout(None)
            return tls_sock, addr
        except ssl.SSLCertVerificationError:
            # Same bug class as the sender-side fix (client.py's _refresh_identity): a cached CA
            # that can never verify a live peer again (e.g. the server's fleet CA was reissued)
            # would otherwise reject EVERY connection forever, requiring someone to notice and
            # restart this service by hand. THIS connection still fails -- socketserver's own
            # loop already treats an OSError from get_request() as "skip this one peer, keep
            # serving" -- but the NEXT attempt gets a fresh context if the refresh below succeeds.
            self._maybe_refresh()
            raise
        except OSError:
            # Handshake timed out (HANDSHAKE_TIMEOUT_S), was reset, or failed some other way that
            # isn't a CA mismatch. socketserver's own loop treats an OSError from get_request() as
            # "skip this one peer, keep serving" -- explicit close so a timed-out half-open socket
            # doesn't linger as an fd leak on top of the hang it already caused.
            sock.close()
            raise

    def _maybe_refresh(self):
        if self.ctx_builder is None:
            return
        now = time.monotonic()
        if now - TLSHTTPServer._last_refresh_ts < 30:
            return   # already refreshed recently (or another listener is mid-refresh) -- don't hammer /p2p-cert
        if not TLSHTTPServer._refresh_lock.acquire(blocking=False):
            return
        try:
            self.ssl_context = self.ctx_builder()
            TLSHTTPServer._last_refresh_ts = now
            print(f"[p2p-receiver] {self.own_name}: refreshed a stale TLS identity after a "
                  f"cert-verify failure", flush=True)
        except Exception as e:
            # Best-effort: leaves self.ssl_context exactly as it was (the OLD, still-loaded
            # context object is never touched or discarded here) -- a refresh that can't
            # complete degrades back to "reject connections until the next attempt", never to
            # "no identity at all". Contrast with the sender-side near-miss this mirrors: there,
            # the FIRST version of that fix deleted the working cache before confirming the
            # replacement worked; here, nothing is torn down until ctx_builder() has already
            # returned a working context.
            print(f"[p2p-receiver] {self.own_name}: TLS identity refresh failed, still using "
                  f"the old context: {e}", flush=True)
        finally:
            TLSHTTPServer._refresh_lock.release()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        # TCP_NODELAY (2026-09-30, found by the P2P timing work — func11 / API docs/50_timing.md):
        # every reply goes out as TWO sends (wire.write_json: headers, then body). On a TLS
        # connection Nagle holds the second until the first is ACKed, and the sender's delayed ACK
        # waits ~40 ms for it — a constant ~40 ms on EVERY mtls/https/pqc exchange (measured:
        # network_ms p50 41 ms -> 2 ms on localhost). The stunnel front doors in front of the plain
        # listener (pqkex*) already set TCP_NODELAY, so without this the classical techs looked
        # ~40 ms slower than PQC for a reason that has nothing to do with cryptography.
        super().setup()
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def log_message(self, fmt, *args):
        print(f"[p2p-receiver] {self.address_string()} - {fmt % args}", flush=True)

    def _sender_or_403(self):
        try:
            return identity.peer_identity(self.connection)
        except errors.IdentityError as e:
            wire.write_json(self, 401, {"ok": False, "reason": str(e)})
            return None

    def _sig_verify_or_401(self, envelope):
        """The `https` tech's identity check (2026-07-28): this listener's handshake authenticated
        only US, so the sender is whoever can produce a fresh RSA signature under a certificate that
        chains to the fleet CA and whose CN is the sender it claims to be.

        Deliberately the SAME four checks, in the same order, that coap_server.py runs — freshness
        first (a stale envelope is refused without spending effort on crypto), then chain, then
        CN-vs-claim, then the signature itself. -> (sender_cn, payload) or (None, None) after
        writing the error."""
        try:
            cert_pem = base64.b64decode(envelope["cert"]).decode()
            sig = base64.b64decode(envelope["sig"])
            payload = envelope["payload"]
            claimed = envelope["sender"]
            ts = envelope["ts"]
        except (KeyError, ValueError, TypeError):
            wire.write_json(self, 400, {"ok": False, "reason": "malformed signed envelope"})
            return None, None
        fresh_ok, fresh_reason = identity.check_freshness(ts)
        if not fresh_ok:
            wire.write_json(self, 401, {"ok": False, "reason": fresh_reason})
            return None, None
        if not identity.verify_chain(self.server.ca_path, cert_pem):
            wire.write_json(self, 401, {"ok": False, "reason": "cert does not chain to the CA"})
            return None, None
        cn = identity.leaf_cn(cert_pem)
        if cn != claimed:
            wire.write_json(self, 401, {"ok": False,
                            "reason": f"cert CN '{cn}' does not match claimed sender '{claimed}'"})
            return None, None
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        if not identity.verify_payload_signature(
                cert_pem, identity.signable_with_ts(payload_bytes, ts), sig):
            wire.write_json(self, 401, {"ok": False,
                            "reason": "signature does not verify against the cert"})
            return None, None
        return cn, payload

    def _authorized_or_403(self, sender_cn, use_case=None):
        server_api = os.environ["SERVER_API_BASE"]
        secret = os.environ["BOOTSTRAP_SECRET"]
        allowed, reason = policy_check(server_api, secret, sender_cn, self.server.own_name,
                                       use_case=use_case)
        if not allowed:
            wire.write_json(self, 403, {"ok": False, "allowed": False, "reason": reason})
        return allowed

    def _pqc_sig_verify_or_401(self, envelope):
        """The ML-DSA-65 envelope check (2026-10-23) for the PQC techs that are not mutual at THIS hop:
        `pqc` (its listener authenticates only us) and `quic-pqc*` (the relay terminates the QUIC session).
        The same four checks as `_sig_verify_or_401`, in the same order, against the PQC CA and with ML-DSA-65:
        freshness, chain, signature, CN == the claimed sender. An RSA envelope cannot pass. -> (cn, payload)."""
        if self.server.pqc_ca_path is None:
            wire.write_json(self, 401, {"ok": False, "reason": "this node has no PQC identity provisioned"})
            return None, None
        if not isinstance(envelope, dict):
            wire.write_json(self, 400, {"ok": False, "reason": "malformed PQC envelope"})
            return None, None
        claimed = envelope.get("sender")
        ok, payload = self._pqc_verify_or_401(claimed, envelope)
        return (claimed, payload) if ok else (None, None)

    def _pqc_verify_or_401(self, sender_cn, envelope):
        """The ML-DSA-65 envelope: freshness, chain to the PQC CA, ML-DSA-65 signature, and both the
        envelope's claimed sender and its PQC cert's CN == `sender_cn`. -> (ok, payload)."""
        if self.server.pqc_ca_path is None:
            wire.write_json(self, 401, {"ok": False, "reason": "this node has no PQC identity provisioned"})
            return False, None
        try:
            cert_pem = base64.b64decode(envelope["cert"]).decode()
            sig = base64.b64decode(envelope["sig"])
            payload = envelope["payload"]
            claimed = envelope["sender"]
            ts = envelope["ts"]
        except (KeyError, ValueError):
            wire.write_json(self, 400, {"ok": False, "reason": "malformed PQC envelope"})
            return False, None
        # 2026-07-26, replay protection: check freshness BEFORE spending effort on chain/signature
        # verification -- a stale envelope is rejected fast regardless of whether it's otherwise
        # well-formed (it might be a perfectly legitimately-signed envelope that's just too old).
        fresh_ok, fresh_reason = identity.check_freshness(ts)
        if not fresh_ok:
            wire.write_json(self, 401, {"ok": False, "reason": fresh_reason})
            return False, None
        if not identity.verify_chain_pqc(self.server.pqc_ca_path, cert_pem):
            wire.write_json(self, 401, {"ok": False, "reason": "PQC cert does not chain to the PQC CA"})
            return False, None
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        if not identity.verify_payload_signature_pqc(
                cert_pem, identity.signable_with_ts(payload_bytes, ts), sig):
            wire.write_json(self, 401, {"ok": False, "reason": "PQC signature verification failed"})
            return False, None
        pqc_cn = identity.leaf_cn_pqc(cert_pem)
        if pqc_cn != sender_cn or claimed != sender_cn:
            wire.write_json(self, 401, {"ok": False,
                            "reason": f"PQC identity mismatch: pqc_cert={pqc_cn} claimed={claimed} "
                                      f"expected={sender_cn}"})
            return False, None
        return True, payload

    # ── exchange correlation + byte accounting (2026-07-28, management/fix.md) ─────────────────
    # The operator asked the GUI to stop showing a raw Bytes column and instead fold "did the
    # delivered bytes match the attempted ones" into the OK column. Answering that needs two
    # things this side has and the log did not carry: the sender's exchange id (so the Server can
    # join the two halves of the mirror) and the framing length we were PROMISED, next to what we
    # actually read off the socket (so a truncated body is caught even with no counterpart report).
    def _xid(self):
        """The sender's exchange id, echoed back verbatim. Untrusted correlation only -- it names
        no identity and gates nothing; the mTLS peer cert is still the sole identity (§4.3)."""
        return self.headers.get("X-P2P-Exchange") or None

    def _content_length(self):
        try:
            return int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            return None

    def _read_body(self):
        """-> (raw_bytes, promised_length). Both are reported, so `len(raw) != promised` is visible
        as a byte-check failure rather than silently becoming a short read."""
        return wire.read_body(self), self._content_length()

    def _report(self, use_case, tech, peer, t0, ok, status_code=None, nbytes=0, payload=None,
               reason=None, expected=None):
        # Operator-directed (2026-07-26): mirror EVERY P2P receipt -- message, timing, outcome --
        # to the Server, best-effort. See comm_log.py's docstring for why this is a mirror only.
        # 2026-10-23 (v2): everything is read NOW (the live connection's TLS facts, the headers, the duration);
        # only the POST itself is handed to _MIRROR, so the handler returns and the connection closes at once.
        try:
            server_api = os.environ["SERVER_API_BASE"]
            secret = os.environ["BOOTSTRAP_SECRET"]
        except KeyError:
            return
        # `use_case` + `tech` are reported separately (2026-07-28, operator-directed) -- they are
        # separate questions, and `type` conflated them. `type` is still written, in its old
        # vocabulary, so nothing that reads it breaks.
        # `tls_*`: what THIS connection negotiated, read off the live socket -- the receiving half
        # of the same detail the sender reports, so the GUI's `tech` column can say
        # "TLSv1.3 · TLS_AES_256_GCM_SHA384 · OpenSSL 3.x" instead of a bare "mtls".
        fields = dict(reported_by="receiver", node=self.server.own_name, sender=peer,
                      receiver=self.server.own_name, use_case=use_case, tech=tech,
                      type=legacy_type(use_case, tech), pqc=(tech in PQC_TECHS), ok=ok,
                      status_code=status_code, duration_ms=round((time.time() - t0) * 1000, 2),
                      bytes=nbytes, bytes_expected=expected, exchange_id=self._xid(),
                      payload=payload or {}, reason=reason,
                      **{**identity.tls_info(self.connection), **self._relay_tls_facts()})
        _MIRROR.submit(comm_log.report, server_api, secret, **fields)

    # ── one dispatcher, every use case × every tech ──────────────────────────
    def do_POST(self):
        use_case = ROUTES.get(self.path)
        if use_case is None or use_case == "status":
            wire.write_json(self, 404, {"ok": False, "reason": f"no such route '{self.path}'"})
            return
        self._serve(use_case)

    def do_GET(self):
        if self.path == "/health":
            # The one open route: a liveness probe carries no data and answers nothing about the
            # node's tenants, so it is not gated (unchanged since §3.2).
            wire.write_json(self, 200, {"ok": True, "node": self.server.own_name,
                                        "mutual_tls": self.server.mutual})
            return
        if ROUTES.get(self.path) == "status":
            self._serve("status")
            return
        wire.write_json(self, 404, {"ok": False, "reason": f"no such route '{self.path}'"})

    def _identify(self, raw, promised):
        """Who is this, and under which tech? -> (tech, sender_cn, payload, file_bytes) or
        (None, ...) once an error has been written.

        THE identity rule, in one place for all five techs:
          mutual listener + no PQC header  -> `mtls`  : the TLS peer cert's CN, full stop
          mutual listener + X-P2P-PQC      -> `pqc`   : the peer cert's CN AND a matching ML-DSA-65
                                                        envelope — both, never either
          https listener                   -> `https` : the RSA-signed envelope alone (this
                                                        listener's handshake authenticated only us)
          http listener (2026-09-26)       -> `http`  : the SAME envelope check as https — this
                                                        listener has no handshake at all, so the
                                                        ONLY difference from https is which port
                                                        the request arrived on
        The tech is derived from the LISTENER and the envelope, never from the client's
        `X-P2P-Tech` header — that header is a display hint for the log, and trusting it for
        anything else would let a caller name its own security level. `https` vs `http` are BOTH
        non-mutual (mutual=False) and share this exact code path — `self.server.tls` is what tells
        them apart (True = this is the https listener, a real TLS session; False = the plain
        listener, no session at all) — it doesn't change the check itself, only the label reported."""
        if not self.server.mutual:
            try:
                envelope = json.loads(raw) if raw else {}
            except ValueError:
                wire.write_json(self, 400, {"ok": False, "reason": "body is not JSON"})
                return None, None, None, None
            tech = self._listener_tech()
            if tech in self.PQC_ENVELOPE_TECHS:
                # ML-KEM-768 + ML-DSA-65 transport (the pqc listener, or the quic-pqc relay): the sender's
                # proof must be ML-DSA-65 too -- an RSA envelope is refused here, not accepted as "pqc"
                cn, payload = self._pqc_sig_verify_or_401(envelope)
            else:
                cn, payload = self._sig_verify_or_401(envelope)
            if cn is None:
                return None, None, None, None
            return tech, cn, payload, self._file_bytes(payload)

        sender_cn = self._sender_or_403()
        if sender_cn is None:
            return None, None, None, None
        if self.headers.get("X-P2P-PQC") == "1" and not getattr(self.server, "pqc", False):
            # the retired 2026-07-26 `pqc` (classical mTLS + an ML-DSA envelope): not PQC by the owner's rule,
            # refused with the reason instead of being written as a file / run as an mtls request
            wire.write_json(self, 400, {"ok": False, "reason": "`pqc` is ML-KEM-768 + ML-DSA-65 TLS now "
                                        "(:P2P_PQC_PORT); the X-P2P-PQC envelope on "
                                        "the mtls port is retired"})
            return None, None, None, None
        if getattr(self.server, "pqc", False):
            # the PQC CA verified this ML-DSA-65 client certificate inside an ML-KEM-768-only handshake;
            # assert the group anyway (fail closed if the pin ever did not apply)
            group = identity.negotiated_group(self.connection)
            if group != identity.PQC_TLS_GROUP:
                wire.write_json(self, 401, {"ok": False, "reason": f"negotiated {group!r}, not ML-KEM-768"})
                return None, None, None, None
            return "pqc", sender_cn, None, None
        return "mtls", sender_cn, None, None

    # the techs whose sender proof on a non-mutual listener is the ML-DSA-65 envelope (_pqc_sig_verify_or_401)
    PQC_ENVELOPE_TECHS = ("quic-pqc", "quic-pqc-mutual")

    def _listener_tech(self):
        """The tech this listener serves, from how the request ARRIVED (never from the client's headers): the
        listener itself, or -- on the plain listener -- the local stunnel / QUIC relay that fronts it."""
        if self.server.mutual:
            return "pqc" if getattr(self.server, "pqc", False) else "mtls"
        if self.server.tls:
            return "https"
        return getattr(self.server, "fronted_tech", None) or self._relay_fronted_tech() or "http"

    # The techs a local relay (quic_pqc_relay.py) fronts this plain listener for. Label only: the
    # identity check is the same signed envelope whatever the label (see _identify).
    RELAY_FRONTED_TECHS = ("quic-pqc", "quic-pqc-mutual", "quic-hybrid", "quic-hybrid-mutual",
                           "quic-classical", "quic-classical-mutual")

    def _relay_tls_facts(self):
        """The TLS facts a local relay observed on ITS handshake (X-P2P-Relay-Tls, JSON), for the receiver's
        log row -- same trust rule as `_relay_fronted_tech` (loopback peer + a relay-fronted tech only), and only
        the tls_* keys the Server accepts plus `group` are taken. {} for anything else."""
        if self._relay_fronted_tech() is None:
            return {}
        try:
            raw = json.loads(self.headers.get("X-P2P-Relay-Tls") or "{}")
        except ValueError:
            return {}
        if not isinstance(raw, dict):
            return {}
        keep = ("tls_version", "tls_cipher", "tls_bits", "tls_lib", "tls_ca", "tls_peer_key", "tls_peer_sig", "group")
        return {k: raw[k] for k in keep if k in raw and isinstance(raw[k], (str, int))}

    def _relay_fronted_tech(self):
        """The tech a local relay says carried this request, or None. Honoured ONLY when the TCP peer is
        this host's loopback (the relay itself) and the value is one of RELAY_FRONTED_TECHS: the plain
        listener is reachable from the network, so the header from any other peer is ignored and the
        request stays `http`. A hint for the log -- it never changes how the sender is identified."""
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            return None
        val = self.headers.get("X-P2P-Relay-Tech")
        return val if val in self.RELAY_FRONTED_TECHS else None

    @staticmethod
    def _file_bytes(payload):
        """A file's content as carried by the envelope techs — base64 INSIDE the signed payload, so
        the signature covers the bytes themselves. None when the payload carries no file."""
        blob = (payload or {}).get("data_b64")
        return base64.b64decode(blob) if blob else None

    def _serve(self, use_case):
        """Authenticate, authorize, run the use case, mirror the result. Identical for all four
        techs — which is the point: the tech decides how the sender proved who it is, and nothing
        else about what happens next."""
        t0 = time.time()
        raw, promised = self._read_body()
        p1 = time.perf_counter()
        tech, sender_cn, payload, file_bytes = self._identify(raw, promised)
        p2 = time.perf_counter()
        if tech is None:
            # _identify already answered the client; still mirror the refusal, since "who was
            # turned away" is exactly what an operator looks for in this log. The tech is the one
            # THIS listener serves (2026-10-23 v2: it used to be the client's own X-P2P-Tech header,
            # so a refused request was filed under whatever tech it claimed to be).
            self._report(use_case, self._listener_tech(),
                        self.headers.get("X-P2P-Sender") or "?", t0, ok=False, status_code=401,
                        nbytes=len(raw), expected=promised, reason="identity verification failed")
            return
        if not self._authorized_or_403(sender_cn, use_case):
            self._report(use_case, tech, sender_cn, t0, ok=False, status_code=403,
                        nbytes=len(raw), expected=promised, reason="policy denied")
            return
        p3 = time.perf_counter()
        try:
            result, nbytes, reported = self._run(use_case, tech, sender_cn, raw, payload, file_bytes)
        except Exception as e:                            # noqa: BLE001 - a handler fault is a 500
            wire.write_json(self, 500, {"ok": False, "reason": str(e)})
            self._report(use_case, tech, sender_cn, t0, ok=False, status_code=500,
                        nbytes=len(raw), expected=promised, reason=str(e))
            return
        p4 = time.perf_counter()
        reply = result
        if isinstance(result, dict):
            # 2026-09-30, benchmarking (func11-benchmarking-readiness.md): the receiver's own share
            # of the exchange, on ITS monotonic clock, so the sender can subtract it from what it
            # waited and get the network time without any clock sync. `total_ms` is the receiver's own
            # work after the body arrived: verify the sender + ask the policy + run the use case. The
            # sender pops this key off the reply into its `timing` block.
            # 2026-10-23 (v2): `receive_body_ms` (the body arriving) and the constant `clock` string are
            # retired: the former overlapped the transfer, was already inside the sender's network_ms
            # and, behind a local relay, timed only the relay's loopback copy.
            # A COPY: for `status` the same dict is also the mirror's payload, which must not grow.
            reply = {**result, "receiver_timing": {
                "verify_ms": round((p2 - p1) * 1000, 3),
                "authorize_ms": round((p3 - p2) * 1000, 3),
                "handler_ms": round((p4 - p3) * 1000, 3),
                "total_ms": round((p4 - p1) * 1000, 3)}}
        wire.write_json(self, 200, reply)
        # on-dev-api P9.7: feed the node-local `on_p2p` hook spool. Only reached AFTER identity +
        # policy passed and the use case ran; emit() swallows its own errors.
        events.emit(use_case, sender_cn, tech, reported, nbytes)
        # `expected` (the framing length) is only comparable with `nbytes` when the body IS the
        # content — on the envelope techs the body is bigger than the file it carries, so passing it
        # would report a permanent, meaningless mismatch. The sender/receiver join in
        # p2p_comm_log.annotate_bytes still answers "delivered == attempted" on every tech.
        expected = promised if tech in CERT_IDENTIFIED else None
        self._report(use_case, tech, sender_cn, t0, ok=True, status_code=200, nbytes=nbytes,
                    expected=expected, payload=reported)

    def _run(self, use_case, tech, sender_cn, raw, payload, file_bytes):
        """The use case itself -> (response, bytes_counted, payload_for_the_log). The three handlers
        are shared by every tech; only how the arguments were extracted differed."""
        if use_case == "file":
            if tech in CERT_IDENTIFIED:
                dest = (self.headers.get("X-P2P-Dest-Path")
                        or self.headers.get("X-P2P-Filename") or "delivered.bin")
                data = raw
                # put_file meta (2026-09-26): mtls sends the file as the raw body, so the meta
                # rides a header -- covered by the mTLS session, as the dest path already is.
                hdr = self.headers.get("X-P2P-Put-File")
                put = json.loads(hdr) if hdr else None
            else:
                dest = (payload or {}).get("dest_filename") or "delivered.bin"
                data = file_bytes or b""
                put = (payload or {}).get("put_file")
            result = file_delivery.handle(sender_cn, dest, data, put=put)
            return result, len(data), {"dest_filename": dest, "sha256": result.get("sha256"),
                                       **({"job_id": result.get("job_id"),
                                           "status": result.get("status")} if put else {})}
        if use_case == "status":
            result = status.handle(sender_cn)
            if tech not in CERT_IDENTIFIED:
                result[f"{tech}_verified"] = True
            reported = dict(result)              # the mirror row never carries the details block
            want = (self.headers.get("X-P2P-Details") == "1" if tech in CERT_IDENTIFIED
                    else bool((payload or {}).get("details")))
            if want:
                result["details"] = status.details()
            return result, len(raw), reported
        if use_case == "rm":
            body = payload if tech not in CERT_IDENTIFIED else (json.loads(raw) if raw else {})
            result = rm.handle(sender_cn, body, tech=tech)
            if tech not in CERT_IDENTIFIED:
                result[f"{tech}_verified"] = True
            # The mirror gets WHAT was asked and HOW it ended — never the command's output. The
            # comm log is a dashboard (and it round-trips into ThingsBoard telemetry); a peer's
            # stdout is arbitrary size and arbitrary content, and it already lives in the reply the
            # sender got and in this node's own /var/lib/p2p/rm.log.
            return result, len(raw), {"cmd": body.get("cmd"), "rc": result.get("rc"),
                                      "refused": result.get("refused"),
                                      "timed_out": result.get("timed_out")}
        if use_case == "ml":
            body = payload if tech not in CERT_IDENTIFIED else (json.loads(raw) if raw else {})
            result = ml.handle(sender_cn, body, tech=tech)
            if tech not in CERT_IDENTIFIED:
                result[f"{tech}_verified"] = True
            # The mirror gets WHICH ML operation and how it ended — never the operation's result.
            # A `get_model` answer is a whole manifest and a `run_model` answer carries inference
            # output; both already live in the reply the sender got and in the node's own ML/TB
            # records. Same rule `rm` follows for a command's stdout.
            return result, len(raw), {"method": body.get("method"), "ok": result.get("ok"),
                                      "refused": result.get("refused"),
                                      "timed_out": result.get("timed_out")}
        if use_case == "fetch":
            body = payload if tech not in CERT_IDENTIFIED else (json.loads(raw) if raw else {})
            result = fetch.handle(sender_cn, body, tech=tech)
            if tech not in CERT_IDENTIFIED:
                result[f"{tech}_verified"] = True
            # The mirror gets WHICH file and its digest — never the bytes (same rule as `file`).
            return result, result.get("bytes") or 0, {"path": body.get("path"),
                                                      "sha256": result.get("sha256"),
                                                      "refused": result.get("refused")}
        body = payload if tech not in CERT_IDENTIFIED else (json.loads(raw) if raw else {})
        result = message.handle(sender_cn, body, tech=tech)
        if tech not in CERT_IDENTIFIED:
            result[f"{tech}_verified"] = True
        return result, len(raw), body


def _make_ctx_refresher(server_api, secret, name, cache_dir, https):
    """-> a zero-arg callable that re-fetches this node's identity and returns a freshly-built
    ssl.SSLContext, WITHOUT ever touching the on-disk cache until the fetch has already
    succeeded. Same "fetch into scratch, swap on success" shape as client.py's
    Client._refresh_identity, for the same reason: an earlier version of that sender-side fix
    deleted the working cache before confirming the replacement worked, and a legitimate 401 (a
    non-revoked cert already on file demands proof of possession, not just the bootstrap secret)
    left the node with no identity at all -- strictly worse than the stale cache it started with.
    Mirrored here so the receiver can't repeat that mistake."""
    def _refresh():
        tmp_dir = tempfile.mkdtemp(prefix=".refresh-", dir=os.path.dirname(cache_dir.rstrip("/")) or None)
        try:
            cert_path, key_path, ca_path = identity.fetch_own_cert(server_api, secret, name, tmp_dir)
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        shutil.rmtree(cache_dir, ignore_errors=True)
        shutil.move(tmp_dir, cache_dir)
        cert_path = os.path.join(cache_dir, os.path.basename(cert_path))
        key_path = os.path.join(cache_dir, os.path.basename(key_path))
        ca_path = os.path.join(cache_dir, os.path.basename(ca_path))
        if https:
            return identity.build_https_server_context(cert_path, key_path)
        return identity.build_server_context(cert_path, key_path, ca_path)
    return _refresh


def main():
    name = os.environ["P2P_NODE_NAME"]
    server_api = os.environ["SERVER_API_BASE"]
    secret = os.environ["BOOTSTRAP_SECRET"]
    port = int(os.environ.get("P2P_PORT", "8443"))
    cache_dir = os.environ.get("P2P_CACHE_DIR", "/var/lib/p2p/certs")

    cert_path, key_path, ca_path = identity.fetch_own_cert(server_api, secret, name, cache_dir)
    ctx = identity.build_server_context(cert_path, key_path, ca_path)

    # PQC (2026-07-26, operator-directed): best-effort -- most nodes won't have a PQC identity
    # provisioned, and that's fine (PQC-mode senders just get a clear 401, not a crash here).
    pqc_ca_path = None
    try:
        _pqc_cert, _pqc_key, pqc_ca_path = identity.load_pqc_material(
            os.environ.get("P2P_PQC_CACHE_DIR"))
    except errors.IdentityError:
        pass

    httpd = TLSHTTPServer(("0.0.0.0", port), Handler, ctx, name, pqc_ca_path=pqc_ca_path,
                          ca_path=ca_path, mutual=True,
                          ctx_builder=_make_ctx_refresher(server_api, secret, name, cache_dir, https=False))
    pqc_note = f", PQC identity loaded from {pqc_ca_path}" if pqc_ca_path else ", no PQC identity"
    print(f"[p2p-receiver] {name} listening on :{port} (TLS 1.3 mTLS, cert cached at {cache_dir}{pqc_note})",
          flush=True)

    # The `https` tech's listener (2026-07-28): server-authenticated only, identity from a signed
    # envelope. Same process, own thread -- one more listener does not justify a second service
    # unit, and both share the certs already fetched above. `P2P_HTTPS_PORT=` (empty) turns it off
    # entirely, which is the way to run a node that should only ever accept mutual-auth peers.
    https_port = os.environ.get("P2P_HTTPS_PORT", "8444").strip()
    if https_port:
        https_ctx = identity.build_https_server_context(cert_path, key_path)
        httpsd = TLSHTTPServer(("0.0.0.0", int(https_port)), Handler, https_ctx, name,
                               pqc_ca_path=pqc_ca_path, ca_path=ca_path, mutual=False,
                               ctx_builder=_make_ctx_refresher(server_api, secret, name, cache_dir, https=True))
        threading.Thread(target=httpsd.serve_forever, daemon=True).start()
        print(f"[p2p-receiver] {name} listening on :{https_port} "
              f"(TLS 1.3 server-auth only -- `https` tech, identity = signed envelope)", flush=True)
    else:
        print(f"[p2p-receiver] {name} `https` tech disabled (P2P_HTTPS_PORT empty)", flush=True)

    # The `http` tech's listener (2026-09-26, benchmark doc's plaintext tier for HTTP): NO TLS
    # context at all (tls=False; get_request() hands back the raw socket unwrapped) -- there is
    # nothing to refresh, so ctx_builder is None here unlike the other two listeners. Identity is
    # still the SAME signed envelope `https` uses (mutual=False routes here too; see _identify's
    # `self.server.tls` branch for how the two are told apart). `P2P_HTTP_PORT=` (empty) disables
    # it, same convention as https.
    http_port = os.environ.get("P2P_HTTP_PORT", "8442").strip()
    if http_port:
        httpd_plain = TLSHTTPServer(("0.0.0.0", int(http_port)), Handler, None, name,
                                    pqc_ca_path=pqc_ca_path, ca_path=ca_path, mutual=False,
                                    tls=False)
        threading.Thread(target=httpd_plain.serve_forever, daemon=True).start()
        print(f"[p2p-receiver] {name} listening on :{http_port} "
              f"(plaintext, NO TLS -- `http` tech, identity = signed envelope)", flush=True)
    else:
        print(f"[p2p-receiver] {name} `http` tech disabled (P2P_HTTP_PORT empty)", flush=True)

    # `pqc` (2026-10-23, owner: "PQC means ML-KEM-768 + ML-DSA-65, not an envelope"): mtls with every algorithm
    # post-quantum -- TLS 1.3, ML-KEM-768 key exchange ONLY, this node's ML-DSA-65 certificate, and an ML-DSA-65
    # client certificate from the PQC CA REQUIRED by the handshake (its CN is the sender). Python's own ssl on the
    # system OpenSSL 3.5. A box with no PQC identity, or whose OpenSSL cannot pin the group, does not run it.
    pq_port = os.environ.get("P2P_PQC_PORT", "8446").strip()
    if pq_port and pqc_ca_path is not None:
        try:
            pq_cert, pq_key, _pq_ca = identity.load_pqc_material(os.environ.get("P2P_PQC_CACHE_DIR"))
            pq_ctx = identity.build_pqc_server_context(pq_cert, pq_key, pqc_ca_path, mutual=True)
            pqd = TLSHTTPServer(("0.0.0.0", int(pq_port)), Handler, pq_ctx, name, pqc_ca_path=pqc_ca_path,
                                ca_path=ca_path, mutual=True, pqc=True)
            threading.Thread(target=pqd.serve_forever, daemon=True).start()
            print(f"[p2p-receiver] {name} listening on :{pq_port} (TLS 1.3, ML-KEM-768 + ML-DSA-65 both sides -- `pqc`)",
                  flush=True)
        except (OSError, errors.IdentityError, ssl.SSLError) as e:
            print(f"[p2p-receiver] {name} cannot serve `pqc` on :{pq_port}: {e}", flush=True)
    else:
        print(f"[p2p-receiver] {name} `pqc` tech disabled ({'no PQC identity' if pqc_ca_path is None else 'P2P_PQC_PORT empty'})",
              flush=True)

    # 2026-10-23 audit: pqkex / pqkex-mutual / hybrid / hybrid-mutual are terminated by a local stunnel that
    # forwards to the plaintext listener above, so every delivery over them was logged as `http` (the plaintext
    # tech). stunnel cannot add a header, so each of its four sections now forwards to ITS OWN loopback-only
    # listener here (PQC-bench/p2p-proxy/p2p-pqc-proxy.conf `connect =`), and the listener names the tech.
    # Bound to 127.0.0.1 only: nothing but the local stunnel can reach these ports, so the label cannot be
    # claimed by a network peer. The check applied to the request is the same signed-envelope check as `http`.
    for fronted, default_port in FRONTED_BACKENDS.items():
        port = os.environ.get("P2P_BACKEND_PORT_" + fronted.upper().replace("-", "_"), str(default_port)).strip()
        if not port:
            continue
        try:
            srv = TLSHTTPServer(("127.0.0.1", int(port)), Handler, None, name, pqc_ca_path=pqc_ca_path,
                                ca_path=ca_path, mutual=False, tls=False)
        except OSError as e:                      # a node without the proxy simply has no use for it
            print(f"[p2p-receiver] {name} cannot bind 127.0.0.1:{port} for `{fronted}` ({e})", flush=True)
            continue
        srv.fronted_tech = fronted
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"[p2p-receiver] {name} listening on 127.0.0.1:{port} (stunnel -> `{fronted}`)", flush=True)

    httpd.serve_forever()


if __name__ == "__main__":
    main()
