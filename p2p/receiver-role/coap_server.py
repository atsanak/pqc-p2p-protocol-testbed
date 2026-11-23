#!/usr/bin/env python3
"""p2p/receiver-role/coap_server — the CoAP transport (p2p-plan..md §3.2's second transport,
Stage D). Same identity + policy check as the HTTP transport (server.py), different codec: plain
CoAP over UDP (RFC 7252), via `aiocoap`. The constrained/datagram case per the requirement (a
sensor value / actuator state).

2026-07-28, operator-directed ("a use case is different than a tech"): this transport now serves
ALL FOUR use cases — /message, /deliver, /status and /rm-exec (device→device remote management) —
not just messages. `coap-enc` is a tech, and
a tech does not get to decide which use cases exist. A file's bytes ride base64 inside the encrypted,
signed payload, so both the signature and the encryption cover the content; aiocoap does block-wise
transfer when that exceeds one datagram, though the HTTP techs remain the sane choice for a large
file.

Identity: a cert + signature carried IN the CoAP payload (see common/identity.py's
sign_payload/verify_payload_signature) — aiocoap's CoAP-over-TLS support is explicitly early-WIP
upstream (its own docstring says so), so there's no literal handshake-level peer cert to read here.
Same situation network-fix's tile J already solved for plain HTTP
(api_server.py::_check_announcer_identity) — reused, not invented fresh.
"""
import asyncio
import base64
import functools
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # p2p/ root, for `common`
from common import comm_log, coap_crypto, errors, identity  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))  # this dir, for `handlers`/`policy_client`
from handlers import events, fetch, file_delivery, message, ml, rm, status  # noqa: E402

# CoAP resource path -> USE CASE, and the comm-log's legacy `type` vocabulary (kept identical to
# the HTTP transport's, so both halves of one exchange file it the same way).
RESOURCES = {"message": "message", "deliver": "file", "status": "status", "rm-exec": "rm",
             "ml-op": "ml", "fetch": "fetch"}
LEGACY_TYPE = {"message": "message-coap", "file": "deliver", "status": "status", "rm": "rm-exec",
               "ml": "ml-op", "fetch": "fetch"}


def legacy_type(use_case):
    return LEGACY_TYPE.get(use_case, use_case)

from policy_client import check as policy_check  # noqa: E402

import aiocoap  # noqa: E402
import aiocoap.resource as resource  # noqa: E402


# A private ELECTIVE CoAP option (65008: in the experimental range, even number = elective, so any
# receiver that does not know it ignores it) in which coap_dtls_pqc_relay.py names the DTLS tech it
# terminated for. The plain listener cannot otherwise tell a DTLS delivery from a cleartext `coap` one
# and used to log all four coap-dtls* techs as `coap`.
RELAY_TECH_OPTION = 65008
RELAY_TLS_OPTION = 65010           # coap_dtls_pqc_relay.py: JSON of what its DTLS session observed
RELAY_FRONTED_TECHS = ("coap-dtls", "coap-dtls-mutual", "coap-dtls-pqc", "coap-dtls-pqc-mutual")
# 2026-10-23 (owner: "PQC always means ML-KEM-768 and ML-DSA-65"): on these the sender's envelope must be
# ML-DSA-65-signed under the PQC CA, and this receiver signs its reply with its own ML-DSA-65 key.
PQC_TECHS = ("coap-pqc", "coap-dtls-pqc", "coap-dtls-pqc-mutual")
_LOOPBACK = ("127.0.0.1", "::1", "::ffff:127.0.0.1")


def relay_fronted_tech(request):
    """The DTLS tech a local relay says carried this request, or None. Honoured ONLY when the datagram
    came from this host's loopback (the relay) and the value is a known relay-fronted tech: the plain
    CoAP port is reachable from the network, so the same option from any other peer is ignored. A hint
    for the log -- it never changes how the sender is identified (the signed envelope does that)."""
    sockaddr = getattr(request.remote, "sockaddr", None)
    if not sockaddr or sockaddr[0] not in _LOOPBACK:
        return None
    for opt in request.opt.get_option(RELAY_TECH_OPTION):
        try:
            val = bytes(opt.value).decode()
        except (AttributeError, UnicodeDecodeError):
            continue
        if val in RELAY_FRONTED_TECHS:
            return val
    return None


def relay_tls_facts(request):
    """The DTLS facts the local relay observed (option 65010), for this node's own log row -- same trust rule as
    relay_fronted_tech: loopback peer and a relay-fronted tech only; only known keys of scalar type are taken."""
    if relay_fronted_tech(request) is None:
        return {}
    for opt in request.opt.get_option(RELAY_TLS_OPTION):
        try:
            raw = json.loads(bytes(opt.value).decode())
        except (AttributeError, UnicodeDecodeError, ValueError):
            continue
        if isinstance(raw, dict):
            keep = ("tls_version", "tls_cipher", "tls_bits", "tls_lib", "tls_ca", "tls_peer_key", "tls_peer_sig", "group")
            return {k: raw[k] for k in keep if k in raw and isinstance(raw[k], (str, int))}
    return {}


class P2pResource(resource.Resource):
    """One CoAP resource per USE CASE (2026-07-28, operator-directed: "a use case can be sent with
    each tech, and not only with a specific one"). Before this the CoAP transport carried messages
    and nothing else, which made `coap-enc` a use case rather than a tech. The envelope, the four
    identity checks, the policy check and the encryption are identical for all three — only
    `use_case` changes what gets run once the sender has been established."""

    def __init__(self, use_case, own_name, ca_path, server_api, secret, own_key_path,
                own_cert_path=None, own_kem_key_path=None, pqc_material=None):
        super().__init__()
        self.use_case = use_case
        self.own_name = own_name
        self.ca_path = ca_path
        self.server_api = server_api
        self.secret = secret
        self.own_key_path = own_key_path   # 2026-07-26: to decrypt an incoming encrypted payload
        self.own_cert_path = own_cert_path  # §3.8.2 phase 1 (2026-08-21): to sign every response
        # PQC coap-enc (2026-09-27): this node's own ML-KEM-768 private key, to decapsulate an
        # `encrypted_pqc` payload -- a SEPARATE file from `own_key_path` (the classical/mTLS key),
        # see coap_crypto.py's own header comment for why the two algorithms can't share one file.
        # None on a box with no OpenSSL 3.5+ build provisioned -- that box simply cannot receive
        # `coap-pqc`, exactly like `own_key_path is None` would mean no `coap-enc` today.
        self.own_kem_key_path = own_kem_key_path
        # (cert, key, ca) of this node's ML-DSA-65 identity (/var/lib/p2p/certs-pqc), or None: the PQC techs'
        # envelopes are verified against that CA and their replies signed with that key (2026-10-23).
        self.pqc_material = pqc_material

    def _sign_response(self, xid, body, pqc=False):
        """§3.8.2 phase 1: mirror the check this box already runs on what it RECEIVES, onto what
        it RETURNS -- every response, including a refusal (a signed FORBIDDEN is still proof this
        box, not an impostor holding the /32, answered "no"). Mutates `body` in place with
        `resp_cert`/`resp_sig`/`resp_ts` and the echoed `xid`, then returns it.

        `xid` inside the signed bytes (not just alongside them) is load-bearing, not decorative:
        without it, a valid response captured from the real receiver could be replayed against a
        DIFFERENT request within the 60s freshness window and still verify -- see this function's
        own design note in monitor.md §3.8.2. `xid` may be `""` on the malformed-envelope path
        (parsing failed before an xid could even be read) -- signing the empty string in its place
        is correct, not a degrade: it still proves THIS box's key produced this exact refusal.

        Never raises: an unwritable/unreadable identity must not turn a real answer into a 500 --
        `resp_cert`/`resp_sig` are simply absent if signing itself fails, and the sender's own
        observe-mode verification (phase 2) already treats an absent signature as unsigned, not
        as an error."""
        if pqc:         # a PQC tech's reply: ML-DSA-65, this node's PQC leaf (the sender requires it)
            if not self.pqc_material:
                return body
            cert_path, key_path = self.pqc_material[0], self.pqc_material[1]
        elif not self.own_cert_path or not self.own_key_path:
            return body
        else:
            cert_path, key_path = self.own_cert_path, self.own_key_path
        try:
            resp_ts = int(time.time())
            signed_over = f"{xid or ''}|".encode() + json.dumps(body, sort_keys=True).encode()
            signable = identity.signable_with_ts(signed_over, resp_ts)
            sig = (identity.sign_payload_pqc(key_path, signable) if pqc
                   else identity.sign_payload(key_path, signable))
            body["resp_cert"] = base64.b64encode(Path(cert_path).read_bytes()).decode()
            body["resp_sig"] = base64.b64encode(sig).decode()
            body["resp_ts"] = resp_ts
            body["xid"] = xid or ""
        except Exception:                                     # noqa: BLE001 -- a signing failure
            pass                                               # must not turn a real answer into a 500
        return body

    def _report(self, peer, t0, ok, status_code=None, nbytes=0, payload=None, reason=None,
               exchange_id=None, tech="coap-enc", tls=None, t_end=None):
        # Operator-directed (2026-07-26): mirror EVERY P2P receipt (CoAP transport too) -- message,
        # timing, outcome -- to the Server, best-effort. See comm_log.py's docstring.
        # `exchange_id` (2026-07-28): the sender's `xid` echoed back, so the Server can join this
        # receipt against the sender's own report of the same exchange and answer "delivered ==
        # attempted" -- see p2p_comm_log.annotate_bytes. Correlation only, no authority: identity
        # here is still the signed cert in the envelope.
        # `use_case` + `tech` reported separately (2026-07-28); `type` keeps its old vocabulary
        # ("message-coap" and friends) so nothing that reads it breaks.
        comm_log.report(self.server_api, self.secret,
                        reported_by="receiver", node=self.own_name, sender=peer,
                        receiver=self.own_name, use_case=self.use_case, tech=tech,
                        type=legacy_type(self.use_case), pqc=(tech in PQC_TECHS), ok=ok, status_code=status_code,
                        duration_ms=round(((t_end or time.time()) - t0) * 1000, 2), bytes=nbytes,
                        exchange_id=exchange_id, payload=payload or {}, reason=reason, **(tls or {}))

    async def render_post(self, request):
        t0 = time.time()
        p0 = time.perf_counter()      # receiver_timing (2026-09-30), see the end of this method
        try:
            envelope = json.loads(request.payload)
            sender_cn = envelope["sender"]
            cert_pem = base64.b64decode(envelope["cert"]).decode()
            sig = base64.b64decode(envelope["sig"])
            # 2026-08-10: three envelope shapes on this transport (a third added 2026-09-27).
            # `coap-enc` carries `encrypted` (RSA-OAEP-wrapped, hybrid-encrypted payload, signature
            # over the CIPHERTEXT); `coap-pqc` carries `encrypted_pqc` (ML-KEM-768-encapsulated,
            # same AES-GCM/signature shape otherwise -- see coap_crypto.py); `coap` carries a
            # cleartext `payload` and signs those bytes instead -- the same thing the `https` tech
            # signs. The tech is derived from WHICH KEY IS PRESENT, never from a client-supplied
            # label: a sender cannot downgrade itself to a weaker check by claiming a tech, it can
            # only send one shape or another, and each is verified on its own terms.
            encrypted = envelope.get("encrypted")
            encrypted_pqc = envelope.get("encrypted_pqc")
            clear_payload = envelope.get("payload")
            if sum(x is not None for x in (encrypted, encrypted_pqc, clear_payload)) != 1:
                raise ValueError(
                    "envelope must carry exactly one of 'encrypted', 'encrypted_pqc', or 'payload'")
            tech = ("coap-enc" if encrypted is not None
                   else "coap-pqc" if encrypted_pqc is not None else "coap")
            if tech == "coap":          # a cleartext envelope: plain CoAP, or one a DTLS relay unwrapped
                tech = relay_fronted_tech(request) or tech
            ts = envelope["ts"]
            xid = envelope.get("xid")     # correlation only (2026-07-28); absent on older senders
        except Exception as e:                        # noqa: BLE001
            body = self._sign_response("", {"ok": False, "reason": f"malformed envelope: {e}"})
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=json.dumps(body).encode())

        # 2026-07-26, replay protection: check freshness first, fail fast regardless of whether
        # the envelope is otherwise well-formed (a stale envelope might be perfectly legitimately
        # signed, just too old -- captured off the wire or replayed from the comm-log mirror).
        fresh_ok, fresh_reason = identity.check_freshness(ts)
        if not fresh_ok:
            self._report(sender_cn, t0, ok=False, status_code=401, reason=fresh_reason, exchange_id=xid, tech=tech)
            body = self._sign_response(xid, {"ok": False, "reason": fresh_reason}, pqc=tech in PQC_TECHS)
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED, payload=json.dumps(body).encode())

        # 2026-07-26: sig covers the CIPHERTEXT (what's actually on the wire), not the plaintext --
        # verified BEFORE decrypting, so a tampered/forged ciphertext is rejected without ever
        # spending effort decrypting it (fail fast on identity, same order as every other transport).
        signed_over = (encrypted["ciphertext"].encode() if encrypted is not None
                       else encrypted_pqc["ciphertext"].encode() if encrypted_pqc is not None
                       else json.dumps(clear_payload, sort_keys=True).encode())
        pqc = tech in PQC_TECHS
        if pqc and not self.pqc_material:
            reason = "this node has no PQC (ML-DSA-65) identity provisioned"
            self._report(sender_cn, t0, ok=False, status_code=401, reason=reason, exchange_id=xid, tech=tech)
            body = self._sign_response(xid, {"ok": False, "reason": reason})
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED, payload=json.dumps(body).encode())
        # the PQC techs: the cert must chain to the PQC CA and the signature be ML-DSA-65 -- an RSA-signed
        # envelope cannot pass as coap-pqc / coap-dtls-pqc* (it chains to the wrong CA and fails ML-DSA)
        chain_ok = (identity.verify_chain_pqc(self.pqc_material[2], cert_pem) if pqc
                    else identity.verify_chain(self.ca_path, cert_pem))
        if not chain_ok:
            why = "cert does not chain to the PQC CA" if pqc else "cert does not chain to the CA"
            self._report(sender_cn, t0, ok=False, status_code=401, reason=why, exchange_id=xid, tech=tech)
            body = self._sign_response(xid, {"ok": False, "reason": why}, pqc=pqc)
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED, payload=json.dumps(body).encode())
        cn = identity.leaf_cn_pqc(cert_pem) if pqc else identity.leaf_cn(cert_pem)
        if cn != sender_cn:
            self._report(sender_cn, t0, ok=False, status_code=401,
                        reason=f"cert CN '{cn}' does not match claimed sender '{sender_cn}'",
                        exchange_id=xid, tech=tech)
            body = self._sign_response(xid, {"ok": False,
                                             "reason": f"cert CN '{cn}' does not match claimed sender '{sender_cn}'"},
                                       pqc=pqc)
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED, payload=json.dumps(body).encode())
        verify = identity.verify_payload_signature_pqc if pqc else identity.verify_payload_signature
        if not verify(cert_pem, identity.signable_with_ts(signed_over, ts), sig):
            self._report(sender_cn, t0, ok=False, status_code=401,
                        reason="signature does not verify against the cert", exchange_id=xid, tech=tech)
            body = self._sign_response(xid, {"ok": False,
                                             "reason": "signature does not verify against the cert"}, pqc=pqc)
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED, payload=json.dumps(body).encode())

        p1 = time.perf_counter()
        allowed, reason = policy_check(self.server_api, self.secret, sender_cn, self.own_name,
                                       use_case=self.use_case)
        p2 = time.perf_counter()
        if not allowed:
            self._report(sender_cn, t0, ok=False, status_code=403, reason=reason, exchange_id=xid, tech=tech)
            body = self._sign_response(xid, {"ok": False, "allowed": False, "reason": reason}, pqc=pqc)
            return aiocoap.Message(code=aiocoap.FORBIDDEN, payload=json.dumps(body).encode())

        try:
            if encrypted is not None:
                payload_bytes = coap_crypto.decrypt_with(self.own_key_path, encrypted)
                payload = json.loads(payload_bytes)
            elif encrypted_pqc is not None:
                if not self.own_kem_key_path:
                    raise RuntimeError("no PQC KEM identity provisioned on this node")
                payload_bytes = coap_crypto.decrypt_with_kem(self.own_kem_key_path, encrypted_pqc)
                payload = json.loads(payload_bytes)
            else:
                payload, payload_bytes = clear_payload, signed_over
        except Exception as e:                        # noqa: BLE001 -- wrong key/tampered ciphertext
            self._report(sender_cn, t0, ok=False, status_code=401,
                        reason=f"decryption failed: {e}", exchange_id=xid, tech=tech)
            body = self._sign_response(xid, {"ok": False, "reason": "decryption failed"}, pqc=pqc)
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED, payload=json.dumps(body).encode())

        p3 = time.perf_counter()
        try:
            # 2026-08-09, found live: `_run` is SYNCHRONOUS and two of its use cases block for a
            # long time on purpose -- `rm` waits on subprocess.run (up to rm_limits.MAX_TIMEOUT,
            # 300s) and `ml` polls the agent spool with time.sleep (up to ml_limits.MAX_TIMEOUT,
            # 300s). Awaited inline it blocked THIS PROCESS'S ENTIRE ASYNCIO LOOP, so one peer's
            # slow call froze the node's whole CoAP receiver for every other peer and every other
            # use case. Measured on the live bench: one `ml` call to a node whose ML agent was
            # absent made every subsequent `status` over coap-enc time out at 10.3s for ~20s+,
            # while the same node's mTLS listener answered in 0.3s throughout.
            #
            # This is precisely the failure server.py's own docstring records fixing on the HTTP
            # side ("it stopped being survivable with /rm-exec, where one peer's command
            # legitimately runs for seconds and would otherwise freeze this node's receiver,
            # including its /health probe") by moving to ThreadingHTTPServer. The CoAP transport
            # never got the equivalent. A thread executor is that equivalent for an asyncio server:
            # the handlers are ordinary blocking functions and stay unchanged, aiocoap keeps
            # serving other requests, and the per-request timeout budgets they already enforce are
            # the only bound needed on the thread's lifetime.
            result, nbytes, reported = await asyncio.get_running_loop().run_in_executor(
                None, self._run, sender_cn, payload, len(payload_bytes), tech)
            p4 = time.perf_counter()
        except Exception as e:                        # noqa: BLE001 -- a handler fault, not a refusal
            self._report(sender_cn, t0, ok=False, status_code=500, reason=str(e), exchange_id=xid, tech=tech)
            body = self._sign_response(xid, {"ok": False, "reason": str(e)}, pqc=pqc)
            return aiocoap.Message(code=aiocoap.INTERNAL_SERVER_ERROR, payload=json.dumps(body).encode())
        # The mirror POST to the Server (~165 ms on a Pi) and the on_p2p event (on-dev-api P9.7) run AFTER the
        # reply, as server.py does for HTTP. 2026-10-23 audit moved the POST to an executor; v2 (same day) also
        # starts it only once the reply has gone out: a mirror thread started before the reply still took the
        # GIL from this loop for ~4 ms (Python's 5 ms switch interval) -- the whole of the then `mirror_ms`.
        loop = asyncio.get_running_loop()
        after = functools.partial(self._after_reply, sender_cn, t0, nbytes, reported, xid, tech,
                                  relay_tls_facts(request), time.time())
        loop.call_later(self.AFTER_REPLY_S, lambda: loop.run_in_executor(None, after))
        if isinstance(result, dict):
            # 2026-09-30, benchmarking (API docs/50_timing.md): this receiver's own share, on ITS
            # monotonic clock -- the same key server.py returns, so the sender's `network_ms`
            # (exchange - receiver total) means the same thing on CoAP as on HTTP. `decrypt_ms` is None
            # where nothing was encrypted (coap, and the coap-dtls* envelopes a relay unwrapped).
            # Added before signing, so the response signature covers it. A COPY: `result` may be the
            # mirror's payload too.
            result = {**result, "receiver_timing": {
                "verify_ms": round((p1 - p0) * 1000, 3),
                "authorize_ms": round((p2 - p1) * 1000, 3),
                "decrypt_ms": (round((p3 - p2) * 1000, 3)
                               if encrypted is not None or encrypted_pqc is not None else None),
                "handler_ms": round((p4 - p3) * 1000, 3),
                "total_ms": round((p4 - p0) * 1000, 3)}}
        result = self._sign_response(xid, result, pqc=pqc)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=json.dumps(result).encode())

    # How long after render_post returns the mirror / event work starts: aiocoap sends the reply as soon as
    # render_post returns, so this only has to outlast that hand-off.
    AFTER_REPLY_S = 0.05

    def _after_reply(self, sender_cn, t0, nbytes, reported, xid, tech, tls, t_end):
        """In an executor thread, after the reply: the on_p2p event, then the Server mirror (best-effort both).
        The mirror's duration_ms ends when the reply was handed over (`t_end`), not when this ran."""
        events.emit(self.use_case, sender_cn, tech, reported, nbytes)
        self._report(sender_cn, t0, ok=True, status_code=204, nbytes=nbytes, payload=reported,
                     exchange_id=xid, tech=tech, tls=tls, t_end=t_end)

    def _run(self, sender_cn, payload, wire_bytes, tech="coap-enc"):
        """The use case itself -> (response, bytes_counted, payload_for_the_log). The same three
        handlers the HTTP transport calls — a use case behaves identically whichever tech carried
        it, which is the whole point of separating the two axes. `tech` is `"coap"` or
        `"coap-enc"` (render_post's own derivation, monitor.md D17, 2026-08-21) -- both CoAP techs
        are envelope-signature-verified before `_run` is ever reached (unlike HTTP's `mtls`), so
        both get `envelope_verified=True` in the audit log via `handle()`'s own `tech` param."""
        if self.use_case == "file":
            # The bytes ride base64 INSIDE the encrypted, signed payload, so both the signature and
            # the encryption cover the file's content and not merely its name.
            data = base64.b64decode(payload.get("data_b64") or "")
            dest = payload.get("dest_filename") or "delivered.bin"
            put = payload.get("put_file")
            result = file_delivery.handle(sender_cn, dest, data, put=put)
            return result, len(data), {"dest_filename": dest, "sha256": result.get("sha256"),
                                       **({"job_id": result.get("job_id"),
                                           "status": result.get("status")} if put else {})}
        if self.use_case == "status":
            result = status.handle(sender_cn)
            result["coap_enc_verified"] = True
            reported = dict(result)              # the mirror row never carries the details block
            if (payload or {}).get("details"):
                result["details"] = status.details()
            return result, wire_bytes, reported
        if self.use_case == "rm":
            result = rm.handle(sender_cn, payload, tech=tech)
            result["coap_enc_verified"] = True
            # As on the HTTP transport: the mirror gets the command and its verdict, never the
            # command's output (server.py::_run says why).
            return result, wire_bytes, {"cmd": payload.get("cmd"), "rc": result.get("rc"),
                                        "refused": result.get("refused"),
                                        "timed_out": result.get("timed_out")}
        if self.use_case == "ml":
            result = ml.handle(sender_cn, payload, tech=tech)
            result["coap_enc_verified"] = True
            # As on the HTTP transport: the mirror gets which operation and its verdict, never the
            # operation's own result (server.py::_run says why).
            return result, wire_bytes, {"method": payload.get("method"), "ok": result.get("ok"),
                                        "refused": result.get("refused"),
                                        "timed_out": result.get("timed_out")}
        if self.use_case == "fetch":
            # on-dev-api P4.1: the PULL use case. The bytes ride base64 in the (signed) reply; the
            # mirror gets the path and digest only, never the content (server.py::_run says why).
            result = fetch.handle(sender_cn, payload, tech=tech)
            result["coap_enc_verified"] = True
            return result, result.get("bytes") or 0, {"path": payload.get("path"),
                                                      "sha256": result.get("sha256"),
                                                      "refused": result.get("refused")}
        result = message.handle(sender_cn, payload, tech=tech)
        return result, wire_bytes, payload


async def main():
    name = os.environ["P2P_NODE_NAME"]
    server_api = os.environ["SERVER_API_BASE"]
    secret = os.environ["BOOTSTRAP_SECRET"]
    port = int(os.environ.get("P2P_COAP_PORT", "5683"))
    cache_dir = os.environ.get("P2P_CACHE_DIR", "/var/lib/p2p/certs")
    cert_path, key_path, ca_path = identity.fetch_own_cert(server_api, secret, name, cache_dir)
    # PQC coap-enc (2026-09-27): best-effort -- a box with no ML-KEM-768 identity provisioned
    # simply can't SERVE `coap-pqc` (own_kem_key_path stays None, handled at request time above),
    # exactly like a box with no PQC toolchain can't serve `pqc` today. Never fatal to start.
    kem_key_path = coap_crypto.own_kem_key_path()
    if not Path(kem_key_path).exists():
        kem_key_path = None

    # the ML-DSA-65 identity the PQC techs need (2026-10-23); a box without one cannot serve them, never fatal
    try:
        pqc_material = identity.load_pqc_material(os.environ.get("P2P_PQC_CACHE_DIR"))
    except errors.IdentityError:
        pqc_material = None

    root = resource.Site()
    for path, use_case in RESOURCES.items():
        root.add_resource([path], P2pResource(use_case, name, ca_path, server_api, secret, key_path,
                                              own_cert_path=cert_path, own_kem_key_path=kem_key_path,
                                              pqc_material=pqc_material))
    await aiocoap.Context.create_server_context(root, bind=("0.0.0.0", port))
    print(f"[p2p-coap-receiver] {name} listening on :{port} (CoAP/UDP, cert+sig identity; "
          f"use cases: {', '.join(sorted(RESOURCES.values()))})", flush=True)
    await asyncio.get_event_loop().create_future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
