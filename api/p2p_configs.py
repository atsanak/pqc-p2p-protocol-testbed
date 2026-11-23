"""The 13 priority P2P configurations (HTTP then CoAP), what each one is, what every v2 timing metric means, the rule that
says whether a handshake was what the configuration is defined by, and the measuring loop -- ONE module shared by the GUI
(Protocols > P2P metrics), TenantAPI (`p2p_configs`, `p2p_verify_configs`) and the tests, so they cannot drift.
2026-10-23, atsanak. Stdlib only."""
import hashlib
import os

# (family, tech, plain-words description) -- HTTP first, then CoAP, the owner's order
CONFIGS = (
    ("HTTP", "https", "TLS 1.3 over TCP. Key exchange X25519 (classical). Only the receiver shows a certificate (RSA); "
                      "the sender proves who it is with an RSA signature inside the message."),
    ("HTTP", "mtls", "TLS 1.3 over TCP. Key exchange X25519. BOTH sides show an RSA certificate in the handshake; the "
                     "client certificate is the sender's identity, the file goes raw (no envelope)."),
    ("HTTP", "pqc", "mtls made post-quantum: TLS 1.3 over TCP with ML-KEM-768 key exchange (nothing else accepted) "
                    "and ML-DSA-65 certificates on BOTH sides. No envelope, no RSA, no X25519 anywhere."),
    ("HTTP", "quic-classical", "HTTP/3 over QUIC (UDP). Key exchange X25519, receiver's RSA certificate, sender "
                               "proves itself with an RSA-signed envelope."),
    ("HTTP", "quic-classical-mutual", "As quic-classical, and the sender must also show its RSA certificate in "
                                      "the QUIC handshake."),
    ("HTTP", "quic-pqc", "HTTP/3 over QUIC with ML-KEM-768 key exchange and the receiver's ML-DSA-65 certificate; the "
                         "sender proves itself with an ML-DSA-65 signature."),
    ("HTTP", "quic-pqc-mutual", "As quic-pqc, and the sender must also show its ML-DSA-65 certificate in the "
                                "handshake."),
    ("CoAP", "coap-enc", "CoAP over plain UDP, no handshake. Each message is encrypted with a fresh AES-256-GCM key "
                         "wrapped for the receiver with RSA-OAEP; request and reply are RSA-signed."),
    ("CoAP", "coap-pqc", "coap-enc made post-quantum: the AES key is wrapped with ML-KEM-768 and request AND reply "
                         "are signed with ML-DSA-65 (the sender refuses a reply that is not)."),
    ("CoAP", "coap-dtls", "CoAP inside DTLS 1.3 (TLS for UDP). Key exchange X25519, receiver's RSA certificate."),
    ("CoAP", "coap-dtls-mutual", "As coap-dtls, and the sender must also show its RSA certificate in the DTLS "
                                 "handshake."),
    ("CoAP", "coap-dtls-pqc", "CoAP inside DTLS 1.3 with ML-KEM-768 key exchange, the receiver's ML-DSA-65 "
                              "certificate, and ML-DSA-65 signatures on request and reply."),
    ("CoAP", "coap-dtls-pqc-mutual", "As coap-dtls-pqc, and the sender must also show its ML-DSA-65 certificate."),
)
PQC = {"pqc", "quic-pqc", "quic-pqc-mutual", "coap-pqc", "coap-dtls-pqc", "coap-dtls-pqc-mutual"}
NO_HANDSHAKE = {"coap-enc", "coap-pqc"}

# (key in the timing block, column heading, plain-words meaning)
METRICS = (
    ("handshake_ms", "handshake ms", "Time to set up the secure session: from the first hello until both sides "
                                     "have agreed keys and the receiver's certificate was checked. 0 / – where "
                                     "there is no handshake (coap-enc, coap-pqc)."),
    ("handshake_cpu_ms", "hs CPU ms", "How much of that the sender's CPU actually computed (key generation, "
                                      "signatures, certificate checks). The rest of handshake ms is waiting for "
                                      "the network."),
    ("handshake_bytes_out", "hs bytes out", "Bytes the sender put on the wire for the handshake (hellos, its "
                                            "certificate, its signature). PQC is bigger: an ML-KEM-768 key is 1184 B, "
                                            "an ML-DSA-65 signature 3309 B, its certificate ~5.5 KB."),
    ("handshake_bytes_in", "hs bytes in", "Bytes the receiver sent back during the handshake (its certificate chain, "
                                          "signature, key share). Not observable through wolfSSL on DTLS (–)."),
    ("rtt_ms", "RTT ms", "Round-trip time of the network path as the connection itself measured it (TCP's or QUIC's "
                         "own smallest RTT). Not available on DTLS / plain CoAP (–)."),
    ("retransmits", "retx", "Packets the sender had to send again. TCP: segments re-sent; CoAP: messages re-sent; "
                            "QUIC: packets its loss detector declared lost (on this testbed these were all false "
                            "alarms: nothing was really lost)."),
    ("prepare_ms", "prepare ms", "Building the request before sending: reading the file, base64, signing, "
                                 "encrypting (CoAP). ~0 on mtls / pqc: the file goes raw."),
    ("exchange_ms", "exchange ms", "From sending the first byte of the request to having the whole reply."),
    ("receiver_ms", "receiver ms", "Of that, the time the RECEIVER spent working (checking the signature, asking "
                                   "the Server's policy, decrypting, writing the file) -- it measures this itself "
                                   "and sends it back."),
    ("network_ms", "network ms", "exchange ms minus receiver ms: the time the bytes spent travelling."),
    ("total_ms", "total ms", "The whole call on the sender, start to finish. The phases above add up to it."),
)
def verdict(tech, negotiated, peer_verified):
    """-> (ok, text): is what was negotiated what this config is defined by?"""
    neg = negotiated or {}
    group, key = neg.get("group"), str(neg.get("tls_peer_key") or "")
    if tech == "coap-enc":
        return True, "no handshake (RSA-OAEP + RSA signatures)"
    if tech == "coap-pqc":
        return (peer_verified is True,
                "reply ML-DSA-65 signature verified" if peer_verified is True else f"reply NOT ML-DSA-verified ({peer_verified!r})")
    if tech in PQC:
        ok = group == "MLKEM768" and key.startswith("ML-DSA-65")
        return ok, f"{group or '?'} + {key or '?'}" + ("" if ok else "  ✗ expected MLKEM768 + ML-DSA-65")
    ok = group == "X25519" and key.startswith("RSA")
    return ok, f"{group or '?'} + {key or '?'}" + ("" if ok else "  ✗ expected X25519 + RSA")


def measure(api, sender, receiver, tech, size, n=3, warmup=1, stop=None, progress=None, timeout=120):
    """Deliver a random `size`-byte file `warmup + n` times on `tech` and check each one.
    -> {tech, n, ok_runs, failures: [str], samples: [timing], stats: {key: timing_stats}, negotiated, verdict}"""
    out = {"tech": tech, "size": size, "n": n, "ok_runs": 0, "failures": [], "samples": [], "negotiated": None,
           "peer_verified": None}
    for i in range(warmup + n):
        if stop is not None and stop.is_set():
            out["failures"].append("stopped")
            break
        data = os.urandom(size)
        try:
            r = api.p2p_deliver(sender, receiver, data=data, dest="gui-metrics-probe.bin", tech=tech, timeout=timeout)
        except Exception as e:                                          # noqa: BLE001 -- shown, never raised
            out["failures"].append(f"run {i}: {type(e).__name__}: {e}")
            continue
        sha_ok = str(r.get("sha256", "")).replace("sha256:", "") == hashlib.sha256(data).hexdigest()
        t = api.p2p_timing(r)
        if not r.get("ok") or not sha_ok or t is None:
            out["failures"].append(f"run {i}: " + str(r.get("reason") or r.get("error")
                                                      or ("sha256 mismatch" if not sha_ok else "no timing block"))[:200])
            continue
        if r.get("negotiated"):
            out["negotiated"] = r["negotiated"]
        if "peer_verified" in r:
            out["peer_verified"] = r.get("peer_verified")
        if i >= warmup:
            out["samples"].append(t)
            out["ok_runs"] += 1
        if progress:
            progress(tech, i + 1, warmup + n)
    keys = [k for k, _h, _d in METRICS] + ["request_bytes"]
    out["stats"] = {k: api.timing_stats([s.get(k) for s in out["samples"]]) for k in keys}
    out["stats"] = {k: v for k, v in out["stats"].items() if v}
    out["verdict"] = verdict(tech, out["negotiated"], out["peer_verified"])
    return out


