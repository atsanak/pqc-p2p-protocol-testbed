# How each of the 13 priority configurations works, and how it was run and checked

**PQC rule (owner, 2026-10-23): every configuration named `*pqc*` uses ML-KEM-768 (the pure FIPS 203 group, TLS codepoint 0x0201,
no X25519 half) for key establishment AND ML-DSA-65 (FIPS 204) for every certificate and every signature in it — in the protocol
itself, never as an add-on envelope over a classical transport. No classical or hybrid fallback anywhere: a classical or hybrid offer,
a classical certificate or an RSA signature is refused (per-config refusal battery, `results/2026-10-23-pqc-mlkem768-mldsa65/`).
The classical configurations are classical on the wire too: since 2026-10-23 they offer X25519 only (before, `https`/`mtls` silently
negotiated the X25519MLKEM768 hybrid — the Pis' OpenSSL 3.5 default — and `coap-dtls` advertised every hybrid group).**

Scope: HTTP `https`, `mtls`, `pqc`, `quic-classical`, `quic-classical-mutual`, `quic-pqc`, `quic-pqc-mutual`; CoAP `coap-enc`,
`coap-pqc`, `coap-dtls`, `coap-dtls-mutual`, `coap-dtls-pqc`, `coap-dtls-pqc-mutual`. (`http`, plain `coap`, `pqkex*`, `hybrid*`,
`quic-hybrid*` exist in the code but are out of scope.)

## 0. What every exchange has in common
```
 sender box (Rpi53)                              Server (10.0.0.2)                        receiver box (Rpi50)
 python3 sender-role/cli.py deliver ...
   1 resolve  --- GET /resolve (receiver name) -->  returns the receiver's /32 + hop chain
   2 build the request (sign / encrypt)
   3 connect + handshake + send --------------------------- over the WireGuard overlay (Wi-Fi first hop, ping ~2-6 ms) -->  listener / relay
   4                                                                       <-- GET /p2p-authorize (sender, receiver, use_case) ---  5 policy check
   6                                                                                                   handler writes /var/lib/p2p/received/<name>, sha256
   7 <------------------------------------------ reply (+ the receiver's own timing block) -----------------------------
   8 sender mirrors a row to the Server comm-log (POST /p2p-comm-log) and writes its own /var/lib/p2p/sent.log
                                                                             9 receiver mirrors ITS row to the comm-log (after replying)
```
* Identity always ends in "the certificate chains to the right CA and its CN is the claimed sender", then the Server decides whether that
  sender may do that use case to that receiver (policy, per pair).
* Two ways to carry the sender's identity: **the TLS client certificate** (`mtls`, `pqc`: the body is the raw request) or **a signed
  envelope in the body** `{sender, cert, sig, ts, xid, payload}` (https, quic-*, coap-*, coap-dtls-*; RSA + fleet CA on the classical
  configs, **ML-DSA-65 + PQC CA on every pqc config**): `sig` covers `payload|ts:<unix>`, the receiver refuses a timestamp older than
  60 s (replay), checks the chain, CN == sender and the signature.
* ML-DSA-65 sign/verify run **in-process** on the system libcrypto (OpenSSL 3.5.7, native FIPS 204) since 2026-10-23, exactly like the
  RSA ones run in-process; before, every PQC envelope spawned 4-5 `openssl` processes (~26 ms) and that process cost showed up as
  "PQC overhead". Byte-compatible with the oqs-provider CLI (proven both ways; `tests/test_pqc_fastpath.py`), which remains the fallback.
* A file rides raw in the body on `mtls`/`pqc`, and base64 inside the signed JSON on every envelope config (~1.35x the file; ~1.8x on
  coap-enc/coap-pqc because the ciphertext is base64'd again).
* The sender is a fresh process per call (no connection reuse, no session resumption): every number includes a cold handshake.
* The `timing` block (metrics v2) is measured on the sender with a monotonic clock; the receiver measures its own part and returns it
  (`receiver.*`). Phases add up to `total_ms`. `network_ms` = exchange - receiver work; `client_overhead_ms` = starting the QUIC helper /
  DTLS worker process. Handshake facts: `handshake_ms`, `handshake_cpu_ms`, `handshake_bytes_out/in`, `rtt_ms`, `retransmits`.

## 1. HTTP family (receiver = `server.py`, one process, several listeners)
| config | port | transport / handshake | who is authenticated | implementation |
|---|---|---|---|---|
| `https` | TCP 8444 | TLS 1.3, **X25519 only**, server RSA-2048 certificate only | receiver by cert; sender by an **RSA-signed envelope** | separate port on purpose: the mTLS port never accepts certless clients |
| `mtls` | TCP 8443 | TLS 1.3, **X25519 only**, **both** sides present a fleet-CA RSA certificate | the handshake itself | `Client._connect()`: TCP, `wrap_socket`, then CN == name, SAN-IP == the /32 dialled, negotiated group == X25519 |
| `pqc` | TCP 8446 | TLS 1.3, **ML-KEM-768 only**, **ML-DSA-65 certificates on both sides** (PQC CA) | the handshake itself, as on mtls (raw body, no envelope) | Python's own `ssl` on the system OpenSSL 3.5.7; Python has no group API, so `identity.pin_tls_groups()` sets `MLKEM768` through libssl and both ends assert the negotiated group. The retired `X-P2P-PQC` envelope on :8443 is refused (400) |
| `quic-classical` | UDP 4443 | QUIC (TLS 1.3 inside), X25519, fleet RSA certificates, HTTP/3 | receiver by cert; sender by RSA envelope | sender: `quic_pqc_client_helper.py` (aioquic, venv `/opt/pqc-libs/quic-pqc-venv`) as a **subprocess per call**; receiver: `quic_pqc_relay.py` terminates QUIC, forwards plain HTTP/1.1 to `server.py` :8442 |
| `quic-classical-mutual` | UDP 4444 | as above + the relay requires the client's RSA certificate | + client cert in the handshake (0x12a if missing/wrong) | same code, `P2P_QUIC_PQC_MUTUAL=1` |
| `quic-pqc` | UDP 4433 | QUIC/TLS 1.3, **ML-KEM-768 only**, **ML-DSA-65** server certificate (quic-pqc CA) | receiver by ML-DSA cert; sender by an **ML-DSA-65-signed** envelope | patched aioquic (`tls.py.patch` + `add_mlkem768.py`, codepoint 0x0201); the relay pins `MLKEM768` (hybrid/classical offers: alert 40) |
| `quic-pqc-mutual` | UDP 4434 | as quic-pqc + the client's ML-DSA-65 leaf, required | + client cert in the handshake | identity per node under `/var/lib/p2p/certs-quic-pqc` |
The relay tells `server.py` the real tech + handshake facts in `X-P2P-Relay-Tech` / `X-P2P-Relay-Tls` (accepted from loopback only).
The sender's QUIC helper refuses to send data unless the negotiated group / certificate are what the config is defined by.

## 2. CoAP family (receiver = `coap_server.py` on UDP 5683, plus a DTLS relay per DTLS port)
| config | port | what protects it | implementation |
|---|---|---|---|
| `coap-enc` | UDP 5683 | no transport security; per-message AES-256-GCM key wrapped with the receiver's **RSA** key (RSA-OAEP), **RSA-2048-signed** envelope and reply | aiocoap CON POST, block-wise 1 KiB blocks, stop-and-wait (one block per round trip — why CoAP is ~0.15 MB/s here) |
| `coap-pqc` | UDP 5683 | same shape, key wrapped with **ML-KEM-768**, envelope **and the receiver's reply ML-DSA-65-signed** (the sender refuses an unsigned/RSA reply) | KEM public keys provisioned offline in `/var/lib/p2p/certs-pqc/kem-peers/` |
| `coap-dtls` | UDP 5687 | **DTLS 1.3** (wolfSSL), **X25519 only** (groups list pinned since 2026-10-23), fleet RSA server certificate; signed cleartext envelope inside | sender: aiocoap + `aiocoap_wolfdtls.py`, handshake + exchange in a **worker process**; message sent as sequence-numbered 1 KiB chunks paced 2 ms apart; receiver: `coap_dtls_pqc_relay.py` (one accept loop per local IP) re-issues the request to `coap_server.py` on 127.0.0.1 |
| `coap-dtls-mutual` | UDP 5688 | as coap-dtls + the client's RSA certificate, required by the relay | same relay, `P2P_COAP_DTLS_PQC_MUTUAL=1` |
| `coap-dtls-pqc` | UDP 5685 | DTLS 1.3, **ML-KEM-768 only**, relay's **ML-DSA-65** certificate (PQC CA); envelope and reply **ML-DSA-65-signed** | `REQUIRE_GROUP` = `ML_KEM_768` + `PQC_MODE` (loads `/var/lib/p2p/certs-pqc`); groups pinned with `wolfSSL_set1_groups_list` on the binding's own wolfSSL. wolfSSL sends the 1184 B key share only after a HelloRetryRequest (one extra round trip, inside `handshake_ms`) |
| `coap-dtls-pqc-mutual` | UDP 5686 | + the client's ML-DSA-65 certificate, required by the relay | |
DTLS robustness fixes (2026-10-23, found by this verification): (1) the relay serves one peer per address by `connect()`ing its socket;
a peer that vanished mid-handshake held the address for wolfSSL's whole back-off (~1 min, every other client got port-unreachable) —
now capped at 1+2+4 s (`wolfSSL_dtls_set_timeout_max`); (2) after the handshake wolfSSL resets `SO_RCVTIMEO` to "forever", so a DTLS
record lost on Wi-Fi hung both ends indefinitely (a 1 MiB transfer ran 20 min under `--timeout 120`) — the relay now has a watchdog
that shuts the socket at `PEER_TIMEOUT_S` (90 s) and the sender kills its worker when its budget expires; (3) a lost REPLY
datagram turned a delivered file into "closed without a reply" (~1 in 100, independent verification) — every message of
≤ 32 chunks (all replies, incl. the ~15-chunk PQC ones) is now sent twice; readers already drop duplicates, so old peers are
unaffected. Soak after the fix: 204/204 (51 each on coap-dtls, coap-dtls-mutual, coap-dtls-pqc, coap-dtls-pqc-mutual).

## 3. How each configuration was run and checked (one at a time, HTTP then CoAP; `run_config.sh TECH`)
1. **Sender result** — `usecase_matrix.py`: all six use cases (`file`, `fetch`, `message`, `status`, `rm`, `ml`) in both directions
   (Rpi53->Rpi50, Rpi50->Rpi53), each with a content check.
2. **Refusals** — `negative_pqc.py TECH`: CONTROL cases with the right parameters (must be accepted — a broken probe cannot "pass"),
   then one-thing-wrong cases (wrong group, hybrid offer, missing / classical / PQC client cert, wrong CA, RSA or forged ML-DSA
   signature, 10-minute-old envelope, retired header); DTLS configs end with a RECOVERY delivery 8 s after the handshake attacks.
3. **Wire** — `wire_check.py`: a raw AF_PACKET sniffer on wg0 reads the handshake off the packets (TLS hellos in clear; QUIC Initial
   packets decrypted with the RFC 9001 Initial keys; DTLS hellos reassembled; CoAP Block1/Block2 reassembled into the envelopes) and
   checks the offered/negotiated group, key-share sizes (1184 B ML-KEM key, 1088 B ciphertext, 32 B X25519), signature sizes (3309 B
   ML-DSA-65), certificate algorithms, that no plaintext slice of the file is on the wire, and the v2 metrics against the packets
   (handshake bytes exactly, handshake_ms within [server flight end, our last segment], rtt vs SYN/SYN-ACK, TCP retransmits vs duplicate
   segments, CoAP retransmits vs duplicate message ids). `loss_check.py` (two-ended capture) is the ground truth for QUIC `retransmits`.
4. **Receiver records** — `usecase_audit.py`: Server comm-log (both halves, same exchange_id, tech, ok), the receiver's
   `messages.log` (nonce, tech label, envelope_verified), `rm.log`, sha256 of the delivered file on its disk.
5. **Campaign** — `campaign1.sh`: 16 KiB / 256 KiB / 1 MiB, 1 warm-up + 5 measured each, a 5/s ping logged for the whole window.
6. **Audit** — `audit_v2.py`: every run joined across the run output, both comm-log halves, the receiver's disk and event log and the
   sender's `sent.log`; v2 None-ness matrix, phase arithmetic, negotiated facts, PQC rule checks.
7. **Medians** — `summarize.py`; the owner's report: `final_report.py` -> `REPORT.md`.

## 4. Honest limits
* One sender/receiver pair over WireGuard whose first hop is Wi-Fi; 5 measured runs per size; no concurrency, no reuse, nothing above 1 MiB.
* QUIC `retransmits` = packets aioquic's loss detector declared lost. Two-ended captures showed **zero** datagrams really lost while the
  metric read 4-64 at 1 MiB: they are spurious retransmissions (real extra datagrams on the wire, not network loss).
* On DTLS, `handshake_bytes_*`, `rtt_ms`, `retransmits` are not observable through the wolfSSL binding (None); the report gives the
  wire-measured handshake bytes instead.
* Every call starts new processes (Python, plus the QUIC helper / DTLS worker: `client_overhead_ms`).
* No Server policy DENIAL test, no revoked/expired certificates. The QUIC-PQC CA key (`certs-quic-pqc/ca.key`) sits on each Pi.
* Out of scope, NOT changed to the PQC rule: MQTT/TAU `pqc*` tiers, video stacks, the bare-metal sidecar (still sends `X-P2P-PQC`).
