# aioquic-patch — hybrid PQC for QUIC (Stack 5/6)

Closes the P2P half of gap (e) from the 2026-09-27 gap table: "Stacks 5 & 6 (QUIC, server +
mutual) — nothing exists — large: new transport entirely." This directory is the "new transport,"
Stack 5 (QUIC server-auth) proven live 2026-09-28; Stack 6 (QUIC mutual) not yet built.

## Why this toolchain looks different from every other PQC tech here

Every other real-handshake PQC tech in this project (`pqkex`, `coap-dtls-pqc`,
`MQTT_MODE=pqc[-mutual]`) exists because Python's stdlib `ssl` — and every C TLS library the
project's other tools call into (system OpenSSL) — has no hybrid PQ-KEX group without a
patched/private build (oqs-provider or wolfSSL). That forced a pattern: compile a private
OpenSSL/wolfSSL, shell out to it via subprocess or front it with stunnel.

`aioquic` doesn't have that problem. It implements TLS 1.3 itself, in pure Python
(`aioquic/tls.py`), using the `cryptography` package for the actual crypto primitives — it never
asks the system TLS stack to do anything. And `cryptography` 50.0.1 (confirmed live 2026-09-28,
`pip install cryptography` — no special build) ships **native** `MLKEM768` and `MLDSA65` support
(`cryptography.hazmat.primitives.asymmetric.mlkem`/`mldsa`). So this whole tech is
`pip install cryptography aioquic` + a 166-line patch to `aioquic/tls.py` — no C compile, no
`LD_LIBRARY_PATH`/`OPENSSL_CONF` juggling, no private toolchain to build per-architecture.

## What the patch does (`tls.py.patch`)

- `Group.X25519MLKEM768 = 0x11EC` — the real IANA TLS codepoint (draft-ietf-tls-ecdhe-mlkem).
- `SignatureAlgorithm.MLDSA65 = 0x0905` — wired into `signature_algorithm_params()` and
  `_signature_algorithms_for_private_key()` the same way `ED25519` already is (no extra
  signing params needed, same calling convention).
- Hybrid key exchange handled as a special case in `_client_send_hello`/`_server_handle_hello`/
  `_client_handle_hello` — checked *before* `decode_public_key()`, which returns ONE
  cryptography key object typed EC/X25519/X448 and can't represent two independent keys
  concatenated. Wire shape: `x25519_pub(32) || mlkem_encap_key(1184)` from the client,
  `x25519_pub(32) || mlkem_ciphertext(1088)` back from the server. Combiner:
  `shared = x25519_shared || mlkem_shared` (classical || post-quantum — same order oqs-provider
  uses for this project's other `X25519MLKEM768` techs, for convention consistency only; this is
  a separate, self-contained implementation, not wire-compatible with those).

Verified byte-identical round trip: apply to a clean `pip install aioquic` → identical file to the
patched one. See `install-aioquic-pqc.sh`.

## Certificates: a FOURTH, separate CA (`../ca/quic_pqc_ca.py`)

Confirmed live: an existing `peer.key` minted by `pqc_ca.py` (oqs-provider) fails to load via
`cryptography`'s native `mldsa` loader — `ASN.1 parsing error: unexpected tag`. The PUBLIC
key/cert (X.509 SPKI) format IS byte-compatible both ways (a `pqc`/`pqkex` peer.crt loads and
verifies fine via `cryptography`'s x509 module) — only the PRIVATE key encoding differs between
oqs-provider's convention and `cryptography`'s native one. So `quic-pqc` mints its own certs,
pure Python, no subprocess, no openssl binary involved at all.

## Live proof, 2026-09-28 (real fleet, not loopback)

Protectli1 (client) → Protectli2 (server), over the real WireGuard overlay:
```
[server] HANDSHAKE COMPLETE alpn=quic-pqc-test
[client] CONNECTED -- real hybrid PQC QUIC handshake complete
[client] APPLICATION DATA ROUND TRIP: b'echo:hello-from-real-fleet'
[client] group negotiated: 0x11ec
```
The server's stunnel-equivalent proof here is `HandshakeCompleted.alpn_protocol` firing on both
ends plus the client's own record of which `Group` value the (hybrid-only, no-fallback) `_supported_groups`
override actually completed with — mirroring the "offer only the group under test" methodology
`pqkex`/`coap-dtls-pqc` already use to prove the group was truly what got negotiated, not a
silent fallback.

## Usage

```
./install-aioquic-pqc.sh                      # on the target box, as root
/opt/pqc-libs/quic-pqc-venv/bin/python3 quic_pqc_server.py           # on the receiver
/opt/pqc-libs/quic-pqc-venv/bin/python3 quic_pqc_client.py <server-ip>   # on the sender
```
`quic_pqc_server.py`/`quic_pqc_client.py` are a minimal echo pair proving the handshake +
one stream round trip — not yet wired into `p2p/`'s `TECHS` tuple as a real `--tech quic-pqc`
(that's the next piece of gap (e), not done here).

## Not done (remaining gap (e) scope)

- P2P tech wiring (`--tech quic-pqc` in `client.py`/`server.py`, real CC/ML/FL pipeline proof
  matching `pqkex`'s rigor).
- Stack 6 (QUIC mutual) — needs a client cert presented during the QUIC/TLS handshake and
  verified server-side; likely a smaller increment once Stack 5's plumbing exists as a real tech,
  mirroring how `pqkex-mutual` was a small increment on `pqkex`.
- MQTT-side QUIC transport ("nothing exists" per the gap table) — HTTP/3 isn't MQTT's shape at
  all; would need its own design, not just a stunnel-style front door.
- Video streaming (MJPEG over HTTP/3) — untouched.
