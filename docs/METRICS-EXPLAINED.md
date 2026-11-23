# What each metric measures, and how each configuration starts and why it is correct

*atsanak, 2026-10-23. Written for a general audience. The technical reference is `p2p/HOW-EACH-CONFIG-WORKS.md`, and the code
that defines every metric is `p2p/sender-role/client.py` (timing block) and `api/p2p_configs.py` (`METRICS`).*

## 1. The picture to keep in mind

Sending a file from one device to another is like sending a sealed parcel by courier:

1. **Prepare**: pack it (read the file, encode it, sign it, maybe encrypt it).
2. **Handshake**: the two sides agree a secret key and check each other's ID. This is the "security" part.
3. **Exchange**: the parcel travels, the receiver checks it, stores it and sends back a receipt.
4. **Total**: everything, start to finish.

Every call is a **fresh** connection, with no reuse. That means every number includes a complete, cold handshake, which is
the worst case and the fair one for comparing security levels.

## 2. Every metric, one by one

| metric | what it captures | the courier analogy | why it matters |
|---|---|---|---|
| **handshake_ms** | Milliseconds from the first "hello" until both sides can send encrypted data. Covers key agreement, certificate exchange and signature checks | the time at the counter showing IDs and agreeing the lock code | this is where post-quantum cryptography lives, so it is the cost of PQC security |
| **handshake_cpu_ms** | Of that time, how much the sender's processor was actually computing (making keys, signing, verifying) | how long the clerk was busy, as opposed to waiting | separates "the maths is slow" from "the network is slow" |
| **handshake_bytes_out** | Bytes the sender put on the wire during the handshake | the paperwork you hand over | PQC keys and signatures are large (ML-DSA-65 signature = 3309 bytes), which matters on radios |
| **handshake_bytes_in** | Bytes the receiver sent back during the handshake | the paperwork handed back | the same, in the other direction |
| **rtt_ms** | Round-trip time of the path, as the connection itself measured it (TCP's or QUIC's own estimate) | how long a shout takes to come back | tells you whether a slow result was the network |
| **retransmits** | Packets the sender had to send again (TCP segments, CoAP messages, QUIC packets declared lost) | parcels re-sent because the first seemed lost | a health signal. On QUIC they were proven *spurious*: no packet was really lost |
| **prepare_ms** | Building the request: reading the file, base64-encoding, signing, encrypting | packing the parcel | envelope configs sign the whole payload. mtls/pqc send it raw, so prepare ≈ 0 |
| **exchange_ms** | From sending the first byte of the request to having the whole reply | the parcel's trip plus the receipt coming back | the transfer itself |
| **receiver_ms** | The part of the exchange the **receiver** spent working (verifying, asking the Server's policy, storing). The receiver reports it itself | the time at the destination desk | separates the receiver's processing from the network |
| **network_ms** | `exchange_ms − receiver_ms`: time the bytes spent travelling | time in the van | the transport's own speed (TCP vs QUIC vs CoAP) |
| **client_overhead_ms** | Starting the separate QUIC helper or DTLS worker process (QUIC and DTLS configs only) | the courier van warming up | it was previously hidden inside "network" (~385 ms!). Now it is shown on its own |
| **total_ms** | The whole call on the sender. **The phases add up to it** | door to door | the number a user feels |
| **MB/s** (GUI/report) | File size ÷ median total time | parcels per hour | throughput including the handshake |
| **request bytes (× file)** | Bytes sent for the request compared with the file size | packaging overhead | 1.00× for raw-body configs; 1.35× with base64; ~1.8× when encrypted then base64 |

**Rules that make these numbers trustworthy**
* A phase that does not exist is shown as **None ("–")**, never 0. CoAP without DTLS has no handshake, and UDP has no TCP connect.
* Phases **add up** to `total_ms`. Nothing is counted twice and nothing is hidden.
* Plumbing (ssh from the GUI's PC, logging to the Server) is **excluded** from protocol time.
* Every metric was **checked against the packets**: handshake bytes match the captured hellos byte for byte, RTT matches the
  TCP SYN/SYN-ACK gap, and re-sends match duplicate segments or message ids (`p2p/results/.../wire_check.py`).

## 3. How each configuration starts (who speaks first, and with what)

| config | 1st message (sender → receiver) | answer | what makes it secure |
|---|---|---|---|
| `https` | TLS ClientHello: "let's use X25519", plus a 32-byte key share | server key share + RSA certificate + signature | X25519 key agreement; the receiver proven by RSA cert; the sender proven by a signed envelope |
| `mtls` | same | + "show me your certificate" → the client sends its RSA cert + signature | both proven in the handshake |
| `pqc` | ClientHello: "**ML-KEM-768 only**" + a 1184-byte encapsulation key | 1088-byte ciphertext + ML-DSA-65 certificate + signature; asks for the client's ML-DSA cert | post-quantum key agreement and post-quantum identities on both sides |
| `quic-classical` | QUIC Initial packet carrying the TLS ClientHello (X25519) | QUIC Initial + Handshake packets with the RSA cert | the same as https, over UDP with QUIC's own reliability |
| `quic-classical-mutual` | same | + the client certificate is required in the handshake | both proven in the handshake |
| `quic-pqc` | QUIC Initial(s) with "ML-KEM-768 only" + 1184-byte key | ciphertext + ML-DSA-65 certificate | PQC key agreement; the sender proven by an ML-DSA-65-signed envelope |
| `quic-pqc-mutual` | same | + the client's ML-DSA-65 certificate is required | everything post-quantum, both sides in the handshake |
| `coap-enc` | **no handshake**: the first message *is* the data, encrypted with a fresh AES-256 key wrapped for the receiver's RSA key, and signed | a signed reply | per-message encryption + RSA signatures both ways |
| `coap-pqc` | no handshake: AES-256 key **encapsulated with ML-KEM-768**, signed with ML-DSA-65 | a reply **signed with ML-DSA-65** (an unsigned one is refused) | post-quantum per-message protection both ways |
| `coap-dtls` | DTLS 1.3 ClientHello (X25519) | RSA certificate | TLS-grade session over UDP |
| `coap-dtls-mutual` | same | + client RSA certificate required | both proven in the handshake |
| `coap-dtls-pqc` | DTLS ClientHello → the receiver asks again (HelloRetryRequest) for **ML-KEM-768** → the client sends the 1184-byte key | ML-DSA-65 certificate | PQC session over UDP |
| `coap-dtls-pqc-mutual` | same | + client ML-DSA-65 certificate required | everything post-quantum, both sides |

## 4. Why each one is correct, not merely working

"The file arrived" is not proof. A file can arrive over a connection that is *not* what its name says, and that is exactly what
was happening before this work. For each configuration, four independent things must agree:

1. **The connection says so.** After the handshake, the sender reads the *negotiated* group and the peer's key type back from the
   TLS/QUIC/DTLS library. If they are not exactly what the configuration is defined by, it **refuses to send any data**.
2. **The wire says so.** A packet sniffer on the tunnel reads the handshake off the packets. QUIC's encrypted Initial packets are
   decrypted with the public RFC 9001 keys. The check is that only the right group and key sizes appear (1184/1088 bytes for
   ML-KEM-768, 32 for X25519, 3309-byte ML-DSA-65 signatures), and that no plaintext of the file is visible.
3. **Wrong things are refused.** A battery of one-thing-wrong attempts (hybrid offer, classical offer, missing or wrong client
   certificate, wrong CA, forged or 10-minute-old signature) must all be rejected. **Control** attempts with the right parameters
   must be accepted, which proves the test itself works.
4. **The receiver agrees.** Its own logs, both halves of the Server's communication log, and the sha256 of the file on its disk.

All 13 configurations pass all four: 216 runs, 240/240 report cells recomputed, 115/115 wire checks, 77/77 refusal checks,
648/648 audit checks, and a 204/204 DTLS soak.

## 5. Where to see it yourself
* GUI: Tenant-Admin ▸ Protocols ▸ **P2P metrics**. Pick a sender and receiver, press **Check readiness**, then **Run selected**.
  Click any row to see its numbers and an explanation.
* API: `TenantAPI.p2p_verify_configs(sender, receiver)` and `TenantAPI.p2p_metric_meanings()`.
