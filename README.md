# P2P protocol-security testbed: 13 HTTP and CoAP configurations, classical and post-quantum

**Developer: Angelos Tsanaktsidis** — the device-to-device transport layer of an IoT testbed:
13 HTTP and CoAP security configurations, real post-quantum TLS / QUIC / DTLS (ML-KEM-768 + ML-DSA-65), the timing
metrics (v2) of every exchange, and the method that proves each configuration on real hardware.
State of 2026-10-23.

* **Every metric and how each configuration starts and why it is correct, for a general audience:** [`docs/METRICS-EXPLAINED.md`](docs/METRICS-EXPLAINED.md)
* How each configuration works (technical): [`p2p/HOW-EACH-CONFIG-WORKS.md`](p2p/HOW-EACH-CONFIG-WORKS.md)
* All final results (HTTP then CoAP, every metric, every check): [`results/REPORT.md`](results/REPORT.md)
* Metric definitions (original timing doc): [`docs/timing-metrics.md`](docs/timing-metrics.md)

## The rule
A configuration named `*pqc*` uses **ML-KEM-768** (pure FIPS 203 group, TLS codepoint 0x0201 — no X25519 half) for key
establishment and **ML-DSA-65** (FIPS 204) for every certificate and signature, **inside the protocol** — never an
envelope over a classical connection, never the hybrid. Classical configurations are classical on the wire (X25519 only).

## The 13 configurations
| family | config | port | key exchange | certificates / signatures | sender identity |
|---|---|---|---|---|---|
| HTTP | `https` | TCP 8444 | X25519 | RSA-2048 server cert | RSA-signed envelope |
| HTTP | `mtls` | TCP 8443 | X25519 | RSA-2048 both sides | client certificate |
| HTTP | `pqc` | TCP 8446 | **ML-KEM-768** | **ML-DSA-65 both sides** | client certificate |
| HTTP | `quic-classical` | UDP 4443 | X25519 | RSA server cert | RSA envelope |
| HTTP | `quic-classical-mutual` | UDP 4444 | X25519 | RSA both sides | client cert + envelope |
| HTTP | `quic-pqc` | UDP 4433 | **ML-KEM-768** | **ML-DSA-65** server cert | ML-DSA-65 envelope |
| HTTP | `quic-pqc-mutual` | UDP 4434 | **ML-KEM-768** | **ML-DSA-65 both sides** | client cert + envelope |
| CoAP | `coap-enc` | UDP 5683 | — (RSA-OAEP key wrap, AES-256-GCM) | RSA-2048 signed request + reply | envelope |
| CoAP | `coap-pqc` | UDP 5683 | — (**ML-KEM-768** key wrap, AES-256-GCM) | **ML-DSA-65** signed request + reply | envelope |
| CoAP | `coap-dtls` | UDP 5687 | X25519 (DTLS 1.3) | RSA server cert | RSA envelope |
| CoAP | `coap-dtls-mutual` | UDP 5688 | X25519 | RSA both sides | client cert + envelope |
| CoAP | `coap-dtls-pqc` | UDP 5685 | **ML-KEM-768** | **ML-DSA-65** server cert, ML-DSA-65 signatures | envelope |
| CoAP | `coap-dtls-pqc-mutual` | UDP 5686 | **ML-KEM-768** | **ML-DSA-65 both sides** | client cert + envelope |

## Layout
| path | what |
|---|---|
| `p2p/sender-role/` | the sender: `client.py` (every tech), `cli.py` (`deliver`, `fetch`, `message`, `status`, `rm`, `ml`) |
| `p2p/receiver-role/` | `server.py` (HTTP listeners: mtls/https/pqc + plain backends), `coap_server.py`, `quic_pqc_relay.py` (QUIC → HTTP), `coap_dtls_pqc_relay.py` (DTLS → CoAP), handlers |
| `p2p/common/identity.py` | certificates, signatures (RSA and ML-DSA-65 in-process), TLS group pinning (`pin_tls_groups`, `negotiated_group`) |
| `PQC-bench/aioquic-patch/` | aioquic with X25519MLKEM768 + **pure ML-KEM-768** + ML-DSA-65 (`tls.py.patch`, `add_mlkem768.py`), the QUIC client helper |
| `PQC-bench/wolfssl-py-patch/` | `aiocoap_wolfdtls.py`: CoAP over wolfSSL DTLS 1.3 (group pinning, framing with duplicate-sent short messages, timeouts) |
| `results/REPORT.md` | the final measured results, every metric and check |
| `p2p/tests/` | unit + loopback tests (`python3 p2p/tests/<test>.py`) |
| `api/p2p_levels.py` | the 21 techs grouped by security level  |
| `api/p2p_configs.py` | the 13 configs, metric meanings, verdict rule and measuring loop () |
| `p2p/tools/` | `deploy_p2p_box.sh`, `provision_identity.py`, `pair_kem_peers.sh`, `p2p_preflight.py`: put the stack on any box and prove it |
| `install/` | OpenSSL 3.5, wolfSSL DTLS and the whole PQC stack installers (`pqc-stacks-all.sh`) |

## How it is set up on a box (Raspberry Pi OS / Debian, Python 3.13, system OpenSSL 3.5)
* Code under `/opt/p2p` (this `p2p/`) and `/opt/PQC-bench` (the two patch folders); config in `/opt/p2p/.env`
  (from `p2p/.env.example`: node name, Server API, bootstrap secret, ports).
* Identities: `/var/lib/p2p/certs` (fleet CA, RSA leaf), `/var/lib/p2p/certs-pqc` (PQC CA, ML-DSA-65 leaf, ML-KEM-768
  keys in `kem/`, peers' KEM keys in `kem-peers/`), `/var/lib/p2p/certs-quic-pqc` (QUIC-PQC identity). Every leaf's SAN
  must carry the node's P2P address.
* systemd units (receiver): `p2p-receiver` (server.py), `p2p-coap-receiver`, `p2p-quic-{classical,pqc}[-mutual]-relay`,
  `p2p-coap-dtls[-pqc][-mutual]-relay`; `ufw` opens the ports above on the overlay.
* Libraries: aioquic 1.3 in `/opt/pqc-libs/quic-pqc-venv` with `add_mlkem768.py` applied; the wolfssl Python binding
  (wolfSSL 5.9 with ML-KEM / ML-DSA, DTLS 1.3) on `/opt/PQC-bench/wolfssl-py-patch`; the private OpenSSL 3.4 + oqs-provider
  only as a fallback CLI.
* The sender runs as root (the node's private keys are root-only): `cd /opt/p2p/sender-role && sudo python3 cli.py deliver <receiver> <file> <name> --tech pqc`.

## How each configuration is proven
`p2p/results/2026-10-23-pqc-mlkem768-mldsa65/run_config.sh TECH` (from an admin PC with ssh to the sender and receiver):
use cases both directions → refusal battery with control cases → wire check (handshake read off the packets) →
receiver-side records → measured campaign (16 KiB / 256 KiB / 1 MiB) → full audit → medians. `final_report.py`
writes `REPORT.md`. The measurement scripts log into the testbed boxes with `sshpass`: set your own password where they
say `CHANGE_ME_TESTBED_PASSWORD` (or switch them to SSH keys).
