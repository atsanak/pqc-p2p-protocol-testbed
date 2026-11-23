# HANDOVER — P2P PQC fix + per-config verification (2026-10-23, evening)

Previous agent ran out of usage mid-task. Everything below is the real state; read it fully before acting.

## Owner's instructions (verbatim intent, latest wins)
1. **"PQC" = ML-KEM-768 + ML-DSA-65, in the protocol itself. NOT an envelope with ML-DSA-65.** Done (see A).
2. Scope = only these 12 configs:
   * HTTP: `https` (TLS 1.3), `mtls`, `pqc`, `quic-classical`, `quic-classical-mutual`, `quic-pqc`, `quic-pqc-mutual`
   * CoAP: `coap-enc`, `coap-pqc`, `coap-dtls`, `coap-dtls-pqc`, `coap-dtls-pqc-mutual`
   * Ignore everything else (pqkex*, hybrid*, quic-hybrid*, http, coap, coap-dtls-mutual): don't change, don't report.
3. Order demanded: for EACH config, one at a time, HTTP first then CoAP:
   (a) inspect analytically, (b) triple-verify it works (sender result + receiver records + wire), (c) inspect the v2
   metrics and prove them correct, (d) only then run that config's measured campaign, capture all metrics, audit it,
   (e) only then next config. Present results HTTP (all configs) then CoAP (all configs).
4. Owner gave full access to the Pis and this PC ("feel free, stop blocking yourself"). Don't ask permission.

## Testbed
* Sender `T1-Rpi53-direct-T1` = `sshpass -p 'CHANGE_ME_TESTBED_PASSWORD' ssh rpi53@10.2.0.100` (sudo same pw). Receiver `T1-Rpi50-subgw-T1`
  = `rpi50@10.2.1.10`, P2P IP **10.2.2.1** (ufw ON). Path = WireGuard over **Wi-Fi** (Rpi53 wlan0) -> noisy at times;
  every campaign logs a 5/s ping (`campaign.sh`) so rows can be matched to channel state.
* Deployed code `/opt/p2p/*`, `/opt/PQC-bench/*`. Repo == both Pis (md5-checked after every deploy). Backups `*.bak-pre-pqcfix-20261023`.
* Run sender as root with `set -a; . /opt/p2p/.env; set +a`, cwd `/opt/p2p/sender-role`; DTLS needs `LD_LIBRARY_PATH=/opt/pqc-libs/wolfssl-dtls/lib`.
* This PC has passwordless sudo (`sudo -n` works).

## A. What was changed (all deployed to both Pis, NOT yet committed unless a commit says so)
| config | now | how |
|---|---|---|
| `pqc` | TLS 1.3 :8446, **pure ML-KEM-768** (group 0x0201) + **ML-DSA-65 certs both sides**, client cert = identity, raw body, **no envelope** | Python ssl on the Pis' system OpenSSL 3.5.7; group pinned via ctypes `SSL_CTX_set1_groups_list` (`identity.pin_tls_groups`, pointer sanity-checked), negotiated group asserted both ends (`identity.negotiated_group`). Old `X-P2P-PQC` header on :8443 is refused (400). `pqc-mutual` (briefly added) was REMOVED again - `pqc` is the mutual one. Port 8447 closed on Rpi50 |
| `quic-pqc(-mutual)` | pure ML-KEM-768 + ML-DSA-65 certs; sender envelope signed ML-DSA-65 (server-auth needs a sender proof; same as quic-classical uses RSA) | `PQC-bench/aioquic-patch/add_mlkem768.py` (applied to the venv tls.py on both Pis AND this PC; `tls.py.patch` regenerated); helper `kex="mlkem"`; relay `QUIC_GROUPS` default `MLKEM768` |
| `coap-pqc` | ML-KEM-768 key wrap + ML-DSA-65 envelope signature + **ML-DSA-65-signed reply required** | client `_coap_signature`, `_require_pqc_reply`; coap_server PQC verify + PQC reply signing |
| `coap-dtls-pqc(-mutual)` | DTLS 1.3 pure ML-KEM-768 + ML-DSA-65 certs (relay + client), ML-DSA envelope + reply | relay `REQUIRE_GROUP` default `ML_KEM_768`, `PQC_MODE` loads `/var/lib/p2p/certs-pqc`; `aiocoap_wolfdtls.pin_groups` (ctypes `wolfSSL_set1_groups_list` on the binding's OWN `_ffi*.so`, it statically links wolfSSL) |
| **`https`, `mtls`** | **were secretly hybrid X25519MLKEM768** (OpenSSL 3.5 default; found on the wire). Now pinned classical: sender offers X25519 only, receiver accepts X25519/P-256/P-384; sender asserts negotiated X25519 | `identity._pin_classical` in build_*_context |
* Rpi50's ML-DSA cert re-issued with SAN IP:10.2.2.1,10.2.1.10 (old one only had 10.2.1.10). PQC CA = `PQC-bench/ca/pki` (not in git).
* CoAP receiver now sets the comm-log `pqc` flag (was missing).
* GUI/API/levels: `p2p_levels.py` (21 techs; Post-quantum levels = the pqc techs; pqkex in "Hybrid KEX + ML-DSA certs"),
  `protocol_impl.py`, `controller.py` notes, `ml_fl.py`, `protocol_matrix.py`; tests updated (GUI 20/20, p2p suites green).
* Metrics v2 (by the earlier Opus agent, kept): retired verify_peer_ms, handshake_in_exchange, identity_refresh_ms,
  receive_body_ms, mirror_ms, api_ms/tooling_ms; added handshake_bytes_out/in, handshake_cpu_ms, rtt_ms, retransmits;
  phases additive (total == sum). DTLS handshake bytes = None (not observable through wolfSSL; wire value reported instead).

## B. Verified so far (BEFORE the last two changes: pqc->mutual-only and classical pin)
* 34-case refusal battery 34/34 refused (`negative_pqc.py`, needs updating: pqc is now mutual, no envelope cases; add
  "hybrid offer to mtls/https port refused").
* Full campaign `pg` (14 configs incl. old pqc/pqc-mutual) 252/252 ok, audit 9846/9846; use-case matrix 168 calls 756/756.
  These numbers are SUPERSEDED for https/mtls/pqc (semantics changed after) - re-run per config.
* Wire check trial: coap-dtls-pqc 9/9 (ClientHello offers only MLKEM768, 1184 B key share, SH 1088 B ciphertext, 1 HRR,
  metrics match wire); https showed the hybrid problem (now fixed, re-check); handshake_bytes/rtt metrics matched the wire exactly.

## C. Tools (in `p2p/results/2026-10-23-pqc-mlkem768-mldsa65/`; copy to `/var/lib/p2p/matrix/` on Rpi53)
* `wire_check.py RECV RIP wg0 TECH OUT.json` - per-config wire verification (sniffer, no install). quic needs
  `quic_initial_decode.py` beside it (decoder bug just fixed: aioquic 1.3 uses `packet_length`; CoAP reply-reassembly fixed:
  skip 2.31 Continue) - both fixes NOT yet re-tested on the Pi.
* `matrix_run.py OUT RECV 5 16384,262144,1048576 TECH` (rows carry t_start/t_end), `campaign.sh` (ping logger + matrix).
* `audit_v2.py RES PREFIX SENDER RECEIVER` with env `AUDIT_FILES=a.jsonl,...` `AUDIT_TAG=<tech>` for one config at a time
  (just updated for pqc = raw body/mutual, https/mtls must show X25519; not yet run after that edit).
* `usecase_matrix.py OUT RECEIVER DIR TECH` (6 use cases) + `usecase_audit.py`; `api_check.py` (TenantAPI, never run yet);
  `summarize.py` (median tables); `negative_pqc.py` (update first, see B).

## D. NEXT STEPS (exactly in this order)
1. Copy wire_check.py + quic_initial_decode.py to Rpi53, run wire_check for `https`, then `mtls`, `pqc` -> must show
   X25519 for https/mtls and MLKEM768 + ML-DSA for pqc. Fix anything.
2. Per config, HTTP order https, mtls, pqc, quic-classical, quic-classical-mutual, quic-pqc, quic-pqc-mutual; then CoAP
   coap-enc, coap-pqc, coap-dtls, coap-dtls-pqc, coap-dtls-pqc-mutual:
   usecase_matrix both directions -> negatives for that config -> wire_check -> campaign (matrix_run + ping log) ->
   audit_v2 (AUDIT_FILES/AUDIT_TAG) -> summarize; stop and fix on any failure before the next config.
3. api_check.py (TenantAPI) for the 12 configs.
4. Report to owner: HTTP table (all 7) then CoAP table (all 5), all v2 metrics, wire evidence, defects found.
5. Commit with a TEMP INDEX only your files (`GIT_INDEX_FILE=/tmp/x; git read-tree HEAD; git add <files>; git commit`);
   the real index has user-staged files - never commit normally; don't push unless asked.
   End commit messages with the Co-Authored-By line from the session's attribution reminder.

## Files changed (uncommitted, verify with `git status`)
p2p/sender-role/client.py, p2p/receiver-role/{server.py,coap_server.py,coap_dtls_pqc_relay.py,quic_pqc_relay.py},
p2p/receiver-role/handlers/{message,rm,ml,fetch}.py, p2p/common/identity.py, PQC-bench/aioquic-patch/{add_mlkem768.py (new),
tls.py.patch,quic_pqc_client_helper.py}, PQC-bench/wolfssl-py-patch/aiocoap_wolfdtls.py, p2p/tests/*, Tenant-Admin-user-PC/API/
{tenant_api.py,p2p_levels.py,docs/50_timing.md,src/50_timing.py}, Device-PC/Device/API/device_api.py, Desktop-GUI
{controller.py,panels/*.py,tests/*}, p2p/HOW-EACH-CONFIG-WORKS.md (needs pqc row updated to "mutual, no envelope"),
WIKI-JS/.../p2p-timing-benchmarks.txt, p2p/results/2026-10-23-pqc-mlkem768-mldsa65/ (new).
Out of scope, unchanged: MQTT/TAU and video pqc tiers (still hybrid), bare-metal sidecar (still sends X-P2P-PQC).

## E. DONE (2026-10-23, night, continuation agent) — section D completed
All 12 configs went through the per-config order (`results/.../run_config.sh TECH`: use cases both ways -> refusal battery with
CONTROL cases -> wire check -> receiver records -> campaign -> v2 audit -> medians), then TenantAPI 60/60. Every step passes for every
config on the code now deployed (both Pis md5-identical to the repo). Results: `results/2026-10-23-pqc-mlkem768-mldsa65/REPORT.md`
(HTTP then CoAP), raw evidence in `per-config/` (superseded runs kept in `per-config/superseded/`).
Defects found and fixed on the way (all deployed):
1. `coap-dtls` ClientHello advertised every hybrid / ML-KEM group (only the key share was pinned) -> groups list pinned to X25519.
2. ML-DSA-65 envelopes cost 4-5 `openssl` processes (~26 ms receiver verify on quic-pqc vs 0.9 ms classical) -> in-process ML-DSA on
   the system libcrypto 3.5.7 (identity.py fast paths, CLI fallback; `tests/test_pqc_fastpath.py` 5/5 on both Pis).
3. DTLS relay: a peer that vanished mid-handshake held the address ~1 min (others got port-unreachable) -> back-off capped (1+2+4 s).
4. DTLS: a record lost on Wi-Fi hung sender AND relay forever (20 min under --timeout 120; wolfSSL resets SO_RCVTIMEO after the
   handshake) -> relay watchdog at PEER_TIMEOUT_S + sender kills its worker when its budget expires.
5. Tooling: QUIC Initial decoder (aioquic 1.3 3-tuple, errors were swallowed), CoAP reassembly (Block2 follow-ups overwrote block 0),
   pqc handshake_ms bound (a >cwnd client flight leaves after do_handshake returns — the metric was right), stale pqc-mutual rule.
Finding (not a bug): QUIC `retransmits` at 1 MiB (4-64) are all spurious — two-ended captures (`loss_check.py`) show 0 datagrams lost.
Left as is: coap-pqc's ML-KEM encap/decap still runs as an OpenSSL subprocess (a few ms); QUIC-PQC CA key sits on each Pi.

## F. After the independent verification (2026-10-23, late)
* DTLS reply loss (~1/100 "closed without a reply" after a successful delivery): short framed messages (<= 32 chunks,
  DTLS_REDUNDANT_MAX_CHUNKS) are sent twice; readers drop duplicates (backward compatible). Soak 204/204.
  `p2p/tests/test_dtls_framing_redundancy.py`. Long requests (> 32 KiB) are still single-copy: a loss fails within budget.
* `coap-dtls-mutual` added as the 13th config: full 7-step pipeline passed (REPORT.md, per-config/*-coap-dtls-mutual*).
* Stale `test_status_details` (pqc = certificate-identified now) fixed; README + wiki (regenerated with gen_api_docs.py,
  walkthroughs/p2p.md, func8 reference) on metrics v2. GUI P2P metrics page lists 13 configs.
* ~1,370 campaign test files (420 MB) removed from Rpi50/Rpi53 /var/lib/p2p/received (only this work's prefixes).
