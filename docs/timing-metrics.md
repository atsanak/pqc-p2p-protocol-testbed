# 50 — Timing of sending: P2P phases, TAU connect cost, TAU RPC round trip

**Source:** `TenantAPI.p2p_timing / timing_stats / p2p_time / mqtt_connect_probe / rpc_time`, plus the
`timing` block every `p2p_*` result now carries (`p2p/sender-role/client.py` `_Timing`, receiver share
from `p2p/receiver-role/server.py`). Probe script: `mqtt_connect_probe.py`. Example:
`src/50_timing.py` (`selftest` is offline; `p2p` / `mqtt` / `rpc` are DRY-RUN unless `--run`).
Why this exists: `WIKI-JS/RUNBOOK/RUNBOOK-Functionalities/docs/func11-benchmarking-readiness.md`.

**The rule.** Every phase is timed where it happens, on a **monotonic clock on the box that lives it**,
and comes back in one shape. No number here needs two boxes' clocks to agree.

## P2P — the `timing` block on every `p2p_*` result

`p2p_status`, `p2p_message`, `p2p_deliver` (incl. `put_file=True`), `p2p_remote_exec` and `p2p_ml` all
return `timing` — measured by the SENDER box, not by this PC:

Reshaped 2026-10-23 (v2,): the phases are **additive on
every tech** (`total_ms` == the sum of the non-None phases), `handshake_ms` always includes the check of
who answered, and five transport observations were added. Not-applicable is `None`, never `0`. Verified
live on the 13 in-scope techs (https, mtls, pqc, quic-classical(-mutual), quic-pqc(-mutual), coap-enc,
coap-pqc, coap-dtls(-mutual), coap-dtls-pqc(-mutual)); the others only keep working (smoke-tested).

| Key | What it measures |
|---|---|
| `resolve_ms` | the sender's `GET /resolve` (a Server hop). The signing key / `cryptography` import it needs is loaded when the sender starts, so a fresh process no longer books ~45 ms of import here |
| `peer_cert_ms` | `coap-enc` only: fetching the receiver's cert from the Server to encrypt for |
| `tcp_connect_ms` | TCP connect (`https`, `mtls`, `pqc`, `http`); `None` where there is no TCP of the sender's own (QUIC, CoAP, and the openssl-subprocess techs `pqkex*`/`hybrid*`) |
| `handshake_ms` | the handshake **including the check of WHO answered** (CN + SAN IP, or the name aioquic checks). `https`/`mtls`/`pqc`: measured by the sender around the TLS handshake + its CN/SAN check. `quic-*`: measured inside the client helper (aioquic checks the name inside the handshake; the helper then checks the SAN IP before any data). `coap-dtls*`: measured inside the DTLS worker, which also checks CN + SAN IP before writing any data. `None` where there is no handshake (`http`, `coap`, `coap-enc`, `coap-pqc`) or it cannot be split out (`pqkex*`, `hybrid*`: their handshake runs inside the openssl subprocess, i.e. inside `exchange_ms`) |
| `prepare_ms` | building the request: signing the envelope; on `coap-enc`/`coap-pqc` also encrypting |
| `client_overhead_ms` | `quic-*`/`coap-dtls*` only: starting and stopping the helper / worker process (spawn, imports, orderly close). `None` on every other tech |
| `exchange_ms` | request out → reply fully read (includes the receiver's work); on `quic-*`/`coap-dtls*` the helper's own request→reply phase, so never a handshake or a process start-up |
| `receiver_ms` | the receiver's own work, on ITS clock (`receiver_timing.total_ms` of the reply) |
| `network_ms` | `exchange_ms − receiver_ms`: the wire both ways, plus any local relay / front door |
| `total_ms` | first phase to last; equals the sum of the phases above |
| `request_bytes` / `response_bytes` | the request body / reply as the application framed them (envelope included) |
| `handshake_bytes_out` / `handshake_bytes_in` | transport payload bytes the sender sent / received until ITS handshake completed (incl. its Finished; not the tickets after it). TLS over TCP: TLS record bytes from the kernel's `TCP_INFO` (`bytes_sent − bytes_retrans + notsent_bytes`, `bytes_received`) read right after the handshake. QUIC: UDP payload bytes (QUIC packets incl. padding) counted at the helper's socket. `None` on DTLS (wolfSSL drives the socket in C with no I/O hook), CoAP and the openssl-subprocess techs. This is where ML-KEM / ML-DSA cost shows |
| `handshake_cpu_ms` | CPU time (user+sys) the sender spent in the handshake: the calling thread's CPU clock around the TLS handshake, the QUIC helper's / DTLS worker's process CPU clock around theirs. The compute share of `handshake_ms`; the rest is waiting for the network and the peer |
| `rtt_ms` | the transport's own minimum round-trip time over this connection (TCP `TCP_INFO.min_rtt`, QUIC min RTT); `None` on CoAP/DTLS |
| `retransmits` | what the sender re-sent: TCP segments (`TCP_INFO.total_retrans`), QUIC packets declared lost, CoAP CON messages re-sent by aiocoap; `None` where not observable (DTLS) |
| `negotiated` (top-level key of a `quic-*` / `coap-dtls*` result, also in the sender's `sent.log`) | what the handshake OBSERVABLY negotiated, read off the ServerHello / the DTLS session, not assumed: `group` (`X25519` / `X25519MLKEM768`), `tls_version`, `tls_cipher` + `tls_bits` (QUIC; wolfSSL does not expose the DTLS cipher), `tls_peer_key` / `tls_peer_sig` / `tls_ca` of the server certificate. The sender REFUSES, before any data leaves, a handshake whose group (or, on QUIC, certificate key type) is not the one the tech is defined by |
| `receiver` | the receiver's own phases: `verify_ms` (sender identity), `authorize_ms` (the Server policy check), `decrypt_ms` (CoAP only: `coap-enc`/`coap-pqc`; `None` where nothing was encrypted), `handler_ms` (the use case itself). Their total is `receiver_ms` |

Retired 2026-10-23 v2 (removed from the sender, the receivers, `TenantAPI`, the GUI's P2P-shaped blocks,
the CSV export, the tests and the docs): `verify_peer_ms` (a constant ~0.2 ms after the in-process
identity checks; now inside `handshake_ms`), `identity_refresh_ms` (never set in any recorded run; a
handshake retried after an identity refresh is now rewound so the block describes the retry alone),
`handshake_in_exchange` (constant per tech; the phases are additive now), the receiver's
`receive_body_ms` (overlapped the transfer, was already inside `network_ms`, and behind a relay only
timed the relay's loopback copy) and `mirror_ms` (the CoAP mirror hand-off; the mirror now starts after
the reply), the nested `receiver.total_ms` (= `receiver_ms`), the constant `clock` strings, and
`TenantAPI`'s `api_ms` / `tooling_ms` (this PC's ssh plumbing).

`_api_ms` (added by `_p2p_cli` to the raw result) is this PC's wall time for the call, **ssh hop to the
sender included** — a call-latency annotation, never a benchmark number (measured live it is 3–5×
`total_ms`); it is not copied into the timing views.

**CoAP receivers** (`coap_server.py`, which also serves `coap-dtls*` behind their relays) return their
share inside the signed response. Since 2026-10-23 v2 the Server mirror and the `on_p2p` event start only
after the reply has gone out (before, the mirror thread took the GIL from the reply for ~4 ms); the HTTP
receiver (`server.py`) now also posts its mirror off the request thread, so a request thread and its
connection are never held open for it.

**Deployment (rolled out 2026-09-30):** `client.py`, `server.py`, `coap_server.py`, `coap_crypto.py`
(and `video_http_server.py` where present) on every reachable node of V1, T1 and T-theo (20 nodes, only
files matching a committed version replaced, `.bak-pre-timing` kept, receivers restarted and active).
Not reached: T-pash (no `/opt/p2p` on its ssh path), the `*-coapdtls-test` / `*-mqttmtls-test` identities
(no ssh mapping), bare-metal leaves (firmware, no timing). An older sender returns no `timing` at all
(`p2p_time` stops and says so); an older receiver leaves `receiver_ms` `None`. The 2026-10-23 v2 shape is
deployed on T1-Rpi53-direct-T1 and T1-Rpi50-subgw-T1 only; a v2 sender drops an older receiver's retired
keys (`receive_body_ms`, `mirror_ms`, `total_ms`, `clock`) from its `receiver` block, so the shape is the
same whichever receiver answered.

### `p2p_timing(result)` (static)
One call's timing, flattened: the block above and `receiver_<phase>` for each receiver phase (protocol
measurements only; the result's `_api_ms` is not copied in). `None` if the result has no `timing`.

### `timing_stats(values)` (static)
`{n, min, p50, p95, max, mean, stdev}` in ms over `values` (`None` skipped), else `None`. Same
nearest-rank quantiles as `video_p2p_latency`.

### `p2p_time(sender, receiver, use_case="status", tech=None, n=5, warmup=1, size=1024, timeout=60)`
Repeat ONE use case `n` times after `warmup` untimed runs, sequentially. `use_case` ∈
`P2P_TIME_USE_CASES` = `status` (no payload) · `message` (JSON padded to `size` bytes) · `file` (`size`
random bytes, stored as `p2p_received/timing-probe.bin`, overwritten each run). `tech` ∈ `P2P_TECHS`
(`None` = `mtls`). Each run opens its own connection, so every sample includes the handshake.
Returns `{ok, sender, receiver, use_case, tech, n, warmup, size, samples: [p2p_timing(...)],
failures: [{i, warmup, reason, denied}], stats: {phase: timing_stats}}` (`TIMING_PHASES` lists the
phases and the transport observations; `timing_stats` works on bytes and counts as well as ms).

## TAU — the Tenant-Admin → ThingsBoard → device leg

A device's MQTT session is **persistent**: its handshake is paid once per (re)connect, never per
command. So TAU has two separate timings:

### `mqtt_connect_probe(name, n=5, mode=None, host=None, port=None, pause=0.2, timeout=None)`
The connect cost. Pipes `mqtt_connect_probe.py` to device `name` over ssh (nothing installed) and opens
`n` fresh MQTT connects to the SAME endpoint the device's daemon uses for its `MQTT_MODE` (or `mode`),
timed on the device: `tcp_ms`, `handshake_ms` (TLS; `0` on plain), `connack_ms` (CONNECT → CONNACK),
`total_ms`. On the four PQC modes (`pqc`, `pqc-mutual`, `quic-pqc`, `quic-pqc-mutual`) the handshake runs
inside the device's local bridge as it dials the broker, so `handshake_ms` is `None` and the cost is in
`connack_ms` (`handshake_in: "connack_ms"`) — compare modes by `total_ms`.
The CONNECT is anonymous with its own client id (`tb-timing-probe-…`), so the device's own session is
untouched; brokers answer `rc=2`/`5` after the handshake, and on `mtls` (cert = identity) `rc=0`, after
which the probe disconnects at once. `host`/`port` override the endpoint (e.g. a `.env` naming
`host.docker.internal`). Returns `{ok, device, mode, mode_source, direct, host, port, kind,
handshake_in, samples, n_ok, stats: {phase: timing_stats}}`. Devices only (reads the device `.env`).

### `rpc_time(name, n=5, warmup=1, method="timing_ping", timeout=10)`
The steady-state command round trip, timed on THIS PC: Tenant-Admin → TB REST (direct device) or →
Server → gateway (gateway-routed device, `route: "gateway"`) → device over its open MQTT session → reply.
The default method is one the device does not know: it answers `{"status": "unknown_method"}` at once,
so the transport is timed, not a handler (pass a real method to include one). Always the direct path,
never an armed P2P impersonation. Returns `{ok, device, route, method, samples: [{ms, ok, reply}],
failures, stats}`.

```python
api = TenantAPI(control="v1-admin-0@tb.tb")
r = api.p2p_time("V1-direct2-V1", "V1-direct1-V1", use_case="file", tech="mtls", n=10, size=65536)
print(r["stats"]["handshake_ms"]["p50"], r["stats"]["exchange_ms"]["p50"])
one = api.p2p_status("V1-direct2-V1", "V1-direct1-V1", tech="https")
print(api.p2p_timing(one))                                    # one call, flat
print(api.mqtt_connect_probe("V1-direct1-V1", n=5, mode="tls")["stats"]["handshake_ms"])
print(api.rpc_time("V1-direct1-V1", n=10)["stats"])
```
```
python3 src/50_timing.py selftest                                       # offline, verified
python3 src/50_timing.py p2p V1-direct2-V1 V1-direct1-V1 --tech mtls --use-case file --size 65536 --run
python3 src/50_timing.py mqtt V1-direct1-V1 --mode tls --run
python3 src/50_timing.py rpc V1-direct1-V1 --n 10 --run
```

## Verified 2026-09-30

- **Offline:** the real `client.py` against the real `server.py` + `coap_server.py` in-process on
  localhost (Server hops stubbed): `status` / `message` / `file` × `http`, `https`, `mtls`, `coap`,
  `coap-enc` — 15/15 return `timing`, the receiver share nested, the phases summing to `total_ms`.
  `mqtt_connect_probe.py` against a local mosquitto: `plain` (rc 5), `tls` (TLSv1.3), `mtls` (rc 0).
- **Live, V1** (sender `V1-direct2-V1`, receiver `V1-direct1-V1`, the new files deployed on those two
  only, `.bak-pre-timing` kept): `p2p_time` n=5 for `status` and a 64 KiB `file` on `http`, `https`,
  `mtls`, `coap`, `coap-enc`, `pqkex` — all 60 samples OK. `rpc_time`: p50 ≈ 101 ms (direct), ≈ 145 ms
  (via gateway). `mqtt_connect_probe` on `V1-direct1-V1`: `plain`, `tls` (handshake p50 ≈ 10 ms), `mtls`
  (rc 0 — the device kept publishing, its session untouched); `pqc` refused cleanly (no local bridge
  running on that box).

## Found while building it: a ~40 ms Nagle stall on every TLS reply (fixed in `server.py`)

The receiver sends each reply as two writes (headers, then body). On TLS connections Nagle held the
second until the first was ACKed and the sender's delayed ACK waited ~40 ms: a constant +40 ms on every
`mtls`/`https`/`pqc` exchange (localhost: `network_ms` p50 41 ms → 2 ms with the fix). The stunnel front
doors in front of `pqkex*` already set `TCP_NODELAY`, so before the fix the classical techs looked ~40 ms
slower than PQC for a reason unrelated to crypto. `Handler.setup()` now sets `TCP_NODELAY`. Deployed on
`V1-direct1-V1` only so far.

## `timing_csv(result, path, stats=True, append=False)` (class method) — CSV export

Writes a `p2p_time`, `mqtt_connect_probe` or `rpc_time` result (the shape is detected) to CSV. It
writes one row per sample: first the context columns (`TIMING_CSV_CONTEXT`), then every phase in ms.
The context columns are:
- `leg`: `p2p` or `tau`
- `kind`: `p2p_time`, `mqtt_connect` or `rpc`
- `use_case`: the P2P use case, the MQTT mode, or the RPC method
- `tech`: the P2P tech, the MQTT endpoint kind, or the RPC route
- `sender`, `receiver`, `device`, `size`, `sample`

`stats=True` also writes `<stem>_stats.csv`, with one row per phase: `phase,n,min,p50,p95,max,mean,stdev`.
The column set is fixed (the union of every phase), so `append=True` can gather several runs into one
sheet under a single header, e.g. one run per tech. Returns `{samples, stats, rows}`.

```python
for tech in ("http", "https", "mtls", "pqkex"):
    r = api.p2p_time("V1-direct2-V1", "V1-direct1-V1", use_case="file", tech=tech, n=10, size=65536)
    api.timing_csv(r, "p2p_file_64k.csv", append=True)
```
```
python3 src/50_timing.py p2p V1-direct2-V1 V1-direct1-V1 --tech mtls --run --csv outputs/p2p.csv --append
```
`selftest` writes all three shapes into `src/outputs/timing_selftest.csv` (+ `_stats.csv`) and checks
the row counts.

## FL round timing (2026-09-30)

`fl_run` / `fl_run_round` / `fl_run_round_broadcast` (Controller, surfaced by the API) now time every
round on **this PC** (`perf_counter`), purely additively (`duration_s` is unchanged):

| Where | Key | What |
|---|---|---|
| each result (per client) | `distribute_ms` | delivering the round's weights to that client (`ml_deliver_model`, pull or inline) |
| | `train_ms` | the `train_step` round trip as seen from this PC (TB RPC, or the P2P sender when impersonation is armed) |
| | `fetch_ms` | big models only: fetching the trained weights back from the Server |
| | `total_ms` | the client's whole turn |
| | `device_train_ms` | the device's own compute time IF its reply carries one (`train_ms` / `duration_*` / `elapsed_*`); today's `train_step.py` does not, so `None` |
| | `p2p` | P2P impersonation only: the sender's phase block (above) for the `train_step` call |
| history entry (per round) | `distribute_ms`, `train_ms` | sums over the clients |
| | `clients_ms` | wall time of the client phase — clients run **one after another** on the RPC path |
| | `aggregate_ms` | the FedAvg averaging; `server_opt_ms` the server optimizer step (fl_run only) |
| | `round_ms` | all of `fl_run_round` |

After a bare `fl_run_round`, the round-level block is at `api.c.fl_last_round_timing`.
**Broadcast rounds:** there is no per-client delivery; `distribute_ms` is the publish (plus the
per-node weights delivery for models too big to embed), and `train_ms` runs from the publish until the
poll that SAW the client's `fl_done` — the poll steps 1 s (`resolution_ms: 1000`), so it is coarse.

Verified: offline (stubbed deliver/RPC: RPC path, P2P path with `p2p` attached, broadcast path, and
`fl_run` 2 rounds) and live on V1 (`fl_run_round`, `Neural_network_example`, V1-direct1 + V1-direct2,
the devices' own weights restored byte-identical afterwards): per client distribute ≈ 440–477 ms,
train ≈ 163–176 ms; round 1258 ms, aggregate 0.06 ms.


## Nagle audit (2026-09-30)

Looked for the same Nagle + delayed-ACK stall that `p2p/receiver-role/server.py` had: a Python/broker
server writes a reply as two sends, the second is held until the first is ACKed, and the peer's delayed
ACK waits ~40 ms. **On a real link it mostly does not appear. Over localhost, and on an accepted MQTT
connect, it does.** Several PQC paths go through exactly such a localhost hop.

**Video HTTP/1.1 backend (`video-streaming/video_http_server.py`) — real, fixed, deployed on T1-Protectli1.**
- Offline (the real Handler, cv2 stubbed, keep-alive `GET /frame` loop): 41.1 ms/frame on plain,
  42.0 ms/frame on https → 0.10–0.11 ms with `TCP_NODELAY`.
- Live, before the fix:
  - classical listeners on 10.2.0.101 :8091 (plain) / :8092 (https): 3.0–3.5 ms/frame from asus14 and
    6–7 ms/frame from T1-Protectli2 — no stall on the real link.
  - the localhost backend `127.0.0.1:8090`: **47 ms/frame**. The stunnel PQC tiers :8094–:8097 all
    `connect = 127.0.0.1:8090`, and the QUIC/H3 relays forward to the same backend.

  So on the live box the bias ran the other way: the PQC/hybrid HTTP tiers paid about +40 ms per frame,
  and the classical ones did not.
- After the fix: `127.0.0.1:8090` is 0.90 ms/frame; the classical tiers are unchanged (2.9–3.0 ms).
  TAU views stay 40/40 valid frames on plain, https, mtls, pqc, pqc-mutual and hybrid.
- `/camera` is ~100 ms/frame, paced by the 10 fps camera, not by Nagle.
- Deployed: `/opt/testvideo/video_http_server.py` on T1-Protectli1 only (md5 `37bc748ab0cf`; the box
  had HEAD `e94360641bcd`, backup `.bak-pre-nodelay`). Restarted only `video-http-backend` and
  `video-http1@{plain,https,mtls}`.

**mosquitto on gateways — real on accepted connects, measured only, NOT changed.**
- The T1-Protectli2 gateway broker (`mosquitto-t1-protectli2-gw-t1`) has no `set_tcp_nodelay` line, so
  it runs at the default, false. Classical ports 1883/8883/8884 go through `docker-proxy`; the PQC
  bridges :9445/:9448/:9450/:9451 go through stunnel.
- `mqtt_connect_probe`, p50, T1-P2-dev-by-gw (T1-P2-pqcmqtt-dev agrees within 1 ms):

  | mode | tcp | handshake | connack | total |
  |---|---|---|---|---|
  | plain | 3.4 | 0 | 2.4 | 5.9 |
  | tls | 3.1 | 9.8 | 3.4 | 17.0 |
  | mtls | 3.3 | 11.0 | **46.5** | 61.3 |
  | pqc | 0.7 | — | 12.3 | 12.8 |
  | pqc-mutual | 0.7 | — | 12.7 | 13.1 |

- Local mosquitto reproduces it: `mtls` connack 41.8 ms → **0.76 ms with `set_tcp_nodelay true`**;
  `tls` stays 0.1 ms either way.
- The stall is on the ACCEPTED connect path (rc 0). The probe's anonymous CONNECT is rejected (rc 5) on
  every mode except `mtls`, where the certificate is the identity. So the 40 ms appears only in the
  `mtls` row. **Do not read it as an mtls cost.** A real device connection is always accepted, so in
  practice every mode pays it, including the PQC bridges, since stunnel hands off to the same broker.
- Steady-state publish → receive latency was not measured (it needs device credentials).
- **Proposed, not done:** add `set_tcp_nodelay true` to the gateway mosquitto config (and the
  `mosquitto-aio` FL broadcast broker), then restart the broker. It restarts every device session on
  that gateway, so it needs the operator's OK. Also still open: V1 ThingsBoard `mtls` connack 37 ms vs
  `tls` 17 ms — the accepted path does more work (a device lookup by cert), so that gap is not proven
  to be Nagle.

**Other Python TCP servers with the same pattern** (`BaseHTTPRequestHandler`, no `TCP_NODELAY`),
not measured:
- **Data path, likely affected (HTTP/1.1 keep-alive):**
  - `PQC-bench/telemetry-proxy/telemetry_pqc_sign_proxy.py`, `telemetry_pqc_verify_proxy.py` (the PQC
    telemetry HTTP legs, localhost hops).
- **Data path, low risk (HTTP/1.0, one request per connection, so quick-ACK usually saves it):**
  - `Gateway-PC/Gateway/python/gateway_provision_proxy.py` (provisioning, `GET /models/<name>` pull via
    the gateway).
- **Control/management only:**
  - `Router-PC/Router/route_api.py`, `p2p/API/p2p_api.py`, `Device-PC/Device/device_health_proxy.py`,
    `bare-metal/host-side/bm_health_proxy.py`, `A-Physical-Testbed/Tenant-Admin-PC/join_listener.py`
  - the attest/SE agents, `bare-metal/targets/.../luckfox/agent.py`
  - `on_dev_api_service.py` (unix socket — not TCP)
- The Server (FastAPI/uvicorn on asyncio) and ThingsBoard (Netty) set `TCP_NODELAY` themselves.

## Video startup time

Per-frame latency is the same whatever the tier (the media is symmetric AES either way). What the tier
changes is the SETUP, so every viewer now times its start on its own monotonic clock
(`capture_time.Startup`) and prints one line, e.g. `[client] startup_ms connect=4.3 handshake=5.3
session=6.2 first_frame=16.3`. Every video view method returns it as `startup` =
`{connect_ms, handshake_ms, session_ms, first_frame_ms}` (`TenantAPI.video_startup(result)` reads it; docs/41).
**Compare tiers by `first_frame_ms`** (start → first complete frame); the other three say where it went.

| Leg | `connect_ms` | `handshake_ms` | `session_ms` | `first_frame_ms` |
|---|---|---|---|---|
| MJPEG / MQTT (`video_subscriber.py`) | paho `connect()`: TCP **and** TLS in one call | `None` (inside `connect_ms`) | CONNACK + SUBSCRIBE → SUBACK; through a local PQC bridge, the bridge's upstream handshake lands here | start → first frame; includes waiting for the publisher's next frame (≤ 1/fps) |
| HTTP/1.1 (`video_http_client.py`) | TCP | TLS alone (`https`, `mtls`); `None` on `plain` and on `pqc*`/`hybrid*` (local stunnel client — their handshake lands in `session_ms`) | first GET → response headers | start → first decoded frame |
| HTTP/3 (`video_http3_client.py`) | UDP endpoint (no round trip) | QUIC + TLS 1.3 | first GET → whole response | start → first decoded frame |
| RTP + DTLS-SRTP (`rtp_dtls_srtp_receiver.py`) | `None` (UDP; this end is the DTLS server) | ClientHello → DTLS 1.3 done | the CoAP session-control exchange's P2P `timing.total_ms` (sender clock) when the result carries one, else `None` | ClientHello (or, `--plain`, first packet) → first complete frame |
| P2P frame stream (`video_stream_p2p`) | — | — | — | not a stream: each step is a P2P delivery, timed by its own P2P `timing` block (above) |

**Live, T1, TAU leg (source T1-Protectli1-direct-T1, viewer = this PC), 2026-09-30, one run each (ms):**

| Leg · tier | connect | handshake | session | first_frame |
|---|---|---|---|---|
| MQTT plain | 2.1 | – | 5.1 | 64.9 |
| MQTT tls | 9.3 | (in connect) | 46.7 | 126.0 |
| MQTT pqc | 2.8 | (in session) | 13.2 | 113.2 |
| HTTP/1.1 plain | 2.0 | – | 8.7 | 11.4 |
| HTTP/1.1 https | 4.3 | 5.3 | 6.2 | 16.3 |
| HTTP/1.1 pqc | 0.8 | (in session) | 19.8 | 21.3 |
| HTTP/3 classical | 0.3 | 18.6 | 8.0 | 27.7 |
| HTTP/3 pqc (Stack 5) | 0.3 | 24.5 | 11.0 | 37.7 |
| HTTP/3 hybrid | 0.3 | 19.9 | 10.1 | 31.0 |
| RTP plain | – | – | – | 3.0 |
| RTP classical DTLS | – | 5.1 | – | 39.9 |
| RTP pqc DTLS (Stack 3) | – | 4.4 | – | 32.9 |

Single runs: take the p50 of several before comparing. The MQTT `first_frame` is dominated by the
publisher's frame interval (8 fps). Offline check: a local mosquitto (plain) and a local
`video_http_server.py` (plain + TLS) gave the same line shape.

**Not yet on the device-viewer (P2P) legs.** The TAU viewers run from this checkout, so they already
have it. The device-side copies under `/opt/testvideo` get it only with `video_stream_deploy_scripts`,
which was NOT run here: it would also push `video_http_server.py`, which is being changed separately.
Until then, a device-leg result has `startup: None`.

## TAU delivery and command timing (2026-09-30)

The TAU calls for C&C, ML delivery and file delivery now return a `timing` block too, measured on THIS
PC's monotonic clock (the device's MQTT session is already open, so there is no handshake in these):

| Call | `timing` keys |
|---|---|
| `deliver_rpc(...)` (file delivery / C&C put), `transport="pull"` | `upload_ms` (to the Server), `put_file_ms` (the put_file RPC: the device fetches from the Server, checks sha256, writes), `total_ms`, `bytes` |
| `deliver_rpc(...)`, `transport="inline"` | `chunks_ms` (the put_file_chunk RPCs), `chunks`, `put_file_ms`, `total_ms`, `bytes` |
| `ml_deliver(...)` | `stage_ms` (pull: uploads to the Server; inline: the deliver_model_chunk calls), `deliver_model_ms` (the deliver_model RPC; pull: the device's fetch is inside it), `files`, `chunks`, `bytes`, `total_ms` |
| `exec_rpc(...)` | `dispatch_ms` only: the exec RPC returns when the job is ACCEPTED |
| `exec_rpc_timed(name, cmd, timeout=60, job_id=None, cwd=None, poll=0.2)` | runs `exec_rpc`, polls `job_status` to a terminal state: `dispatch_ms`, `observed_run_ms` (accepted → terminal seen here; resolution = `poll`), `device_run_ms` (the job's own start → finish on the device's clock, from `list_jobs`; `None` on a device without it), `total_ms`, `polls`. Also returns `ok`, `state`, `exit_code`, `stdout_tail`. |

With armed P2P impersonation the same keys are measured, but the RPCs then ride P2P.

**Live, V1-direct1 (60 KB):** `deliver_rpc` pull 181 ms (upload 94 + put_file 87), inline 317 ms
(3 chunks 215 + put_file 101); `ml_deliver` pull 170 ms, inline 452 ms; `exec_rpc_timed("sleep 0.5;
echo hi")`: dispatch 46 ms, observed run 735 ms, device run 541 ms, total 781 ms.
(The test delivered to a throw-away model `timing-probe-model`, left on V1-direct1.)

## Live 2026-09-30: FL over P2P, and P2P-leg video startup

**FL over P2P** (V1-direct2 → V1-direct1, `fl_run_round`, weights restored byte-identical after):
each client's `timing` carries the sender's full P2P block under `p2p` — `mtls`: handshake 3.6 ms,
receiver handler 102 ms, network 2.3 ms, P2P total 172 ms (client total 2137 ms); `pqkex`: handshake
inside exchange, exchange 431 ms, network 179 ms, P2P total 459 ms (client total 1996 ms).

**Video startup, P2P leg** (T1-Protectli1 → device viewers T1-Protectli2-gw-T1 / T1-P2-dev-by-gw,
viewer scripts deployed there 2026-09-30; one run each, ms — connect / handshake / session / first frame):

| Leg | plaintext | classical | PQC | hybrid |
|---|---|---|---|---|
| HTTP/1.1 | 3.1 / – / 7.5 / 11.3 | 4.4 / 6.8 / 5.5 / 18.6 | 1.3 / in session / 31.1 / 32.9 | 1.2 / in session / 24.0 / 25.9 |
| HTTP/3 | – | 0.4 / 15.8 / 9.0 / 25.8 | 0.5 / 21.5 / 10.4 / 32.9 | 0.5 / 23.9 / 11.2 / 36.2 |
| RTP + DTLS-SRTP | first frame 1.9 | handshake 14.6, first frame 40.8 | handshake 15.5, first frame 41.1 | – |
| MQTT | 1.8 / – / 2.3 / 62.6 | 6.4 / in connect / 45.0 / 151.1 | 3.1 / in session / 9.1 / 64.6 | – |

RTP `session_ms` is empty on this leg because T1-Protectli1/2 still run the pre-timing P2P sender (the
session control's P2P timing is what fills it). MQTT's first frame is dominated by the publisher's frame
interval.

### mosquitto `set_tcp_nodelay` (2026-09-30)

`Gateway-PC/docker/gw/generate_compose.py` now renders `set_tcp_nodelay true` (global) into every
gateway's `mosquitto_auth.generated.conf`, so the next broker regeneration carries it. Baseline measured
before the change (`mqtt_connect_probe` from a child device, accepted `mtls` connect, connack p50):
V1-gw 43.7 ms, V1-subgw 45.8 ms, T1-Protectli2 47.7 ms, T1-Rpi50 51.9 ms (plain/tls rejected connects:
1–6 ms). Applying it to the running gateways (add the line + restart the broker container, which briefly
drops that gateway's device sessions) is an operator step: `apply_mosquitto_nodelay.py` — **applied
2026-09-30 on all four**. After: accepted `mtls` connack p50 V1-gw 3.4 ms, V1-subgw 3.2 ms, T1-Protectli2
4.3 ms, T1-Rpi50 6.5 ms (from 44–52 ms); child devices publishing again within seconds.
