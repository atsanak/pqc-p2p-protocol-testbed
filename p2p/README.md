# p2p/

The P2P peer service — device/direct/gateway/sub-gateway-to-device-etc. communication, independent
of the MQTT/TB stack. Implements `p2p-requirements.md` and `management/requirements/p2p-plan..md`
(read the plan first; this file is just the layout map).

```
p2p/
  sender-role/           # runs on the SENDER node
    client.py            # the sender; resolve() -> connect -> request, on any of the four techs
    cli.py                # mode-2 developer entry point ("Sender API"); `--tech`
  receiver-role/         # runs on EVERY node — the peer server
    server.py             # TWO listeners: mutual-auth (mtls/pqc) + server-auth-only (https)
    coap_server.py        # the CoAP/UDP transport (techs `coap-enc` and `coap`), all use cases
    policy_client.py       # asks the Server whether this pair is allowed (§4.3 join)
    handlers/             { file_delivery.py · message.py · status.py · rm.py }
  common/                 { identity.py (TLS/cert/resolve/authorize) · wire.py (envelope) ·
                            errors.py · rm_limits.py (the rm use case's shared time budget) }
  .env.example
  README.md
```

## Use case × tech — two independent axes

Operator-directed, 2026-07-28: *"a use case is different than a tech — a use case e.g. message can
be sent with each tech, and not only with a specific one."* The **use case** is what is exchanged;
the **tech** is how it is protected. All sixteen combinations work:

|            | `mtls` | `https` | `pqc` | `coap-enc` | `coap` |
|------------|:------:|:-------:|:-----:|:----------:|:------:|
| `message`  |   ✓    |    ✓    |   ✓   |     ✓      |     ✓      |
| `file`     |   ✓    |    ✓    |   ✓   |     ✓      |     ✓      |
| `status`   |   ✓    |    ✓    |   ✓   |     ✓      |     ✓      |
| `rm`       |   ✓    |    ✓    |   ✓   |     ✓      |     ✓      |
| `ml`       |   ✓    |    ✓    |   ✓   |     ✓      |     ✓      |

`rm` (2026-07-28) is **device→device remote management**: `POST /rm-exec`, the receiver runs the
command and returns its exit code and both streams. It is a use case like any other precisely
*because* it is the strongest one — going through the same route table means it inherits the same
identity gate, the same per-pair policy check and the same mirror, instead of growing a second,
weaker door. Two things are specific to it:

- `P2P_RM_ENABLED=0` in a node's `.env` makes that node refuse peer-driven RM outright, whatever
  the policy says, and say so in the refusal. `P2P_RM_ALLOW` narrows it to a list of command
  prefixes. Both are node-local; neither is reachable from the network.
- Every command is appended to the receiver's own `/var/lib/p2p/rm.log` **before** it runs, so a
  command that takes the node down still leaves the record of who asked for it.

Worth stating plainly: the in-tenant policy default is `allow`, so out of the box every device in a
tenant can run commands on every other device in that tenant. Cross-tenant does not have this
property — it defaults to `deny` and needs both tenants' consent.

`ml` (2026-07-29) is **ML over P2P**: `POST /ml-op`, the receiver performs ONE enumerated ML
operation on itself and returns its device/gateway agent's own answer. It is what the ML GUI tab's
"P2P on behalf of sender" mode drives — the tenant admin coordinates, the sender acts.

It is a use case rather than a shell line sent through `rm`, and that is the whole design:

- **an enumerated verb list, not a command.** `handlers/ml.py`'s `ML_METHODS` is the entire surface
  (registry · delivery · run · parameters · inference). `exec`/`put_file`/`cancel`/`set_policy` are
  deliberately absent — that is the RM surface and it has its own gate.
- **the receiver does not reimplement ML.** The operations live in the device/gateway agent inside
  the node's container; the receiver runs on the VM. It hands the call over a bind-mounted spool
  (`/var/lib/p2p/ml-spool`) and returns the agent's own payload, so a P2P `run_model` and a
  ThingsBoard `run_model` are the same code publishing the same telemetry. `p2p_ml_agent.py` (in
  `Device-PC/Device/`, mirrored into the Gateway role) is the other half.
- **`P2P_ML_ENABLED=0` / `P2P_ML_ALLOW`** are the node-local controls, mirroring `rm`'s. Every call
  is appended to `/var/lib/p2p/ml.log` before it is dispatched.

A spool with nobody servicing it is reported as exactly that ("the device/gateway container is
down, or was built without p2p_ml_agent.py") rather than as a timeout — the true diagnosis.

| tech | transport | who the handshake authenticates | where the sender's identity comes from |
|---|---|---|---|
| `mtls` | HTTPS on `:P2P_PORT` | both peers | the TLS peer certificate (the strongest, and the default) |
| `pqc` | HTTPS on `:P2P_PORT` | both peers | the peer certificate **and** a matching ML-DSA-65 envelope |
| `https` | HTTPS on `:P2P_HTTPS_PORT` | the receiver only | an RSA-signed envelope in the body |
| `coap-enc` | CoAP/UDP on `:P2P_COAP_PORT` | neither (no handshake) | an RSA-signed envelope; the payload is also encrypted to the receiver |
| `coap` | CoAP/UDP on `:P2P_COAP_PORT` | neither (no handshake) | an RSA-signed envelope; the payload is **cleartext** |

`coap` (2026-08-10) is RFC 7252's NoSec mode with authenticity kept on top. It gives up
**confidentiality and nothing else**: anyone who can see the UDP traffic reads the payload, but
the signed cert envelope and the per-pair policy check are byte-for-byte `coap-enc`'s, because
dropping those would leave the receiver unable to say who is talking to it and make the policy
table decorative. It exists for constrained nodes that cannot afford RSA-OAEP+AES-GCM per
message. The receiver picks the tech from WHICH KEY the envelope carries (`encrypted` vs
`payload`), never from a client-supplied label — a sender cannot talk its way into the weaker
check. Verified live: a corrupted signature and a 300s-old timestamp are both refused `4.01`
on `coap` exactly as on `coap-enc`.

`https` is **strictly weaker** than `mtls`: a stranger reaches the application before being refused,
instead of being refused by OpenSSL during the handshake. It runs on its own port for exactly that
reason — nothing that was true of `mtls` became less true when it was added — and every request on
it is still authenticated (chain + CN + signature + freshness) and still passes the same per-pair
policy check before a handler runs. Set `P2P_HTTPS_PORT=` empty on a node that should only ever
accept mutual-auth peers.

On the envelope techs a delivered file's bytes ride base64 **inside the signed payload**, so the
signature covers the content and not merely its name.

## Timing of every exchange (2026-09-30, benchmarking)

Every `Client` call now returns a `timing` block (and writes it to the sender's own `sent.log`),
measured on the SENDER's monotonic clock. Metrics v2 (2026-10-23): the phases are ADDITIVE -- `resolve_ms`,
`peer_cert_ms` (coap-enc / coap-pqc), `tcp_connect_ms`, `handshake_ms` (ends after the check of who answered; measured
inside the helper/worker for quic-* and coap-dtls*), `prepare_ms`, `client_overhead_ms` (starting the QUIC helper /
DTLS worker process), `exchange_ms`, of which `receiver_ms` (the receiver's own clock) and `network_ms` (the rest) --
sum to `total_ms`. What the transport observed: `handshake_bytes_out` / `handshake_bytes_in`, `handshake_cpu_ms`,
`rtt_ms`, `retransmits` (TCP: re-sent segments; CoAP: re-sent CON messages; QUIC: packets declared lost -- on this
testbed all spurious; DTLS: not observable, None), plus request/response bytes. Not-applicable values are `None`,
never `0`. Retired in v2: `verify_peer_ms` (folded into handshake_ms), `handshake_in_exchange`, `identity_refresh_ms`,
the receiver's `receive_body_ms` / `mirror_ms`, and TenantAPI's `api_ms` / `tooling_ms` (this PC's ssh plumbing).

Identity checks (2026-10-23): `common/identity.py` signs and verifies RSA/EC payload signatures, reads a certificate's
CN and SAN-IPs in-process with `cryptography` (falling back to the `openssl` CLI when it is missing or cannot decide) and
caches a successful `openssl verify` chain verdict for up to 300 s (`P2P_CHAIN_CACHE_TTL_S`, never past the leaf's
notAfter; failures are never cached; a changed CA file invalidates it). `coap_crypto.load_private_key` parses the node's
RSA key once per process and skips OpenSSL's re-validation of it (218 ms per load on a Pi 5). A CoAP `4.01` from the receiver
now raises `AuthorizationDenied` like HTTP 401/403 do, and a non-2xx response is logged `ok=False`.
`quic_pqc_relay.py` and `coap_dtls_pqc_relay.py` default to pinning their key-exchange group (`QUIC_GROUPS` /
`P2P_COAP_DTLS_REQUIRE_GROUP`; `*` opts out). `p2p/tests/test_identity_fastpath.py` checks the fast paths against the CLI. The HTTP-family receiver (`server.py`)
adds its own share to every reply as `receiver_timing` (verify / authorize / handler, on ITS clock), which the sender folds into `timing.receiver`; `coap_server.py` does the same (plus
`decrypt_ms`), inside the signed response. `server.py` also sets `TCP_NODELAY` now: before, every TLS reply paid a ~40 ms Nagle +
delayed-ACK stall. API side and how to read it:
`Tenant-Admin-user-PC/API/docs/50_timing.md`.

## Status (Stage A + B combined, 2026-07-25 — see `p2p-progress.md`)

Transport is TLS 1.3 mutual auth from day one (not deferred to a later "Stage B"), per the operator's
explicit instruction to implement it with OpenSSL TLS 1.3 immediately rather than starting plaintext.
Certs are issued by the SAME CA the Router-PC/announce system already uses (§7 Q6 — `POST /p2p-cert`
on the Server, backed by `mtls_ca.py`). Policy is the real §4 join (`GET /p2p-authorize`), not a
stubbed default-allow-only table — overrides (`POST /p2p-policy-set`) and denial events
(`GET /p2p-events`) all work today; only the GUI editor (Stage C) doesn't exist yet.

The CoAP transport, the additional APIs (RM-without-Tenant-Admin) and the GUI all landed later —
see `p2p-progress.md` for what's done. 2026-07-28 added the `https` tech and decoupled the use case
from the tech (see the matrix above); before that, file delivery was mTLS-only and CoAP carried
messages and nothing else.

## Running a node manually (before the deploy-script wiring lands)

```
cd p2p
cp .env.example .env      # fill in P2P_NODE_NAME for this node
set -a; source .env; set +a
python3 receiver-role/server.py &          # both HTTP listeners
python3 receiver-role/coap_server.py &     # the CoAP one, if you want tech coap-enc
python3 sender-role/cli.py deliver <receiver-name> /path/to/file
python3 sender-role/cli.py deliver <receiver-name> /path/to/file --tech https
python3 sender-role/cli.py status  <receiver-name> --tech coap-enc
python3 sender-role/cli.py status  <receiver-name> --details   # + the receiver's Network Map row
python3 sender-role/cli.py self                                 # this node's own Network Map row
python3 sender-role/cli.py message <receiver-name> '{"v":1}' --tech pqc
python3 sender-role/cli.py rm     <receiver-name> 'systemctl is-active p2p-receiver'
python3 sender-role/cli.py ml     <receiver-name> list_models '{}'
python3 sender-role/cli.py ml     <receiver-name> run_model '{"name":"iris"}' --timeout 60
python3 sender-role/cli.py path   <receiver-name>   # how we reach it; sends nothing
```

`cli.py rm` exits with the REMOTE command's own exit code, so it composes in a shell the way `ssh`
does. It prints the structured result as JSON by default (which is what the API parses) — add
`--echo` for the raw remote streams on your own stdout/stderr instead.

## Verifying the mesh

`../verify-p2p-mesh.py` checks **every ordered pair** of P2P peers, in-tenant and cross-tenant, at
four layers (resolve+symmetry · L3 reach · a real mTLS `status` exchange · a real device→device
`rm`), and reports the result per topology shape. That is the check that answers "can every device
reach every other and do P2P", which no sampled test can.

## Deliberate design choices (so they aren't re-litigated)

- **Cert CN = node name**, not a DNS hostname — `identity.peer_identity()` and
  `build_client_context(check_hostname=False)` both encode this on purpose.
- **Fail-closed policy checks**: if the Server is unreachable, `policy_client.check()` returns
  `deny`, never `allow` — an outage should never silently open P2P up.
- **No liveness pre-check** (§7 Q7): a dead path is discovered by a failed connect, not by reading
  `/resolve`'s `realized` block first. Revisit only if the GUI wants to show staleness.
- **Every role-PC except the server is a peer** (2026-07-29): the two seg-0 infra boxes — the
  Router-PC and the Tenant-Admin PC — are peers too, under the synthetic names
  `<TENANT>-Router-PC` / `<TENANT>-Admin-PC` that `p2p_resolve.INFRA_PEERS` defines. The SERVER is
  the one exclusion, and deliberately: it answers `/resolve` and `/p2p-authorize` for everyone, so
  a Server that were also a peer could authorize itself.
- **Server is never a data-plane hop**: `client.py` connects directly to the receiver's `/32` after
  resolving it; the Server only ever answers name/policy questions.
