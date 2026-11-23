# p2p local API

The LOCAL, in-process API for the P2P peer service as it exists **on a node**. Seventh role in this
sweep, after Device-PC, Gateway-PC, Router-PC, Server-PC, node-agent and
A-Physical-Testbed/Tenant-Admin-PC.

Built 2026-08-09 after reading all 17 Python files under `p2p/` in full (~2500 lines).

## Start here — `p2p_api.py`
```python
import sys; sys.path.insert(0, "/opt/p2p/API")     # or "<repo>/p2p/API"
from p2p_api import P2PAPI
a = P2PAPI()                                        # defaults from this node's own /opt/p2p/.env

print(a.identity_status())                          # do I have a usable identity? (offline)
print(a.path("just-test-tenant-Router-PC"))          # how do I reach that peer?
print(a.preflight("just-test-tenant-Router-PC"))      # would an exchange work, and if not, why not?
print(a.rm_gate("uptime"))                             # what would I refuse, before any network?
```

## Layout
| Path | What it is |
|---|---|
| **`p2p_api.py`** | the facade — one `P2PAPI` class. **Use this.** |
| **`docs/NN_*.md`** | reference per unit. |
| **`examples/NN_*.py`** | one runnable narrative demo per unit. Nothing they do changes a peer. |
| **`src/NN_*.py`** | standalone CLI scripts; results saved under `src/outputs/`. |

| unit | what it covers |
|---|---|
| `01 identity` | this box's own P2P identity + the cert primitives — offline, no Server needed |
| `02 resolve` | the node's side of `/resolve`, and its own degrade cache |
| `03 policy` | the per-pair verdict, fail-closed, in both directions |
| `04 exchange` | preflight/health/status/envelope, plus gated real `message`/`file`/`ml`. No `rm`. |
| `05 receiver_gates` | what THIS node refuses on its own, before the network |

## Every `P2PAPI` method, by unit
Full reference + a verified-live narrative for each of these lives in that unit's `docs/NN_*.md` /
`examples/NN_*.py` (see the table above) — this is the one-line index, so every name below is real
and grep-able against `p2p_api.py` itself.

- **01 identity** — `identity_status(cache_dir=None)` is this box's cached P2P identity present,
  sound and still valid, reporting `chains_to_cached_ca` BEFORE a peer connection fails on it;
  `pqc_status(cache_dir=None)` can this box do the `pqc` tech — toolchain and material reported side
  by side since each fails from a different place at send time; `identity_headers(name=None,
  cache_dir=None)` the proof-of-possession headers this node attaches to its own control-plane
  calls, `{}` on a best-effort degrade; `check_freshness(ts, max_age=None)` → `(ok, reason)`, is an
  envelope timestamp inside its replay window, the first check both certless transports run;
  `fetch_identity(cache_dir=None, confirm=False)` → refuses unless `confirm=True`, then enrols this
  node with the Server's `POST /p2p-cert` and caches the result — a real action only against an
  EMPTY cache, since a populated one is returned untouched.
- **02 resolve** — `path(receiver_name)` → `{ip, via_chain, hops, cross_tenant, ...}`, how this node
  reaches a peer without sending anything, re-expressed from `resolve()` so it needs no cert fetch;
  `peer_cert(name)` another node's PUBLIC certificate PEM from the Server's `POST /p2p-peer-cert`,
  never a private key and deliberately not cached.
- **03 policy** — `policy_check(sender, receiver)` → `(allowed, reason)`, may `sender` talk to
  `receiver` — the exact fail-closed call every handler runs before doing anything, asked from where
  the receiver stands; `would_accept(sender)` → `(allowed, reason)`, would THIS node's own receiver
  accept `sender` right now — `policy_check(sender, self.name)` with the receiver side filled in.
- **04 exchange** — `preflight(receiver_name, tech="mtls")` → `{resolve, connect, peer_cn_ok,
  san_ok, tls, policy, would_succeed}`, separates the four independent things a failed exchange could
  mean, sending nothing; `peer_health(receiver_name, tech="mtls")` is the peer's receiver up and
  really who it claims, over the one route `server.py` leaves ungated; `build_envelope(use_case,
  payload=None, data=b"", tech="https")` builds the exact signed envelope an envelope-tech exchange
  would put on the wire and verifies it locally, for `tech` `"https"`/`"pqc"` only;
  `get_status(receiver_name, tech="mtls")` use case STATUS, ungated because it changes nothing on
  the receiver; `send_message(receiver_name, payload, tech="mtls", confirm=False)` → refuses unless
  `confirm=True`, then delivers a JSON body to a peer, appending one record to its `messages.log`;
  `deliver_file(receiver_name, data, dest_filename, tech="mtls", confirm=False)` → refuses unless
  `confirm=True`, then writes raw bytes into the peer's own basename-confined `DROP_DIR`, overwriting
  any same-named file with no warning; `ml_op(receiver_name, method, params=None, timeout=None, tech="mtls",
  confirm=False)` runs one enumerated ML verb on a peer — the four read-only verbs (`list_models`,
  `get_model`, `read_model_file`, `run_status`) need no confirmation, every other verb refuses
  without `confirm=True`, an unrecognised verb is refused locally rather than sent.
- **05 receiver_gates** — `ml_gate(method=None)` what THIS node's receiver would do with a peer's ML
  call, before the network is consulted, and whether `P2P_ML_ALLOW` has a typo silently narrowing the
  surface (`unrecognised_in_config`); `ml_spool(spool_dir=None)` is anything actually servicing this
  node's ML spool right now — a non-zero `pending` with a rising `oldest_age_s` means no agent is
  running, visible before a peer spends a 60-second budget discovering it.

## The angle: node-side. Two things already cover P2P from elsewhere, and this is neither
1. **`Server-PC/Server/app/API/server_api.py`'s `p2p_admin`** is the SERVER side — the policy
   *table*, the comm-log's hash chain, the audit log. It answers "what does the fleet's policy say"
   by reading the Server's own files.
2. **`Device-PC/Device/Monitor/device_monitor.py`** already tails this box's
   `/var/lib/p2p/{messages,rm,ml}.log` and counts the comm-log spool. It answers "what has arrived".

Neither answers what a NODE can ask and do for itself, which is what `p2p/` actually implements:
does this box have a usable identity, how does it reach a named peer right now, would that peer
accept it, what exactly would go on the wire, and what would this box's own receiver refuse before
the network is even consulted.

## The daemon gap is real here — the first time since Gateway-PC
Router-PC, Server-PC, node-agent and A-Physical-Testbed were all "thin shell over pure functions".
The receiver side is not: `server.py`'s identity checks are methods on a live
`BaseHTTPRequestHandler` bound to an accepted TLS socket, and `TLSHTTPServer` caches an
`ssl.SSLContext` plus a class-level refresh lock. None of that is reachable from a separate
process, and reimplementing it would be a second copy of the fleet's identity gate — exactly the
drift `handlers/rm.py`'s own docstring warns about.

So this package wraps the receiver only where the receiver is genuinely pure (`policy_client.check`,
and the handlers' node-local gate functions), and observes the rest from the outside over the wire
(`peer_health`, `preflight`), which is the only honest way to ask.

## What this deliberately does NOT wrap
- **`Client.remote_exec()` — the `rm` use case.** Arbitrary shell execution on another live box
  (`handlers/rm.py`: `subprocess.run(["/bin/sh", "-c", cmd])`), with an in-tenant policy default of
  `allow`. Same category as `Server-PC`'s `p2p_rm.ssh_run`, already excluded by this sweep; a
  different transport does not make it a different category. Covered from the free side instead:
  `rm_gate()` says what this node would refuse.
- **`handlers/{message,file_delivery,rm,ml}.handle()` directly.** Calling them in-process would
  append to this box's real receiver logs / write into its real drop directory / dispatch a real ML
  request, all while bypassing the two gates that make them safe (the peer certificate and the
  per-pair policy). A local API that can forge a delivery from any claimed `sender_cn` is worse
  than the capability it wraps.

## Gated, but fully tested
`send_message` / `deliver_file` / mutating `ml_op` verbs need `confirm=True` — they change real
state on another live box. The blast radius of each is genuinely small and self-contained (one
appended log line; one file under the receiver's own basename-confined `DROP_DIR`; one enumerated
ML verb), so the **real path was exercised end-to-end** against the live fleet rather than only
refusal-tested. `docs/04_exchange.md` records what was sent where and what was checked before and
after — including that the receiving box's `rm.log` was byte-for-byte the same size afterwards, and
that the probe file's sha256 as computed by the receiver matched the sender's own.

`get_status` / `peer_health` / `preflight` / the four read-only `ml_op` verbs need no confirmation:
they read.

## Two real findings from building this
1. **Fleet drift, found by running it.** The live fleet's deployed `/opt/p2p/common/identity.py`
   predates the repo's 2026-08-08 unreachable-Server degrade — no `cache_dir` parameter on
   `resolve()`, no `RESOLVE_CACHE_MAX_AGE_S`. `P2PAPI.resolve()` raises a loud `TypeError` there,
   which is correct and deliberately not shimmed: a compatibility shim would make `resolve_cache()`
   return `[]` on a node with no degrade cache, reading as "nothing cached" instead of "this node
   cannot degrade at all". **This package must be deployed alongside the `p2p/` tree it wraps.**
2. **`leaf_cn()` on an impostor.** Verified live by minting a self-signed cert carrying a real
   node's exact CN: `verify_peer_cert()` returned `{'chains': False, 'cn':
   'just-test-tenant-Router-PC'}`. The CN read back perfectly. That is why `verify_chain` runs
   first at every real call site, and why this API reports it first too.

## Test bench used (2026-08-09)
Live: Server at `https://10.0.0.2:18443`; peers `just-test-tenant-Test-direct-device-pc-…` (device,
where the API was run), `just-test-tenant-Router-PC`, `just-test-tenant-Admin-PC`,
`mergesandbox-Router-PC` and `mergesandbox-Gw1-gateway-pc-…` — two tenants, so both the
`intra-tenant allow` and `cross-tenant allow (both sides agree)` verdicts were exercised for real,
plus `Chain2-Router-PC` as a node with no receiver listening.
