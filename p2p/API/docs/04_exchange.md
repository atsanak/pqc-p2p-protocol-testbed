# 04 — Exchange (sender side)

What this node can do TO a peer. Runnable: `examples/04_exchange.py` (nothing changes on the peer),
`src/04_exchange.py --send` (the gated real writes). The tech is a parameter everywhere — `mtls`
(default), `https`, `pqc`, `coap-enc`.

## Functionalities
1. Separate the four things a failed exchange could mean (`preflight`)
2. Is the peer's receiver up, and is it really that peer (`peer_health`)
3. Build the exact wire envelope without sending it (`build_envelope`)
4. Use case STATUS — read-only, ungated (`get_status`)
5. Use case MESSAGE — gated, real (`send_message`)
6. Use case FILE — gated, real (`deliver_file`)
7. Use case ML — read verbs ungated, write verbs gated, real (`ml_op`)
8. Use case RM — **deliberately absent**

---

## 1. `preflight(receiver, tech="mtls")`
`{resolve, connect, peer_cn_ok, san_ok, tls, policy, would_succeed}`

Four independent failures, separated: the Server could not name the peer; the peer is not
listening; the peer is not who it claims; the policy says no. `client.py` collapses all four into
one raise at send time, and the comm-log mirror then records whichever fired first as *the* reason.

Sends nothing. The TLS connection is opened — that is the only way to see a peer certificate at all
— and closed without a request. The policy question goes to the Server, not the peer.

Verified live 2026-08-09: same-tenant and cross-tenant pairs both `would_succeed: true` with full
`tls` detail (`TLSv1.3 · TLS_AES_256_GCM_SHA384 · 256 · OpenSSL 3.0.20`, peer CA
`network-fix Intermediate CA`, `RSA-2048`); and against `Chain2-Router-PC` — a node whose receiver
is not running — `resolve.ok: true` with a full 4-hop chain but `connect: {ok: false, reason:
"could not reach Chain2-Router-PC (10.5.0.1:8443): [Errno 111] Connection refused"}`. That is the
split the unit exists for: name resolution was fine, the box is not listening.

## 2. `peer_health(receiver, tech="mtls")`
`GET /health` is the one route `server.py` deliberately leaves ungated (a liveness probe carries no
data), so this needs no policy allowance — but it is **not** a bare ping. It goes through
`Client._connect()`, so the peer's cert CN must equal `receiver` and its SAN IP must cover the
address we resolved to. Those two checks landed on 2026-07-28 for a specific attack: every fleet
node holds a valid fleet cert, so on this any-to-any fabric whoever takes the victim's /32 could
otherwise answer for it and the sender's own comm-log would record a normal successful exchange.
This is the cheapest way to exercise them against a real peer.

Verified live: `{status: 200, ok: true, node: "just-test-tenant-Router-PC", mutual_tls: true}` plus
the negotiated `tls` block and the resolved `via_chain`; and `PeerUnreachable` against the down node.

## 3. `build_envelope(use_case, payload, data, tech="https"|"pqc")`
`Client._envelope()`/`_signed_payload()` verbatim, then the receiver's own four checks (freshness →
chain → CN-vs-claim → signature, the order `server.py::_sig_verify_or_401` uses) applied locally to
what was just built. Sends nothing, needs no peer, needs no policy allowance.

That round-trip answers "can this node produce an envelope its peers will accept" — otherwise only
answerable by a peer 401'ing mid-exchange, where the reason lands in the *peer's* log.

`mtls` and `coap-enc` are refused with an explanation rather than silently accepted: `mtls`'s
identity is the handshake (there is no envelope), and `coap-enc` signs the *ciphertext*, which
needs the receiver's public cert — `peer_cert()` is the way in for that.

Verified live: `message` → `verified/chains/cn_matches_claim/fresh` all true, 32 signable bytes;
`file` with 100 bytes of content → payload keys `['data_b64', 'dest_filename']` and 192 signable
bytes, i.e. the signature demonstrably covers the file's **bytes**, not just its name. On a node
with no PQC toolchain, `tech="pqc"` raises `IdentityError` naming the missing binary — never a
silent fall back to classical.

## 4. `get_status(receiver, tech)` — ungated
The one use case that changes nothing on the receiver: `handlers/status.py` reads two clocks and
returns. It still traverses the whole stack (identity, per-pair policy, the comm-log mirror on both
sides), so it is the cheapest honest end-to-end proof that a pair works and the right thing to call
before anything gated. Verified live on `mtls` and on `https` (the latter comes back with
`https_verified: true`, the receiver's marker that the signed-envelope path authenticated it).

## 5/6. `send_message` · `deliver_file` — gated, and the real path WAS exercised
Both default to refused. Both are bucket 2 of this sweep's framework: no built-in sandbox exists,
but the real blast radius is small and self-contained, so the real path was tested rather than only
the refusal.

- `send_message` → `handlers/message.py` appends **one** record to the peer's
  `/var/lib/p2p/messages.log`. Nothing else on that box is touched.
- `deliver_file` → `handlers/file_delivery.handle()` takes `Path(dest_path).name`, so a sender
  picks a **name**, never a location: there is no path-escape radius. What remains, and what the
  gate is really for, is that a same-named file in the receiver's `DROP_DIR` is overwritten with no
  warning and no backup.

**Verified live 2026-08-09**, device VM → `just-test-tenant-Router-PC`, both with `confirm=True`:
the router's `/var/lib/p2p/` held `certs/`, `ml-spool/` and a 122766-byte `rm.log`, with **no**
`messages.log` and **no** `received/` before. Afterwards: `messages.log` contained exactly one line
(the probe, with the correct sender CN), `received/` held exactly one file of 40 bytes whose
receiver-computed `sha256` matched the sender's own digest of the bytes it sent, and `rm.log` was
still 122766 bytes. The probe file was then removed; the log line is left, because deleting a line
out of an append-only audit log is a worse act than the one it would tidy.

## 7. `ml_op(receiver, method, params, confirm=False)`
The four read-only verbs — `list_models`, `get_model`, `read_model_file`, `run_status` — run
without confirmation. That split is not this package's invention: it is verbatim the read-only
`P2P_ML_ALLOW` example `p2p/.env.example` itself gives. Every other `ML_METHODS` verb starts, stops,
reparameterises or replaces something on a live box and needs `confirm=True`. An unknown verb is
refused here rather than travelling to the peer to be refused there, against the same
`handlers/ml.py` list, so the two cannot disagree.

Verified live, both outcomes:
- `list_models` → a gateway whose ML agent is running answered
  `{ok: true, method: "list_models", ms: 200.9, result: {status: "ok", models: []}}` — the whole
  VM→container spool round trip, for real.
- `list_models` → a Router-PC, which has no ML agent, answered `{ok: false, refused: true, reason:
  "no ML agent is servicing /var/lib/p2p/ml-spool on this node — the device/gateway container is
  down, or was built without p2p_ml_agent.py"}`. That is `handlers/ml.py`'s
  still-queued-request diagnosis, and it is exactly what `ml_spool()` (unit 05) reports locally.
- `run_model` without `confirm` → refused locally, naming the read-only set.
- `"rm -rf /"` as a method → refused locally as unknown, with the full enumerated list.

## 8. Use case RM — deliberately not wrapped
`Client.remote_exec()` runs an **arbitrary shell command** on another live box
(`handlers/rm.py`: `subprocess.run(["/bin/sh", "-c", cmd])`), and the in-tenant policy default is
`allow`, so on this fabric it reaches every peer in the tenant. That is the same category as
`Server-PC`'s `p2p_rm.ssh_run`, which this sweep already excluded; a different transport does not
make it a different category. Bucket 4: not wrapped, and said so here and in the module docstring.

The `rm` use case is still covered from the side that costs nothing — `rm_gate()` (unit 05) reports
what this node would refuse, and `device_monitor.py` already surfaces `/var/lib/p2p/rm.log`.
