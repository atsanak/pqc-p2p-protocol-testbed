# 05 — Receiver gates (node local)

What THIS node refuses on its own, before the network is consulted. Runnable:
`examples/05_receiver_gates.py`, `src/05_receiver_gates.py`.

Entirely local — no Server, no peer, no certificate — so this is the one unit that still answers on
a box whose P2P is otherwise completely broken.

**Not overlapping `device_monitor.py`.** That already tails `/var/lib/p2p/{messages,rm,ml}.log` and
counts the comm-log spool: it reports what has *arrived*. This reports what *would be refused*, and
the ML spool's servicing state, neither of which is derivable from the logs.

## Functionalities
1. Would a peer's `rm` command run here (`rm_gate`)
2. Would a peer's ML call run here (`ml_gate`)
3. Is anything actually servicing peer-driven ML on this node (`ml_spool`)

---

## 1. `rm_gate(cmd=None)`
`{node, enabled, allow_prefixes, log_file, default_timeout_s, max_timeout_s, cmd, would_refuse,
reason}` — `handlers/rm.py`'s own `_enabled()` and `_allowed_prefixes()`, with that module's
`handle()` refusal logic applied in the same order, so the verdict is the real one, read from the
same process environment the receiver reads.

`P2P_RM_ENABLED` and `P2P_RM_ALLOW` are node-local and unreachable from the network by design —
which is also why nothing outside the box can report their effective state: a refused peer learns
only that this node declines RM. `P2P_RM_ENABLED` defaults **on** and the in-tenant policy default
is `allow`, so on a stock node every peer in the tenant can run commands here. This is how to
confirm whether that is still true of a given box.

Verified live 2026-08-09: `enabled: true`, `allow_prefixes: null` (no narrowing), `'uptime'` →
`would_refuse: false`.

Only the LOCAL half of the `rm` use case — firing a command at a peer is not in this package at
all, see `docs/04_exchange.md` §8.

## 2. `ml_gate(method=None)`
`{enabled, all_methods, read_only_methods, allowed_methods, configured, unrecognised_in_config,
spool_dir, log_file, timeouts, method, would_refuse, reason}` — `handlers/ml.py`'s `_enabled()` and
`_allowed_methods()` verbatim.

**Worth knowing what `_allowed_methods()` actually does**: it INTERSECTS `P2P_ML_ALLOW` with
`ML_METHODS`, so a typo silently narrows the surface instead of failing. A node configured
`list_models,get_modle` answers only `list_models` and says nothing about the second. Comparing
`allowed_methods` against `configured` — and the explicit `unrecognised_in_config` list — is the
only way to see that from the box itself.

Verified live: `enabled: true`, all 13 `ML_METHODS` allowed, `configured: null`,
`unrecognised_in_config: null`, `'run_model'` → `would_refuse: false`.

## 3. `ml_spool(spool_dir=None)`
`{spool_dir, exists, pending, oldest_age_s, stale_responses, agent_servicing, detail}`

The local half of the VM→container boundary `ml_op()` crosses. `handlers/ml.py` writes a
`.req.json`, polls for a `.res.json`, and on timeout tells two very different failures apart by
whether the request file is **still there**: still queued means nothing picked it up (the
device/gateway container is down, or was built without `p2p_ml_agent.py`); gone means the agent
took it and did not answer in budget.

That distinction is otherwise visible only at the moment of timeout, inside the handler, to whoever
was waiting. This reports the same signal standing still: a non-zero `pending` with a rising
`oldest_age_s` is a node whose agent is not running — findable before a peer spends a 60-second
budget discovering it. It is the same condition that produced the real `refused` answer in
`docs/04_exchange.md` §7, seen from the receiving side instead of the sending one.

Read-only, deliberately: no request is written, and `.res.json` files left by a caller that gave up
are **counted, not swept** — sweeping here would race a live handler one poll away from reading one.

Verified live: `exists: true`, `pending: 0`, `stale_responses: 0`, `agent_servicing: true`.
