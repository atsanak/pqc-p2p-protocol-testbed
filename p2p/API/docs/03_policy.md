# 03 — Policy (node side)

The per-pair authorization question every use case on every tech passes through before a handler
runs. Runnable: `examples/03_policy.py`, `src/03_policy.py`. Read-only, and it contacts only the
Server — asking about a pair leaves no trace on the other node.

## Functionalities
1. May sender talk to receiver (`policy_check`)
2. Would THIS node accept a given sender (`would_accept`)

---

## 1. `policy_check(sender, receiver)` → `(allowed, reason)`
`receiver-role/policy_client.check()` verbatim — literally the call `server.py::_authorized_or_403`
and `coap_server.py` make, on every use case and every tech, before any handler is reached.

**Not `Server-PC`'s `p2p_admin.p2p_authorize`.** That evaluates the policy table locally, on the
Server, from its own `p2p_policy.json`. This asks over the wire from where a receiver stands — so
it also answers "can this node reach the policy oracle at all", which the Server-side call cannot.

**Fail-closed, and that is the behaviour worth being able to observe.** An unreachable Server does
not mean "no opinion"; `policy_client.check()` catches every exception and returns
`(False, "policy check failed (fail-closed): …")`. Verified live 2026-08-09 against a name the
Server has never heard of:
`(False, 'policy check failed (fail-closed): HTTP Error 404: Not Found')` — a 404 became a deny
carrying its cause, not an exception the caller had to interpret.

Also verified live, both real verdict shapes:
- same tenant → `(True, 'intra-tenant allow')`
- cross tenant → `(True, 'cross-tenant allow (both sides agree)')`

That second one is worth reading carefully rather than assuming: cross-tenant defaults to **deny**
in code, and this fleet's live Server config has it open deliberately. The reason string names
which rule fired, which is the only reliable way to tell an intentional cross-tenant allowance from
a default.

## 2. `would_accept(sender)` → `(allowed, reason)`
`policy_check(sender, self.name)` — the same question with the receiver side filled in, so a node
can ask it about itself before a peer tries and fails. Verified live.

## Why both directions are worth printing
The two directions are separate entries and can legitimately disagree: a cross-tenant pair needs
BOTH sides to have consented, and the table records each side's answer independently. `src/
03_policy.py` prints them as two columns and flags asymmetry, because an exchange that fails in one
direction while its reverse works is otherwise a confusing thing to debug from either end alone.
