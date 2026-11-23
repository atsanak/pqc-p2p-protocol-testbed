# 02 — Resolve (node side)

How this node finds a peer, and what it could still answer with if the Server disappeared.
Runnable: `examples/02_resolve.py`, `src/02_resolve.py`. All read-only; the peer is never contacted.

**Not the same unit as `Server-PC`'s `resolve`.** That one computes the answer from `netplan.json`
on the Server. This is the CLIENT half: it travels the real control-plane path (with the cert-proof
headers `node_identity_headers` adds), and it is the only side that can degrade to a cached answer.

## Functionalities
1. Resolve a name as this node (`resolve`)
2. The hop chain to a peer, sending nothing (`path`)
3. This node's own degrade cache (`resolve_cache`)
4. A peer's public certificate (`peer_cert`)

---

## 1/2. `resolve(name, frm=None)` · `path(receiver_name)`
`identity.resolve()` verbatim; `path()` adds the flattened `hops` list exactly as `Client.path()`
does — re-expressed rather than called through `Client`, so it needs no cert fetch. That matters
precisely on the box whose identity is the thing you are debugging.

**`stale` is the field to read.** On a Server outage `identity.resolve()` serves a cached answer up
to `RESOLVE_CACHE_MAX_AGE_S` (900s) old and marks it `stale`/`stale_age_s`. `client.py` prints a
warning to **stderr** about this — invisible to a library caller — so the flag is passed straight
through here instead.

Verified live 2026-08-09 from the device VM:
- same-tenant → `just-test-tenant-Router-PC` at `10.4.0.1`, `cross_tenant` absent, 2 hops
  (`device → router-pc`).
- cross-tenant → `mergesandbox-Router-PC` at `10.6.0.1`, `cross_tenant: true`, 4 hops
  (`device → just-test-tenant-Router-PC → VIRTUAL-Router-PC → mergesandbox-Router-PC`) — the
  climb-to-each-Router-PC-and-turn-at-the-hub shape `Client.path`'s docstring describes.
- an unknown name raises `ResolveError … HTTP Error 404`, not a silent empty answer.

## 3. `resolve_cache(cache_dir=None)`
`[{name, ip, age_s, usable, max_age_s, path}]`, newest first. **Nothing else in the codebase can
see this.** `identity.resolve()` writes an entry on every success and reads one back only on a
failure, so on a healthy fleet the cache is written constantly and never read — and the first time
its contents matter is an outage, when they decide whether an exchange proceeds on a possibly-stale
route or refuses outright. `usable` applies the same comparison the real degrade path applies.

Verified live: after two resolves, two entries at `age_s: 0`, `usable: true`, under
`/var/lib/p2p/certs/resolve-cache/`.

## 4. `peer_cert(name)`
`identity.fetch_peer_cert()` verbatim — a peer's PUBLIC PEM, never a private key, and deliberately
not cached (a peer's cert can be revoked and reissued between two messages). The `coap-enc` tech
fetches this to encrypt to a peer; on its own it is how to see what CN/SAN the fleet currently
believes a name has, without connecting to it. Verified live and fed straight into
`verify_peer_cert()` → `{'chains': True, 'cn': 'just-test-tenant-Router-PC'}`.

## A drift trap worth knowing
This package must be deployed **alongside the `p2p/` tree it wraps**, not dropped on top of an
older one. Found while testing: the live fleet's `/opt/p2p/common/identity.py` predates the
2026-08-08 degrade work — its `resolve()` has no `cache_dir` parameter and no
`RESOLVE_CACHE_MAX_AGE_S` — so `P2PAPI.resolve()` raises `TypeError` there. That is the correct
behaviour (a loud, immediate failure naming the missing parameter), not something to paper over
with a compatibility shim: a shim would let `resolve_cache()` silently return `[]` on a node that
has no degrade cache at all, which reads as "nothing cached" rather than "this node cannot degrade".
