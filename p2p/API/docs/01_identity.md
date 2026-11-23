# 01 — Identity (node side)

Everything about THIS box's own P2P identity, plus the cert primitives the certless transports use
in place of a handshake. Runnable: `examples/01_identity.py`, `src/01_identity.py`.

Read-only and offline apart from `fetch_identity`/`peer_cert` — this unit answers on a node whose
Server is down and whose peers are all unreachable, which is exactly when you need it.

## Functionalities
1. Is the cached identity present, sound and still valid (`identity_status`)
2. Can this node do the `pqc` tech (`pqc_status`)
3. The proof-of-possession headers it attaches to control-plane calls (`identity_headers`)
4. Does an arbitrary cert chain to our CA, and what CN does it claim (`verify_peer_cert`)
5. Is an envelope timestamp inside its replay window (`check_freshness`)
6. Enrol with the Server — gated, real (`fetch_identity`)

---

## 1. `identity_status()`
`{present, cn, issuer_cn, san_ips, san_dns, not_before, not_after, days_left, expired,
chain_certs, chains_to_cached_ca, ca_cn, key_mode, ...}`

**The question `fetch_own_cert()` never asks.** That function's contract is "if all three files
exist, reuse them untouched" — no staleness detection at all. Both `client.py::_refresh_identity`
and `server.py::_make_ctx_refresher` exist because of that, each carrying a comment about a cached
`ca.crt` that can never verify a live peer again once the fleet CA is reissued, and each firing
only **after** a connection has already failed. `chains_to_cached_ca=False` on a box whose receiver
still reports `active` is that exact time bomb, visible before a peer hits it.

`chain_certs` is routinely `2`: `mtls_ca.issue()` hands back leaf+intermediate whenever a leaf was
signed via an intermediate, which is what makes `verify_chain`'s leaf-splitting necessary.

Verified live 2026-08-09 on `just-test-tenant-Test-direct-device-pc-just-test-tenant`:
`cn` = the node name, `issuer_cn` = `network-fix Intermediate CA`, `ca_cn` = `network-fix Root CA`,
`san_ips` = `["10.4.0.100"]` (matching its /32), `chain_certs` = 2, `chains_to_cached_ca` = true,
`days_left` = 820, `key_mode` = `0o600`.

## 2. `pqc_status()`
`{available, openssl_bin, openssl_conf, material_present, cn, days_left, detail}`

Toolchain and material are genuinely independent, and they fail from different places at send time
— the toolchain from `Client._pqc()`, the material from `identity.load_pqc_material()`. Reported
side by side so "why did `--tech pqc` fail" is one call. Verified live: on a node with neither,
`available=false`, `material_present=false`, and `detail` is `load_pqc_material`'s own actionable
message naming `pqc_ca.py issue`.

## 3. `identity_headers()`
`identity.node_identity_headers()` verbatim → `{"X-Node-Cert", "X-Node-Sig"}` or `{}`.
Best-effort by design: any failure (a mid-rotation cert) returns `{}` and the call it was for
degrades silently to bootstrap-secret-only. Making that degrade visible is the point. Verified
live: 3612- and 344-char b64 values on a healthy node.

## 4. `verify_peer_cert(cert_pem, ca_path=None, pqc=False)`
`{chains, cn, ca, pqc}` — `identity.verify_chain` + `leaf_cn`, the application-level check the CoAP
transport and the `https` listener both run.

**Both halves matter and `cn` alone is worthless.** Verified live by minting a self-signed cert
with `CN=just-test-tenant-Router-PC` — the real router's exact name — and passing it in:
`{'chains': False, 'cn': 'just-test-tenant-Router-PC'}`. `leaf_cn` read the impostor's CN happily.
That is why `verify_chain` runs first in every real call site, and why it is reported first here.

## 5. `check_freshness(ts, max_age=None)`
`(ok, reason)` — the FIRST check both certless transports run, ahead of chain and signature, so a
stale envelope costs no crypto. Symmetric (`abs()`), so a node whose clock runs ahead fails too.
Verified live: `now` → `(True, None)`; 120s ago → `(False, 'envelope timestamp is 121s from now
(max 60s) — stale or replayed')`.

## 6. `fetch_identity(cache_dir=None, confirm=False)` — gated, real path exercised
Default refuses. `confirm=True` runs `identity.fetch_own_cert()` unmodified.

Idempotent against a POPULATED cache (it returns the three existing paths untouched), so the only
real action is against an EMPTY one — and that is what the gate is for. Enrolling mints a
server-side cert record for this name, after which the Server refuses to hand the key out again to
a bare bootstrap secret (`api_server.py`'s 2026-07-27 anti-key-handout fix). A node that loses its
cache after that point cannot simply re-fetch; the leaf has to be revoked and deleted first.

**Verified live (2026-08-09), the real `confirm=True` path, on a node that already holds a cert:**
called against a throwaway scratch directory → `{'ok': False, 'detail': "could not fetch a P2P cert
for '…' from https://10.0.0.2:18443: HTTP Error 401: Unauthorized"}`. The anti-key-handout rule
fired exactly as documented. Afterwards the node's real `/var/lib/p2p/certs` was md5-identical for
all three files and the scratch directory was **empty** — a refused enrolment leaves no partial
identity behind, which is the failure mode `client.py::_refresh_identity`'s own comment describes
having hit the hard way.
