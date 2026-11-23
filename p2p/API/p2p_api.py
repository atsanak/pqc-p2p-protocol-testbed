"""p2p_api.py — the local, in-process API for the P2P peer service as it exists ON A NODE.

Seventh role in the src/examples/docs sweep, after Device-PC, Gateway-PC, Router-PC, Server-PC,
node-agent and A-Physical-Testbed/Tenant-Admin-PC. Built 2026-08-09 after reading all 17 Python
files under `p2p/` in full (~2500 lines): `common/{identity,comm_log,coap_crypto,wire,errors,
rm_limits,ml_limits}.py`, `receiver-role/{server,coap_server,policy_client}.py`,
`receiver-role/handlers/{message,file_delivery,status,rm,ml}.py`, `sender-role/{client,cli}.py`.

THE ANGLE: NODE-SIDE. TWO THINGS ALREADY COVER P2P FROM ELSEWHERE, AND THIS IS NEITHER
  1. `Server-PC/Server/app/API/server_api.py`'s `p2p_admin` unit is the SERVER side — the policy
     TABLE (`p2p_policy.authorize`/`effective_state`), the comm-log's hash chain, the audit log.
     It answers "what does the fleet's policy say" by reading the Server's own files.
  2. `Device-PC/Device/Monitor/device_monitor.py` already tails this box's
     `/var/lib/p2p/{messages,rm,ml}.log` and counts the comm-log spool. It answers "what has
     arrived here".
  Neither answers what a NODE can ask and do for itself, which is what `p2p/` actually implements
  and what this package wraps: does this box have a usable P2P identity, how does it reach a named
  peer right now, would that peer's receiver accept it, what exactly would go on the wire, and
  what would THIS box's own receiver refuse before the network is even consulted.

THE DAEMON GAP IS REAL HERE — THE FIRST TIME SINCE GATEWAY-PC
  Unlike Router-PC/Server-PC/node-agent/A-Physical-Testbed ("thin shell over pure functions"), the
  receiver side genuinely holds process state: `server.py`'s identity checks are methods on a live
  `BaseHTTPRequestHandler` bound to an accepted TLS socket, and `TLSHTTPServer` caches an
  `ssl.SSLContext` plus a class-level refresh lock. None of that is reachable from a separate
  script process, and reimplementing it here would be a second copy of the fleet's identity gate —
  exactly the drift `rm.py`'s docstring warns about. So this package wraps the receiver only where
  the receiver is genuinely pure: `policy_client.check()` (unit 03) and the handlers' own node-local
  gate functions (unit 05). What a live receiver does with a live socket is left to the live
  receiver; `peer_health()`/`preflight()` (unit 04) observe it from the outside, over the wire,
  which is the only honest way to ask.

WHAT THIS DELIBERATELY DOES NOT WRAP
  `sender-role/client.py`'s `remote_exec()` — the `rm` use case. It runs an ARBITRARY shell command
  on another live box (`handlers/rm.py`: `subprocess.run(["/bin/sh", "-c", cmd])`), and the
  in-tenant policy default is `allow`, so on this fabric it reaches every peer in the tenant. That
  is the same category as `Server-PC`'s `p2p_rm.ssh_run`, which this sweep already excluded for
  exactly this reason; a different transport does not make it a different category. The `rm` use
  case is still covered here from the side that costs nothing: `rm_gate()` (unit 05) reports what
  THIS node would refuse, and `handlers/rm.py` writes `/var/lib/p2p/rm.log`, which
  `device_monitor.py` already surfaces.

  `handlers/{message,file_delivery,rm,ml}.handle()` are also not wrapped directly. Calling them
  in-process would append to this box's real receiver logs / write into its real drop directory /
  dispatch a real ML request to its agent, all while bypassing the two gates that make those
  handlers safe (the peer certificate and the per-pair policy) — a local API that can forge a
  delivery from any claimed `sender_cn` is a worse thing than the capability it wraps.

GATED, BUT FULLY TESTED (the framework this sweep settled into — see the A-Physical-Testbed README)
  `send_message`/`deliver_file`/mutating `ml_op` need `confirm=True`: they change real state on
  ANOTHER live box. But the blast radius of each is genuinely small and self-contained (one appended
  log line; one file under the receiver's own `DROP_DIR`, basename-confined by
  `file_delivery.handle`; one enumerated ML verb), so the REAL path was exercised end-to-end against
  the live fleet, not merely refusal-tested — see `docs/04_exchange.md` for what was sent where and
  what was checked before and after. `get_status`/`peer_health`/`preflight` need no confirmation:
  they read.

Usage:
    import sys; sys.path.insert(0, "/opt/p2p/API")
    from p2p_api import P2PAPI
    a = P2PAPI()                      # name/server/secret default from this node's own env
    print(a.identity_status())
    print(a.path("just-test-tenant-Router-PC"))
"""
import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))          # p2p/API/
P2P_DIR = os.path.dirname(HERE)                             # p2p/
sys.path.insert(0, P2P_DIR)                                  # for `common`
sys.path.insert(0, os.path.join(P2P_DIR, "receiver-role"))    # for `handlers`, `policy_client`
sys.path.insert(0, os.path.join(P2P_DIR, "sender-role"))       # for `client`

from common import errors, identity  # noqa: E402
try:                                                   # a box whose /opt/p2p predates P4.1 has no fetch.py
    from handlers import fetch as fetch_handler  # noqa: E402
except ImportError:                                    # noqa: E722 — the rest of P2PAPI must keep working
    fetch_handler = None
from handlers import ml as ml_handler  # noqa: E402
from handlers import rm as rm_handler  # noqa: E402
from policy_client import check as policy_check  # noqa: E402

# `client.py` imports nothing exotic and constructs no state at import time (the network call is in
# `Client.__init__`), so a plain import is fine — but it is deferred into `_client()` anyway, so a
# box with no env / no Server can still use units 01 and 05.

# The ML verbs that only READ. Not this package's own taxonomy: it is verbatim the read-only
# allow-list `p2p/.env.example` itself suggests for `P2P_ML_ALLOW` ("A read-only ML peer, for
# example: P2P_ML_ALLOW=list_models,get_model,read_model_file,run_status"). Everything else in
# `handlers/ml.py`'s ML_METHODS changes something on the receiver and needs `confirm=True`.
ML_READ_ONLY = ("list_models", "get_model", "read_model_file", "run_status")

# Every use case a sender can drive (sender-role/client.py's Client.USE_CASES, spelled out so units
# 01/03/05 keep working without importing the sender). The Server's policy is PER PAIR, not per use
# case, so "allowed" for a pair means every one of these passes the policy gate; what can still
# refuse is the RECEIVER's node-local switch for that use case (rm/ml/fetch gates, unit 05).
ALL_USE_CASES = ("message", "file", "status", "rm", "ml", "fetch")


class P2PAPI:
    def __init__(self, name=None, server_api_base=None, bootstrap_secret=None, cache_dir=None,
                 pqc_cache_dir=None, port=None, https_port=None, coap_port=None):
        """Every argument defaults from this node's own `/opt/p2p/.env` environment, the same names
        `client.py`/`server.py` read — but NOTHING is required here. `Client.__init__` raises
        `KeyError` on a missing `P2P_NODE_NAME`/`SERVER_API_BASE`/`BOOTSTRAP_SECRET` and makes a
        network call before it returns; that is right for a sender, and wrong for an API whose
        units 01 and 05 are pure local inspection. So the env is read leniently here and the
        `Client` is built lazily, on the first call that actually needs the wire."""
        self.name = name or os.environ.get("P2P_NODE_NAME")
        self.server_api = server_api_base or os.environ.get("SERVER_API_BASE")
        self.secret = bootstrap_secret or os.environ.get("BOOTSTRAP_SECRET")
        self.cache_dir = cache_dir or os.environ.get("P2P_CACHE_DIR", "/var/lib/p2p/certs")
        self.pqc_cache_dir = pqc_cache_dir or os.environ.get(
            "P2P_PQC_CACHE_DIR", identity.PQC_CACHE_DIR_DEFAULT)
        self.port = int(port or os.environ.get("P2P_PORT", "8443"))
        self.https_port = int(https_port or os.environ.get("P2P_HTTPS_PORT") or 8444)
        self.coap_port = int(coap_port or os.environ.get("P2P_COAP_PORT", "5683"))
        self._client_obj = None

    # ── plumbing ────────────────────────────────────────────────────────────────────────────────
    def _need_env(self):
        missing = [k for k, v in (("P2P_NODE_NAME", self.name),
                                  ("SERVER_API_BASE", self.server_api),
                                  ("BOOTSTRAP_SECRET", self.secret)) if not v]
        if missing:
            raise errors.P2PError(
                f"this call needs {'/'.join(missing)} — pass them to P2PAPI(...) or run where "
                f"/opt/p2p/.env is loaded (see p2p/.env.example)")

    def _client(self):
        """The real `sender-role/client.py` Client, built once. Its `__init__` fetches/loads this
        node's cert, so the first call that needs the wire is also the one that proves the identity
        is usable — deliberately not done in `P2PAPI.__init__`, see that docstring."""
        if self._client_obj is None:
            self._need_env()
            from client import Client                       # noqa: PLC0415 — deferred on purpose
            self._client_obj = Client(name=self.name, server_api_base=self.server_api,
                                      bootstrap_secret=self.secret, cache_dir=self.cache_dir,
                                      port=self.port, https_port=self.https_port,
                                      pqc_cache_dir=self.pqc_cache_dir)
        return self._client_obj

    # ── 01 · identity (common/identity.py — this node's own P2P identity, read-only) ────────────
    def identity_status(self, cache_dir=None):
        """Is this box's P2P identity present, sound, and still valid? -> {present, cache_dir, cn,
        issuer_cn, san_ips, san_dns, not_before, not_after, days_left, expired, chain_certs,
        chains_to_cached_ca, key_mode, ...}.

        The question `identity.fetch_own_cert()` never asks. That function's whole contract is "if
        all three files exist, reuse them untouched" — which is why `client.py::_refresh_identity`
        and `server.py::_make_ctx_refresher` both exist, each carrying its own comment about a
        cached `ca.crt` that can never verify a live peer again after the fleet CA is reissued, and
        each only firing AFTER a connection has already failed. This reports the same facts BEFORE
        anything fails: `chains_to_cached_ca=False` on a box whose receiver is still nominally
        'active' is that exact time bomb, visible without waiting for a peer to hit it.

        Read-only, no network, no env required. Facts come from `openssl x509` — the same
        shell-out-to-openssl idiom `identity.py` itself uses everywhere (see `verify_chain`,
        `leaf_cn`), so this needs nothing installed that the rest of P2P does not already need."""
        d = Path(cache_dir or self.cache_dir)
        cert_path, key_path, ca_path = d / "peer.crt", d / "peer.key", d / "ca.crt"
        out = {"cache_dir": str(d), "cert": str(cert_path), "present": False,
               "has_cert": cert_path.exists(), "has_key": key_path.exists(),
               "has_ca": ca_path.exists()}
        if not cert_path.exists():
            out["detail"] = f"no P2P identity cached at {d} (peer.crt missing)"
            return out
        pem = cert_path.read_text(encoding="utf-8")
        out.update(_cert_fields(pem))
        # peer.crt is routinely a leaf+intermediate BUNDLE (mtls_ca.issue hands back the full chain
        # when a leaf was signed via an intermediate) — reported, because it is what makes
        # `verify_chain`'s leaf-splitting necessary and is easy to mistake for a duplicate.
        out["chain_certs"] = pem.count("-----BEGIN CERTIFICATE-----")
        out["present"] = bool(out.get("cn")) and out["has_key"] and out["has_ca"]
        if ca_path.exists():
            out["chains_to_cached_ca"] = identity.verify_chain(str(ca_path), pem)
            out["ca_cn"] = _cert_fields(ca_path.read_text(encoding="utf-8")).get("cn")
        if key_path.exists():
            # fetch_own_cert chmods the key 0600; anything looser means it was provisioned some
            # other way, which is worth seeing next to the rest.
            out["key_mode"] = oct(key_path.stat().st_mode & 0o777)
        return out

    def pqc_status(self, cache_dir=None):
        """Can this box do the `pqc` tech, and does it have an identity for it? -> {available,
        openssl_bin, openssl_conf, material_present, cn, not_after, days_left, detail}.

        `identity.pqc_available()` verbatim for the toolchain half, `identity.load_pqc_material()`
        for the material half — the two are genuinely independent (a box can have the oqs-provider
        build and no minted leaf, or the reverse) and both failures raise from a DIFFERENT place at
        send time: the toolchain from `Client._pqc()`, the material from `load_pqc_material()`.
        Reported side by side here so 'why did --tech pqc fail' is one read-only call."""
        out = {"available": identity.pqc_available(),
               "openssl_bin": identity.PQC_OPENSSL, "openssl_conf": identity.PQC_OPENSSL_CONF,
               "cache_dir": str(cache_dir or self.pqc_cache_dir), "material_present": False}
        try:
            cert_path, _key, ca_path = identity.load_pqc_material(cache_dir or self.pqc_cache_dir)
        except errors.IdentityError as e:
            out["detail"] = str(e)
            return out
        out["material_present"] = True
        out.update({k: v for k, v in _cert_fields(
            Path(cert_path).read_text(encoding="utf-8"), openssl_bin=identity.PQC_OPENSSL,
            env=identity.pqc_env()).items() if k in ("cn", "issuer_cn", "not_after", "days_left",
                                                     "expired")})
        out["ca"] = ca_path
        if not out["available"]:
            out["detail"] = ("a PQC identity is provisioned but the oqs-provider toolchain is not "
                             "installed here — `--tech pqc` will still fail, from Client._pqc()")
        return out

    def identity_headers(self, name=None, cache_dir=None):
        """The proof-of-possession headers this node attaches to its own control-plane calls ->
        {"X-Node-Cert": b64, "X-Node-Sig": b64}, or {} if it has no cached identity to sign with.
        `identity.node_identity_headers()` verbatim — best-effort by design (a mid-rotation cert
        falls back to bootstrap-secret-only rather than breaking the call), so an empty dict here
        is the same silent degrade `resolve()` and the comm-log reporter would take, made visible."""
        return identity.node_identity_headers(name or self.name, cache_dir or self.cache_dir)

    def verify_peer_cert(self, cert_pem, ca_path=None, pqc=False):
        """Does `cert_pem` chain to our CA, and what CN does it assert? -> {chains, cn}. The
        application-level check the CoAP transport and the `https` listener both run in place of a
        handshake (`identity.verify_chain` + `leaf_cn`, verbatim; the `_pqc` variants when
        `pqc=True`). Both halves matter and neither alone is enough: `leaf_cn` will happily read a
        CN off a self-signed impostor, which is why `verify_chain` runs first everywhere in the real
        code and is reported first here."""
        ca = ca_path or str(Path(self.pqc_cache_dir if pqc else self.cache_dir) / "ca.crt")
        if pqc:
            return {"chains": identity.verify_chain_pqc(ca, cert_pem),
                    "cn": identity.leaf_cn_pqc(cert_pem), "ca": ca, "pqc": True}
        return {"chains": identity.verify_chain(ca, cert_pem), "cn": identity.leaf_cn(cert_pem),
                "ca": ca, "pqc": False}

    def check_freshness(self, ts, max_age=None):
        """Is an envelope timestamp inside its replay window? -> (ok, reason).
        `identity.check_freshness()` verbatim — the FIRST check both certless transports run, ahead
        of chain/signature, so a stale envelope costs no crypto. Symmetric by design (a little clock
        skew either way is fine), which is why a node whose clock is ahead fails this too."""
        return identity.check_freshness(ts, max_age or identity.MAX_ENVELOPE_AGE_S)

    def fetch_identity(self, cache_dir=None, confirm=False):
        """Enrol this node with the Server's `POST /p2p-cert` and cache the result -> {ok, cert,
        key, ca, detail}. **Refuses unless `confirm=True`.**

        `identity.fetch_own_cert()` is idempotent against a POPULATED cache (it returns the three
        paths untouched), so this is only ever a real action against an EMPTY one — and that is the
        case worth gating. Enrolling mints a server-side cert record for this name, and the Server
        then refuses to hand the key out again to a bare bootstrap secret (`api_server.py`'s
        2026-07-27 anti-key-handout fix). A node that loses its local cache after that point cannot
        simply re-fetch: it needs the leaf revoked and deleted first. So a careless call against a
        scratch directory on a box that already has an identity does not create a spare copy — it
        gets a 401, and the mistake it protects against is doing this on a box whose real cache was
        just cleared. `confirm=True` runs the real, unmodified function."""
        if not confirm:
            return {"ok": False, "detail": "refused — pass confirm=True (enrolment mints a "
                                            "server-side cert record for this name and is not "
                                            "freely repeatable; see this method's docstring)"}
        self._need_env()
        try:
            cert, key, ca = identity.fetch_own_cert(self.server_api, self.secret, self.name,
                                                    cache_dir or self.cache_dir)
        except errors.IdentityError as e:
            return {"ok": False, "detail": str(e)}
        return {"ok": True, "cert": cert, "key": key, "ca": ca}

    # ── 02 · resolve (the NODE's side of GET /resolve, plus its own local cache) ────────────────
    def resolve(self, name, frm=None):
        """Ask the Server where `name` lives, AS THIS NODE -> {ip, via_chain, cross_tenant, ...},
        plus `stale`/`stale_age_s` when the answer came from this box's local cache because the
        Server was unreachable. `identity.resolve()` verbatim.

        Not the same question `Server-PC`'s own `resolve` unit answers. That one computes the
        answer from `netplan.json` on the Server. This one is the CLIENT half: it travels the real
        control-plane path (including the cert-proof headers `node_identity_headers` adds when
        `frm` is given), and it is the only side that can degrade to a cached answer. A caller that
        ignores `stale` is trusting a route up to `identity.RESOLVE_CACHE_MAX_AGE_S` seconds old —
        `client.py` prints a warning to stderr on exactly this, which is invisible to a library
        caller, so the flag is passed through here rather than logged."""
        self._need_env()
        return identity.resolve(self.server_api, self.secret, name, frm=frm or self.name,
                                cache_dir=self.cache_dir)

    def path(self, receiver_name):
        """"How does this node reach `receiver_name`" without sending anything -> {ip, via_chain,
        hops, cross_tenant, ...}. Exactly what `Client.path()` returns and computed the same way
        (a `resolve` with the hop names flattened out of `via_chain`) — re-expressed here rather
        than called through `Client` so it needs no cert fetch, which matters precisely on the box
        whose identity is the thing you are debugging."""
        r = self.resolve(receiver_name)
        return {**r, "hops": [h.get("name") for h in (r.get("via_chain") or [])]}

    def resolve_cache(self, cache_dir=None):
        """What this node has cached from past resolves, and whether each entry is still inside the
        degrade window -> [{name, ip, age_s, usable, path}], newest first.

        Nothing else in the codebase can see this. `identity.resolve()` writes an entry on every
        success and reads one back only on a failure — so on a healthy fleet the cache is written
        constantly and never read, and the first time it matters is an outage, when its contents
        decide whether an exchange proceeds on a possibly-stale route or refuses outright.
        `usable` applies the same `RESOLVE_CACHE_MAX_AGE_S` comparison the real degrade path
        applies. Read-only, no network."""
        d = Path(cache_dir or self.cache_dir) / "resolve-cache"
        if not d.is_dir():
            return []
        now, out = time.time(), []
        for f in d.glob("*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
                age = now - f.stat().st_mtime
            except (OSError, ValueError):
                continue
            out.append({"name": rec.get("name") or f.stem, "ip": rec.get("ip"),
                        "age_s": int(age), "usable": age <= identity.RESOLVE_CACHE_MAX_AGE_S,
                        "max_age_s": identity.RESOLVE_CACHE_MAX_AGE_S, "path": str(f)})
        return sorted(out, key=lambda r: r["age_s"])

    def peer_cert(self, name):
        """Another node's PUBLIC certificate PEM, from the Server's `POST /p2p-peer-cert`.
        `identity.fetch_peer_cert()` verbatim — never a private key, and deliberately not cached
        (a peer's cert can be revoked and reissued between two messages). This is what the
        `coap-enc` tech fetches to encrypt a payload to a peer; on its own it is also the way to
        check what CN/SAN the fleet currently believes a name has, without connecting to it."""
        self._need_env()
        return identity.fetch_peer_cert(self.server_api, self.secret, name)

    # ── 03 · policy (receiver-role/policy_client.py — the per-pair question, fail-closed) ───────
    def policy_check(self, sender, receiver):
        """May `sender` talk to `receiver`? -> (allowed, reason). `policy_client.check()` verbatim —
        the exact call `server.py::_authorized_or_403` and `coap_server.py` make before ANY handler
        runs, on every use case and every tech.

        Fail-closed, and that is the behaviour worth being able to observe: an unreachable Server
        does not mean 'no opinion', it means denied, with the reason string saying so. Distinct
        from `Server-PC`'s `p2p_admin.p2p_authorize`, which evaluates the policy table locally on
        the Server; this one asks over the wire from where the receiver stands, so it also answers
        'can this node reach the policy oracle at all'."""
        self._need_env()
        return policy_check(self.server_api, self.secret, sender, receiver)

    def would_accept(self, sender):
        """Would THIS node's receiver accept an exchange from `sender` right now? -> (allowed,
        reason). `policy_check(sender, self.name)` — the same call this box's own receiver makes,
        with the receiver side filled in, so it can be asked before a peer tries and fails."""
        return self.policy_check(sender, self.name)

    def peers(self, direction="both", scope="tenant", candidates=None):
        """on-dev-api P4.3 — "who may I talk to / who may talk to me", in ONE call ->
        {ok, node, tenant, scope, outgoing: [{peer, role, use_cases}], incoming: [...],
        denied_outgoing: [{peer, reason}], denied_incoming: [...], unresolved: [name]}.

        `policy_check()` asked for every candidate, both ways (`direction` = "out" | "in" |
        "both"). Candidates: `candidates` if given, else every node the Server's
        `/fleet-node-state` knows plus this tenant's two infra peers (`<TENANT>-Router-PC`,
        `<TENANT>-Admin-PC`), each placed with a side-effect-free `/resolve`. `scope="tenant"`
        (default) keeps same-tenant peers only; `scope="all"` also asks about every cross-tenant
        node.

        Two honest limits: (1) the policy is per PAIR, so `use_cases` for an outgoing pair is every
        use case — the peer's own node-local switches (P2P_RM_ENABLED …) are invisible from here and
        can still refuse; `incoming` IS narrowed by THIS node's own switches. (2) every
        `/p2p-authorize` call is mirrored to TB as `p2p_policy_decision` and every deny is recorded
        in `/p2p-events` — which is why cross-tenant (default deny) is opt-in via `scope="all"`."""
        self._need_env()
        if direction not in ("out", "in", "both"):
            return {"ok": False, "detail": f"direction must be out|in|both, not {direction!r}"}
        try:
            me = identity.resolve(self.server_api, self.secret, self.name)
        except errors.P2PError as e:
            return {"ok": False, "node": self.name, "detail": f"cannot resolve myself: {e}"}
        tenant = me.get("tenant")
        if candidates is None:
            try:
                r = identity._get(self.server_api, "/fleet-node-state", self.secret)
                candidates = sorted((r.get("nodes") or {}).keys())
            except Exception as e:                                       # noqa: BLE001
                return {"ok": False, "node": self.name, "detail": f"/fleet-node-state: {e}"}
            if tenant:
                candidates += [f"{tenant.upper()}-Router-PC", f"{tenant.upper()}-Admin-PC"]
        incoming_uc = [u for u in ALL_USE_CASES
                       if not (u == "rm" and not rm_handler._enabled())
                       and not (u == "ml" and not ml_handler._enabled())
                       and not (u == "fetch" and not (fetch_handler and fetch_handler._enabled()))]
        out = {"ok": True, "node": self.name, "tenant": tenant, "scope": scope,
               "outgoing": [], "incoming": [], "denied_outgoing": [], "denied_incoming": [],
               "unresolved": []}
        for name in dict.fromkeys(candidates):
            if name == self.name:
                continue
            try:
                r = identity.resolve(self.server_api, self.secret, name)
            except errors.P2PError:
                out["unresolved"].append(name)
                continue
            if scope == "tenant" and r.get("tenant") != tenant:
                continue
            role = r.get("role")
            if direction in ("out", "both"):
                allowed, reason = self.policy_check(self.name, name)
                (out["outgoing"].append({"peer": name, "role": role,
                                         "use_cases": list(ALL_USE_CASES)}) if allowed else
                 out["denied_outgoing"].append({"peer": name, "role": role, "reason": reason}))
            if direction in ("in", "both"):
                allowed, reason = self.policy_check(name, self.name)
                (out["incoming"].append({"peer": name, "role": role, "use_cases": incoming_uc})
                 if allowed else
                 out["denied_incoming"].append({"peer": name, "role": role, "reason": reason}))
        return out

    # ── 04 · exchange (sender-role/client.py — read first, gated writes, no `rm`) ───────────────
    def peer_health(self, receiver_name, tech="mtls"):
        """Is `receiver_name`'s P2P receiver up, and is it who it claims to be? -> {ok, node,
        mutual_tls, ip, port, tls, via_chain} or raises.

        `GET /health` is the one route `server.py` deliberately leaves ungated (a liveness probe
        carries no data), so this needs no policy allowance — but it is NOT a bare ping: it goes
        through `Client._connect()`, which means the peer's certificate CN must equal
        `receiver_name` and its SAN IP must cover the address we resolved to. Those two checks were
        added to the sender on 2026-07-28 for a specific attack (any fleet node can present a valid
        fleet cert, so on this any-to-any fabric whoever holds the victim's /32 could answer for
        it), and this is the cheapest way to exercise them against a real peer."""
        c = self._client()
        conn, resolved, tls = c._connect(receiver_name, tech, c.SOCKET_TIMEOUT)
        try:
            conn.request("GET", "/health", headers={"X-P2P-Sender": self.name})
            resp = conn.getresponse()
            body = json.loads(resp.read() or b"{}")
        finally:
            conn.close()
        return {"status": resp.status, "ip": resolved.get("ip"),
                "port": self.https_port if tech == "https" else self.port,
                "via_chain": resolved.get("via_chain"), "tls": tls, **body}

    def preflight(self, receiver_name, tech="mtls"):
        """Everything that would happen before a byte of payload is sent, and then stop ->
        {resolve, connect, peer_cn_ok, san_ok, tls, policy: {allowed, reason}, would_succeed}.

        The four independent things a failed exchange could actually mean, separated: the Server
        could not name the peer; the peer is not listening; the peer is not who it claims; or the
        policy says no. `client.py` collapses all four into one raise at send time, and the comm-log
        mirror then records a failure whose `reason` is whichever one happened to fire first.

        Sends NOTHING: the TLS connection is opened (that is what proves the peer's identity — the
        cert only exists on a live handshake) and closed without a request. The policy question is
        asked of the Server, not of the peer, so this leaves no trace on the receiver at all."""
        out = {"receiver": receiver_name, "tech": tech, "would_succeed": False}
        try:
            resolved = self.resolve(receiver_name)
            out["resolve"] = {"ok": True, "ip": resolved.get("ip"),
                              "stale": bool(resolved.get("stale")),
                              "hops": [h.get("name") for h in (resolved.get("via_chain") or [])]}
        except errors.P2PError as e:
            out["resolve"] = {"ok": False, "reason": str(e)}
            return out
        c = self._client()
        try:
            conn, _resolved, tls = c._connect(receiver_name, tech, c.SOCKET_TIMEOUT)
            conn.close()
            # _connect raises IdentityError on a CN or SAN mismatch and PeerUnreachable on a dead
            # port -- reaching here means all three passed, which is why they are reported together
            # rather than re-derived (re-deriving would be a second, drifting copy of the check).
            out["connect"] = {"ok": True}
            out["peer_cn_ok"] = out["san_ok"] = True
            out["tls"] = tls
        except errors.IdentityError as e:
            out["connect"] = {"ok": True, "reason": str(e)}
            out["peer_cn_ok"] = out["san_ok"] = False
            return out
        except errors.P2PError as e:
            out["connect"] = {"ok": False, "reason": str(e)}
            return out
        allowed, reason = self.policy_check(self.name, receiver_name)
        out["policy"] = {"allowed": allowed, "reason": reason}
        out["would_succeed"] = allowed
        return out

    def build_envelope(self, use_case, payload=None, data=b"", tech="https"):
        """Build the exact signed envelope an envelope-tech exchange would put on the wire, and
        verify it here -> {envelope, signable_bytes, verified, cn, fresh, sender}. Sends nothing,
        touches no peer, needs no policy allowance.

        `Client._envelope()` and `Client._signed_payload()` verbatim, then the receiver's own four
        checks (`server.py::_sig_verify_or_401` runs freshness → chain → CN-vs-claim → signature)
        applied locally to what was just built. That round-trip is the point: it answers "can this
        node produce an envelope its peers will accept" — a question that otherwise only gets
        answered by a peer 401'ing mid-exchange, where the reason lands in the peer's log and not
        this one's. `tech="pqc"` signs with the ML-DSA-65 key instead and verifies against the PQC
        CA, so the PQC toolchain is exercised end to end without needing a PQC-provisioned peer."""
        if tech not in ("https", "pqc"):
            raise ValueError(f"tech {tech!r} carries no signed envelope this method can build — "
                             f"one of 'https', 'pqc' (mtls's identity is the handshake; coap-enc "
                             f"signs the CIPHERTEXT, which needs the receiver's public cert — use "
                             f"peer_cert() for that; plain coap signs the same bytes 'https' does, "
                             f"so build_envelope('...', tech='https') shows you that envelope)")
        c = self._client()
        signed = c._signed_payload(use_case, payload or {}, data)
        env = c._envelope(tech, signed, c._new_exchange_id())
        cert_pem = base64.b64decode(env["cert"]).decode()
        payload_bytes = json.dumps(env["payload"], sort_keys=True).encode()
        signable = identity.signable_with_ts(payload_bytes, env["ts"])
        fresh_ok, fresh_reason = identity.check_freshness(env["ts"])
        chk = self.verify_peer_cert(cert_pem, pqc=(tech == "pqc"))
        verify = (identity.verify_payload_signature_pqc if tech == "pqc"
                  else identity.verify_payload_signature)
        return {"tech": tech, "use_case": use_case, "sender": env["sender"], "xid": env["xid"],
                "ts": env["ts"], "fresh": fresh_ok, "fresh_reason": fresh_reason,
                "chains": chk["chains"], "cn": chk["cn"], "cn_matches_claim": chk["cn"] == env["sender"],
                "verified": verify(cert_pem, signable, base64.b64decode(env["sig"])),
                "signable_bytes": len(signable), "envelope_bytes": len(json.dumps(env)),
                "envelope": env}

    def get_status(self, receiver_name, tech="mtls"):
        """Use case STATUS: ask a peer about itself -> {ok, requested_by, active, uptime_s, ts,
        status, via_chain}. `Client.get_status()` verbatim.

        Ungated here because it is the one use case that changes nothing on the receiver:
        `handlers/status.py` reads two clocks and returns. It does go through the full stack —
        identity, per-pair policy, the comm-log mirror on both sides — so it is the cheapest honest
        end-to-end proof that a pair works, and the right thing to call before anything gated."""
        return self._client().get_status(receiver_name, tech=tech)

    def get_status_details(self, receiver_name, tech="mtls"):
        """STATUS with `details` (2026-10-02): the reply also carries the receiver's Network Map row
        (`details`: ip, real_ip, role, lifecycle state, segment, parent, hops, via_chain — its on-board
        API's map_details_self). Same gate and policy as get_status; a receiver on older code answers
        without `details`. The comm-log rows on both sides stay the plain status row."""
        return self._client().get_status(receiver_name, tech=tech, details=True)

    def self_details(self):
        """THIS node's own Network Map row from its on-board API (no P2P traffic) — the sender half of
        get_status_details. -> map_details_self() or {ok: False, detail}."""
        from common import onboard
        return onboard.map_details(max_age=0)

    def send_message(self, receiver_name, payload: dict, tech="mtls", confirm=False):
        """Use case MESSAGE: deliver a JSON body to a peer -> {ok, from, sha256, bytes, status,
        via_chain}. **Refuses unless `confirm=True`.** `Client.send_message()` verbatim.

        The reply returns a `sha256` of the payload, not the payload itself: echoing it back put the
        decrypted content on the wire in cleartext even under `--tech coap-enc` (fixed 2026-08-11).
        Compare the digest if you need to confirm exactly what the peer received.

        Gated because it writes on ANOTHER live box — `handlers/message.py` appends one record to
        that node's `/var/lib/p2p/messages.log`. The radius is genuinely that small (an append to a
        log, plus the two comm-log mirror records every exchange files), which is why the real path
        was tested end-to-end rather than only refused; but it is still someone else's box and an
        append is not undoable, so the default stays refused."""
        if not confirm:
            return {"ok": False, "detail": "refused — pass confirm=True (this appends a real "
                                            "record to another live node's messages.log)"}
        return self._client().send_message(receiver_name, payload, tech=tech)

    def deliver_file(self, receiver_name, data: bytes, dest_filename, tech="mtls", confirm=False):
        """Use case FILE: deliver raw bytes to a peer -> {ok, written_to, bytes, sha256, status}.
        **Refuses unless `confirm=True`.** `Client.deliver_file()` verbatim.

        `handlers/file_delivery.handle()` confines the write to the receiver's own `DROP_DIR` by
        taking `Path(dest_path).name` — a sender picks a NAME, never a location, so there is no
        path-escape radius to worry about. What remains is real and worth the gate: an existing
        file of the same name in that directory is overwritten with no warning and no backup. Use
        a name nothing else would choose."""
        if not confirm:
            return {"ok": False, "detail": "refused — pass confirm=True (this writes a real file "
                                            "into another live node's drop directory, overwriting "
                                            "any same-named file there)"}
        return self._client().deliver_file(receiver_name, data, dest_filename, tech=tech)

    def ml_op(self, receiver_name, method, params=None, timeout=None, tech="mtls", confirm=False):
        """Use case ML: run ONE enumerated ML operation on a peer -> {ok, method, result|reason,
        refused?, timed_out?}. `Client.ml_op()` verbatim.

        **The four read-only methods run without confirmation** (`list_models`, `get_model`,
        `read_model_file`, `run_status` — verbatim `.env.example`'s own suggested read-only
        `P2P_ML_ALLOW`); **every other `ML_METHODS` verb needs `confirm=True`**, because it starts,
        stops, reparameterises or replaces something on a live box. An unknown verb is refused HERE
        rather than travelling to the peer to be refused there — the same list `handlers/ml.py`
        enumerates, so the two cannot disagree.

        Worth knowing before reading a result: this crosses a VM→container boundary. The receiver
        hands the call to its device/gateway agent through a bind-mounted spool and waits; a node
        whose container is down (or was built without `p2p_ml_agent.py`) answers `refused` with
        that exact diagnosis rather than a timeout — see `ml_spool()` for the local half of it."""
        if method not in ml_handler.ML_METHODS:
            return {"ok": False, "refused": True, "method": method,
                    "reason": f"unknown ML method {method!r} — one of {list(ml_handler.ML_METHODS)}"}
        if method not in ML_READ_ONLY and not confirm:
            return {"ok": False, "refused": True, "method": method,
                    "detail": f"refused — '{method}' changes state on {receiver_name}; pass "
                              f"confirm=True (read-only without it: {list(ML_READ_ONLY)})"}
        return self._client().ml_op(receiver_name, method, params or {}, timeout=timeout, tech=tech)

    def fetch_file(self, receiver_name, remote_path, tech="mtls"):
        """on-dev-api P4.1 — use case FETCH: read ONE file off a peer -> the receiver's reply plus
        `data` (bytes) and `sha256_ok`. `Client.fetch_file()` verbatim.

        Ungated here (no `confirm=`) for the same reason `get_status` is: it changes nothing on the
        receiver beyond one line in its `/var/lib/p2p/fetch.log`. The receiver serves only paths
        under its own `P2P_FETCH_ROOTS` (see `fetch_gate()` for this node's own answer)."""
        return self._client().fetch_file(receiver_name, remote_path, tech=tech)

    # ── 05 · receiver_gates (handlers/{rm,ml}.py — what THIS node refuses, before the network) ──
    def rm_gate(self, cmd=None):
        """What would THIS node's receiver do with a peer's `rm` command, before the network is
        consulted? -> {enabled, allow_prefixes, cmd, would_refuse, reason}.

        `handlers/rm.py`'s own `_enabled()` and `_allowed_prefixes()` verbatim, with this module's
        `handle()` refusal logic applied in the same order — so the answer is the real one, read
        out of the same process environment the receiver reads.

        The two switches are node-local and unreachable from the network, which is the whole point
        of them and also why nothing can tell you their effective state from outside: a peer that
        is refused learns only that this node declines RM. `P2P_RM_ENABLED` defaults to ON and the
        in-tenant policy default is `allow`, so on a stock node every peer in the tenant can run
        commands here — this is how you confirm whether that is still true of a given box.

        (This is only the LOCAL half of the `rm` use case. Firing a command at a peer is not
        wrapped by this package at all — see the module docstring for why.)"""
        enabled = rm_handler._enabled()
        prefixes = rm_handler._allowed_prefixes()
        out = {"node": self.name, "enabled": enabled, "allow_prefixes": prefixes,
               "log_file": str(rm_handler.LOG_FILE),
               "default_timeout_s": rm_handler.DEFAULT_TIMEOUT,
               "max_timeout_s": rm_handler.MAX_TIMEOUT}
        if cmd is None:
            return out
        out["cmd"] = cmd
        if not cmd or not isinstance(cmd, str) or not cmd.strip():
            return {**out, "would_refuse": True, "reason": "no command given"}
        if not enabled:
            return {**out, "would_refuse": True, "reason": f"{self.name} does not accept "
                                                            f"peer-driven remote management "
                                                            f"(P2P_RM_ENABLED=0)"}
        if prefixes is not None and not any(cmd.strip().startswith(p) for p in prefixes):
            return {**out, "would_refuse": True,
                    "reason": f"command is not on {self.name}'s P2P_RM_ALLOW list "
                              f"({', '.join(prefixes)})"}
        return {**out, "would_refuse": False, "reason": None}

    def ml_gate(self, method=None):
        """The same question for the `ml` use case -> {enabled, allowed_methods, all_methods,
        read_only_methods, method, would_refuse, reason}. `handlers/ml.py`'s `_enabled()` and
        `_allowed_methods()` verbatim.

        Note what `_allowed_methods()` actually does with `P2P_ML_ALLOW`: it INTERSECTS the
        configured list with `ML_METHODS`, so a typo in that env var silently narrows the surface
        instead of failing loudly — a node configured `list_models,get_modle` answers only
        `list_models` and says nothing about the second. Comparing `allowed_methods` against
        `configured` here is the only way to see that from the box itself."""
        enabled = ml_handler._enabled()
        allowed = ml_handler._allowed_methods()
        configured = [m.strip() for m in os.environ.get("P2P_ML_ALLOW", "").split(",") if m.strip()]
        out = {"node": self.name, "enabled": enabled,
               "all_methods": list(ml_handler.ML_METHODS),
               "read_only_methods": list(ML_READ_ONLY),
               "allowed_methods": sorted(allowed),
               "configured": configured or None,
               "unrecognised_in_config": sorted(set(configured) - set(ml_handler.ML_METHODS)) or None,
               "spool_dir": str(ml_handler.SPOOL_DIR), "log_file": str(ml_handler.LOG_FILE),
               "default_timeout_s": ml_handler.DEFAULT_TIMEOUT,
               "max_timeout_s": ml_handler.MAX_TIMEOUT}
        if method is None:
            return out
        out["method"] = method
        if not enabled:
            return {**out, "would_refuse": True,
                    "reason": "this node does not accept peer-driven ML (P2P_ML_ENABLED=0)"}
        if method not in allowed:
            known = ("unknown" if method not in ml_handler.ML_METHODS
                     else "not on this node's P2P_ML_ALLOW list")
            return {**out, "would_refuse": True, "reason": f"ML method '{method}' is {known}"}
        return {**out, "would_refuse": False, "reason": None}

    def fetch_gate(self, path=None):
        """The same question for the `fetch` use case (on-dev-api P4.1) -> {enabled, roots,
        max_bytes, path, would_refuse, reason}. `handlers/fetch.gate()` verbatim — the function the
        live handler calls — so this is the real answer for this node's environment."""
        if fetch_handler is None:
            return {"node": self.name, "enabled": False, "detail":
                    "this /opt/p2p predates the fetch use case (needs p2p rollout)"}
        out = {"node": self.name, "enabled": fetch_handler._enabled(),
               "roots": fetch_handler._roots(), "max_bytes": fetch_handler._max_bytes(),
               "log_file": str(fetch_handler.LOG_FILE)}
        if path is None:
            return out
        real, reason = fetch_handler.gate(path)
        return {**out, "path": path, "real_path": real, "would_refuse": real is None,
                "reason": reason}

    def ml_spool(self, spool_dir=None):
        """Is anything servicing this node's ML spool? -> {spool_dir, exists, pending, oldest_age_s,
        stale_responses, agent_servicing, detail}.

        The local half of the boundary `ml_op()` crosses. `handlers/ml.py` writes a `.req.json`,
        polls for a `.res.json`, and on timeout distinguishes two very different failures by
        whether the request file is STILL THERE: still queued means nothing picked it up (the
        device/gateway container is down, or was built without `p2p_ml_agent.py`); gone means the
        agent took it and did not answer in budget. That distinction is only visible at the moment
        of timeout, inside the handler. This reports the same signal standing still — a non-zero
        `pending` with a rising `oldest_age_s` is a node whose agent is not running, before any
        peer has spent a 60-second budget discovering it.

        Read-only: no request is written, nothing is unlinked (`.res.json` files left behind by a
        caller that gave up are COUNTED, not swept — sweeping them here would race a live handler
        that is one poll away from reading one)."""
        d = Path(spool_dir or ml_handler.SPOOL_DIR)
        out = {"spool_dir": str(d), "exists": d.is_dir(), "pending": 0, "stale_responses": 0,
               "oldest_age_s": None}
        if not d.is_dir():
            out["detail"] = "no ML spool directory — nothing has ever asked this node for ML"
            return out
        now = time.time()
        ages = []
        for f in d.glob("*.req.json"):
            try:
                ages.append(now - f.stat().st_mtime)
            except OSError:
                continue
        out["pending"] = len(ages)
        out["stale_responses"] = len(list(d.glob("*.res.json")))
        if ages:
            out["oldest_age_s"] = int(max(ages))
        # A request older than the handler's own ceiling can no longer be answered in time by
        # anyone -- whoever asked stopped listening. That is the signature of an absent agent.
        out["agent_servicing"] = not (out["oldest_age_s"] or 0) > ml_handler.MAX_TIMEOUT
        if not out["agent_servicing"]:
            out["detail"] = (f"a request has sat unread for {out['oldest_age_s']}s (> the handler's "
                             f"{ml_handler.MAX_TIMEOUT}s ceiling) — no ML agent is servicing "
                             f"{d} on this node")
        return out


# ── cert field reading (openssl CLI, the same idiom identity.py itself uses) ────────────────────
def _cert_fields(pem, openssl_bin="openssl", env=None):
    """-> {cn, issuer_cn, not_before, not_after, days_left, expired, san_ips, san_dns} for the LEAF
    of `pem` (which may be a leaf+intermediate bundle). One `openssl x509` call; `-noout` with the
    fields asked for by name, rather than parsing `-text`, so the output shape is stable."""
    try:
        p = subprocess.run([openssl_bin, "x509", "-noout", "-subject", "-issuer", "-dates",
                            "-ext", "subjectAltName"],
                           input=pem, text=True, capture_output=True, env=env)
    except OSError as e:
        return {"detail": f"could not run {openssl_bin}: {e}"}
    if p.returncode != 0:
        return {"detail": f"openssl could not read this certificate: {p.stderr.strip()}"}
    out, txt = {}, p.stdout
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            out["cn"] = _rdn_cn(line)
        elif line.startswith("issuer="):
            out["issuer_cn"] = _rdn_cn(line)
        elif line.startswith("notBefore="):
            out["not_before"] = line.split("=", 1)[1]
        elif line.startswith("notAfter="):
            out["not_after"] = line.split("=", 1)[1]
        elif line.startswith("IP Address:") or line.startswith("DNS:"):
            out.setdefault("san_ips", []).extend(
                v.split("IP Address:")[1] for v in line.split(", ") if v.startswith("IP Address:"))
            out.setdefault("san_dns", []).extend(
                v.split("DNS:")[1] for v in line.split(", ") if v.startswith("DNS:"))
    if out.get("not_after"):
        try:
            expiry = time.mktime(time.strptime(out["not_after"], "%b %d %H:%M:%S %Y %Z"))
            out["days_left"] = int((expiry - time.time()) // 86400)
            out["expired"] = out["days_left"] < 0
        except ValueError:
            pass
    return out


def _rdn_cn(line):
    """CN out of an `openssl x509 -subject/-issuer` line: `subject=CN = X, O = Y`. Same job as
    `identity.leaf_cn()` does for a whole PEM, but on a line we have already paid for."""
    for part in line.split("=", 1)[1].split(","):
        k, _, v = part.partition("=")
        if k.strip() in ("CN", "commonName"):
            return v.strip()
    return None


def default_api():
    return P2PAPI()
