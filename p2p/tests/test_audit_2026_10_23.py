#!/usr/bin/env python3
"""Regression tests for the 2026-10-23 audit fixes (no network, no fleet identity needed).

  1. tech labels  -- server.py / coap_server.py name a relay-fronted delivery (quic-*, coap-dtls*) from a
                     header/option the LOCAL relay sets, and ignore it from anybody else.
  2. timing block -- not-applicable phases are None (never 0.0); a helper-reported handshake / request
                     phase is carried; network_ms excludes the helper's start-up; client_overhead_ms
                     (v2 semantics: see test_metrics_v2.py).
  3. relay config -- the ML-DSA QUIC relay pins the hybrid group by default; the relay names its own tech.
Run: python3 p2p/tests/test_audit_2026_10_23.py   (the relay-config part needs the quic-pqc venv; else skipped)
"""
import importlib.util, os, subprocess, sys, types, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
P2P = os.path.join(HERE, "..")
sys.path.insert(0, P2P)
sys.path.insert(0, os.path.join(P2P, "receiver-role"))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(P2P, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TechLabels(unittest.TestCase):
    def test_http_header_only_from_loopback_and_known_values(self):
        server = load("p2p_server_t", "receiver-role/server.py")
        H = server.P2pHandler if hasattr(server, "P2pHandler") else None
        cls = next(c for c in vars(server).values()
                   if isinstance(c, type) and hasattr(c, "_relay_fronted_tech"))
        def fake(addr, val):
            o = types.SimpleNamespace(client_address=(addr, 5555),
                                      headers={"X-P2P-Relay-Tech": val} if val else {})
            o.headers = types.SimpleNamespace(get=lambda k, d=None, h=o.headers: h.get(k, d))
            o.RELAY_FRONTED_TECHS = cls.RELAY_FRONTED_TECHS
            return cls._relay_fronted_tech(o)
        self.assertEqual(fake("127.0.0.1", "quic-classical-mutual"), "quic-classical-mutual")
        self.assertEqual(fake("127.0.0.1", "quic-pqc"), "quic-pqc")
        self.assertIsNone(fake("10.2.0.100", "quic-pqc"), "a network peer must not name its own tech")
        self.assertIsNone(fake("127.0.0.1", "mtls"), "only relay-fronted techs may be claimed")
        self.assertIsNone(fake("127.0.0.1", "pqc"))
        self.assertIsNone(fake("127.0.0.1", None))

    def test_coap_option_only_from_loopback_and_known_values(self):
        try:
            import aiocoap  # noqa: F401
        except ImportError:
            self.skipTest("aiocoap not installed")
        cs = load("p2p_coap_server_t", "receiver-role/coap_server.py")
        def req(addr, val):
            opt = types.SimpleNamespace(value=val.encode()) if val is not None else None
            return types.SimpleNamespace(
                remote=types.SimpleNamespace(sockaddr=(addr, 1, 0, 0)),
                opt=types.SimpleNamespace(get_option=lambda n: (opt,) if opt and n == cs.RELAY_TECH_OPTION else ()))
        self.assertEqual(cs.relay_fronted_tech(req("::ffff:127.0.0.1", "coap-dtls-pqc-mutual")), "coap-dtls-pqc-mutual")
        self.assertEqual(cs.relay_fronted_tech(req("::1", "coap-dtls")), "coap-dtls")
        self.assertIsNone(cs.relay_fronted_tech(req("::ffff:10.2.0.100", "coap-dtls")))
        self.assertIsNone(cs.relay_fronted_tech(req("::ffff:127.0.0.1", "coap-enc")))
        self.assertIsNone(cs.relay_fronted_tech(req("::ffff:127.0.0.1", None)))


class RelayTlsFacts(unittest.TestCase):
    """The receiver's own log row carries what the LOCAL relay observed (QUIC header / DTLS option), nowhere else."""

    def test_http_header(self):
        server = load("p2p_server_t2", "receiver-role/server.py")
        cls = next(c for c in vars(server).values() if isinstance(c, type) and hasattr(c, "_relay_tls_facts"))
        def facts(addr, tech, tls):
            hdrs = {"X-P2P-Relay-Tech": tech, "X-P2P-Relay-Tls": tls}
            o = types.SimpleNamespace(client_address=(addr, 1), RELAY_FRONTED_TECHS=cls.RELAY_FRONTED_TECHS,
                                      headers=types.SimpleNamespace(get=lambda k, d=None: hdrs.get(k, d)))
            o._relay_fronted_tech = lambda: cls._relay_fronted_tech(o)
            return cls._relay_tls_facts(o)
        good = '{"tls_version":"TLSv1.3","group":"X25519","tls_cipher":"TLS_AES_256_GCM_SHA384","tls_bits":256,"evil":"x","tls_ca":{"a":1}}'
        self.assertEqual(facts("127.0.0.1", "quic-classical", good),
                         {"tls_version": "TLSv1.3", "group": "X25519", "tls_cipher": "TLS_AES_256_GCM_SHA384", "tls_bits": 256})
        self.assertEqual(facts("10.2.0.100", "quic-classical", good), {}, "a network peer cannot supply facts")
        self.assertEqual(facts("127.0.0.1", "mtls", good), {}, "only relay-fronted techs")
        self.assertEqual(facts("127.0.0.1", "quic-pqc", "not json"), {})
        self.assertEqual(facts("127.0.0.1", "quic-pqc", "[1,2]"), {})

    def test_coap_option(self):
        try:
            import aiocoap  # noqa: F401
        except ImportError:
            self.skipTest("aiocoap not installed")
        cs = load("p2p_coap_server_t2", "receiver-role/coap_server.py")
        def req(addr, tech, tls):
            def get(n):
                if n == cs.RELAY_TECH_OPTION and tech:
                    return (types.SimpleNamespace(value=tech.encode()),)
                if n == cs.RELAY_TLS_OPTION and tls:
                    return (types.SimpleNamespace(value=tls.encode()),)
                return ()
            return types.SimpleNamespace(remote=types.SimpleNamespace(sockaddr=(addr, 1, 0, 0)), opt=types.SimpleNamespace(get_option=get))
        good = '{"tls_version":"DTLSv1.3","group":"X25519MLKEM768","tls_peer_key":"RSA-2048","x":"y"}'
        self.assertEqual(cs.relay_tls_facts(req("::ffff:127.0.0.1", "coap-dtls-pqc", good)),
                         {"tls_version": "DTLSv1.3", "group": "X25519MLKEM768", "tls_peer_key": "RSA-2048"})
        self.assertEqual(cs.relay_tls_facts(req("::ffff:10.2.0.100", "coap-dtls-pqc", good)), {})
        self.assertEqual(cs.relay_tls_facts(req("::ffff:127.0.0.1", "coap-enc", good)), {})
        self.assertEqual(cs.relay_tls_facts(req("::ffff:127.0.0.1", "coap-dtls", "{bad")), {})


class TimingBlock(unittest.TestCase):
    """(updated 2026-10-23 v2: verify_peer_ms / handshake_in_exchange retired; a helper's request phase IS
    exchange_ms now, so every tech's phases add up to total_ms)"""
    def setUp(self):
        self.client = load("p2p_client_t", "sender-role/client.py")

    def test_not_applicable_is_none_not_zero(self):
        t = self.client._Timing("coap")
        t.lap("resolve_ms"); t.lap("prepare_ms"); t.lap("exchange_ms")
        b = t.block(receiver={"total_ms": 1.0})
        for k in ("tcp_connect_ms", "handshake_ms", "client_overhead_ms") + self.client._Timing.NET_KEYS:
            self.assertIsNone(b[k], k)
        for gone in ("verify_peer_ms", "identity_refresh_ms", "handshake_in_exchange", "clock"):
            self.assertNotIn(gone, b)

    def test_helper_phases_split_handshake_request_and_overhead(self):
        t = self.client._Timing("quic-classical")
        t.lap("resolve_ms"); t.lap("prepare_ms")
        t.ms["exchange_ms"] = 500.0                      # whole subprocess, as the sender saw it
        t.note(handshake_ms=30.0, wire_ms=100.0)         # what the helper measured inside
        b = t.block(receiver={"total_ms": 60.0})
        self.assertEqual(b["handshake_ms"], 30.0)
        self.assertEqual(b["exchange_ms"], 100.0)        # the request phase, not the subprocess
        self.assertEqual(b["network_ms"], 40.0)          # 100 - 60: NOT 500 - 60
        self.assertEqual(b["client_overhead_ms"], 370.0)  # 500 - 30 - 100
        self.assertIsNone(b["tcp_connect_ms"])

    def test_plain_tls_tech_unchanged(self):
        t = self.client._Timing("mtls")
        t.ms.update(tcp_connect_ms=2.0, handshake_ms=15.0, exchange_ms=100.0)
        b = t.block(receiver={"total_ms": 40.0})
        self.assertEqual((b["tcp_connect_ms"], b["handshake_ms"], b["network_ms"]), (2.0, 15.0, 60.0))
        self.assertIsNone(b["client_overhead_ms"])


class StunnelFrontedTechs(unittest.TestCase):
    """pqkex / pqkex-mutual / hybrid / hybrid-mutual: each stunnel section forwards to its own loopback listener, which names the tech."""

    def test_conf_ports_match_the_receivers_fronted_listeners(self):
        server = load("p2p_server_t3", "receiver-role/server.py")
        import re
        conf = open(os.path.join(P2P, "..", "PQC-bench", "p2p-proxy", "p2p-pqc-proxy.conf")).read()
        secs = dict(re.findall(r"(?m)^\[([\w-]+)\]\naccept = \d+\nconnect = 127\.0\.0\.1:(\d+)", conf))
        want = {"p2p-pqc": "pqkex", "p2p-pqc-mutual": "pqkex-mutual", "p2p-hybrid": "hybrid", "p2p-hybrid-mutual": "hybrid-mutual"}
        self.assertEqual(set(secs), set(want))
        for sec, tech in want.items():
            self.assertEqual(int(secs[sec]), server.FRONTED_BACKENDS[tech], sec)
        self.assertEqual(len(set(server.FRONTED_BACKENDS.values())), 4, "four distinct ports")
        self.assertNotIn(8442, server.FRONTED_BACKENDS.values())


class DtlsRelayConfig(unittest.TestCase):
    def _group(self, env):
        code = ("import sys; sys.path.insert(0, %r); import coap_dtls_pqc_relay as r; "
                "print(r.REQUIRE_GROUP or '-', r._relay_tech(False), r._relay_tech(True))" % os.path.join(P2P, "receiver-role"))
        e = {k: v for k, v in os.environ.items() if not k.startswith("P2P_COAP_DTLS")}
        e.update(env)
        out = subprocess.run([sys.executable, "-c", code], env=e, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr[-400:])
        return out.stdout.split()

    def test_pqc_relay_pins_mlkem768_by_default(self):
        self.assertEqual(self._group({}), ["ML_KEM_768", "coap-dtls-pqc", "coap-dtls-pqc-mutual"])

    def test_classical_relay_and_opt_out(self):
        self.assertEqual(self._group({"P2P_COAP_DTLS_REQUIRE_GROUP": "X25519"}), ["X25519", "coap-dtls", "coap-dtls-mutual"])
        self.assertEqual(self._group({"P2P_COAP_DTLS_REQUIRE_GROUP": "*"})[0], "-")


class RelayConfig(unittest.TestCase):
    VENV = "/opt/pqc-libs/quic-pqc-venv/bin/python3"

    def _probe(self, **env):
        if not os.path.exists(self.VENV):
            self.skipTest("quic-pqc venv not installed")
        code = ("import sys; sys.path.insert(0, %r); sys.path.insert(0, '/opt/PQC-bench/aioquic-patch'); "
                "import quic_pqc_relay as r; print(r.RELAY_TECH, ','.join(r.QUIC_GROUPS))"
                % os.path.join(P2P, "receiver-role"))
        e = {k: v for k, v in os.environ.items() if not k.startswith(("QUIC_", "P2P_QUIC"))}
        e.update(env)
        out = subprocess.run([self.VENV, "-c", code], env=e, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr[-400:])
        return out.stdout.split()[-2:] if len(out.stdout.split()) >= 2 else (out.stdout.strip(), "")

    def test_mldsa_relay_pins_mlkem768_by_default(self):
        self.assertEqual(self._probe(), ["quic-pqc", "MLKEM768"])
        self.assertEqual(self._probe(P2P_QUIC_PQC_MUTUAL="1"), ["quic-pqc-mutual", "MLKEM768"])

    def test_classical_relays_name_themselves(self):
        self.assertEqual(self._probe(QUIC_CERT_MODE="classical", QUIC_GROUPS="X25519"),
                         ["quic-classical", "X25519"])
        self.assertEqual(self._probe(QUIC_CERT_MODE="classical", QUIC_GROUPS="X25519", P2P_QUIC_PQC_MUTUAL="1"),
                         ["quic-classical-mutual", "X25519"])
        self.assertEqual(self._probe(QUIC_CERT_MODE="classical", QUIC_GROUPS="X25519MLKEM768"),
                         ["quic-hybrid", "X25519MLKEM768"])

    def test_client_chain_verifier_accepts_fleet_leaf_and_rejects_stranger(self):
        """_verify_client_chain (the check now run INSIDE the handshake) against a throwaway CA."""
        if not os.path.exists(self.VENV):
            self.skipTest("quic-pqc venv not installed")
        import tempfile
        code = r"""
import datetime, os, sys, tempfile
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
d = tempfile.mkdtemp()
def key(): return rsa.generate_private_key(65537, 2048)
def cert(subj, k, issuer, ik, ca=False):
    n = lambda c: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, c)])
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(n(subj)).issuer_name(n(issuer)).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return b.sign(ik, hashes.SHA256())
ck, lk, sk = key(), key(), key()
ca = cert("test-ca", ck, "test-ca", ck, ca=True)
good = cert("T1-node", lk, "test-ca", ck)
stranger = cert("T1-node", sk, "T1-node", sk)          # self-signed, not from the CA
open(d + "/ca.crt", "wb").write(ca.public_bytes(serialization.Encoding.PEM))
os.environ["QUIC_CERT_MODE"] = "classical"; os.environ["QUIC_CLASSICAL_CERT_DIR"] = d
sys.path.insert(0, %r)
import quic_pqc_relay as r
r._verify_client_chain(good, [])
print("good ok")
try:
    r._verify_client_chain(stranger, [])
    print("stranger ACCEPTED")
except Exception:
    print("stranger rejected")
""" % os.path.join(P2P, "receiver-role")
        out = subprocess.run([self.VENV, "-c", code], capture_output=True, text=True,
                             env={**os.environ, "PYTHONPATH": "/opt/PQC-bench/aioquic-patch"})
        self.assertIn("good ok", out.stdout, out.stderr[-600:])
        self.assertIn("stranger rejected", out.stdout, out.stdout + out.stderr[-600:])

    def test_explicit_opt_out(self):
        self.assertEqual(self._probe(QUIC_GROUPS="*")[0], "quic-pqc")


if __name__ == "__main__":
    unittest.main(verbosity=2)
