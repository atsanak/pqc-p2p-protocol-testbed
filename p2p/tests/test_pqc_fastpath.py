#!/usr/bin/env python3
"""The in-process ML-DSA-65 fast paths in p2p/common/identity.py (2026-10-23) must give EXACTLY the oqs-provider CLI
answers. Needs a system OpenSSL >= 3.5 (native ML-DSA), this node's PQC identity in /var/lib/p2p/certs-pqc (readable),
and the private OpenSSL + oqs-provider build -- i.e. a P2P box (the Pis); skipped elsewhere.
Run (root on a Pi): python3 p2p/tests/test_pqc_fastpath.py
"""
import os, sys, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from common import identity  # noqa: E402

D = os.environ.get("P2P_PQC_CACHE_DIR", "/var/lib/p2p/certs-pqc")
KEY, CERT, CA = (os.path.join(D, f) for f in ("peer.key", "peer.crt", "ca.crt"))
HAVE = (identity._libcrypto() is not None and identity.pqc_available()
        and all(os.access(p, os.R_OK) for p in (KEY, CERT, CA)))


@unittest.skipUnless(HAVE, "needs OpenSSL >= 3.5, the oqs-provider CLI and a readable PQC identity")
class PqcFastPath(unittest.TestCase):
    def setUp(self):
        self.cert = open(CERT).read()
        self.msg = os.urandom(4096)

    def cli_sign(self, msg):
        return identity.sign_payload(KEY, msg, openssl_bin=identity.PQC_OPENSSL, digest=None, env=identity.pqc_env())

    def cli_verify(self, msg, sig):
        return identity.verify_payload_signature(self.cert, msg, sig, openssl_bin=identity.PQC_OPENSSL, digest=None,
                                                 env=identity.pqc_env())

    def test_fast_sign_is_ml_dsa_65_and_cli_verifies_it(self):
        sig = identity._pqc_fast_sign(KEY, self.msg)
        self.assertEqual(len(sig), 3309, "ML-DSA-65 signature size (FIPS 204)")
        self.assertTrue(self.cli_verify(self.msg, sig))
        self.assertEqual(identity.sign_payload_pqc(KEY, self.msg)[:0], b"")

    def test_fast_verify_matches_cli_on_good_tampered_and_truncated(self):
        good = self.cli_sign(self.msg)
        for msg, sig in ((self.msg, good), (self.msg[:-1] + b"x", good), (self.msg, good[:-5]),
                         (self.msg, bytes(len(good)))):
            self.assertEqual(identity._pqc_fast_verify(self.cert, msg, sig), self.cli_verify(msg, sig))
            self.assertEqual(identity.verify_payload_signature_pqc(self.cert, msg, sig), self.cli_verify(msg, sig))

    def test_rsa_leaf_is_not_decided_by_the_fast_path(self):
        rsa_pem = open("/var/lib/p2p/certs/peer.crt").read()
        self.assertIsNone(identity._pqc_fast_verify(rsa_pem, self.msg, b"\x00" * 256), "non-ML-DSA -> CLI decides")

    def test_cn_and_san_match_the_cli(self):
        self.assertEqual(identity.leaf_cn_pqc(self.cert), identity.leaf_cn(self.cert, openssl_bin=identity.PQC_OPENSSL,
                                                                         env=identity.pqc_env()))
        fast = identity.leaf_san_ips(self.cert, openssl_bin=identity.PQC_OPENSSL, env=identity.pqc_env())
        identity_crypto = identity._CRYPTO
        try:
            identity._CRYPTO = False                       # force the CLI branch
            cli = identity.leaf_san_ips(self.cert, openssl_bin=identity.PQC_OPENSSL, env=identity.pqc_env())
        finally:
            identity._CRYPTO = identity_crypto
        self.assertEqual(fast, cli)

    def test_chain_cache_only_caches_success(self):
        identity._CHAIN_OK.clear()
        self.assertTrue(identity.verify_chain_pqc(CA, self.cert))
        self.assertEqual(len([k for k in identity._CHAIN_OK if k[0] == "pqc"]), 1)
        t = time.perf_counter(); self.assertTrue(identity.verify_chain_pqc(CA, self.cert))
        self.assertLess((time.perf_counter() - t) * 1000, 2, "second verdict comes from the cache")
        self.assertFalse(identity.verify_chain_pqc("/var/lib/p2p/certs/ca.crt", self.cert), "wrong CA never chains")
        self.assertEqual(len([k for k in identity._CHAIN_OK if k[0] == "pqc"]), 1, "a failure is not cached")


if __name__ == "__main__":
    unittest.main(verbosity=2)
