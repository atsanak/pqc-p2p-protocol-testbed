#!/usr/bin/env python3
"""The in-process fast paths in p2p/common/identity.py (2026-10-23) must give EXACTLY the openssl-CLI answers.

Each check runs the function twice -- the default call (fast path) and the same call with the absolute path
of the openssl binary (`/usr/bin/openssl`, which is not the literal "openssl" the fast path requires, so it
takes the original subprocess code) -- on a throwaway CA -> intermediate -> leaf chain and a stranger.
Run: python3 p2p/tests/test_identity_fastpath.py
"""
import datetime, os, shutil, subprocess, sys, tempfile, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
OPENSSL = shutil.which("openssl")

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    import ipaddress
    HAVE = OPENSSL is not None
except ImportError:
    HAVE = False

from common import identity  # noqa: E402


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def mk(subject, key, issuer, ikey, ca=False, ips=(), days=30, start_days=-1):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer)).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now + datetime.timedelta(days=start_days))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ips:
        b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(i)) for i in ips]), False)
    return b.sign(ikey, hashes.SHA256())


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM).decode()


@unittest.skipUnless(HAVE, "needs cryptography and an openssl binary")
class FastPaths(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cak = rsa.generate_private_key(65537, 2048)
        ik = cls.ik = rsa.generate_private_key(65537, 2048)
        lk = rsa.generate_private_key(65537, 2048)
        cls.lk = lk
        cls.ca = mk("root", cak, "root", cak, ca=True, days=365)
        cls.inter = mk("inter", ik, "root", cak, ca=True, days=365)
        cls.leaf = mk("T1-node", lk, "inter", ik, ips=["10.2.0.100", "10.9.9.9"])
        cls.bundle = pem(cls.leaf) + pem(cls.inter)
        cls.ca_path = os.path.join(cls.d, "ca.crt")
        open(cls.ca_path, "w").write(pem(cls.ca))
        cls.key_path = os.path.join(cls.d, "leaf.key")
        open(cls.key_path, "wb").write(lk.private_bytes(serialization.Encoding.PEM,
                                                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        sk = rsa.generate_private_key(65537, 2048)
        cls.stranger = mk("T1-node", sk, "T1-node", sk)           # self-signed, same CN
        cls.eck = ec.generate_private_key(ec.SECP256R1())
        cls.ec_leaf = mk("ec-node", cls.eck, "root", cak)
        cls.ec_key_path = os.path.join(cls.d, "ec.key")
        open(cls.ec_key_path, "wb").write(cls.eck.private_bytes(serialization.Encoding.PEM,
                                                                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_sign_matches_openssl_byte_for_byte(self):
        for keyp in (self.key_path,):
            data = b"hello|ts:1"
            fast = identity.sign_payload(keyp, data)
            slow = identity.sign_payload(keyp, data, openssl_bin=OPENSSL)
            self.assertEqual(fast, slow, "PKCS#1 v1.5 is deterministic: the two must be identical")

    def test_ec_signature_verifies_both_ways(self):
        data = b"payload"
        sig = identity.sign_payload(self.ec_key_path, data)                  # fast ECDSA
        self.assertTrue(identity.verify_payload_signature(pem(self.ec_leaf), data, sig))
        self.assertTrue(identity.verify_payload_signature(pem(self.ec_leaf), data, sig, openssl_bin=OPENSSL))
        sig2 = identity.sign_payload(self.ec_key_path, data, openssl_bin=OPENSSL)   # openssl-made
        self.assertTrue(identity.verify_payload_signature(pem(self.ec_leaf), data, sig2))

    def test_verify_agrees_on_good_tampered_wrong_key(self):
        data = b"payload|ts:5"
        sig = identity.sign_payload(self.key_path, data)
        other = rsa.generate_private_key(65537, 2048).sign(data, __import__("cryptography").hazmat.primitives.asymmetric.padding.PKCS1v15(), hashes.SHA256())
        cases = [(data, sig, True), (data + b"x", sig, False), (data, other, False), (data, b"\x00" * 256, False),
                 (data, b"short", False)]
        for payload, signature, want in cases:
            fast = identity.verify_payload_signature(self.bundle, payload, signature)
            slow = identity.verify_payload_signature(self.bundle, payload, signature, openssl_bin=OPENSSL)
            self.assertEqual(fast, slow)
            self.assertEqual(fast, want)

    def test_cn_and_san_agree(self):
        for c in (self.bundle, pem(self.leaf), pem(self.stranger)):
            self.assertEqual(identity.leaf_cn(c), identity.leaf_cn(c, openssl_bin=OPENSSL))
        self.assertEqual(identity.leaf_cn(self.bundle), "T1-node")
        self.assertEqual(sorted(identity.leaf_san_ips(self.bundle)), sorted(identity.leaf_san_ips(self.bundle, openssl_bin=OPENSSL)))
        self.assertEqual(sorted(identity.leaf_san_ips(self.bundle)), ["10.2.0.100", "10.9.9.9"])
        self.assertEqual(identity.leaf_san_ips(pem(self.stranger)), [])

    def test_chain_verdicts_and_cache(self):
        identity._CHAIN_OK.clear()
        self.assertTrue(identity.verify_chain(self.ca_path, self.bundle))
        self.assertEqual(len(identity._CHAIN_OK), 1, "a verified chain is cached")
        # second call must not spawn openssl: point PATH at an empty dir -- a subprocess would now fail
        old = os.environ["PATH"]; os.environ["PATH"] = self.d
        try:
            self.assertTrue(identity.verify_chain(self.ca_path, self.bundle), "served from the cache")
        finally:
            os.environ["PATH"] = old
        self.assertFalse(identity.verify_chain(self.ca_path, pem(self.stranger)), "a stranger is never accepted")
        self.assertNotIn(True, [k[3] == __import__("hashlib").sha256(pem(self.stranger).encode()).hexdigest()
                                for k in identity._CHAIN_OK], "failures are not cached")
        # replacing the CA file invalidates the cache (stamp changes)
        other_ca = mk("other", rsa.generate_private_key(65537, 2048), "other", rsa.generate_private_key(65537, 2048), ca=True)
        time.sleep(0.01)
        open(self.ca_path, "w").write(pem(other_ca))
        self.assertFalse(identity.verify_chain(self.ca_path, self.bundle), "new CA file -> re-verified -> no longer chains")
        open(self.ca_path, "w").write(pem(self.ca))

    def test_cache_never_outlives_leaf_expiry(self):
        identity._CHAIN_OK.clear()
        short = mk("short", rsa.generate_private_key(65537, 2048), "inter", self.ik, days=5.0 / 86400)
        self.assertTrue(identity.verify_chain(self.ca_path, pem(short) + pem(self.inter)))
        (expiry,) = identity._CHAIN_OK.values()
        self.assertLessEqual(expiry, time.time() + 6, "cached no longer than the leaf's remaining life (5 s), not the 300 s TTL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
