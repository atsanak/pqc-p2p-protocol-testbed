#!/usr/bin/env python3
"""Offline test for the opt-in `details` on the STATUS use case (2026-10-02, Network Map parity):
the receiver adds its Network Map row ONLY when asked (header X-P2P-Details on mtls, signed `details` flag on the
envelope techs, CoAP payload flag), never into the comm-log row; common/onboard answers {ok: False} without an
on-board API, caches, and survives a broken one; the sender keeps `details` out of its own log row.
Run: python3 p2p/tests/test_status_details.py"""
import importlib.util
import os
import sys
import tempfile
import types
import unittest

P2P = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, P2P)
sys.path.insert(0, os.path.join(P2P, "receiver-role"))
from common import onboard                                                  # noqa: E402


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(P2P, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def fake_api_dir(body):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "device_api.py"), "w") as fh:
        fh.write(body)
    return d


GOOD = 'class DeviceAPI:\n    def map_details_self(self):\n        return {"ok": True, "name": "FAKE"}\n'
OLD = 'class DeviceAPI:\n    pass\n'
BROKEN = 'class DeviceAPI:\n    def map_details_self(self):\n        raise RuntimeError("boom")\n'


def use(body):
    sys.modules.pop("device_api", None)
    onboard.CANDIDATES = ((fake_api_dir(body), "device_api", "DeviceAPI"),)
    onboard._api.update(obj=None, tried=False, detail=None)
    onboard._cache.update(at=0.0, value=None)


class Onboard(unittest.TestCase):
    def test_good_and_cached(self):
        use(GOOD)
        self.assertEqual(onboard.map_details()["name"], "FAKE")
        self.assertIn("cached_age_s", onboard.map_details())
        self.assertNotIn("cached_age_s", onboard.map_details(max_age=0))

    def test_old_api_and_broken_api(self):
        use(OLD)
        self.assertIn("predates", onboard.map_details()["detail"])
        use(BROKEN)
        self.assertIn("boom", onboard.map_details()["detail"])

    def test_no_api(self):
        onboard.CANDIDATES = (("/nonexistent", "device_api", "DeviceAPI"),)
        onboard._api.update(obj=None, tried=False, detail=None)
        onboard._cache.update(at=0.0, value=None)
        self.assertFalse(onboard.map_details()["ok"])


class Receiver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        use(GOOD)
        srv = load("p2p_srv_t", "receiver-role/server.py")
        cls.H = [v for v in vars(srv).values() if isinstance(v, type) and hasattr(v, "_run")][0]
        cls.coap = load("p2p_coap_t", "receiver-role/coap_server.py")

    def run_http(self, tech, headers, payload):
        return self.H._run(types.SimpleNamespace(headers=headers), "status", tech, "SENDER", b"", payload, None)

    def test_http_family(self):
        for tech, hdr, payload, want in (("mtls", {}, None, False), ("mtls", {"X-P2P-Details": "1"}, None, True),
                                         ("https", {}, {}, False), ("https", {}, {"details": True}, True),
                                         # 2026-10-23: pqc is certificate-identified like mtls (raw body) -> the header
                                         ("pqc", {}, None, False), ("pqc", {"X-P2P-Details": "1"}, None, True)):
            res, _n, logged = self.run_http(tech, hdr, payload)
            self.assertEqual("details" in res, want, (tech, hdr, payload))
            self.assertNotIn("details", logged)
            self.assertTrue(res["ok"])

    def test_coap(self):
        for payload, want in (({}, False), ({"details": True}, True)):
            res, _n, logged = self.coap.P2pResource._run(types.SimpleNamespace(use_case="status"), "S", payload, 1)
            self.assertEqual("details" in res, want)
            self.assertNotIn("details", logged)


class Sender(unittest.TestCase):
    def test_details_flag_reaches_the_exchange(self):
        cl = load("p2p_client_t", "sender-role/client.py")
        c = cl.Client.__new__(cl.Client)
        seen = {}
        c._tech = lambda tech, pqc: tech or "mtls"
        c._exchange = lambda use_case, receiver, tech, payload=None, **k: seen.update(payload=payload) or {}
        c.get_status("R")
        self.assertEqual(seen["payload"], {})
        c.get_status("R", details=True)
        self.assertEqual(seen["payload"], {"details": True})


if __name__ == "__main__":
    unittest.main(verbosity=1)
