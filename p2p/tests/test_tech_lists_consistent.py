#!/usr/bin/env python3
"""Drift guard: every place that lists the P2P techs lists the SAME 21, groups them by transport the same way, and rejects an
unknown tech ("quic", "dtls") with the grouped HTTP/CoAP message (2026-10-23).
Run: python3 p2p/tests/test_tech_lists_consistent.py"""
import importlib.util, os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(HERE, ".."))


def load(name, rel, extra_path=None):
    if extra_path:
        sys.path.insert(0, os.path.join(ROOT, extra_path))
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


class Techs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = load("t_client", "p2p/sender-role/client.py")
        cls.mods = {"client.TECHS": set(cls.client.TECHS)}
        try:
            cls.mods["DeviceAPI.P2P_TECHS"] = set(load("t_dev", "Device-PC/Device/API/device_api.py", "Device-PC/Device/API").DeviceAPI.P2P_TECHS)
        except Exception as e:                                                  # noqa: BLE001
            cls.mods["DeviceAPI.P2P_TECHS"] = e
        try:
            cls.tenant = load("t_ten", "Tenant-Admin-user-PC/API/tenant_api.py", "Tenant-Admin-user-PC/API")
            cls.mods["TenantAPI.P2P_TECHS"] = set(cls.tenant.TenantAPI.P2P_TECHS)
        except Exception as e:                                                  # noqa: BLE001
            cls.tenant = None
            cls.mods["TenantAPI.P2P_TECHS"] = e
        sys.path[:0] = [os.path.join(ROOT, "Tenant-Admin-user-PC/API"), os.path.join(ROOT, "api")]   # testbed tree / standalone repo
        import p2p_levels
        cls.mods["p2p_levels"] = {t for v in p2p_levels.P2P_LEVELS.values() for t, _ in v}

    def test_all_lists_equal(self):
        want = self.mods["client.TECHS"]
        self.assertEqual(len(want), 21)
        for k, v in self.mods.items():
            if isinstance(v, Exception):
                self.skipTest(f"{k} not importable here: {v}")
            self.assertEqual(v, want, k)

    def test_listing_groups_by_transport(self):
        text = self.client.tech_listing()
        http, coap = text.split("; CoAP: ")
        self.assertTrue(http.startswith("HTTP: "))
        self.assertTrue(all(not t.startswith("coap") for t in http[6:].split(" | ")))
        self.assertTrue(all(t.startswith("coap") for t in coap.split(" | ")))
        self.assertEqual(len(http[6:].split(" | ")) + len(coap.split(" | ")), 21)

    def test_unknown_tech_rejected_with_the_grouped_message(self):
        for mod in (self.tenant and self.tenant.TenantAPI,):
            if mod is None:
                continue
            with self.assertRaises(ValueError) as cm:
                mod._tech_args("quic", False)
            self.assertIn("HTTP: ", str(cm.exception)); self.assertIn("; CoAP: ", str(cm.exception))
        # the device API validates before it ever spawns the CLI
        try:
            dev = load("t_dev2", "Device-PC/Device/API/device_api.py", "Device-PC/Device/API").DeviceAPI
        except Exception as e:                                                  # noqa: BLE001
            self.skipTest(f"device_api not importable: {e}")
        with self.assertRaises(ValueError):
            dev._tech_args("dtls", False)
        self.assertEqual(dev._tech_args("coap-dtls", False), ["--tech", "coap-dtls"])
        self.assertEqual(dev._tech_args(None, True), ["--tech", "pqc"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
