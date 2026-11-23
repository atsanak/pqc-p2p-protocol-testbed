#!/usr/bin/env python3
"""Sender wait-budget override (2026-10-01): defaults UNCHANGED, optional P2P_COAP_PER_BLOCK_S env and `--timeout` on
deliver/put-file. Run: python3 p2p/tests/test_sender_timeouts.py"""
import importlib.util, os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
SENDER = os.path.join(HERE, "..", "sender-role")
sys.path.insert(0, os.path.join(HERE, ".."))


def load(env=None):
    old = os.environ.pop("P2P_COAP_PER_BLOCK_S", None)
    if env is not None:
        os.environ["P2P_COAP_PER_BLOCK_S"] = env
    try:
        spec = importlib.util.spec_from_file_location("p2p_sender_client_t", os.path.join(SENDER, "client.py"))
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        return m
    finally:
        os.environ.pop("P2P_COAP_PER_BLOCK_S", None)
        if old is not None:
            os.environ["P2P_COAP_PER_BLOCK_S"] = old


def budget(m, use_case, timeout, wire_len):
    return m.Client._coap_budget(object.__new__(m.Client), use_case, timeout, wire_len)


class T(unittest.TestCase):
    def test_defaults_unchanged(self):
        m = load(None)
        self.assertEqual(m.Client.COAP_PER_BLOCK_S, 0.5)
        self.assertEqual(budget(m, "file", None, 40 * 1024), 30.0)       # the live 40 KB case: 10 + 0.5*40
        self.assertEqual(budget(m, "status", None, 900), 10)
        self.assertEqual(budget(m, "rm", None, 900), min(m.rm_limits.DEFAULT_TIMEOUT, m.rm_limits.MAX_TIMEOUT) + 10)  # rm/ml untouched
        self.assertEqual(budget(m, "ml", 20, 900), 30)

    def test_env_override(self):
        self.assertEqual(budget(load("2"), "file", None, 40 * 1024), 90.0)
        self.assertEqual(budget(load("0.25"), "file", None, 40 * 1024), 20.0)

    def test_bad_env_falls_back(self):
        for bad in ("", "  ", "abc", "0", "-1", "nan", "inf", "1e9"):
            self.assertEqual(load(bad).Client.COAP_PER_BLOCK_S, 0.5, bad)

    def test_explicit_file_timeout(self):
        m = load(None)
        self.assertEqual(budget(m, "file", 120, 40 * 1024), 120 + 20.0)
        self.assertEqual(budget(m, "file", 3, 900), 10)                   # never below the 10 s floor
        self.assertEqual(budget(m, "message", 120, 900), 10)              # only file/put-file take it


class CliParse(unittest.TestCase):
    def test_timeout_flag_on_put_file(self):
        spec = importlib.util.spec_from_file_location("p2p_sender_cli_t", os.path.join(SENDER, "cli.py"))
        sys.path.insert(0, SENDER)
        cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
        pos, fl = cli._split(["blob.bin", "dest", "--timeout", "120", "--tech", "coap-enc", "--job-id", "j"])
        self.assertEqual(pos, ["blob.bin", "dest"])
        self.assertEqual(fl["--timeout"], "120")


if __name__ == "__main__":
    unittest.main()
