#!/usr/bin/env python3
"""Regression tests for the 2026-10-23 v2 metrics change and the fixes that came with it (no fleet, no network
beyond loopback).

  1. timing block shape   -- retired keys are gone everywhere; the five transport keys are present (None, never 0)
  2. additivity           -- on every shape (in-process TLS, helper/subprocess, CoAP) total_ms == sum of phases
  3. rewind               -- a failed-and-retried handshake leaves only the retry in the block, still additive
  4. receiver block       -- an OLDER receiver's total_ms / clock / receive_body_ms / mirror_ms are not carried
  5. TCP_INFO reader      -- bytes_sent / bytes_received / min RTT of a real loopback TCP connection
  6. CoAP status mapping  -- 2.04 -> 204, 4.01 -> 401 (both comm-log halves agree)
  7. receiver labels      -- a refused request is filed under the listener's tech, not the client's header
Run: python3 p2p/tests/test_metrics_v2.py
"""
import importlib.util
import os
import socket
import sys
import threading
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
P2P = os.path.join(HERE, "..")
sys.path.insert(0, P2P)
sys.path.insert(0, os.path.join(P2P, "receiver-role"))

PHASES = ("resolve_ms", "peer_cert_ms", "tcp_connect_ms", "handshake_ms", "prepare_ms", "client_overhead_ms",
          "exchange_ms")
RETIRED = ("verify_peer_ms", "identity_refresh_ms", "handshake_in_exchange", "clock")


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(P2P, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


client = load("p2p_client_v2", "sender-role/client.py")


def _read(*parts):
    with open(os.path.join(*parts)) as f:
        return f.read()


def phase_sum(b):
    return round(sum(b[k] or 0.0 for k in PHASES), 3)


class Shape(unittest.TestCase):
    def test_retired_keys_absent_and_net_keys_present(self):
        t = client._Timing("mtls")
        t.lap("resolve_ms")
        b = t.block()
        for k in RETIRED:
            self.assertNotIn(k, b)
        for k in client._Timing.NET_KEYS:
            self.assertIn(k, b)
            self.assertIsNone(b[k])

    def test_note_net_ignores_none_and_types(self):
        t = client._Timing("quic-pqc")
        t.note_net(handshake_bytes_out=5445, handshake_bytes_in=None, handshake_cpu_ms=16.85512, rtt_ms=None,
                   retransmits=0, bogus=3)
        b = t.block()
        self.assertEqual(b["handshake_bytes_out"], 5445)
        self.assertIsNone(b["handshake_bytes_in"])            # never 0 for "not observed"
        self.assertEqual(b["handshake_cpu_ms"], 16.855)
        self.assertEqual(b["retransmits"], 0)                 # a real observation of zero stays 0
        self.assertNotIn("bogus", b)


class Additive(unittest.TestCase):
    def _laps(self, t, names, pause=0.002):
        for n in names:
            time.sleep(pause)
            t.lap(n)

    def test_tls_in_process(self):
        t = client._Timing("https")
        self._laps(t, ("resolve_ms", "tcp_connect_ms", "handshake_ms", "prepare_ms", "exchange_ms"))
        b = t.block(receiver={"total_ms": 1.0})
        self.assertAlmostEqual(phase_sum(b), b["total_ms"], delta=0.01)
        self.assertIsNone(b["client_overhead_ms"])

    def test_helper_tech(self):
        t = client._Timing("quic-pqc")
        self._laps(t, ("resolve_ms", "prepare_ms"))
        time.sleep(0.03)
        t.lap("exchange_ms")                                   # the whole subprocess
        t.note(handshake_ms=10.0, wire_ms=12.0)
        b = t.block(receiver={"total_ms": 5.0})
        self.assertAlmostEqual(phase_sum(b), b["total_ms"], delta=0.01)
        self.assertEqual(b["exchange_ms"], 12.0)
        self.assertEqual(b["network_ms"], 7.0)
        self.assertGreater(b["client_overhead_ms"], 0)

    def test_coap_plain(self):
        t = client._Timing("coap-enc")
        self._laps(t, ("resolve_ms", "peer_cert_ms", "prepare_ms", "exchange_ms"))
        b = t.block(receiver={"total_ms": 1.0})
        self.assertAlmostEqual(phase_sum(b), b["total_ms"], delta=0.01)


class Rewind(unittest.TestCase):
    def test_failed_attempt_is_dropped_and_block_still_adds_up(self):
        t = client._Timing("mtls")
        snap = t.snapshot()
        time.sleep(0.01); t.lap("resolve_ms")
        time.sleep(0.01); t.lap("tcp_connect_ms")
        t.note_net(handshake_cpu_ms=5.0)
        time.sleep(0.05)                                       # the failed handshake + the identity refresh
        t.rewind(snap)
        time.sleep(0.01); t.lap("resolve_ms")
        time.sleep(0.01); t.lap("tcp_connect_ms")
        time.sleep(0.01); t.lap("handshake_ms")
        time.sleep(0.01); t.lap("prepare_ms")
        time.sleep(0.01); t.lap("exchange_ms")
        b = t.block(receiver={"total_ms": 1.0})
        self.assertLess(b["resolve_ms"], 18)                   # the first attempt's resolve is not added in
        self.assertLess(b["tcp_connect_ms"], 18)
        self.assertIsNone(b["handshake_cpu_ms"])               # the failed attempt's observation is dropped too
        self.assertAlmostEqual(phase_sum(b), b["total_ms"], delta=0.05)
        self.assertLess(b["total_ms"], 90)                     # the 50 ms of failure is not in it


class ReceiverBlock(unittest.TestCase):
    def test_old_receiver_keys_dropped_and_total_hoisted(self):
        t = client._Timing("https")
        t.lap("exchange_ms")
        old = {"receive_body_ms": 5.4, "verify_ms": 0.9, "authorize_ms": 11.1, "handler_ms": 0.3,
               "total_ms": 12.3, "clock": "monotonic, receiver box"}
        b = t.block(receiver=old)
        self.assertEqual(b["receiver_ms"], 12.3)
        self.assertEqual(b["receiver"], {"verify_ms": 0.9, "authorize_ms": 11.1, "handler_ms": 0.3})
        old_coap = {"verify_ms": 1, "authorize_ms": 2, "decrypt_ms": 0.0, "handler_ms": 1, "mirror_ms": 4.2,
                    "total_ms": 8.2, "clock": "x"}
        self.assertNotIn("mirror_ms", client._Timing("coap").block(receiver=old_coap)["receiver"])

    def test_no_receiver_block(self):
        b = client._Timing("http").block(receiver=None)
        self.assertIsNone(b["receiver"]); self.assertIsNone(b["receiver_ms"]); self.assertIsNone(b["network_ms"])


class TcpInfo(unittest.TestCase):
    def test_real_loopback_connection(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        got = []

        def serve():
            c, _ = srv.accept()
            data = b""
            while len(data) < 1000:
                data += c.recv(4096)
            got.append(len(data))
            c.sendall(b"y" * 777)
            c.close()
        th = threading.Thread(target=serve); th.start()
        s = socket.create_connection(srv.getsockname())
        s.sendall(b"x" * 1000)
        rx = b""
        while len(rx) < 777:
            rx += s.recv(4096)
        th.join(); time.sleep(0.05)
        ti = client._tcp_info(s)
        s.close(); srv.close()
        if ti is None:
            self.skipTest("TCP_INFO without tcpi_bytes_sent on this kernel")
        self.assertEqual(ti["bytes_sent"] - ti["bytes_retrans"] + ti["notsent_bytes"], 1000)
        self.assertIn(ti["bytes_received"], (777, 778))       # +1 once the peer's FIN is in
        self.assertGreater(ti["min_rtt_us"], 0)
        self.assertEqual(ti["total_retrans"], 0)

    def test_not_a_tcp_socket(self):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.assertIsNone(client._tcp_info(u)); u.close()
        self.assertIsNone(client._tcp_info(object()))


class CoapStatus(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(client.coap_status_code(68), 204)      # 2.04 Changed
        self.assertEqual(client.coap_status_code(69), 205)      # 2.05 Content
        self.assertEqual(client.coap_status_code(129), 401)     # 4.01
        self.assertEqual(client.coap_status_code(131), 403)     # 4.03
        self.assertEqual(client.coap_status_code(160), 500)     # 5.00


class ListenerTech(unittest.TestCase):
    def setUp(self):
        self.server = load("p2p_server_v2", "receiver-role/server.py")

    def _h(self, mutual, tls, headers, fronted=None, peer="10.2.0.100"):
        h = self.server.Handler.__new__(self.server.Handler)
        h.server = types.SimpleNamespace(mutual=mutual, tls=tls)
        if fronted:
            h.server.fronted_tech = fronted
        h.headers = headers
        h.client_address = (peer, 5555)
        return h

    def test_refusal_label_comes_from_the_listener(self):
        claim = {"X-P2P-Tech": "mtls"}                          # a stranger claiming the strongest tech
        self.assertEqual(self._h(False, True, claim)._listener_tech(), "https")
        self.assertEqual(self._h(False, False, claim)._listener_tech(), "http")
        self.assertEqual(self._h(False, False, claim, fronted="pqkex")._listener_tech(), "pqkex")
        self.assertEqual(self._h(True, True, {"X-P2P-Tech": "https"})._listener_tech(), "mtls")
        # 2026-10-23: a header never names the tech -- the retired X-P2P-PQC switch on the mtls listener is
        # still `mtls` (and refused by _identify); `pqc` / `pqc-mutual` are their own ML-KEM-768 listeners
        self.assertEqual(self._h(True, True, {"X-P2P-PQC": "1"})._listener_tech(), "mtls")
        h = self._h(True, True, claim); h.server.pqc = True        # the ML-KEM-768 + ML-DSA-65 mutual listener
        self.assertEqual(h._listener_tech(), "pqc")
        relay = {"X-P2P-Relay-Tech": "quic-pqc"}
        self.assertEqual(self._h(False, False, relay, peer="127.0.0.1")._listener_tech(), "quic-pqc")
        self.assertEqual(self._h(False, False, relay, peer="10.2.0.100")._listener_tech(), "http")

    def test_receiver_block_has_no_retired_keys(self):
        src = _read(P2P, "receiver-role", "server.py")
        self.assertNotIn('"receive_body_ms"', src)
        src = _read(P2P, "receiver-role", "coap_server.py")
        self.assertNotIn('"mirror_ms"', src)


if __name__ == "__main__":
    unittest.main(verbosity=1)
