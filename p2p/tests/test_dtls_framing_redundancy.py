#!/usr/bin/env python3
"""aiocoap_wolfdtls framing (2026-10-23): a short message (every reply) is sent twice, so ONE lost datagram no longer
loses the reply; both copies lost still fails cleanly; long messages are not doubled. A fake socket drops chosen writes.
Run: python3 p2p/tests/test_dtls_framing_redundancy.py"""
import os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "PQC-bench", "wolfssl-py-patch"))
try:
    import aiocoap_wolfdtls as W
except ImportError as e:                                     # aiocoap not installed here
    W = None; WHY = str(e)


class Lossy:
    """write() i is lost when i is in `drop`; read() returns the next delivered datagram, b'' when none are left."""
    def __init__(self, drop=()):
        self.drop, self.sent, self.q = set(drop), 0, []
    def write(self, b):
        if self.sent not in self.drop:
            self.q.append(b)
        self.sent += 1
    def read(self, n):
        return self.q.pop(0) if self.q else b""


@unittest.skipIf(W is None, "aiocoap_wolfdtls not importable here")
class Redundancy(unittest.TestCase):
    def roundtrip(self, data, drop):
        s = Lossy(drop)
        W.write_framed(s, data, pace_s=0)
        return s, W.read_framed(s)

    def test_one_chunk_reply_survives_losing_its_first_copy(self):
        s, got = self.roundtrip(b"reply" * 50, drop={0})
        self.assertEqual(got, b"reply" * 50); self.assertEqual(s.sent, 2)

    def test_multi_chunk_message_survives_one_loss_in_each_half(self):
        data = os.urandom(W.CHUNK_SIZE * 3 + 7)                  # 4 chunks -> 8 writes
        _s, got = self.roundtrip(data, drop={1, 6})
        self.assertEqual(got, data)

    def test_both_copies_lost_still_fails_cleanly(self):
        with self.assertRaises(W.FramingError):
            self.roundtrip(b"x" * 10, drop={0, 1})

    def test_long_message_is_not_doubled(self):
        n = W.REDUNDANT_MAX_CHUNKS + 1
        s, got = self.roundtrip(os.urandom(W.CHUNK_SIZE * n), drop=())
        self.assertEqual(s.sent, n); self.assertEqual(len(got), W.CHUNK_SIZE * n)

    def test_duplicates_do_not_corrupt(self):
        data = os.urandom(W.CHUNK_SIZE * 2)
        _s, got = self.roundtrip(data, drop=())
        self.assertEqual(got, data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
