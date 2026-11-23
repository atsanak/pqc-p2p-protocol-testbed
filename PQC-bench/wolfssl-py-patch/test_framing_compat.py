#!/usr/bin/env python3
"""Local test: read_framed/write_framed accept the legacy (pre-ea681b73) framing and answer in it.
No network, no wolfSSL. Run: python3 test_framing_compat.py"""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aiocoap_wolfdtls as w                                      # noqa: E402


class Pipe:
    """A fake DTLS socket: write() appends records, read() pops them (in a chosen order)."""
    def __init__(self, records=None):
        self.out, self.inq = [], list(records or [])

    def write(self, b):
        self.out.append(bytes(b))

    def read(self, _n):
        return self.inq.pop(0) if self.inq else b""


def legacy_write(data, chunk=w.CHUNK_SIZE):                      # the 9be8befa sender, verbatim shape
    n = max(1, (len(data) + chunk - 1) // chunk)
    return [bytes([1 if i < n - 1 else 0]) + data[i * chunk:(i + 1) * chunk] for i in range(n)]


COAP = bytes([0x50, 0x02, 0x12, 0x34]) + b"\xb3api" + b"\xff" + b'{"ts":1,"values":{"k":1}}'


class Compat(unittest.TestCase):
    def test_new_to_new_reordered(self):
        data = os.urandom(5 * w.CHUNK_SIZE + 7)
        tx = Pipe()
        w.write_framed(tx, data, pace_s=0)
        recs = tx.out[:]
        random.Random(1).shuffle(recs)
        rx = Pipe(recs)
        self.assertEqual(w.read_framed(rx), data)
        self.assertFalse(getattr(rx, "_legacy_framing", False))

    def test_legacy_request_is_read_and_answered_in_legacy(self):
        big = COAP + b"x" * (2 * w.CHUNK_SIZE)
        rx = Pipe(legacy_write(big))
        self.assertEqual(w.read_framed(rx), big)
        self.assertTrue(rx._legacy_framing)
        w.write_framed(rx, b"\x60\x44\x12\x34", pace_s=0)          # the reply
        self.assertEqual(rx.out, [b"\x00\x60\x44\x12\x34"])        # legacy shape: [more=0] + data

    def test_new_first_chunk_never_looks_legacy(self):
        tx = Pipe()
        w.write_framed(tx, COAP, pace_s=0)
        self.assertFalse(w._is_legacy_first_chunk(tx.out[0]))
        self.assertTrue(w._is_legacy_first_chunk(legacy_write(COAP)[0]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
