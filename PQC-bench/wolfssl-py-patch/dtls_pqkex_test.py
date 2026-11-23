#!/usr/bin/env python3
"""Real hybrid PQ-KEX DTLS 1.3 handshake, in pure Python, via the patched wolfssl-py binding
(key_share_group= / negotiated_group(), both added 2026-09-27 -- see the package's own
__init__.py/_build_ffi.py diffs). Proves the SAME thing the C example client/server already
proved (wolfSSL_UseKeyShare + a real DTLSv1.3 handshake negotiating X25519MLKEM768), but from
Python -- the actual language every other tech in this codebase (pqkex, coap-pqc, pqc) is written
in, closing the gap those couldn't: none of them could do a real PQC handshake at all, because
Python's stdlib `ssl` has no oqs-provider/PQ support. This binding is how that gap closes.
"""
import multiprocessing
import socket
import sys

import wolfssl

CERTS = "/tmp/wolfssl-check/wolfssl-5.9.2.post0/certs"
HOST, PORT = "127.0.0.1", 22334


def server(ready):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    ready.set()
    data, addr = sock.recvfrom(4096, socket.MSG_PEEK)
    sock.connect(addr)

    ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_DTLSv1_3, server_side=True)
    ctx.load_cert_chain(f"{CERTS}/server-cert.pem", f"{CERTS}/server-key.pem")
    ssock = ctx.wrap_socket(sock, server_side=True)
    ssock.do_handshake()
    msg = ssock.read(64)
    print("[server] received:", msg.decode())
    print("[server] negotiated_group():", ssock.negotiated_group())
    ssock.write(b"hello from server, over real hybrid PQ-KEX DTLS 1.3")
    ssock.close()


def client(ready):
    ready.wait()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((HOST, PORT))

    ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_DTLSv1_3, server_side=False)
    ctx.verify_mode = wolfssl.CERT_NONE
    ssock = ctx.wrap_socket(sock, key_share_group=wolfssl.WOLFSSL_X25519MLKEM768)
    ssock.do_handshake()
    group = ssock.negotiated_group()
    print("[client] negotiated_group():", group)
    ssock.write(b"hello from client, requesting X25519MLKEM768")
    reply = ssock.read(128)
    print("[client] received:", reply.decode())
    ssock.close()

    assert group == "X25519MLKEM768", f"expected X25519MLKEM768, got {group!r}"
    print("PASS: real hybrid PQ-KEX DTLS 1.3 handshake, from pure Python")


if __name__ == "__main__":
    ready = multiprocessing.Event()
    sp = multiprocessing.Process(target=server, args=(ready,))
    cp = multiprocessing.Process(target=client, args=(ready,))
    sp.start()
    cp.start()
    cp.join(15)
    sp.join(5)
    sys.exit(0 if cp.exitcode == 0 else 1)
