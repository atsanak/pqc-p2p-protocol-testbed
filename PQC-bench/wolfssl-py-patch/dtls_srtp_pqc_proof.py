#!/usr/bin/env python3
"""dtls_srtp_pqc_proof.py -- real hybrid PQ-KEX DTLS 1.3 handshake with RFC 5764 use_srtp
negotiated, proving BOTH ends independently derive byte-identical SRTP keying material -- the
actual cryptographic proof for the video streaming RTP+DTLS-SRTP (Stack 3) leg. Mirrors
dtls_pqkex_test.py's shape (same certs, same X25519MLKEM768 group), adding use_srtp=/
export_srtp_keying_material() (2026-09-28 testbed additions to the wolfssl-py binding).
"""
import multiprocessing
import socket
import sys

import wolfssl

CERTS = "/var/lib/p2p/certs-pqc"
HOST, PORT = "127.0.0.1", 22335
PROFILE = "SRTP_AES128_CM_SHA1_80"


def server(ready, q):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    ready.set()
    data, addr = sock.recvfrom(4096, socket.MSG_PEEK)
    sock.connect(addr)

    ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_DTLSv1_3, server_side=True)
    ctx.load_cert_chain(f"{CERTS}/peer.crt", f"{CERTS}/peer.key")
    ssock = ctx.wrap_socket(sock, server_side=True, use_srtp=PROFILE)
    ssock.do_handshake()
    km = ssock.export_srtp_keying_material()
    print(f"[server] negotiated_group(): {ssock.negotiated_group()}")
    print(f"[server] srtp keying material ({len(km)}B): {km.hex()}")
    q.put(("server", km))
    ssock.close()


def client(ready, q):
    ready.wait()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((HOST, PORT))

    ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_DTLSv1_3, server_side=False)
    ctx.verify_mode = wolfssl.CERT_NONE
    ssock = ctx.wrap_socket(sock, key_share_group=wolfssl.WOLFSSL_X25519MLKEM768, use_srtp=PROFILE)
    ssock.do_handshake()
    group = ssock.negotiated_group()
    km = ssock.export_srtp_keying_material()
    print(f"[client] negotiated_group(): {group}")
    print(f"[client] srtp keying material ({len(km)}B): {km.hex()}")
    q.put(("client", km))
    ssock.close()
    assert group == "X25519MLKEM768", f"expected X25519MLKEM768, got {group!r}"


if __name__ == "__main__":
    ready = multiprocessing.Event()
    q = multiprocessing.Queue()
    sp = multiprocessing.Process(target=server, args=(ready, q))
    cp = multiprocessing.Process(target=client, args=(ready, q))
    sp.start()
    cp.start()
    cp.join(15)
    sp.join(5)
    results = {}
    while not q.empty():
        who, km = q.get()
        results[who] = km
    if results.get("server") and results.get("client") and results["server"] == results["client"]:
        print(f"\nPASS: real hybrid PQ-KEX DTLS 1.3 + RFC 5764 use_srtp -- both ends derived "
              f"byte-identical {len(results['server'])}B SRTP keying material independently")
        sys.exit(0)
    print(f"\nFAIL: server={results.get('server')} client={results.get('client')}")
    sys.exit(1)
