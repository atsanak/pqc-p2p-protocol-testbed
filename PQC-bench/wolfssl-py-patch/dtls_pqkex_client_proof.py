#!/usr/bin/env python3
"""The real proof for aiocoap_wolfdtls.py: a genuine aiocoap.Message, built and sent through a
real aiocoap.Context via the new coaps:// transport (aiocoap_wolfdtls's own MessageInterface),
arriving at a raw wolfSSL DTLS 1.3 server (not a stub) that decodes it as a real CoAP message and
replies with a real CoAP response -- which the SAME aiocoap.Context then decodes back into a real
Message object.

Deliberately not a full aiocoap MessageInterfaceX server (see aiocoap_wolfdtls.py's own docstring
for why receiver-side is separate, unstarted work) -- the server half here is the same
hand-rolled wolfssl-py server dtls_pqkex_test.py already proved works, extended just enough to
speak one real CoAP exchange instead of raw bytes.
"""
import asyncio
import multiprocessing
import os
import socket
import sys

# `wolfssl` is deliberately NOT imported here at module level -- this module is imported in the
# process that later forks server() off via multiprocessing.Process, and importing a cffi-wrapped
# C library before that fork is worth avoiding on general principle. server() does `import
# wolfssl` locally instead, same as aiocoap_wolfdtls.py's own worker does.

sys.path.insert(0, "/tmp/wolfssl-check/wolfssl-5.9.2.post0")  # certs/ lives here
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # this dir, for aiocoap_wolfdtls
CERTS = "/tmp/wolfssl-check/wolfssl-5.9.2.post0/certs"
HOST, PORT = "127.0.0.1", 22335


def server(ready):
    import wolfssl
    from aiocoap.message import Message
    from aiocoap.numbers.codes import Code
    from aiocoap.numbers.types import Type
    from aiocoap_wolfdtls import write_framed, read_framed

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    ready.set()
    _, addr = sock.recvfrom(4096, socket.MSG_PEEK)
    sock.connect(addr)

    ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_DTLSv1_3, server_side=True)
    ctx.load_cert_chain(f"{CERTS}/server-cert.pem", f"{CERTS}/server-key.pem")
    # do_handshake_on_connect=False -- the socket is already connect()'ed above, so wrap_socket()
    # would otherwise ALSO drive an implicit wolfSSL_accept() (SSLSocket.__init__'s own `if
    # connected: ... self.do_handshake()`), and our own explicit call below would then be a
    # redundant second one on the same SSL object -- found live, 2026-09-27: that double-invoke
    # sent the same flight twice back to back and produced an immediate, deterministic
    # SOCKET_ERROR_E (-308) on whichever side got to it. One explicit call, and only one.
    ssock = ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
    ssock.do_handshake()
    print("[server] negotiated_group():", ssock.negotiated_group())

    raw = read_framed(ssock)
    req = Message.decode(raw)
    print(f"[server] decoded a REAL aiocoap.Message: code={req.code} "
          f"uri_path={req.opt.uri_path} mid={req.mid} token={req.token!r}")
    assert req.code == Code.GET and req.opt.uri_path == ("status",), \
        f"unexpected request: {req.code} {req.opt.uri_path}"

    # mtype=Type.NON to match the client's transport_tuning=Unreliable (no CoAP-level ACK
    # tracking on either side of this raw transport) -- required explicitly: Message.encode()
    # raises unless code/mtype/mid are ALL set, and mtype defaults to None if left unspecified.
    resp = Message(code=Code.CONTENT, mtype=Type.NON, mid=req.mid, token=req.token,
                   payload=b'{"ok": true}')
    write_framed(ssock, resp.encode())
    print("[server] replied with a real CoAP 2.05 Content response")
    ssock.close()


async def client_main():
    import aiocoap
    from aiocoap_wolfdtls import MessageInterfaceWolfDTLS

    # transports=["udp6"] explicitly: bypasses get_default_clienttransports(), which would
    # otherwise auto-select tinydtls and claim coaps:// before we get to.
    ctx = await aiocoap.Context.create_client_context(transports=["udp6"])
    await ctx._append_tokenmanaged_messagemanaged_transport(
        lambda mman: MessageInterfaceWolfDTLS.create_client_transport_endpoint(
            mman, log=ctx.log, loop=ctx.loop))

    # transport_tuning=Unreliable: a hybrid-PQC DTLS handshake genuinely takes longer than
    # aiocoap's own default ACK_TIMEOUT (2.0s) -- found live, 2026-09-27: aiocoap's OWN CoAP-level
    # CON retransmission fired mid-handshake and sent a SECOND concurrent request, colliding with
    # the first on the (single-peer, non-pooling) server. A real receiver-side transport would
    # need proper handling of this (a reused/pooled connection so a retry doesn't restart the
    # handshake, and/or a wider timeout for exchanges known to be over DTLS) -- Unreliable
    # sidesteps it for this proof, which is about the transport integration itself, not CoAP's
    # retry tuning. (mtype=NON alone is deprecated for this and, found live, insufficient anyway.)
    req = aiocoap.Message(code=aiocoap.GET, uri=f"coaps://{HOST}:{PORT}/status",
                          transport_tuning=aiocoap.Unreliable)
    print("[client] sending a real aiocoap GET over coaps://, via the wolfDTLS transport")
    response = await ctx.request(req).response
    print(f"[client] received a real aiocoap response: {response.code} {response.payload}")
    await ctx.shutdown()

    assert response.code == aiocoap.CONTENT, f"unexpected response code {response.code}"
    assert response.payload == b'{"ok": true}', f"unexpected payload {response.payload!r}"
    print("PASS: a real aiocoap.Message round-tripped through real hybrid PQ-KEX DTLS 1.3")


if __name__ == "__main__":
    ready = multiprocessing.Event()
    sp = multiprocessing.Process(target=server, args=(ready,))
    sp.start()
    ready.wait(5)
    try:
        asyncio.run(asyncio.wait_for(client_main(), timeout=15))
        rc = 0
    except Exception as e:
        print("CLIENT SIDE FAILED:", repr(e))
        rc = 1
    sp.join(5)
    sys.exit(rc)
