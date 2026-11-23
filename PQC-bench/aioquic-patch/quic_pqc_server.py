import asyncio, sys
sys.path.insert(0, "/opt/PQC-bench/ca")
import quic_pqc_ca

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived

PKI = "/var/lib/p2p/certs-quic-pqc"
HOST, PORT = "0.0.0.0", 4433


class EchoProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            print(f"[server] HANDSHAKE COMPLETE alpn={event.alpn_protocol}", flush=True)
        if isinstance(event, StreamDataReceived):
            try:
                self._quic.send_stream_data(event.stream_id, b"echo:" + event.data, end_stream=True)
                self.transmit()
            except AssertionError:
                pass


async def main():
    import os
    name = os.uname().nodename
    crt, key = quic_pqc_ca.issue(PKI, "T1-Protectli2-gw-T1", "10.2.1.1", "T1")
    open(f"{PKI}/server.crt", "wb").write(crt)
    open(f"{PKI}/server.key", "wb").write(key)
    config = QuicConfiguration(is_client=False, alpn_protocols=["quic-pqc-test"])
    config.load_cert_chain(f"{PKI}/server.crt", f"{PKI}/server.key")
    print(f"[server] listening on {HOST}:{PORT}, CA at {PKI}/ca.crt", flush=True)
    await serve(HOST, PORT, configuration=config, create_protocol=EchoProtocol)
    await asyncio.Event().wait()


asyncio.run(main())
