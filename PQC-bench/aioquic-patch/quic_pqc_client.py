import asyncio, socket, sys
sys.path.insert(0, "/opt/PQC-bench/ca")

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic import tls as aioquic_tls
from aioquic.tls import Group, SignatureAlgorithm

_OrigContext = aioquic_tls.Context


class _HybridOnlyContext(_OrigContext):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        if self._is_client:
            self._supported_groups = [Group.X25519MLKEM768]
            self._signature_algorithms = [SignatureAlgorithm.MLDSA65]


aioquic_tls.Context = _HybridOnlyContext

PKI = "/var/lib/p2p/certs-quic-pqc"


async def main(server_ip):
    config = QuicConfiguration(is_client=True, alpn_protocols=["quic-pqc-test"], server_name=server_ip)
    config.load_verify_locations(cafile=f"{PKI}/ca.crt")
    connection = QuicConnection(configuration=config)

    loop = asyncio.get_running_loop()
    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    csock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: QuicConnectionProtocol(connection, stream_handler=None), sock=csock
    )
    protocol.connect((server_ip, 4433))
    protocol.transmit()
    try:
        await asyncio.wait_for(protocol.wait_connected(), timeout=10)
        print("[client] CONNECTED -- real hybrid PQC QUIC handshake complete", flush=True)
        reader, writer = await protocol.create_stream()
        writer.write(b"hello-from-real-fleet")
        writer.write_eof()
        response = await asyncio.wait_for(reader.read(), timeout=5)
        print(f"[client] APPLICATION DATA ROUND TRIP: {response!r}", flush=True)
        print(f"[client] group negotiated: {hex(Group.X25519MLKEM768)}", flush=True)
    finally:
        protocol.close()
        await asyncio.sleep(0.2)
        transport.close()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
