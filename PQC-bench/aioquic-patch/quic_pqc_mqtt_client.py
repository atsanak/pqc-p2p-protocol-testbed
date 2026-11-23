#!/usr/bin/env python3
"""quic_pqc_mqtt_client.py — the device side of `MQTT_MODE=quic-pqc`/`quic-pqc-mutual`
(2026-09-28). Local TCP front door, same role `mqtt-pqc-client.conf`'s stunnel already plays for
`MQTT_MODE=pqc[-mutual]`: paho-mqtt (device.py) connects to `127.0.0.1:<local port>` in plaintext,
exactly like `MQTT_MODE=plain`, and never knows a real hybrid-PQC QUIC tunnel carried the session
underneath. One QUIC connection + one stream per incoming local TCP connection, open for that
connection's whole lifetime -- see quic_pqc_mqtt_relay.py's own docstring for why this is a raw
byte-pipe stream, not HTTP/3.

Usage:  /opt/pqc-libs/quic-pqc-venv/bin/python3 quic_pqc_mqtt_client.py
Env:    QUIC_PQC_MQTT_LOCAL_HOST (default 0.0.0.0 -- not 127.0.0.1: a device.py running in a
            further-nested Docker container reaches this host only via its own bridge gateway,
            the SAME finding mqtt-pqc-client.conf's own comment already documents),
        QUIC_PQC_MQTT_LOCAL_PORT (default 9450, or 9451 if QUIC_PQC_MQTT_MUTUAL=1),
        QUIC_PQC_MQTT_BROKER_HOST (the relay's address -- REQUIRED, no default, same as
            mqtt-pqc-client.conf's own `connect =` needing an explicit per-box edit),
        P2P_QUIC_PQC_MQTT_PORT (default 4435, or 4436 if QUIC_PQC_MQTT_MUTUAL=1),
        QUIC_PQC_MQTT_SERVER_NAME (the relay's CN, for hostname verification -- REQUIRED),
        QUIC_PQC_CA_PATH (default /var/lib/p2p/certs-quic-pqc/ca.crt),
        QUIC_PQC_MQTT_MUTUAL (0/1, default 0), QUIC_PQC_CERT_PATH/QUIC_PQC_KEY_PATH (mutual only,
            this device's own quic-pqc identity -- default /var/lib/p2p/certs-quic-pqc/peer.{crt,key})
"""
import asyncio
import os

from aioquic import tls as aioquic_tls
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated
from aioquic.tls import Group, SignatureAlgorithm

MUTUAL = os.environ.get("QUIC_PQC_MQTT_MUTUAL", "0") == "1"
LOCAL_HOST = os.environ.get("QUIC_PQC_MQTT_LOCAL_HOST", "0.0.0.0")
LOCAL_PORT = int(os.environ.get("QUIC_PQC_MQTT_LOCAL_PORT", "9451" if MUTUAL else "9450"))
BROKER_HOST = os.environ["QUIC_PQC_MQTT_BROKER_HOST"]
BROKER_PORT = int(os.environ.get("P2P_QUIC_PQC_MQTT_PORT", "4436" if MUTUAL else "4435"))
SERVER_NAME = os.environ["QUIC_PQC_MQTT_SERVER_NAME"]
CA_PATH = os.environ.get("QUIC_PQC_CA_PATH", "/var/lib/p2p/certs-quic-pqc/ca.crt")
CERT_PATH = os.environ.get("QUIC_PQC_CERT_PATH", "/var/lib/p2p/certs-quic-pqc/peer.crt")
KEY_PATH = os.environ.get("QUIC_PQC_KEY_PATH", "/var/lib/p2p/certs-quic-pqc/peer.key")

# Same "offer only the group/algorithm under test" methodology every real-handshake PQC tech
# here uses -- see quic_pqc_client_helper.py's own identical override for the P2P tech.
_OrigContext = aioquic_tls.Context


class _HybridOnlyContext(_OrigContext):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        if self._is_client:
            self._supported_groups = [Group.X25519MLKEM768]
            self._signature_algorithms = [SignatureAlgorithm.MLDSA65]


aioquic_tls.Context = _HybridOnlyContext


class MqttTunnelProtocol(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.recv_queue = asyncio.Queue()
        self.stream_id = None

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived) and event.stream_id == self.stream_id:
            self.recv_queue.put_nowait(event.data)
            if event.end_stream:
                self.recv_queue.put_nowait(None)
        elif isinstance(event, ConnectionTerminated):
            self.recv_queue.put_nowait(None)


async def handle_local(reader, writer):
    peer = writer.get_extra_info("peername")
    print(f"[quic-pqc-mqtt-client] local connection from {peer}, opening QUIC tunnel to "
          f"{BROKER_HOST}:{BROKER_PORT}", flush=True)
    config = QuicConfiguration(is_client=True, alpn_protocols=["mqtt-quic-pqc"],
                               server_name=SERVER_NAME)
    config.load_verify_locations(cafile=CA_PATH)
    if MUTUAL:
        config.load_cert_chain(CERT_PATH, KEY_PATH)
    connection = QuicConnection(configuration=config)

    loop = asyncio.get_running_loop()
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MqttTunnelProtocol(connection, stream_handler=None), sock=sock
    )
    try:
        protocol.connect((BROKER_HOST, BROKER_PORT))
        protocol.transmit()
        await asyncio.wait_for(protocol.wait_connected(), timeout=10)
        protocol.stream_id = connection.get_next_available_stream_id()
        print(f"[quic-pqc-mqtt-client] tunnel established (stream {protocol.stream_id}) "
              f"for {peer}", flush=True)

        async def local_to_quic():
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    connection.send_stream_data(protocol.stream_id, b"", end_stream=True)
                    protocol.transmit()
                    return
                connection.send_stream_data(protocol.stream_id, chunk)
                protocol.transmit()

        async def quic_to_local():
            while True:
                chunk = await protocol.recv_queue.get()
                if chunk is None:
                    writer.write_eof()
                    return
                writer.write(chunk)
                await writer.drain()

        await asyncio.gather(local_to_quic(), quic_to_local())
    except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError) as e:
        print(f"[quic-pqc-mqtt-client] tunnel for {peer} failed: {e}", flush=True)
    finally:
        writer.close()
        protocol.close()
        transport.close()
        print(f"[quic-pqc-mqtt-client] tunnel for {peer} closed", flush=True)


async def main():
    server = await asyncio.start_server(handle_local, LOCAL_HOST, LOCAL_PORT)
    print(f"[quic-pqc-mqtt-client{'-mutual' if MUTUAL else ''}] listening on "
          f"{LOCAL_HOST}:{LOCAL_PORT} -> {BROKER_HOST}:{BROKER_PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
