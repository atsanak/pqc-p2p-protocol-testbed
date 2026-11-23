#!/usr/bin/env python3
"""quic_pqc_mqtt_relay.py — the receiver side of `MQTT_MODE=quic-pqc` (2026-09-28), the "MQTT-side
QUIC" gap: nothing existed here before this file. Different shape from `quic_pqc_relay.py`'s P2P
tech deliberately -- MQTT is a long-lived, bidirectional, stateful byte STREAM (a persistent
session, PINGREQ/PINGRESP keepalives, subscriptions living for the connection's lifetime), not a
one-shot request/response the way P2P's `message`/`file`/`status`/`rm`/`ml` verbs are. So this is
NOT HTTP/3 over the hybrid handshake (no H3Connection, no headers/status semantics at all) -- it's
a raw QUIC bidirectional STREAM used as a byte pipe, one stream per MQTT TCP connection, open for
that connection's entire lifetime. Same idea `mqtt-pqc-proxy.conf`'s stunnel front door already
uses for `MQTT_MODE=pqc[-mutual]` (dial a real broker's plain 1883 with a plaintext socket on one
side, an authenticated/encrypted transport on the other) -- just QUIC instead of TLS-over-TCP.

Every byte written to the QUIC stream by the device-side bridge (quic_pqc_mqtt_client.py) is
forwarded byte-for-byte to the broker's plain listener, and vice versa -- paho-mqtt on the device
side, and mosquitto on the broker side, both see an ordinary plaintext MQTT/TCP session throughout;
neither knows a hybrid-PQC QUIC tunnel carried it. Same "paho-mqtt never sees a difference from
MQTT_MODE=plain" idiom `device.py`'s existing pqc/pqc-mutual branches already document.

Usage:  /opt/pqc-libs/quic-pqc-venv/bin/python3 quic_pqc_mqtt_relay.py
Env:    P2P_QUIC_PQC_MQTT_PORT (default 4435, or 4436 if QUIC_PQC_MQTT_MUTUAL=1),
        QUIC_PQC_MQTT_BROKER_HOST (default 10.2.1.1 -- NOT 127.0.0.1: found live for
            MQTT_MODE=pqc's own stunnel proxy that this Docker container's port publish binds
            only its own overlay IP, same gotcha applies here), QUIC_PQC_MQTT_BROKER_PORT
            (default 1883), QUIC_PQC_MQTT_CERT_DIR (default /var/lib/p2p/certs-quic-pqc),
        QUIC_PQC_MQTT_MUTUAL (0/1, default 0)
"""
import asyncio
import os
import sys

sys.path.insert(0, "/opt/PQC-bench/ca")
import quic_pqc_ca  # noqa: E402

from aioquic import tls as aioquic_tls
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived, ConnectionTerminated
from cryptography import x509
from cryptography.x509.oid import NameOID

CERT_DIR = os.environ.get("QUIC_PQC_MQTT_CERT_DIR", "/var/lib/p2p/certs-quic-pqc")
MUTUAL = os.environ.get("QUIC_PQC_MQTT_MUTUAL", "0") == "1"
QUIC_PORT = int(os.environ.get("P2P_QUIC_PQC_MQTT_PORT", "4436" if MUTUAL else "4435"))
BROKER_HOST = os.environ.get("QUIC_PQC_MQTT_BROKER_HOST", "10.2.1.1")
BROKER_PORT = int(os.environ.get("QUIC_PQC_MQTT_BROKER_PORT", "1883"))

if MUTUAL:
    _OrigContext = aioquic_tls.Context

    class _RequireClientCertContext(_OrigContext):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            if not self._is_client:
                self._request_client_certificate = True
                # See quic_pqc_relay.py's own comment -- the stock default signature_algorithms
                # list has no MLDSA65 entry, so the client's negotiate() would silently send an
                # empty certificate without this.
                self._signature_algorithms = [aioquic_tls.SignatureAlgorithm.MLDSA65]

    aioquic_tls.Context = _RequireClientCertContext

def _write_file(path, data, mode):
    """Write `data` to `path` with permissions `mode` (2026-10-03): a temp file created with that mode, then
    os.replace(). A plain open(path, "wb") left server.key world-readable (0644 under the default umask) and
    kept an older file's mode; the rename gives a new inode, so an existing 0644 key becomes 0600 at the
    next start. The rename is atomic, so the plain and mutual relays, which both write this same file at
    start, never read a half-written one."""
    tmp = f"{path}.{os.getpid()}.{os.urandom(4).hex()}.tmp"   # unique per call, not only per process
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(fd, mode)          # os.open's mode is filtered by the umask; set it exactly
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)


class MqttBridgeProtocol(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._queues = {}   # stream_id -> asyncio.Queue of bytes FROM the QUIC stream
        self._tasks = {}    # stream_id -> the bridge task
        self._client_verified = None if MUTUAL else True

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            if MUTUAL:
                self._client_verified = self._check_client_cert()
            return
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if sid not in self._queues:
                if MUTUAL and not self._client_verified:
                    # Never open a TCP connection to the broker at all for an unverified peer.
                    return
                self._queues[sid] = asyncio.Queue()
                self._tasks[sid] = asyncio.ensure_future(self._bridge(sid))
            self._queues[sid].put_nowait(event.data)
            if event.end_stream:
                self._queues[sid].put_nowait(None)  # sentinel: the device closed its half
        elif isinstance(event, ConnectionTerminated):
            for t in self._tasks.values():
                t.cancel()

    def _check_client_cert(self):
        """Same chain+CN check quic_pqc_relay.py's mutual mode already does -- see that module's
        own docstring for why aioquic itself doesn't do this server-side."""
        cert = self._quic.tls._peer_certificate
        if cert is None:
            print("[quic-pqc-mqtt-relay-mutual] REJECTED: no client certificate presented",
                  flush=True)
            return False
        try:
            ca_cert = x509.load_pem_x509_certificate(open(f"{CERT_DIR}/ca.crt", "rb").read())
            ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        except Exception as e:  # noqa: BLE001
            print(f"[quic-pqc-mqtt-relay-mutual] REJECTED: chain does not verify: {e}", flush=True)
            return False
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        print(f"[quic-pqc-mqtt-relay-mutual] client cert verified: CN={cn}", flush=True)
        return True

    async def _bridge(self, stream_id):
        """One QUIC stream <-> one real TCP connection to the broker's plain listener, both
        directions, for as long as the device's MQTT session lives."""
        try:
            reader, writer = await asyncio.open_connection(BROKER_HOST, BROKER_PORT)
        except Exception as e:  # noqa: BLE001 -- close the QUIC stream, don't crash the relay
            print(f"[quic-pqc-mqtt-relay] stream {stream_id}: could not reach broker "
                  f"{BROKER_HOST}:{BROKER_PORT}: {e}", flush=True)
            self._quic.send_stream_data(stream_id, b"", end_stream=True)
            self.transmit()
            return
        print(f"[quic-pqc-mqtt-relay] stream {stream_id}: bridged to broker "
              f"{BROKER_HOST}:{BROKER_PORT}", flush=True)

        async def quic_to_tcp():
            q = self._queues[stream_id]
            while True:
                chunk = await q.get()
                if chunk is None:
                    writer.write_eof()
                    return
                writer.write(chunk)
                await writer.drain()

        async def tcp_to_quic():
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    self._quic.send_stream_data(stream_id, b"", end_stream=True)
                    self.transmit()
                    return
                self._quic.send_stream_data(stream_id, chunk)
                self.transmit()

        try:
            await asyncio.gather(quic_to_tcp(), tcp_to_quic())
        # OSError, not just Reset/BrokenPipe: when the broker closes first (e.g. CONNACK rc=5 to a
        # client without credentials), write_eof() on the dead socket raises ENOTCONN, which was
        # logged as "Task exception was never retrieved" per connection (T1-Rpi50, 2026-10-03).
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            self._queues.pop(stream_id, None)
            self._tasks.pop(stream_id, None)
            print(f"[quic-pqc-mqtt-relay] stream {stream_id}: closed", flush=True)

def _local_ipv4_addrs():
    """This box's global-scope IPv4 addresses (`ip -4 -o addr show scope global`); [] when `ip` fails."""
    import subprocess
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope", "global"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    addrs = []
    for line in out.splitlines():
        parts = line.split()
        if "inet" in parts and parts.index("inet") + 1 < len(parts):
            addrs.append(parts[parts.index("inet") + 1].split("/")[0])
    return sorted(set(addrs))


async def _serve_each_address(port, configuration, create_protocol, tag, bind_env):
    """Serve QUIC on `port` with one socket PER local IPv4 address (+ 127.0.0.1), never the 0.0.0.0
    wildcard (2026-10-03). A wildcard UDP socket answers from whatever source the ROUTE picks: on a
    gateway a client that dialled its anchor 10.2.1.1 got the handshake back from 10.2.0.10 (its wg0
    address), and aioquic never completed it ("ConnectionError" on T1-Rpi51 -> T1-Protectli2). Same
    cause and same fix as coap_dtls_pqc_relay.py ("Multi-homed reply address"). Addresses that appear
    later (wg0 after a slow boot) are picked up by a rescan every 60 s. $<bind_env>: "auto" (default),
    or a comma list of addresses ("0.0.0.0" restores the old wildcard). Never returns."""
    want = os.environ.get(bind_env, "auto").strip() or "auto"
    if want != "auto":
        for h in [x.strip() for x in want.split(",") if x.strip()]:
            await serve(h, port, configuration=configuration, create_protocol=create_protocol)
        print(f"[{tag}] bound {want} :{port} (from ${bind_env})", flush=True)
        await asyncio.Event().wait()
    bound, failed = set(), set()
    while True:
        for h in ["127.0.0.1"] + _local_ipv4_addrs():
            if h in bound:
                continue
            try:
                await serve(h, port, configuration=configuration, create_protocol=create_protocol)
                bound.add(h)
                failed.discard(h)
                print(f"[{tag}] bound {h}:{port}", flush=True)
            except OSError as e:          # vanished meanwhile, or in use: retried at the next scan
                if h not in failed:
                    print(f"[{tag}] cannot bind {h}:{port}: {e} (retrying every 60 s)", flush=True)
                failed.add(h)
        if not bound:
            raise SystemExit(f"[{tag}] could not bind any address on :{port}")
        await asyncio.sleep(60)


async def main():
    crt, key = quic_pqc_ca.issue(
        CERT_DIR, os.environ.get("QUIC_PQC_MQTT_NODE_NAME", os.uname().nodename),
        os.environ.get("QUIC_PQC_MQTT_NODE_IP", "0.0.0.0"),
        os.environ.get("QUIC_PQC_MQTT_TENANT", "T1"),
    )
    _write_file(f"{CERT_DIR}/server.crt", crt, 0o644)
    _write_file(f"{CERT_DIR}/server.key", key, 0o600)
    config = QuicConfiguration(is_client=False, alpn_protocols=["mqtt-quic-pqc"])
    config.load_cert_chain(f"{CERT_DIR}/server.crt", f"{CERT_DIR}/server.key")
    print(f"[quic-pqc-mqtt-relay{'-mutual' if MUTUAL else ''}] listening on :{QUIC_PORT} (each local IPv4 address)"
          f"{' (client cert REQUIRED)' if MUTUAL else ''}, bridging to broker "
          f"{BROKER_HOST}:{BROKER_PORT}, CA at {CERT_DIR}/ca.crt", flush=True)
    await _serve_each_address(QUIC_PORT, config, MqttBridgeProtocol,
                              f"quic-pqc-mqtt-relay{'-mutual' if MUTUAL else ''}", "QUIC_PQC_MQTT_BIND")


if __name__ == "__main__":
    asyncio.run(main())
