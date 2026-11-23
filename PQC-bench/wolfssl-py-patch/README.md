# wolfssl-py patch — real hybrid PQ-KEX DTLS 1.3, from Python

2026-09-27. Closes the gap every other PQC tech in this codebase hit: Python's stdlib `ssl` binds
system OpenSSL, which has no oqs-provider and never will negotiate a PQ-hybrid group — that's why
`pqc` is an ML-DSA-65-signed *envelope* over classical TLS instead of a real handshake, and why
`pqkex`/`coap-pqc`'s actual PQC transport work shells out to the private OpenSSL 3.4/3.5 builds as
a subprocess (see `p2p/sender-role/client.py`'s `_PQKexConnection`, `p2p/common/coap_crypto.py`).

The official `wolfssl` PyPI package (cffi-based Python binding for the wolfSSL C library) is real
and well-maintained — it has genuine `PROTOCOL_DTLSv1_3` support, mapped straight to
`wolfDTLSv1_3_client_method()`/`_server_method()`. But as shipped it exposes **no group/key-share
selection API at all**. Without one, nothing in this package can ever request a PQ-hybrid group —
the same gap, one layer up. `wolfSSL_UseKeyShare(ssl, group)` is the single C function needed to
force one; this patch adds it (plus `wolfSSL_get_curve_name()` to read back what was actually
negotiated, the only way to prove a request was honored rather than silently ignored).

## What the patch adds (`key-share-group.patch`, ~103 lines against `wolfssl==5.9.2.post0`)

- `_build_ffi.py`: two new `cdef` declarations (`wolfSSL_UseKeyShare`, `wolfSSL_get_curve_name`) —
  signatures verified against the actual `wolfssl/ssl.h` this pairs with before adding them
  (`word16` is `unsigned short` on any real CPU; the `WC_16BIT_CPU` branch that makes it `unsigned
  int` only applies to genuine 16-bit microcontroller targets).
- `__init__.py`:
  - `WOLFSSL_X25519MLKEM768 = 4588` and three siblings (`SECP256R1MLKEM768`,
    `SECP384R1MLKEM1024`, `ML_KEM_768` standalone) as module-level constants, from
    `wolfssl/ssl.h`'s own group-ID enum (`draft-ietf-tls-ecdhe-mlkem`).
  - `SSLSocket.__init__`/`SSLContext.wrap_socket` gain a new `key_share_group=` kwarg. When set,
    it calls `wolfSSL_UseKeyShare()` right after `wolfSSL_set_fd()` — before the handshake, same
    place the C example client (`examples/client/client.c`'s own `--pqc` flag) calls it. `None`
    (the default) changes nothing for any existing caller.
  - `SSLSocket.negotiated_group()` — wraps `wolfSSL_get_curve_name()`, returns e.g.
    `"X25519MLKEM768"` or `None`.

## Building the toolchain this pairs with

`../install-wolfssl-dtls.sh <target>` builds the wolfSSL C library itself with the exact flag set
that converges cleanly against this Python package (documented in full, including the trial-and-
error that found each one, in that script's own header comment — short version: `--enable-all
--enable-secure-renegotiation --enable-dtls13 --enable-dtls-mtu --enable-curve25519
--enable-tls-mlkem-standalone`). `--enable-all` does NOT include secure renegotiation; that one
has to be added explicitly or `wolfssl-py`'s import fails on a single missing symbol
(`wolfSSL_Rehandshake`) despite the C library itself building and working fine without it.

## Installing the patched Python package

```bash
pip download --no-deps --no-binary :all: -d /tmp/wolfssl-src wolfssl==5.9.2.post0
cd /tmp/wolfssl-src && tar xzf wolfssl-5.9.2.post0.tar.gz && cd wolfssl-5.9.2.post0
patch -p1 < /opt/PQC-bench/wolfssl-py-patch/key-share-group.patch
USE_LOCAL_WOLFSSL=/opt/pqc-libs/wolfssl-dtls pip install --no-deps -e .
```

## Proof (`dtls_pqkex_test.py`)

A real client+server DTLS 1.3 handshake, in pure Python, over a UDP socket pair, requesting
`WOLFSSL_X25519MLKEM768` explicitly:

```
LD_LIBRARY_PATH=/opt/pqc-libs/wolfssl-dtls/lib python3 dtls_pqkex_test.py
```
```
[client] negotiated_group(): X25519MLKEM768
[server] received: hello from client, requesting X25519MLKEM768
[server] negotiated_group(): X25519MLKEM768
[client] received: hello from server, over real hybrid PQ-KEX DTLS 1.3
PASS: real hybrid PQ-KEX DTLS 1.3 handshake, from pure Python
```

Both sides independently confirm the negotiated group (not just "connection succeeded" — the same
rigor `pqkex`'s own C-level proof used), and real application data flows both directions.

## aiocoap transport plugin (`aiocoap_wolfdtls.py`, `dtls_pqkex_client_proof.py`)

Closes the gap the previous section called out: aiocoap's only DTLS support
(`aiocoap.transports.tinydtls`) is DTLS 1.2 via tinydtls, with no PQ group of any kind — but
`p2p/receiver-role/coap_server.py` and `p2p/sender-role/client.py`'s `_coap_exchange` (the `coap`/
`coap-enc`/`coap-pqc` techs) are built on aiocoap. `aiocoap_wolfdtls.py` is a real aiocoap
`interfaces.MessageInterface`, CLIENT side only (matching tinydtls's own precedent — its docstring
says outright "This currently only implements the client side"), built on this patched `wolfssl`
binding instead of tinydtls. `dtls_pqkex_client_proof.py` is the live proof: a genuine
`aiocoap.Message`, sent through a real `aiocoap.Context` over this transport, decoded by a raw
wolfSSL DTLS 1.3 server as a real CoAP GET, answered with a real CoAP 2.05 Content response, and
decoded back into a real `Message` by the same `Context` — negotiated group confirmed both sides.

```
LD_LIBRARY_PATH=/opt/pqc-libs/wolfssl-dtls/lib python3 dtls_pqkex_client_proof.py
```
```
[server] negotiated_group(): X25519MLKEM768
[server] decoded a REAL aiocoap.Message: code=GET uri_path=('status',) mid=... token=...
[server] replied with a real CoAP 2.05 Content response
[client] received a real aiocoap response: 2.05 Content b'{"ok": true}'
PASS: a real aiocoap.Message round-tripped through real hybrid PQ-KEX DTLS 1.3
```

Verified passing on 3 consecutive runs, 2026-09-27. The one bug worth remembering if this gets
extended: **never call `sock.settimeout()` on the raw UDP socket handed to wolfSSL**. Python's
`settimeout(n)` (n other than `None`/`0`) puts the fd into non-blocking mode; wolfSSL drives that
fd directly via its own C-level I/O callbacks (bypassing Python's socket wrapper entirely) once
`wolfSSL_set_fd()` is called, and a non-blocking fd made this build send its ClientHello flight
twice and fail with a deterministic `SOCKET_ERROR_E` (-308). Full root-cause writeup, including
which earlier hypotheses turned out to be dead ends, is in `aiocoap_wolfdtls.py`'s own docstring.

## Wired into p2p as `coap-dtls-pqc` (2026-09-27)

`p2p/sender-role/client.py`'s `_coap_dtls_exchange` (tech `coap-dtls-pqc`) and
`p2p/receiver-role/coap_dtls_pqc_relay.py` — the scheme-collision question above is resolved by
NEVER sharing a Context with `tinydtls`: this tech opens its own fresh Context per exchange
(matching `_coap_exchange`'s own pattern for `coap`/`coap-enc`/`coap-pqc`), and the receiver side
is a SEPARATE dedicated port + process (the relay), not a mode added to coap_server.py's own
Context. The relay decrypts and re-issues the request as a genuine aiocoap client call against
coap_server.py's existing plain listener — NOT a byte-for-byte pipe (see the relay's own docstring
for why: coap_server.py Block2-chunks any response over ~1 KB unprompted, and p2p's envelope
always carries a whole certificate, so that's every exchange, not an edge case).

Two more bugs found wiring this in, past the ones above:
- **DTLS_SIZE_ERROR (-439)**: this build's DTLS write is capped well under 1200-1400 bytes per
  `ssock.write()` call, and the envelope (cert included) is reliably bigger than that. Fixed with
  `write_framed`/`read_framed` (≤1024-byte chunks, each with a 1-byte more-flag + 4-byte sequence
  number, relying on DTLS/UDP's message-boundary-preserving `read()`/`write()`) — used by BOTH ends,
  imported from here rather than reimplemented, so they can't drift apart.
- **Large payloads lost/reordered chunks (fixed 2026-10-01)**: DTLS application records are plain
  UDP — not retransmitted, not ordered. Over the real WireGuard overlay an unpaced 300 KB message
  (~293 chunks) lost 65 chunks and reordered others; the old header-less framing joined what
  arrived, so the envelope signature failed (the old "300 KB fails on `coap-dtls-pqc[-mutual]`"
  limitation; loopback never showed it). Now: sequence numbers (reorder/duplicate tolerant, a real
  gap raises `FramingError` naming the missing chunks) + a 2 ms inter-chunk pause (`CHUNK_PACE_S`
  env). Live-verified Protectli2→Protectli1 over the overlay: 300 KB intact twice when paced;
  unpaced fails loudly instead of corrupting. **Wire-format change** — sender and relay must be
  deployed together.
- **Legacy framing still accepted (2026-10-02)**: the Server's telemetry `coap-dtls-pqc` relays were
  never upgraded, so new devices' telemetry/ML records reached them as "Protocol Version must be 1".
  `read_framed` now recognises a legacy first chunk (byte 1 is a CoAP header, version 1, instead of
  seq 0's 0x00), reads it the old way and marks the socket, and `write_framed` answers that peer in
  legacy framing. Either end can now be upgraded first. Test: `test_framing_compat.py`.
- CoAP's own blockwise transfer (RFC 7959) fires on the REQUEST side too, for the same reason, and
  this transport has no Block1 continuation logic — the sender disables it explicitly
  (`ctx.request(req, handle_blockwise=False)`) rather than half-implementing it.

Proven end-to-end, real `Client` → real relay → real `coap_server.py` (self-signed test certs
standing in for the fleet CA, since this sandbox has no live control-plane access set up for it),
6/6 runs: real hybrid handshake, real CN/SAN cert verification, a real signed CoAP response with
both request (2013B) and reply (2082B) exercising the chunking above in both directions.

## Deployed and verified live on the real fleet (2026-09-27)

Built and installed on both Protectli1 (`T1-Protectli1-direct-T1`, sender) and Protectli2
(`T1-Protectli2-gw-T1`, receiver+relay) — the wolfSSL C toolchain via `install-wolfssl-dtls.sh`
(one real compile on Protectli1, ~cached and restored on Protectli2 since both are x86_64), the
patched `wolfssl` Python binding via the same download+patch+`pip install -e .` steps this
README's own "Installing the patched Python package" section documents, `PQC-bench/wolfssl-py-patch/`
and the relay + its systemd unit (`p2p-coap-dtls-pqc-relay.service`) pushed to `/opt`.

Four more real bugs found ONLY on real hardware — every one of them invisible over loopback, which
is what every earlier proof in this file used:
- **DTLS handshake fragmentation vs. a real tunnel's MTU**: this build's own default DTLS
  fragmentation threshold (`WOLFSSL_MAX_MTU`, 1400) plus its own record/UDP/IP header overhead
  exceeds the 1420-byte MTU of the WireGuard tunnel Protectli1↔Protectli2 talk over — the
  oversized ClientHello datagram was silently dropped (DF set, no PMTU signal makes it back
  through the tunnel), and the handshake failed with a LOCAL-ONLY error that never reached the
  peer at all. Fixed by adding `wolfSSL_dtls_set_mtu()` to the patch (a second function, alongside
  the original two) and calling it with a value safely under 1420 on both ends.
- **Multi-homed reply address**: a receiver bound to the wildcard `0.0.0.0` replies with whatever
  source address the kernel's routing table picks for the destination, not necessarily the address
  the request arrived on — invisible on a single-homed box, real on Protectli2 (a gateway with two
  relevant addresses). Fixed by binding one listener per local IPv4 address instead of the
  wildcard.
- **wolfSSL is not safe to use concurrently from multiple threads** in this build (no
  `--enable-mutex` or equivalent) — the multi-address fix above means multiple threads each touch
  wolfSSL, and doing so concurrently reproduced live as the whole relay process crashing
  periodically. Fixed with a single process-wide lock serializing every wolfSSL call.
- **The real root cause of "works once, then every later exchange on the same address times out
  with nothing logged"**: after one exchange completes, the sender's wolfSSL socket sends a
  trailing DTLS record (an Alert, almost certainly `close_notify`) from the same source port that
  just finished. A bare `MSG_PEEK` can't distinguish that from a genuine new peer's ClientHello —
  the old code `connect()`ed to it and called `do_handshake()` on it, which then blocked for the
  *entire* idle-timeout window (the sender has nothing more to say) while holding the wolfSSL lock
  above, starving every other real peer with nothing ever logged (`do_handshake()` was still "in
  progress", not yet failed). Fixed by checking each peeked datagram's DTLS content-type byte
  (RFC 6347: `0x16` is Handshake) before treating it as a new peer, and draining/discarding
  anything else. This was THE fix — verified 28/28 successful live exchanges afterward, 0/8 before it.

Also found and fixed along the way (real, but smaller): `SO_RCVTIMEO` expiry raises
`BlockingIOError`, not `socket.timeout` (that's reserved for Python's own `settimeout()`
mechanism, deliberately not used here); a socket leak when `wrap_socket()` itself failed before
the function's own `try`/`finally` had started; and a defensive `SO_REUSEADDR` that turned out to
risk letting the kernel route a packet to an already-abandoned socket on Linux UDP, removed once
the actual leak was fixed properly.

`status` verified live end-to-end after all of the above: real hybrid DTLS 1.3 handshake, real
CN/SAN certificate verification against the fleet CA, real relay, real signed CoAP response —
consistently under a second per exchange once past the very first call (which also pays cert-cache
and cold-process overhead).

## What this is still NOT (yet)

Receiver side: a real asyncio DTLS SERVER transport (accepting many peers concurrently, not one
sequential blocking-socket loop per address) — genuinely separate, larger, unstarted work;
`coap_dtls_pqc_relay.py` is deliberately sequential/single-peer-at-a-time PER ADDRESS (see its own
docstring) as the smaller, scoped alternative, now proven reliable at that scope on real hardware.

## DTLS-SRTP for video streaming (`srtp.patch`, 2026-09-28)

Closes the "budget a research spike" open question `WIKI-JS/MAIN/video-streaming-plaintext-plan.md`
flagged for the RTP+DTLS-SRTP leg: does this build's wolfSSL actually support RFC 5764 DTLS-SRTP
key export? Confirmed via `nm -D` on the already-built `/opt/pqc-libs/wolfssl-dtls/lib/libwolfssl.so`
that the C symbols exist (`wolfSSL_set_tlsext_use_srtp`, `wolfSSL_export_dtls_srtp_keying_material`,
`wolfSSL_get_selected_srtp_profile`) — same shape gap `key-share-group.patch` closed for PQ groups:
the C library has it, the Python binding didn't expose it at all.

### What the patch adds (`srtp.patch`, ~155 lines against the key-share-group-patched baseline)

- `_build_ffi.py`: two new `cdef` declarations (`wolfSSL_set_tlsext_use_srtp`,
  `wolfSSL_export_dtls_srtp_keying_material`), plus `--enable-srtp --enable-mldsa
  --enable-curve25519 --enable-tls-mlkem-standalone --enable-dtls-mtu --enable-all` added to this
  file's OWN internal wolfSSL rebuild (triggered any time `python3 -m wolfssl._build_ffi` runs --
  it clones+configures its own copy under `lib/wolfssl/`, independent of whatever
  `/opt/pqc-libs/wolfssl-dtls` already has built, so it needs the SAME flags stated explicitly
  here or it silently regresses features the rest of this patch chain already depends on).
- `__init__.py`: `SSLContext.wrap_socket`/`SSLSocket.__init__` gain `use_srtp=` (a profile string,
  e.g. `"SRTP_AES128_CM_SHA1_80"`, negotiated via `wolfSSL_set_tlsext_use_srtp()` before the
  handshake); `SSLSocket.export_srtp_keying_material()` wraps
  `wolfSSL_export_dtls_srtp_keying_material()`, called AFTER `do_handshake()` on both ends.

### Three real bugs found standing this up

- **`wolfSSL_set_tlsext_use_srtp` uses OpenSSL's return convention (0=success, 1=error)**, the
  OPPOSITE of every other wolfSSL-native call in this binding (`SSL_SUCCESS=1`) — confirmed
  against this build's own `ssl_api_dtls.c` docstring ("@return 0 on success ... to match
  OpenSSL"). `rc=0` looked like a failure the first time; it wasn't.
- **`--enable-all` is NOT a superset of `--enable-srtp`/`--enable-mldsa`/`--enable-curve25519`/
  `--enable-tls-mlkem-standalone`** for THIS internal rebuild path specifically — each needed
  adding explicitly, confirmed live via `nm` on the resulting `libwolfssl.a` after a first build
  attempt silently omitted the real SRTP symbols (only an unrelated `IsDtlsNotSrtpMode` helper was
  present) and again after ML-DSA cert loading failed with a content-free "Unable to load
  certificate chain. E(0)" against this tenant's real ML-DSA-65 leaf.
- **The exact same "multi-homed reply address" bug this README's own earlier section documents**
  for `coap_dtls_pqc_relay.py` — hit again independently on the same box (Protectli2), for the
  video-streaming RTP+DTLS-SRTP receiver this time. Same fix: bind to the specific tenant address,
  never the `0.0.0.0` wildcard.

### Proof (`dtls_srtp_pqc_proof.py`)

```
LD_LIBRARY_PATH=/opt/pqc-libs/wolfssl-dtls/lib python3 dtls_srtp_pqc_proof.py
```
```
[server] negotiated_group(): X25519MLKEM768
[server] srtp keying material (60B): a1d7d5ec...
[client] negotiated_group(): X25519MLKEM768
[client] srtp keying material (60B): a1d7d5ec...
PASS: real hybrid PQ-KEX DTLS 1.3 + RFC 5764 use_srtp -- both ends derived byte-identical 60B
SRTP keying material independently
```

Both ends independently deriving byte-identical keying material from ONLY the DTLS handshake
(never exchanged directly) is the actual cryptographic proof, same rigor `negotiated_group()`
already established for the PQ-KEX side.

### Wired into video streaming as RTP+DTLS-SRTP (Stacks 3/4), proven live 2026-09-28

See `video-streaming/README.md`'s own RTP+DTLS-SRTP section for the full write-up: real
`SRTP_AES128_CM_SHA1_80` (`video-streaming/srtp_crypto.py`, pure Python + `cryptography`, no
libsrtp) streaming the real saved video Protectli1→Protectli2, both server-auth (Stack 3) and
mutual (Stack 4, confirmed by a NEGATIVE test — a non-mutual client gets refused with
`alert (116): certificate_required`). Session control (port/codec/resolution/SSRC) rides over
this same `coap-dtls-pqc` tech via `tenant_api.p2p_message`, per `for-your-ok.md`'s own design —
zero new transport code for that half.
