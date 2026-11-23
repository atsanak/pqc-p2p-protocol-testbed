#!/usr/bin/env bash
# install-aioquic-pqc.sh — build /opt/pqc-libs/quic-pqc-venv: a dedicated Python venv with
# `cryptography>=50` + `aioquic`, hybrid-PQC-patched (2026-09-28), for the quic-pqc tech
# (Stack 5/6 -- QUIC/HTTP-3, for-your-ok.md's numbering).
#
# A FIFTH parallel toolchain, alongside the private OpenSSL 3.4+oqs-provider build (pqc/pqkex),
# the private OpenSSL 3.5+ build (pqc_kem.py's ML-KEM), the wolfSSL DTLS 1.3 build
# (coap-dtls-pqc), and system OpenSSL -- but the ONLY one that is NOT a compiled C toolchain.
# `cryptography` 50.0.1 ships NATIVE ML-KEM-768 (`mlkem` module) and ML-DSA-65 (`mldsa` module)
# support, confirmed live 2026-09-28 -- no oqs-provider, no LD_LIBRARY_PATH/OPENSSL_CONF
# gymnastics, no C compile at all. And `aioquic` implements TLS 1.3 itself in pure Python (via
# `cryptography` for the crypto primitives, not Python's stdlib `ssl`/system libssl) -- the same
# wall that forced `pqc`/`pqkex`/`coap-dtls-pqc` into private OpenSSL/wolfSSL builds simply
# doesn't exist here, because aioquic never asks the system TLS stack to do anything at all.
#
# What `tls.py.patch` adds (see that file, and quic_pqc_ca.py's own docstring for why a FOURTH
# separate CA, not a reuse of pqc_ca.py's oqs-provider-issued certs -- confirmed live that their
# PRIVATE KEY encodings are not cross-compatible, even though the PUBLIC key/cert format is):
#   - Group.X25519MLKEM768 = 0x11EC (IANA TLS codepoint, draft-ietf-tls-ecdhe-mlkem) -- a hybrid
#     key_share handled as a special case in _client_send_hello/_server_handle_hello/
#     _client_handle_hello, since decode_public_key()/encode_public_key() return ONE cryptography
#     key object and a hybrid key_share is genuinely two independent keys concatenated.
#   - SignatureAlgorithm.MLDSA65 = 0x0905, wired into signature_algorithm_params() and
#     _signature_algorithms_for_private_key() the same way ED25519 already is.
# Combiner order: x25519_shared || mlkem_shared (classical || post-quantum) -- same order
# oqs-provider uses for this project's OTHER "X25519MLKEM768" techs, for convention consistency,
# though this is a completely separate, self-contained implementation (not wire-compatible with
# those -- TLS-inside-QUIC, not a stunnel front door).
#
# Live-verified 2026-09-28, real fleet (Protectli1 client -> Protectli2 server, over the real
# WireGuard overlay, not loopback): a genuine hybrid PQC QUIC handshake completes
# (HandshakeCompleted, alpn negotiated), an application-data stream round-trips, and the
# negotiated group is confirmed 0x11ec on both ends.
#
# Usage (run AS ROOT, directly on the target box -- unlike the C-toolchain installers in this
# directory, there is no multi-hour build to justify pqc-transport.sh's remote-orchestration +
# tarball-cache machinery, so this one is push-and-run-locally, same convention as
# mqtt-pqc-client's run-mqtt-pqc-client.sh):
#   ./install-aioquic-pqc.sh
# Idempotent: an existing working venv is left untouched.
set -Eeuo pipefail
PREFIX=/opt/pqc-libs/quic-pqc-venv
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

works(){
  [ -x "$PREFIX/bin/python3" ] || return 1
  "$PREFIX/bin/python3" -c "
from aioquic.tls import Group, SignatureAlgorithm
assert Group.X25519MLKEM768 == 0x11EC
assert Group.MLKEM768 == 0x0201   # 2026-10-23: the PURE ML-KEM-768 group the quic-pqc* configs negotiate
assert SignatureAlgorithm.MLDSA65 == 0x0905
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
" >/dev/null 2>&1
}

if works; then
  echo "==> $PREFIX already present and patched -- nothing to do"
  exit 0
fi

echo "==> [1/3] python3-venv"
apt-get install -y -qq python3-venv >/dev/null

echo "==> [2/3] venv + pip install (cryptography>=50, aioquic)"
rm -rf "$PREFIX"
python3 -m venv "$PREFIX"
"$PREFIX/bin/pip" install -q --upgrade pip
# aioquic is PINNED to the release tls.py.patch was cut against (1.3.0). Unpinned, a new box got whatever PyPI
# had (1.6.1 on 2026-10-16): the patch still applied, but the handshake then failed with "No supported key
# share" (found live on T-pash2-IntelNUC, Ubuntu 25.10 / Python 3.13) -- quic-pqc* PeerUnreachable.
"$PREFIX/bin/pip" install -q 'cryptography>=50' 'aioquic==1.3.0'

echo "==> [3/3] apply the hybrid-PQC patch"
TLS_PY="$("$PREFIX/bin/python3" -c 'import aioquic.tls; print(aioquic.tls.__file__)')"
patch "$TLS_PY" < "$HERE/tls.py.patch"

works && echo "==> OK: $PREFIX ready (Group.X25519MLKEM768, Group.MLKEM768, SignatureAlgorithm.MLDSA65 present)" \
      || { echo "==> FAILED: patch applied but the module doesn't verify" >&2; exit 1; }
