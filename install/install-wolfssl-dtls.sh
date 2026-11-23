#!/usr/bin/env bash
# install-wolfssl-dtls.sh — build wolfSSL (real DTLS 1.3 + hybrid PQ-KEX + full opensslextra
# compat) into /opt/pqc-libs/wolfssl-dtls, for CoAP-over-DTLS-1.3 work (2026-09-27).
#
# A FOURTH parallel toolchain, alongside the private OpenSSL 3.4+oqs-provider build (pqc/pqkex),
# the private OpenSSL 3.5+ build (pqc_kem.py's ML-KEM), and system OpenSSL. wolfSSL is the only
# TLS library here with real DTLS 1.3 support at all -- OpenSSL (any version) has none.
#
# The flag set below is NOT arbitrary -- it converged the hard way, one missing symbol at a time,
# trying to get the OFFICIAL `wolfssl` PyPI Python binding (cffi-based) to import successfully
# against this exact build:
#   --enable-all                  the broadest feature set (needed: most of wolfssl-py's huge
#                                  openssl-compat cdef surface; NOT included: SSLv3, and --
#                                  surprisingly -- secure renegotiation, hence the next line)
#   --enable-secure-renegotiation  wolfSSL_Rehandshake -- wolfssl-py's SSL_renegotiate compat
#                                  macro needs this even though --enable-all does not turn it on
#   --enable-dtls13                real DTLS 1.3 (the actual point of this build)
#   --enable-dtls-mtu               DTLS ClientHello fragmenting (a PQ hybrid key share is too
#                                  big for one datagram without this)
#   --enable-curve25519            the classical half of X25519MLKEM768 -- without it, only
#                                  non-hybrid ML-KEM groups are available, and this codebase's
#                                  convention (pqkex, coap-pqc, PQC-bench generally) is hybrid
#   --enable-tls-mlkem-standalone   lets a NON-hybrid ML-KEM group be selected too, if ever wanted
#
# Getting here from a plain --enable-dtls13 needed FOUR rebuild rounds, discovered live:
#   SSL_OP_NO_TICKET undeclared  -> needs --enable-session-ticket (folded into --enable-all here)
#   wolfSSL_LoadCRLFile missing  -> needs --enable-crl                      ( ditto )
#   wolfSSL_Rehandshake missing  -> needs --enable-secure-renegotiation (NOT in --enable-all)
# If a future wolfssl-py version needs yet another symbol, the fix is always the same shape:
# `nm -D $PREFIX/lib/libwolfssl.so | grep -i <symbol fragment>` to confirm it is really absent,
# then `./configure --help | grep -i <relevant keyword>` to find the flag that adds it.
#
# Usage:  ./install-wolfssl-dtls.sh <target> [--ssh-key PATH]
#   <target> = an incus VM name, or ssh:<user>@<host> for a physical box (pqc-transport.sh).
# Idempotent: re-running with the tree already present and runnable exits early.
set -Eeuo pipefail
_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: install-wolfssl-dtls.sh <incus-vm|ssh:user@host> [--ssh-key PATH]}"; shift
while [ $# -gt 0 ]; do
  case "$1" in
    --ssh-key) PQC_SSH_KEY="${2:?--ssh-key needs a path}"; export PQC_SSH_KEY; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
# shellcheck source=pqc-transport.sh
. "$_HERE/pqc-transport.sh"
nx_init "$TARGET"
VM="$(nx_label)"

WOLFSSL_TAG="${WOLFSSL_TAG:-v5.9.4-stable}"
PREFIX=/opt/pqc-libs/wolfssl-dtls
CACHE_DIR="${PQC_CACHE_DIR:-$HOME/.cache/testbed/pqc}"

ARCH="$(nx_exec uname -m 2>/dev/null | tr -d '\r\n')"
[ -n "$ARCH" ] || { echo "    ERROR: could not read uname -m from $VM"; exit 1; }
CACHE_TAR="$CACHE_DIR/$ARCH/wolfssl-dtls.tar.gz"

wolfssl_works(){
  nx_sh "LD_LIBRARY_PATH=$PREFIX/lib $PREFIX/bin/openssl version >/dev/null 2>&1; \
     test -f $PREFIX/lib/libwolfssl.so" >/dev/null 2>&1
}

echo "==> [$VM] wolfSSL $WOLFSSL_TAG (DTLS 1.3 + hybrid PQ-KEX) -> $PREFIX  (arch: $ARCH)"

if wolfssl_works; then
  echo "    already present and runnable — skipping"
  exit 0
fi

if [ -f "$CACHE_TAR" ]; then
  echo "    restoring from cache ($(du -h "$CACHE_TAR" | cut -f1)) — no compile"
  nx_push "$CACHE_TAR" /tmp/wolfssl-dtls.tar.gz >/dev/null
  nx_sh 'mkdir -p /opt/pqc-libs && tar -C /opt/pqc-libs -xzf /tmp/wolfssl-dtls.tar.gz && rm -f /tmp/wolfssl-dtls.tar.gz'
  if wolfssl_works; then
    echo "==> [$VM] done (from cache)"
    exit 0
  fi
  echo "    WARN: cache restore produced no usable build — falling through to a source build"
fi

nx_sh_stdin <<EOF
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
PREFIX=$PREFIX
WOLFSSL_TAG=$WOLFSSL_TAG
LOG=/root/wolfssl-src/build.log
trap 'echo "  FAILED -- tail of \$LOG:"; tail -20 \$LOG' ERR
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq build-essential autoconf automake libtool git >/dev/null 2>&1
mkdir -p \$PREFIX /root/wolfssl-src
cd /root/wolfssl-src
[ -d wolfssl ] || git clone --depth 1 --branch \$WOLFSSL_TAG https://github.com/wolfSSL/wolfssl.git >>\$LOG 2>&1
cd wolfssl
./autogen.sh >>\$LOG 2>&1
./configure --prefix=\$PREFIX --enable-all --enable-secure-renegotiation \\
    --enable-dtls13 --enable-dtls-mtu --enable-curve25519 \\
    --enable-tls-mlkem-standalone >>\$LOG 2>&1
make -j\$(nproc) >>\$LOG 2>&1
make install >>\$LOG 2>&1
echo "  wolfSSL DTLS 1.3 + hybrid PQ-KEX build verified present"
EOF

if [ ! -f "$CACHE_TAR" ] && wolfssl_works; then
  mkdir -p "$(dirname "$CACHE_TAR")"
  if nx_exec tar -C /opt/pqc-libs -czf /tmp/wolfssl-dtls.tar.gz wolfssl-dtls 2>/dev/null \
     && nx_pull /tmp/wolfssl-dtls.tar.gz "$CACHE_TAR" 2>/dev/null; then
    nx_exec rm -f /tmp/wolfssl-dtls.tar.gz 2>/dev/null || true
    echo "    cached the built tree -> $CACHE_TAR ($(du -h "$CACHE_TAR" | cut -f1))"
  fi
fi
echo "==> [$VM] done"
echo "    Python bindings: pip install the patched wolfssl-py in ./wolfssl-py-patch/ against"
echo "    this prefix (USE_LOCAL_WOLFSSL=$PREFIX) -- see wolfssl-py-patch/README.md"
