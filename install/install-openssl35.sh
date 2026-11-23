#!/usr/bin/env bash
# install-openssl35.sh — build a THIRD, independent OpenSSL install into /opt/pqc-libs/openssl35,
# for pqc_kem.py's ML-KEM-768 operations only (2026-09-27).
#
# Why a third toolchain, not a third mode of the existing one: /opt/pqc-libs/openssl-priv (3.4.1 +
# oqs-provider) cannot export a standalone ML-KEM key at all -- confirmed live, a documented
# upstream oqs-provider limitation (open-quantum-safe/oqs-provider#84/#589), not fixable by
# reconfiguring that build. OpenSSL 3.5+ has ML-KEM/ML-DSA NATIVE in its own default provider, no
# oqs-provider involved -- a completely separate install, parallel to (not replacing) the working
# 3.4 build every existing pqc/pqkex/gateway-proxy path depends on. System OpenSSL and
# openssl-priv are both completely untouched by this.
#
# Usage:  ./install-openssl35.sh <target> [--ssh-key PATH]
#   <target> = an incus VM name, or ssh:<user>@<host> for a physical box (pqc-transport.sh).
# Idempotent: re-running with the tree already present and runnable exits early.
set -Eeuo pipefail
_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: install-openssl35.sh <incus-vm|ssh:user@host> [--ssh-key PATH]}"; shift
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

OPENSSL_VER="${OPENSSL_VER:-3.5.8}"
PREFIX=/opt/pqc-libs/openssl35
CACHE_DIR="${PQC_CACHE_DIR:-$HOME/.cache/testbed/pqc}"

ARCH="$(nx_exec uname -m 2>/dev/null | tr -d '\r\n')"
[ -n "$ARCH" ] || { echo "    ERROR: could not read uname -m from $VM"; exit 1; }
CACHE_TAR="$CACHE_DIR/$ARCH/openssl35.tar.gz"

openssl_works(){
  nx_sh "LD_LIBRARY_PATH=$PREFIX/lib64 $PREFIX/bin/openssl genpkey -algorithm ML-KEM-768 -out /tmp/.o35check.key >/dev/null 2>&1 \
     && rm -f /tmp/.o35check.key" >/dev/null 2>&1
}

echo "==> [$VM] OpenSSL $OPENSSL_VER (native ML-KEM/ML-DSA) -> $PREFIX  (arch: $ARCH)"

if openssl_works; then
  echo "    already present and runnable — skipping"
  exit 0
fi

if [ -f "$CACHE_TAR" ]; then
  echo "    restoring from cache ($(du -h "$CACHE_TAR" | cut -f1)) — no compile"
  nx_push "$CACHE_TAR" /tmp/openssl35.tar.gz >/dev/null
  nx_sh 'mkdir -p /opt/pqc-libs && tar -C /opt/pqc-libs -xzf /tmp/openssl35.tar.gz && rm -f /tmp/openssl35.tar.gz'
  if openssl_works; then
    echo "==> [$VM] done (from cache)"
    exit 0
  fi
  echo "    WARN: cache restore produced no usable openssl — falling through to a source build"
fi

nx_sh_stdin <<EOF
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
PREFIX=$PREFIX
OPENSSL_VER=$OPENSSL_VER
LOG=/root/openssl35-src/build.log
trap 'echo "  FAILED -- tail of \$LOG:"; tail -15 \$LOG' ERR
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq build-essential perl wget >/dev/null 2>&1
mkdir -p \$PREFIX /root/openssl35-src
cd /root/openssl35-src
[ -f openssl-\$OPENSSL_VER.tar.gz ] || \
  wget -q https://github.com/openssl/openssl/releases/download/openssl-\$OPENSSL_VER/openssl-\$OPENSSL_VER.tar.gz
rm -rf openssl-\$OPENSSL_VER && tar xf openssl-\$OPENSSL_VER.tar.gz
cd openssl-\$OPENSSL_VER
./Configure --prefix=\$PREFIX --openssldir=\$PREFIX/ssl --libdir=lib64 shared enable-ec_nistp_64_gcc_128 >>\$LOG 2>&1
make -j\$(nproc) >>\$LOG 2>&1
make install_sw >>\$LOG 2>&1
LD_LIBRARY_PATH=\$PREFIX/lib64 \$PREFIX/bin/openssl genpkey -algorithm ML-KEM-768 -out /tmp/.verify.key
LD_LIBRARY_PATH=\$PREFIX/lib64 \$PREFIX/bin/openssl pkey -in /tmp/.verify.key -pubout -out /tmp/.verify.pub >/dev/null
rm -f /tmp/.verify.key /tmp/.verify.pub
echo "  native ML-KEM-768 keygen+export verified"
EOF

if [ ! -f "$CACHE_TAR" ] && openssl_works; then
  mkdir -p "$(dirname "$CACHE_TAR")"
  if nx_exec tar -C /opt/pqc-libs -czf /tmp/openssl35.tar.gz openssl35 2>/dev/null \
     && nx_pull /tmp/openssl35.tar.gz "$CACHE_TAR" 2>/dev/null; then
    nx_exec rm -f /tmp/openssl35.tar.gz 2>/dev/null || true
    echo "    cached the built tree -> $CACHE_TAR ($(du -h "$CACHE_TAR" | cut -f1))"
  fi
fi
echo "==> [$VM] done"
