#!/usr/bin/env bash
# build-wolfssl-py-in-docker.sh — build the PATCHED wolfssl python binding (wolfSSL statically linked, stable-ABI _ffi.abi3.so) for the CPU
# architecture of one box, INSIDE python:3.11-slim (the device image's base, so the .so is built against the glibc the container runs it
# on), and store it in the local package cache that PQC-bench/telemetry-coap/install-device-wolfssl-dtls.sh installs from.
#
#   build-wolfssl-py-in-docker.sh <ssh-user@ip> [--ssh-key PATH]        e.g.  rmssh@10.2.0.100  (an aarch64 box)
#   -> ~/.cache/testbed/pqc/<arch>/wolfssl-py-pkg.tar.gz   (PQC_CACHE_DIR overrides the base)
#
# Takes ~10 min on a Raspberry Pi 5 (wolfSSL compiles inside pip). Needs docker + internet on that box. Nothing on the box is installed:
# everything happens in a throwaway container and in /tmp/wbuild (removed at the end).
# Patches applied to wolfssl==5.9.2.post0: key-share-group.patch (wolfSSL_UseKeyShare -> the X25519MLKEM768 hybrid group) and srtp.patch,
# plus --disable-armasm (Pi 4 has no SHA-3 instructions: SIGILL in the handshake otherwise) and -fPIC added to the sdist's own wolfSSL configure flags: it links a NON-PIC libwolfssl.a into a shared module, which x86 tolerates
# and aarch64 refuses ("dangerous relocation: unsupported relocation R_AARCH64_ADR_PREL_PG_HI21").
set -uo pipefail
TARGET=${1:?usage: build-wolfssl-py-in-docker.sh <ssh-user@ip> [--ssh-key PATH]}; shift
KEY="${RM_KEY:-}"
while [ $# -gt 0 ]; do case "$1" in --ssh-key) KEY="${2:?}"; shift 2 ;; *) echo "unknown argument $1" >&2; exit 2 ;; esac; done
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE="${PQC_CACHE_DIR:-$HOME/.cache/testbed/pqc}"
SSHO=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
[ -n "$KEY" ] && SSHO+=(-i "$KEY" -o IdentitiesOnly=yes)
box()  { ssh -n "${SSHO[@]}" "$TARGET" "$@"; }
boxi() { ssh "${SSHO[@]}" "$TARGET" "$@"; }
ARCH=$(box 'uname -m') || exit 1
echo "==> [$TARGET] building for $ARCH"
box 'sudo rm -rf /tmp/wbuild && sudo mkdir -p /tmp/wbuild/patches /tmp/wbuild/out'
for f in key-share-group.patch srtp.patch; do boxi "sudo tee /tmp/wbuild/patches/$f >/dev/null" < "$HERE/$f"; done
boxi 'sudo tee /tmp/wbuild/build.sh >/dev/null' <<'EOF'
#!/bin/bash
exec > /tmp/wbuild/build.log 2>&1
set -x
docker run --rm -v /tmp/wbuild:/w python:3.11-slim bash -c '
set -ex
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential autoconf automake libtool patch pkg-config git >/dev/null
pip install -q cffi cryptography setuptools wheel
mkdir /src && cd /src
pip download -q --no-deps --no-binary :all: wolfssl==5.9.2.post0
tar xzf wolfssl-*.tar.gz && cd wolfssl-*/
patch -p1 < /w/patches/key-share-group.patch
patch -p1 < /w/patches/srtp.patch
sed -i "s/cflags.append(\"-DKEEP_PEER_CERT\")/cflags.append(\"-DKEEP_PEER_CERT\"); cflags.append(\"-fPIC\")/" wolfssl/_build_ffi.py
# aarch64: the ARM assembly in wolfSSL (the ML-KEM code uses SHA-3 instructions) raises SIGILL inside the handshake on a Raspberry Pi 4 (Cortex-A72,
# no SHA-3 or crypto extensions) while a Pi 5 runs it fine. Portable C runs on both. Exit 132 in do_handshake, found live on T1-Rpi54.
sed -i "s/flags.append(\"--disable-examples\")/flags.append(\"--disable-examples\"); flags.append(\"--disable-armasm\")/" wolfssl/_build_ffi.py
grep -n "disable-armasm" wolfssl/_build_ffi.py
pip install --no-deps --no-build-isolation --target /w/out/site .
python - <<PY
import sys; sys.path.insert(0, "/w/out/site")
import wolfssl
print("IMPORT-RESULT OK", hasattr(wolfssl, "WOLFSSL_X25519MLKEM768"))
PY
'
echo BUILD_EXIT=$?
EOF
box 'sudo chmod +x /tmp/wbuild/build.sh; sudo nohup /tmp/wbuild/build.sh >/dev/null 2>&1 &'
echo "==> build running on the box (log /tmp/wbuild/build.log); waiting ..."
for i in $(seq 1 180); do
  box 'sudo grep -q "^BUILD_EXIT=" /tmp/wbuild/build.log 2>/dev/null' && break
  sleep 10
done
RES=$(box 'sudo grep -E "^BUILD_EXIT=|^IMPORT-RESULT" /tmp/wbuild/build.log | tr "\n" " "')
echo "==> $RES"
case "$RES" in *"BUILD_EXIT=0"*"IMPORT-RESULT OK True"*|*"IMPORT-RESULT OK True"*"BUILD_EXIT=0"*) ;; *) echo "build failed: box:/tmp/wbuild/build.log" >&2; exit 1 ;; esac
mkdir -p "$CACHE/$ARCH"
box 'sudo tar -C /tmp/wbuild/out/site -czf - wolfssl' > "$CACHE/$ARCH/wolfssl-py-pkg.tar.gz"
echo "==> stored $CACHE/$ARCH/wolfssl-py-pkg.tar.gz ($(du -h "$CACHE/$ARCH/wolfssl-py-pkg.tar.gz" | cut -f1))"
box 'sudo rm -rf /tmp/wbuild'
