#!/bin/bash
# Launch/reload the P2P hybrid-TLS front door. Run by p2p-pqc-proxy.service; own process, own
# pidfile, not any distro stunnel service, not in node-agent's bundle. Uses the private OpenSSL 3.4
# build -- system OpenSSL can't serve a provider-native ML-DSA cert, same reasoning as
# ../run-gateway-proxy.sh (see stunnel-pqc.conf's header comment for the full story).
set -euo pipefail
# liboqs-priv MUST come first -- oqsprovider.so has no embedded RPATH; see run-gateway-proxy.sh's
# comment for the ABI-mismatch segfault this order avoids.
export LD_LIBRARY_PATH=/opt/pqc-libs/liboqs-priv/lib:/opt/pqc-libs/openssl-priv/lib64
if [ -f /opt/PQC-bench/oqs-openssl-priv.cnf ]; then
  export OPENSSL_CONF=/opt/PQC-bench/oqs-openssl-priv.cnf
else
  export OPENSSL_CONF=/opt/pqc-libs/oqs-openssl-priv.cnf
fi
cd /opt/PQC-bench/p2p-proxy
mkdir -p run logs
if [ -f run/stunnel-p2p-pqc.pid ] && kill -0 "$(cat run/stunnel-p2p-pqc.pid)" 2>/dev/null; then
  kill "$(cat run/stunnel-p2p-pqc.pid)"
  sleep 1
fi
stunnel p2p-pqc-proxy.conf
