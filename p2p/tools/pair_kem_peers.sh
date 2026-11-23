#!/usr/bin/env bash
# pair_kem_peers.sh -- give two boxes each other's ML-KEM-768 public key, for the `coap-pqc` configuration (2026-10-23, atsanak).
#
#   TESTBED_SSH_PASS=... p2p/tools/pair_kem_peers.sh rpi53@10.2.0.100 rpi50@10.2.1.10      (or key auth + passwordless sudo)
#
# coap-pqc wraps each message key with the RECEIVER's ML-KEM-768 public key, which the sender looks up offline in
# /var/lib/p2p/certs-pqc/kem-peers/<receiver P2P_NODE_NAME>.pub (p2p/common/coap_crypto.py). Nothing else distributes it between
# two fleet nodes (pqc-stacks-all.sh only fills the Router VM's kem-peers/), so after a Raspberry Pi is replaced its new key has
# to be handed to its peers, and theirs to it. Per box: read P2P_NODE_NAME from /opt/p2p/.env; mint kem/own.key + own.pub ON THE
# BOX with /opt/pqc-libs/openssl35 only if it has none (the private key never leaves the box); then install each box's own.pub
# as the other's kem-peers/<name>.pub (0644) and read it back. Re-running changes nothing. p2p_preflight.py checks the result.
set -euo pipefail
A="${1:?usage: $0 user@hostA user@hostB}"; B="${2:?usage: $0 user@hostA user@hostB}"
if [ -n "${TESTBED_SSH_PASS:-}" ]; then
  SSH=(sshpass -p "$TESTBED_SSH_PASS" ssh -o ConnectTimeout=10); SUDO="echo '$TESTBED_SSH_PASS' | sudo -S -p ''"
else
  SSH=(ssh -o ConnectTimeout=10); SUDO="sudo -n"
fi
KEM=/var/lib/p2p/certs-pqc/kem; PEERS=/var/lib/p2p/certs-pqc/kem-peers
O35="LD_LIBRARY_PATH=/opt/pqc-libs/openssl35/lib64 /opt/pqc-libs/openssl35/bin/openssl"

OWN=$(cat <<EOF
set -e
n=\$(grep -E '^(export )?P2P_NODE_NAME=' /opt/p2p/.env | tail -1 | cut -d= -f2- | sed 's/[^A-Za-z0-9._-]//g')
[ -n "\$n" ] || { echo 'no P2P_NODE_NAME in /opt/p2p/.env' >&2; exit 3; }
if [ ! -s $KEM/own.key ] || [ ! -s $KEM/own.pub ]; then
  install -d -m 755 $KEM; umask 077; $O35 genpkey -algorithm ML-KEM-768 -out $KEM/own.key
  $O35 pkey -in $KEM/own.key -pubout -out $KEM/own.pub; chmod 600 $KEM/own.key; chmod 644 $KEM/own.pub
  echo "minted a new ML-KEM-768 keypair for \$n" >&2
fi
echo "\$n \$(base64 -w0 $KEM/own.pub)"
EOF
)
own() {   # box -> prints "<P2P_NODE_NAME> <base64 of own.pub>", minting the keypair on the box if absent
  "${SSH[@]}" "$1" "$SUDO bash -c $(printf %q "$OWN")"
}

give() {  # box name b64 -> installs it as that box's kem-peers/<name>.pub and checks it
  local box="$1" name="$2" b64="$3"
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad node name: $name" >&2; exit 2; }
  [[ "$b64" =~ ^[A-Za-z0-9+/=]+$ ]] || { echo "bad key from the other box" >&2; exit 2; }
  local G="set -e
install -d -m 755 $PEERS; echo $b64 | base64 -d > $PEERS/.$name.pub.tmp
grep -q 'BEGIN PUBLIC KEY' $PEERS/.$name.pub.tmp; chmod 644 $PEERS/.$name.pub.tmp; mv -f $PEERS/.$name.pub.tmp $PEERS/$name.pub
echo \"\$(hostname): kem-peers/$name.pub sha256 \$(sha256sum < $PEERS/$name.pub | cut -c1-16)\""
  "${SSH[@]}" "$box" "$SUDO bash -c $(printf %q "$G")"
}

read -r NA PA < <(own "$A"); read -r NB PB < <(own "$B")
[ "$NA" != "$NB" ] || { echo "both boxes call themselves $NA -- fix /opt/p2p/.env first" >&2; exit 2; }
echo "$A = $NA   own.pub sha256 $(echo "$PA" | base64 -d | sha256sum | cut -c1-16)"
echo "$B = $NB   own.pub sha256 $(echo "$PB" | base64 -d | sha256sum | cut -c1-16)"
give "$B" "$NA" "$PA"; give "$A" "$NB" "$PB"
echo "paired: $NA <-> $NB for coap-pqc"
