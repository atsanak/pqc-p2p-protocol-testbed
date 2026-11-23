#!/usr/bin/env bash
# deploy_p2p_box.sh -- ship the WHOLE P2P / post-quantum transport layer of this repo to one box, then prove it (2026-10-23, atsanak).
#
#   TESTBED_SSH_PASS=... p2p/tools/deploy_p2p_box.sh rpi50@10.2.1.10          (or key auth + passwordless sudo: no env needed)
#
# Why a new script: on-dev-api/deploy/p2p-rollout-ssh.sh ships a fixed list of 9 files -- not common/identity.py, the handlers,
# the aioquic / wolfSSL layers or the CA modules -- so a fresh box deployed with it runs a MIX of old and new code. This ships
# every file the 13 HTTP/CoAP configurations execute:
#   p2p/{common,sender-role,receiver-role,receiver-role/handlers,tools}/*  -> /opt/p2p/...
#   PQC-bench/aioquic-patch/*.py + tls.py.patch, PQC-bench/wolfssl-py-patch/aiocoap_wolfdtls.py, PQC-bench/ca/{pqc_ca,quic_pqc_ca,pqc_kem}.py
#                                                                          -> /opt/PQC-bench/...
# Steps: stage in /tmp on the box -> compile + import check there (nothing touched yet) -> back up every file it replaces ->
# install -> apply add_mlkem768.py to the quic venv's aioquic -> write /opt/p2p/MANIFEST.json (sha256 of every shipped file;
# p2p_preflight.py checks it, so later drift shows up as NOT READY) -> restart the P2P units -> run p2p_preflight.py.
# A failed compile/import rolls back. Identities (certificates) are NOT shipped here: p2p/tools/provision_identity.py.
set -euo pipefail
BOX="${1:?usage: $0 user@host}"
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"; STG="/tmp/p2p-deploy-$STAMP"
if [ -n "${TESTBED_SSH_PASS:-}" ]; then
  SSH=(sshpass -p "$TESTBED_SSH_PASS" ssh -o ConnectTimeout=10); SCP=(sshpass -p "$TESTBED_SSH_PASS" scp -q)
  SUDO="echo '$TESTBED_SSH_PASS' | sudo -S -p ''"
else
  SSH=(ssh -o ConnectTimeout=10); SCP=(scp -q); SUDO="sudo -n"
fi
cd "$ROOT"
mapfile -t FILES < <( { git ls-files 'p2p/common/*.py' 'p2p/sender-role/*.py' 'p2p/receiver-role/*.py' 'p2p/receiver-role/handlers/*.py' \
                         'p2p/tools/*.py' 'p2p/tools/*.sh' 'PQC-bench/aioquic-patch/*.py' 'PQC-bench/aioquic-patch/tls.py.patch' \
                         'PQC-bench/wolfssl-py-patch/aiocoap_wolfdtls.py' 'PQC-bench/ca/pqc_ca.py' 'PQC-bench/ca/quic_pqc_ca.py' \
                         'PQC-bench/ca/pqc_kem.py' 'A-Physical-Testbed/Tenant-Admin-PC/node-scripts/tb-p2p-cli.sh' \
                         'A-Physical-Testbed/Tenant-Admin-PC/node-scripts/tb-p2p-preflight.sh';
                         git ls-files --others --exclude-standard 'p2p/tools/*.py' 'p2p/tools/*.sh' \
                         'A-Physical-Testbed/Tenant-Admin-PC/node-scripts/tb-p2p-preflight.sh'; } | sort -u)
[ "${#FILES[@]}" -gt 20 ] || { echo "only ${#FILES[@]} files found -- run from the repo"; exit 1; }
echo "== $BOX: shipping ${#FILES[@]} files"
python3 - "${FILES[@]}" > /tmp/p2p-manifest-$STAMP.json <<'PY'
import hashlib, json, sys
print(json.dumps({("p2p/" + f[4:] if f.startswith("p2p/") else f): hashlib.sha256(open(f, "rb").read()).hexdigest() for f in sys.argv[1:]
                  if "/node-scripts/" not in f}, indent=0))       # (node-scripts land in /usr/local/lib/tb/scripts, not under /opt)
PY
tar -cf /tmp/p2p-deploy-$STAMP.tar "${FILES[@]}"
"${SCP[@]}" /tmp/p2p-deploy-$STAMP.tar /tmp/p2p-manifest-$STAMP.json "$BOX:/tmp/"
rm -f /tmp/p2p-deploy-$STAMP.tar
REMOTE=$(cat <<EOF
set -e
mkdir -p $STG && tar -xf /tmp/p2p-deploy-$STAMP.tar -C $STG && rm -f /tmp/p2p-deploy-$STAMP.tar
cd $STG/p2p/receiver-role && python3 -B -c 'import sys; sys.path[:0]=[".",".."]; import server, coap_server'
cd $STG/p2p/sender-role && python3 -B -c 'import sys; sys.path[:0]=[".",".."]; import client, cli'
cd $STG && python3 -B -m py_compile \$(find . -name '*.py') && echo "staged code compiles and imports"
BK=/var/backups/p2p-deploy-$STAMP; mkdir -p \$BK
cd $STG
for f in \$(find . -type f | sed 's|^\./||'); do
  case "\$f" in
    A-Physical-Testbed/*/node-scripts/*)   # the tbctl workers TenantAPI / DeviceAPI call (tb-p2p-cli, tb-p2p-preflight): only where tbctl is
      [ -d /etc/tbctl/scripts.d ] || continue
      n=\$(basename "\$f" .sh); dst=/usr/local/lib/tb/scripts/\$n.sh
      if [ -f "\$dst" ]; then mkdir -p "\$BK/node-scripts"; cp -p "\$dst" "\$BK/node-scripts/"; fi
      install -o root -g root -m 755 "\$f" "\$dst"; ln -sfn "\$dst" /etc/tbctl/scripts.d/\$n; continue ;;
    p2p/*) dst="/opt/p2p/\${f#p2p/}";; *) dst="/opt/\$f";; esac
  if [ -f "\$dst" ]; then mkdir -p "\$BK/\$(dirname "\$f")"; cp -p "\$dst" "\$BK/\$f"; fi
  install -D -m 644 "\$f" "\$dst"
done
chmod 755 /opt/p2p/tools/*.sh /opt/p2p/tools/*.py 2>/dev/null || true
install -m 644 /tmp/p2p-manifest-$STAMP.json /opt/p2p/MANIFEST.json; rm -f /tmp/p2p-manifest-$STAMP.json
TLS=\$(ls /opt/pqc-libs/quic-pqc-venv/lib/python3*/site-packages/aioquic/tls.py 2>/dev/null | head -1)
[ -n "\$TLS" ] && /opt/pqc-libs/quic-pqc-venv/bin/python3 /opt/PQC-bench/aioquic-patch/add_mlkem768.py "\$TLS" || echo "WARN: no quic venv (install it: PQC-bench/aioquic-patch/install-aioquic-pqc.sh)"
for u in \$(systemctl list-units --all --no-legend 'p2p-*' | awk '{print \$1}' | grep -v p2p-pqc-proxy); do systemctl restart "\$u" || true; done
sleep 5
echo "backup of replaced files: \$BK"
rm -rf $STG
python3 /opt/p2p/tools/p2p_preflight.py --manifest /opt/p2p/MANIFEST.json || true
EOF
)
"${SSH[@]}" "$BOX" "$SUDO bash -c $(printf %q "$REMOTE")"
rm -f /tmp/p2p-manifest-$STAMP.json
