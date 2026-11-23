#!/usr/bin/env bash
# pqc-stacks-all.sh -- Stage 2: the PQC pieces that pqc-all.sh (OpenSSL 3.4 / liboqs / ML-DSA leaf) and extras-all.sh (virtual p2p-pqc-proxy)
# do NOT build, so P2P techs quic-pqc, quic-pqc-mutual, coap-dtls-pqc and coap-dtls-pqc-mutual work on a freshly built tenant. Until now they
# were installed by hand, and a clean build lacked them (found live on T1, 2026-10-02: the Router/Admin sender VM had no aioquic venv, no
# quic identity, no wolfSSL; the physical receiver T1-Rpi53-direct-T1 had no p2p-pqc-proxy and none of the four relays). The P2P tech
# `coap-pqc` (CoAP + ML-KEM-768 wrapped AES-GCM) is the `kem` component below.
#
# What it provisions, per box (every component is checked first, only what is missing is installed; a re-run changes nothing):
#   quic-venv      /opt/pqc-libs/quic-pqc-venv  (PQC-bench/aioquic-patch/install-aioquic-pqc.sh: cryptography>=50 + patched aioquic) and the
#                  aioquic-patch helper files the sender calls (/opt/PQC-bench/aioquic-patch/quic_pqc_client_helper.py)
#   quic-identity  /var/lib/p2p/certs-quic-pqc/{ca.crt,peer.crt,peer.key}: a leaf for the box's P2P name, minted by PQC-bench/ca/quic_pqc_ca.py
#                  issue() on the CA holder with the holder's quic venv, in a 0700 temp dir on the holder, streamed to the box as a tar and
#                  never written to this host; every temp copy of a private key is shred -u. (The `quic_pqc_ca.py issue` CLI is the wrong CA.)
#   wolfssl        /opt/pqc-libs/wolfssl-dtls (PQC-bench/install-wolfssl-dtls.sh: cache first, else a source build on the box) AND the patched
#                  `wolfssl` Python binding + aiocoap_wolfdtls.py in /opt/PQC-bench/wolfssl-py-patch/ (the binding comes from the per-arch cache
#                  $PQC_CACHE_DIR/<arch>/wolfssl-py-pkg.tar.gz, built once with PQC-bench/wolfssl-py-patch/build-wolfssl-py-in-docker.sh;
#                  cffi is added with pip --target when the box's python lacks it) AND the two paths the VIDEO roles use (tb-video-rtp-run /
#                  TenantAPI _WEBRTC_WOLF): /opt/PQC-bench/wolfssl-src/wolfssl-5.9.2.post0 (-> the patched binding dir) must import wolfssl, and
#                  where /opt/pqc-libs/video-venv exists it must import cryptography + wolfssl and create a DTLS 1.3 context (needs cffi/cryptography
#                  in that venv). Both used to be created only as a side effect of the binding install, so a box whose binding was installed
#                  earlier (T1-Rpi53, 2026-10-18) passed this check without them and `tb-video-rtp-run deps-wolf` refused.
#   base-ports     RECEIVERS with an ACTIVE ufw: the P2P receiver's own ports 8442/tcp (http), 8443/tcp (mtls), 8444/tcp (https), 8446/tcp (pqc),
#                  5683/udp (coap*). complete_onboarding.sh opens them (8442 since 2026-10-03); this repairs boxes onboarded before that.
#                  Opened like the other doors (scope of the 8443 rule, else 10.0.0.0/8, tag testbed); an iptables INPUT ACCEPT counts as open.
#   quic-relays    RECEIVERS only: p2p-quic-pqc-relay.service (UDP 4433) + p2p-quic-pqc-mutual-relay.service (UDP 4434), plus the hybrid / classical QUIC relays
#                  (p2p-quic-hybrid[-mutual]-relay UDP 4441/4442, p2p-quic-classical[-mutual]-relay UDP 4443/4444), the canonical unit
#                  files of p2p/receiver-role/, a drop-in override.conf with QUIC_PQC_NODE_NAME/NODE_IP/TENANT, and the relay's CA material
#   dtls-relays    RECEIVERS only: p2p-coap-dtls-pqc-relay.service (UDP 5685) + p2p-coap-dtls-pqc-mutual-relay.service (UDP 5686), plus the plain classical
#                  DTLS relays p2p-coap-dtls[-mutual]-relay (UDP 5687/5688)
#                  Both relay groups: an installed unit file that differs from the repo copy is incomplete too. The repo units are
#                  WantedBy= their receiver (2026-10-03); an older copy is WantedBy=multi-user.target and a lifecycle stop + restart leaves
#                  it dead until the next boot. Updating one is push + `systemctl reenable`, and a relay that is already active is NOT restarted.
#   p2p-pqc-proxy  PHYSICAL receivers only: stunnel :9444 / :9447 (via on-dev-api/deploy/pqc-frontdoor-install-ssh.sh). Virtual boxes get it
#                  from extras-all.sh and are not looked at here.
#   mqtt-frontdoors PHYSICAL gateways only (fleet is_gw): stunnel mqtt-pqc-proxy, the MQTT hybrid-PQC front doors :9445 (mqtt-pqc) / :9448
#                  (mqtt-pqc-mutual) / :9450 (mqtt-hybrid) / :9451 (mqtt-hybrid-mutual) in front of the gateway's plain mosquitto
#                  <GATEWAY_HOST>:1883 (via on-dev-api/deploy/pqc-frontdoor-install-ssh.sh <target> mqtt-broker <GATEWAY_HOST>). <GATEWAY_HOST> is
#                  read from the box's /opt/Gateway-PC/Gateway/.env (the anchor IP a.b.<c+1>.1 when the .env has none). Judged complete when the
#                  unit is enabled+active, all four ports listen, the deployed conf forwards to <GATEWAY_HOST>:1883, and (a port counts as open
#                  with its own ufw ALLOW, the blanket 10.0.0.0/8 one, or an iptables INPUT ACCEPT for it -- :9450/:9451 are opened that way by
#                  Gateway-PC/Gateway/setup-underlay.sh) the firewall lets them in. Virtual gateways get the doors from extras-all.sh and are
#                  not looked at here; the MQTT-over-QUIC relays are the next component.
#   mqtt-quic      PHYSICAL gateways only: the MQTT-over-QUIC relays quic-pqc-mqtt-relay (UDP :4435) + quic-pqc-mqtt-relay-mutual (UDP :4436)
#                  -> <GATEWAY_HOST>:1883 (via on-dev-api/deploy/pqc-frontdoor-install-ssh.sh <target> quic-broker <GATEWAY_HOST>; since
#                  2026-10-03). Complete when both units are enabled+active, both ports listen, the firewall lets them in (as for the MQTT doors),
#                  and the deployed relay unit forwards to <GATEWAY_HOST>: its QUIC_PQC_MQTT_BROKER_HOST, or, when the unit has none (the
#                  hand-installed T1-Protectli2 units), the relay's built-in 10.2.1.1. Needs quic-venv, quic-identity and the CA key (quic-relays).
#   mqtt-quic-client PHYSICAL devices with a fleet `gateway`: quic-pqc-mqtt-client (TCP :9450) + -mutual (:9451), tunnelling to that
#                  gateway's mqtt-quic relays (via pqc-frontdoor-install-ssh.sh <target> quic-client <GW_MQTT_HOST> --server-name <gateway>; since
#                  2026-10-03). Broker = the gateway's OVERLAY IP (fleet ip of the gateway; falls back to the device's GW_MQTT_HOST); server name = the fleet gateway name (= its quic cert
#                  CN). Complete when both units are active, both ports listen, and both client env files point at that broker and name. The
#                  container side (MQTT_QUIC_PQC*_LOCAL_HOST, ufw on the compose bridge) is the installer's; --check does not look at it.
#   kem            the P2P tech `coap-pqc`. It does NOT use the native `cryptography>=50` ML-KEM: p2p/common/coap_crypto.py shells out to a private
#                  OpenSSL 3.5 at /opt/pqc-libs/openssl35 (`openssl pkeyutl -encap` on the sender, `-decap` on the target), so, per box:
#                    every box (router VM and fleet nodes)  openssl35 present and runnable (PQC-bench/install-openssl35.sh: cache first, x86_64
#                                   is cached; aarch64 is NOT, it is COMPILED on the box, ~30+ min on a Pi, and then cached here)
#                    every fleet node  its own ML-KEM-768 keypair /var/lib/p2p/certs-pqc/kem/own.key (0600) + own.pub (0644), dir 0755, minted ON
#                                   THE BOX with its own openssl35 (genpkey + pkey -pubout, = PQC-bench/ca/pqc_kem.py issue_kem()) so the private
#                                   key never travels; an existing own.key is never re-minted (peers hold the old public key). p2p-coap-receiver
#                                   reads own.key ONCE at startup, so it is restarted -- only it, only when own.key was just created, only if it is
#                                   running (a stopped one picks the key up at its next start; a note says so)
#                    the Router/Admin VM  /var/lib/p2p/certs-pqc/kem-peers/<node-name>.pub (dir 0755, files 0644) for EVERY fleet node of the tenant,
#                                   each fetched from the node's own own.pub (PUBLIC keys only; a stale copy that differs from the node's own.pub is
#                                   replaced). The sender looks them up by the receiver's fleet node name (coap_crypto.peer_kem_pub_path).
#                  `--check` names the missing items per box, e.g. `kem: openssl35 absent ...; own.key absent; own.pub absent` for a node or
#                  `kem: kem-peers/<n>.pub (3 missing: a, b, c)` for the router. LIMITATION: a sender that is itself a fleet node (anything but
#                  the tenant Router/Admin VM) gets no kem-peers here; only the Router VM is provisioned as a coap-pqc sender.
# and, on a box whose ufw is active, the ports above are opened to the scope of the box's 8443/tcp rule (else 10.0.0.0/8), as pqc-all.sh does
# for 9443.
#
# Who gets what:
#   the tenant Router/Admin VM (incus `tenant-<t>-router`, P2P name `<T>-Router-PC`)  quic-venv, quic-identity, wolfssl  (a SENDER: no relays)
#   every fleet node, virtual (incus VM `tenant-<t>-<node>`, target form <vm-name>) or physical (target ssh:rmssh@<overlay-ip> with the key
#   rm_ssh/<TENANT>/id_ed25519, the same channel pqc-all.sh uses): everything above. A leaf's IP is the node's overlay IP, for a gateway
#   its anchor IP (a.b.<c+1>.1, e.g. 10.2.1.1 for 10.2.0.10) when the box carries it -- what the working fleet's leaves use.
#
# The CA holder (who owns /var/lib/p2p/certs-quic-pqc/ca.key; the fleet's quic-pqc CA is ONE CA shared by T1 and V1) is not hard-coded:
# --ca-holder <fleet-node-name|local>, else the first of this tenant's gateways that has a ca.key, else THIS host if it has one. Printed
# on the first line. A box never gets the leaf of another box, and the CA key never leaves the holder -- except under --relay-ca-key copy.
#
# Relay CA material (--relay-ca-key stub|copy, default stub). quic_pqc_relay.py calls quic_pqc_ca.issue(/var/lib/p2p/certs-quic-pqc, <name>, ...)
# at every start. issue() loads ca.key unconditionally, and ensure_ca() would silently MINT A NEW CA over ca.crt if ca.key is missing, so a
# relay needs a file named ca.key. `copy` = what the hand-built reference (T1-Protectli1) has: the real CA key on every receiver (0600 here;
# the reference has it 0666). `stub` = a throw-away ML-DSA key under that name: issue() only reads it, finds nodes/<name>.{crt,key} (installed
# from the box's own leaf) and returns them, so the real CA key stays on the holder. Tested locally with the real quic_pqc_ca.py; the
# trade-off is that a relay re-minting for a NEW name would sign with the stub (a leaf nobody trusts), where `copy` would work.
#
# Where: the GUI host (it holds rm_ssh keys, the caches and incus), in src/stage2/. Needs pqc-all.sh first (the toolchain/identity the
# proxy and the DTLS libs rely on) and the p2p role deployed on every receiver (/opt/p2p/receiver-role, p2p-receiver + p2p-coap-receiver).
#
# Usage:
#   ./pqc-stacks-all.sh --tenant T1                  install what is missing
#   ./pqc-stacks-all.sh --tenant T1 --check          read-only: per box, what is missing; exit 1 if anything is
#   ./pqc-stacks-all.sh --tenant T1 --dry-run        like the install, but only PRINTS every command it would run (read-only probes still run)
# Options: --ca-holder <node|local>   --relay-ca-key stub|copy   --only <regex on box name>   --force-low-ram   (PQC_CACHE_DIR in the env)
#   A PHYSICAL box with under 900 MB of available RAM (the 512 MB P1/P2 boards) is REFUSED by the installer (aioquic venv + four relays + wolfSSL need ~120 MB
#   resident and far more to build; install-device-secure-telemetry.sh refuses the same boxes) unless --force-low-ram. --check still reports it.
#   A box whose ONLY gap is `kem` is refused only if openssl35 would have to be compiled (absent and no cache for its arch); minting a key is light.
# Exit: 0 all present (or install done), 1 something missing (--check) / a step failed (install), 2 usage.
# Order inside a box: venv, identity, wolfssl, relays, proxy, mqtt-frontdoors, mqtt-quic, mqtt-quic-client, kem. The Router VM is processed LAST, so the node own.pub files it needs exist by then.
# Check output, per box: `  <name> <ip> <kind>  ok` or `  <name> <ip> <kind>  MISSING: <component>[, ...]` followed by `      - <component>: <why>`
# lines (a box that does not answer is `MISSING: unreachable`), `      note:` lines are informational (a deployed relay source or unit that differs
# from the repo, low RAM) and never fail the check; the last line is `== pqc-stacks-all: OK` or `== pqc-stacks-all: N box(es) incomplete`.
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE" && git rev-parse --show-toplevel)/testbed/"
# Room config (optional): ROUTER_VM / ROLE_VM_PREFIX from ../verify/room.env (or $VL_ROOM_ENV); an exported value wins. Unset = the T1/V1 naming
# (Router `tenant-<t>-router`, role VMs `tenant-<t>-<node>`). ROUTER_VM is one name, so it fits a room with a single Router.
_re="${VL_ROOM_ENV:-$HERE/../verify/room.env}"
if [ -f "$_re" ]; then
  _rv="$( . "$_re" >/dev/null 2>&1; printf '%s|%s' "${ROUTER_VM:-}" "${ROLE_VM_PREFIX:-}" )"
  ROUTER_VM="${ROUTER_VM:-${_rv%%|*}}"; ROLE_VM_PREFIX="${ROLE_VM_PREFIX:-${_rv#*|}}"
fi
_router_vm() { if [ -n "${ROUTER_VM:-}" ]; then printf '%s' "$ROUTER_VM"; else printf 'tenant-%s-router' "$(printf '%s' "$1" | tr 'A-Z' 'a-z')"; fi; }
PQC="$REPO/PQC-bench"
P2PSRC="$REPO/p2p/receiver-role"
DEP="$REPO/on-dev-api/deploy"
KEYS="$REPO/Tenant-Admin-user-PC/Tenant-Admin/rm_ssh"
CACHE="${PQC_CACHE_DIR:-$HOME/.cache/testbed/pqc}"
TENANT="" CHECK=0 DRY=0 HOLDER_ARG="" CAKEY_MODE=stub ONLY="" LOWRAM=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tenant)        TENANT="${2:?--tenant needs a name}"; shift 2 ;;
    --check)         CHECK=1; shift ;;
    --dry-run)       DRY=1; shift ;;
    --ca-holder)     HOLDER_ARG="${2:?--ca-holder needs a fleet node name or 'local'}"; shift 2 ;;
    --relay-ca-key)  CAKEY_MODE="${2:?--relay-ca-key needs stub|copy}"; shift 2 ;;
    --only)          ONLY="${2:?--only needs a regex}"; shift 2 ;;
    --force-low-ram) LOWRAM=1; shift ;;
    -h|--help)       sed -n '2,/^set -Eeuo/{/^set -Eeuo/!p}' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$TENANT" ] || { echo "usage: $0 --tenant <TENANT> [--check|--dry-run] [--ca-holder N] [--relay-ca-key stub|copy] [--only RE]" >&2; exit 2; }
case "$CAKEY_MODE" in stub|copy) ;; *) echo "--relay-ca-key must be stub or copy" >&2; exit 2 ;; esac
# shellcheck source=../../../../PQC-bench/pqc-transport.sh
. "$PQC/pqc-transport.sh"

QV=/opt/pqc-libs/quic-pqc-venv            # the working reference's paths (T1-Protectli1-direct-T1)
QD=/var/lib/p2p/certs-quic-pqc
WL=/opt/pqc-libs/wolfssl-dtls
WP=/opt/PQC-bench/wolfssl-py-patch
WSRC=/opt/PQC-bench/wolfssl-src/wolfssl-5.9.2.post0   # the source-tree layout the video code hardcodes (a symlink to $WP)
VV=/opt/pqc-libs/video-venv
O35=/opt/pqc-libs/openssl35               # coap-pqc: the private OpenSSL 3.5 (p2p/common/coap_crypto.py KEM_OPENSSL), its own ML-KEM-768 key, the sender's cache
KEMD=/var/lib/p2p/certs-pqc/kem; KEMP=/var/lib/p2p/certs-pqc/kem-peers
# The group lists include the hybrid / classical QUIC relays and the plain (classical) DTLS relays, so ALL 21 P2P techs have a door on a receiver
# (T-pash2-IntelNUC 2026-10-16: quic-hybrid*, quic-classical*, coap-dtls* were PeerUnreachable until these six units were installed by hand).
QUIC_UNITS="p2p-quic-pqc-relay p2p-quic-pqc-mutual-relay p2p-quic-hybrid-relay p2p-quic-hybrid-mutual-relay p2p-quic-classical-relay p2p-quic-classical-mutual-relay"
DTLS_UNITS="p2p-coap-dtls-pqc-relay p2p-coap-dtls-pqc-mutual-relay p2p-coap-dtls-relay p2p-coap-dtls-mutual-relay"
PORTS_QUIC="4433/udp 4434/udp 4441/udp 4442/udp 4443/udp 4444/udp"; PORTS_DTLS="5685/udp 5686/udp 5687/udp 5688/udp"; PORTS_PROXY="9444/tcp 9447/tcp"
PORTS_BASE="8442/tcp 8443/tcp 8444/tcp 8446/tcp 5683/udp"   # the P2P receiver itself: http, mtls, https, pqc (ML-KEM-768 + ML-DSA-65 TLS, 2026-10-23), coap*
MQTT_QUIC_CLIENT_UNITS="quic-pqc-mqtt-client quic-pqc-mqtt-client-mutual"   # a device: TCP 9450/9451 -> its gateway UDP 4435/4436
MQTT_QUIC_UNITS="quic-pqc-mqtt-relay quic-pqc-mqtt-relay-mutual"   # MQTT over hybrid-PQC QUIC, UDP 4435/4436 (PQC-bench/aioquic-patch)
MQTT_DOORS="9445 9448 9450 9451"           # mqtt-pqc, mqtt-pqc-mutual, mqtt-hybrid, mqtt-hybrid-mutual (PQC-bench/mqtt-proxy/mqtt-pqc-proxy.conf)
[ -s "$PQC/mqtt-proxy/mqtt-pqc-proxy.conf" ] || { echo "missing repo file $PQC/mqtt-proxy/mqtt-pqc-proxy.conf" >&2; exit 1; }
MQTT_CONN_N="$(grep -c '^connect = 10\.2\.1\.1:1883$' "$PQC/mqtt-proxy/mqtt-pqc-proxy.conf" || true)"   # forwarding sections in the repo conf (4)
for u in $QUIC_UNITS $DTLS_UNITS; do [ -s "$P2PSRC/$u.service" ] || { echo "missing canonical unit $P2PSRC/$u.service" >&2; exit 1; }; done

# ---- the fleet: name tenant ip gw, one per line (same source as pqc-all.sh); the Admin PC's import can fail for a moment while the
# GUI sources are being edited, so it is retried
nodes=""
for _try in 1 2 3; do
  nodes="$(cd "$REPO/Tenant-Admin-user-PC/API" && python3 - "$TENANT" <<'PY' 2>/dev/null
import sys
from tenant_api import TenantAPI
want = sys.argv[1]
def exempt(n):   # classes that legitimately have no registry ip: a deliberate copy of
    # A-Physical-Testbed/role-lifecycle-gui/deploy-role-lifecycle-gui.py _is_exempt (the is_target exemptions)
    nm = n["name"]; low = nm.lower()
    bm = tuple("-%s-pc-" % t for t in ("baremetal", "stm", "nordic", "nxp", "ti", "esp", "arduino"))
    return (nm.endswith("-Admin-PC_node") or "-CONT-" in nm or "-ctr-" in low or n.get("nature") == "container"
            or low in ("esp32-c6", "t-beam", "nano-33-iot") or any(s in low for s in bm))
for n in TenantAPI(as_sysadmin=True).fleet_all()["nodes"]:
    if n.get("tenant") != want:
        continue
    if n.get("ip"):
        print(n["name"], n["tenant"], n["ip"], "gw" if n.get("is_gw") else "-", n.get("gateway") or "-")
    elif exempt(n):   # persona / container / bare-metal row: no ip by design, informational only
        print("!skip", n["name"])
    else:   # a registry node with no ip must not vanish from the run (nor from --check): reported as FAIL below
        print("!noip", n["name"])
PY
)" && [ -n "$nodes" ] && ! grep -q '^!noip ' <<< "$nodes" && break   # a real no-ip row: ips may still be appearing after onboarding -> wait + refetch
  [ "$_try" = 3 ] || sleep "${PQC_FLEET_RETRY_SLEEP:-10}"
done
[ -n "$nodes" ] || { echo "FAIL no nodes in the fleet for tenant $TENANT (TenantAPI.fleet_all)" >&2; exit 1; }
# registry nodes with no ip: never silently skipped (a false-green gate, found 2026-10-03); counted in the exit status
noip="$(grep '^!noip ' <<< "$nodes" | cut -d' ' -f2- || true)"
skipx="$(grep '^!skip ' <<< "$nodes" | cut -d' ' -f2- || true)"
nodes="$(grep -v '^!noip \|^!skip ' <<< "$nodes" || true)"
noip_n=0
while read -r nm; do
  [ -n "$nm" ] || continue
  if [ -n "$ONLY" ] && ! [[ "$nm" =~ $ONLY ]]; then continue; fi
  echo "skip (no ip, exempt class): $nm"
done <<< "$skipx"
while read -r nm; do
  [ -n "$nm" ] || continue
  if [ -n "$ONLY" ] && ! [[ "$nm" =~ $ONLY ]]; then continue; fi
  echo "FAIL no ip in registry: $nm"; noip_n=$((noip_n + 1))
done <<< "$noip"
[ -n "$nodes" ] || { echo "FAIL no nodes with an ip in the fleet for tenant $TENANT" >&2; exit 1; }

INCUS_VMS="$(incus list -c n --format csv 2>/dev/null || true)"
# per box: kind (incus|ssh|sender), target, key, effective ip, role (node|sender), gw
declare -A KIND TGT KEY EIP ROLE GW TEN UPGW   # UPGW = the fleet "gateway" of a device (its MQTT gateway), else -
ORDER=()
add_box() { ORDER+=("$1"); KIND[$1]="$2"; TGT[$1]="$3"; KEY[$1]="$4"; EIP[$1]="$5"; ROLE[$1]="$6"; GW[$1]="$7"; TEN[$1]="$8"; }

# the broker address of a device's MQTT-over-QUIC client: its gateway's OVERLAY IP (fleet ip of UPGW), else the device's GW_MQTT_HOST.
# Why: a gateway relay with an old 0.0.0.0 socket answers a dial of its anchor IP (10.2.1.1) from the overlay IP and the QUIC client drops it (Rpi51 -> Protectli2,
# fixed 2026-10-03 by per-address relays); the overlay IP is safe either way. The check accepts the old GW_MQTT_HOST broker too.
qc_broker() { local g="${UPGW[$1]:--}" ip=""; [ "$g" = - ] || ip="${EIP[$g]:-}"; [ -n "$ip" ] && [ "$ip" != unknown ] || ip="${P[devgw]:-}"; echo "$ip"; }

while read -r name t ip gw upgw; do
  [ -n "$name" ] || continue
  UPGW[$name]="${upgw:--}"
  core="${name#"$t"-}"; core="${core%-"$t"}"; vm="${ROLE_VM_PREFIX:-tenant-${t,,}-}${core,,}"
  if grep -qx "$vm" <<< "$INCUS_VMS"; then add_box "$name" incus "$vm" "" "$ip" node "$gw" "$t"
  else add_box "$name" ssh "ssh:rmssh@$ip" "$KEYS/$t/id_ed25519" "$ip" node "$gw" "$t"; fi
done <<< "$nodes"
# the tenant's Router/Admin VM on this host: the P2P sender; its IP is the first SAN of its classical leaf (as pqc-all.sh)
inst="$(_router_vm "$TENANT")"
if grep -qx "$inst" <<< "$INCUS_VMS"; then
  rip="$(incus exec "$inst" -- openssl x509 -in /var/lib/p2p/certs/peer.crt -noout -ext subjectAltName </dev/null 2>/dev/null \
          | grep -o 'IP Address:[0-9.]*' | head -1 | cut -d: -f2 || true)"
  add_box "$TENANT-Router-PC" incus "$inst" "" "${rip:-unknown}" sender - "$TENANT"
fi
ALLBOXES=("${ORDER[@]}")      # holder candidates ignore --only
if [ -n "$ONLY" ]; then
  keep=(); for b in "${ORDER[@]}"; do [[ "$b" =~ $ONLY ]] && keep+=("$b"); done; ORDER=("${keep[@]}")
fi
[ "${#ORDER[@]}" -gt 0 ] || { echo "FAIL no box matches --only '$ONLY'" >&2; exit 1; }

# ---- transport: one nx_* call against ONE target, in a subshell so targets never leak into each other
nxc() { local t="$1" k="$2"; shift 2; ( NX_KEY="$k"; nx_init "$t"; "$@" ); }
bx() { local b="$1"; shift; nxc "${TGT[$b]}" "${KEY[$b]}" "$@"; }       # bx <box> nx_sh '<script>' | nx_exec argv... | nx_push ...
sha() { sha256sum "$1" | cut -d' ' -f1; }

# ---- the CA holder: where quic-pqc ca.key lives. "local" = this host; else a fleet node name
HOLDER="" HOLDER_HASH=""
CALOCAL="${QUIC_PQC_LOCAL_CA_DIR:-$QD}"      # this host as a CA holder (override only for tests)
holder_has_ca() {   # <holder> -> prints the sha256 of its ca.crt when it has ca.key + ca.crt, else nothing
  local h="$1"
  if [ "$h" = local ]; then
    [ -s "$CALOCAL/ca.key" ] && [ -s "$CALOCAL/ca.crt" ] && sha "$CALOCAL/ca.crt" || true
  else
    [ -n "${TGT[$h]:-}" ] || return 0
    bx "$h" nx_sh "[ -s $QD/ca.key ] && [ -s $QD/ca.crt ] && sha256sum $QD/ca.crt | cut -d' ' -f1" </dev/null 2>/dev/null || true
  fi
}
resolve_holder() {
  local cand h hash
  if [ -n "$HOLDER_ARG" ]; then cand=("$HOLDER_ARG")
  else cand=(); for b in "${ALLBOXES[@]}"; do [ "${ROLE[$b]}" = node ] && [ "${GW[$b]}" = gw ] && cand+=("$b"); done; cand+=(local); fi
  for h in "${cand[@]}"; do
    hash="$(holder_has_ca "$h")"
    if [ -n "$hash" ]; then HOLDER="$h"; HOLDER_HASH="$hash"; return 0; fi
    [ -n "$HOLDER_ARG" ] && break
  done
  return 1
}
holder_run() {      # <script> -> runs it as root on the holder (stdin = the script; stdout = whatever the script prints)
  if [ "$HOLDER" = local ]; then printf '%s\n' "$1" | bash -s; else bx "$HOLDER" nx_sh "$1"; fi
}

# ---- one read-only probe per box: k=v lines, judged ON the box
probe_script() {   # <name> <anchor-ip-or-""> <role node|sender>
  printf "NAME='%s'; ANCHOR='%s'; ROLE='%s'\n" "$1" "$2" "$3"
  cat <<'BODY'
PY=/opt/pqc-libs/quic-pqc-venv/bin/python3
QD=/var/lib/p2p/certs-quic-pqc
WL=/opt/pqc-libs/wolfssl-dtls
WP=/opt/PQC-bench/wolfssl-py-patch
WSRC=/opt/PQC-bench/wolfssl-src/wolfssl-5.9.2.post0
VV=/opt/pqc-libs/video-venv
echo "arch=$(uname -m)"
echo "mem=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null)"
# quic venv: the very test install-aioquic-pqc.sh uses, plus the sender's helper file
if [ -x $PY ] && $PY -c 'from aioquic.tls import Group, SignatureAlgorithm; assert Group.X25519MLKEM768 == 0x11EC; assert SignatureAlgorithm.MLDSA65 == 0x0905; from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem' >/dev/null 2>&1
  then echo venv=ok; else echo venv=missing; fi
[ -s /opt/PQC-bench/aioquic-patch/quic_pqc_client_helper.py ] && echo helper=ok || echo helper=missing
# quic identity: three files, the CN of peer.crt is the box's P2P name
ident=ok
for f in ca.crt peer.crt peer.key; do [ -s $QD/$f ] || ident=files; done
if [ "$ident" = ok ] && [ -x $PY ]; then
  cn="$($PY -c 'import sys; from cryptography import x509; from cryptography.x509.oid import NameOID; print(x509.load_pem_x509_certificate(open(sys.argv[1],"rb").read()).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)' $QD/peer.crt 2>/dev/null)"
  [ "$cn" = "$NAME" ] || ident="cn:${cn:-unreadable}"
fi
echo "ident=$ident"
echo "cahash=$(sha256sum $QD/ca.crt 2>/dev/null | cut -d' ' -f1)"
# relay CA material
[ -s $QD/nodes/$NAME.crt ] && [ -s $QD/nodes/$NAME.key ] && echo relayleaf=ok || echo relayleaf=missing
[ -s $QD/ca.key ] && echo cakey=present || echo cakey=absent
# wolfSSL: the C tree (as install-wolfssl-dtls.sh judges it), the binding, the aiocoap transport file, aiocoap itself
[ -f $WL/lib/libwolfssl.so ] && echo wclib=ok || echo wclib=missing
if LD_LIBRARY_PATH=$WL/lib PYTHONPATH=$WP /usr/bin/python3 -c 'import wolfssl; assert hasattr(wolfssl, "WOLFSSL_X25519MLKEM768")' >/dev/null 2>&1
  then echo wcpy=ok; else echo wcpy=missing; fi
[ -s $WP/aiocoap_wolfdtls.py ] && echo wcfile=ok || echo wcfile=missing
# the video roles' wolfssl-src path and (if the box has a video venv) its DTLS 1.3 import, exactly what `tb-video-rtp-run deps-wolf` runs
if [ -d $WSRC ] && LD_LIBRARY_PATH=$WL/lib PYTHONPATH=$WSRC /usr/bin/python3 -c 'import wolfssl' >/dev/null 2>&1
  then echo wcsrc=ok; else echo wcsrc=missing; fi
if [ -x $VV/bin/python3 ]; then
  if LD_LIBRARY_PATH=$WL/lib PYTHONPATH=$WSRC $VV/bin/python3 -c 'import cryptography, wolfssl; wolfssl.SSLContext(wolfssl.PROTOCOL_DTLSv1_3, server_side=False)' >/dev/null 2>&1
    then echo wcvenv=ok; else echo wcvenv=missing; fi
else echo wcvenv=novenv; fi
/usr/bin/python3 -c 'import aiocoap' >/dev/null 2>&1 && echo aiocoap=ok || echo aiocoap=missing
# receiver prerequisites for the relays
[ -s /opt/p2p/receiver-role/quic_pqc_relay.py ] && [ -s /opt/p2p/receiver-role/coap_dtls_pqc_relay.py ] && echo rolesrc=ok || echo rolesrc=missing
systemctl cat p2p-receiver >/dev/null 2>&1 && systemctl cat p2p-coap-receiver >/dev/null 2>&1 && [ -s /opt/p2p/.env ] && echo recv=ok || echo recv=missing
[ -s /opt/PQC-bench/ca/quic_pqc_ca.py ] && echo casrc=ok || echo casrc=missing
echo "sha.quic_pqc_relay=$(sha256sum /opt/p2p/receiver-role/quic_pqc_relay.py 2>/dev/null | cut -d' ' -f1)"
echo "sha.coap_dtls_pqc_relay=$(sha256sum /opt/p2p/receiver-role/coap_dtls_pqc_relay.py 2>/dev/null | cut -d' ' -f1)"
# units: enabled/active, installed file hash, drop-in
for u in p2p-quic-pqc-relay p2p-quic-pqc-mutual-relay p2p-quic-hybrid-relay p2p-quic-hybrid-mutual-relay p2p-quic-classical-relay p2p-quic-classical-mutual-relay p2p-coap-dtls-pqc-relay p2p-coap-dtls-pqc-mutual-relay p2p-coap-dtls-relay p2p-coap-dtls-mutual-relay p2p-pqc-proxy mqtt-pqc-proxy quic-pqc-mqtt-relay quic-pqc-mqtt-relay-mutual quic-pqc-mqtt-client quic-pqc-mqtt-client-mutual; do
  if [ -f /etc/systemd/system/$u.service ]; then
    echo "unit.$u=$(systemctl is-enabled $u 2>/dev/null)/$(systemctl is-active $u 2>/dev/null)"
    echo "sha.$u=$(sha256sum /etc/systemd/system/$u.service | cut -d' ' -f1)"
  else echo "unit.$u=absent"; fi
done
for u in p2p-quic-pqc-relay p2p-quic-pqc-mutual-relay p2p-quic-hybrid-relay p2p-quic-hybrid-mutual-relay p2p-quic-classical-relay p2p-quic-classical-mutual-relay; do
  f=/etc/systemd/system/$u.service.d/override.conf
  if [ -f $f ] && grep -qx "Environment=QUIC_PQC_NODE_NAME=$NAME" $f; then echo "dropin.$u=ok"; elif [ -f $f ]; then echo "dropin.$u=wrong"; else echo "dropin.$u=absent"; fi
done
# listeners
for p in 4433 4434 4441 4442 4443 4444 5685 5686 5687 5688; do ss -lunH 2>/dev/null | awk '{print $4}' | grep -Eq ":$p\$" && echo "listen.$p=yes" || echo "listen.$p=no"; done
for p in 9444 9447; do ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq ":$p\$" && echo "listen.$p=yes" || echo "listen.$p=no"; done
# firewall: a port counts as open with its own ALLOW rule or the blanket 10.0.0.0/8 one
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  echo ufw=active
  for p in 4433/udp 4434/udp 4441/udp 4442/udp 4443/udp 4444/udp 5685/udp 5686/udp 5687/udp 5688/udp 9444/tcp 9447/tcp 8442/tcp 8443/tcp 8444/tcp 8446/tcp 5683/udp; do
    # open = its own ufw ALLOW, the blanket 10.0.0.0/8 one, or a raw iptables INPUT ACCEPT (a gateway's routes.d/40-underlay-firewall)
    if ufw status | grep -Eq "^$p +ALLOW +[0-9]" || ufw status | grep -Eq '^Anywhere +ALLOW +10\.0\.0\.0/8' \
       || iptables -S INPUT 2>/dev/null | grep -Eq -- "-p ${p#*/} .*--dport ${p%/*} .*-j ACCEPT"; then echo "ufw.$p=ok"; else echo "ufw.$p=closed"; fi
  done
else echo ufw=none; fi
# mqtt front doors (a gateway's mosquitto): the broker address the doors must forward to, the doors, the deployed conf, the firewall
GWH="$(sed -n 's/^GATEWAY_HOST=//p' /opt/Gateway-PC/Gateway/.env 2>/dev/null | head -1 | tr -d '\r"')"
echo "gwhost=$GWH"
[ -n "$GWH" ] && echo "mqttconn=$(grep -c "^connect = $GWH:1883\$" /opt/PQC-bench/mqtt-proxy/mqtt-pqc-proxy.conf 2>/dev/null)" || echo "mqttconn=0"
echo "sha.mqtt-pqc-proxy.conf=$(sha256sum /opt/PQC-bench/mqtt-proxy/mqtt-pqc-proxy.conf 2>/dev/null | cut -d' ' -f1)"
for p in 9445 9448 9450 9451; do
  ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq ":$p\$" && echo "listen.$p=yes" || echo "listen.$p=no"
  if [ "$(ufw status 2>/dev/null | sed -n 's/^Status: //p')" != active ]; then echo "mfw.$p=none"
  elif ufw status | grep -Eq "^$p(/tcp)? +ALLOW +[0-9]" || ufw status | grep -Eq '^Anywhere +ALLOW +10\.0\.0\.0/8' \
       || iptables -S INPUT 2>/dev/null | grep -Eq -- "--dport $p .*-j ACCEPT"; then echo "mfw.$p=ok"; else echo "mfw.$p=closed"; fi
done
# MQTT-over-QUIC relays (a gateway): UDP listeners, firewall, the broker the deployed unit forwards to (unit line, else the relay's default)
for p in 4435 4436; do
  ss -lunH 2>/dev/null | awk '{print $4}' | grep -Eq ":$p\$" && echo "listen.$p=yes" || echo "listen.$p=no"
  if [ "$(ufw status 2>/dev/null | sed -n 's/^Status: //p')" != active ]; then echo "mfw.$p=none"
  elif ufw status | grep -Eq "^$p/udp +ALLOW +[0-9]" || ufw status | grep -Eq '^Anywhere +ALLOW +10\.0\.0\.0/8' \
       || iptables -S INPUT 2>/dev/null | grep -Eq -- "-p udp .*--dport $p .*-j ACCEPT"; then echo "mfw.$p=ok"; else echo "mfw.$p=closed"; fi
done
QB="$(sed -n 's/^Environment=QUIC_PQC_MQTT_BROKER_HOST=//p' /etc/systemd/system/quic-pqc-mqtt-relay.service 2>/dev/null | tail -1)"
echo "qbroker=${QB:-10.2.1.1}"
# MQTT-over-QUIC CLIENT (a device): its gateway broker (device .env), what the deployed client env files point at
echo "devgw=$(sed -n 's/^GW_MQTT_HOST=//p' /opt/testbed-role/.env 2>/dev/null | tail -1 | tr -d '\r"')"
for m in "" -mutual; do
  E=/opt/PQC-bench/aioquic-patch/quic-pqc-mqtt-client$m.env
  echo "qcbroker$m=$(sed -n 's/^QUIC_PQC_MQTT_BROKER_HOST=//p' $E 2>/dev/null | tail -1)"
  echo "qcsni$m=$(sed -n 's/^QUIC_PQC_MQTT_SERVER_NAME=//p' $E 2>/dev/null | tail -1)"
done
# proxy prerequisites (pqc-all.sh)
[ -d /opt/pqc-libs/openssl-priv ] && [ -s /var/lib/p2p/certs-pqc/peer.crt ] && echo pqctool=ok || echo pqctool=missing
# kem (coap-pqc): read-only. genpkey goes to stdout -> /dev/null (nothing is written); the private key is only piped into cmp, never printed
O35=/opt/pqc-libs/openssl35; KD=/var/lib/p2p/certs-pqc/kem; KP=/var/lib/p2p/certs-pqc/kem-peers
o35() { LD_LIBRARY_PATH=$O35/lib64 $O35/bin/openssl "$@"; }
if [ -x $O35/bin/openssl ] && o35 genpkey -algorithm ML-KEM-768 >/dev/null 2>&1; then echo o35=ok; O35OK=1; else echo o35=missing; O35OK=0; fi
[ -s $KD/own.key ] && echo kemkey=ok || echo kemkey=missing
[ -s $KD/own.pub ] && echo kempub=ok || echo kempub=missing
echo "kemmode=$(stat -c %a $KD/own.key 2>/dev/null)/$(stat -c %a $KD/own.pub 2>/dev/null)/$(stat -c %a $KD 2>/dev/null)"
echo "kempubsha=$(sha256sum $KD/own.pub 2>/dev/null | cut -d' ' -f1)"
if [ "$O35OK" = 1 ] && [ -s $KD/own.key ] && [ -s $KD/own.pub ]; then
  if o35 pkey -in $KD/own.key -pubout 2>/dev/null | cmp -s - $KD/own.pub; then echo kemmatch=ok; else echo kemmatch=bad; fi
else echo kemmatch=unknown; fi
echo "kemrecv=$(systemctl is-active p2p-coap-receiver 2>/dev/null)"
if [ "$ROLE" = sender ]; then
  echo "kpdir=$(stat -c %a $KP 2>/dev/null)"
  for f in $KP/*.pub; do [ -s "$f" ] || continue; n="$(basename "$f" .pub)"; echo "kp.$n=$(sha256sum "$f" | cut -d' ' -f1)"; echo "kpm.$n=$(stat -c %a "$f")"; done
fi
# a gateway's anchor IP, if the box carries it
[ -n "$ANCHOR" ] && ip -4 -o addr 2>/dev/null | grep -q " $ANCHOR/" && echo anchor=yes || echo anchor=no
BODY
}

declare -A P            # the parsed probe of the box under evaluation
declare -A NPSHA        # per fleet node: sha256 of its kem/own.pub, `none` (no own.pub) or `unreach`; filled by probe_box, or lazily by node_pubsha
MISS=()                 # components missing on it
DET=()                  # one explanation line per missing component
anchor_of() { local a b c d; IFS=. read -r a b c d <<< "$1"; echo "$a.$b.$((c + 1)).1"; }

probe_box() {   # <box> -> fills P (P[state]=ok|unreachable)
  local b="$1" out anchor="" k v
  [ "${GW[$b]}" = gw ] && anchor="$(anchor_of "${EIP[$b]}")"
  P=()
  NPSHA[$b]=unreach
  if ! out="$(bx "$b" nx_sh "$(probe_script "$b" "$anchor" "${ROLE[$b]}")" </dev/null 2>/dev/null)" || [ -z "$out" ]; then P[state]=unreachable; return 0; fi
  P[state]=ok
  while IFS='=' read -r k v; do [ -n "$k" ] && P[$k]="$v"; done <<< "$out"
  for k in venv helper ident cahash relayleaf cakey wclib wcpy wcfile wcsrc aiocoap rolesrc recv casrc pqctool anchor ufw \
           listen.4433 listen.4434 listen.5685 listen.5686 listen.9444 listen.9447 listen.4435 listen.4436 o35 kemkey kempub kemmatch; do : "${P[$k]:=missing}"; done
  : "${P[wcvenv]:=novenv}"
  NPSHA[$b]="${P[kempubsha]:-none}"; [ -n "${NPSHA[$b]}" ] || NPSHA[$b]=none      # a node's own.pub fingerprint, for the Router's kem-peers
  : "${P[arch]:=?}"
  # the identity IP: a gateway's anchor when the box carries it (what the working fleet's leaves use), else its overlay IP
  if [ "${P[anchor]:-no}" = yes ]; then P[leafip]="$anchor"; else P[leafip]="${EIP[$b]}"; fi
}

add() { MISS+=("$1"); DET+=("$1: $2"); }
unit_ok() { [ "${P[unit.$1]:-absent}" = enabled/active ]; }
unit_stale() { [ "${P[unit.$1]:-absent}" != absent ] && [ "${P[sha.$1]:-}" != "$(sha "$P2PSRC/$1.service")" ]; }   # installed file != repo copy
stale_units() { local u; for u in $1; do unit_stale "$u" && printf '; %s unit file differs from p2p/receiver-role/%s.service (re-run without --check)' "$u" "$u"; done; return 0; }
group_state() {   # <units> <ports> -> prints the reasons the group is not complete (empty = complete)
  local u p r=()
  for u in $1; do unit_ok "$u" || r+=("$u ${P[unit.$u]:-absent}"); done
  for p in $2; do [ "${P[listen.${p%/*}]:-no}" = yes ] || r+=("nothing listens on $p"); done
  if [ "${P[ufw]:-none}" = active ]; then for p in $2; do [ "${P[ufw.$p]:-closed}" = ok ] || r+=("ufw closes $p"); done; fi
  local IFS=';'; echo "${r[*]}" | sed 's/;/; /g'
}

node_pubsha() {   # <node> -> NPS = sha256 of the node's kem/own.pub | none | unreach (cached in NPSHA; call it directly, NOT inside $(...), or the cache is lost)
  local n="$1" out
  if [ -z "${NPSHA[$n]:-}" ]; then
    if out="$(bx "$n" nx_sh "[ -s $KEMD/own.pub ] && sha256sum $KEMD/own.pub | cut -d' ' -f1 || echo none" </dev/null 2>/dev/null)" && [ -n "$out" ]; then NPSHA[$n]="$out"; else NPSHA[$n]=unreach; fi
  fi
  NPS="${NPSHA[$n]}"
}
peer_need() {   # <node> -> PN = ok | missing | stale, for the Router's kem-peers/<node>.pub (stale = differs from the node's own.pub, when that is known)
  local n="$1"
  if [ -z "${P[kp.$n]:-}" ]; then PN=missing; return 0; fi
  node_pubsha "$n"
  if [ "$NPS" = none ] || [ "$NPS" = unreach ] || [ "$NPS" = "${P[kp.$n]}" ]; then PN=ok; else PN=stale; fi
}
join_names() { local IFS=,; echo "$*" | sed 's/,/, /g'; }

eval_box() {   # <box> -> MISS/DET from P
  local b="$1" role="${ROLE[$b]}" r
  MISS=(); DET=()
  if [ "${P[state]}" = unreachable ]; then add unreachable "no answer over ${KIND[$b]} (${TGT[$b]})"; return 0; fi
  # quic venv
  if [ "${P[venv]}" != ok ]; then add quic-venv "no working patched aioquic venv at $QV"
  elif [ "${P[helper]}" != ok ]; then add quic-venv "venv ok but /opt/PQC-bench/aioquic-patch/quic_pqc_client_helper.py is missing"; fi
  # quic identity
  case "${P[ident]}" in
    ok) if [ -n "$HOLDER_HASH" ] && [ "${P[cahash]}" != "$HOLDER_HASH" ]; then
          add quic-identity "ca.crt (${P[cahash]:0:8}) is not the CA holder's (${HOLDER_HASH:0:8}): stale CA"; fi ;;
    files) add quic-identity "ca.crt / peer.crt / peer.key missing in $QD" ;;
    cn:*)  add quic-identity "peer.crt CN is '${P[ident]#cn:}', expected $b" ;;
  esac
  # wolfSSL
  r=()
  [ "${P[wclib]}" = ok ]  || r+=("$WL/lib/libwolfssl.so absent")
  [ "${P[wcpy]}" = ok ]   || r+=("patched wolfssl binding not importable (PYTHONPATH=$WP)")
  [ "${P[wcfile]}" = ok ] || r+=("$WP/aiocoap_wolfdtls.py absent")
  [ "${P[wcsrc]}" = ok ]  || r+=("$WSRC absent or no importable wolfssl there (the video RTP-SRTP / WebRTC roles need it)")
  [ "${P[wcvenv]}" != missing ] || r+=("$VV cannot import cryptography + wolfssl / make a DTLS 1.3 context")
  [ "${#r[@]}" = 0 ] || add wolfssl "$(IFS=';'; echo "${r[*]}" | sed 's/;/; /g')"
  # kem (coap-pqc): openssl35 everywhere; own keypair on a node; kem-peers/<node>.pub for every fleet node on the Router
  r=()
  [ "${P[o35]}" = ok ] || r+=("openssl35 absent or not runnable ($O35/bin/openssl)")
  if [ "$role" = node ]; then
    local mk mp md; IFS=/ read -r mk mp md <<< "${P[kemmode]:-//}"
    [ "${P[kemkey]}" = ok ] || r+=("own.key absent ($KEMD/own.key)")
    [ "${P[kempub]}" = ok ] || r+=("own.pub absent ($KEMD/own.pub)")
    if [ "${P[kemkey]}" = ok ] && [ "${P[kempub]}" = ok ] && [ "${P[kemmatch]}" = bad ]; then r+=("own.pub does not match own.key (or own.key is unreadable)"); fi
    [ "${P[kemkey]}" != ok ] || [ "$mk" = 600 ] || r+=("own.key mode $mk (want 600)")
    [ "${P[kempub]}" != ok ] || [ "$mp" = 644 ] || r+=("own.pub mode $mp (want 644)")
    [ "${P[kemkey]}" != ok ] && [ "${P[kempub]}" != ok ] || [ "$md" = 755 ] || r+=("$KEMD mode $md (want 755)")
  else
    local n miss=() stale=() k
    for n in "${ALLBOXES[@]}"; do
      [ "${ROLE[$n]}" = node ] || continue
      peer_need "$n"
      case "$PN" in missing) miss+=("$n") ;; stale) stale+=("$n") ;; esac
    done
    [ "${#miss[@]}" = 0 ]  || r+=("kem-peers/<n>.pub (${#miss[@]} missing: $(join_names "${miss[@]}"))")
    [ "${#stale[@]}" = 0 ] || r+=("kem-peers/<n>.pub (${#stale[@]} stale, differ from the node's own.pub: $(join_names "${stale[@]}"))")
    [ -z "${P[kpdir]:-}" ] || [ "${P[kpdir]}" = 755 ] || r+=("$KEMP mode ${P[kpdir]} (want 755)")
    for k in "${!P[@]}"; do [[ "$k" == kpm.* ]] && [ "${P[$k]}" != 644 ] && r+=("kem-peers/${k#kpm.}.pub mode ${P[$k]} (want 644)"); done
  fi
  [ "${#r[@]}" = 0 ] || add kem "$(IFS=';'; echo "${r[*]}" | sed 's/;/; /g')"
  [ "$role" = node ] || return 0
  # base P2P ports through an ACTIVE ufw (no ufw = nothing blocks them). Since 2026-10-03 onboarding opens 8442 as well;
  # older boxes (T1-Rpi51) had a per-port list without it, so plain `http` timed out there.
  if [ "${P[ufw]:-none}" = active ]; then
    r=(); for p in $PORTS_BASE; do [ "${P[ufw.$p]:-closed}" = ok ] || r+=("ufw closes $p"); done
    [ "${#r[@]}" = 0 ] || add base-ports "$(IFS=';'; echo "${r[*]}" | sed 's/;/; /g')"
  fi
  # relays: only a receiver can run them
  if [ "${P[rolesrc]}" != ok ] || [ "${P[recv]}" != ok ]; then
    add quic-relays "no p2p receiver-role on the box (/opt/p2p/receiver-role/*relay.py, p2p-receiver + p2p-coap-receiver units, /opt/p2p/.env): deploy the p2p role first"
    add dtls-relays "same: no p2p receiver-role on the box"
  else
    r="$(group_state "$QUIC_UNITS" "$PORTS_QUIC")$(stale_units "$QUIC_UNITS")"; r="${r#; }"
    for u in $QUIC_UNITS; do [ "${P[dropin.$u]:-absent}" = ok ] || r="${r:+$r; }$u drop-in ${P[dropin.$u]:-absent}"; done
    [ -z "$r" ] || { [ "${P[relayleaf]}" = ok ] && [ "${P[cakey]}" = present ] || r="$r; relay CA material (nodes/$b.*, ca.key) absent"; add quic-relays "$r"; }
    r="$(group_state "$DTLS_UNITS" "$PORTS_DTLS")$(stale_units "$DTLS_UNITS")"; r="${r#; }"
    [ -z "$r" ] || add dtls-relays "$r"
  fi
  # the p2p-pqc-proxy: physical receivers only (virtual ones: extras-all.sh)
  if [ "${KIND[$b]}" = ssh ]; then
    if [ "${P[unit.p2p-pqc-proxy]:-absent}" != enabled/active ] || [ "${P[listen.9444]}" != yes ] || [ "${P[listen.9447]}" != yes ] \
       || { [ "${P[ufw]:-none}" = active ] && { [ "${P[ufw.9444/tcp]}" != ok ] || [ "${P[ufw.9447/tcp]}" != ok ]; }; }; then
      r="unit ${P[unit.p2p-pqc-proxy]:-absent}"
      [ "${P[listen.9444]}" = yes ] && [ "${P[listen.9447]}" = yes ] || r="$r; :9444/:9447 not both listening"
      [ "${P[pqctool]}" = ok ] || r="$r; no PQC toolchain/identity yet (run pqc-all.sh first)"
      add p2p-pqc-proxy "$r"
    fi
  fi
  # the MQTT front doors: physical gateways only (virtual ones: extras-all.sh)
  if [ "${KIND[$b]}" = ssh ] && [ "${GW[$b]}" = gw ]; then
    local p mgw="${P[gwhost]:-}"
    [ -n "$mgw" ] || { [ "${P[anchor]:-no}" = yes ] && mgw="${P[leafip]}"; } || true
    r=()
    [ "${P[unit.mqtt-pqc-proxy]:-absent}" = enabled/active ] || r+=("unit ${P[unit.mqtt-pqc-proxy]:-absent}")
    for p in $MQTT_DOORS; do [ "${P[listen.$p]:-no}" = yes ] || r+=("nothing listens on $p"); done
    for p in $MQTT_DOORS; do [ "${P[mfw.$p]:-none}" != closed ] || r+=("ufw closes $p/tcp"); done
    if [ -z "${P[gwhost]:-}" ]; then r+=("no GATEWAY_HOST in /opt/Gateway-PC/Gateway/.env${mgw:+ (anchor $mgw would be used)}")
    elif [ "${P[unit.mqtt-pqc-proxy]:-absent}" != absent ] && [ "${P[mqttconn]:-0}" != "$MQTT_CONN_N" ]; then r+=("deployed conf forwards ${P[mqttconn]:-0} of $MQTT_CONN_N doors to ${P[gwhost]}:1883"); fi
    if [ "${#r[@]}" -gt 0 ]; then
      [ "${P[pqctool]}" = ok ] || r+=("no PQC toolchain/identity yet (run pqc-all.sh first)")
      add mqtt-frontdoors "$(IFS=';'; echo "${r[*]}" | sed 's/;/; /g')"
    fi
    # the MQTT-over-QUIC relays, same gateways
    r=()
    for u in $MQTT_QUIC_UNITS; do unit_ok "$u" || r+=("unit $u ${P[unit.$u]:-absent}"); done
    for p in 4435 4436; do [ "${P[listen.$p]:-no}" = yes ] || r+=("nothing listens on $p/udp"); done
    for p in 4435 4436; do [ "${P[mfw.$p]:-none}" != closed ] || r+=("ufw closes $p/udp"); done
    [ -z "${P[gwhost]:-}" ] || [ "${P[unit.quic-pqc-mqtt-relay]:-absent}" = absent ] || [ "${P[qbroker]:-}" = "${P[gwhost]}" ] \
      || r+=("relay forwards to ${P[qbroker]:-?}:1883, not GATEWAY_HOST ${P[gwhost]}")
    if [ "${#r[@]}" -gt 0 ]; then
      [ -n "$mgw" ] || r+=("no broker address (no GATEWAY_HOST, no anchor)")
      [ "${P[venv]}" = ok ] && [ "${P[ident]}" = ok ] && [ "${P[cakey]}" = present ] || r+=("needs quic-venv + quic-identity + the relay CA key first (quic-relays)")
      add mqtt-quic "$(IFS=';'; echo "${r[*]}" | sed 's/;/; /g')"
    fi
  fi
  # the MQTT-over-QUIC CLIENT: physical devices that have a fleet gateway (virtual ones: on-dev-api/deploy/pqc-frontdoor-install.sh)
  if [ "${KIND[$b]}" = ssh ] && [ "${GW[$b]}" != gw ] && [ "${UPGW[$b]:--}" != - ]; then
    local m g="${UPGW[$b]}"
    r=()
    for u in $MQTT_QUIC_CLIENT_UNITS; do unit_ok "$u" || r+=("unit $u ${P[unit.$u]:-absent}"); done
    for p in 9450 9451; do [ "${P[listen.$p]:-no}" = yes ] || r+=("nothing listens on $p/tcp"); done
    if [ -z "${P[devgw]:-}" ]; then r+=("no GW_MQTT_HOST in /opt/testbed-role/.env")
    else
      for m in "" -mutual; do
        [ "${P[unit.quic-pqc-mqtt-client$m]:-absent}" = absent ] && continue
        [ "${P[qcbroker$m]:-}" = "$(qc_broker "$b")" ] || [ "${P[qcbroker$m]:-}" = "${P[devgw]}" ] || r+=("quic-pqc-mqtt-client$m.env broker ${P[qcbroker$m]:-none}, neither the gateway overlay IP $(qc_broker "$b") nor GW_MQTT_HOST ${P[devgw]}")
        [ "${P[qcsni$m]:-}" = "$g" ] || r+=("quic-pqc-mqtt-client$m.env server name ${P[qcsni$m]:-none}, not the gateway $g")
      done
    fi
    if [ "${#r[@]}" -gt 0 ]; then
      [ "${P[venv]}" = ok ] && [ "${P[ident]}" = ok ] || r+=("needs quic-venv + quic-identity first")
      add mqtt-quic-client "$(IFS=';'; echo "${r[*]}" | sed 's/;/; /g')"
    fi
  fi
}
has_miss() { local m; for m in "${MISS[@]}"; do [ "$m" = "$1" ] && return 0; done; return 1; }

report_box() {   # <box> -> one line + details; returns 1 if incomplete
  local b="$1" list
  if [ "${#MISS[@]}" = 0 ]; then printf '  %-30s %-12s %-7s ok\n' "$b" "${EIP[$b]}" "${KIND[$b]}"; return 0; fi
  list="$(IFS=,; echo "${MISS[*]}" | sed 's/,/, /g')"
  printf '  %-30s %-12s %-7s MISSING: %s\n' "$b" "${EIP[$b]}" "${KIND[$b]}" "$list"
  local d; for d in "${DET[@]}"; do printf '      - %s\n' "$d"; done
  return 1
}
o35_compiles() { [ "${P[o35]}" != ok ] && [ ! -f "$CACHE/${P[arch]}/openssl35.tar.gz" ]; }     # true when install-openssl35.sh would COMPILE on the box
low_ram_refused() {   # <box> (after eval_box): would the installer refuse it? physical, <900 MB, and more than a light `kem` fix to do
  local b="$1" m heavy=0
  [ "${KIND[$b]}" = ssh ] && [ "${#MISS[@]}" -gt 0 ] && [ "${P[mem]:-9999}" -lt 900 ] 2>/dev/null || return 1
  for m in "${MISS[@]}"; do [ "$m" = kem ] || [ "$m" = base-ports ] || heavy=1; done   # opening ports is light too
  o35_compiles && heavy=1
  [ "$heavy" = 1 ]
}
# informational, never fails the check: a deployed relay source that differs from the repo's
notes_box() {
  local b="$1"
  if low_ram_refused "$b"; then
    printf '      note: only %s MB RAM available (<900): the installer refuses this box without --force-low-ram\n' "${P[mem]}"; fi
  has_miss kem && o35_compiles && printf '      note: no cached OpenSSL 3.5 tree for %s (%s/%s/openssl35.tar.gz): the installer COMPILES it on the box (~30+ min on a Pi)\n' "${P[arch]}" "$CACHE" "${P[arch]}"
  [ -z "${P[sha.quic_pqc_relay]:-}" ] || [ "${P[sha.quic_pqc_relay]}" = "$(sha "$P2PSRC/quic_pqc_relay.py")" ] \
    || printf '      note: /opt/p2p/receiver-role/quic_pqc_relay.py differs from the repo copy\n'
  [ -z "${P[sha.coap_dtls_pqc_relay]:-}" ] || [ "${P[sha.coap_dtls_pqc_relay]}" = "$(sha "$P2PSRC/coap_dtls_pqc_relay.py")" ] \
    || printf '      note: /opt/p2p/receiver-role/coap_dtls_pqc_relay.py differs from the repo copy\n'
  if [ -n "${P[gwhost]:-}" ] && [ -n "${P[sha.mqtt-pqc-proxy.conf]:-}" ] \
     && [ "${P[sha.mqtt-pqc-proxy.conf]}" != "$(sed "s/10\.2\.1\.1/${P[gwhost]}/g" "$PQC/mqtt-proxy/mqtt-pqc-proxy.conf" | sha256sum | cut -d' ' -f1)" ]; then
    printf '      note: /opt/PQC-bench/mqtt-proxy/mqtt-pqc-proxy.conf differs from the repo copy (with 10.2.1.1 -> %s)\n' "${P[gwhost]}"; fi
  local u; for u in $QUIC_UNITS $DTLS_UNITS; do
    [ -z "${P[sha.$u]:-}" ] || [ "${P[sha.$u]}" = "$(sha "$P2PSRC/$u.service")" ] || printf '      note: /etc/systemd/system/%s.service differs from p2p/receiver-role/%s.service\n' "$u" "$u"
  done
}

# ---- 1. header: the CA holder
if resolve_holder; then
  echo "== quic-pqc CA holder: $HOLDER (ca.crt sha256 ${HOLDER_HASH:0:16})"
else
  echo "== quic-pqc CA holder: NONE FOUND${HOLDER_ARG:+ (--ca-holder $HOLDER_ARG has no ca.key)}: no gateway of $TENANT and not this host has ca.key; identities cannot be minted (use --ca-holder)"
fi

# ---- 2. --check
if [ "$CHECK" = 1 ]; then
  bad=0
  for b in "${ORDER[@]}"; do
    probe_box "$b"; eval_box "$b"
    report_box "$b" || bad=$((bad + 1))
    [ "${P[state]}" = ok ] && notes_box "$b"
  done
  bad=$((bad + noip_n))
  if [ "$bad" = 0 ]; then echo "== pqc-stacks-all: OK"; exit 0; fi
  echo "== pqc-stacks-all: $bad box(es) incomplete ($noip_n with no ip in registry)"; exit 1
fi

# ---- 3. install (or --dry-run: print every command, run none)
FAIL=$noip_n
show() {   # print what a bx call WOULD run
  local fn="$1"; shift
  if [ "$fn" = nx_sh ]; then printf '%s\n' "$1" | sed 's/^/          | /'; else printf '          %s %s\n' "$fn" "$(printf '%q ' "$@")"; fi
}
do_bx() {   # <box> <why> <nx fn> args...
  local b="$1" why="$2"; shift 2
  if [ "$DRY" = 1 ]; then printf '      [dry-run] %s\n' "$why"; show "$@"; return 0; fi
  bx "$b" "$@" </dev/null
}
do_ext() {  # <why> cmd args... (a repo script that talks to the box itself)
  local why="$1"; shift
  if [ "$DRY" = 1 ]; then printf '      [dry-run] %s\n          %s\n' "$why" "$(printf '%q ' "$@")"; return 0; fi
  "$@"
}
keyargs() { [ -n "${KEY[$1]}" ] && printf -- '--ssh-key\n%s\n' "${KEY[$1]}" || true; }

fix_venv() {   # <box>
  local b="$1"
  do_bx "$b" "mkdir /opt/PQC-bench" nx_exec mkdir -p /opt/PQC-bench || return 1
  do_bx "$b" "push PQC-bench/aioquic-patch/ -> /opt/PQC-bench/aioquic-patch" nx_push_dir "$PQC/aioquic-patch" /opt/PQC-bench || return 1
  do_bx "$b" "build the patched aioquic venv ($QV)" nx_sh "set -e
export DEBIAN_FRONTEND=noninteractive
chown -R root:root /opt/PQC-bench/aioquic-patch
command -v patch >/dev/null || { apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq patch >/dev/null 2>&1; }
bash /opt/PQC-bench/aioquic-patch/install-aioquic-pqc.sh 2>&1 | tail -3" || return 1
}

mint_script() {   # <name> <ip> <tenant> <ca-dir on the holder> -> the script the holder runs; its stdout is ONLY a tar of ca.crt + the leaf
  local name="$1" ip="$2" t="$3" cad="$4"
  cat <<EOS
set -Eeuo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
T=\$(mktemp -d); chmod 700 "\$T"
trap 'find "\$T" -type f -name "*.key" -exec shred -u {} + 2>/dev/null; rm -rf "\$T"' EXIT
cp $cad/ca.key $cad/ca.crt "\$T/"
base64 -d > "\$T/quic_pqc_ca.py" <<'B64'
$(base64 -w0 "$PQC/ca/quic_pqc_ca.py")
B64
cd "\$T"
$QV/bin/python3 -c "import quic_pqc_ca as q; q.issue('.', '$name', '$ip', '$t')" >&2
tar -cf - ca.crt nodes/$name.crt nodes/$name.key
EOS
}

mint_leaf() {   # <box> <ip> -> leaf installed as peer.crt/peer.key + ca.crt on the box (never on this host)
  local b="$1" ip="$2" name="$1" t="${TEN[$1]}" cad="$QD"
  [ "$HOLDER" = local ] && cad="$CALOCAL"
  if [ "$DRY" = 1 ]; then
    printf '      [dry-run] mint %s (%s, tenant %s) on the CA holder %s: temp 0700 dir, copy ca.key+ca.crt, quic_pqc_ca.issue(), tar to stdout, shred -u\n' "$name" "$ip" "$t" "${HOLDER:-?}"
    printf '          | ... | bx %s nx_exec tar -xf - -C %s/.stage      (stream, no file on this host)\n' "$b" "$QD"
    printf '      [dry-run] on the box: install ca.crt (644), peer.crt (644), peer.key (600) into %s; shred -u the staged key\n' "$QD"
    return 0
  fi
  [ -n "$HOLDER" ] || { echo "      no CA holder: cannot mint $name" >&2; return 1; }
  bx "$b" nx_sh "umask 077; mkdir -p $QD; chmod 755 $QD; rm -rf $QD/.stage; mkdir -m 700 $QD/.stage" </dev/null || return 1
  if ! holder_run "$(mint_script "$name" "$ip" "$t" "$cad")" | bx "$b" nx_exec tar -xf - -C "$QD/.stage"; then
    bx "$b" nx_sh "find $QD/.stage -type f -name '*.key' -exec shred -u {} + 2>/dev/null; rm -rf $QD/.stage" </dev/null || true
    echo "      minting/streaming the leaf failed" >&2; return 1
  fi
  bx "$b" nx_sh "set -e; cd $QD
install -m 0644 .stage/ca.crt ca.crt
install -m 0644 .stage/nodes/$name.crt peer.crt
install -m 0600 .stage/nodes/$name.key peer.key
find .stage -type f -name '*.key' -exec shred -u {} + ; rm -rf .stage" </dev/null
}

fix_wolfssl() {   # <box>
  local b="$1" arch pkg
  if [ "${P[wclib]}" != ok ]; then
    # install-wolfssl-dtls.sh: cache first (x86_64 has one), else a SOURCE BUILD on the box (aarch64: no cache yet, many minutes)
    [ -f "$CACHE/${P[arch]}/wolfssl-dtls.tar.gz" ] || echo "      NOTE: no cached wolfSSL tree for ${P[arch]} ($CACHE/${P[arch]}/wolfssl-dtls.tar.gz): it is COMPILED on the box (git clone from github.com, ~10-30 min on a Pi) and then cached here"
    do_ext "wolfSSL C library on $b ($WL)" "$PQC/install-wolfssl-dtls.sh" "${TGT[$b]}" $(keyargs "$b") || return 1
  fi
  if [ "${P[wcpy]}" != ok ] || [ "${P[wcfile]}" != ok ]; then
    arch="${P[arch]}"; pkg="$CACHE/$arch/wolfssl-py-pkg.tar.gz"
    if [ "$DRY" != 1 ] && [ ! -f "$pkg" ]; then
      echo "      no cached wolfssl binding for $arch: $pkg (build it once: PQC-bench/wolfssl-py-patch/build-wolfssl-py-in-docker.sh <ssh-user@ip of a $arch box>)" >&2; return 1; fi
    do_bx "$b" "mkdir $WP, $PQC/wolfssl-py-patch/aiocoap_wolfdtls.py -> $WP" nx_exec mkdir -p "$WP" || return 1
    do_bx "$b" "push aiocoap_wolfdtls.py" nx_push "$PQC/wolfssl-py-patch/aiocoap_wolfdtls.py" "$WP/aiocoap_wolfdtls.py" || return 1
    do_bx "$b" "push the cached patched binding $pkg" nx_push "$pkg" /tmp/wolfssl-py-pkg.tar.gz || return 1
    do_bx "$b" "unpack the binding into $WP, give the box's python a cffi (pip --target), verify the import" nx_sh "set -e
tar -xzf /tmp/wolfssl-py-pkg.tar.gz -C $WP; rm -f /tmp/wolfssl-py-pkg.tar.gz
chown -R root:root $WP
# Two paths the VIDEO code expects (found on T-pash2-IntelNUC 2026-10-16: WebRTC pqc/hybrid and RTP/DTLS-SRTP failed with
# \"No module named wolfssl\"): the API hardcodes the source-tree layout of the original hand-built boxes for the video venv
# (tenant_api _WEBRTC_WOLF / _RTP_SENDER_PY), and the RTP receiver runs the SYSTEM python3, which needs the binding on its path.
mkdir -p /opt/PQC-bench/wolfssl-src; ln -sfn $WP /opt/PQC-bench/wolfssl-src/wolfssl-5.9.2.post0
SPK=\$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_paths()[\"purelib\"])'); echo $WP > \$SPK/wolfssl-patch.pth
export LD_LIBRARY_PATH=$WL/lib PYTHONPATH=$WP
ok() { /usr/bin/python3 -c 'import wolfssl; assert hasattr(wolfssl, \"WOLFSSL_X25519MLKEM768\")' >/dev/null 2>&1; }
if ! ok; then
  export DEBIAN_FRONTEND=noninteractive
  /usr/bin/python3 -m pip --version >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq python3-pip >/dev/null 2>&1; }
  /usr/bin/python3 -m pip install -q --break-system-packages --target $WP cffi >/dev/null 2>&1 || /usr/bin/python3 -m pip install -q --target $WP cffi >/dev/null 2>&1 || true
fi
ok && echo '  wolfssl binding imports (X25519MLKEM768 present)' || { echo '  wolfssl binding does NOT import on this box'; /usr/bin/python3 -c 'import wolfssl' 2>&1 | tail -2; exit 1; }" || return 1
  elif [ "${P[wcsrc]}" != ok ]; then
    # the binding is already there (installed before the video roles needed the source-tree path): only the root-owned link is missing
    do_bx "$b" "link $WSRC -> $WP (root-owned dirs)" nx_sh "set -e; mkdir -p /opt/PQC-bench/wolfssl-src; chown root:root /opt/PQC-bench/wolfssl-src; chmod 755 /opt/PQC-bench/wolfssl-src; ln -sfn $WP $WSRC" || return 1
  fi
  if [ "${P[wcvenv]}" = missing ]; then
    # fixed package names, into the video venv only; a re-run changes nothing once the import works
    do_bx "$b" "pip install cryptography cffi into $VV (the DTLS 1.3 context probe)" nx_sh "$VV/bin/python3 -m pip install -q cryptography cffi" || return 1
  fi
}

relay_ca_material() {   # <box> -> nodes/<name>.{crt,key} from the box's own leaf, and a ca.key (stub|copy) -- see the header
  local b="$1"
  if [ "${P[relayleaf]}" != ok ]; then
    do_bx "$b" "relay leaf: nodes/$b.{crt,key} from the box's own peer.crt/peer.key" nx_sh "set -e; umask 077; mkdir -p $QD/nodes; chmod 755 $QD $QD/nodes
install -m 0644 $QD/peer.crt $QD/nodes/$b.crt; install -m 0600 $QD/peer.key $QD/nodes/$b.key" || return 1
  fi
  [ "${P[cakey]}" = present ] && return 0
  if [ "$CAKEY_MODE" = copy ]; then
    if [ "$DRY" = 1 ]; then
      printf '      [dry-run] ca.key: stream the REAL ca.key from the holder %s into %s/ca.key (0600), no temp file: holder cat | bx %s nx_exec sh -c "umask 077; cat > ..."\n' "${HOLDER:-?}" "$QD" "$b"; return 0; fi
    [ -n "$HOLDER" ] || { echo "      no CA holder to copy ca.key from" >&2; return 1; }
    holder_run "cat $QD/ca.key" | bx "$b" nx_exec sh -c "umask 077; cat > $QD/ca.key; chmod 600 $QD/ca.key" || return 1
  else
    do_bx "$b" "ca.key STUB: a throw-away ML-DSA-65 key (the real CA key stays on the holder; quic_pqc_ca.issue() only reads it here)" nx_sh "set -e; umask 077
$QV/bin/python3 -c \"from cryptography.hazmat.primitives import serialization as s; from cryptography.hazmat.primitives.asymmetric import mldsa; open('$QD/ca.key','wb').write(mldsa.MLDSA65PrivateKey.generate().private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))\"
chmod 600 $QD/ca.key" || return 1
  fi
}

ufw_open() {   # <box> <ports...>
  local b="$1"; shift
  do_bx "$b" "ufw (only if active): open $* to the scope of 8443/tcp, else 10.0.0.0/8" nx_sh '
command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active" || exit 0
SCOPE="$(ufw status | awk "\$1==\"8443/tcp\" && \$2==\"ALLOW\" {print \$3; exit}")"
for p in '"$*"'; do ufw allow from "${SCOPE:-10.0.0.0/8}" to any port "${p%/*}" proto "${p#*/}" comment testbed >/dev/null; done'
}

fix_relays() {   # <box> quic|dtls -- touches only the units that are not already right (a working relay is never restarted)
  local b="$1" which="$2" units ports u todo=() kick=()
  if [ "$which" = quic ]; then units="$QUIC_UNITS"; ports="$PORTS_QUIC"; else units="$DTLS_UNITS"; ports="$PORTS_DTLS"; fi
  for u in $units; do
    if ! unit_ok "$u" || { [ "$which" = quic ] && [ "${P[dropin.$u]:-absent}" != ok ]; }; then todo+=("$u"); kick+=("$u")
    elif unit_stale "$u"; then todo+=("$u"); fi   # running fine, only the file is old: update it, do not restart it
  done
  if [ "$which" = quic ] && [ "${#todo[@]}" -gt 0 ]; then
    do_bx "$b" "mkdir /opt/PQC-bench/ca" nx_exec mkdir -p /opt/PQC-bench/ca || return 1
    do_bx "$b" "push PQC-bench/ca/quic_pqc_ca.py (the relay imports it)" nx_push "$PQC/ca/quic_pqc_ca.py" /opt/PQC-bench/ca/quic_pqc_ca.py || return 1
    relay_ca_material "$b" || return 1
  fi
  for u in "${todo[@]}"; do
    if [ "${P[unit.$u]:-absent}" = absent ] || [ "${P[sha.$u]:-}" != "$(sha "$P2PSRC/$u.service")" ]; then
      do_bx "$b" "unit $u.service <- p2p/receiver-role/$u.service" nx_push "$P2PSRC/$u.service" "/etc/systemd/system/$u.service" || return 1
    fi
    if [ "$which" = quic ]; then
      do_bx "$b" "drop-in $u.service.d/override.conf (QUIC_PQC_NODE_NAME/NODE_IP/TENANT)" nx_sh "set -e
mkdir -p /etc/systemd/system/$u.service.d
printf '[Service]\nEnvironment=QUIC_PQC_NODE_NAME=%s\nEnvironment=QUIC_PQC_NODE_IP=%s\nEnvironment=QUIC_PQC_TENANT=%s\n' '$b' '${P[leafip]}' '${TEN[$b]}' > /etc/systemd/system/$u.service.d/override.conf" || return 1
    fi
  done
  if [ "${#todo[@]}" -gt 0 ]; then
    do_bx "$b" "units: root:root 0644" nx_sh "chown root:root $(for u in "${todo[@]}"; do printf '/etc/systemd/system/%s.service ' "$u"; done); chmod 0644 $(for u in "${todo[@]}"; do printf '/etc/systemd/system/%s.service ' "$u"; done)" || return 1
  fi
  ufw_open "$b" $ports || return 1
  if [ "${#todo[@]}" -gt 0 ]; then
    do_bx "$b" "daemon-reload; reenable ${todo[*]}; restart ${kick[*]:-(none)}" nx_sh "set -e
systemctl daemon-reload
for u in ${todo[*]}; do systemctl reenable \$u >/dev/null 2>&1; done
for u in ${kick[*]}; do systemctl restart \$u; done
sleep 4
for u in ${todo[*]}; do printf '  %-40s %s\n' \$u \"\$(systemctl is-active \$u)\"; done" || return 1
  fi
}

fix_proxy() {   # <box>   (a dry run still runs the child, with --dry-run: it makes no connection)
  local b="$1"
  "$DEP/pqc-frontdoor-install-ssh.sh" "${TGT[$b]}" p2p $(keyargs "$b") $([ "$DRY" = 1 ] && echo --dry-run)
}

fix_mqtt_doors() {   # <box>   (a dry run still runs the child, with --dry-run: it makes no connection)
  local b="$1" gw="${P[gwhost]:-}"
  [ -n "$gw" ] || { [ "${P[anchor]:-no}" = yes ] && gw="${P[leafip]}"; } || true
  [ -n "$gw" ] || { echo "no broker address for $b: no GATEWAY_HOST in /opt/Gateway-PC/Gateway/.env and the box does not carry its anchor IP" >&2; return 1; }
  "$DEP/pqc-frontdoor-install-ssh.sh" "${TGT[$b]}" mqtt-broker "$gw" $(keyargs "$b") $([ "$DRY" = 1 ] && echo --dry-run)
}

fix_mqtt_quic() {   # <box>   (a dry run still runs the child, with --dry-run: it makes no connection)
  local b="$1" gw="${P[gwhost]:-}"
  [ -n "$gw" ] || { [ "${P[anchor]:-no}" = yes ] && gw="${P[leafip]}"; } || true
  [ -n "$gw" ] || { echo "no broker address for $b: no GATEWAY_HOST in /opt/Gateway-PC/Gateway/.env and the box does not carry its anchor IP" >&2; return 1; }
  "$DEP/pqc-frontdoor-install-ssh.sh" "${TGT[$b]}" quic-broker "$gw" $(keyargs "$b") $([ "$DRY" = 1 ] && echo --dry-run)
}

fix_mqtt_quic_client() {   # <box>   (a dry run still runs the child, with --dry-run: it makes no connection)
  local b="$1" gw; gw="$(qc_broker "$b")"
  [ -n "$gw" ] || { echo "no broker address for $b: no GW_MQTT_HOST in /opt/testbed-role/.env" >&2; return 1; }
  "$DEP/pqc-frontdoor-install-ssh.sh" "${TGT[$b]}" quic-client "$gw" --server-name "${UPGW[$b]}" $(keyargs "$b") $([ "$DRY" = 1 ] && echo --dry-run)
}

kem_mint_script() {   # -> the script that runs ON the node: its own ML-KEM-768 keypair, minted with its own openssl35 (the private key never leaves it)
  printf "O35='%s'; KD='%s'\n" "$O35" "$KEMD"
  cat <<'BODY'
set -Eeuo pipefail
export LD_LIBRARY_PATH=$O35/lib64
o35() { "$O35/bin/openssl" "$@"; }
umask 022; mkdir -p "$KD"; chmod 755 "$KD"
umask 077
trap 'shred -u "$KD/.own.key.new" 2>/dev/null || rm -f "$KD/.own.key.new"; rm -f "$KD/.own.pub.new"' EXIT
CREATED=0
if [ ! -s "$KD/own.key" ]; then
  # a NEW keypair: key and pub are written under temp names, checked, then moved into place (key first)
  o35 genpkey -algorithm ML-KEM-768 -out "$KD/.own.key.new"
  o35 pkey -in "$KD/.own.key.new" -pubout -out "$KD/.own.pub.new"
  o35 pkey -pubin -in "$KD/.own.pub.new" -noout
  [ ! -s "$KD/own.pub" ] || echo "  note: an existing own.pub without an own.key is replaced; peers holding the old one must be refreshed (kem-peers)"
  chmod 600 "$KD/.own.key.new"; chmod 644 "$KD/.own.pub.new"
  mv -f "$KD/.own.key.new" "$KD/own.key"; mv -f "$KD/.own.pub.new" "$KD/own.pub"
  CREATED=1; echo "  minted $KD/own.key (0600) + own.pub (0644)"
else
  # an own.key is NEVER re-minted (peers already hold its public half); only a missing/mismatched own.pub is re-derived from it
  o35 pkey -in "$KD/own.key" -noout 2>/dev/null || { echo "  $KD/own.key exists but openssl35 cannot read it: refusing to touch it" >&2; exit 1; }
  if ! { [ -s "$KD/own.pub" ] && o35 pkey -in "$KD/own.key" -pubout 2>/dev/null | cmp -s - "$KD/own.pub"; }; then
    o35 pkey -in "$KD/own.key" -pubout -out "$KD/.own.pub.new"
    o35 pkey -pubin -in "$KD/.own.pub.new" -noout
    chmod 644 "$KD/.own.pub.new"; mv -f "$KD/.own.pub.new" "$KD/own.pub"; echo "  own.pub re-derived from the existing own.key"
  fi
fi
chmod 600 "$KD/own.key"; chmod 644 "$KD/own.pub"
if [ "$CREATED" = 1 ]; then
  # p2p-coap-receiver checks for own.key ONCE at startup: restart only it, only now, only if it runs
  if systemctl is-active --quiet p2p-coap-receiver 2>/dev/null; then
    systemctl restart p2p-coap-receiver; sleep 3; echo "  p2p-coap-receiver restarted: $(systemctl is-active p2p-coap-receiver)"
  else echo "  note: p2p-coap-receiver is not running (or not installed): it loads own.key at its next start"; fi
fi
BODY
}

fix_kem() {   # <box> -- openssl35, then (node) its own keypair or (Router) kem-peers/<node>.pub for every fleet node
  local b="$1" n fail=0 modebad=0 k
  if [ "${P[o35]}" != ok ]; then
    [ -f "$CACHE/${P[arch]}/openssl35.tar.gz" ] || echo "      NOTE: no cached OpenSSL 3.5 tree for ${P[arch]} ($CACHE/${P[arch]}/openssl35.tar.gz): it is COMPILED on the box (wget from github.com + make, ~30+ min on a Pi) and then cached here"
    do_ext "OpenSSL 3.5 (native ML-KEM) on $b ($O35)" "$PQC/install-openssl35.sh" "${TGT[$b]}" $(keyargs "$b") || return 1
  fi
  if [ "${ROLE[$b]}" = node ]; then
    do_bx "$b" "mint (if absent) this node's ML-KEM-768 keypair in $KEMD ON the box, restart p2p-coap-receiver only if own.key was just created" nx_sh "$(kem_mint_script)"
    return
  fi
  # the Router: public keys only, node -> this host's memory -> Router; nothing is written on this host
  [ -n "${P[kpdir]:-}" ] && [ "${P[kpdir]}" != 755 ] && modebad=1
  for k in "${!P[@]}"; do [[ "$k" == kpm.* ]] && [ "${P[$k]}" != 644 ] && modebad=1; done
  for n in "${ALLBOXES[@]}"; do
    [ "${ROLE[$n]}" = node ] || continue
    peer_need "$n"; [ "$PN" = ok ] && continue
    [[ "$n" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "      refusing odd node name '$n'" >&2; fail=1; continue; }
    if [ "$DRY" = 1 ]; then
      printf '      [dry-run] kem-peers/%s.pub (%s): fetch the PUBLIC key of %s (%s) and install it on %s\n' "$n" "$PN" "$n" "$KEMD/own.pub" "$b"
      printf '          bx %s nx_sh "cat %s/own.pub"  |  bx %s nx_exec sh -c "umask 022; mkdir -p %s; cat > .%s.pub.new; openssl35 pkey -pubin -noout; chmod 644; mv -f -> %s/%s.pub"\n' "$n" "$KEMD" "$b" "$KEMP" "$n" "$KEMP" "$n"
      continue
    fi
    local pub
    node_pubsha "$n"
    if [ "$NPS" = none ] || [ "$NPS" = unreach ]; then echo "      kem-peers/$n.pub: node $n has no readable own.pub ($NPS): fix the node first (kem on that box, not excluded by --only)" >&2; fail=1; continue; fi
    pub="$(bx "$n" nx_sh "cat $KEMD/own.pub" </dev/null)" || { echo "      cannot read own.pub from $n" >&2; fail=1; continue; }
    case "$pub" in *"BEGIN PUBLIC KEY"*) ;; *) echo "      $n's own.pub is not a PEM public key: not installed" >&2; fail=1; continue ;; esac
    case "$pub" in *PRIVATE*) echo "      $n's own.pub contains a PRIVATE KEY marker: not installed" >&2; fail=1; continue ;; esac
    if printf '%s\n' "$pub" | bx "$b" nx_exec sh -c "set -e; umask 022; mkdir -p $KEMP; chmod 755 $KEMP; trap 'rm -f $KEMP/.$n.pub.new' EXIT; cat > $KEMP/.$n.pub.new; LD_LIBRARY_PATH=$O35/lib64 $O35/bin/openssl pkey -pubin -in $KEMP/.$n.pub.new -noout; chmod 644 $KEMP/.$n.pub.new; mv -f $KEMP/.$n.pub.new $KEMP/$n.pub"; then
      echo "      kem-peers/$n.pub installed ($PN)"
    else echo "      kem-peers/$n.pub FAILED" >&2; fail=1; fi
  done
  if [ "$modebad" = 1 ]; then do_bx "$b" "kem-peers modes: dir 0755, files 0644" nx_sh "chmod 755 $KEMP; chmod 644 $KEMP/*.pub" || fail=1; fi
  return "$fail"
}

ok=1
step() {   # <label> fn args...: run one install step, indent its output, record a failure in $ok
  local what="$1"; shift
  echo "   -- $what"
  if "$@" 2>&1 | sed 's/^/      /'; [ "${PIPESTATUS[0]}" = 0 ]; then return 0; fi
  echo "   !! $what FAILED"; ok=0; return 1
}
for b in "${ORDER[@]}"; do
  probe_box "$b"; eval_box "$b"
  if [ "${P[state]}" = unreachable ]; then echo "== $b (${EIP[$b]}): FAIL unreachable over ${KIND[$b]}"; FAIL=$((FAIL + 1)); continue; fi
  if [ "${#MISS[@]}" = 0 ]; then echo "== $b (${EIP[$b]}): already complete"; continue; fi
  if low_ram_refused "$b" && [ "$LOWRAM" != 1 ]; then
    echo "== $b (${EIP[$b]}): SKIPPED, only ${P[mem]} MB RAM available (<900); missing: $(IFS=,; echo "${MISS[*]}" | sed 's/,/, /g'); --force-low-ram to install anyway"
    FAIL=$((FAIL + 1)); continue
  fi
  echo "== $b (${EIP[$b]}, ${KIND[$b]}$([ "$DRY" = 1 ] && echo ', dry-run')): installing: $(IFS=,; echo "${MISS[*]}" | sed 's/,/, /g')"
  ok=1
  # order matters: venv -> identity -> wolfssl -> relays (quic needs venv+identity, dtls needs wolfssl) -> proxy -> kem (the Router is last: it needs the nodes' own.pub)
  has_miss base-ports    && { step "base-ports" ufw_open "$b" $PORTS_BASE || true; }
  has_miss quic-venv     && { step "quic-venv" fix_venv "$b" || true; }
  has_miss quic-identity && { if [ "$ok" = 1 ] || [ "${P[venv]}" = ok ]; then step "quic-identity" mint_leaf "$b" "${P[leafip]}" || true; else echo "   -- quic-identity skipped (venv failed)"; fi; }
  has_miss wolfssl       && { step "wolfssl" fix_wolfssl "$b" || true; }
  if has_miss quic-relays; then
    if [ "${P[rolesrc]}" != ok ] || [ "${P[recv]}" != ok ]; then echo "   -- quic-relays: p2p receiver-role not deployed on the box: deploy it first"; ok=0
    else step "quic-relays" fix_relays "$b" quic || true; fi
  fi
  if has_miss dtls-relays; then
    if [ "${P[rolesrc]}" != ok ] || [ "${P[recv]}" != ok ]; then echo "   -- dtls-relays: p2p receiver-role not deployed on the box: deploy it first"; ok=0
    else step "dtls-relays" fix_relays "$b" dtls || true; fi
  fi
  has_miss p2p-pqc-proxy && { step "p2p-pqc-proxy" fix_proxy "$b" || true; }
  has_miss mqtt-frontdoors && { step "mqtt-frontdoors" fix_mqtt_doors "$b" || true; }
  has_miss mqtt-quic     && { step "mqtt-quic" fix_mqtt_quic "$b" || true; }
  has_miss mqtt-quic-client && { if [ "${P[venv]}" = ok ] || has_miss quic-venv; then step "mqtt-quic-client" fix_mqtt_quic_client "$b" || true; fi; }
  has_miss kem           && { step "kem" fix_kem "$b" || true; }
  [ "$DRY" = 1 ] && continue
  # judge the result on the box itself, not on the exit codes above
  probe_box "$b"; eval_box "$b"
  if [ "${#MISS[@]}" = 0 ]; then echo "   => $b: complete"
  else echo "   => $b: STILL MISSING"; for d in "${DET[@]}"; do printf '      - %s\n' "$d"; done; ok=0; fi
  [ "$ok" = 1 ] || FAIL=$((FAIL + 1))
done
if [ "$DRY" = 1 ]; then echo "== pqc-stacks-all: dry run, nothing was changed${FAIL:+ ($FAIL box(es) would be skipped or are unreachable)}" | sed 's/ (0 box(es) would be skipped or are unreachable)//'; [ "$noip_n" = 0 ] || exit 1; exit 0; fi
[ "$FAIL" = 0 ] && echo "== pqc-stacks-all: OK" || { echo "== pqc-stacks-all: $FAIL box(es) FAILED"; exit 1; }
