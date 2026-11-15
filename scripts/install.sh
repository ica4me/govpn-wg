#!/usr/bin/env bash
# GoVPN (WireGuard Engine) installer for Debian 12/13 and Ubuntu 22.04+.
#
# Run from a checkout of the repository:
#   sudo bash scripts/install.sh                 interactive
#   sudo bash scripts/install.sh --yes \
#        --admin-user admin --admin-password 'change-me-please' \
#        --port 3478 --mtu 1360 --server-lan 10.10.9.0/24 --api 127.0.0.1:8080
#
# Re-running is safe: state, keys and the JWT signing key are kept. Values not
# given keep their previous setting from /etc/govpn/wg.env.
set -euo pipefail
umask 022

PREFIX=/opt/govpn/wg
CONF_DIR=/etc/govpn
CONF=$CONF_DIR/wg.env
DATA=/var/lib/govpn/wg
UNIT=/etc/systemd/system/govpn-wg.service
GO_MIN=1.24
GO_VERSION=${GO_VERSION:-}

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

c_bold=$'\e[1m' c_dim=$'\e[2m' c_red=$'\e[31m' c_grn=$'\e[32m' c_off=$'\e[0m'
[ -t 1 ] || { c_bold='' c_dim='' c_red='' c_grn='' c_off=''; }
log()  { printf '%s==>%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '%s!!%s  %s\n' "$c_red" "$c_off" "$*" >&2; }
die()  { warn "$*"; exit 1; }

usage() {
  cat <<EOF
Usage: sudo bash scripts/install.sh [options]

  --port N               first WireGuard UDP port (default 3478)
  --mtu N                default WireGuard MTU (default 1360)
  --server-lan CIDRS     LAN(s) behind this server, comma separated ("" = none)
  --api ADDR:PORT        REST API listen address (default 127.0.0.1:8080)
  --endpoint HOST        public IP/hostname written into peer configs (default: auto)
  --admin-user NAME      API admin username (default admin)
  --admin-password PW    API admin password (min 8 chars; fresh default: admin)
  --tune | --no-tune     kernel + virtual NIC tuning (default: yes)
  --mss mtu|pmtu         MSS clamp mode (default mtu = MTU-40)
  --yes, -y              non-interactive, accept defaults for anything not given
  --skip-build           use an existing ./bin/govpn-wg instead of compiling
  -h, --help
EOF
}

# ---------------------------------------------------------------- arguments
YES=0 SKIP_BUILD=0
A_PORT='' A_MTU='' A_LAN='__unset__' A_API='' A_ENDPOINT='__unset__' A_USER='' A_PASS='' A_TUNE='' A_MSS=''
while [ $# -gt 0 ]; do
  case "$1" in
    --port) A_PORT=$2; shift ;;
    --mtu) A_MTU=$2; shift ;;
    --server-lan) A_LAN=$2; shift ;;
    --api) A_API=$2; shift ;;
    --endpoint) A_ENDPOINT=$2; shift ;;
    --admin-user) A_USER=$2; shift ;;
    --admin-password) A_PASS=$2; shift ;;
    --tune) A_TUNE=1 ;;
    --no-tune) A_TUNE=0 ;;
    --mss) A_MSS=$2; shift ;;
    -y|--yes) YES=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
  shift
done
[ -t 0 ] || YES=1

[ "$(id -u)" -eq 0 ] || die 'run as root (sudo)'
[ -f "$SRC/go.mod" ] || die "run from a govpn-wg checkout (go.mod not found in $SRC)"
. /etc/os-release
case "${ID:-}:${ID_LIKE:-}" in
  debian:*|ubuntu:*|*:*debian*) ;;
  *) die "Debian or Ubuntu required (found ${PRETTY_NAME:-unknown})" ;;
esac

# Previous values (reinstall keeps them).
declare -A OLD=()
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    [[ $k =~ ^GOVPN_[A-Z_]+$ ]] || continue
    v=${v%\"}; v=${v#\"}; v=${v%\'}; v=${v#\'}
    OLD[$k]=$v
  done < "$CONF"
fi
old() { printf '%s' "${OLD[$1]:-$2}"; }

ask() { # ask VAR "Prompt" default
  local __var=$1 prompt=$2 def=$3 reply
  if [ "$YES" -eq 1 ]; then printf -v "$__var" '%s' "$def"; return; fi
  read -r -p "$prompt ${c_dim}[$def]${c_off}: " reply || true
  printf -v "$__var" '%s' "${reply:-$def}"
}

ask_yn() { # ask_yn VAR "Prompt" 1|0
  local __var=$1 prompt=$2 def=$3 reply hint='Y/n'
  [ "$def" = 1 ] || hint='y/N'
  if [ "$YES" -eq 1 ]; then printf -v "$__var" '%s' "$def"; return; fi
  read -r -p "$prompt [$hint]: " reply || true
  case "${reply,,}" in y|yes) printf -v "$__var" 1 ;; n|no) printf -v "$__var" 0 ;; *) printf -v "$__var" '%s' "$def" ;; esac
}

valid_port() { [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_mtu()  { [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1280 ] && [ "$1" -le 9000 ]; }
valid_cidrs() {
  local IFS=, c
  for c in $1; do
    c=${c// /}
    [ -z "$c" ] && continue
    [[ $c =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]] || return 1
  done
}
valid_listen() { [[ $1 =~ ^([0-9.]+|\[[0-9a-fA-F:]+\]|localhost):[0-9]+$ ]] && valid_port "${1##*:}"; }

# ---------------------------------------------------------------- detection
PUB_IF=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
PUB_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)
DETECTED_LAN=$(ip -4 -o addr show scope global 2>/dev/null | awk -v pub="$PUB_IF" '$2!=pub && $2 !~ /^(wg|docker|br-|veth|virbr|lo)/ {print $4}' |
  while read -r a; do
    ip=${a%/*} bits=${a#*/}
    IFS=. read -r o1 o2 o3 o4 <<<"$ip"
    n=$(( (o1<<24 | o2<<16 | o3<<8 | o4) & (0xFFFFFFFF << (32-bits)) & 0xFFFFFFFF ))
    printf '%d.%d.%d.%d/%d\n' $((n>>24&255)) $((n>>16&255)) $((n>>8&255)) $((n&255)) "$bits"
  done | paste -sd, -)

printf '\n%sGoVPN (WireGuard Engine) installer%s\n' "$c_bold" "$c_off"
printf '%sHost:%s %s  %sPublic:%s %s (%s)  %sOther LANs:%s %s\n\n' "$c_dim" "$c_off" "${PRETTY_NAME}" \
  "$c_dim" "$c_off" "${PUB_IP:-?}" "${PUB_IF:-?}" "$c_dim" "$c_off" "${DETECTED_LAN:-none}"

# ---------------------------------------------------------------- questions
while :; do
  ask PORT 'First WireGuard UDP port' "${A_PORT:-$(old GOVPN_BASE_PORT 3478)}"
  valid_port "$PORT" && break; warn 'port must be 1-65535'; A_PORT=''; [ "$YES" -eq 0 ] || exit 1
done
while :; do
  ask MTU 'Default WireGuard MTU' "${A_MTU:-$(old GOVPN_DEFAULT_MTU 1360)}"
  valid_mtu "$MTU" && break; warn 'MTU must be 1280-9000'; A_MTU=''; [ "$YES" -eq 0 ] || exit 1
done
lan_default=$(old GOVPN_SERVER_LAN "$DETECTED_LAN")
[ "$A_LAN" = '__unset__' ] || lan_default=$A_LAN
while :; do
  ask SERVER_LAN 'Server LAN exposed to sites/clients (comma separated, "none" to skip)' "${lan_default:-none}"
  [ "$SERVER_LAN" = none ] && SERVER_LAN=''
  SERVER_LAN=${SERVER_LAN// /}
  valid_cidrs "$SERVER_LAN" && break; warn 'use IPv4 CIDRs like 10.10.9.0/24'; lan_default=''; [ "$YES" -eq 0 ] || exit 1
done
while :; do
  ask LISTEN 'REST API listen address' "${A_API:-$(old GOVPN_LISTEN 127.0.0.1:8080)}"
  valid_listen "$LISTEN" && break; warn 'use HOST:PORT, e.g. 127.0.0.1:8080'; A_API=''; [ "$YES" -eq 0 ] || exit 1
done
ep_default=$(old GOVPN_ENDPOINT "")
[ "$A_ENDPOINT" = '__unset__' ] || ep_default=$A_ENDPOINT
ask ENDPOINT 'Public endpoint for peer configs ("auto" = detect at runtime)' "${ep_default:-auto}"
[ "$ENDPOINT" = auto ] && ENDPOINT=''
ask ADMIN_USER 'API admin username' "${A_USER:-$(old GOVPN_ADMIN_USER admin)}"
[[ $ADMIN_USER =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || die 'admin username: 1-64 chars of A-Z a-z 0-9 _ . @ -'

HASH=$(old GOVPN_ADMIN_PASSWORD_HASH '')
ADMIN_PASS=$A_PASS
if [ -z "$ADMIN_PASS" ] && [ "$YES" -eq 0 ]; then
  while :; do
    if [ -n "$HASH" ]; then
      read -r -s -p 'API admin password (empty = keep current): ' ADMIN_PASS; echo
      [ -z "$ADMIN_PASS" ] && break
    else
      read -r -s -p 'API admin password (empty = bootstrap default): ' ADMIN_PASS; echo
      [ -z "$ADMIN_PASS" ] && break
    fi
    [ ${#ADMIN_PASS} -ge 8 ] || { warn 'too short'; ADMIN_PASS=''; continue; }
    read -r -s -p 'Repeat password: ' again; echo
    [ "$again" = "$ADMIN_PASS" ] && break
    warn 'passwords differ'; ADMIN_PASS=''
  done
fi
if [ -z "$ADMIN_PASS" ] && [ -z "$HASH" ]; then
  ADMIN_PASS=admin
fi
if [ "$ADMIN_PASS" = admin ]; then
  warn 'Bootstrap default password is active. Change it immediately via POST /api/v1/auth/password.'
else
  [ -z "$ADMIN_PASS" ] || [ ${#ADMIN_PASS} -ge 8 ] || die 'admin password must be at least 8 characters'
fi

tune_default=${A_TUNE:-$(old GOVPN_TUNE_ON_START 1)}
ask_yn TUNE 'Run kernel + virtual NIC tuning (sysctl, BBR, ethtool) now and at every start?' "$tune_default"
MSS=${A_MSS:-$(old GOVPN_MSS_MODE mtu)}
[[ $MSS =~ ^(mtu|pmtu)$ ]] || die '--mss must be mtu or pmtu'

# ---------------------------------------------------------------- packages
log 'installing packages'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl iproute2 iptables ethtool kmod \
  wireguard-tools tar >/dev/null
modprobe wireguard || die 'kernel module wireguard is not available (Linux >= 5.6 required)'

# ---------------------------------------------------------------- build
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }
find_go() {
  for g in "$(command -v go 2>/dev/null)" /usr/local/go/bin/go; do
    [ -x "$g" ] || continue
    v=$("$g" env GOVERSION 2>/dev/null | sed 's/^go//')
    version_ge "$v" "$GO_MIN" && { echo "$g"; return; }
  done
}

if [ "$SKIP_BUILD" -eq 1 ]; then
  [ -x "$SRC/bin/govpn-wg" ] || die "--skip-build but $SRC/bin/govpn-wg is missing"
else
  GO=$(find_go || true)
  if [ -z "$GO" ]; then
    arch=$(dpkg --print-architecture)
    case "$arch" in amd64|arm64) ;; armhf) arch=armv6l ;; *) die "no Go toolchain for $arch" ;; esac
    [ -n "$GO_VERSION" ] || GO_VERSION=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -n1)
    log "installing $GO_VERSION to /usr/local/go"
    tmp=$(mktemp -d)
    curl -fsSL -o "$tmp/go.tgz" "https://go.dev/dl/$GO_VERSION.linux-$arch.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp/go.tgz"
    rm -rf "$tmp"
    GO=/usr/local/go/bin/go
  fi
  log "compiling with $($GO version | awk '{print $3}')"
  VERSION=$(git -C "$SRC" describe --tags --always --dirty 2>/dev/null || echo dev)
  (cd "$SRC" && CGO_ENABLED=0 GOFLAGS=-mod=readonly "$GO" build -trimpath \
     -ldflags "-s -w -X github.com/ica4me/govpn-wg/internal/api.Version=$VERSION" \
     -o bin/govpn-wg ./cmd/govpn-wg)
fi

install -d -m 755 "$PREFIX"
install -d -m 700 "$CONF_DIR" "$DATA"
install -m 755 "$SRC/bin/govpn-wg" "$PREFIX/govpn-wg.new"
mv -f "$PREFIX/govpn-wg.new" "$PREFIX/govpn-wg"
install -m 755 "$SRC/scripts/uninstall.sh" "$PREFIX/uninstall.sh"
ln -sf "$PREFIX/govpn-wg" /usr/local/bin/govpn-wg

if [ -n "$ADMIN_PASS" ]; then
  HASH=$(printf '%s\n' "$ADMIN_PASS" | "$PREFIX/govpn-wg" hash-initial-password)
fi

# ---------------------------------------------------------------- config
log "writing $CONF"
tmp=$(mktemp "$CONF_DIR/.wg.env.XXXXXX")
cat > "$tmp" <<EOF
# GoVPN (WireGuard Engine) - generated by scripts/install.sh on $(date -u +%FT%TZ)
# Edit, then: systemctl restart govpn-wg

GOVPN_LISTEN=$LISTEN
GOVPN_DATA_DIR=$DATA
GOVPN_LOG_LEVEL=$(old GOVPN_LOG_LEVEL info)

GOVPN_ADMIN_USER=$ADMIN_USER
GOVPN_ADMIN_PASSWORD_HASH='$HASH'
GOVPN_TOKEN_TTL=$(old GOVPN_TOKEN_TTL 12h)

# Empty = detected at runtime from the default route.
GOVPN_ENDPOINT=$ENDPOINT
GOVPN_PUBLIC_IF=$(old GOVPN_PUBLIC_IF '')

GOVPN_BASE_PORT=$PORT
GOVPN_DEFAULT_MTU=$MTU
GOVPN_DNS=$(old GOVPN_DNS 1.1.1.1)
GOVPN_KEEPALIVE=$(old GOVPN_KEEPALIVE 25)

# Networks behind this server that sites/clients can be granted.
GOVPN_SERVER_LAN=$SERVER_LAN
# Masquerade tunnel traffic into the server LAN (no return route needed).
GOVPN_LAN_NAT=$(old GOVPN_LAN_NAT 1)

# mtu = clamp TCP MSS to MTU-40, pmtu = --clamp-mss-to-pmtu
GOVPN_MSS_MODE=$MSS

GOVPN_TUNE_ON_START=$TUNE
GOVPN_TUNE_NIC=$(old GOVPN_TUNE_NIC 1)
GOVPN_NIC_RING=$(old GOVPN_NIC_RING max)
# Extra sysctl, e.g. "net.core.rmem_max=67108864;net.core.wmem_max=67108864"
GOVPN_SYSCTL_EXTRA=$(old GOVPN_SYSCTL_EXTRA '')
EOF
chmod 600 "$tmp"
mv -f "$tmp" "$CONF"

# ---------------------------------------------------------------- systemd
log "installing $UNIT"
cat > "$UNIT" <<EOF
[Unit]
Description=GoVPN (WireGuard Engine)
Documentation=https://github.com/ica4me/govpn-wg
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/sbin/modprobe wireguard
ExecStart=$PREFIX/govpn-wg serve -config $CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
UMask=0077
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$DATA /etc/sysctl.d /etc/modules-load.d /run
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE CAP_SYS_ADMIN CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

if [ "$TUNE" = 1 ]; then
  log 'kernel + NIC tuning'
  "$PREFIX/govpn-wg" tune -config "$CONF" > "$DATA/tune-report.json" || warn 'tuning reported errors, see tune-report.json'
  python3 - "$DATA/tune-report.json" <<'PY' 2>/dev/null || true
import json,sys,collections
r=json.load(open(sys.argv[1]))
c=collections.Counter(s['status'] for k in ('sysctl','modules','nic') for s in (r.get(k) or []))
print('    public_if=%s applied=%d unchanged=%d unsupported=%d failed=%d'%(r.get('public_if'),c['applied'],c['unchanged'],c['unsupported'],c['failed']))
PY
fi

systemctl daemon-reload
systemctl enable govpn-wg.service >/dev/null 2>&1
systemctl restart govpn-wg.service

api_url="http://$LISTEN"
for _ in $(seq 1 30); do
  curl -fsS "$api_url/api/v1/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$api_url/api/v1/health" >/dev/null 2>&1 || { journalctl -u govpn-wg -n 30 --no-pager; die 'API did not come up'; }

printf '\n%sGoVPN is running.%s\n' "$c_bold" "$c_off"
printf '  API        %s\n' "$api_url"
printf '  Config     %s\n' "$CONF"
printf '  State      %s\n' "$DATA"
printf '  Admin      %s\n' "$ADMIN_USER"
printf '  Open UDP   %s and up on the provider firewall\n\n' "$PORT"
printf 'Try:\n  TOKEN=$(curl -s %s/api/v1/auth/login -d %s | sed -n %s)\n' \
  "$api_url" "'{\"username\":\"$ADMIN_USER\",\"password\":\"...\"}'" "'s/.*\"access_token\": *\"\\([^\"]*\\)\".*/\\1/p'"
printf '  curl -s -H "Authorization: Bearer $TOKEN" %s/api/v1/system/status\n' "$api_url"
