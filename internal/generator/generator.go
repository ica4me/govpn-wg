// Package generator renders the artifacts handed to site gateways and
// clients: wg-quick configs and self-contained Debian/Ubuntu setup scripts.
//
// Every interpolated value comes from validated state (base64 keys, CIDRs,
// IP addresses, interface-safe names), so the output is safe inside
// single-quoted shell strings and wg-quick INI files.
package generator

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"text/template"
)

// Peer is everything a remote side needs to configure its tunnel.
type Peer struct {
	Kind       string // "site" or "client"
	Name       string // display name
	FileName   string // safe file stem
	Address    string // tunnel address with prefix, e.g. 172.31.214.2/24
	PrivateKey string
	ServerKey  string // hub public key
	PSK        string
	Endpoint   string // host:port
	AllowedIPs []string
	DNS        []string
	MTU        int
	Keepalive  int
	TunnelMode string
	LocalLANs  []string // site only: LANs behind the site gateway
	Iface      string   // wg-quick name on the remote side
}

var fileRe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// SafeFileName strips anything that would be awkward in a download name.
func SafeFileName(s string) string {
	s = strings.Trim(fileRe.ReplaceAllString(s, "-"), "-.")
	if s == "" {
		return "peer"
	}
	return s
}

// HostPort joins host and port, bracketing IPv6 literals.
func HostPort(host string, port int) string {
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

var funcs = template.FuncMap{
	"join":   strings.Join,
	"spaced": func(xs []string) string { return strings.Join(xs, " ") },
}

const confTmpl = `# GoVPN (WireGuard Engine) - {{.Kind}} "{{.Name}}"
# Mode: {{.TunnelMode}} tunnel
# IPv4-only profile: AllowedIPs carries IPv4 routes only. IPv6 is not routed
# through this tunnel, so IPv6 traffic follows the client's normal (non-VPN)
# path. The Linux installer disables IPv6 on the tunnel link only, never
# host-wide; this profile claims no IPv6 leak blocking on any platform.
[Interface]
PrivateKey = {{.PrivateKey}}
Address = {{.Address}}
MTU = {{.MTU}}
{{- if .DNS}}
DNS = {{join .DNS ", "}}
{{- end}}
{{- if .Linux}}
PostUp = sysctl -q -w net.ipv6.conf.%i.disable_ipv6=1 2>/dev/null || true
PreDown = sysctl -q -w net.ipv6.conf.%i.disable_ipv6=0 2>/dev/null || true
{{- end}}

[Peer]
PublicKey = {{.ServerKey}}
PresharedKey = {{.PSK}}
Endpoint = {{.Endpoint}}
AllowedIPs = {{join .AllowedIPs ", "}}
PersistentKeepalive = {{.Keepalive}}
`

type confData struct {
	Peer
	Linux bool
}

// Conf renders a wg-quick / WireGuard app compatible config. It is the
// platform-neutral download (Windows, generic .conf, QR), so it contains no
// Linux-only hooks; ClientScript uses linuxConf for the same profile plus
// link-scoped IPv6 hardening.
func Conf(p Peer) (string, error) { return render("conf", confTmpl, confData{Peer: p}) }

func linuxConf(p Peer) (string, error) {
	return render("conf", confTmpl, confData{Peer: p, Linux: true})
}

// siteConf is the wg-quick config used on a Linux site gateway. It differs
// from Conf: no DNS (a gateway keeps its own resolver), Table=off in full
// mode with explicit policy routing so the gateway keeps reaching the hub,
// and IPv6 disabled on this link only (never host-wide).
const siteConfTmpl = `# GoVPN (WireGuard Engine) - site "{{.Name}}"
# IPv4-only profile: no IPv6 default route, so IPv6 is not routed through
# this tunnel and keeps using the host's normal path. IPv6 is disabled on
# this WireGuard link only; other interfaces are untouched.
[Interface]
PrivateKey = {{.PrivateKey}}
Address = {{.Address}}
MTU = {{.MTU}}
PostUp = sysctl -q -w net.ipv6.conf.%i.disable_ipv6=1 2>/dev/null || true
PreDown = sysctl -q -w net.ipv6.conf.%i.disable_ipv6=0 2>/dev/null || true
{{- if eq .TunnelMode "full"}}
Table = off
PostUp = /etc/govpn-site/route.sh up %i
PreDown = /etc/govpn-site/route.sh down %i
{{- end}}

[Peer]
PublicKey = {{.ServerKey}}
PresharedKey = {{.PSK}}
Endpoint = {{.Endpoint}}
AllowedIPs = {{join .AllowedIPs ", "}}
PersistentKeepalive = {{.Keepalive}}
`

const siteScriptTmpl = `#!/usr/bin/env bash
# GoVPN (WireGuard Engine) - site gateway setup for "{{.Name}}".
#   sudo bash install-site-{{.FileName}}.sh            install or update (idempotent)
#   sudo bash install-site-{{.FileName}}.sh --uninstall
# Contains the site private key and PSK. Keep it mode 600, delete after use.
set -euo pipefail
umask 077

IFACE='{{.Iface}}'
LOCAL_LANS='{{spaced .LocalLANs}}'
MODE='{{.TunnelMode}}'
MTU='{{.MTU}}'
MSS=$((MTU - 40))
TABLE='govpn_site'

log() { printf '[govpn-site] %s\n' "$*"; }
die() { printf '[govpn-site] ERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die 'run as root'

if [ "${1:-}" = '--uninstall' ]; then
  systemctl disable --now "wg-quick@$IFACE" 2>/dev/null || true
  nft delete table inet "$TABLE" 2>/dev/null || true
  rm -f "/etc/wireguard/$IFACE.conf" /etc/sysctl.d/60-govpn-site.conf /etc/nftables.d/govpn-site.nft
  rm -rf /etc/govpn-site
  systemctl disable --now govpn-site-nat.service 2>/dev/null || true
  rm -f /etc/systemd/system/govpn-site-nat.service
  systemctl daemon-reload
  log 'removed'
  exit 0
fi

. /etc/os-release
case "${ID:-}" in debian|ubuntu) ;; *) case " ${ID_LIKE:-} " in *" debian "*) ;; *) die "Debian/Ubuntu only (found ${ID:-unknown})";; esac;; esac

if ! command -v wg >/dev/null || ! command -v wg-quick >/dev/null || ! command -v nft >/dev/null; then
  log 'installing wireguard-tools nftables'
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends wireguard-tools nftables iproute2 >/dev/null
fi
modprobe wireguard 2>/dev/null || true

# Egress interface towards the LANs (used for masquerade).
LAN_IFS=''
for net in $LOCAL_LANS; do
  dev=$(ip -4 route get "${net%/*}" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
  [ -n "$dev" ] && case " $LAN_IFS " in *" $dev "*) ;; *) LAN_IFS="$LAN_IFS $dev";; esac
done
LAN_IFS="${LAN_IFS# }"
[ -n "$LAN_IFS" ] || log "WARNING: no local route to $LOCAL_LANS yet; NAT rules apply once the LAN interface exists"

install -d -m 700 /etc/wireguard /etc/govpn-site
cat > "/etc/wireguard/$IFACE.conf" <<'WGCONF'
{{.SiteConf}}WGCONF
chmod 600 "/etc/wireguard/$IFACE.conf"

cat > /etc/govpn-site/route.sh <<'ROUTE'
#!/usr/bin/env bash
# Full tunnel for a site gateway: default route through the hub in table 51820,
# hub endpoint and local networks stay on the main table.
set -eu
action=$1 dev=$2
if [ "$action" = up ]; then
  ip -4 route replace default dev "$dev" table 51820
  ip -4 rule add not fwmark 51820 table 51820 priority 32000 2>/dev/null || true
  ip -4 rule add table main suppress_prefixlength 0 priority 31999 2>/dev/null || true
  wg set "$dev" fwmark 51820
else
  ip -4 rule del table main suppress_prefixlength 0 priority 31999 2>/dev/null || true
  ip -4 rule del not fwmark 51820 table 51820 priority 32000 2>/dev/null || true
  ip -4 route flush table 51820 2>/dev/null || true
fi
ROUTE
chmod 700 /etc/govpn-site/route.sh

cat > /etc/sysctl.d/60-govpn-site.conf <<'SYSCTL'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
SYSCTL
sysctl -q -p /etc/sysctl.d/60-govpn-site.conf

# Own nft table only; other rule sets are left alone.
{
  echo "table inet $TABLE {"
  echo "  chain forward {"
  echo "    type filter hook forward priority -10; policy accept;"
  echo "    oifname \"$IFACE\" tcp flags syn tcp option maxseg size set rt mtu"
  echo "    iifname \"$IFACE\" tcp flags syn tcp option maxseg size > $MSS tcp option maxseg size set $MSS"
  echo "  }"
  echo "  chain postrouting {"
  echo "    type nat hook postrouting priority srcnat; policy accept;"
  for dev in $LAN_IFS; do
    echo "    iifname \"$IFACE\" oifname \"$dev\" masquerade"
  done
  echo "  }"
  echo "}"
} > /etc/govpn-site/nat.nft
nft delete table inet "$TABLE" 2>/dev/null || true
nft -f /etc/govpn-site/nat.nft

cat > /etc/systemd/system/govpn-site-nat.service <<UNIT
[Unit]
Description=GoVPN site NAT/MSS rules for $IFACE
After=network-online.target nftables.service
Wants=network-online.target
Before=wg-quick@$IFACE.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'nft delete table inet $TABLE 2>/dev/null; nft -f /etc/govpn-site/nat.nft'
ExecStop=/usr/sbin/nft delete table inet $TABLE
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now govpn-site-nat.service >/dev/null
systemctl enable "wg-quick@$IFACE" >/dev/null 2>&1
systemctl restart "wg-quick@$IFACE"

log "tunnel $IFACE up, LAN: $LOCAL_LANS, mode: $MODE"
for i in 1 2 3 4 5 6 7 8 9 10; do
  hs=$(wg show "$IFACE" latest-handshakes | awk '{print $2}')
  if [ -n "$hs" ] && [ "$hs" != 0 ]; then log 'handshake with hub OK'; exit 0; fi
  sleep 1
done
log 'no handshake yet: check UDP reachability of {{.Endpoint}}'
`

// SiteScript renders install-site-<name>.sh.
func SiteScript(p Peer) (string, error) {
	conf, err := render("siteconf", siteConfTmpl, p)
	if err != nil {
		return "", err
	}
	return render("site", siteScriptTmpl, struct {
		Peer
		SiteConf string
	}{p, conf})
}

const clientScriptTmpl = `#!/usr/bin/env bash
# GoVPN (WireGuard Engine) - client "{{.Name}}" for Debian/Ubuntu.
#   sudo bash config-{{.FileName}}.sh               install and connect
#   sudo bash config-{{.FileName}}.sh --uninstall
# Contains the private key. Keep it mode 600.
set -euo pipefail
umask 077
IFACE='{{.Iface}}'
log() { printf '[govpn] %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo 'run as root' >&2; exit 1; }

if [ "${1:-}" = '--uninstall' ]; then
  systemctl disable --now "wg-quick@$IFACE" 2>/dev/null || true
  rm -f "/etc/wireguard/$IFACE.conf"
  log 'removed'
  exit 0
fi

pkgs=''
command -v wg-quick >/dev/null || pkgs='wireguard-tools'
{{- if .DNS}}
command -v resolvconf >/dev/null || command -v resolvectl >/dev/null || pkgs="$pkgs openresolv"
{{- end}}
{{- if eq .TunnelMode "full"}}
command -v iptables-restore >/dev/null || command -v nft >/dev/null || pkgs="$pkgs nftables"
{{- end}}
if [ -n "$pkgs" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends $pkgs >/dev/null
fi
{{- if .DNS}}
# systemd-resolved hosts need the resolvconf shim for wg-quick DNS=.
if command -v resolvectl >/dev/null && ! command -v resolvconf >/dev/null; then
  ln -sf "$(command -v resolvectl)" /usr/local/sbin/resolvconf
fi
{{- end}}
modprobe wireguard 2>/dev/null || true

install -d -m 700 /etc/wireguard
cat > "/etc/wireguard/$IFACE.conf" <<'WGCONF'
{{.Conf}}WGCONF
chmod 600 "/etc/wireguard/$IFACE.conf"
systemctl enable "wg-quick@$IFACE" >/dev/null 2>&1
systemctl restart "wg-quick@$IFACE"
log "connected via $IFACE"
wg show "$IFACE" | sed -n '1,12p'
`

// ClientScript renders config-<username>.sh. The embedded wg-quick config is
// Linux-specific: besides the platform-neutral profile it disables IPv6 on
// the tunnel link only, so native IPv6 on the host is left alone.
func ClientScript(p Peer) (string, error) {
	conf, err := linuxConf(p)
	if err != nil {
		return "", err
	}
	return render("client", clientScriptTmpl, struct {
		Peer
		Conf string
	}{p, conf})
}

func render(name, text string, data any) (string, error) {
	t, err := template.New(name).Funcs(funcs).Parse(text)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
