#!/usr/bin/env bash
# Remove GoVPN (WireGuard Engine).
#   sudo bash uninstall.sh            remove service, interfaces, rules, binary
#   sudo bash uninstall.sh --purge    also delete /etc/govpn and /var/lib/govpn/wg (keys!)
set -euo pipefail
PREFIX=/opt/govpn/wg
CONF=/etc/govpn/wg.env
PURGE=0
[ "${1:-}" = --purge ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo 'run as root' >&2; exit 1; }

systemctl disable --now govpn-wg.service 2>/dev/null || true

if [ -x "$PREFIX/govpn-wg" ]; then
  "$PREFIX/govpn-wg" teardown -config "$CONF" || true
else
  # Fallback without the binary: owned links and chains only.
  for l in $(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^wg-[sc]([0-9]+|-[a-z0-9-]+)$'); do
    ip link del "$l" || true
  done
  for spec in filter:FORWARD:GOVPN-FWD nat:POSTROUTING:GOVPN-POST mangle:FORWARD:GOVPN-MSS; do
    IFS=: read -r t from chain <<<"$spec"
    while iptables -w -t "$t" -D "$from" -j "$chain" 2>/dev/null; do :; done
    iptables -w -t "$t" -F "$chain" 2>/dev/null && iptables -w -t "$t" -X "$chain" 2>/dev/null || true
  done
fi

rm -f /etc/systemd/system/govpn-wg.service /usr/local/bin/govpn-wg
systemctl daemon-reload
rm -rf "$PREFIX"
# Tuning stays active until reboot; the files are removed so it is not re-applied.
rm -f /etc/sysctl.d/99-govpn-wg.conf /etc/modules-load.d/govpn-wg.conf

if [ "$PURGE" -eq 1 ]; then
  rm -rf /etc/govpn /var/lib/govpn/wg
  rmdir /var/lib/govpn 2>/dev/null || true
  echo 'govpn-wg removed, configuration and keys deleted'
else
  echo 'govpn-wg removed; kept /etc/govpn and /var/lib/govpn/wg (use --purge to delete)'
fi
