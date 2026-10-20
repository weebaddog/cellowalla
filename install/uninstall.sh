#!/usr/bin/env bash
# Removes Cellowalla from this box. Settings stay in /var/lib/cellowalla (delete it yourself if you want).
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo bash install/uninstall.sh"; exit 1; }

systemctl disable --now cellowalla 2>/dev/null
systemctl disable --now wg-quick@cw0 2>/dev/null
nft delete table inet cellowalla 2>/dev/null
rm -f /etc/systemd/system/cellowalla.service /usr/local/sbin/cellowalla-reset-password \
      /etc/wireguard/cw0.conf /etc/nftables.d/cellowalla.nft /etc/dnsmasq.d/cellowalla.conf \
      /etc/sysctl.d/90-cellowalla.conf /etc/systemd/resolved.conf.d/cellowalla.conf \
      /etc/systemd/network/10-cellowalla-lan.network /etc/systemd/network/10-cellowalla-wan.network \
      /etc/network/interfaces.d/cellowalla
systemctl is-active -q dnsmasq && systemctl restart dnsmasq
systemctl is-active -q systemd-resolved && systemctl restart systemd-resolved
if systemctl is-active -q NetworkManager; then
  nmcli con delete cellowalla-lan cellowalla-wan >/dev/null 2>&1
  echo "If this box was in gatekeeper mode, re-enable your original wired connection in NetworkManager (nmcli con mod <name> connection.autoconnect yes)."
fi
systemctl daemon-reload
rm -rf /opt/cellowalla
echo "Cellowalla removed. Settings kept in /var/lib/cellowalla."
echo "Remember: set your router's DNS back to automatic (lookout), or plug your Wi-Fi router back into the modem (gatekeeper)."
