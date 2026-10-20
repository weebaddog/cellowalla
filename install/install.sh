#!/usr/bin/env bash
# Cellowalla installer for Debian 12+, Raspberry Pi OS (Bookworm+) and Ubuntu 22.04+.
# Safe to run again: to change mode or ports, or to upgrade.
#
#   sudo bash install/install.sh
#
# Without questions (all optional): CW_MODE=lookout|gatekeeper CW_LAN=eth0 CW_WAN=eth1 CW_TZ=America/Detroit CW_YES=1

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP=/opt/cellowalla
DATA=/var/lib/cellowalla
LAN_NET_IP=192.168.50.1

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { local q="$1" def="${2:-}" a; if [[ -n "${CW_YES:-}" ]]; then echo "$def"; return; fi; read -r -p "$q${def:+ [$def]}: " a </dev/tty; echo "${a:-$def}"; }

[[ $EUID -eq 0 ]] || die "Run with sudo: sudo bash install/install.sh"
command -v apt-get >/dev/null || die "This installer needs a Debian-based system (Debian, Raspberry Pi OS, Ubuntu)."
[[ -f "$SRC/src/main.js" ]] || die "Run this from inside the cellowalla folder."

# ---- questions ---------------------------------------------------------------------------------

say "Network ports on this box"
ip -br link | awk '$1 != "lo" && $1 !~ /^(cw|wg|docker|veth|br-)/ {print "   " $1 "  " $2 "  " $3}'
PORTS=$(ip -br link | awk '$1 != "lo" && $1 !~ /^(cw|wg|docker|veth|br-|wlan)/ {print $1}')
DEFAULT_PORT=$(ip route show default 2>/dev/null | awk '{print $5; exit}')

CUR_MODE=""; [[ -f "$DATA/state.json" ]] && CUR_MODE=$(grep -o '"mode": *"[a-z]*"' "$DATA/state.json" | head -1 | grep -o '[a-z]*"$' | tr -d '"') || true
echo
echo "  lookout     the box plugs into your router; your router sends DNS to it (easy)"
echo "  gatekeeper  the box sits between the modem and your Wi-Fi and is the router (two ports)"
MODE="${CW_MODE:-$(ask "Mode (lookout/gatekeeper)" "${CUR_MODE:-lookout}")}"
[[ "$MODE" == lookout || "$MODE" == gatekeeper ]] || die "Mode must be lookout or gatekeeper"

if [[ "$MODE" == lookout ]]; then
  LAN="${CW_LAN:-$(ask "Port connected to your router" "${DEFAULT_PORT:-eth0}")}"
  WAN=""
else
  N=$(echo "$PORTS" | grep -c . || true)
  [[ $N -ge 2 ]] || warn "Gatekeeper mode needs two wired ports; only found: $(echo $PORTS)"
  WAN="${CW_WAN:-$(ask "Port going to the MODEM (internet side)" "${DEFAULT_PORT:-eth0}")}"
  OTHER=$(echo "$PORTS" | grep -vx "$WAN" | head -1 || true)
  LAN="${CW_LAN:-$(ask "Port going to your Wi-Fi router / switch (home side)" "${OTHER:-eth1}")}"
  [[ "$LAN" != "$WAN" ]] || die "The two ports must be different"
fi
for p in $LAN $WAN; do ip link show "$p" >/dev/null 2>&1 || die "There's no port called $p"; done

TZ_NOW=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC)
TZ_NEW="${CW_TZ:-$(ask "Time zone (for bedtimes)" "$TZ_NOW")}"
if [[ "$TZ_NEW" != "$TZ_NOW" ]]; then timedatectl set-timezone "$TZ_NEW" || warn "Couldn't set the time zone to $TZ_NEW"; fi

if [[ "$MODE" == gatekeeper && -n "${SSH_CONNECTION:-}" ]]; then
  SSH_IF=$(ip route get "$(echo "$SSH_CONNECTION" | awk '{print $1}')" 2>/dev/null | grep -o 'dev [^ ]*' | awk '{print $2}')
  if [[ "$SSH_IF" == "$LAN" ]]; then
    warn "You're connected over $LAN, which is about to become the home side ($LAN_NET_IP)."
    warn "Your SSH session will drop. Reconnect to $LAN_NET_IP after plugging in as described in the guide."
    [[ "$(ask "Carry on? (yes/no)" "no")" == yes ]] || die "Stopped; nothing changed on the network."
  fi
fi

# ---- packages ----------------------------------------------------------------------------------

say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
PKGS="nftables wireguard-tools iproute2 openssl curl ca-certificates"
[[ "$MODE" == gatekeeper ]] && PKGS="$PKGS dnsmasq"
apt-get install -y -qq $PKGS >/dev/null

NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
if [[ $NODE_MAJOR -lt 18 ]]; then
  apt-get install -y -qq nodejs >/dev/null 2>&1 || true
  NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
fi
[[ $NODE_MAJOR -ge 18 ]] || die "Cellowalla needs Node.js 18 or newer, and this system's package is older. Install Node.js 20 from https://nodejs.org (or NodeSource), then run this again."
NODE=$(command -v node)

# ---- files -------------------------------------------------------------------------------------

say "Copying Cellowalla to $APP"
systemctl stop cellowalla 2>/dev/null || true
mkdir -p "$APP"
rm -rf "$APP/src" "$APP/web" "$APP/install"
cp -r "$SRC/src" "$SRC/web" "$SRC/install" "$SRC/package.json" "$APP/"
install -d -m 700 "$DATA" "$DATA/tls"
install -d -m 755 /etc/nftables.d /etc/dnsmasq.d
install -d -m 700 /etc/wireguard

"$NODE" "$APP/install/configure.mjs" --data "$DATA" --mode "$MODE" --lan "$LAN" ${WAN:+--wan "$WAN"} \
  ${DEFAULT_PORT:+--gateway "$(ip route show default | awk '{print $3; exit}')"}

if [[ ! -s "$DATA/oui.csv" ]]; then
  say "Downloading device maker names (IEEE)"
  curl -fsSL --max-time 120 -o "$DATA/oui.csv.part" https://standards-oui.ieee.org/oui/oui.csv && mv "$DATA/oui.csv.part" "$DATA/oui.csv" \
    || { rm -f "$DATA/oui.csv.part"; warn "Couldn't download; devices will show without maker names."; }
fi

# ---- the box's own network ---------------------------------------------------------------------

say "Setting up the network"
cat > /etc/sysctl.d/90-cellowalla.conf <<EOF
net.ipv4.ip_forward = 1
EOF
sysctl -q --system

# Port 53 must be free for Shield, and the box itself uses public DNS (so it can always update).
if systemctl is-active -q systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/cellowalla.conf <<EOF
[Resolve]
DNSStubListener=no
DNS=1.1.1.1 9.9.9.9
EOF
  systemctl restart systemd-resolved
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
fi
if systemctl is-active -q dnsmasq && [[ "$MODE" == lookout ]]; then systemctl disable --now dnsmasq; fi

NM=0; systemctl is-active -q NetworkManager && NM=1
if [[ "$MODE" == lookout ]]; then
  if [[ $NM == 1 ]]; then
    CON=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="$LAN" '$2==d {print $1; exit}')
    [[ -n "$CON" ]] && nmcli con mod "$CON" ipv4.ignore-auto-dns yes ipv4.dns "1.1.1.1 9.9.9.9" && nmcli con up "$CON" >/dev/null || true
  elif ! systemctl is-active -q systemd-resolved; then
    chattr -i /etc/resolv.conf 2>/dev/null || true
    printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > /etc/resolv.conf
  fi
else
  if [[ $NM == 1 ]]; then
    nmcli -t -f NAME,DEVICE con show | awk -F: -v l="$LAN" -v w="$WAN" '($2==l || $2==w) && $1 !~ /^cellowalla-/ {print $1}' | while read -r c; do nmcli con mod "$c" connection.autoconnect no || true; done
    nmcli con delete cellowalla-lan cellowalla-wan >/dev/null 2>&1 || true
    nmcli con add type ethernet ifname "$WAN" con-name cellowalla-wan ipv4.method auto ipv4.ignore-auto-dns yes ipv4.dns "1.1.1.1 9.9.9.9" ipv6.method auto >/dev/null
    nmcli con add type ethernet ifname "$LAN" con-name cellowalla-lan ipv4.method manual ipv4.addresses "$LAN_NET_IP/24" ipv6.method disabled >/dev/null
    nmcli con up cellowalla-wan >/dev/null || warn "The internet port didn't come up yet (is the modem plugged in?)"
    nmcli con up cellowalla-lan >/dev/null || true
  elif systemctl is-enabled -q systemd-networkd 2>/dev/null; then
    cat > /etc/systemd/network/10-cellowalla-wan.network <<EOF
[Match]
Name=$WAN
[Network]
DHCP=yes
DNS=1.1.1.1
[DHCPv4]
UseDNS=no
EOF
    cat > /etc/systemd/network/10-cellowalla-lan.network <<EOF
[Match]
Name=$LAN
[Network]
Address=$LAN_NET_IP/24
LinkLocalAddressing=no
IPv6AcceptRA=no
EOF
    systemctl restart systemd-networkd
  else
    cat > /etc/network/interfaces.d/cellowalla <<EOF
auto $WAN
iface $WAN inet dhcp
auto $LAN
iface $LAN inet static
    address $LAN_NET_IP/24
EOF
    warn "Network settings written to /etc/network/interfaces.d/cellowalla; remove any other lines for $LAN and $WAN in /etc/network/interfaces, then reboot."
  fi
  # dnsmasq only hands out addresses (DNS is Shield's job).
  grep -q '^conf-dir=/etc/dnsmasq.d' /etc/dnsmasq.conf 2>/dev/null || echo 'conf-dir=/etc/dnsmasq.d/,*.conf' >> /etc/dnsmasq.conf
  systemctl enable dnsmasq >/dev/null 2>&1 || true
fi

BOX_IP=$LAN_NET_IP
[[ "$MODE" == lookout ]] && BOX_IP=$(ip -4 -br addr show "$LAN" | awk '{print $3}' | cut -d/ -f1)

# ---- certificate for the dashboard -------------------------------------------------------------

if [[ ! -s "$DATA/tls/cert.pem" ]] || ! openssl x509 -in "$DATA/tls/cert.pem" -noout -text | grep -q "IP Address:$BOX_IP"; then
  say "Making the dashboard's certificate"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj "/CN=cellowalla.lan" \
    -addext "subjectAltName=DNS:cellowalla.lan,DNS:cellowalla,IP:$BOX_IP" -keyout "$DATA/tls/key.pem" -out "$DATA/tls/cert.pem" 2>/dev/null
  chmod 600 "$DATA/tls/key.pem"
fi

# ---- service -----------------------------------------------------------------------------------

say "Starting Cellowalla"
cat > /etc/systemd/system/cellowalla.service <<EOF
[Unit]
Description=Cellowalla home network guard
After=network-online.target nftables.service
Wants=network-online.target

[Service]
ExecStart=$NODE $APP/src/main.js
Environment=CELLOWALLA_DATA=$DATA
Environment=NODE_ENV=production
Restart=always
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=$DATA /etc/wireguard /etc/nftables.d -/etc/dnsmasq.d -/var/lib/misc

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/sbin/cellowalla-reset-password <<EOF
#!/usr/bin/env bash
set -e
[[ \$EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }
systemctl stop cellowalla
$NODE $APP/install/configure.mjs --data $DATA --reset-password
systemctl start cellowalla
for i in \$(seq 1 20); do [[ -s $DATA/setup-code.txt ]] && break; sleep 0.5; done
echo "New setup code: \$(cat $DATA/setup-code.txt)"
EOF
chmod 755 /usr/local/sbin/cellowalla-reset-password

systemctl daemon-reload
systemctl enable --now cellowalla >/dev/null
for i in $(seq 1 30); do [[ -s "$DATA/setup-code.txt" ]] && break; sleep 0.5; done
sleep 1
systemctl is-active -q cellowalla || { journalctl -u cellowalla -n 30 --no-pager; die "Cellowalla didn't start (see above)."; }

say "Done"
echo "  Mode:       $MODE"
echo "  Dashboard:  https://$BOX_IP  (or https://cellowalla.lan once devices use the box)"
if grep -q '"admin": *null' "$DATA/state.json" 2>/dev/null; then
  echo "  Setup code: $(cat "$DATA/setup-code.txt")   <- type this the first time you open the dashboard"
fi
echo
if [[ "$MODE" == lookout ]]; then
  echo "  Next: in your router, reserve $BOX_IP for this box and set the DNS server it hands out to $BOX_IP."
else
  echo "  Next: plug $WAN into the modem and $LAN into your Wi-Fi router (set to access point / bridge mode)."
fi
echo "  The user guide is in the dashboard (the ? button)."
