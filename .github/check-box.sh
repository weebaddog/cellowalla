#!/usr/bin/env bash
# CI: checks a freshly installed box (lookout mode). Run as root.
set -uo pipefail
t() { local m="$1"; shift; if "$@"; then echo "ok   $m"; else echo "FAIL $m"; exit 1; fi; }
is() { [[ "$1" == "$2" ]]; }
real() { [[ -n "$1" && "$1" != "0.0.0.0" ]]; }
q() { dig +short +time=5 +tries=3 "$@" | tail -1; }

t "service running" systemctl is-active -q cellowalla
for i in $(seq 1 90); do journalctl -u cellowalla --no-pager | grep -q '\[lists\] ads [1-9]' && break; sleep 2; done
journalctl -u cellowalla --no-pager | grep '\[lists\]' | tail -1

t "ads blocked" is "$(q @127.0.0.1 doubleclick.net A)" 0.0.0.0
t "names under a blocked one blocked" is "$(q @127.0.0.1 x.doubleclick.net A)" 0.0.0.0
t "normal names answered" real "$(q @127.0.0.1 example.com A)"
t "DNS over TCP" real "$(q +tcp @127.0.0.1 wikipedia.org A)"
t "encrypted-DNS dodge blocked" is "$(q @127.0.0.1 dns.google A)" 0.0.0.0
t "Firefox canary" bash -c 'dig @127.0.0.1 use-application-dns.net | grep -q NXDOMAIN'
t "firewall table loaded" nft list table inet cellowalla

C=(-sk --fail-with-body -H 'x-cellowalla: 1' -H 'content-type: application/json' -b /tmp/jar -c /tmp/jar)
t "dashboard over https" bash -c "curl -sk https://127.0.0.1/api/hello | grep -q '\"setUp\":false'"
t "http redirects to https" is "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/)" 301
CODE=$(cat /var/lib/cellowalla/setup-code.txt)
t "first-time setup" curl "${C[@]}" -o /dev/null -d "{\"code\":\"$CODE\",\"password\":\"ci-password-123\"}" https://127.0.0.1/api/setup
t "Clean Search on" curl "${C[@]}" -o /dev/null -X PUT -d '{"cleanSearch":true}' https://127.0.0.1/api/shield
t "Clean Search answers" bash -c 'dig +short @127.0.0.1 www.google.com A | grep -q forcesafesearch'
curl "${C[@]}" -o /dev/null -X PUT -d '{"cleanSearch":false}' https://127.0.0.1/api/shield

# Tunnel: switch on, make a pass, connect a pretend phone (a network namespace) and use Shield through it.
t "Tunnel on" curl "${C[@]}" -o /dev/null -X PUT -d '{"on":true,"endpoint":"172.31.0.1"}' https://127.0.0.1/api/tunnel
for i in $(seq 1 20); do ip link show cw0 >/dev/null 2>&1 && break; sleep 0.5; done
t "WireGuard interface up" bash -c 'ip -4 addr show cw0 | grep -q 10.88.0.1'
t "pass made" curl "${C[@]}" -o /tmp/pass.json -d '{"name":"CI phone","full":false}' https://127.0.0.1/api/tunnel/passes
t "pass added to the server" grep -q 'AllowedIPs = 10.88.0.2/32' /etc/wireguard/cw0.conf
t "pass is live in WireGuard" bash -c 'wg show cw0 allowed-ips | grep -q 10.88.0.2/32'
node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync("/tmp/pass.json","utf8")).conf)' > /tmp/phone.conf

ip netns add phone
ip link add cwtest-h type veth peer name cwtest-p
ip link set cwtest-p netns phone
ip addr add 172.31.0.1/30 dev cwtest-h; ip link set cwtest-h up
ip -n phone addr add 172.31.0.2/30 dev cwtest-p; ip -n phone link set cwtest-p up; ip -n phone link set lo up
ip -n phone link add wg0 type wireguard
grep -vE '^(Address|DNS) *=' /tmp/phone.conf | sed 's/^AllowedIPs = .*/AllowedIPs = 10.88.0.0\/24/' > /tmp/phone.wg
ip netns exec phone wg setconf wg0 /tmp/phone.wg
ip -n phone addr add 10.88.0.2/32 dev wg0; ip -n phone link set wg0 up
ip -n phone route add 10.88.0.0/24 dev wg0
t "phone through the Tunnel gets Shield" is "$(ip netns exec phone dig +short +time=5 +tries=3 @10.88.0.1 doubleclick.net A)" 0.0.0.0
t "phone through the Tunnel gets answers" real "$(ip netns exec phone dig +short +time=5 +tries=3 @10.88.0.1 example.com A | tail -1)"
t "WireGuard handshake" bash -c '[[ $(wg show cw0 latest-handshakes | awk "{print \$2}") -gt 0 ]]'
sleep 35
OUT=$(curl "${C[@]}" https://127.0.0.1/api/tunnel); t "dashboard shows the phone connected" grep -q '"online":true' <<<"$OUT"
OUT=$(curl "${C[@]}" https://127.0.0.1/api/devices); t "pass listed in the Roster" grep -q '"kind":"tunnel"' <<<"$OUT"
OUT=$(nft -j list counters table inet cellowalla); t "data counters for the pass" grep -q u_10_88_0_2 <<<"$OUT"
OUT=$(curl "${C[@]}" https://127.0.0.1/api/pings); t "Ping for the Tunnel connection" grep -q 'CI phone connected' <<<"$OUT"

# House Rules through the Tunnel: pause the pass's device; its look-ups get nowhere.
MAC=$(curl "${C[@]}" https://127.0.0.1/api/devices | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).devices.find(d=>d.kind==="tunnel").mac))')
t "pause the pass" curl "${C[@]}" -o /dev/null -X PUT -d "{\"mac\":\"$MAC\",\"pauseMinutes\":30}" https://127.0.0.1/api/devices
sleep 1
t "paused device gets no answers" is "$(ip netns exec phone dig +short +time=5 @10.88.0.1 example.com A)" 0.0.0.0
t "paused device in the firewall's cut set" bash -c 'nft list set inet cellowalla cut4 | grep -q 10.88.0.2'

ip netns del phone; ip link del cwtest-h 2>/dev/null || true
echo "all box checks passed"
