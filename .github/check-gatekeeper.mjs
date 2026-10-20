// CI: the gatekeeper-mode firewall rules must pass the kernel's own check (nft -c), and the DHCP
// settings must pass dnsmasq's. Nothing is applied.
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { DEFAULTS } from "../src/state.js";
import { nftRules, dnsmasqConf } from "../src/gate.js";

const s = DEFAULTS();
s.mode = "gatekeeper";
s.net.lanIf = "eth1"; s.net.wanIf = "eth0";
s.tunnel.on = true;
s.devices = { "aa:bb:cc:dd:ee:01": { mac: "aa:bb:cc:dd:ee:01", ip: "192.168.50.101", kind: "lan" } };
for (const plan of [{}, { cut: ["192.168.50.101", "10.88.0.2"], lobby: ["192.168.50.102"], counted: ["192.168.50.101", "192.168.50.102", "10.88.0.2"] }]) {
  fs.writeFileSync("/tmp/gk.nft", nftRules(s, plan));
  execFileSync("nft", ["-c", "-f", "/tmp/gk.nft"], { stdio: "inherit" });
}
console.log("ok   gatekeeper nftables rules accepted by the kernel");
for (const plan of [{}, { cut: ["192.168.1.9"] }]) {
  fs.writeFileSync("/tmp/lo.nft", nftRules({ ...s, mode: "lookout", net: { ...s.net, lanIf: "eth0" } }, plan));
  execFileSync("nft", ["-c", "-f", "/tmp/lo.nft"], { stdio: "inherit" });
}
console.log("ok   lookout nftables rules accepted by the kernel");
fs.writeFileSync("/tmp/cw-dnsmasq.conf", dnsmasqConf(s));
execFileSync("dnsmasq", ["--test", "-C", "/tmp/cw-dnsmasq.conf"], { stdio: "inherit" });
console.log("ok   dnsmasq settings accepted");
