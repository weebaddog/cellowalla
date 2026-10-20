# Cellowalla

A home network guard for a small Linux box (Raspberry Pi 4/5 or any mini PC running Debian, Raspberry Pi OS or Ubuntu).

- **Shield**: DNS blocking (ads and trackers, malware and scams, adult, social, gaming, gambling, your own lists), Clean Search, DNS-rebinding guard, look-up log
- **Roster**: every device on the network, the **Lobby** for new devices
- **House Rules**: **Crews** with extra blocking, bedtimes, pause, "30 more minutes"
- **Tunnel**: WireGuard server with QR-code **passes**
- **Pings**: alerts in the dashboard and to your phone through ntfy or a webhook
- Two setups: **Lookout** (DNS only, plugs into your router) or **Gatekeeper** (two ports, the box is the router)

Install on the box: `sudo bash install/install.sh` (step by step: `HOW-TO-INSTALL.txt`). The full user guide is `web/guide.html`, and the dashboard opens it from the ? button.

Development (any OS, nothing on the system changes):

    node test/selftest.js   # all checks
    node test/demo.js       # demo dashboard at http://localhost:8088, password demo-password

No npm dependencies. Node 18 or newer.
