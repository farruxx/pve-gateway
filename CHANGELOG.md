# Changelog

All notable changes to pve-gateway. Versions follow [semantic versioning](https://semver.org/); the version is
`VERSION` in `pve-gateway.py`. The **Update** button in Settings (and `pve-gateway update`) installs the latest version
from GitHub and shows the entries below that are newer than the installed one.

## 1.1.0 - 2026-10-16
- Updates: check GitHub for a new version and install it from the UI (Settings → Updates) or `pve-gateway update`.
- Web UI access control: only listed IPs/networks can reach the UI (Settings, `pve-gateway ui-allow`).
- Security: login brute-force protection (counted before checking, one attempt per IP at a time, 15 min lockout),
  sessions bound to IP + browser, Host header check against DNS rebinding, connection limits, request size fix,
  Proxmox two-factor (TOTP) login, sandboxed systemd unit.
- Host network strip on Ports/Domains with tips; interface menu shows IPs.
- Guest IPs without the guest agent (ARP table by MAC, cloud-init).
- Installer: `curl | sh` one-liner, automatic switch to the no-subscription repositories when the enterprise repos
  answer 401, `--with-dns <provider>`, no longer installs stale files from the current directory.
- nginx 1.25.1+ (Debian trixie / PVE 9): `http2 on;` syntax.

## 1.0.0 - 2026-10-07
- Port forwarding to guests (iptables DNAT in own chains), live hit counters, per-rule tests.
- Domains: nginx reverse proxy with Let's Encrypt and wildcard certificates (DNS-01, six providers).
- Debug tab, CLI, mock mode for local development.
