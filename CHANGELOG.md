# Changelog

All notable changes to pve-gateway. Versions follow [semantic versioning](https://semver.org/); the version is
`VERSION` in `pve-gateway.py`. The **Update** button in Settings (and `pve-gateway update`) installs the latest version
from GitHub and shows the entries below that are newer than the installed one.

## 1.2.1 - 2026-10-16
- App logo (a gate with three servers) in the header, on the login page and as the browser favicon.

## 1.2.0 - 2026-10-16
- Domains: aliases can redirect (301) to the main domain instead of serving the same site.
- Domains: "Behind the Cloudflare proxy" option - nginx trusts Cloudflare's ranges and uses the real visitor IP
  (CF-Connecting-IP) for logs, the guest and "Allowed sources"; the DNS test recognises Cloudflare-proxied records.
- Domains: optional security headers (nosniff, same-origin framing, referrer policy) and HSTS.
- Domain test: checks the certificate nginx actually serves (covers every name, expiry, same certificate over IPv4
  and IPv6), warns about AAAA records that don't point to this host, and checks that aliases answer with a 301.
- Debug: warns about risky services (rpcbind, databases, Redis, Docker API, VNC, ...) listening on all interfaces,
  and about Proxmox enterprise repositories enabled without a subscription.
- Settings: edit the Proxmox users allowed to sign in; optional automatic updates.

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
