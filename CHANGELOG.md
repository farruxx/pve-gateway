# Changelog

All notable changes to pve-gateway. Versions follow [semantic versioning](https://semver.org/); the version is
`VERSION` in `pve-gateway.py`. The **Update** button in Settings (and `pve-gateway update`) installs the latest version
from GitHub and shows the entries below that are newer than the installed one.

## 1.5.0 - 2026-10-16
- Security tab - fail2ban: status and jails (failed / banned now and total), banned IPs with one-click unban,
  "Unban all", manual ban (never your own IP or localhost), and "Install fail2ban" when it's missing.
- Optional management: pve-gateway writes /etc/fail2ban/jail.d/pve-gateway.local and its filters, tests them with
  `fail2ban-client -t` (previous files restored on failure) and reloads. Settings: ban time, find time, max retries,
  never-ban list, and jails for SSH, the Proxmox web UI (port 8006), pve-gateway logins, nginx-botsearch (Let's
  Encrypt challenge requests are never counted, so validation servers don't get banned) and recidive.
- Failed pve-gateway logins are logged ("login failed from <ip>") for the pve-gateway jail.

## 1.4.0 - 2026-10-16
- Monitor tab - health checks: HTTP(S) (expected status, certificate expiry), TCP and ping checks on guests and
  domains every N seconds; up / failing / down status, response time, uptime, last 60 results. "Add checks for my
  domains & ports" creates one check per domain and port rule. CLI: `pve-gateway monitors`.
- Alerts when a check goes down (after N failures in a row), comes back up, or a certificate is about to expire:
  e-mail (the host's sendmail/postfix), webhook (Slack, Discord, any URL) and Telegram; "Send test alert".
- Port scanner: TCP connect scan from the host (common ports, ranges up to 5000 ports) with service names and risk
  levels; limited to this host, private networks and known guests. CLI: `pve-gateway scan IP [PORTS]`.

## 1.3.0 - 2026-10-16
- While domains exist, ports 80/443 to this host are reserved for nginx here: a rule at the top of pve-gateway's nat
  chain stops DNAT rules from other tools (e.g. old port forwards to a firewall VM) from sending them to a guest, and
  the watchdog keeps pve-gateway's nat hook first. Domains tab shows "Ports 80/443: handled by nginx on this host" or
  the exact problems (listener, forwarding, firewall, fail2ban).
- Port 80/443 check (Debug, domain test, and in the error when Let's Encrypt can't connect): what listens there
  (must be nginx), iptables rules that drop/reject the port, fail2ban jails on 80/443 with banned addresses (Let's
  Encrypt's validation servers get "Connection refused" once banned after failed challenges), and whether the
  Proxmox firewall, when enabled, accepts 80/443 (HTTP/HTTPS macros or dport rules).
- The same check fails when an iptables/nftables rule from another tool forwards (DNAT) ports 80/443 to a guest:
  then requests never reach nginx on the host; the message shows the rule and how to remove it.

## 1.2.3 - 2026-10-16
- Fix: when certbot failed, the reason (Domain / Type / Detail) was dropped - only stderr was kept, certbot prints
  the details on stdout. Failed commands now keep both; if certbot's output still has no reason, it is read from the
  ACME error in `/var/log/letsencrypt/letsencrypt.log`.
- Debug: new "Let's Encrypt log" section with the relevant lines of the latest certbot run (emails and signed
  payloads filtered out).
- When the local challenge check passes but Let's Encrypt can't connect, the error says the block is between the
  internet and the host (provider firewall, Proxmox firewall, router).

## 1.2.2 - 2026-10-16
- Fix: Let's Encrypt failed when another nginx site on the host (e.g. another panel) binds the public IP explicitly
  (`listen <ip>:80`) - nginx then never used pve-gateway's blocks for that address. pve-gateway now detects such sites
  (`nginx -T`) and listens on the same addresses, re-applies before each certificate request, and the watchdog follows
  later changes.
- Before asking Let's Encrypt, pve-gateway serves a test challenge and fetches it through the public IP like Let's
  Encrypt does; if that fails it reports who answered instead (and doesn't use up the 5-failures-per-hour limit).
- Domain test checks through the public IP (127.0.0.1 could hide the problem), reports other sites that claim the same
  name or whether nginx loads pve-gateway's file at all; the red certificate status is clickable.

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
