#!/bin/sh
# Install / uninstall pve-gateway on a Proxmox VE host (run as root).
#
#   curl -fsSL https://raw.githubusercontent.com/farruxx/pve-gateway/master/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/farruxx/pve-gateway/master/install.sh | sh -s -- --with-nginx
#
#   sh install.sh                     install + start (uses the files next to this script, or downloads them)
#   sh install.sh --with-nginx        also install nginx + certbot (needed for the Domains tab)
#   sh install.sh --with-dns cloudflare
#                                     also install a certbot DNS plugin (wildcard certificates)
#   sh install.sh uninstall           stop, remove rules, nginx config and files (keeps /etc/pve-gateway)
#
# PVE_GATEWAY_REF=<branch|tag> picks what to download (default: master).
set -e

REPO="https://raw.githubusercontent.com/farruxx/pve-gateway/${PVE_GATEWAY_REF:-master}"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

WITH_NGINX=""; DNS_PLUGIN=""; ACTION=install
while [ $# -gt 0 ]; do
    case "$1" in
        uninstall) ACTION=uninstall ;;
        --with-nginx) WITH_NGINX=1 ;;
        --with-dns) shift; DNS_PLUGIN="$1"; WITH_NGINX=1 ;;
        -h|--help) sed -n '2,13p' "$0" 2>/dev/null || echo "see https://github.com/farruxx/pve-gateway"; exit 0 ;;
        *) echo "unknown option: $1"; exit 1 ;;
    esac
    shift
done

if [ "$ACTION" = uninstall ]; then
    systemctl disable --now pve-gateway 2>/dev/null || true
    [ -x /usr/local/bin/pve-gateway ] && /usr/local/bin/pve-gateway flush || true
    rm -f /usr/local/bin/pve-gateway /etc/systemd/system/pve-gateway.service /etc/sysctl.d/99-pve-gateway.conf
    if [ -f /etc/nginx/conf.d/pve-gateway.conf ]; then
        rm -f /etc/nginx/conf.d/pve-gateway.conf
        systemctl reload nginx 2>/dev/null || true
        echo "removed nginx domains config (certificates in /etc/letsencrypt are kept)"
    fi
    systemctl daemon-reload
    echo "uninstalled (config left in /etc/pve-gateway)"
    exit 0
fi

command -v python3  >/dev/null || { echo "python3 missing: apt install python3-minimal"; exit 1; }
command -v iptables >/dev/null || { echo "iptables missing: apt install iptables"; exit 1; }

# ---- source files: next to this script (git clone / scp), otherwise download them
SRC="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
if [ ! -f "$SRC/pve-gateway.py" ] || [ ! -f "$SRC/pve-gateway.service" ]; then
    SRC="$(mktemp -d)"
    trap 'rm -rf "$SRC"' EXIT
    echo "downloading pve-gateway (${PVE_GATEWAY_REF:-master}) ..."
    for f in pve-gateway.py pve-gateway.service; do
        if command -v curl >/dev/null; then
            curl -fsSL "$REPO/$f" -o "$SRC/$f"
        else
            wget -qO "$SRC/$f" "$REPO/$f"
        fi
    done
    python3 -m py_compile "$SRC/pve-gateway.py" || { echo "download looks broken"; exit 1; }
fi

# ---- optional packages (from Debian; an unreachable Proxmox enterprise repo must not stop us)
if [ -n "$WITH_NGINX" ]; then
    PKGS="nginx certbot"
    [ -n "$DNS_PLUGIN" ] && PKGS="$PKGS python3-certbot-dns-$DNS_PLUGIN"
    LOG="$(mktemp)"
    if ! apt-get update >"$LOG" 2>&1; then
        echo "warning: apt-get update reported errors (continuing):"
        grep -E "^(E|W):" "$LOG" | head -5
        if grep -q "enterprise.proxmox.com" "$LOG"; then
            echo "  -> the Proxmox enterprise repository needs a subscription. To get rid of this error, in the"
            echo "     Proxmox UI go to Node > Updates > Repositories: disable the 'enterprise' entries"
            echo "     (pve and ceph) and add the 'No-Subscription' repository."
        fi
    fi
    rm -f "$LOG"
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PKGS || {
        echo "could not install: $PKGS"
        echo "fix the apt repositories (see above), then run this again"
        exit 1
    }
    systemctl enable --now nginx
fi

# ---- migrate from the old name (pve-portfwd): config, credentials, ACME webroot, certbot renewal configs
if [ -e /etc/systemd/system/pve-portfwd.service ] || [ -d /etc/pve-portfwd ]; then
    echo "migrating from pve-portfwd ..."
    systemctl disable --now pve-portfwd 2>/dev/null || true
    [ -x /usr/local/bin/pve-portfwd ] && /usr/local/bin/pve-portfwd flush || true   # drop old PORTFWD_* chains
    if [ -d /etc/pve-portfwd ] && [ ! -e /etc/pve-gateway ]; then mv /etc/pve-portfwd /etc/pve-gateway; fi
    if [ -d /var/lib/pve-portfwd ] && [ ! -e /var/lib/pve-gateway ]; then mv /var/lib/pve-portfwd /var/lib/pve-gateway; fi
    if [ -d /etc/letsencrypt/renewal ]; then
        sed -i 's#/etc/pve-portfwd/#/etc/pve-gateway/#g; s#/var/lib/pve-portfwd/#/var/lib/pve-gateway/#g' /etc/letsencrypt/renewal/*.conf 2>/dev/null || true
    fi
    rm -f /etc/nginx/conf.d/pve-portfwd.conf   # regenerated as pve-gateway.conf on start
    rm -f /usr/local/bin/pve-portfwd /etc/systemd/system/pve-portfwd.service /etc/sysctl.d/99-pve-portfwd.conf
fi

install -m 0755 "$SRC/pve-gateway.py" /usr/local/bin/pve-gateway
install -m 0644 "$SRC/pve-gateway.service" /etc/systemd/system/pve-gateway.service
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-pve-gateway.conf
sysctl -q -p /etc/sysctl.d/99-pve-gateway.conf
install -d -m 0700 /etc/pve-gateway

systemctl daemon-reload
systemctl enable pve-gateway >/dev/null 2>&1
systemctl restart pve-gateway
sleep 1
systemctl --no-pager --lines=5 status pve-gateway || true

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "Open: https://${IP:-<host-ip>}:8099  (log in with root@pam)"
