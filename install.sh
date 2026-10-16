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
#   sh install.sh fix-repos           only switch apt from the Proxmox enterprise repos to no-subscription
#
# No Proxmox subscription? When apt answers 401 for enterprise.proxmox.com, the installer disables the
# enterprise repos and enables the free no-subscription ones (backup in /var/lib/pve-gateway/apt-backup).
# Use --keep-repos to leave apt sources untouched.
#
# PVE_GATEWAY_REF=<branch|tag> picks what to download (default: master).
set -e

REPO="https://raw.githubusercontent.com/farruxx/pve-gateway/${PVE_GATEWAY_REF:-master}"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

WITH_NGINX=""; DNS_PLUGIN=""; KEEP_REPOS=""; ACTION=install
while [ $# -gt 0 ]; do
    case "$1" in
        uninstall) ACTION=uninstall ;;
        fix-repos) ACTION=fix-repos ;;
        --keep-repos) KEEP_REPOS=1 ;;
        --with-nginx) WITH_NGINX=1 ;;
        --with-dns) shift; DNS_PLUGIN="$1"; WITH_NGINX=1 ;;
        -h|--help) sed -n '2,19p' "$0" 2>/dev/null || echo "see https://github.com/farruxx/pve-gateway"; exit 0 ;;
        *) echo "unknown option: $1"; exit 1 ;;
    esac
    shift
done

# >>> fix_repos
# Switch apt from the Proxmox enterprise repositories (need a subscription, else 401) to no-subscription.
# Handles PVE 8 (.list) and PVE 9 (deb822 .sources). Paths are overridable for testing.
APT_DIR="${APT_DIR:-/etc/apt/sources.list.d}"
APT_MAIN="${APT_MAIN:-/etc/apt/sources.list}"
PVEGW_STATE="${PVEGW_STATE:-/var/lib/pve-gateway}"
# true if the file still has an enabled entry pointing at enterprise.proxmox.com
enterprise_enabled() {
    case "$1" in
    *.sources) awk '
        function chk() { if (ent && !dis) found = 1; ent = 0; dis = 0 }
        /^[ \t]*$/ { chk(); next }
        /enterprise\.proxmox\.com/ { ent = 1 }
        /^Enabled:[ \t]*(no|false)/ { dis = 1 }
        END { chk(); exit !found }' "$1" ;;
    *) grep -qs "^[^#]*enterprise\.proxmox\.com" "$1" ;;
    esac
}

fix_repos() {
    bk="$PVEGW_STATE/apt-backup/$(date +%Y%m%d-%H%M%S)"
    repos=""; suite=""; deb822=""; key=""
    for f in "$APT_DIR"/*.list "$APT_DIR"/*.sources "$APT_MAIN"; do
        [ -f "$f" ] && enterprise_enabled "$f" || continue
        mkdir -p "$bk" && cp -p "$f" "$bk/"
        repos="$repos $(grep -o 'enterprise\.proxmox\.com/debian/[a-z0-9-]*' "$f" | sed 's#.*/debian/##' | tr '\n' ' ')"
        case "$f" in
        *.sources)
            deb822=1
            [ -n "$suite" ] || suite=$(sed -n 's/^Suites:[[:space:]]*\([a-z]*\).*/\1/p' "$f" | head -1)
            [ -n "$key" ] || key=$(sed -n 's/^Signed-By:[[:space:]]*//p' "$f" | head -1)
            # add "Enabled: no" to every stanza that points at enterprise.proxmox.com
            awk '
                function flush() { if (n) printf "%s", (ent ? keep "Enabled: no\n" : all); all = ""; keep = ""; n = 0; ent = 0 }
                /^[ \t]*$/ { flush(); print; next }
                { n = 1; all = all $0 "\n"; if ($0 !~ /^Enabled:/) keep = keep $0 "\n"; if ($0 ~ /enterprise\.proxmox\.com/) ent = 1 }
                END { flush() }' "$f" > "$f.pvegw" ;;
        *)
            [ -n "$suite" ] || suite=$(sed -n 's#^[[:space:]]*deb[[:space:]].*enterprise\.proxmox\.com/debian/[a-z0-9-]*[[:space:]]\{1,\}\([a-z]*\).*#\1#p' "$f" | head -1)
            sed 's#^[[:space:]]*deb[[:space:]].*enterprise\.proxmox\.com#\# disabled by pve-gateway (no subscription): &#' "$f" > "$f.pvegw" ;;
        esac
        cat "$f.pvegw" > "$f" && rm -f "$f.pvegw"
        echo "  disabled enterprise repo in $f"
    done
    [ -n "$repos" ] || return 1
    if [ -z "$suite" ]; then . /etc/os-release 2>/dev/null || true; suite="$VERSION_CODENAME"; fi
    [ -n "$key" ] || { [ -f /usr/share/keyrings/proxmox-archive-keyring.gpg ] && key=/usr/share/keyrings/proxmox-archive-keyring.gpg; }
    for r in $(echo "$repos" | tr ' ' '\n' | sort -u); do
        case "$r" in pve) comp=pve-no-subscription ;; ceph-*) comp=no-subscription ;; *) continue ;; esac
        if grep -rqs "^[^#]*download\.proxmox\.com/debian/$r\b" "$APT_DIR" "$APT_MAIN"; then continue; fi
        if [ -n "$deb822" ]; then
            out="$APT_DIR/proxmox-no-subscription.sources"
            [ -s "$out" ] && echo >> "$out"
            { echo "Types: deb"; echo "URIs: http://download.proxmox.com/debian/$r"; echo "Suites: $suite"
              echo "Components: $comp"; [ -n "$key" ] && echo "Signed-By: $key"; } >> "$out"
        else
            out="$APT_DIR/proxmox-no-subscription.list"
            echo "deb http://download.proxmox.com/debian/$r $suite $comp" >> "$out"
        fi
        echo "  added no-subscription repo: debian/$r $suite $comp ($out)"
    done
    echo "  backup of the previous files: $bk"
}
# <<< fix_repos

if [ "$ACTION" = fix-repos ]; then
    if fix_repos; then apt-get update; else echo "no enabled enterprise.proxmox.com repositories found - nothing to do"; fi
    exit 0
fi

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

# ---- source files: next to this script when it is run as a file (git clone), otherwise download them.
# Piped (curl | sh) $0 is "sh", so the current directory is never used - it may hold an old copy.
SRC=""
case "$0" in
    *install.sh)
        d="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
        [ -f "$d/pve-gateway.py" ] && [ -f "$d/pve-gateway.service" ] && SRC="$d" ;;
esac
if [ -z "$SRC" ]; then
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
    echo "updating package lists ..."
    apt-get update >"$LOG" 2>&1 || true
    if grep -q "enterprise\.proxmox\.com.*401" "$LOG"; then
        if [ -n "$KEEP_REPOS" ]; then
            echo "warning: no Proxmox subscription (401 from enterprise.proxmox.com) - keeping apt sources (--keep-repos)"
        else
            echo "no Proxmox subscription (401 from enterprise.proxmox.com) - switching to the no-subscription repositories:"
            fix_repos || true
            apt-get update >"$LOG" 2>&1 || true
        fi
    fi
    if grep -qE "^(E|Err):" "$LOG"; then
        echo "warning: apt-get update still reports errors (continuing):"
        grep -E "^(E|Err):" "$LOG" | head -5
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
echo "installed $(/usr/local/bin/pve-gateway --version 2>/dev/null) from ${SRC}"
echo "Open: https://${IP:-<host-ip>}:8099  (log in with root@pam)"
