#!/usr/bin/env python3
"""
pve-gateway - web UI that makes a Proxmox host the gateway for its guests:
forward ports (iptables DNAT) and route domains (nginx reverse proxy, Let's Encrypt
and wildcard certificates).

Zero dependencies: Python 3 standard library + iptables (both ship with Proxmox VE);
nginx + certbot only if you use domains.

Port rules live in their own iptables chains (PVEGW_PRE / PVEGW_POST / PVEGW_FWD)
and are swapped atomically with iptables-restore, so nothing else on the host
(pve-firewall, your own rules) is touched.

Usage:
  pve-gateway.py [serve]        run the web UI (default)
  pve-gateway.py apply          (re)apply saved rules and exit
  pve-gateway.py flush          remove all forwarding rules + chains
  pve-gateway.py passwd         set a local password (instead of Proxmox login)
  pve-gateway.py --dry-run ...  print iptables commands instead of running them
  pve-gateway.py --help         all commands (status, test, debug, domains, cert, ...)
"""
import argparse
import base64
import calendar
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.8.0"  # semantic version; bump it (and CHANGELOG.md) with every user-visible change
REPO_URL = "https://github.com/farruxx/pve-gateway"
REPO_RAW = "https://raw.githubusercontent.com/farruxx/pve-gateway"
CONF_DIR = os.environ.get("PVE_GATEWAY_DIR") or "/etc/pve-gateway"
CH_PRE, CH_POST, CH_FWD = "PVEGW_PRE", "PVEGW_POST", "PVEGW_FWD"
JUMPS = (("nat", "PREROUTING", CH_PRE), ("nat", "POSTROUTING", CH_POST), ("filter", "FORWARD", CH_FWD))

DEFAULTS = {
    "listen": "0.0.0.0",
    "port": 8099,
    # Web UI access: source IPs/networks allowed to connect (empty = anyone; loopback always works),
    # and extra hostnames the UI may be opened by (IP addresses and this host's own names always work).
    "ui_allow": [],
    "allowed_hosts": [],
    # Proxmox accounts allowed to log in (checked against the local PVE API).
    "allowed_users": ["root@pam"],
    # If set (via `passwd`), use a local password instead of Proxmox login.
    "local_user": "admin",
    "pass_hash": "",
    # Empty = reuse the Proxmox web certificate automatically.
    "cert": "",
    "key": "",
    # Ports that may never be forwarded away from the host (SSH, PVE UI, spice, rpcbind, corosync).
    "protected_ports": ["22", "8006", "3128", "111", "5405-5412"],
    # Add ACCEPT rules in FORWARD for forwarded traffic (needed if FORWARD policy is DROP).
    "forward_accept": True,
    "rules": [],
    # Domains: nginx reverse proxy (+ optional Let's Encrypt via certbot).
    "domains": [],
    "wildcards": [],  # wildcard certificates via DNS-01 (credentials in <config dir>/dns/<id>.ini)
    "acme_email": "",
    "nginx_conf": "/etc/nginx/conf.d/pve-gateway.conf",
    "acme_webroot": "/var/lib/pve-gateway/acme",
    "letsencrypt_dir": "/etc/letsencrypt/live",
    "nginx_ipv6": True,  # also listen on [::]:80/443
    # Updates: branch/tag on GitHub to check and install from; daily background check.
    "update_ref": "master",
    "update_check": True,
    "auto_update": False,  # install new versions automatically after the daily check
    # Monitoring: health checks of guests/domains and where to send alerts (secrets masked in the API/debug)
    "monitors": [],
    "alerts": {"email": "", "webhook": "", "telegram_token": "", "telegram_chat": "", "fail_after": 2, "cert_days": 14},
    # fail2ban: pve-gateway writes /etc/fail2ban/jail.d/pve-gateway.local only after "managed" is switched on
    # Host firewall (inbound): backend "custom" = pve-gateway's own iptables/ip6tables chain, "pve" = Proxmox firewall
    "firewall": {"backend": "custom", "enabled": False, "policy": "accept", "allow_ping": True, "rules": []},
    # WireGuard tunnels; private keys live in <config dir>/wireguard/*.key (0600), never in config.json
    "wireguard": {"tunnels": []},
    "fail2ban": {"managed": False, "bantime": "1h", "findtime": "10m", "maxretry": 5, "ignoreip": [],
                 "jails": {"sshd": True, "proxmox": True, "pve-gateway": True, "nginx-botsearch": True, "recidive": True}},
}

LOCK = threading.RLock()
STATE = {"cfg": None, "last_apply": None, "last_error": None}
SESSIONS = {}  # token -> [user, expires]
FAILS = {}     # ip -> [count, first_ts]
LOGIN_LOCK = threading.Lock()
LOGIN_INFLIGHT = set()   # IPs with a login being checked right now
TFA_PENDING = {}         # id -> {"user", "ticket", "ip", "exp"}
LOGIN_MAX_FAILS, LOGIN_WINDOW = 5, 900
SESSION_TTL = 8 * 3600
DRY_RUN = False
MOCK = None  # dev/mock.py instance when started with --mock (simulated host for local development)


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


# --------------------------------------------------------------------------- config

def conf_file():
    return os.path.join(CONF_DIR, "config.json")


def load_config():
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        with open(conf_file()) as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        pass
    try:
        cfg["ui_allow"] = parse_networks(cfg.get("ui_allow", []))
    except ApiError as e:
        log("ignoring invalid ui_allow (%s) - web UI is open to everyone" % e, "warn")
        cfg["ui_allow"] = []
    try:
        cfg["allowed_hosts"] = parse_hostnames(cfg.get("allowed_hosts", []))
    except ApiError as e:
        log("ignoring invalid allowed_hosts (%s)" % e, "warn")
        cfg["allowed_hosts"] = []
    rules = []
    for r in cfg.get("rules", []):
        try:
            rules.append(validate_rule(r, [], cfg, r.get("id")))
        except (ApiError, ValueError) as e:
            log("skipping invalid rule %r: %s" % (r.get("name") or r.get("id"), e), "warn")
    cfg["rules"] = rules
    wildcards = []
    for w in cfg.get("wildcards", []):
        try:
            wildcards.append(validate_wildcard(w, wildcards, w.get("id")))
        except (ApiError, ValueError) as e:
            log("skipping invalid wildcard %r: %s" % (w.get("zone") or w.get("id"), e), "warn")
    cfg["wildcards"] = wildcards
    mons = []
    for m in cfg.get("monitors", []):
        try:
            mons.append(validate_monitor(m, mons, m.get("id")))
        except (ApiError, ValueError) as e:
            log("skipping invalid check %r: %s" % (m.get("name") or m.get("id"), e), "warn")
    cfg["monitors"] = mons
    cfg["alerts"] = dict(DEFAULTS["alerts"], **(cfg.get("alerts") or {}))
    try:
        cfg["firewall"] = validate_fw(dict(DEFAULTS["firewall"], **(cfg.get("firewall") or {})),
                                      json.loads(json.dumps(DEFAULTS["firewall"])), cfg)
    except ApiError as e:
        log("firewall settings invalid (%s) - firewall disabled" % e, "error")
        cfg["firewall"] = json.loads(json.dumps(DEFAULTS["firewall"]))
    wg = {"tunnels": []}
    for t in (cfg.get("wireguard") or {}).get("tunnels", []):
        try:
            nt = validate_wg_tunnel(t, wg["tunnels"], cfg, t.get("id"))
            nt["public_key"] = t.get("public_key", "")
            for p in t.get("peers", []):
                np_ = validate_wg_peer(p, nt, p.get("id"))
                np_["public_key"] = p.get("public_key", "")
                nt["peers"].append(np_)
            wg["tunnels"].append(nt)
        except (ApiError, ValueError) as e:
            log("skipping invalid WireGuard tunnel %r: %s" % (t.get("name"), e), "warn")
    cfg["wireguard"] = wg
    f2b = json.loads(json.dumps(DEFAULTS["fail2ban"]))
    f2b.update({k: v for k, v in (cfg.get("fail2ban") or {}).items() if k != "jails"})
    f2b["jails"].update((cfg.get("fail2ban") or {}).get("jails") or {})
    try:
        cfg["fail2ban"] = validate_f2b(f2b, json.loads(json.dumps(DEFAULTS["fail2ban"])))
    except ApiError as e:
        log("ignoring invalid fail2ban settings: %s" % e, "warn")
        cfg["fail2ban"] = json.loads(json.dumps(DEFAULTS["fail2ban"]))
    domains = []
    for d in cfg.get("domains", []):
        try:
            domains.append(validate_domain(d, domains, cfg, d.get("id"), check_rules=False))
        except (ApiError, ValueError) as e:
            log("skipping invalid domain %r: %s" % (d.get("domain") or d.get("id"), e), "warn")
    cfg["domains"] = domains
    return cfg


def save_config(cfg):
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    tmp = conf_file() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, conf_file())


LOGS = deque(maxlen=500)  # recent log lines, shown in the Debug tab
VERBOSE = False           # log every command / request (toggle: --verbose or Debug tab)


def log(msg, level="info"):
    if level == "debug" and not VERBOSE:
        return
    LOGS.append("%s %-5s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), level.upper(), msg))
    sys.stderr.write("[pve-gateway] %s%s\n" % ("" if level == "info" else level.upper() + ": ", msg))
    sys.stderr.flush()


# --------------------------------------------------------------------------- validation

NAME_RE = re.compile(r"^[A-Za-z0-9 _.:/@+-]{0,40}$")
PORT_RE = re.compile(r"^(\d{1,5})(?:[-:](\d{1,5}))?$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$")  # no leading "-": it is an iptables argument
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def _as_list(v):
    return re.split(r"[\s,]+", v) if isinstance(v, str) else list(v or [])


def parse_networks(v):
    """IP addresses / CIDRs (IPv4 or IPv6) -> normalised list."""
    out = []
    for x in _as_list(v):
        x = str(x).strip()
        if not x:
            continue
        try:
            n = str(ipaddress.ip_network(x, strict=False))
        except ValueError:
            raise ApiError("invalid IP address or network '%s' (e.g. 203.0.113.7 or 10.20.0.0/24)" % x)
        if n not in out:
            out.append(n)
    return out


def parse_hostnames(v):
    out = []
    for x in _as_list(v):
        x = str(x).strip().lower().rstrip(".")
        if not x:
            continue
        if not HOSTNAME_RE.match(x):
            raise ApiError("invalid hostname '%s'" % x)
        if x not in out:
            out.append(x)
    return out


def norm_ip(ip):
    """'::ffff:1.2.3.4' -> '1.2.3.4' (dual-stack sockets)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(a.ipv4_mapped) if getattr(a, "ipv4_mapped", None) else str(a)


def ui_client_allowed(ip, cfg):
    """Web UI source filter. Loopback always works (ssh tunnel / recovery)."""
    try:
        a = ipaddress.ip_address(norm_ip(ip))
    except ValueError:
        return False
    if a.is_loopback or not cfg.get("ui_allow"):
        return True
    return any(a in ipaddress.ip_network(n) for n in cfg["ui_allow"])


def own_hostnames():
    names = {"localhost"}
    hn = socket.gethostname().lower()
    names |= {hn, hn.split(".")[0]}
    try:
        names.add(socket.getfqdn().lower())
    except OSError:
        pass
    return {n for n in names if n and not n.endswith(".arpa")}  # getfqdn() may return a reverse-DNS name


def host_allowed(host, cfg):
    """Host header check against DNS rebinding: IP literals, this host's names, allowed_hosts."""
    h = (host or "").strip().lower()
    if not h:
        return True  # no browser omits Host; scripts (HTTP/1.0) may
    if h.startswith("["):
        h = h[1:h.find("]")] if "]" in h else h
    elif h.count(":") == 1:
        h = h.split(":")[0]
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    h = h.rstrip(".")
    return h in own_hostnames() or h in cfg.get("allowed_hosts", [])


def parse_ports(s):
    m = PORT_RE.match(str(s).strip())
    if not m:
        raise ApiError("invalid port '%s' (use 8080 or 8000-8010)" % s)
    a, b = int(m.group(1)), int(m.group(2) or m.group(1))
    if not 1 <= a <= b <= 65535:
        raise ApiError("port out of range: %s" % s)
    return a, b


def protos(p):
    return ["tcp", "udp"] if p == "both" else [p]


def validate_rule(data, others, cfg, rid=None):
    if not isinstance(data, dict):
        raise ApiError("rule must be an object")
    r = {"id": rid or uuid.uuid4().hex[:8]}
    if not re.match(r"^[0-9a-f]{1,16}$", r["id"]):
        raise ApiError("invalid id")

    r["name"] = str(data.get("name", "")).strip()
    if not NAME_RE.match(r["name"]):
        raise ApiError("name: max 40 chars, letters/digits/space/_.:/@+- only")

    r["enabled"] = bool(data.get("enabled", True))
    r["proto"] = str(data.get("proto", "tcp")).lower()
    if r["proto"] not in ("tcp", "udp", "both"):
        raise ApiError("protocol must be tcp, udp or both")

    ea, eb = parse_ports(data.get("ext_port", ""))
    r["ext_port"] = str(ea) if ea == eb else "%d-%d" % (ea, eb)

    try:
        ip = ipaddress.IPv4Address(str(data.get("ip", "")).strip())
    except ValueError:
        raise ApiError("destination must be an IPv4 address")
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise ApiError("destination IP is not usable")
    r["ip"] = str(ip)

    ip_port = str(data.get("int_port", "") or "").strip()
    if ip_port:
        ia, ib = parse_ports(ip_port)
        if ia != ib:
            raise ApiError("destination port must be a single port (leave empty to keep the same ports)")
        if ea != eb:
            raise ApiError("for a port range leave the destination port empty (ports are kept as-is)")
        ip_port = str(ia)
    r["int_port"] = ip_port

    src = str(data.get("source", "") or "").strip()
    if src:
        try:
            src = str(ipaddress.IPv4Network(src, strict=False))
        except ValueError:
            raise ApiError("source must be an IPv4 address or CIDR, e.g. 203.0.113.0/24")
    r["source"] = src

    iface = str(data.get("iface", "") or "").strip()
    if iface and not IFACE_RE.match(iface):
        raise ApiError("invalid interface name")
    r["iface"] = iface
    r["masq"] = bool(data.get("masq", False))

    # never hijack ports the host itself needs
    for p in list(cfg.get("protected_ports", [])) + [str(cfg.get("port", 8099))]:
        pa, pb = parse_ports(p)
        if ea <= pb and pa <= eb:
            raise ApiError("external port %s overlaps protected host port %s" % (r["ext_port"], p))
    if r["enabled"] and any(d["enabled"] for d in cfg.get("domains", [])) and "tcp" in protos(r["proto"]):
        for p in (80, 443):
            if ea <= p <= eb:
                raise ApiError("port %d is used by nginx for your domains - add a domain instead of a port rule" % p)

    if r["enabled"]:
        for o in others:
            if not o["enabled"]:
                continue
            oa, ob = parse_ports(o["ext_port"])
            same_proto = set(protos(o["proto"])) & set(protos(r["proto"]))
            same_if = not o["iface"] or not r["iface"] or o["iface"] == r["iface"]
            same_src = not o["source"] or not r["source"] or o["source"] == r["source"]
            if same_proto and same_if and same_src and ea <= ob and oa <= eb:
                raise ApiError("port %s conflicts with rule '%s' (%s)" % (r["ext_port"], o["name"] or o["id"], o["ext_port"]))
    return r


# --------------------------------------------------------------------------- iptables

def run(cmd, data=None, check_only=False, timeout=30):
    """Run a command. check_only=True: a non-zero exit is an expected answer, not an error."""
    line = " ".join(cmd)
    if DRY_RUN and not check_only:  # read-only queries (check_only) still run for real
        log("[dry-run] $ %s%s" % (line, "\n" + data.rstrip() if data else ""))
        return 0, ""
    t = time.time()
    if MOCK:
        rc, out = MOCK.exec(cmd, data)
    else:
        try:
            p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=timeout)
            rc = p.returncode
            out = (p.stdout if rc == 0 else "\n".join(x for x in (p.stderr.strip(), p.stdout.strip()) if x)).strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            rc, out = 1, str(e)
    if rc != 0 and not check_only:
        log("$ %s -> exit %d: %s" % (line, rc, out), "warn")
    else:
        log("$ %s -> exit %d (%dms)%s" % (line, rc, (time.time() - t) * 1000,
                                         ("\n" + data.rstrip()) if data else ""), "debug")
    return rc, out


def sh(cmd, timeout=10):
    """Read-only diagnostic command: returns (rc, combined output)."""
    if MOCK:
        return MOCK.exec(cmd)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=timeout)
        return p.returncode, p.stdout.rstrip() or "(no output, exit %d)" % p.returncode
    except FileNotFoundError:
        return 127, "(command not found: %s)" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "(timed out after %ss)" % timeout


def view_wants_ports(handler):
    """port_checks() runs several commands - only when the Domains tab asks for it (?ports=1)."""
    return "ports=1" in (urllib.parse.urlsplit(handler.path).query or "")


def owns_web_ports(cfg):
    return any(d["enabled"] for d in cfg.get("domains", []))


def build_ruleset(cfg):
    nat = ["*nat", ":%s - [0:0]" % CH_PRE, ":%s - [0:0]" % CH_POST]
    flt = ["*filter", ":%s - [0:0]" % CH_FWD]
    if owns_web_ports(cfg):
        # Domains: 80/443 to this host belong to nginx here. ACCEPT in nat PREROUTING ends NAT processing, so a DNAT
        # rule from another tool further down can't forward these ports to a guest. (Our hook is kept at #1.)
        nat.append('-A %s -p tcp -m addrtype --dst-type LOCAL -m multiport --dports 80,443 '
                   '-m comment --comment "gw:domains" -j ACCEPT' % CH_PRE)
    for t in cfg.get("wireguard", {}).get("tunnels", []):
        if t["enabled"]:  # VPN clients may reach guests; replies come back as established traffic
            net = str(ipaddress.ip_interface(t["address"]).network)
            flt.append('-A %s -i %s -m comment --comment "gw:wg" -j ACCEPT' % (CH_FWD, t["name"]))
            flt.append('-A %s -o %s -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "gw:wg" -j ACCEPT'
                       % (CH_FWD, t["name"]))
            if t["nat"]:  # guests see the host's bridge address, so they don't need a route back to the VPN
                nat.append('-A %s -s %s ! -d %s -m comment --comment "gw:wg" -j MASQUERADE' % (CH_POST, net, net))
    for r in cfg["rules"]:
        if not r["enabled"]:
            continue
        ea, eb = parse_ports(r["ext_port"])
        dport = str(ea) if ea == eb else "%d:%d" % (ea, eb)
        to = "%s:%s" % (r["ip"], r["int_port"]) if r["int_port"] else r["ip"]
        iport = r["int_port"] or dport
        cm = '-m comment --comment "gw:%s"' % r["id"]
        for p in protos(r["proto"]):
            pre = "-A %s -p %s" % (CH_PRE, p)
            if r["iface"]:
                pre += " -i " + r["iface"]
            if r["source"]:
                pre += " -s " + r["source"]
            # only traffic addressed to the host itself - never hijack guests' outbound traffic
            pre += " -m addrtype --dst-type LOCAL -m %s --dport %s %s -j DNAT --to-destination %s" % (p, dport, cm, to)
            nat.append(pre)
            if r["masq"]:
                nat.append("-A %s -d %s/32 -p %s -m %s --dport %s -m conntrack --ctstate DNAT %s -j MASQUERADE"
                           % (CH_POST, r["ip"], p, p, iport, cm))
            if cfg.get("forward_accept", True):
                flt.append("-A %s -d %s/32 -p %s -m %s --dport %s -m conntrack --ctstate DNAT %s -j ACCEPT"
                           % (CH_FWD, r["ip"], p, p, iport, cm))
                flt.append("-A %s -s %s/32 -p %s -m %s --sport %s -m conntrack --ctstate DNAT %s -j ACCEPT"
                           % (CH_FWD, r["ip"], p, p, iport, cm))
    return "\n".join(nat + ["COMMIT"] + flt + ["COMMIT"]) + "\n"


def ensure_ip_forward():
    path = "/proc/sys/net/ipv4/ip_forward"
    if MOCK and not MOCK.ip_forward:
        MOCK.ip_forward = True
        log("enabled net.ipv4.ip_forward")
    if MOCK or DRY_RUN or not os.path.exists(path):
        return
    with open(path) as f:
        if f.read().strip() == "1":
            return
    with open(path, "w") as f:
        f.write("1")
    log("enabled net.ipv4.ip_forward")


def apply_rules(cfg=None):
    """Atomically replace our chains. Returns error string or None."""
    with LOCK:
        cfg = cfg or STATE["cfg"]
        rc, out = run(["iptables-restore", "--noflush"], build_ruleset(cfg))
        if rc != 0:
            STATE["last_error"] = "iptables-restore failed: " + out
            log(STATE["last_error"], "error")
            return STATE["last_error"]
        for table, chain, target in JUMPS:
            if run(["iptables", "-t", table, "-C", chain, "-j", target], check_only=True)[0] != 0:
                rc, out = run(["iptables", "-t", table, "-I", chain, "1", "-j", target])
                if rc != 0:
                    STATE["last_error"] = "cannot hook %s/%s: %s" % (table, chain, out)
                    log(STATE["last_error"], "error")
                    return STATE["last_error"]
        if owns_web_ports(cfg) and not DRY_RUN and hook_position("nat", "PREROUTING", CH_PRE) not in (None, 1):
            # a DNAT above our hook would still forward 80/443 away from nginx
            log("moving pve-gateway's nat hook to the top of PREROUTING (ports 80/443 belong to nginx here)", "warn")
            run(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", CH_PRE])
            run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", CH_PRE])
        try:
            ensure_ip_forward()
        except OSError as e:
            STATE["last_error"] = "cannot enable ip_forward: %s" % e
            return STATE["last_error"]
        STATE["last_apply"] = time.time()
        STATE["last_error"] = None
        log("applied %d rule(s)" % sum(r["enabled"] for r in cfg["rules"]))
        return None


def flush_rules():
    for table, chain, target in JUMPS:
        while run(["iptables", "-t", table, "-D", chain, "-j", target])[0] == 0 and not DRY_RUN:
            pass
        run(["iptables", "-t", table, "-F", target])
        run(["iptables", "-t", table, "-X", target])


def hooks_active():
    return all(run(["iptables", "-t", t, "-C", c, "-j", tg], check_only=True)[0] == 0 for t, c, tg in JUMPS)


def counters():
    res = {}
    rc, out = run(["iptables-save", "-c", "-t", "nat"], check_only=True)
    if rc != 0:
        return res
    for line in out.splitlines():
        m = re.match(r"^\[(\d+):(\d+)\] -A %s .*gw:([0-9a-f]+)(?![0-9a-z])" % CH_PRE, line)
        if m:
            c = res.setdefault(m.group(3), [0, 0])
            c[0] += int(m.group(1))
            c[1] += int(m.group(2))
    return res


def ip_forward_on():
    if MOCK:
        return MOCK.ip_forward
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except OSError:
        return DRY_RUN


def watchdog():
    """Re-hook our chains if something (iptables -F, network restart) removed them."""
    tick = 0
    while True:
        time.sleep(10 if MOCK else 30)
        tick += 1
        try:
            if not DRY_RUN and not hooks_active():
                log("hooks missing (iptables flushed?), re-applying rules", "warn")
                apply_rules()
            fw = STATE["cfg"]["firewall"]
            if not DRY_RUN and fw["enabled"] and fw["backend"] == "custom" and \
                    run(["iptables", "-C", "INPUT", "-j", CH_IN], check_only=True)[0] != 0:
                log("firewall hook missing, re-applying", "warn")
                apply_fw(STATE["cfg"])
            if not DRY_RUN and owns_web_ports(STATE["cfg"]) and hook_position("nat", "PREROUTING", CH_PRE) not in (None, 1):
                # another tool inserted rules above ours; they could DNAT 80/443 away from nginx
                log("moving pve-gateway's nat hook back to the top of PREROUTING", "warn")
                with LOCK:
                    run(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", CH_PRE])
                    run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", CH_PRE])
            # every ~5 min: another nginx site bound to a specific IP (installed later) would hide our domains
            if tick % 10 == 0 and any(d["enabled"] for d in STATE["cfg"]["domains"]) and \
                    explicit_listens(nginx_sites(STATE["cfg"])) != NGINX.get("extra"):
                log("another nginx site changed its listen addresses, re-applying domains", "warn")
                apply_nginx()
        except Exception as e:
            log("watchdog: %s" % e, "error")


# --------------------------------------------------------------------------- guests / interfaces

GUEST_CACHE = {"t": 0, "data": []}


def list_ifaces():
    if MOCK:
        return MOCK.ifaces()
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []
    skip = ("lo", "fwbr", "fwpr", "fwln", "tap", "veth", "docker")
    return [n for n in names if not n.startswith(skip) and os.path.isdir(os.path.join("/sys/class/net", n))]


IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
NET_CACHE = {"t": 0, "data": None}


def host_networks():
    """Host IPv4 addresses per interface, flagging public ones and the default-route (WAN) interface."""
    if NET_CACHE["data"] is not None and time.time() - NET_CACHE["t"] < 30:
        return NET_CACHE["data"]
    rc, out = sh(["ip", "-4", "-br", "addr"])
    wan = set()
    rc2, routes = sh(["ip", "-4", "route"])
    for line in routes.splitlines() if rc2 == 0 else []:
        m = re.match(r"^default\b.*\bdev (\S+)", line)
        if m:
            wan.add(m.group(1))
    skip = ("lo", "fwbr", "fwpr", "fwln", "tap", "veth", "docker")
    nets = []
    for f in (line.split() for line in out.splitlines()) if rc == 0 else []:
        name = f[0].split("@")[0] if f else ""
        if len(f) < 3 or name.startswith(skip):
            continue
        for cidr in f[2:]:
            try:
                itf = ipaddress.IPv4Interface(cidr)
            except ValueError:
                continue
            nets.append({"iface": name, "state": f[1], "cidr": cidr, "ip": str(itf.ip),
                         "network": str(itf.network), "public": itf.ip.is_global, "wan": name in wan})
    nets.sort(key=lambda n: (not n["wan"], n["iface"]))
    NET_CACHE.update(t=time.time(), data=nets)
    return nets


def host_ipv6():
    """Public (global) IPv6 addresses of the host."""
    rc, out = sh(["ip", "-6", "-br", "addr"])
    res = []
    for f in (line.split() for line in out.splitlines()) if rc == 0 else []:
        for cidr in f[2:]:
            try:
                a = ipaddress.IPv6Interface(cidr).ip
            except ValueError:
                continue
            if a.is_global:
                res.append(str(a))
    return res


def neighbors():
    """{mac: [ipv4, ...]} from the host's ARP table - finds guests without a guest agent."""
    rc, out = sh(["ip", "-4", "neigh"])
    res = {}
    for line in out.splitlines() if rc == 0 else []:
        m = re.match(r"^(\S+) dev \S+ lladdr ([0-9a-f:]{17}) (\S+)", line.strip(), re.I)
        if m and m.group(3) not in ("FAILED", "INCOMPLETE"):
            res.setdefault(m.group(2).lower(), []).append(m.group(1))
    return res


ARP_SWEEP = {"t": 0}


def arp_sweep():
    """Make the kernel ARP every address on the host's private bridges (one empty UDP datagram each), so guests
    that never talk to the host itself - e.g. behind a router VM - show up in `ip neigh`. At most every 5 min."""
    if MOCK:
        return MOCK.arp_sweep()
    if time.time() - ARP_SWEEP["t"] < 300:
        return False
    ARP_SWEEP["t"] = time.time()
    sent = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    try:
        for n in host_networks():
            net = ipaddress.IPv4Network(n["network"])
            if n["public"] or n["wan"] or net.num_addresses > 1024:  # guest bridges only, never the uplink
                continue
            for ip in net.hosts():
                if str(ip) != n["ip"]:
                    try:
                        s.sendto(b"", (str(ip), 9))  # discard port; only the ARP lookup matters
                        sent += 1
                    except OSError:
                        pass
    finally:
        s.close()
    if sent:
        log("arp sweep: probed %d addresses on guest bridges" % sent, "debug")
        time.sleep(1.5)  # let ARP replies arrive
    return sent > 0


def _clean(ips):
    return [i for i in dict.fromkeys(ips) if IPV4_RE.match(i) and not i.startswith(("127.", "169.254."))]


def _guest_ips(g, neigh, ipam=None):
    """{"ips", "source", "hint"}: guest agent / lxc first, then ARP by MAC, SDN IPAM by MAC, then static config."""
    ipam = ipam or {}
    vmid, running = str(g["vmid"]), g.get("status") == "running"
    if g["type"] == "lxc":
        if running:
            rc, out = run(["lxc-info", "-n", vmid, "-iH"], check_only=True)
            ips = _clean(out.split()) if rc == 0 else []
            if ips:
                return {"ips": ips, "source": "lxc", "hint": ""}
        rc, out = run(["pct", "config", vmid], check_only=True)
        ips = _clean(re.findall(r"\bip=(\d+\.\d+\.\d+\.\d+)", out)) if rc == 0 else []
        if not ips and rc == 0:
            ips = _clean(ip for mac in re.findall(r"hwaddr=([0-9A-Fa-f:]{17})", out) for ip in ipam.get(mac.lower(), []))
            if ips:
                return {"ips": ips, "source": "ipam", "hint": ""}
        return {"ips": ips, "source": "config" if ips else None,
                "hint": "" if ips else "container uses DHCP and is not running"}
    rc, conf = run(["qm", "config", vmid], check_only=True)
    conf = conf if rc == 0 else ""
    agent = bool(re.search(r"^agent:\s*(1|enabled=1)", conf, re.M))
    macs = [m.lower() for m in re.findall(r"^net\d+:\s*\w+=([0-9A-Fa-f:]{17})", conf, re.M)]
    if running and agent:
        rc, out = run(["timeout", "3", "qm", "guest", "cmd", vmid, "network-get-interfaces"], check_only=True)
        ips = []
        if rc == 0:
            try:
                ips = _clean(a["ip-address"] for itf in json.loads(out) for a in itf.get("ip-addresses", [])
                             if a.get("ip-address-type") == "ipv4")
            except (ValueError, KeyError, TypeError):
                pass
        if ips:
            return {"ips": ips, "source": "agent", "hint": ""}
    if running:
        ips = _clean(ip for mac in macs for ip in neigh.get(mac, []))
        if ips:
            return {"ips": ips, "source": "arp", "hint": ""}
    ips = _clean(ip for mac in macs for ip in ipam.get(mac, []))
    if ips:
        return {"ips": ips, "source": "ipam", "hint": ""}
    ips = _clean(re.findall(r"^ipconfig\d+:.*\bip=(\d+\.\d+\.\d+\.\d+)", conf, re.M))
    if ips:
        return {"ips": ips, "source": "cloud-init", "hint": ""}
    if not running:
        hint = "VM is stopped"
    elif not agent:
        hint = "install qemu-guest-agent in the VM and enable Options > QEMU Guest Agent (or type the IP)"
    else:
        hint = "guest agent not responding - is qemu-guest-agent running inside the VM?"
    return {"ips": [], "source": None, "hint": hint}


def list_guests():
    if time.time() - GUEST_CACHE["t"] < 30:
        return GUEST_CACHE["data"]
    rc, out = run(["pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"], check_only=True)
    if rc != 0:
        return []
    node = socket.gethostname().split(".")[0]
    try:
        items = [g for g in json.loads(out) if g.get("node") == node and not g.get("template")]
    except ValueError:
        return []
    neigh = neighbors()
    ipam = {}
    for e in sdn_ipam() if SDN_CACHE["data"] is None or SDN_CACHE["data"]["available"] else []:
        if e["mac"]:
            ipam.setdefault(e["mac"], []).append(e["ip"])
    with ThreadPoolExecutor(8) as ex:
        found = list(ex.map(lambda g: _guest_ips(g, neigh, ipam), items))
        missing = [i for i, (g, f) in enumerate(zip(items, found))
                   if not f["ips"] and g["type"] == "qemu" and g.get("status") == "running"]
        if missing and arp_sweep():
            neigh = neighbors()
            for i, f in zip(missing, ex.map(lambda i: _guest_ips(items[i], neigh, ipam), missing)):
                found[i] = f
    data = sorted((dict({"vmid": g["vmid"], "name": g.get("name", ""), "type": g["type"],
                         "status": g.get("status", "")}, **f) for g, f in zip(items, found)),
                  key=lambda x: x["vmid"])
    GUEST_CACHE.update(t=time.time(), data=data)
    return data


# --------------------------------------------------------------------------- domains (nginx)

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[a-z]{2,}$", re.I)
BODY_RE = re.compile(r"^\d{1,5}[kmg]?$")
NGINX = {"last_apply": None, "last_error": None}
CERT_JOBS = {}    # domain id -> {"state": "pending"|"ok"|"error", "msg": str, "t": ts}
CERT_CACHE = {}   # cert name -> (checked_at, info)


def _names(d):
    return [d["domain"]] + d["aliases"]


def validate_domain(data, others, cfg, did=None, check_rules=True):
    if not isinstance(data, dict):
        raise ApiError("domain must be an object")
    d = {"id": did or uuid.uuid4().hex[:8]}
    if not re.match(r"^[0-9a-f]{1,16}$", d["id"]):
        raise ApiError("invalid id")
    d["domain"] = str(data.get("domain", "")).strip().lower().rstrip(".")
    if not DOMAIN_RE.match(d["domain"]):
        raise ApiError("invalid domain name '%s' (e.g. cloud.example.com)" % d["domain"])
    aliases = data.get("aliases", [])
    if isinstance(aliases, str):
        aliases = re.split(r"[\s,]+", aliases)
    d["aliases"] = []
    for a in aliases:
        a = str(a).strip().lower().rstrip(".")
        if not a or a == d["domain"] or a in d["aliases"]:
            continue
        if not DOMAIN_RE.match(a):
            raise ApiError("invalid alias '%s'" % a)
        d["aliases"].append(a)
    if len(d["aliases"]) > 20:
        raise ApiError("max 20 aliases")
    try:
        ip = ipaddress.IPv4Address(str(data.get("ip", "")).strip())
    except ValueError:
        raise ApiError("target must be an IPv4 address")
    if ip.is_multicast or ip.is_unspecified:
        raise ApiError("target IP is not usable")
    d["ip"] = str(ip)
    try:
        d["port"] = int(data.get("port", 80))
    except (TypeError, ValueError):
        raise ApiError("target port must be a number")
    if not 1 <= d["port"] <= 65535:
        raise ApiError("target port out of range")
    d["upstream_https"] = bool(data.get("upstream_https", False))
    d["tls"] = str(data.get("tls", "none"))
    if d["tls"] not in ("none", "letsencrypt", "wildcard"):
        raise ApiError("tls must be 'none', 'letsencrypt' or 'wildcard'")
    d["force_https"] = bool(data.get("force_https", True))
    d["alias_redirect"] = bool(data.get("alias_redirect", False))  # aliases 301 to the main domain instead of serving
    d["cloudflare"] = bool(data.get("cloudflare", False))          # behind Cloudflare proxy: trust CF-Connecting-IP
    d["headers"] = bool(data.get("headers", False))                # nosniff / frame / referrer headers
    d["hsts"] = bool(data.get("hsts", False))
    d["max_body"] = str(data.get("max_body", "100m") or "100m").strip().lower()
    if not BODY_RE.match(d["max_body"]):
        raise ApiError("max upload size: number with optional k/m/g, 0 = unlimited (e.g. 100m)")
    src = data.get("source", [])
    if isinstance(src, str):
        src = re.split(r"[\s,]+", src)
    d["source"] = []
    for c in src:
        c = str(c).strip()
        if c:
            try:
                d["source"].append(str(ipaddress.ip_network(c, strict=False)))
            except ValueError:
                raise ApiError("invalid source '%s' (IP or CIDR)" % c)
    d["enabled"] = bool(data.get("enabled", True))

    taken = {n: o for o in others for n in _names(o)}
    for n in _names(d):
        if n in taken:
            raise ApiError("%s is already used by domain %s" % (n, taken[n]["domain"]))
    if check_rules and d["enabled"] and d["tls"] == "wildcard" and not wildcard_for(cfg, d):
        raise ApiError("no wildcard certificate covers %s - add one for its parent zone (a wildcard covers one level: "
                       "*.example.com matches a.example.com, not a.b.example.com)" % ", ".join(_names(d)))
    if check_rules and d["enabled"]:
        for r in cfg.get("rules", []):
            if r["enabled"] and "tcp" in protos(r["proto"]):
                ea, eb = parse_ports(r["ext_port"])
                for p in (80, 443):
                    if ea <= p <= eb:
                        raise ApiError("port rule '%s' (%s) forwards port %d away from nginx - disable it first"
                                       % (r["name"] or r["id"], r["ext_port"], p))
    return d


# DNS-01 providers: certbot plugin "dns-<key>" from Debian package, credentials written to an .ini file
DNS_PROVIDERS = {
    "cloudflare": {"label": "Cloudflare", "package": "python3-certbot-dns-cloudflare",
                   "help": "API token with Zone / DNS / Edit permission for the zone",
                   "fields": [{"key": "dns_cloudflare_api_token", "label": "API token", "secret": True}]},
    "digitalocean": {"label": "DigitalOcean", "package": "python3-certbot-dns-digitalocean",
                     "help": "Personal access token with write scope",
                     "fields": [{"key": "dns_digitalocean_token", "label": "API token", "secret": True}]},
    "linode": {"label": "Linode / Akamai", "package": "python3-certbot-dns-linode", "extra": {"dns_linode_version": "4"},
               "help": "Personal access token with Domains read/write",
               "fields": [{"key": "dns_linode_key", "label": "API token", "secret": True}]},
    "dnsimple": {"label": "DNSimple", "package": "python3-certbot-dns-dnsimple", "help": "Account API token",
                 "fields": [{"key": "dns_dnsimple_token", "label": "API token", "secret": True}]},
    "ovh": {"label": "OVH", "package": "python3-certbot-dns-ovh",
            "help": "Create keys at https://api.ovh.com/createToken/ with GET/POST/PUT/DELETE on /domain/zone/*",
            "fields": [{"key": "dns_ovh_endpoint", "label": "Endpoint", "default": "ovh-eu"},
                       {"key": "dns_ovh_application_key", "label": "Application key", "secret": True},
                       {"key": "dns_ovh_application_secret", "label": "Application secret", "secret": True},
                       {"key": "dns_ovh_consumer_key", "label": "Consumer key", "secret": True}]},
    "rfc2136": {"label": "RFC 2136 (BIND, PowerDNS, Knot...)", "package": "python3-certbot-dns-rfc2136",
                "help": "Dynamic DNS updates signed with a TSIG key",
                "fields": [{"key": "dns_rfc2136_server", "label": "DNS server IP"},
                           {"key": "dns_rfc2136_port", "label": "Port", "default": "53"},
                           {"key": "dns_rfc2136_name", "label": "TSIG key name"},
                           {"key": "dns_rfc2136_secret", "label": "TSIG secret", "secret": True},
                           {"key": "dns_rfc2136_algorithm", "label": "Algorithm", "default": "HMAC-SHA512"}]},
}


def covers(zone, name):
    """A wildcard cert for zone covers the zone itself and exactly one label below it."""
    return name == zone or (name.endswith("." + zone) and "." not in name[:-len(zone) - 1])


def wildcard_for(cfg, d):
    return next((w for w in cfg.get("wildcards", []) if w["enabled"] and all(covers(w["zone"], n) for n in _names(d))), None)


def wc_cert_name(w):
    return "wildcard." + w["zone"]


def domain_cert(cfg, d):
    """(certbot cert name, CERT_JOBS key) used by a domain, or (None, None)."""
    if d["tls"] == "letsencrypt":
        return d["domain"], d["id"]
    if d["tls"] == "wildcard":
        w = wildcard_for(cfg, d)
        if w:
            return wc_cert_name(w), w["id"]
    return None, None


def validate_wildcard(data, others, wid=None):
    if not isinstance(data, dict):
        raise ApiError("wildcard must be an object")
    w = {"id": wid or uuid.uuid4().hex[:8]}
    if not re.match(r"^[0-9a-f]{1,16}$", w["id"]):
        raise ApiError("invalid id")
    zone = str(data.get("zone", "")).strip().lower().rstrip(".")
    w["zone"] = zone[2:] if zone.startswith("*.") else zone
    if not DOMAIN_RE.match(w["zone"]):
        raise ApiError("invalid zone '%s' (e.g. example.com - the certificate covers it and *.example.com)" % zone)
    w["provider"] = str(data.get("provider", ""))
    if w["provider"] not in DNS_PROVIDERS:
        raise ApiError("unknown DNS provider '%s'" % w["provider"])
    try:
        w["propagation"] = int(data.get("propagation", 0) or 0)
    except (TypeError, ValueError):
        raise ApiError("propagation wait must be a number of seconds")
    if not 0 <= w["propagation"] <= 900:
        raise ApiError("propagation wait: 0-900 seconds (0 = plugin default)")
    w["enabled"] = bool(data.get("enabled", True))
    for o in others:
        if o["zone"] == w["zone"]:
            raise ApiError("a wildcard for %s already exists" % w["zone"])
    return w


def cred_path(w):
    return os.path.join(CONF_DIR, "dns", w["id"] + ".ini")


def read_creds(w):
    vals = {}
    try:
        with open(cred_path(w)) as f:
            for line in f:
                k, sep, v = line.partition("=")
                if sep:
                    vals[k.strip()] = v.strip()
    except OSError:
        pass
    return vals


def build_creds(w, given, old_w=None):
    """Merge submitted credential fields with the stored ones (empty field = keep)."""
    prov = DNS_PROVIDERS[w["provider"]]
    old = read_creds(old_w) if old_w and old_w["provider"] == w["provider"] else {}
    given = given if isinstance(given, dict) else {}
    vals = {}
    for f in prov["fields"]:
        v = str(given.get(f["key"], "") or "").strip() or old.get(f["key"], "") or f.get("default", "")
        if not v:
            raise ApiError("%s: %s is required" % (prov["label"], f["label"]))
        if len(v) > 1000 or any(c in v for c in "\r\n"):
            raise ApiError("%s: invalid value" % f["label"])
        vals[f["key"]] = v
    vals.update(prov.get("extra", {}))
    return vals


def write_creds(w, vals):
    os.makedirs(os.path.dirname(cred_path(w)), mode=0o700, exist_ok=True)
    tmp = cred_path(w) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# pve-gateway: certbot %s credentials for %s\n" % (w["provider"], w["zone"]))
        f.writelines("%s = %s\n" % kv for kv in vals.items())
    os.replace(tmp, cred_path(w))


def cert_paths(cfg, name):
    base = os.path.join(cfg.get("letsencrypt_dir", "/etc/letsencrypt/live"), name)
    return os.path.join(base, "fullchain.pem"), os.path.join(base, "privkey.pem")


def cert_info(cfg, name, fresh=False):
    """{"exists": bool, "expires": ts, "days": int} for a certbot certificate by name (cached 60s)."""
    if not name:
        return {"exists": False}
    hit = CERT_CACHE.get(name)
    if hit and not fresh and time.time() - hit[0] < 60:
        return hit[1]
    rc, out = sh(["openssl", "x509", "-noout", "-enddate", "-in", cert_paths(cfg, name)[0]])
    info = {"exists": False}
    m = re.search(r"notAfter=(.+)", out or "") if rc == 0 else None
    if m:
        try:
            exp = calendar.timegm(time.strptime(m.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
            info = {"exists": True, "expires": exp, "days": int((exp - time.time()) // 86400)}
        except ValueError:
            info = {"exists": True}
    CERT_CACHE[name] = (time.time(), info)
    return info


# Cloudflare's proxy ranges (https://www.cloudflare.com/ips/), trusted for CF-Connecting-IP on "behind Cloudflare" domains
CLOUDFLARE_NETS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
SEC_HEADERS = [("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "SAMEORIGIN"),
               ("Referrer-Policy", "strict-origin-when-cross-origin")]


def is_cloudflare(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n) for n in CLOUDFLARE_NETS)


def nginx_proxy_block(d, tls=False):
    up = "%s://%s:%d" % ("https" if d["upstream_https"] else "http", d["ip"], d["port"])
    lines = ["    client_max_body_size %s;" % d["max_body"], "", "    location / {"]
    lines += ["        allow %s;" % c for c in d["source"]] + (["        deny all;"] if d["source"] else [])
    lines += [
        "        proxy_pass %s;" % up,
        "        proxy_http_version 1.1;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "        proxy_set_header X-Forwarded-Host $host;",
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $pvegw_connection_upgrade;",
        "        proxy_read_timeout 1h;",
        "        proxy_send_timeout 1h;",
    ]
    if d["upstream_https"]:
        lines += ["        proxy_ssl_server_name on;", "        proxy_ssl_verify off;  # guests usually have self-signed certs"]
    headers = list(SEC_HEADERS) if d.get("headers") else []
    if tls and d.get("hsts"):
        headers.append(("Strict-Transport-Security", "max-age=15552000"))
    for name, value in headers:  # replace the guest's own copy instead of sending the header twice
        lines += ["        proxy_hide_header %s;" % name, '        add_header %s "%s" always;' % (name, value)]
    return lines + ["    }"]


def build_nginx(cfg):
    out = ["# Generated by pve-gateway %s - do not edit, changes are overwritten." % VERSION,
           "# Manage domains in the pve-gateway web UI.", "",
           "map $http_upgrade $pvegw_connection_upgrade {", "    default upgrade;", "    ''      close;", "}"]
    v6 = cfg.get("nginx_ipv6", True)
    new_h2 = nginx_version() >= (1, 25, 1)  # Debian trixie / PVE 9: "listen ... http2" is deprecated
    ssl_listen = "ssl" if new_h2 else "ssl http2"
    acme = ["    location ^~ /.well-known/acme-challenge/ {", "        root %s;" % cfg["acme_webroot"],
            "        default_type text/plain;", "    }"]
    extra = explicit_listens(nginx_sites(cfg))  # other sites bound to a specific IP would otherwise win
    NGINX["extra"] = extra
    listen80 = ["    listen 80;"] + (["    listen [::]:80;"] if v6 else []) + \
        ["    listen %s:80;  # another site listens on this address" % a for a, p in extra if p == 80]
    listen443 = ["    listen 443 %s;" % ssl_listen] + (["    listen [::]:443 %s;" % ssl_listen] if v6 else []) + \
        ["    listen %s:443 %s;  # another site listens on this address" % (a, ssl_listen) for a, p in extra if p == 443] + \
        (["    http2 on;"] if new_h2 else [])
    for d in cfg["domains"]:
        if not d["enabled"]:
            continue
        cname = domain_cert(cfg, d)[0]
        tls = cert_info(cfg, cname)["exists"]
        crt, key = cert_paths(cfg, cname) if tls else (None, None)
        ssl = ["    ssl_certificate %s;" % crt, "    ssl_certificate_key %s;" % key, "    ssl_protocols TLSv1.2 TLSv1.3;",
               "    ssl_session_cache shared:pvegw_ssl:10m;", "    ssl_session_timeout 1d;"] if tls else []
        realip = (["    set_real_ip_from %s;" % n for n in CLOUDFLARE_NETS] +
                  ["    real_ip_header CF-Connecting-IP;"]) if d.get("cloudflare") else []
        redirect_aliases = d.get("alias_redirect") and d["aliases"]
        names = d["domain"] if redirect_aliases else " ".join(_names(d))
        out += ["", "# %s -> %s:%d  (id %s)" % (d["domain"], d["ip"], d["port"], d["id"]),
                "server {"] + listen80 + ["    server_name %s;" % names] + realip + acme
        if tls and d["force_https"]:
            out += ["    location / {", "        return 301 https://$host$request_uri;", "    }"]
        else:
            out += nginx_proxy_block(d)
        out.append("}")
        if tls:
            out += ["server {"] + listen443 + ["    server_name %s;" % names] + ssl + realip + nginx_proxy_block(d, True) + ["}"]
        if redirect_aliases:  # aliases answer with a permanent redirect to the main domain (still in the certificate)
            target = "%s://%s$request_uri" % ("https" if tls else "http", d["domain"])
            names = " ".join(d["aliases"])
            out += ["server {"] + listen80 + ["    server_name %s;" % names] + acme + [
                "    location / {", "        return 301 %s;" % target, "    }", "}"]
            if tls:
                out += ["server {"] + listen443 + ["    server_name %s;" % names] + ssl + [
                    "    return 301 %s;" % target, "}"]
    return "\n".join(out) + "\n"


def nginx_installed():
    return sh(["nginx", "-v"])[0] == 0


def nginx_version():
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", sh(["nginx", "-v"])[1])
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def nginx_conf_path(cfg):
    return MOCK.path_for(cfg["nginx_conf"]) if MOCK else cfg["nginx_conf"]


def apply_nginx(cfg=None):
    """Write the nginx config, validate with `nginx -t` (rolling back on failure), reload. Returns error or None."""
    with LOCK:
        cfg = cfg or STATE["cfg"]
        path = nginx_conf_path(cfg)
        active = [d for d in cfg["domains"] if d["enabled"]]
        if not active and not os.path.exists(path):
            return None  # domains never used: don't require nginx
        if not nginx_installed():
            NGINX["last_error"] = "nginx is not installed - run: apt install nginx" + (
                " certbot" if any(d["tls"] != "none" for d in active) else "")
            return NGINX["last_error"]
        conf = build_nginx(cfg)
        if DRY_RUN:
            log("[dry-run] would write %s:\n%s" % (path, conf.rstrip()))
            return None
        try:
            with open(path) as f:
                old = f.read()
        except OSError:
            old = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            os.makedirs(os.path.join(MOCK.path_for(cfg["acme_webroot"]) if MOCK else cfg["acme_webroot"],
                                     ".well-known", "acme-challenge"), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.write(conf)
            os.replace(tmp, path)
        except OSError as e:
            NGINX["last_error"] = "cannot write %s: %s" % (path, e)
            log(NGINX["last_error"], "error")
            return NGINX["last_error"]
        rc, out = run(["nginx", "-t"])
        if rc != 0:
            if old is None:
                os.remove(path)
            else:
                with open(path, "w") as f:
                    f.write(old)
            NGINX["last_error"] = "nginx config test failed (previous config restored): " + out
            log(NGINX["last_error"], "error")
            return NGINX["last_error"]
        rc, out = run(["systemctl", "reload-or-restart", "nginx"])
        if rc != 0:
            NGINX["last_error"] = "nginx reload failed: " + out
            log(NGINX["last_error"], "error")
            return NGINX["last_error"]
        NGINX["last_apply"], NGINX["last_error"] = time.time(), None
        log("nginx: applied %d domain(s)" % len(active))
        return None


LE_LOG = "/var/log/letsencrypt/letsencrypt.log"
LE_LOG_KEEP = re.compile(r'Domain:|Type:|Detail:|"detail"|"type": "urn:|urn:ietf:params:acme:error|Error|error:|Attempting|'
                         r'Requesting|Performing the following challenges|http-01|dns-01|Waiting \d+ seconds|'
                         r'Cleaning up|Exiting abnormally|AuthorizationError|Some challenges have failed')
LE_LOG_DROP = re.compile(r'mailto:|"payload"|"protected"|"signature"|BEGIN|Bearer|_token|secret', re.I)


def le_log_lines(limit=80):
    """Relevant, privacy-safe lines from the latest certbot run (letsencrypt.log is rotated per run)."""
    text = _read(MOCK.path_for(LE_LOG) if MOCK else LE_LOG) or ""
    lines = [l.rstrip() for l in text.splitlines() if LE_LOG_KEEP.search(l) and not LE_LOG_DROP.search(l)]
    return lines[-limit:]


def le_failure_reason(out):
    """Why certbot failed: its own Domain/Type/Detail lines, else the ACME error details from letsencrypt.log."""
    lines = [l.strip() for l in out.splitlines() if re.match(r"\s*(Domain|Type|Detail):", l)]
    if not lines:
        text = _read(MOCK.path_for(LE_LOG) if MOCK else LE_LOG) or ""
        details = re.findall(r'"detail":\s*"((?:[^"\\]|\\.)*)"', text)
        kinds = re.findall(r'"type":\s*"urn:ietf:params:acme:error:(\w+)"', text)
        lines = ["Detail: " + d.encode().decode("unicode_escape") for d in dict.fromkeys(details)][-3:]
        if kinds:
            lines.insert(0, "Type: " + kinds[-1])
    if not lines:
        lines = [l.strip() for l in out.splitlines() if re.search(r"error|problem|Unable|Invalid|failed", l, re.I)][:4]
    return "\n".join(lines[:6]) or out[-500:]


def run_certbot(key, cert_name, names, auth, plugin=None, package=None, preflight=False):
    """certbot certonly in the background; progress in CERT_JOBS[key]. auth = authenticator arguments."""
    if CERT_JOBS.get(key, {}).get("state") == "pending":
        return
    CERT_JOBS[key] = {"state": "pending", "msg": "requesting certificate for %s ..." % ", ".join(names), "t": time.time()}

    def fail(msg):
        CERT_JOBS[key] = {"state": "error", "msg": msg, "t": time.time()}
        log("certbot failed for %s: %s" % (cert_name, msg), "error")

    def job():
        cfg = STATE["cfg"]
        if sh(["certbot", "--version"])[0] != 0:
            return fail("certbot is not installed - run: apt install certbot")
        if plugin and not re.search(r"\* %s\b" % re.escape(plugin), sh(["certbot", "plugins"], timeout=60)[1]):
            return fail("certbot plugin %s is missing - run: apt install %s" % (plugin, package))
        if preflight:  # don't spend Let's Encrypt's failure limit (5/hour) on a request that can't succeed
            err = apply_nginx()  # picks up other sites installed since the last save
            if err:
                return fail(err)
            if owns_web_ports(cfg):
                apply_rules(cfg)  # make sure 80/443 are kept on this host before Let's Encrypt connects
            # the local fetch can't see rules that only match traffic from outside (e.g. DNAT -i vmbr0)
            problems = [d for n, st, d in port_checks(cfg) if st == "fail" and "forwarded away" in n]
            problems += acme_preflight(cfg, names)
            if problems:
                return fail("not asking Let's Encrypt, its check would fail: " + "; ".join(problems[:3]) +
                            other_sites_hint(cfg, names))
            log("certbot: local challenge check ok for %s via %s:80" % (", ".join(names), check_ips()[0]))
        cmd = ["certbot", "certonly"] + auth + [
            "--non-interactive", "--agree-tos", "--keep-until-expiring", "--expand",
            "--cert-name", cert_name, "--deploy-hook", "systemctl reload nginx"]
        cmd += ["-m", cfg["acme_email"]] if cfg.get("acme_email") else ["--register-unsafely-without-email"]
        for n in names:
            cmd += ["-d", n]
        log("certbot: requesting %s for %s" % (cert_name, ", ".join(names)))
        rc, out = run(cmd, timeout=900)
        if rc != 0:
            reason = le_failure_reason(out)
            if preflight and re.search(r"connection|Timeout|firewall|refused", reason, re.I):
                found = [d for n, st, d in port_checks(cfg) if st in ("fail", "warn")]
                reason += ("\n" + "\n".join(found) if found else
                           "\n(the same check worked from this host, so something between the internet and this host "
                           "blocks Let's Encrypt: your hosting provider's firewall or a router)")
            return fail(reason)
        cert_info(cfg, cert_name, fresh=True)
        err = apply_nginx()
        msg = "certificate is valid, not due for renewal yet" if "no action taken" in out else "certificate installed"
        CERT_JOBS[key] = {"state": "error" if err else "ok", "msg": err or msg, "t": time.time()}
        log("certbot: %s - %s" % (cert_name, CERT_JOBS[key]["msg"]))

    threading.Thread(target=job, daemon=True).start()


def issue_cert(did, force=False):
    """Get the certificate a domain needs: per-domain HTTP-01, or its wildcard (only if missing unless force)."""
    cfg = STATE["cfg"]
    d = next((x for x in cfg["domains"] if x["id"] == did), None)
    if not d or not d["enabled"]:
        return
    if d["tls"] == "wildcard":
        w = wildcard_for(cfg, d)
        if w and (force or not cert_info(cfg, wc_cert_name(w))["exists"]):
            issue_wildcard(w["id"])
    elif d["tls"] == "letsencrypt":
        run_certbot(did, d["domain"], _names(d), ["--webroot", "-w", cfg["acme_webroot"]], preflight=True)


def issue_wildcard(wid):
    cfg = STATE["cfg"]
    w = next((x for x in cfg["wildcards"] if x["id"] == wid), None)
    if not w or not w["enabled"]:
        return
    prov, p = w["provider"], DNS_PROVIDERS[w["provider"]]
    auth = ["--authenticator", "dns-" + prov, "--dns-%s-credentials" % prov, cred_path(w)]
    if w["propagation"]:
        auth += ["--dns-%s-propagation-seconds" % prov, str(w["propagation"])]
    run_certbot(wid, wc_cert_name(w), [w["zone"], "*." + w["zone"]], auth, plugin="dns-" + prov, package=p["package"])


def wildcard_status(cfg):
    return {w["id"]: {"cert": cert_info(cfg, wc_cert_name(w)), "job": CERT_JOBS.get(w["id"]),
                      "has_credentials": os.path.exists(cred_path(w)),
                      "used_by": [d["domain"] for d in cfg["domains"] if d["tls"] == "wildcard"
                                  and (wildcard_for(cfg, d) or {}).get("id") == w["id"]]}
            for w in cfg.get("wildcards", [])}


def domain_status(cfg):
    res = {}
    for d in cfg["domains"]:
        name, key = domain_cert(cfg, d)
        st = {"job": CERT_JOBS.get(key) if key else None, "cert": cert_info(cfg, name) if name else None}
        if d["tls"] == "wildcard":
            w = wildcard_for(cfg, d)
            st["wildcard"] = "*." + w["zone"] if w else None
        res[d["id"]] = st
    return res


def resolve(name):
    if MOCK:
        return MOCK.resolve(name)
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        return []


def check_ips():
    """Addresses to test domains through, like visitors do: public IPv4s, else the WAN address, else loopback.
    nginx picks server blocks per address, so 127.0.0.1 can hide another site bound to the public IP."""
    nets = host_networks()
    return [n["ip"] for n in nets if n["public"]] or [n["ip"] for n in nets if n["wan"]] or ["127.0.0.1"]


def http_get(ip, port, host, path="/", tls=False, timeout=8):
    """GET path from ip:port with Host/SNI = host. Returns (status, {header: value}, body bytes)."""
    if MOCK:
        return MOCK.http_get(ip, port, host, path, tls)
    import http.client
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        if tls:
            sock = socket.create_connection((ip, port), timeout)
            conn.sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname=host)
        conn.request("GET", path, headers={"Host": host, "User-Agent": "pve-gateway-check"})
        r = conn.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read(4096)
    except (OSError, http.client.HTTPException) as e:
        return 0, {}, str(e).encode()


def describe_response(status, headers, body):
    if not status:
        return body.decode("utf-8", "replace")[:200]
    loc = headers.get("location")
    return "%d%s%s" % (status, " -> " + loc if loc else "", " (%s)" % headers["server"] if headers.get("server") else "")


def http_check(host, tls):
    """Request / for host through nginx the way visitors reach it. Returns (status, text)."""
    ip = check_ips()[0]
    status, headers, body = http_get(ip, 443 if tls else 80, host, "/", tls)
    if not status:
        return 0, describe_response(status, headers, body)
    text = "%d via %s" % (status, ip)
    return status, text + (" -> " + headers["location"] if headers.get("location") else "")


def acme_preflight(cfg, names):
    """Do what Let's Encrypt's HTTP-01 check does, from this host: serve a token from the ACME webroot and fetch it
    for every name through the visitor-facing address. Returns a list of problems (empty = certbot can succeed)."""
    webroot = MOCK.path_for(cfg["acme_webroot"]) if MOCK else cfg["acme_webroot"]
    d = os.path.join(webroot, ".well-known", "acme-challenge")
    token, body = "pvegw-" + secrets.token_urlsafe(18), secrets.token_hex(16)
    try:
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, token), "w") as f:
            f.write(body)
        os.chmod(os.path.join(d, token), 0o644)
    except OSError as e:
        return ["cannot write the challenge file in %s: %s" % (d, e)]
    problems = []
    try:
        for n in names:
            for ip in check_ips():
                st, hdr, got = http_get(ip, 80, n, "/.well-known/acme-challenge/" + token)
                if st != 200 or got.strip() != body.encode():
                    problems.append("%s via %s:80 answered %s instead of the challenge" % (n, ip, describe_response(st, hdr, got)))
    finally:
        try:
            os.remove(os.path.join(d, token))
        except OSError:
            pass
    return problems


def _ports_in(spec):
    """Ports matched by an iptables --dport/--dports value ("80", "80,443", "79:81")."""
    res = set()
    for part in spec.split(","):
        a, _, b = part.partition(":")
        if a.isdigit():
            res.update(range(int(a), int(b or a) + 1) if (b or a).isdigit() else [int(a)])
    return res


def _pvefw_allows(port):
    """Does the Proxmox firewall config (datacenter or this node) accept incoming TCP `port`? None if unreadable."""
    files = ["/etc/pve/firewall/cluster.fw", "/etc/pve/nodes/%s/host.fw" % socket.gethostname().split(".")[0]]
    texts = [_read(MOCK.path_for(f) if MOCK else f) for f in files]
    if not any(texts):
        return None
    macro = {80: "HTTP", 443: "HTTPS"}.get(port)
    if any(re.search(r"^policy_in:\s*ACCEPT", t or "", re.M) for t in texts):
        return True
    groups = False
    for text in texts:
        rules = (text or "").split("[RULES]", 1)[1] if "[RULES]" in (text or "") else ""
        for line in rules.splitlines():
            line = line.strip()
            if line.startswith("[") and line != "[RULES]":
                break
            if line.startswith("GROUP "):
                groups = True
            if not line.startswith("IN "):  # "|IN ..." = disabled rule
                continue
            if macro and re.match(r"^IN %s\(ACCEPT\)" % macro, line):
                return True
            m = re.search(r"-dport (\S+)", line)
            if re.match(r"^IN ACCEPT\b", line) and "-p tcp" in line and m and port in _ports_in(m.group(1)) and "-source" not in line:
                return True
    return None if groups else False  # security groups: can't tell without resolving them


def port_checks(cfg, ports=(80, 443)):
    """What stands between the internet and nginx on 80/443: listener, iptables/fail2ban rejects, Proxmox firewall.
    Returns [(name, status, detail)]."""
    res = []
    tls_needed = any(d["enabled"] and d["tls"] != "none" for d in cfg["domains"])
    rc, out = sh(["ss", "-Hltnp"])
    for port in ports:
        lines = [l for l in out.splitlines() if re.search(r":%d\s" % port, l)] if rc == 0 else []
        procs = sorted({m for l in lines for m in re.findall(r'\(\("([^"]+)"', l)})
        if not lines:
            if port == 80 or tls_needed:
                res.append(("port %d listener" % port, "fail" if port == 80 else "warn",
                            "nothing listens on port %d - is nginx running? (systemctl status nginx)" % port))
            else:
                res.append(("port %d listener" % port, "info", "not used yet - nginx listens on 443 once a domain has a certificate"))
        elif any(p != "nginx" for p in procs):
            res.append(("port %d listener" % port, "fail", "%s listens on port %d, not (only) nginx - stop it or move it" % (", ".join(procs), port)))
        else:
            res.append(("port %d listener" % port, "ok", "nginx"))
    rc, rules = sh(["iptables-save", "-t", "filter"])
    rules = rules.splitlines() if rc == 0 else []
    for port in ports:
        blocking = []
        for l in rules:
            m = re.search(r"--dports? (\S+)", l)
            if not l.startswith("-A ") or not m or port not in _ports_in(m.group(1)) or "-p udp" in l:
                continue
            if re.search(r"-j (DROP|REJECT)\b", l) and " -s " not in l:
                blocking.append(l)
        if blocking:
            res.append(("firewall port %d" % port, "fail", "an iptables rule drops/rejects port %d for everyone: %s" % (port, blocking[0][:160])))
    jails = {}
    for l in rules:
        jm = re.match(r"^-A (INPUT|PVEFW-INPUT) .*--dports? (\S+).* -j (f2b-\S+)", l)
        if jm and set(ports) & _ports_in(jm.group(2)):
            jails[jm.group(3)] = sum(1 for x in rules if x.startswith("-A %s -s " % jm.group(3)) and re.search(r"-j (REJECT|DROP)", x))
    for jail, banned in sorted(jails.items()):
        if banned:
            res.append(("fail2ban %s" % jail[4:], "warn", "%d address(es) banned on ports 80/443 - Let's Encrypt's validation servers "
                        "get 'Connection refused' if they are among them (they are banned after failed challenges = 404s). "
                        "Unban: fail2ban-client unban --all, and exclude /.well-known/acme-challenge/ from that jail" % banned))
    # 80/443 must reach nginx on this host; a DNAT from another tool sends them to a guest instead
    rc, nat = sh(["iptables-save", "-t", "nat"])
    for l in nat.splitlines() if rc == 0 else []:
        m = re.search(r"--dports? (\S+)", l)
        to = re.search(r"--to-destination (\S+)", l)
        if l.startswith("-A ") and "-j DNAT" in l and m and set(ports) & _ports_in(m.group(1)) and "-p udp" not in l \
                and not l.split()[1].startswith("PVEGW_"):
            which = "/".join(str(p) for p in sorted(set(ports) & _ports_in(m.group(1))))
            guarded = owns_web_ports(cfg) and l.split()[1] == "PREROUTING" and \
                hook_position("nat", "PREROUTING", CH_PRE) == 1 and "gw:domains" in nat
            if guarded:
                res.append(("port %s kept on this host" % which, "info", "a rule from another tool would forward it to %s, "
                            "but pve-gateway's rule runs first and keeps it for nginx here; remove the old rule when you "
                            "can: iptables -t nat -D %s" % (to.group(1) if to else "another address", l[3:])))
            else:
                res.append(("port %s forwarded away" % which, "fail",
                            "an iptables rule outside pve-gateway forwards it to %s, so requests never reach nginx on this host "
                            "(%s) - remove it: iptables -t nat -D %s" % (to.group(1) if to else "another address", l[:140], l[3:])))
    rc, nft = sh(["nft", "list", "ruleset"])
    if rc == 0:
        table = ""
        for l in nft.splitlines():
            t = re.match(r"^table (\S+) (\S+)", l)
            if t:
                table = "%s %s" % t.groups()
            m = re.search(r"tcp dport (\{[^}]*\}|\d+).*\bdnat\b.*?to (\S+)", l)
            if m and "pvegw" not in table.lower() and set(ports) & _ports_in(m.group(1).strip("{} ").replace(" ", "")):
                res.append(("port 80/443 forwarded away (nftables)", "fail", "nftables table %s forwards it to %s, so requests "
                            "never reach nginx on this host: %s" % (table, m.group(2), l.strip()[:140])))
    rc, st = sh(["pve-firewall", "status"])
    if rc == 0 and "enabled" in st:
        for port in ports:
            if port == 443 and not tls_needed:
                continue
            allowed = _pvefw_allows(port)
            if allowed is False:
                res.append(("Proxmox firewall port %d" % port, "fail", "the Proxmox firewall is on and has no rule accepting port %d - "
                            "add Datacenter > Firewall > Add: direction in, action ACCEPT, macro %s"
                            % (port, {80: "HTTP", 443: "HTTPS"}[port])))
            elif allowed:
                res.append(("Proxmox firewall port %d" % port, "ok", "accepted"))
            else:
                res.append(("Proxmox firewall port %d" % port, "info", "firewall is on; can't verify port %d (security groups "
                            "or unreadable config) - make sure HTTP/HTTPS are accepted" % port))
    return res


def nginx_sites(cfg):
    """Other nginx server blocks (from `nginx -T`, excluding ours): [{"file", "listen", "names", "default"}] and
    whether nginx loads our file at all. None if nginx -T fails."""
    rc, out = sh(["nginx", "-T"], timeout=20)
    if rc != 0:
        return None
    parts = re.split(r"^# configuration file (.+?):\s*$", out, flags=re.M)
    loaded, sites = False, []
    for name, text in zip(parts[1::2], parts[2::2]):
        if name.strip() == cfg["nginx_conf"]:
            loaded = True
            continue
        text = re.sub(r"#[^\n]*", "", text)
        for m in re.finditer(r"(?<![\w-])server\s*\{", text):
            depth, i = 1, m.end()
            while i < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[i], 0)
                i += 1
            body = text[m.end():i - 1]
            top = re.sub(r"\{[^{}]*\}", "", body)
            while re.search(r"\{[^{}]*\}", top):
                top = re.sub(r"\{[^{}]*\}", "", top)
            listens = [x.strip() for x in re.findall(r"(?:^|;|\n)\s*listen\s+([^;]+);", top)]
            names = " ".join(re.findall(r"(?:^|;|\n)\s*server_name\s+([^;]+);", top)).split()
            sites.append({"file": name.strip(), "listen": listens, "names": names,
                          "default": any("default_server" in x for x in listens)})
    return {"loaded": loaded, "sites": sites}


def explicit_listens(sites):
    """'ip:port' (80/443) that other sites bind to explicitly. nginx only considers servers listening on exactly that
    address for such connections, so our blocks must listen there too or they never see those requests."""
    res = set()
    for site in (sites or {}).get("sites", []):
        for l in site["listen"]:
            addr = l.split()[0]
            m = re.match(r"^(\[[0-9a-fA-F:]+\]|\d+\.\d+\.\d+\.\d+):(80|443)$", addr)
            if m and m.group(1) not in ("0.0.0.0", "[::]"):
                res.add((m.group(1), int(m.group(2))))
    return sorted(res)


def other_sites_hint(cfg, names):
    """Which other nginx sites could be answering instead of ours (for error messages)."""
    sites = nginx_sites(cfg)
    conflicts = name_conflicts(sites, names)
    if conflicts:
        return " - other nginx sites also define %s: %s; remove the name there" % (
            ", ".join(sorted(conflicts)), ", ".join(sorted({f for fs in conflicts.values() for f in fs})))
    on80 = sorted({x["file"] for x in (sites or {}).get("sites", []) if any(re.match(r"^(\S*:)?80\b", l) for l in x["listen"])})
    if on80:
        return " - other nginx sites on port 80: %s (one of them answers instead of pve-gateway)" % ", ".join(on80)
    if sites is not None and not sites["loaded"]:
        return " - nginx does not load %s at all (nginx.conf needs include /etc/nginx/conf.d/*.conf)" % cfg["nginx_conf"]
    return " - check port 80 isn't blocked or forwarded elsewhere"


def name_conflicts(sites, names):
    """{name: [file, ...]} for our names that another server block also claims."""
    res = {}
    for site in (sites or {}).get("sites", []):
        for n in names:
            if any(x == n or (x.startswith("*.") and n.endswith(x[1:])) or (x.startswith(".") and (n == x[1:] or n.endswith(x)))
                   for x in site["names"]):
                res.setdefault(n, []).append(site["file"])
    return res


def name_covered(names, host):
    """Does a certificate with these DNS names cover host? (wildcards: one label)"""
    return any(n == host or (n.startswith("*.") and host.endswith(n[1:]) and "." not in host[:-len(n) + 1])
               for n in names)


def served_cert(host, v6=False):
    """The certificate nginx actually serves for host: {"names", "days", "fingerprint"} or {"error"}."""
    rc, out = run(["openssl", "s_client", "-connect", "[::1]:443" if v6 else "127.0.0.1:443", "-servername", host],
                  data="", check_only=True, timeout=10)
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out or "", re.S)
    if not m:
        lines = [x for x in (out or "").strip().splitlines() if x.strip()]
        return {"error": (lines[-1] if lines else "no certificate served")[:200]}
    rc, info = run(["openssl", "x509", "-noout", "-enddate", "-fingerprint", "-sha256", "-ext", "subjectAltName"],
                   data=m.group(0) + "\n", check_only=True, timeout=10)
    res = {"names": re.findall(r"DNS:([^,\s]+)", info or "")}
    fp = re.search(r"Fingerprint=([0-9A-F:]+)", info or "")
    res["fingerprint"] = fp.group(1) if fp else ""
    end = re.search(r"notAfter=(.+)", info or "")
    if end:
        try:
            exp = calendar.timegm(time.strptime(end.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
            res["days"] = int((exp - time.time()) // 86400)
        except ValueError:
            pass
    return res


def check_served(cfg, d, add):
    """Health of the certificate nginx serves for every name of the domain, on IPv4 and IPv6."""
    v4 = served_cert(d["domain"])
    if v4.get("error"):
        add("served certificate", "fail", "nginx doesn't serve HTTPS for %s: %s" % (d["domain"], v4["error"]))
        return
    missing = [n for n in _names(d) if not name_covered(v4["names"], n)]
    days = v4.get("days")
    if missing:
        add("served certificate", "fail", "the certificate nginx serves (%s) doesn't cover %s - browsers will warn"
            % (", ".join(v4["names"][:4]) or "no names", ", ".join(missing)))
    else:
        add("served certificate", _st(days is None or days >= 14, warn=True), "covers %s%s" % (
            ", ".join(_names(d)), "" if days is None else ", expires in %d days" % days))
    if cfg.get("nginx_ipv6", True):
        v6 = served_cert(d["domain"], v6=True)
        if v6.get("error"):
            add("served certificate (IPv6)", "warn", "IPv6 listener: %s" % v6["error"])
        elif v6.get("fingerprint") != v4.get("fingerprint"):
            add("served certificate (IPv6)", "warn", "IPv4 and IPv6 serve different certificates - check other nginx "
                "sites listening on [::]:443 for the same name")
        else:
            add("served certificate (IPv6)", "ok", "same certificate as IPv4")


def check_dns(d, n, add):
    public4 = [x["ip"] for x in host_networks() if x["public"]]
    public6 = host_ipv6()
    ips = resolve(n)
    v4 = [i for i in ips if ":" not in i]
    v6 = [i for i in ips if ":" in i]
    cf = [i for i in ips if is_cloudflare(i)]
    if not ips:
        return add("DNS %s" % n, "fail", "does not resolve - create an A record pointing to %s"
                   % (" / ".join(public4) if public4 else "your public IP"))
    if cf:
        if d.get("cloudflare"):
            return add("DNS %s" % n, "ok", "proxied by Cloudflare (%s) - Cloudflare's origin record must point to %s"
                       % (", ".join(cf[:2]), " / ".join(public4) or "this host"))
        return add("DNS %s" % n, "warn", "resolves to Cloudflare (%s, orange cloud): enable 'Behind Cloudflare' for "
                   "real visitor IPs, or set the record to DNS only" % ", ".join(cf[:2]))
    if not v4:
        add("DNS %s" % n, "warn", "only AAAA records (%s) - add an A record for IPv4 visitors" % ", ".join(v6))
    elif not public4:
        add("DNS %s" % n, "ok", "resolves to %s - this host has no public IPv4, so that must be your router "
            "forwarding ports 80/443 here" % ", ".join(v4))
    elif set(v4) & set(public4):
        add("DNS %s" % n, "ok", "resolves to %s (this host)" % ", ".join(v4))
    else:
        add("DNS %s" % n, "warn", "resolves to %s, but this host's public IP is %s - fix the A record, unless "
            "a router or proxy in front forwards 80/443 here" % (", ".join(v4), ", ".join(public4)))
    if v6 and not set(v6) & set(public6):
        add("AAAA %s" % n, "warn", "AAAA record %s %s - IPv6 visitors will fail: fix or delete the AAAA record" % (
            ", ".join(v6), "but this host's IPv6 is " + ", ".join(public6) if public6 else "but this host has no public IPv6"))
    elif v6:
        add("AAAA %s" % n, "ok", "resolves to %s (this host)" % ", ".join(v6))


def test_domain(d):
    cfg = STATE["cfg"]
    steps = []

    def add(name, status, detail=""):
        steps.append({"name": name, "status": status, "detail": detail})

    add("domain enabled", _st(d["enabled"]))
    for n in _names(d):
        check_dns(d, n, add)
    rc, out = sh(["systemctl", "is-active", "nginx"])
    add("nginx running", _st(out.strip() == "active"), out.strip() if out else "")
    for name, status, detail in port_checks(cfg):
        if status != "ok" or name.startswith("port 80"):
            add(name, status, detail)
    sites = nginx_sites(cfg)
    if sites is not None and not sites["loaded"]:
        add("nginx loads pve-gateway", "fail", "%s is not included by nginx.conf - nginx ignores all domains; make sure "
            "nginx.conf has: include /etc/nginx/conf.d/*.conf;" % cfg["nginx_conf"])
    for n, files in sorted(name_conflicts(sites, _names(d)).items()):
        add("other site claims %s" % n, "warn", "also defined in %s - nginx uses whichever it loads first; remove the "
            "name there" % ", ".join(sorted(set(files))))
    try:
        with open(nginx_conf_path(cfg)) as f:
            main = d["domain"] if d.get("alias_redirect") and d["aliases"] else " ".join(_names(d))
            present = ("server_name %s;" % main) in f.read()
    except OSError:
        present = False
    add("in nginx config", _st(present or not d["enabled"]), cfg["nginx_conf"])
    if d["enabled"] and out.strip() == "active":
        problems = acme_preflight(cfg, _names(d))
        add("reachable like Let's Encrypt", _st(not problems), "; ".join(problems) + other_sites_hint(cfg, _names(d)) if problems else
            "challenge file served for %s via %s:80" % (", ".join(_names(d)), check_ips()[0]))
    res, ms = tcp_probe(d["ip"], d["port"])
    add("upstream %s:%d" % (d["ip"], d["port"]), _st(res == "ok"),
        "connected in %dms" % ms if res == "ok" else res + (" - nothing listens on that port" if res == "refused" else ""))
    cname, key = domain_cert(cfg, d)
    tls = cert_info(cfg, cname)["exists"]
    if d["tls"] == "wildcard" and not cname:
        add("certificate", "fail", "no enabled wildcard certificate covers " + ", ".join(_names(d)))
    elif cname:
        ci, job = cert_info(cfg, cname, fresh=True), CERT_JOBS.get(key)
        what = "wildcard *.%s" % cname[len("wildcard."):] if d["tls"] == "wildcard" else "certificate"
        if ci["exists"]:
            days = ci.get("days", 0)
            add("certificate", "ok" if days >= 14 else "warn", "%s expires in %d days (certbot renews automatically)" % (what, days))
        else:
            add("certificate", "warn" if job and job["state"] == "pending" else "fail",
                job["msg"] if job else "not issued yet - click Cert")
    if tls:
        check_served(cfg, d, add)
    for proto_tls in ([False, True] if tls else [False]):
        status, text = http_check(d["domain"], proto_tls)
        name = "request via nginx (%s)" % ("https" if proto_tls else "http")
        if status in (502, 504):
            add(name, "fail", text + " - nginx can't reach the upstream")
        elif status == 0:
            add(name, "fail", text)
        else:
            add(name, "ok" if status < 500 else "warn", text)
    if d.get("alias_redirect"):
        for a in d["aliases"]:
            status, text = http_check(a, tls)
            add("alias %s" % a, _st(status in (301, 308)), text + ("" if status in (301, 308) else " - expected a 301 to " + d["domain"]))
    if d["tls"] == "none":
        add("TLS", "info", "HTTP only - pick Let's Encrypt to get HTTPS")
    return steps


# --------------------------------------------------------------------------- diagnostics

def _st(ok, warn=False):
    return "ok" if ok else ("warn" if warn else "fail")


def host_listeners():
    """{(proto, port)} of sockets the host itself listens on."""
    rc, out = sh(["ss", "-Hlntu"])
    res = set()
    if rc == 0:
        for f in (line.split() for line in out.splitlines()):
            m = re.search(r":(\d+)$", f[4]) if len(f) > 4 else None
            if m:
                res.add((f[0], int(m.group(1))))
    return res


def hook_position(table, chain, target):
    """1-based position of our jump rule in a built-in chain, or None if missing."""
    rc, out = sh(["iptables", "-t", table, "-S", chain])
    if rc != 0:
        return None
    rules = [line for line in out.splitlines() if line.startswith("-A ")]
    want = "-A %s -j %s" % (chain, target)
    return rules.index(want) + 1 if want in rules else None


def loaded_rule_ids():
    """{rule id: number of DNAT entries currently in the kernel}"""
    rc, out = sh(["iptables-save", "-t", "nat"])
    ids = {}
    if rc == 0:
        for m in re.finditer(r"^-A %s .*gw:([0-9a-f]+)(?![0-9a-z])" % CH_PRE, out, re.M):
            ids[m.group(1)] = ids.get(m.group(1), 0) + 1
    return ids


# services that should not be reachable from the internet (port -> what)
RISKY_PORTS = {111: "rpcbind", 2049: "NFS", 139: "SMB", 445: "SMB", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
               6379: "Redis", 11211: "memcached", 27017: "MongoDB", 9200: "Elasticsearch", 2375: "Docker API",
               8086: "InfluxDB", 9090: "Prometheus", 9100: "node_exporter", 10250: "kubelet", 5000: "Docker registry"}


def exposed_services():
    """[(proto, port, bind, process)] listening on all interfaces or a public address (not loopback / LAN)."""
    rc, out = sh(["ss", "-Hlntup"])
    res = []
    for f in (line.split() for line in out.splitlines()) if rc == 0 else []:
        if len(f) < 5:
            continue
        addr, _, port = f[4].rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        if not port.isdigit():
            continue
        if addr in ("0.0.0.0", "*", "::"):
            scope = "all interfaces"
        else:
            try:
                a = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if not a.is_global:
                continue
            scope = addr
        proc = re.search(r'\(\("([^"]+)"', " ".join(f))
        res.append((f[0], int(port), scope, proc.group(1) if proc else "?"))
    return res


def apt_dirs():
    base = "/etc/apt"
    return MOCK.path_for(base) if MOCK else base


def enterprise_repos():
    """apt source files with an enabled enterprise.proxmox.com entry."""
    found = []
    d = os.path.join(apt_dirs(), "sources.list.d")
    for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        text = _read(os.path.join(d, name)) or ""
        if name.endswith(".sources"):
            for stanza in re.split(r"\n\s*\n", text):
                if "enterprise.proxmox.com" in stanza and not re.search(r"^Enabled:\s*(no|false)", stanza, re.M | re.I):
                    found.append(name)
                    break
        elif name.endswith(".list") and re.search(r"^[^#\n]*enterprise\.proxmox\.com", text, re.M):
            found.append(name)
    return found


def sdn_checks(add):
    """Only on hosts that use SDN zones: dnsmasq, pending changes, VNet bridges up, DHCP servers running."""
    try:
        sdn = sdn_state()
    except ApiError as e:
        return add("Proxmox SDN", "warn", str(e))
    if not sdn["available"] or not sdn["zones"]:
        return
    dhcp = [z["zone"] for z in sdn["zones"] if z["dhcp"] and z["state"] != "deleted"]
    if dhcp and sh(["dnsmasq", "--version"])[0] != 0:
        add("SDN DHCP: dnsmasq", "fail", "zone(s) %s hand out DHCP but dnsmasq is missing - Network tab > Install dnsmasq "
            "(or: apt install dnsmasq && systemctl disable --now dnsmasq)" % ", ".join(dhcp))
    if not interfaces_sourced():
        add("SDN: /etc/network/interfaces", "fail", "add 'source /etc/network/interfaces.d/*' at the end, then Apply on the Network tab")
    add("SDN changes applied", _st(not sdn["pending"], warn=True),
        "all applied" if not sdn["pending"] else "pending changes - Network tab > Apply SDN changes")
    up = {n["iface"] for n in host_networks()}
    for v in sdn["vnets"]:
        if v["state"] in ("new", "deleted") or not v["subnets"]:
            continue
        add("SDN VNet %s" % v["vnet"], _st(v["vnet"] in up),
            "bridge up, gateway %s" % ", ".join(x["gateway"] for x in v["subnets"]) if v["vnet"] in up else
            "bridge has no address - Apply on the Network tab, or run: ifreload -a")
    for z in dhcp:
        if next(x for x in sdn["zones"] if x["zone"] == z)["state"] == "new":
            continue
        rc, out = sh(["systemctl", "is-active", "dnsmasq@%s" % z])
        add("SDN DHCP server (zone %s)" % z, _st(rc == 0), "dnsmasq@%s %s" % (z, "running" if rc == 0 else
            "not running - journalctl -u dnsmasq@%s" % z))


def checks():
    cfg = STATE["cfg"]
    res = []

    def add(name, status, detail=""):
        res.append({"name": name, "status": status, "detail": detail})

    if MOCK:
        add("mock mode", "warn", "simulated host - nothing real is touched (state: %s)" % MOCK.path)
    if DRY_RUN:
        add("dry-run mode", "warn", "iptables changes are only logged, nothing is changed")
    uid = os.geteuid() if hasattr(os, "geteuid") else -1
    add("running as root", _st(MOCK or DRY_RUN or uid == 0), "mock" if MOCK else "uid %d" % uid)
    rc, out = sh(["iptables", "--version"])
    add("iptables available", "info" if rc is None else _st(rc == 0), out)
    add("net.ipv4.ip_forward", _st(ip_forward_on()), "routing between interfaces")
    for t, c, tg in JUMPS:
        name = "hook %s/%s -> %s" % (t, c, tg)
        pos = hook_position(t, c, tg)
        add(name, "fail" if pos is None else _st(pos == 1, warn=True),
            "missing - click Re-apply" if pos is None else
            "rule #1" if pos == 1 else "rule #%d: the %d rule(s) above it are evaluated first" % (pos, pos - 1))
    expected = {r["id"]: len(protos(r["proto"])) for r in cfg["rules"] if r["enabled"]}
    loaded = loaded_rule_ids()
    missing = [r["name"] or r["id"] for r in cfg["rules"] if r["enabled"] and loaded.get(r["id"]) != expected[r["id"]]]
    stale = [i for i in loaded if i not in expected]
    add("kernel rules match config", _st(not missing and not stale),
        "%d expected, %d loaded" % (sum(expected.values()), sum(loaded.values()))
        + ("; missing/incomplete: " + ", ".join(missing) if missing else "")
        + ("; stale ids: " + ", ".join(stale) if stale else ""))
    rc, out = sh(["iptables", "-S", "FORWARD"])
    if rc == 0:
        policy = out.splitlines()[0] if out else "?"
        drop = "DROP" in policy
        add("FORWARD policy", "fail" if drop and not cfg.get("forward_accept", True) else "info",
            policy + (" - forward_accept must stay enabled" if drop else ""))
    rc, out = sh(["pve-firewall", "status"])
    add("pve-firewall", "info", out)
    if rc == 0 and "enabled" in out and cfg.get("forward_accept", True) and any(r["enabled"] for r in cfg["rules"]):
        add("forwarded ports vs pve-firewall", "info", "forwarded traffic is accepted before pve-firewall, so guest "
            "firewall rules don't filter it - limit access with each rule's Allowed source")
    for proto, port, scope, proc in exposed_services():
        what = RISKY_PORTS.get(port) or ("VNC" if 5900 <= port <= 5999 else None)
        if what:
            add("exposed %s/%d" % (proto, port), "warn", "%s (%s) listens on %s - reachable from the internet unless the "
                "Proxmox firewall blocks it; bind it to localhost or block the port" % (what, proc, scope))
    repos = enterprise_repos()
    if repos:
        rc, sub = sh(["pvesubscription", "get"])
        if rc == 0 and not re.search(r"status:\s*active", sub, re.I):
            add("apt repositories", "warn", "Proxmox enterprise repos are enabled (%s) but there is no subscription, so "
                "apt update fails with 401 - switch to no-subscription: curl -fsSL %s/master/install.sh | sh -s -- fix-repos"
                % (", ".join(repos), REPO_RAW))
    for t in cfg["wireguard"]["tunnels"]:
        if t["enabled"]:
            stt = wg_status(t)
            online = sum(1 for x in stt["peers"].values() if x["online"])
            add("WireGuard %s" % t["name"], _st(stt["up"]), "up, %d/%d peers online, UDP %d" % (online, len(t["peers"]), t["port"])
                if stt["up"] else "down - try: wg-quick up %s; journalctl -u wg-quick@%s" % (t["name"], t["name"]))
    sdn_checks(add)
    fw = cfg["firewall"]
    if fw["enabled"]:
        add("firewall", "ok", "%s backend, policy %s, %d rule(s)%s" % (
            "pve-gateway" if fw["backend"] == "custom" else "Proxmox", fw["policy"], len(fw["rules"]),
            " - waiting for confirmation" if FW_PENDING.get("deadline") else ""))
        if fw["backend"] == "custom" and sh(["pve-firewall", "status"])[1].find("enabled") >= 0:
            add("two firewalls", "info", "the Proxmox firewall is also enabled; pve-gateway's rules run first (INPUT #1)")
    if f2b_installed():
        rc, out = sh(["fail2ban-client", "status"])
        add("fail2ban", _st(rc == 0, warn=True), (re.search(r"Jail list:\s*(.*)", out).group(1) or "no jails")
            if rc == 0 and "Jail list" in out else "installed but not running - systemctl start fail2ban")
    down = [m["name"] or m["target"] for m in cfg.get("monitors", []) if MON.get(m["id"], {}).get("status") == "down"]
    if cfg.get("monitors"):
        add("health checks", "fail" if down else "ok", ("down: " + ", ".join(down)) if down else
            "%d checks, all up or pending" % len(cfg["monitors"]))
    info = update_info()
    if info["available"]:
        add("pve-gateway version", "warn", "%s installed, %s available - update in Settings or run: pve-gateway update"
            % (VERSION, info["latest"]))
    else:
        add("pve-gateway version", "info" if info["error"] or not info["latest"] else "ok",
            VERSION + (" (latest)" if info["latest"] else "") + (" - " + info["error"] if info["error"] else ""))
    if cfg.get("ui_allow"):
        add("web UI access", "ok", "only from " + ", ".join(cfg["ui_allow"]) + " (and localhost)")
    else:
        add("web UI access", "warn", "port %s is open to every IP - restrict it in Settings or run: pve-gateway ui-allow <your-ip>"
            % cfg.get("port", 8099))
    listeners = host_listeners()
    for r in cfg["rules"]:
        if not r["enabled"]:
            continue
        ea, eb = parse_ports(r["ext_port"])
        for p, port in sorted(listeners):
            if p in protos(r["proto"]) and ea <= port <= eb:
                add("host port %s/%d" % (p, port), "warn",
                    "a host service listens here, but incoming traffic now goes to %s (rule '%s')" % (r["ip"], r["name"] or r["id"]))
    add("last apply", _st(not STATE["last_error"]), STATE["last_error"] or (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(STATE["last_apply"])) if STATE["last_apply"] else "never"))

    if cfg["domains"] or os.path.exists(nginx_conf_path(cfg)):
        rc, out = sh(["nginx", "-v"])
        add("nginx installed", _st(rc == 0), out if rc == 0 else "apt install nginx")
        rc, out = sh(["systemctl", "is-active", "nginx"])
        add("nginx running", _st(out.strip() == "active"), out.strip())
        for name, status, detail in port_checks(cfg):
            add(name, status, detail)
        sites = nginx_sites(cfg)
        if sites is not None:
            add("nginx loads pve-gateway.conf", _st(sites["loaded"] or not cfg["domains"]),
                "yes" if sites["loaded"] else "no - nginx.conf must include /etc/nginx/conf.d/*.conf")
            for a, p in explicit_listens(sites):
                add("other site on %s:%d" % (a, p), "info", "another nginx site binds this address explicitly - pve-gateway's "
                    "domains listen there too, so nginx still picks them by name")
            for n, files in sorted(name_conflicts(sites, [x for dm in cfg["domains"] if dm["enabled"] for x in _names(dm)]).items()):
                add("name conflict %s" % n, "warn", "also defined in %s" % ", ".join(sorted(set(files))))
        add("nginx last apply", _st(not NGINX["last_error"]), NGINX["last_error"] or (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(NGINX["last_apply"])) if NGINX["last_apply"] else "never"))
        rc, out = sh(["ss", "-Hlntp"])
        for line in out.splitlines() if rc == 0 else []:
            m = re.search(r":(80|443)\s", line)
            if m and "nginx" not in line:
                add("port %s" % m.group(1), "warn", "used by another program, not nginx: " + line.split()[-1])
        le = [d for d in cfg["domains"] if d["tls"] == "letsencrypt" and d["enabled"]]
        wcs = [w for w in cfg.get("wildcards", []) if w["enabled"]]
        if le or wcs:
            rc, out = sh(["certbot", "--version"])
            add("certbot installed", _st(rc == 0), out if rc == 0 else "apt install certbot")
        plugins = sh(["certbot", "plugins"], timeout=60)[1] if wcs else ""
        for w in wcs:
            p = DNS_PROVIDERS[w["provider"]]
            ok = bool(re.search(r"\* dns-%s\b" % w["provider"], plugins))
            add("plugin dns-%s" % w["provider"], _st(ok), "installed" if ok else "apt install " + p["package"])
            add("credentials *.%s" % w["zone"], _st(os.path.exists(cred_path(w))), cred_path(w))
            ci, job = cert_info(cfg, wc_cert_name(w)), CERT_JOBS.get(w["id"])
            if ci["exists"]:
                add("wildcard *.%s" % w["zone"], _st(ci.get("days", 0) >= 14, warn=True), "expires in %s days" % ci.get("days", "?"))
            else:
                add("wildcard *.%s" % w["zone"], "warn" if job and job["state"] == "pending" else "fail",
                    job["msg"] if job else "not issued")
        for d in cfg["domains"]:
            if d["enabled"] and d["tls"] == "wildcard" and not wildcard_for(cfg, d):
                add("domain %s" % d["domain"], "fail", "set to wildcard TLS, but no enabled wildcard covers it")
        for d in le:
            ci, job = cert_info(cfg, d["domain"]), CERT_JOBS.get(d["id"])
            if ci["exists"]:
                add("certificate %s" % d["domain"], _st(ci.get("days", 0) >= 14, warn=True), "expires in %s days" % ci.get("days", "?"))
            else:
                add("certificate %s" % d["domain"], "warn" if job and job["state"] == "pending" else "fail",
                    job["msg"] if job else "not issued")
    return res


def conntrack_lines(ips):
    if not ips:
        return "(no enabled rules)"
    if not MOCK and os.path.exists("/proc/net/nf_conntrack"):
        try:
            with open("/proc/net/nf_conntrack") as f:
                lines = f.read().splitlines()
        except OSError as e:
            return str(e)
    else:
        rc, out = sh(["conntrack", "-L"])
        if rc == 127:
            return "(conntrack table not readable: apt install conntrack)"
        lines = out.splitlines()
    pats = ["src=%s " % ip for ip in ips] + ["dst=%s " % ip for ip in ips]
    hits = [line for line in lines if any(p in line + " " for p in pats)]
    return "\n".join(hits[-200:]) or "(no tracked connections to forwarded guests)"


def sections():
    cfg = STATE["cfg"]

    def ours(table):
        rc, out = sh(["iptables-save", "-c", "-t", table])
        return "\n".join(line for line in out.splitlines() if "PVEGW" in line) or "(none loaded)" if rc == 0 else out

    safe_cfg = dict(cfg, pass_hash="***" if cfg.get("pass_hash") else "", alerts=masked_alerts(cfg.get("alerts", {})))
    return [
        {"title": "Service log", "text": "\n".join(LOGS) or "(empty)", "open": True},
        {"title": "Generated ruleset (iptables-restore input)", "text": build_ruleset(cfg)},
        {"title": "Loaded rules: nat [packets:bytes]", "text": ours("nat")},
        {"title": "Loaded rules: filter [packets:bytes]", "text": ours("filter")},
        {"title": "iptables -t nat PREROUTING", "text": sh(["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"])[1]},
        {"title": "iptables -t nat POSTROUTING", "text": sh(["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"])[1]},
        {"title": "iptables FORWARD", "text": sh(["iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers"])[1]},
        {"title": "Tracked connections to forwarded guests", "text": conntrack_lines(sorted({r["ip"] for r in cfg["rules"] if r["enabled"]}))},
        {"title": "Interfaces", "text": sh(["ip", "-4", "-br", "addr"])[1]},
        {"title": "Routes", "text": sh(["ip", "-4", "route"])[1]},
        {"title": "Listening sockets on host", "text": sh(["ss", "-Hlntup"])[1]},
        {"title": "Config " + conf_file(), "text": json.dumps(safe_cfg, indent=2)},
        {"title": "wg show (keys hidden)", "text": re.sub(r"(private key|preshared key): \S+", r"\1: (hidden)",
                                                           sh(["wg", "show"])[1]) if cfg["wireguard"]["tunnels"] else "(no tunnels)"},
        {"title": "Proxmox SDN (zones, VNets, subnets, IPAM, DNS plugins without keys)",
         "text": json.dumps(sdn_state(fresh=True), indent=1)},
        {"title": "/etc/network/interfaces.d/sdn", "text": _read(MOCK.path_for("/etc/network/interfaces.d/sdn") if MOCK else
                                                                 "/etc/network/interfaces.d/sdn") or "(not written - no SDN applied)"},
    ] + ([
        {"title": "nginx config " + cfg["nginx_conf"], "text": _read(nginx_conf_path(cfg)) or "(not written yet)"},
        {"title": "nginx -t", "text": sh(["nginx", "-t"])[1]},
        {"title": "certbot certificates", "text": sh(["certbot", "certificates"], timeout=30)[1]},
        {"title": "Let's Encrypt log (latest run, %s)" % LE_LOG, "text": "\n".join(le_log_lines()) or "(empty - no certbot run yet)"},
    ] if cfg["domains"] or os.path.exists(nginx_conf_path(cfg)) else [])


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def diagnostics():
    return {"version": VERSION, "host": socket.gethostname(), "verbose": VERBOSE, "dry_run": DRY_RUN,
            "mock": MOCK.scenarios() if MOCK else None,
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "checks": checks(), "sections": sections()}


def fmt_steps(steps):
    return "\n".join("[%-4s] %s%s" % (s["status"].upper(), s["name"],
                                      (" - " + s["detail"].replace("\n", "\n         ")) if s["detail"] else "")
                     for s in steps)


def report_text(d):
    out = ["pve-gateway %s debug report | host %s | %s%s" % (
        d["version"], d["host"], d["generated"], " | DRY RUN" if d["dry_run"] else " | MOCK" if d["mock"] else ""),
        "", fmt_steps(d["checks"])]
    for s in d["sections"][1:] + d["sections"][:1]:  # log last
        out += ["", "===== %s =====" % s["title"], s["text"]]
    return "\n".join(out) + "\n"


def tcp_probe(ip, port, timeout=3):
    """('ok'|'refused'|'timeout'|error text, ms)"""
    if MOCK:
        return MOCK.tcp_probe(ip, port)
    s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET)
    s.settimeout(timeout)
    t = time.time()
    try:
        s.connect((ip, port))
        return "ok", (time.time() - t) * 1000
    except ConnectionRefusedError:
        return "refused", 0
    except socket.timeout:
        return "timeout", 0
    except OSError as e:
        return str(e), 0
    finally:
        s.close()


def test_rule(r):
    """Step-by-step reachability check for one rule, run from the host."""
    steps = []

    def add(name, status, detail=""):
        steps.append({"name": name, "status": status, "detail": detail})

    ip = r["ip"]
    ea, _ = parse_ports(r["ext_port"])
    port = int(r["int_port"] or ea)
    add("rule enabled", _st(r["enabled"]), "" if r["enabled"] else "rule is disabled - nothing is forwarded")
    n = loaded_rule_ids().get(r["id"], 0)
    add("loaded in iptables", _st(n == len(protos(r["proto"])) or not r["enabled"]),
        "%d DNAT entr%s in %s" % (n, "y" if n == 1 else "ies", CH_PRE))
    add("ip_forward", _st(ip_forward_on()))

    rc, out = sh(["ip", "route", "get", ip])
    src = re.search(r"\bsrc (\S+)", out or "")
    if rc != 0:
        add("route to guest", "fail", out)
    else:
        via = " via " in out
        add("route to guest", "warn" if via and not r["masq"] else "ok", out.splitlines()[0].strip() + (
            "" if not via else "\nguest is behind a gateway - Masquerade is on, so replies come back through this host"
            if r["masq"] else "\nguest is behind a gateway, not on a local bridge - replies may bypass this host; try Masquerade"))

    rc, out = sh(["ping", "-c", "1", "-W", "1", ip], timeout=5)
    add("ping guest", _st(rc == 0, warn=True),
        "reply received" if rc == 0 else "no reply (guest down, wrong IP, or ICMP blocked)")

    if "tcp" in protos(r["proto"]):
        name = "TCP connect %s:%d from host" % (ip, port)
        res, ms = tcp_probe(ip, port)
        if res == "ok":
            add(name, "ok", "connected in %dms - service is listening" % ms)
        elif res == "refused":
            add(name, "fail", "connection refused - guest is up but nothing listens on port %d (or its firewall rejects)" % port)
        elif res == "timeout":
            add(name, "fail", "timeout - guest down, wrong IP, or the guest's firewall drops port %d" % port)
        else:
            add(name, "fail", res)
    if "udp" in protos(r["proto"]):
        add("UDP", "info", "UDP can't be verified with a connect test - check the service on the guest")

    c = counters().get(r["id"])
    add("traffic counter", "info", "%d connection(s), %d bytes matched since rules were loaded" % tuple(c) if c and c[0] else
        "no traffic has hit this rule yet - if tests from outside fail, check that your router / ISP / "
        "cloud firewall sends port %s to this host" % r["ext_port"])
    if not r["masq"]:
        add("return path", "info", "without Masquerade the guest's default gateway must be this host%s"
            % (" (%s)" % src.group(1) if src else ""))
    return steps


# --------------------------------------------------------------------------- monitoring

MON_TYPES = ("http", "tcp", "ping")
MON = {}            # monitor id -> live state
MON_LOCK = threading.Lock()
SCANS = {}          # scan id -> {"target", "total", "done", "open", "state", "started"}
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 587, 631, 636, 853, 873,
                993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375, 2376, 2379, 3000, 3128, 3306,
                3389, 3478, 4443, 5000, 5060, 5222, 5432, 5601, 5672, 5900, 5901, 5984, 6379, 6443, 7001, 8000, 8006,
                8007, 8008, 8080, 8081, 8086, 8088, 8099, 8123, 8200, 8443, 8888, 9000, 9042, 9090, 9092, 9100, 9200,
                9300, 9418, 9443, 10000, 10050, 10051, 10250, 10443, 11211, 15672, 25565, 27017, 51820]
SERVICE_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "rpcbind",
                 139: "SMB", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP submission",
                 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "MS SQL", 1521: "Oracle", 1883: "MQTT", 2049: "NFS",
                 2375: "Docker API", 2376: "Docker API (TLS)", 3000: "web app", 3128: "Proxmox spice / proxy",
                 3306: "MySQL/MariaDB", 3389: "RDP", 3478: "STUN/TURN", 5060: "SIP", 5432: "PostgreSQL",
                 5672: "AMQP", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes API", 8006: "Proxmox VE", 8007: "Proxmox Backup",
                 8080: "HTTP alt", 8086: "InfluxDB", 8099: "pve-gateway", 8443: "HTTPS alt", 9000: "web app",
                 9090: "Prometheus", 9100: "node_exporter", 9200: "Elasticsearch", 10050: "Zabbix agent",
                 10250: "kubelet", 11211: "memcached", 15672: "RabbitMQ", 25565: "Minecraft", 27017: "MongoDB",
                 51820: "WireGuard"}


def port_risk(port):
    if port in RISKY_PORTS or 5900 <= port <= 5999 or port in (23, 21, 1433, 1521, 3389):
        return "high"
    if port in (22, 8006, 8007, 8099, 3128, 10000, 6443, 2379):
        return "admin"
    return "low"


def parse_port_list(spec, limit=5000):
    """"common" | "22,80,8000-8100" -> sorted ports."""
    spec = str(spec or "common").strip().lower()
    if spec == "common":
        return list(COMMON_PORTS)
    ports = set()
    for part in re.split(r"[\s,]+", spec):
        if part:
            a, b = parse_ports(part)
            ports.update(range(a, b + 1))
            if len(ports) > limit:
                raise ApiError("at most %d ports per scan" % limit)
    if not ports:
        raise ApiError("no ports given")
    return sorted(ports)


def validate_monitor(data, others, mid=None):
    if not isinstance(data, dict):
        raise ApiError("check must be an object")
    m = {"id": mid or uuid.uuid4().hex[:8]}
    m["name"] = str(data.get("name", "")).strip()
    if not NAME_RE.match(m["name"]):
        raise ApiError("name: max 40 chars, letters/digits/space/_.:/@+- only")
    m["type"] = str(data.get("type", "http"))
    if m["type"] not in MON_TYPES:
        raise ApiError("type must be http, tcp or ping")
    t = str(data.get("target", "")).strip()
    if m["type"] == "http":
        u = urllib.parse.urlsplit(t)
        if u.scheme not in ("http", "https") or not u.hostname or len(t) > 300 or any(c in t for c in " \r\n"):
            raise ApiError("target must be a URL like https://cloud.example.com/health")
    elif m["type"] == "tcp":
        host, _, port = t.rpartition(":")
        if not host or not port.isdigit() or not 1 <= int(port) <= 65535 or not HOSTNAME_RE.match(host.lower().strip("[]")) \
                and not _is_ip(host.strip("[]")):
            raise ApiError("target must be host:port, e.g. 10.10.10.11:5432")
    elif not (HOSTNAME_RE.match(t.lower()) or _is_ip(t)):
        raise ApiError("target must be an IP address or hostname")
    m["target"] = t
    try:
        m["interval"] = int(data.get("interval", 60))
        m["timeout"] = int(data.get("timeout", 5))
    except (TypeError, ValueError):
        raise ApiError("interval and timeout must be numbers (seconds)")
    if not 30 <= m["interval"] <= 86400 or not 1 <= m["timeout"] <= 30:
        raise ApiError("interval: 30-86400 s, timeout: 1-30 s")
    m["expect"] = str(data.get("expect", "200-399") or "200-399").strip()
    if not re.match(r"^\d{3}(-\d{3})?$", m["expect"]):
        raise ApiError("expected status: e.g. 200 or 200-399")
    m["verify_tls"] = bool(data.get("verify_tls", True))
    m["alert"] = bool(data.get("alert", True))
    m["enabled"] = bool(data.get("enabled", True))
    if len(others) >= 200:
        raise ApiError("at most 200 checks")
    return m


def _is_ip(x):
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def validate_alerts(data, old):
    a = dict(old or {})
    for k in ("email", "webhook", "telegram_token", "telegram_chat"):
        if k in data:
            v = str(data[k] or "").strip()
            if v == "saved":  # masked value sent back unchanged
                continue
            if len(v) > 500 or any(c in v for c in "\r\n"):
                raise ApiError("invalid %s" % k)
            a[k] = v
    if a.get("email") and not all(EMAIL_RE.match(e.strip()) for e in a["email"].split(",")):
        raise ApiError("invalid alert e-mail address")
    if a.get("webhook") and not re.match(r"^https?://[^\s]+$", a["webhook"]):
        raise ApiError("webhook must be an http(s) URL")
    if a.get("telegram_token") and not re.match(r"^\d+:[\w-]{20,}$", a["telegram_token"]):
        raise ApiError("Telegram bot token looks wrong (format 123456:ABC...)")
    for k, lo, hi in (("fail_after", 1, 20), ("cert_days", 1, 60)):
        if k in data:
            try:
                a[k] = int(data[k])
            except (TypeError, ValueError):
                raise ApiError("%s must be a number" % k)
            if not lo <= a[k] <= hi:
                raise ApiError("%s: %d-%d" % (k, lo, hi))
    return a


def masked_alerts(a):
    return dict(a, telegram_token="saved" if a.get("telegram_token") else "", webhook="saved" if a.get("webhook") else "")


def send_alert(subject, text):
    """Send to every configured channel, in the background. Failures are logged, never raised."""
    a = STATE["cfg"].get("alerts", {})
    host = socket.gethostname()
    msg = "[pve-gateway %s] %s\n%s" % (host, subject, text)

    def job():
        sent = []
        if MOCK:
            log("[mock] alert (not sent): %s - %s" % (subject, text), "warn")
            return
        if a.get("email"):
            mail = "To: %s\nSubject: [pve-gateway %s] %s\nContent-Type: text/plain; charset=utf-8\n\n%s\n" % (
                a["email"], host, subject, text)
            rc, out = run(["sendmail", "-t"], data=mail, timeout=30)
            sent.append("e-mail" if rc == 0 else "e-mail failed (%s)" % out[:80])
        for name, url, body in (
                ("webhook", a.get("webhook"), {"text": msg, "content": msg}),
                ("telegram", "https://api.telegram.org/bot%s/sendMessage" % a["telegram_token"]
                 if a.get("telegram_token") and a.get("telegram_chat") else None, {"chat_id": a.get("telegram_chat"), "text": msg})):
            if not url:
                continue
            try:
                req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json",
                                                                                "User-Agent": "pve-gateway/" + VERSION})
                urllib.request.urlopen(req, timeout=15).read()
                sent.append(name)
            except Exception as e:
                sent.append("%s failed (%s)" % (name, str(e)[:80]))
        log("alert '%s': %s" % (subject, ", ".join(sent) or "no channel configured"), "info" if sent else "warn")

    threading.Thread(target=job, daemon=True).start()


def tls_cert_days(host, port, timeout):
    """Days until the (verified) certificate of host:port expires, or None."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                end = tls.getpeercert().get("notAfter")
        return int((ssl.cert_time_to_seconds(end) - time.time()) // 86400) if end else None
    except (OSError, ssl.SSLError, ValueError):
        return None


def run_monitor(m):
    """One check: (ok, ms, detail, cert_days)."""
    t, start = m["target"], time.time()
    if m["type"] == "ping":
        host = t
        rc, out = sh(["ping", "-c", "1", "-W", str(m["timeout"]), host], timeout=m["timeout"] + 3)
        ms = re.search(r"time=([\d.]+) ms", out or "")
        return rc == 0, float(ms.group(1)) if ms else (time.time() - start) * 1000, "reply" if rc == 0 else "no reply", None
    if m["type"] == "tcp":
        host, _, port = t.rpartition(":")
        res, ms = tcp_probe(host.strip("[]"), int(port), timeout=m["timeout"])
        return res == "ok", ms, "connected" if res == "ok" else res, None
    if MOCK:
        return MOCK.monitor_http(m)
    u = urllib.parse.urlsplit(t)
    lo, _, hi = m["expect"].partition("-")
    ctx = ssl.create_default_context() if m["verify_tls"] else ssl._create_unverified_context()
    try:
        req = urllib.request.Request(t, headers={"User-Agent": "pve-gateway-monitor/" + VERSION})
        try:
            r = urllib.request.urlopen(req, timeout=m["timeout"], context=ctx)
            status = r.status
            r.read(65536)
        except urllib.error.HTTPError as e:
            status = e.code
        ms = (time.time() - start) * 1000
        ok = int(lo) <= status <= int(hi or lo)
        days = tls_cert_days(u.hostname, u.port or 443, m["timeout"]) if u.scheme == "https" and m["verify_tls"] else None
        return ok, ms, "HTTP %d" % status + ("" if ok else " (expected %s)" % m["expect"]), days
    except Exception as e:
        reason = getattr(e, "reason", e)
        return False, (time.time() - start) * 1000, str(reason)[:200], None


def record_result(m, ok, ms, detail, days):
    a = STATE["cfg"].get("alerts", {})
    now = time.time()
    with MON_LOCK:
        st = MON.setdefault(m["id"], {"status": "unknown", "since": now, "fails": 0, "history": deque(maxlen=288),
                                      "cert_alerted": 0})
        st.update(checked=now, ms=round(ms, 1), detail=detail, cert_days=days, running=False)
        st["history"].append((int(now), bool(ok), round(ms, 1)))
        prev = st["status"]
        if ok:
            st["fails"] = 0
            if prev != "up":
                st.update(status="up", since=now)
                if prev == "down" and m["alert"]:
                    send_alert("UP: %s" % (m["name"] or m["target"]), "%s is reachable again (%s, %.0f ms)" % (m["target"], detail, ms))
        else:
            st["fails"] += 1
            if st["fails"] >= a.get("fail_after", 2) and prev != "down":
                st.update(status="down", since=now)
                if m["alert"]:
                    send_alert("DOWN: %s" % (m["name"] or m["target"]), "%s failed %d times in a row: %s"
                               % (m["target"], st["fails"], detail))
        if days is not None and days < a.get("cert_days", 14) and m["alert"] and now - st["cert_alerted"] > 86400:
            st["cert_alerted"] = now
            send_alert("CERTIFICATE: %s" % (m["name"] or m["target"]), "the certificate of %s expires in %d days" % (m["target"], days))


def check_now(m):
    with MON_LOCK:
        MON.setdefault(m["id"], {"status": "unknown", "since": time.time(), "fails": 0, "history": deque(maxlen=288),
                                 "cert_alerted": 0})["running"] = True
    try:
        record_result(m, *run_monitor(m))
    except Exception as e:
        record_result(m, False, 0, "check crashed: %s" % e, None)


def monitor_loop():
    """Run due checks, at most 8 at a time."""
    pool = ThreadPoolExecutor(8)
    time.sleep(3)
    while True:
        now = time.time()
        for m in list(STATE["cfg"].get("monitors", [])):
            st = MON.get(m["id"], {})
            if m["enabled"] and not st.get("running") and now - st.get("checked", 0) >= m["interval"]:
                with MON_LOCK:
                    MON.setdefault(m["id"], {"status": "unknown", "since": now, "fails": 0,
                                             "history": deque(maxlen=288), "cert_alerted": 0})["running"] = True
                pool.submit(check_now, m)
        time.sleep(5)


def monitor_status():
    out = {}
    with MON_LOCK:
        for mid, st in MON.items():
            h = list(st["history"])
            out[mid] = {k: st.get(k) for k in ("status", "since", "checked", "ms", "detail", "cert_days", "running", "fails")}
            out[mid]["uptime"] = round(100.0 * sum(1 for x in h if x[1]) / len(h), 1) if h else None
            out[mid]["history"] = [[x[0], 1 if x[1] else 0, x[2]] for x in h[-60:]]
    return out


def suggest_monitors(cfg):
    """Checks for every domain and enabled port rule that isn't monitored yet."""
    have = {m["target"] for m in cfg.get("monitors", [])}
    new = []
    for d in cfg["domains"]:
        if d["enabled"]:
            url = "%s://%s/" % ("https" if d["tls"] != "none" else "http", d["domain"])
            if url not in have:
                new.append({"name": d["domain"][:40], "type": "http", "target": url, "expect": "200-499"})
    for r in cfg["rules"]:
        if r["enabled"] and "tcp" in protos(r["proto"]):
            port = r["int_port"] or r["ext_port"].split("-")[0]
            t = "%s:%s" % (r["ip"], port)
            if t not in have and not any(x["target"] == t for x in new):
                new.append({"name": (r["name"] or t)[:40], "type": "tcp", "target": t})
    return new


def scan_allowed(ip):
    """Only this host, private/local ranges and known guests - never arbitrary internet hosts."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    own = {n["ip"] for n in host_networks()}
    guests = {i for g in GUEST_CACHE.get("data") or [] for i in g.get("ips", [])}
    return a.is_private or a.is_loopback or ip in own or ip in guests


def start_scan(target, ports):
    if not scan_allowed(target):
        raise ApiError("only this host's addresses, private networks and known guests can be scanned")
    if sum(1 for x in SCANS.values() if x["state"] == "running") >= 2:
        raise ApiError("two scans are already running - wait for them to finish", 429)
    sid = uuid.uuid4().hex[:8]
    SCANS[sid] = {"id": sid, "target": target, "total": len(ports), "done": 0, "open": [], "state": "running",
                  "started": time.time()}
    for k in sorted(SCANS, key=lambda k: SCANS[k]["started"])[:-6]:
        SCANS.pop(k, None)

    def probe(port):
        if MOCK:
            ok = MOCK.port_open(target, port)
        else:
            try:
                with socket.create_connection((target, port), 0.8):
                    ok = True
            except OSError:
                ok = False
        SCANS[sid]["done"] += 1
        if ok:
            try:
                name = SERVICE_NAMES.get(port) or socket.getservbyport(port, "tcp")
            except OSError:
                name = ""
            SCANS[sid]["open"].append({"port": port, "service": name, "risk": port_risk(port)})

    def job():
        with ThreadPoolExecutor(64) as ex:
            list(ex.map(probe, ports))
        SCANS[sid]["open"].sort(key=lambda x: x["port"])
        SCANS[sid]["state"] = "done"
        log("port scan of %s: %d open of %d" % (target, len(SCANS[sid]["open"]), len(ports)))

    threading.Thread(target=job, daemon=True).start()
    return SCANS[sid]


# --------------------------------------------------------------------------- fail2ban

F2B_JAILS = {  # jail -> (description, extra settings); filters prefixed pvegw- are written by pve-gateway
    "sshd": ("SSH logins", ["backend = systemd"]),
    "proxmox": ("Proxmox web UI logins (port 8006)", ["port = https,http,8006", "filter = pvegw-proxmox", "backend = systemd",
                                                      "journalmatch = _SYSTEMD_UNIT=pvedaemon.service"]),
    "pve-gateway": ("pve-gateway logins", ["filter = pvegw-login", "backend = systemd",
                                           "journalmatch = _SYSTEMD_UNIT=pve-gateway.service"]),
    "nginx-botsearch": ("bots probing nginx for missing pages (Let's Encrypt challenges are never counted)",
                        ["port = http,https", "logpath = /var/log/nginx/error.log",
                         "ignoreregex = .*/\\.well-known/acme-challenge/.*"]),
    "recidive": ("repeat offenders: banned again within a day -> banned for a week",
                 ["logpath = /var/log/fail2ban.log", "bantime = 1w", "findtime = 1d", "maxretry = 3"]),
}
F2B_FILTERS = {
    "pvegw-proxmox": ("[Definition]\nfailregex = authentication failure; rhost=(?:::ffff:)?<HOST> user=\\S+ msg=.*\n"
                      "ignoreregex =\njournalmatch = _SYSTEMD_UNIT=pvedaemon.service\n"),
    "pvegw-login": "[Definition]\nfailregex = login failed from (?:::ffff:)?<HOST>\\b\nignoreregex =\n",
}
F2B_JAIL_FILE = "/etc/fail2ban/jail.d/pve-gateway.local"
F2B_JOB = {"state": None, "msg": ""}
TIME_RE = re.compile(r"^(-1|\d{1,6}[smhdw]?)$")


def f2b_path(p):
    return MOCK.path_for(p) if MOCK else p


def validate_f2b(data, old):
    f = json.loads(json.dumps(old))
    for k in ("bantime", "findtime"):
        if k in data:
            v = str(data[k]).strip().lower()
            if not TIME_RE.match(v):
                raise ApiError("%s: a duration like 10m, 1h, 1d (or -1 = forever for the ban time)" % k)
            if k == "findtime" and v == "-1":
                raise ApiError("findtime can't be -1")
            f[k] = v
    if "maxretry" in data:
        try:
            f["maxretry"] = int(data["maxretry"])
        except (TypeError, ValueError):
            raise ApiError("maxretry must be a number")
        if not 1 <= f["maxretry"] <= 100:
            raise ApiError("maxretry: 1-100")
    if "ignoreip" in data:
        f["ignoreip"] = parse_networks(data["ignoreip"])
    if "jails" in data:
        jails = data["jails"] if isinstance(data["jails"], dict) else {}
        f["jails"] = {j: bool(jails.get(j, f["jails"].get(j, False))) for j in F2B_JAILS}
    if "managed" in data:
        f["managed"] = bool(data["managed"])
    return f


def build_f2b(cfg):
    f = cfg["fail2ban"]
    ignore = ["127.0.0.1/8", "::1"] + f["ignoreip"]
    out = ["# Generated by pve-gateway %s - managed in the web UI (Security tab); changes here are overwritten." % VERSION,
           "# jail.d/*.local is read last, so these settings win over jail.local.", "",
           "[DEFAULT]", "bantime = %s" % f["bantime"], "findtime = %s" % f["findtime"], "maxretry = %d" % f["maxretry"],
           "ignoreip = %s" % " ".join(ignore)]
    for jail, (desc, extra) in F2B_JAILS.items():
        out += ["", "# %s" % desc, "[%s]" % jail, "enabled = %s" % ("true" if f["jails"].get(jail) else "false")]
        if jail == "pve-gateway":
            extra = ["port = %d" % int(cfg.get("port", 8099))] + extra
        out += extra
    return "\n".join(out) + "\n"


def f2b_installed():
    return sh(["fail2ban-client", "--version"])[0] == 0


def apply_f2b(cfg):
    """Write jail.d/pve-gateway.local + filters, test the config (restore on failure), reload. Returns error or None."""
    if not cfg["fail2ban"]["managed"]:
        path = f2b_path(F2B_JAIL_FILE)
        if os.path.exists(path):  # handing control back: remove our file
            os.remove(path)
            run(["fail2ban-client", "reload"])
        return None
    if not f2b_installed():
        return "fail2ban is not installed - click Install or run: apt install fail2ban"
    files = {F2B_JAIL_FILE: build_f2b(cfg)}
    files.update({"/etc/fail2ban/filter.d/%s.conf" % n: t for n, t in F2B_FILTERS.items()})
    if DRY_RUN:
        log("[dry-run] would write %s" % ", ".join(files))
        return None
    old = {p: _read(f2b_path(p)) for p in files}
    for p, text in files.items():
        os.makedirs(os.path.dirname(f2b_path(p)), exist_ok=True)
        with open(f2b_path(p), "w") as fh:
            fh.write(text)
    rc, out = run(["fail2ban-client", "-t"])
    if rc != 0:
        for p, text in old.items():
            if text is None:
                os.remove(f2b_path(p))
            else:
                with open(f2b_path(p), "w") as fh:
                    fh.write(text)
        return "fail2ban rejected the configuration (previous files restored): %s" % out[-400:]
    if sh(["fail2ban-client", "ping"])[0] != 0:
        rc, out = run(["systemctl", "enable", "--now", "fail2ban"])
    else:
        rc, out = run(["fail2ban-client", "reload"])
    if rc != 0:
        return "fail2ban reload failed: %s" % out[-300:]
    log("fail2ban: applied (%s)" % ", ".join(j for j, on in cfg["fail2ban"]["jails"].items() if on))
    return None


def f2b_status():
    res = {"installed": f2b_installed(), "running": False, "version": "", "jails": [], "job": F2B_JOB}
    if not res["installed"]:
        return res
    res["version"] = sh(["fail2ban-client", "--version"])[1].splitlines()[0]
    rc, out = sh(["fail2ban-client", "status"])
    if rc != 0:
        return res
    res["running"] = True
    m = re.search(r"Jail list:\s*(.*)", out)
    for jail in [j.strip() for j in (m.group(1) if m else "").split(",") if j.strip()]:
        rc, js = sh(["fail2ban-client", "status", jail])
        num = lambda k: int((re.search(r"%s:\s*(\d+)" % k, js) or [0, 0])[1])
        banned = re.search(r"Banned IP list:\s*(.*)", js)
        res["jails"].append({"name": jail, "failed": num("Currently failed"), "failed_total": num("Total failed"),
                             "banned": num("Currently banned"), "banned_total": num("Total banned"),
                             "ips": (banned.group(1).split() if banned else [])[:200]})
    return res


def f2b_install():
    if F2B_JOB.get("state") == "pending":
        return
    F2B_JOB.update(state="pending", msg="installing fail2ban ...")

    def job():
        rc, out = run(["apt-get", "install", "-y", "-q", "fail2ban"], timeout=600)
        if rc != 0:
            F2B_JOB.update(state="error", msg="apt-get install failed: %s - if apt reports 401 from enterprise.proxmox.com, "
                           "run: curl -fsSL %s/master/install.sh | sh -s -- fix-repos" % (out[-300:], REPO_RAW))
            return
        err = apply_f2b(STATE["cfg"])
        F2B_JOB.update(state="error" if err else "ok", msg=err or "fail2ban installed")

    threading.Thread(target=job, daemon=True).start()


# --------------------------------------------------------------------------- firewall

CH_IN = "PVEGW_IN"
FW_ACTIONS = ("ACCEPT", "DROP", "REJECT")
FW_PROTOS = ("tcp", "udp", "icmp", "any")
FW_PENDING = {}   # {"old": firewall cfg, "deadline": ts, "timer": Timer} while a change waits for confirmation
FW_TEMPLATES = {
    "web": ("Web server (HTTP/HTTPS)", [("ACCEPT", "tcp", "80,443", "")]),
    "mail": ("Mail server", [("ACCEPT", "tcp", "25,465,587,110,995,143,993", "")]),
    "dns": ("DNS server", [("ACCEPT", "tcp", "53", ""), ("ACCEPT", "udp", "53", "")]),
    "wireguard": ("WireGuard VPN", [("ACCEPT", "udp", "51820", "")]),
    "ssh": ("SSH", [("ACCEPT", "tcp", "22", "")]),
    "proxmox": ("Proxmox web UI + console (8006, 3128, 5900-5999)", [("ACCEPT", "tcp", "8006,3128,5900-5999", "")]),
    "database-lan": ("Databases from private networks only", [("ACCEPT", "tcp", "3306,5432,6379,27017", n) for n in
                                                            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")] +
                     [("DROP", "tcp", "3306,5432,6379,27017", "")]),
}
PRIVATE_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def fw_ports(spec):
    """'22,80,8000-8100' -> normalised list of 'a' / 'a-b' (max 15 entries, iptables multiport)."""
    out = []
    if isinstance(spec, (list, tuple)):
        spec = ",".join(str(x) for x in spec)
    for part in re.split(r"[\s,]+", str(spec or "").strip()):
        if part:
            a, b = parse_ports(part)
            out.append(str(a) if a == b else "%d-%d" % (a, b))
    if len(out) > 15:
        raise ApiError("at most 15 ports/ranges per rule")
    return out


def validate_fw_rule(data, cfg, rid=None):
    if not isinstance(data, dict):
        raise ApiError("rule must be an object")
    r = {"id": rid or uuid.uuid4().hex[:8], "enabled": bool(data.get("enabled", True))}
    r["action"] = str(data.get("action", "ACCEPT")).upper()
    if r["action"] not in FW_ACTIONS:
        raise ApiError("action must be ACCEPT, DROP or REJECT")
    r["proto"] = str(data.get("proto", "tcp")).lower()
    if r["proto"] not in FW_PROTOS:
        raise ApiError("protocol must be tcp, udp, icmp or any")
    r["ports"] = fw_ports(data.get("ports")) if r["proto"] in ("tcp", "udp") else []
    if r["proto"] in ("tcp", "udp") and not r["ports"]:
        raise ApiError("give the port(s) for a %s rule, e.g. 80,443 or 8000-8100" % r["proto"])
    src = str(data.get("source", "") or "").strip()
    if src:
        try:
            src = str(ipaddress.ip_network(src, strict=False))
        except ValueError:
            raise ApiError("source must be an IP address or network")
        if src in ("0.0.0.0/0", "::/0"):  # = everyone
            src = ""
    r["source"] = src
    r["comment"] = str(data.get("comment", "") or "").strip()
    if not re.match(r"^[A-Za-z0-9 _.:/@+(),-]{0,50}$", r["comment"]):  # no quotes: it ends up in an iptables comment
        raise ApiError("comment: max 50 chars, letters/digits/space and _.:/@+(),- only")
    if r["action"] != "ACCEPT" and not r["source"] and r["enabled"]:  # never lock the admin out
        vital = {22, 8006, int(cfg.get("port", 8099))}
        covered = set()
        for p in r["ports"] or (["1-65535"] if r["proto"] == "any" else []):
            a, b = parse_ports(p)
            covered |= {x for x in vital if a <= x <= b}
        if covered:
            raise ApiError("a %s rule for everyone on port %s would lock you out - give a source network"
                           % (r["action"], ", ".join(map(str, sorted(covered)))))
    return r


def validate_fw(data, old, cfg):
    f = json.loads(json.dumps(old))
    if "backend" in data:
        if data["backend"] not in ("custom", "pve"):
            raise ApiError("backend must be custom or pve")
        f["backend"] = data["backend"]
    if "policy" in data:
        if data["policy"] not in ("accept", "drop"):
            raise ApiError("policy must be accept or drop")
        f["policy"] = data["policy"]
    for k in ("enabled", "allow_ping"):
        if k in data:
            f[k] = bool(data[k])
    if "rules" in data:
        if not isinstance(data["rules"], list) or len(data["rules"]) > 200:
            raise ApiError("rules must be a list (max 200)")
        f["rules"] = [validate_fw_rule(r, cfg, r.get("id") if isinstance(r, dict) else None) for r in data["rules"]]
    return f


def fw_safety(cfg):
    """Rules the firewall always keeps open (before the user's rules) so the host stays manageable.
    (action, proto, ports, source, why, in-interface)"""
    f = cfg["firewall"]
    ui_src = cfg.get("ui_allow") or [""]
    rules = [("ACCEPT", "tcp", ["22"], "", "safety: SSH"), ("ACCEPT", "tcp", ["8006"], "", "safety: Proxmox UI")]
    rules += [("ACCEPT", "tcp", [str(cfg.get("port", 8099))], s, "safety: pve-gateway UI") for s in ui_src]
    if owns_web_ports(cfg):
        rules.append(("ACCEPT", "tcp", ["80", "443"], "", "safety: domains (nginx)"))
    if os.path.exists("/etc/pve/corosync.conf") and not MOCK:
        rules.append(("ACCEPT", "udp", ["5405-5412"], "", "safety: cluster (corosync)"))
    for t in cfg.get("wireguard", {}).get("tunnels", []):
        if t["enabled"]:
            rules.append(("ACCEPT", "udp", [str(t["port"])], "", "safety: WireGuard %s" % t["name"]))
    if f.get("allow_ping"):
        rules.append(("ACCEPT", "icmp", [], "", "ping"))
    rules = [r + ("",) for r in rules]
    if f.get("enabled"):  # guests on SDN VNets ask the host's dnsmasq for an address
        rules += [("ACCEPT", "udp", ["67"], "", "safety: DHCP on %s" % v, v) for v in sdn_dhcp_vnets()]
    return rules


def fw_iptables(cfg, v6):
    """iptables-restore payload for the PVEGW_IN chain (one address family)."""
    f = cfg["firewall"]
    out = ["*filter", ":%s - [0:0]" % CH_IN]
    if not f["enabled"]:
        return "\n".join(out + ["COMMIT"]) + "\n"
    out += ["-A %s -i lo -j ACCEPT" % CH_IN, "-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" % CH_IN,
            "-A %s -m conntrack --ctstate INVALID -j DROP" % CH_IN]
    if v6:  # neighbour discovery etc. - IPv6 breaks without it
        out += ["-A %s -p ipv6-icmp -m icmp6 --icmpv6-type %s -j ACCEPT" % (CH_IN, t)
                for t in ("neighbour-solicitation", "neighbour-advertisement", "router-advertisement", "packet-too-big")]

    def emit(action, proto, ports, src, tag, iface=""):
        if src and (":" in src) != v6:
            return
        base = "-A %s" % CH_IN + (" -i %s" % iface if iface else "") + (" -s %s" % src if src else "")
        target = "-j %s" % action + (" --reject-with %s" % ("icmp6-port-unreachable" if v6 else "icmp-port-unreachable")
                                     if action == "REJECT" else "")
        cm = '-m comment --comment "gw:fw:%s"' % tag
        if proto == "icmp":
            out.append("%s -p %s %s %s" % (base, "ipv6-icmp -m icmp6 --icmpv6-type echo-request" if v6 else
                                           "icmp -m icmp --icmp-type echo-request", cm, target))
        elif proto == "any":
            out.append("%s %s %s" % (base, cm, target))
        else:
            out.append("%s -p %s -m multiport --dports %s %s %s" % (base, proto, ",".join(p.replace("-", ":") for p in ports),
                                                                     cm, target))
    for action, proto, ports, src, why, iface in fw_safety(cfg):
        emit(action, proto, ports, src, "safety", iface)
    for r in f["rules"]:
        if r["enabled"]:
            emit(r["action"], r["proto"], r["ports"], r["source"], r["id"])
    if f["policy"] == "drop":
        out.append('-A %s -m comment --comment "gw:fw:policy" -j DROP' % CH_IN)
    return "\n".join(out + ["COMMIT"]) + "\n"


def apply_fw_custom(cfg):
    for v6, restore, ipt in ((False, "iptables-restore", "iptables"), (True, "ip6tables-restore", "ip6tables")):
        rc, out = run([restore, "--noflush"], fw_iptables(cfg, v6))
        if rc != 0:
            return "%s failed: %s" % (restore, out)
        hooked = run([ipt, "-C", "INPUT", "-j", CH_IN], check_only=True)[0] == 0
        if cfg["firewall"]["enabled"] and not hooked:
            rc, out = run([ipt, "-I", "INPUT", "1", "-j", CH_IN])
            if rc != 0:
                return "cannot hook INPUT: %s" % out
        elif not cfg["firewall"]["enabled"] and hooked:
            run([ipt, "-D", "INPUT", "-j", CH_IN])
    return None


def node_name():
    return socket.gethostname().split(".")[0]


def pve_fw_rules():
    """All rules of this node's Proxmox firewall (ordered)."""
    rc, out = sh(["pvesh", "get", "/nodes/%s/firewall/rules" % node_name(), "--output-format", "json"])
    if rc != 0:
        raise ApiError("cannot read the Proxmox firewall rules: %s" % out[-200:], 500)
    try:
        return sorted(json.loads(out), key=lambda r: r.get("pos", 0))
    except ValueError:
        raise ApiError("unexpected answer from pvesh", 500)


def apply_fw_pve(cfg):
    """Replace pve-gateway's rules (comment pvegw:...) at the top of the node firewall, set options."""
    f, node = cfg["firewall"], node_name()
    try:
        ours = [r for r in pve_fw_rules() if str(r.get("comment", "")).startswith("pvegw:")]
    except ApiError as e:
        return str(e)
    for r in sorted(ours, key=lambda r: -r["pos"]):
        rc, out = run(["pvesh", "delete", "/nodes/%s/firewall/rules/%d" % (node, r["pos"])])
        if rc != 0:
            return "cannot delete Proxmox firewall rule %d: %s" % (r["pos"], out)
    wanted = []
    if f["enabled"]:
        wanted = [(a, p, ports, src, "safety: " + why.split(": ", 1)[-1], i) for a, p, ports, src, why, i in fw_safety(cfg)]
        wanted += [(r["action"], r["proto"], r["ports"], r["source"], r["comment"] or r["id"], "") for r in f["rules"] if r["enabled"]]
    for pos, (action, proto, ports, src, why, iface) in enumerate(wanted):
        cmd = ["pvesh", "create", "/nodes/%s/firewall/rules" % node, "--type", "in", "--action", action, "--enable", "1",
               "--pos", str(pos), "--comment", ("pvegw: " + why)[:60]]
        if proto == "icmp":
            cmd += ["--macro", "Ping"]
        elif proto != "any":
            cmd += ["--proto", proto, "--dport", ",".join(p.replace("-", ":") for p in ports)]
        if src:
            cmd += ["--source", src]
        if iface:
            cmd += ["--iface", iface]
        rc, out = run(cmd)
        if rc != 0:
            return "cannot create Proxmox firewall rule (%s): %s" % (why, out[-200:])
    if f["enabled"]:
        for path, opts in (("/nodes/%s/firewall/options" % node, ["--enable", "1"]),
                           ("/cluster/firewall/options", ["--enable", "1", "--policy_in", f["policy"].upper()])):
            rc, out = run(["pvesh", "set", path] + opts)
            if rc != 0:
                return "cannot set Proxmox firewall options: %s" % out[-200:]
    return None


def apply_fw(cfg, old=None):
    """Apply the firewall with the selected backend; when the backend changed, clear the previous one first."""
    if old and old.get("backend") != cfg["firewall"]["backend"]:
        prev = dict(cfg, firewall=dict(old, enabled=False))
        (apply_fw_pve if old["backend"] == "pve" else apply_fw_custom)(prev)
    with LOCK:
        err = (apply_fw_pve if cfg["firewall"]["backend"] == "pve" else apply_fw_custom)(cfg)
    if not err:
        f = cfg["firewall"]
        log("firewall (%s): %s, policy %s, %d rule(s)" % (f["backend"], "on" if f["enabled"] else "off", f["policy"], len(f["rules"])))
    return err


def fw_change(new_cfg, user):
    """Apply now; keep it only if confirmed within 60 s (otherwise the previous firewall comes back)."""
    old_fw = (FW_PENDING.get("old") if FW_PENDING else None) or STATE["cfg"]["firewall"]
    if FW_PENDING.get("timer"):
        FW_PENDING["timer"].cancel()
    err = apply_fw(new_cfg, STATE["cfg"]["firewall"])
    if err:
        apply_fw(STATE["cfg"], new_cfg["firewall"])
        raise ApiError(err, 500)
    STATE["cfg"] = new_cfg
    risky = new_cfg["firewall"]["enabled"]

    def revert():
        log("firewall change was not confirmed within 60 s - restoring the previous firewall", "warn")
        cur = STATE["cfg"]["firewall"]
        STATE["cfg"] = dict(STATE["cfg"], firewall=old_fw)
        apply_fw(STATE["cfg"], cur)
        FW_PENDING.clear()

    if risky:
        t = threading.Timer(60, revert)
        t.daemon = True
        t.start()
        FW_PENDING.update(old=old_fw, deadline=time.time() + 60, timer=t)
    else:
        FW_PENDING.clear()
        save_config(new_cfg)
    log("%s changed the firewall%s" % (user, " (waiting for confirmation)" if risky else ""))


def fw_confirm():
    if FW_PENDING.get("timer"):
        FW_PENDING["timer"].cancel()
    FW_PENDING.clear()
    save_config(STATE["cfg"])


def fw_state(cfg):
    f = cfg["firewall"]
    res = {"settings": f, "safety": [{"action": a, "proto": p, "ports": po, "source": s, "why": w, "iface": i}
                                        for a, p, po, s, w, i in fw_safety(cfg)],
           "pending": max(0, int(FW_PENDING["deadline"] - time.time())) if FW_PENDING.get("deadline") else 0,
           "templates": {k: v[0] for k, v in FW_TEMPLATES.items()}, "other_rules": [], "pve_enabled": None}
    rc, st = sh(["pve-firewall", "status"])
    res["pve_enabled"] = rc == 0 and "enabled" in st
    if f["backend"] == "pve":
        try:
            res["other_rules"] = [r for r in pve_fw_rules() if not str(r.get("comment", "")).startswith("pvegw:")]
        except ApiError as e:
            res["error"] = str(e)
    return res


def fw_template_rules(name):
    if name == "risky-lan":
        ports = sorted({port for proto, port, scope, proc in exposed_services()
                        if RISKY_PORTS.get(port) or 5900 <= port <= 5999})
        if not ports:
            raise ApiError("no risky services listen on all interfaces right now")
        spec = ",".join(map(str, ports[:15]))
        return [{"action": "ACCEPT", "proto": "tcp", "ports": spec, "source": n, "comment": "risky ports: LAN"} for n in PRIVATE_NETS] + \
               [{"action": "DROP", "proto": "tcp", "ports": spec, "source": "", "comment": "risky ports: not from internet"}]
    if name not in FW_TEMPLATES:
        raise ApiError("unknown template")
    label, rules = FW_TEMPLATES[name]
    return [{"action": a, "proto": p, "ports": ports, "source": src, "comment": label[:40]} for a, p, ports, src in rules]


# --------------------------------------------------------------------------- wireguard

WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")  # base64 of 32 bytes
WG_NAME_RE = re.compile(r"^[a-z][a-z0-9]{0,14}$")
WG_JOB = {"state": None, "msg": ""}


def wg_secret(name, value=None):
    """Read or write <config dir>/wireguard/<name> (0600)."""
    d = os.path.join(CONF_DIR, "wireguard")
    p = os.path.join(d, name)
    if value is None:
        return (_read(p) or "").strip()
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value.strip() + "\n")
    os.replace(p + ".tmp", p)


def wg_forget(name):
    try:
        os.remove(os.path.join(CONF_DIR, "wireguard", name))
    except OSError:
        pass


def wg_installed():
    return sh(["wg", "--version"])[0] == 0


def wg_genkey():
    rc, priv = run(["wg", "genkey"], check_only=True)
    if rc != 0 or not WG_KEY_RE.match(priv.strip()):
        raise ApiError("cannot generate a WireGuard key (is wireguard-tools installed?)", 500)
    return priv.strip(), wg_pubkey(priv.strip())


def wg_pubkey(priv):
    rc, pub = run(["wg", "pubkey"], data=priv + "\n", check_only=True)
    if rc != 0 or not WG_KEY_RE.match(pub.strip()):
        raise ApiError("cannot derive the WireGuard public key", 500)
    return pub.strip()


def wg_defaults(cfg):
    """Suggestions for a new tunnel: a free 10.99.x.0/24, port 51820, the public endpoint, guest networks."""
    used = [ipaddress.ip_network(n["network"]) for n in host_networks()]
    used += [ipaddress.ip_interface(t["address"]).network for t in cfg["wireguard"]["tunnels"]]
    sub = next(n for n in ipaddress.ip_network("10.99.0.0/16").subnets(new_prefix=24) if not any(n.overlaps(u) for u in used))
    ports = {t["port"] for t in cfg["wireguard"]["tunnels"]}
    nets = host_networks()
    pub = [n["ip"] for n in nets if n["public"]] or [n["ip"] for n in nets if n["wan"]]
    return {"name": "wg%d" % len(cfg["wireguard"]["tunnels"]), "address": "%s/24" % next(sub.hosts()),
            "port": next(p for p in range(51820, 52000) if p not in ports), "endpoint": pub[0] if pub else "",
            "client_routes": [n["network"] for n in nets if not n["public"] and not n["wan"]]}


def validate_wg_tunnel(data, others, cfg, tid=None):
    t = {"id": tid or uuid.uuid4().hex[:8], "enabled": bool(data.get("enabled", True)), "nat": bool(data.get("nat", True))}
    t["name"] = str(data.get("name", "")).strip()
    if not WG_NAME_RE.match(t["name"]):
        raise ApiError("interface name: lowercase letters/digits, e.g. wg0")
    try:
        itf = ipaddress.IPv4Interface(str(data.get("address", "")).strip())
    except ValueError:
        raise ApiError("tunnel address must be like 10.99.0.1/24")
    if itf.network.prefixlen > 30 or itf.ip in (itf.network.network_address, itf.network.broadcast_address):
        raise ApiError("tunnel address: a host address in a /30 or bigger network, e.g. 10.99.0.1/24")
    t["address"] = str(itf)
    try:
        t["port"] = int(data.get("port", 51820))
    except (TypeError, ValueError):
        raise ApiError("port must be a number")
    if not 1 <= t["port"] <= 65535:
        raise ApiError("port out of range")
    t["endpoint"] = str(data.get("endpoint", "") or "").strip().lower()
    if t["endpoint"] and not (HOSTNAME_RE.match(t["endpoint"]) or _is_ip(t["endpoint"])):
        raise ApiError("endpoint: this host's public hostname or IP that clients connect to")
    t["client_routes"] = parse_networks(data.get("client_routes", []))
    t["dns"] = [x for x in _as_list(data.get("dns", [])) if x.strip()]
    if any(not _is_ip(x) for x in t["dns"]):
        raise ApiError("DNS servers must be IP addresses")
    for o in others:
        if o["name"] == t["name"]:
            raise ApiError("a tunnel named %s already exists" % t["name"])
        if o["port"] == t["port"]:
            raise ApiError("port %d is used by tunnel %s" % (t["port"], o["name"]))
        if ipaddress.ip_interface(o["address"]).network.overlaps(itf.network):
            raise ApiError("%s overlaps tunnel %s" % (itf.network, o["name"]))
    for n in host_networks():
        if ipaddress.ip_network(n["network"]).overlaps(itf.network):
            raise ApiError("%s overlaps the host network on %s - pick another subnet" % (itf.network, n["iface"]))
    t["peers"] = []
    return t


def validate_wg_peer(data, tunnel, pid=None):
    p = {"id": pid or uuid.uuid4().hex[:8], "enabled": bool(data.get("enabled", True)), "psk": bool(data.get("psk", True))}
    p["name"] = str(data.get("name", "")).strip()
    if not p["name"] or not NAME_RE.match(p["name"]):
        raise ApiError("name: 1-40 chars, letters/digits/space/_.:/@+- only")
    p["kind"] = "site" if data.get("kind") == "site" else "device"
    net = ipaddress.ip_interface(tunnel["address"]).network
    taken = {ipaddress.ip_interface(tunnel["address"]).ip} | {ipaddress.ip_interface(x["address"]).ip
                                                             for x in tunnel["peers"] if x["id"] != p["id"]}
    addr = str(data.get("address", "") or "").strip()
    if not addr:  # next free address in the tunnel
        ip = next((h for h in net.hosts() if h not in taken), None)
        if ip is None:
            raise ApiError("the tunnel subnet is full")
    else:
        try:
            ip = ipaddress.IPv4Interface(addr if "/" in addr else addr + "/32").ip
        except ValueError:
            raise ApiError("address must be an IP in %s" % net)
        if ip not in net or ip in taken or ip in (net.network_address, net.broadcast_address):
            raise ApiError("%s is not a free address in %s" % (ip, net))
    p["address"] = "%s/32" % ip
    p["allowed_ips"] = parse_networks(data.get("allowed_ips", [])) if p["kind"] == "site" else []
    p["public_key"] = str(data.get("public_key", "") or "").strip()
    if p["kind"] == "site" and not WG_KEY_RE.match(p["public_key"]):
        raise ApiError("paste the site's WireGuard public key (44 characters ending in =)")
    p["endpoint"] = str(data.get("endpoint", "") or "").strip()
    if p["endpoint"]:
        host, _, port = p["endpoint"].rpartition(":")
        if not port.isdigit() or not 1 <= int(port) <= 65535 or not (HOSTNAME_RE.match(host.lower()) or _is_ip(host.strip("[]"))):
            raise ApiError("endpoint must be host:port, e.g. office.example.com:51820")
    try:
        p["keepalive"] = int(data.get("keepalive", 25 if p["kind"] == "device" else 0) or 0)
    except (TypeError, ValueError):
        raise ApiError("keepalive must be seconds")
    if not 0 <= p["keepalive"] <= 3600:
        raise ApiError("keepalive: 0-3600 seconds")
    for o in tunnel["peers"]:
        if o["id"] != p["id"] and p["public_key"] and o["public_key"] == p["public_key"]:
            raise ApiError("this public key is already used by peer %s" % o["name"])
    return p


def wg_server_conf(t):
    out = ["# Generated by pve-gateway %s - managed in the web UI (VPN tab); changes here are overwritten." % VERSION,
           "[Interface]", "Address = %s" % t["address"], "ListenPort = %d" % t["port"],
           "PrivateKey = %s" % wg_secret(t["id"] + ".key")]
    for p in t["peers"]:
        if not p["enabled"] or not p["public_key"]:
            continue
        out += ["", "# %s (%s)" % (p["name"], p["kind"]), "[Peer]", "PublicKey = %s" % p["public_key"]]
        psk = wg_secret(p["id"] + ".psk") if p["psk"] else ""
        if psk:
            out.append("PresharedKey = %s" % psk)
        out.append("AllowedIPs = %s" % ", ".join([p["address"]] + p["allowed_ips"]))
        if p["endpoint"]:
            out.append("Endpoint = %s" % p["endpoint"])
        if p["keepalive"] and p["kind"] == "site":
            out.append("PersistentKeepalive = %d" % p["keepalive"])
    return "\n".join(out) + "\n"


def wg_client_conf(t, p):
    priv = wg_secret(p["id"] + ".key")
    if not priv:
        raise ApiError("this device's private key isn't stored (it was created elsewhere) - nothing to download", 404)
    net = str(ipaddress.ip_interface(t["address"]).network)
    endpoint = t["endpoint"] or wg_defaults(STATE["cfg"])["endpoint"]
    out = ["# %s - WireGuard config from pve-gateway (tunnel %s)" % (p["name"], t["name"]), "[Interface]",
           "PrivateKey = %s" % priv, "Address = %s" % p["address"]]
    if t["dns"]:
        out.append("DNS = %s" % ", ".join(t["dns"]))
    out += ["", "[Peer]", "PublicKey = %s" % t["public_key"]]
    psk = wg_secret(p["id"] + ".psk") if p["psk"] else ""
    if psk:
        out.append("PresharedKey = %s" % psk)
    out += ["Endpoint = %s:%d" % (("[%s]" % endpoint) if ":" in endpoint else endpoint, t["port"]),
            "AllowedIPs = %s" % ", ".join([net] + t["client_routes"]),
            "PersistentKeepalive = %d" % (p["keepalive"] or 25)]
    return "\n".join(out) + "\n"


def wg_conf_path(t):
    p = "/etc/wireguard/%s.conf" % t["name"]
    return MOCK.path_for(p) if MOCK else p


def wg_is_up(name):
    return sh(["wg", "show", name])[0] == 0


def apply_wg(cfg, old=None):
    """Write /etc/wireguard/<name>.conf (0600), bring tunnels up/down, sync peers without dropping sessions."""
    if not cfg["wireguard"]["tunnels"] and not (old and old["wireguard"]["tunnels"]):
        return None
    if not wg_installed():
        return "wireguard-tools is not installed - click Install or run: apt install wireguard-tools"
    names = {t["name"] for t in cfg["wireguard"]["tunnels"]}
    for t in (old or {}).get("wireguard", {}).get("tunnels", []):
        if t["name"] not in names:  # tunnel removed
            if wg_is_up(t["name"]):
                run(["wg-quick", "down", t["name"]])
            run(["systemctl", "disable", "wg-quick@%s" % t["name"]])
            try:
                os.remove(wg_conf_path(t))
            except OSError:
                pass
    for t in cfg["wireguard"]["tunnels"]:
        if DRY_RUN:
            log("[dry-run] would write %s" % wg_conf_path(t))
            continue
        path = wg_conf_path(t)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(wg_server_conf(t))
        os.replace(path + ".tmp", path)
        up = wg_is_up(t["name"])
        if t["enabled"]:
            if up:  # reload peers in place: established sessions keep running
                rc, stripped = run(["wg-quick", "strip", t["name"]], check_only=True)
                tmp = os.path.join(os.path.dirname(path), ".%s.strip" % t["name"])
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(stripped + "\n")
                rc, out = run(["wg", "syncconf", t["name"], tmp])
                os.remove(tmp)
            else:
                rc, out = run(["wg-quick", "up", t["name"]])
            if rc != 0:
                return "WireGuard %s: %s" % (t["name"], out[-300:])
            run(["systemctl", "enable", "wg-quick@%s" % t["name"]])
        else:
            if up:
                run(["wg-quick", "down", t["name"]])
            run(["systemctl", "disable", "wg-quick@%s" % t["name"]])
    log("wireguard: %s" % ", ".join("%s %s (%d peers)" % (t["name"], "up" if t["enabled"] else "down", len(t["peers"]))
                                    for t in cfg["wireguard"]["tunnels"]) or "no tunnels")
    return None


def wg_status(t):
    """{"up", "peers": {public_key: {"endpoint", "handshake", "rx", "tx", "online"}}}"""
    rc, out = sh(["wg", "show", t["name"], "dump"])
    res = {"up": rc == 0, "peers": {}}
    for line in out.splitlines()[1:] if rc == 0 else []:
        f = line.split("\t")
        if len(f) >= 8:
            hs = int(f[4]) if f[4].isdigit() else 0
            res["peers"][f[0]] = {"endpoint": "" if f[2] == "(none)" else f[2], "handshake": hs,
                                  "rx": int(f[5]) if f[5].isdigit() else 0, "tx": int(f[6]) if f[6].isdigit() else 0,
                                  "online": bool(hs) and time.time() - hs < 180}
    return res


def wg_install():
    if WG_JOB.get("state") == "pending":
        return
    WG_JOB.update(state="pending", msg="installing wireguard-tools ...")

    def job():
        rc, out = run(["apt-get", "install", "-y", "-q", "wireguard-tools"], timeout=600)
        WG_JOB.update(state="ok" if rc == 0 else "error",
                      msg="wireguard-tools installed" if rc == 0 else "apt-get install failed: %s" % out[-300:])

    threading.Thread(target=job, daemon=True).start()


def wg_save(new, old, user, what):
    """Apply WireGuard + the iptables side (NAT / forwarding / firewall port), then save."""
    with LOCK:
        err = apply_wg(new, old)
        if err:
            apply_wg(old, new)
            raise ApiError(err, 500)
        err = apply_rules(new)
        if not err and new["firewall"]["enabled"]:
            err = apply_fw(new)
        if err:
            raise ApiError(err, 500)
        save_config(new)
        STATE["cfg"] = new
    log("%s %s" % (user, what))


# --------------------------------------------------------------------------- sdn (DHCP / IPAM / DNS)
# Everything lives in Proxmox SDN (/etc/pve/sdn, cluster-wide), driven through pvesh - pve-gateway keeps no copy.
# Edits are "pending" in Proxmox until applied (Apply = `pvesh set /cluster/sdn`, reloads the node networks).

SDN_ID_RE = re.compile(r"^[a-z][a-z0-9]{1,7}$")  # Proxmox: zone / vnet ids, 2-8 chars
SDN_SUBNET_RE = re.compile(r"^[a-z][a-z0-9]{1,7}-[0-9.]+-\d{1,2}$")  # <zone>-<network>-<prefix>
MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
SDN_JOB = {"state": None, "msg": ""}
SDN_CACHE = {"t": 0, "data": None}
NIC_CACHE = {"t": 0, "data": []}


def sdn_error(out):
    out = (out or "").strip()
    if re.search(r"No '\w+' handler defined|Method '[^']+' not implemented|command not found", out):
        return "Proxmox SDN isn't available here - it needs Proxmox VE 8.1 or newer (apt install libpve-network-perl on 8.0)"
    return out.splitlines()[-1][:300] if out else "pvesh failed"


def pvesh_get(path, *args):
    rc, out = sh(["pvesh", "get", path, "--output-format", "json"] + list(args), timeout=20)
    if rc != 0:
        raise ApiError(sdn_error(out), 502)
    try:
        return json.loads(out or "null")
    except ValueError:
        raise ApiError("unexpected answer from pvesh get %s" % path, 502)


def pvesh_do(verb, path, opts=None, delete=()):
    """pvesh create|set|delete <path> --key value ... (list values repeat the option); --delete clears options."""
    cmd = ["pvesh", verb, path]
    for k, v in (opts or {}).items():
        for x in v if isinstance(v, list) else [v]:
            cmd += ["--" + k, str(x)]
    if delete:
        cmd += ["--delete", ",".join(delete)]
    rc, out = run(cmd, timeout=60)
    SDN_CACHE["t"] = 0
    if rc != 0:
        raise ApiError(sdn_error(out), 400)
    return out


def _dhcp_ranges(v):
    """Proxmox returns dhcp-range as property strings or objects: -> [[start, end], ...]."""
    res = []
    for x in v if isinstance(v, list) else ([v] if v else []):
        if isinstance(x, str):
            x = dict(kv.split("=", 1) for kv in x.split(",") if "=" in kv)
        if isinstance(x, dict) and x.get("start-address") and x.get("end-address"):
            res.append([x["start-address"], x["end-address"]])
    return res


def pve_version():
    try:
        v = pvesh_get("/version").get("version", "")
    except (ApiError, AttributeError):
        return "", False
    m = re.match(r"^(\d+)\.(\d+)", v)
    return v, bool(m) and (int(m.group(1)), int(m.group(2))) >= (8, 1)


def interfaces_sourced():
    """SDN writes /etc/network/interfaces.d/sdn - the main file has to include that directory."""
    p = MOCK.path_for("/etc/network/interfaces") if MOCK else "/etc/network/interfaces"
    return bool(re.search(r"^\s*(source\s+/etc/network/interfaces\.d/\*|source-directory\s+/etc/network/interfaces\.d)",
                          _read(p) or "", re.M))


def guest_nics():
    """[{vmid, name, nic, mac, bridge}] for every guest NIC - shows which guests sit on which VNet."""
    if time.time() - NIC_CACHE["t"] < 30:
        return NIC_CACHE["data"]
    res = []
    for g in list_guests():
        rc, conf = run(["qm" if g["type"] == "qemu" else "pct", "config", str(g["vmid"])], check_only=True)
        for nic, opts in re.findall(r"^(net\d+):\s*(\S+)", conf if rc == 0 else "", re.M):
            mac = re.search(r"(?:^|,)(?:\w+|hwaddr)=([0-9A-Fa-f:]{17})", opts)
            br = re.search(r"(?:^|,)bridge=([^,]+)", opts)
            if mac and br:
                res.append({"vmid": g["vmid"], "name": g["name"], "nic": nic, "mac": mac.group(1).lower(), "bridge": br.group(1)})
    NIC_CACHE.update(t=time.time(), data=res)
    return res


def sdn_ipam():
    """IPAM entries of the built-in Proxmox IPAM (gateways, DHCP leases, reservations)."""
    try:
        items = pvesh_get("/cluster/sdn/ipams/pve/status") or []
    except ApiError:
        return []
    return [{"zone": x.get("zone", ""), "vnet": x.get("vnet", ""), "subnet": x.get("subnet", ""), "ip": x.get("ip", ""),
             "mac": str(x.get("mac", "")).lower(), "hostname": x.get("hostname", ""), "vmid": x.get("vmid"),
             "gateway": bool(x.get("gateway"))} for x in items if isinstance(x, dict) and x.get("ip")]


def sdn_state(fresh=False):
    """Zones, VNets (with subnets), IPAM and DNS plugins as the UI shows them; 10 s cache."""
    if not fresh and SDN_CACHE["data"] and time.time() - SDN_CACHE["t"] < 10:
        return SDN_CACHE["data"]
    res = {"available": False, "error": "", "zones": [], "vnets": [], "ipam": [], "dns": [], "pending": False}
    try:
        zones = pvesh_get("/cluster/sdn/zones") or []
    except ApiError as e:
        res["error"] = str(e)
        SDN_CACHE.update(t=time.time(), data=res)
        return res
    res["available"] = True

    def states(path, key):  # {id: "new"|"changed"|"deleted"} for objects not applied yet
        try:
            return {x[key]: x["state"] for x in pvesh_get(path, "--pending", "1") or [] if x.get(key) and x.get("state")}
        except ApiError:
            return {}
    zst, vst = states("/cluster/sdn/zones", "zone"), states("/cluster/sdn/vnets", "vnet")
    for z in zones:
        res["zones"].append({"zone": z.get("zone"), "type": z.get("type", ""), "dhcp": z.get("dhcp", ""), "ipam": z.get("ipam", ""),
                             "dns": z.get("dns", ""), "reversedns": z.get("reversedns", ""), "dnszone": z.get("dnszone", ""),
                             "state": zst.get(z.get("zone"), "")})
    res["zones"] += [{"zone": k, "type": "", "dhcp": "", "ipam": "", "dns": "", "reversedns": "", "dnszone": "", "state": v}
                     for k, v in zst.items() if v == "deleted"]
    try:
        vnets = pvesh_get("/cluster/sdn/vnets") or []
    except ApiError as e:
        vnets, res["error"] = [], str(e)
    for v in vnets + [{"vnet": k, "zone": "", "deleted": True} for k, s in vst.items() if s == "deleted"]:
        name = v.get("vnet")
        subs, sst = [], {}
        if not v.get("deleted"):
            try:
                subs = pvesh_get("/cluster/sdn/vnets/%s/subnets" % name) or []
            except ApiError as e:
                res["error"] = str(e)
            sst = states("/cluster/sdn/vnets/%s/subnets" % name, "subnet")
        res["vnets"].append({
            "vnet": name, "zone": v.get("zone", ""), "alias": v.get("alias", ""), "tag": v.get("tag"),
            "state": vst.get(name, ""),
            "subnets": [{"id": s.get("subnet"), "cidr": s.get("cidr") or s.get("subnet", "").split("-", 1)[-1].replace("-", "/"),
                         "gateway": s.get("gateway", ""), "snat": bool(s.get("snat")),
                         "dhcp_range": _dhcp_ranges(s.get("dhcp-range")), "dns_server": s.get("dhcp-dns-server", ""),
                         "state": sst.get(s.get("subnet"), "")} for s in subs]
                       + [{"id": k, "cidr": k.split("-", 1)[-1].replace("-", "/"), "gateway": "", "snat": False, "dhcp_range": [],
                           "dns_server": "", "state": "deleted"} for k, s in sst.items() if s == "deleted"]})
    res["ipam"] = sdn_ipam()
    try:  # never pass the plugin's API key on
        res["dns"] = [{"dns": d.get("dns"), "type": d.get("type", ""), "url": d.get("url", "")} for d in pvesh_get("/cluster/sdn/dns") or []]
    except ApiError:
        pass
    res["pending"] = any(x["state"] for x in res["zones"] + res["vnets"]) or \
        any(s["state"] for v in res["vnets"] for s in v["subnets"])
    SDN_CACHE.update(t=time.time(), data=res)
    return res


def sdn_dhcp_vnets():
    """Applied VNets whose zone hands out DHCP - the host firewall must let DHCP requests in on them."""
    try:
        s = sdn_state()
    except ApiError:
        return []
    dhcp = {z["zone"] for z in s["zones"] if z["dhcp"] and z["state"] != "new"}
    return sorted(v["vnet"] for v in s["vnets"] if v["zone"] in dhcp and v["state"] != "new")


def validate_sdn_zone(data, sdn, zid=None):
    """-> (opts for pvesh, options to delete). New zones are always 'simple' (one host, no VLAN setup needed)."""
    opts, delete = {}, []
    if not zid:
        zid = str(data.get("zone", "")).strip()
        if not SDN_ID_RE.match(zid):
            raise ApiError("zone id: 2-8 lowercase letters/digits, starting with a letter (e.g. lab)")
        if any(z["zone"] == zid for z in sdn["zones"]):
            raise ApiError("zone %s already exists" % zid)
        opts.update(zone=zid, type="simple", ipam="pve")
    if data.get("dhcp"):
        opts["dhcp"] = "dnsmasq"
    elif zid:
        delete.append("dhcp")
    plugins = {d["dns"] for d in sdn["dns"]}
    for k in ("dns", "reversedns"):
        v = str(data.get(k, "") or "").strip()
        if v and v not in plugins:
            raise ApiError("unknown DNS plugin %s - add it in Proxmox: Datacenter > SDN > Options > DNS" % v)
        if v:
            opts[k] = v
        else:
            delete.append(k)
    dz = str(data.get("dnszone", "") or "").strip().lower().rstrip(".")
    if dz and not HOSTNAME_RE.match(dz):
        raise ApiError("DNS zone must be a domain, e.g. lab.example.com")
    if (opts.get("dns") or opts.get("reversedns")) and not dz:
        raise ApiError("set the DNS zone (domain) the guests' names are registered in")
    if dz:
        opts["dnszone"] = dz
    else:
        delete.append("dnszone")
    return opts, [] if "type" in opts else delete


def validate_sdn_vnet(data, sdn):
    vid = str(data.get("vnet", "")).strip()
    if not SDN_ID_RE.match(vid):
        raise ApiError("VNet name: 2-8 lowercase letters/digits, starting with a letter (it becomes the bridge name)")
    if any(v["vnet"] == vid for v in sdn["vnets"]):
        raise ApiError("VNet %s already exists" % vid)
    if vid in list_ifaces() or any(n["iface"] == vid for n in host_networks()):
        raise ApiError("%s is already an interface on this host - pick another name" % vid)
    zone = next((z for z in sdn["zones"] if z["zone"] == data.get("zone")), None)
    if not zone or zone["state"] == "deleted":
        raise ApiError("pick the zone this VNet belongs to")
    if zone["type"] != "simple":
        raise ApiError("zone %s is a %s zone - create its VNets in the Proxmox UI (they need a VLAN tag etc.)" % (zone["zone"], zone["type"]))
    alias = str(data.get("alias", "") or "").strip()
    if not NAME_RE.match(alias):
        raise ApiError("description: up to 40 chars, letters/digits/space/_.:/@+- only")
    return {"vnet": vid, "zone": zone["zone"]}, alias


def _sdn_ip(v, net, what):
    try:
        ip = ipaddress.IPv4Address(str(v).strip())
    except ValueError:
        raise ApiError("%s must be an IPv4 address in %s" % (what, net))
    if ip not in net or ip in (net.network_address, net.broadcast_address):
        raise ApiError("%s %s is not a usable address in %s" % (what, ip, net))
    return ip


def validate_sdn_subnet(data, vnet, sdn, cfg, sid=None):
    """-> pvesh opts. IPv4; must not clash with host networks, other subnets or WireGuard tunnels."""
    if sid:
        cur = next((s for s in vnet["subnets"] if s["id"] == sid), None)
        net = ipaddress.IPv4Network(cur["cidr"])
    else:
        try:
            net = ipaddress.IPv4Network(str(data.get("cidr", "")).strip(), strict=False)
        except ValueError:
            raise ApiError("subnet must be like 10.20.30.0/24")
        if not 8 <= net.prefixlen <= 29:
            raise ApiError("subnet size: /8 to /29")
        if not net.is_private:
            raise ApiError("use a private range (10.x, 172.16-31.x, 192.168.x) - guests get it via DHCP/NAT")
        for v in sdn["vnets"]:
            for s in v["subnets"]:
                if s["state"] != "deleted" and ipaddress.ip_network(s["cidr"]).overlaps(net):
                    raise ApiError("%s overlaps subnet %s on VNet %s" % (net, s["cidr"], v["vnet"]))
        for n in host_networks():
            if n["iface"] != vnet["vnet"] and ipaddress.ip_network(n["network"]).overlaps(net):
                raise ApiError("%s overlaps the host network %s on %s" % (net, n["network"], n["iface"]))
        for t in cfg["wireguard"]["tunnels"]:
            if ipaddress.ip_interface(t["address"]).network.overlaps(net):
                raise ApiError("%s overlaps WireGuard tunnel %s" % (net, t["name"]))
    gw = _sdn_ip(data.get("gateway") or next(net.hosts()), net, "gateway")
    opts = {"gateway": str(gw), "snat": 1 if data.get("snat", True) else 0}
    ranges = []
    for r in _as_list(data.get("dhcp_range", [])):
        r = r.strip() if isinstance(r, str) else "-".join(r)
        if not r:
            continue
        a, _, b = r.replace(" ", "").partition("-")
        start, end = _sdn_ip(a, net, "DHCP range start"), _sdn_ip(b or a, net, "DHCP range end")
        if start > end:
            raise ApiError("DHCP range %s: the start must come before the end" % r)
        if start <= gw <= end:
            raise ApiError("DHCP range %s contains the gateway %s" % (r, gw))
        ranges.append("start-address=%s,end-address=%s" % (start, end))
    zone = next((z for z in sdn["zones"] if z["zone"] == vnet["zone"]), {})
    if ranges and not zone.get("dhcp"):
        raise ApiError("zone %s has DHCP off - turn it on in the zone first" % vnet["zone"])
    dns = str(data.get("dns_server", "") or "").strip()
    if dns and not _is_ip(dns):
        raise ApiError("DNS server for DHCP clients must be an IP address")
    if not sid:
        opts.update(subnet=str(net), type="subnet")
    delete = []
    for k, v in (("dhcp-range", ranges), ("dhcp-dns-server", dns)):
        if v:
            opts[k] = v
        elif sid:
            delete.append(k)
    return opts, delete


def validate_sdn_ip(data, vnet, sdn):
    """A fixed IP for a MAC address (DHCP reservation) in the Proxmox IPAM."""
    try:
        ip = ipaddress.IPv4Address(str(data.get("ip", "")).strip())
    except ValueError:
        raise ApiError("IP must be an IPv4 address")
    sub = next((s for s in vnet["subnets"] if s["state"] != "deleted" and ip in ipaddress.ip_network(s["cidr"])), None)
    if not sub:
        raise ApiError("%s is not in a subnet of %s (%s)" % (ip, vnet["vnet"], ", ".join(s["cidr"] for s in vnet["subnets"]) or "none yet"))
    _sdn_ip(ip, ipaddress.ip_network(sub["cidr"]), "IP")
    if str(ip) == sub["gateway"]:
        raise ApiError("%s is the gateway" % ip)
    mac = str(data.get("mac", "")).strip().lower().replace("-", ":")
    if not MAC_RE.match(mac):
        raise ApiError("MAC must look like bc:24:11:12:34:56 (Proxmox shows it on the guest's network device)")
    for e in sdn["ipam"]:
        if e["ip"] == str(ip):
            raise ApiError("%s is already used by %s" % (ip, e["hostname"] or e["mac"] or "the gateway"))
        if e["mac"] == mac and e["vnet"] == vnet["vnet"]:
            raise ApiError("%s already has %s - delete that entry first" % (mac, e["ip"]))
    opts = {"zone": vnet["zone"], "ip": str(ip), "mac": mac}
    if str(data.get("vmid", "") or "").strip():
        try:
            opts["vmid"] = int(data["vmid"])
        except (TypeError, ValueError):
            raise ApiError("VM ID must be a number")
    return opts


def sdn_apply():
    """`pvesh set /cluster/sdn` starts a task that rewrites the SDN network config on every node; wait for it."""
    if SDN_JOB.get("state") == "pending":
        return
    SDN_JOB.update(state="pending", msg="applying SDN configuration ...", t=time.time())

    def job():
        rc, out = run(["pvesh", "set", "/cluster/sdn"], timeout=120)
        err = None if rc == 0 else sdn_error(out)
        upid = re.search(r"UPID:\S+", out or "")
        for _ in range(120) if upid and not err else []:
            try:
                st = pvesh_get("/nodes/%s/tasks/%s/status" % (node_name(), upid.group(0)))
            except ApiError as e:
                err = str(e)
                break
            if st.get("status") == "stopped":
                if st.get("exitstatus") != "OK":
                    err = "Proxmox reported: %s (see Datacenter > SDN in the Proxmox UI or the task log)" % st.get("exitstatus")
                break
            time.sleep(1)
        NET_CACHE["data"], SDN_CACHE["t"], GUEST_CACHE["t"], NIC_CACHE["t"] = None, 0, 0, 0
        SDN_JOB.update(state="error" if err else "ok", msg=err or "SDN configuration applied", t=time.time())
        log("SDN apply: %s" % (err or "ok"), "error" if err else "info")
        if not err and STATE["cfg"]["firewall"]["enabled"]:  # DHCP on new VNets
            e2 = apply_fw(STATE["cfg"])
            if e2:
                log("firewall after SDN apply: %s" % e2, "warn")

    threading.Thread(target=job, daemon=True).start()


def dnsmasq_install():
    """Proxmox runs one dnsmasq per zone (dnsmasq@<zone>); the default instance must stay off."""
    if SDN_JOB.get("state") == "pending":
        return
    SDN_JOB.update(state="pending", msg="installing dnsmasq ...", t=time.time())

    def job():
        rc, out = run(["apt-get", "install", "-y", "-q", "dnsmasq"], timeout=600)
        if rc == 0:
            run(["systemctl", "disable", "--now", "dnsmasq"])
        SDN_JOB.update(state="ok" if rc == 0 else "error", t=time.time(),
                       msg="dnsmasq installed" if rc == 0 else "apt-get install failed: %s" % out[-300:])

    threading.Thread(target=job, daemon=True).start()


def sdn_info():
    """GET /api/sdn: SDN state + host requirements + which guest NICs are on which VNet."""
    s = dict(sdn_state())
    ver, dhcp_ok = pve_version()
    s.update(version=ver, dhcp_ok=dhcp_ok, dnsmasq=sh(["dnsmasq", "--version"])[0] == 0, sourced=interfaces_sourced(), job=SDN_JOB)
    vnets = {v["vnet"] for v in s["vnets"]}
    s["nics"] = [n for n in guest_nics() if n["bridge"] in vnets] if s["available"] else []
    return s


# --------------------------------------------------------------------------- updates

UPDATE = {"latest": None, "changes": [], "checked": None, "error": None, "running": False, "started": None}
UPDATE_DIR = "/var/lib/pve-gateway/update"


def parse_version(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3]) or (0,)


def fetch_remote(path, ref):
    """A file from the GitHub repo at ref (TLS verified)."""
    if MOCK:
        return MOCK.remote_file(path)
    req = urllib.request.Request("%s/%s/%s" % (REPO_RAW, urllib.parse.quote(ref, safe=""), path),
                                 headers={"User-Agent": "pve-gateway/" + VERSION})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read(4000000)


def parse_changelog(text, newer_than):
    """[{"version", "notes"}] for CHANGELOG.md sections newer than the given version."""
    out = []
    for block in re.split(r"^## ", text, flags=re.M)[1:]:
        head, _, body = block.partition("\n")
        ver = head.split()[0] if head.split() else ""
        if parse_version(ver) > parse_version(newer_than):
            out.append({"version": ver, "title": head.strip(), "notes": body.strip()})
    return out


def check_update():
    ref = STATE["cfg"].get("update_ref", "master")
    try:
        src = fetch_remote("pve-gateway.py", ref).decode("utf-8", "replace")
        m = re.search(r'^VERSION = "([^"]+)"', src, re.M)
        if not m:
            raise ValueError("no VERSION found in %s/pve-gateway.py" % ref)
        try:
            changes = parse_changelog(fetch_remote("CHANGELOG.md", ref).decode("utf-8", "replace"), VERSION)
        except Exception:
            changes = []
        UPDATE.update(latest=m.group(1), changes=changes, checked=time.time(), error=None)
        log("update check: installed %s, latest %s" % (VERSION, m.group(1)), "debug")
    except Exception as e:
        UPDATE.update(checked=time.time(), error="cannot reach GitHub: %s" % e)
        log("update check failed: %s" % e, "warn")
    return update_info()


def update_info():
    latest, ref = UPDATE["latest"], STATE["cfg"].get("update_ref", "master")
    return {"current": VERSION, "latest": latest, "ref": ref, "checked": UPDATE["checked"], "error": UPDATE["error"],
            "available": bool(latest) and parse_version(latest) > parse_version(VERSION),
            "changes": UPDATE["changes"], "running": UPDATE["running"], "url": "%s/commits/%s" % (REPO_URL, ref)}


def run_update():
    """Download the latest release files, check them, and run install.sh outside our own service
    (systemd-run), because the installer restarts pve-gateway and would otherwise kill itself."""
    if UPDATE["running"] and time.time() - (UPDATE["started"] or 0) < 600:
        raise ApiError("an update is already running", 409)
    ref = STATE["cfg"].get("update_ref", "master")
    try:
        files = {n: fetch_remote(n, ref) for n in ("pve-gateway.py", "pve-gateway.service", "install.sh")}
    except Exception as e:
        raise ApiError("download failed: %s" % e, 502)
    src = files["pve-gateway.py"].decode("utf-8", "replace")
    m = re.search(r'^VERSION = "([^"]+)"', src, re.M)
    try:
        compile(src, "pve-gateway.py", "exec")
    except SyntaxError as e:
        raise ApiError("downloaded pve-gateway.py does not compile (%s) - not installing" % e, 502)
    if not m or not files["install.sh"].startswith(b"#!/bin/sh"):
        raise ApiError("downloaded files look wrong - not installing", 502)
    new = m.group(1)
    if MOCK:
        log("[mock] update to %s: would run install.sh via systemd-run" % new, "warn")
        return {"ok": True, "version": new, "mock": True}
    os.makedirs(UPDATE_DIR, mode=0o700, exist_ok=True)
    for name, data in files.items():
        with open(os.path.join(UPDATE_DIR, name), "wb") as f:
            f.write(data)
    unit = "pve-gateway-update"
    run(["systemctl", "reset-failed", unit + ".service"], check_only=True)
    rc, out = run(["systemd-run", "--unit", unit, "--collect", "--quiet", "--description", "pve-gateway update to " + new,
                   "/bin/sh", os.path.join(UPDATE_DIR, "install.sh")])
    if rc != 0:
        raise ApiError("could not start the update: %s" % out, 500)
    UPDATE.update(running=True, started=time.time())
    log("update to %s started (journalctl -u %s)" % (new, unit))
    return {"ok": True, "version": new}


def update_checker():
    time.sleep(5 if MOCK else 120)
    while True:
        if STATE["cfg"].get("update_check", True):
            info = check_update()
            if info["available"] and STATE["cfg"].get("auto_update") and not MOCK:
                try:
                    log("auto-update: installing %s" % info["latest"])
                    run_update()
                except ApiError as e:
                    log("auto-update failed: %s" % e, "error")
        time.sleep(86400)


# --------------------------------------------------------------------------- auth

def hash_password(pw, iters=200000):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return "pbkdf2_sha256$%d$%s$%s" % (iters, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def check_password(pw, stored):
    try:
        _, iters, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(iters))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def pve_ticket(params):
    """POST /access/ticket on the local Proxmox API. Returns the "data" dict or None."""
    body = urllib.parse.urlencode(params).encode()
    ctx = ssl._create_unverified_context()  # localhost only
    try:
        with urllib.request.urlopen("https://127.0.0.1:8006/api2/json/access/ticket", body,
                                    timeout=10, context=ctx) as resp:
            return json.load(resp).get("data") or None
    except Exception:
        return None


def pve_login(user, pw):
    """Returns (canonical user, None) on success, (user, challenge ticket) if a second factor is needed."""
    if "@" not in user:
        user += "@pam"
    d = pve_ticket({"username": user, "password": pw})
    if not d or not d.get("ticket"):
        return None, None
    if d.get("NeedTFA"):
        return d.get("username") or user, d["ticket"]
    return d.get("username"), None


def pve_tfa(user, challenge, code):
    """Second step: TOTP code (or "recovery:<code>") against the challenge ticket."""
    code = code if ":" in code else "totp:" + code
    d = pve_ticket({"username": user, "tfa-challenge": challenge, "password": code})
    return d.get("username") if d and d.get("ticket") and not d.get("NeedTFA") else None


def authenticate(user, pw):
    """(user, None) ok, (None, None) failed, (user, challenge) second factor needed."""
    cfg = STATE["cfg"]
    if cfg.get("pass_hash"):
        ok = hmac.compare_digest(user.encode(), cfg.get("local_user", "admin").encode()) and check_password(pw, cfg["pass_hash"])
        return (user if ok else None), None
    u, challenge = pve_login(user, pw)
    if not u or u not in cfg.get("allowed_users", []):
        return None, None
    return u, challenge


# --------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "pve-gateway/" + VERSION
    sys_version = ""
    timeout = 30

    def log_message(self, fmt, *args):
        log("%s %s" % (self.client_address[0], fmt % args), "debug")

    def send(self, code, body, ctype="application/json", cookies=(), headers=()):
        if ctype == "application/json":
            body = json.dumps(body)
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        raw = (self.headers.get("Content-Length") or "0").strip()
        if not raw.isdigit():  # "-1" would make rfile.read() read until the client hangs up
            raise ApiError("invalid Content-Length", 400)
        n = int(raw)
        if n > 65536:
            raise ApiError("request too large", 413)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ApiError("invalid JSON")

    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def client_ip(self):
        return norm_ip(self.client_address[0])

    def ua_hash(self):
        return hashlib.sha256((self.headers.get("User-Agent") or "").encode()).hexdigest()[:16]

    def sid_cookie(self):
        # __Host- needs Secure; cookies are not isolated by port, so the session is also bound to IP + browser
        return "__Host-pvegw_sid" if self.server.tls else "pvegw_sid"

    def session_user(self):
        tok = self.cookie(self.sid_cookie())
        s = SESSIONS.get(tok) if tok else None
        if s and s[1] > time.time() and s[2] == self.client_ip() and s[3] == self.ua_hash():
            s[1] = time.time() + SESSION_TTL
            return s[0]
        return None

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")

    def route(self, method):
        path = urllib.parse.urlsplit(self.path).path
        try:
            if not host_allowed(self.headers.get("Host"), STATE["cfg"]):
                log("rejected Host %r from %s" % (self.headers.get("Host"), self.client_ip()), "warn")
                return self.send(421, "pve-gateway: unknown hostname %r. Open the UI by IP address, or allow the name:\n"
                                 "  pve-gateway ui-host %s\n" % (self.headers.get("Host"), (self.headers.get("Host") or "").split(":")[0]),
                                 "text/plain")
            if method == "GET" and path in STATIC:
                ctype, content = STATIC[path]
                return self.send(200, content, ctype)
            if not path.startswith("/api/"):
                return self.send(404, {"error": "not found"})
            # custom header can't be sent cross-site without CORS preflight -> CSRF protection
            if method != "GET" and self.headers.get("X-PVEGW") != "1":
                return self.send(403, {"error": "missing X-PVEGW header"})
            if path == "/api/login" and method == "POST":
                return self.login()
            if path == "/api/authinfo" and method == "GET":
                local = bool(STATE["cfg"].get("pass_hash"))
                return self.send(200, {"mode": "local" if local else "pve", "mock": bool(MOCK),
                                       "user": "admin" if MOCK else "" if local else "root@pam"})
            user = self.session_user()
            if not user:
                return self.send(401, {"error": "login required"})
            self.api(method, path, user)
        except ApiError as e:
            self.send(e.code, {"error": str(e)})
        except Exception:
            traceback.print_exc()
            self.send(500, {"error": "internal error"})

    def login(self):
        ip, now = self.client_ip(), time.time()
        with LOGIN_LOCK:
            for k in [k for k, v in FAILS.items() if now - v[1] > LOGIN_WINDOW]:
                FAILS.pop(k, None)
            for k in [k for k, v in TFA_PENDING.items() if v["exp"] < now]:
                TFA_PENDING.pop(k, None)
            f = FAILS.get(ip)
            if f and f[0] >= LOGIN_MAX_FAILS:
                raise ApiError("too many failed attempts - try again in %d minutes"
                               % max(1, int((f[1] + LOGIN_WINDOW - now) // 60) + 1), 429)
            if ip in LOGIN_INFLIGHT or len(LOGIN_INFLIGHT) >= 8:
                raise ApiError("another login is being checked - try again in a moment", 429)
            LOGIN_INFLIGHT.add(ip)
            FAILS.setdefault(ip, [0, now])[0] += 1  # counted before checking, so parallel guesses can't skip it
        try:
            d = self.body()
            if d.get("tfa_id"):
                p = TFA_PENDING.pop(str(d["tfa_id"]), None)
                user = None
                if p and p["ip"] == ip and p["exp"] > now:
                    user = pve_tfa(p["user"], p["ticket"], str(d.get("code", "")).strip())
                    user = user if user in STATE["cfg"].get("allowed_users", []) else None
            else:
                user, challenge = authenticate(str(d.get("username", "")), str(d.get("password", "")))
                if user and challenge:
                    tid = secrets.token_urlsafe(16)
                    TFA_PENDING[tid] = {"user": user, "ticket": challenge, "ip": ip, "exp": now + 300}
                    return self.send(200, {"tfa": tid})
        finally:
            with LOGIN_LOCK:
                LOGIN_INFLIGHT.discard(ip)
        if not user:
            time.sleep(1)
            log("login failed from %s" % ip, "warn")  # fail2ban jail "pve-gateway" matches this line
            raise ApiError("invalid credentials or user not allowed", 401)
        with LOGIN_LOCK:
            FAILS.pop(ip, None)
        for k in [k for k, v in SESSIONS.items() if v[1] < now]:
            SESSIONS.pop(k, None)
        tok = secrets.token_urlsafe(32)
        SESSIONS[tok] = [user, now + SESSION_TTL, ip, self.ua_hash()]
        log("login %s from %s" % (user, ip))
        secure = "; Secure" if self.server.tls else ""
        self.send(200, {"user": user}, cookies=["%s=%s; Path=/; HttpOnly; SameSite=Strict%s" % (self.sid_cookie(), tok, secure)])

    def api(self, method, path, user):
        cfg = STATE["cfg"]
        if path == "/api/logout" and method == "POST":
            SESSIONS.pop(self.cookie(self.sid_cookie()), None)
            return self.send(200, {"ok": True}, cookies=["%s=; Path=/; Max-Age=0%s" % (
                self.sid_cookie(), "; Secure" if self.server.tls else "")])
        if path == "/api/state" and method == "GET":
            return self.send(200, {
                "user": user, "version": VERSION, "rules": cfg["rules"], "counters": counters(),
                "ui_open": not cfg.get("ui_allow"),
                "update": {"available": update_info()["available"], "latest": UPDATE["latest"]},
                "web_ports": [{"name": n, "status": st, "detail": dt} for n, st, dt in port_checks(cfg)]
                if cfg["domains"] and view_wants_ports(self) else None,
                "ifaces": list_ifaces(), "networks": host_networks(), "dry_run": DRY_RUN, "mock": bool(MOCK),
                "status": {"ip_forward": ip_forward_on(), "active": DRY_RUN or hooks_active(),
                           "last_apply": STATE["last_apply"], "last_error": STATE["last_error"]},
                "domains": cfg["domains"], "domain_status": domain_status(cfg), "acme_email": cfg.get("acme_email", ""),
                "wildcards": cfg["wildcards"], "wildcard_status": wildcard_status(cfg), "dns_providers": DNS_PROVIDERS,
                "nginx": {"last_apply": NGINX["last_apply"], "last_error": NGINX["last_error"]},
            })
        if path == "/api/wireguard" and method == "GET":
            tunnels = []
            for t in cfg["wireguard"]["tunnels"]:
                tunnels.append(dict(t, status=wg_status(t), peers=[dict(p, has_key=bool(wg_secret(p["id"] + ".key")))
                                                                   for p in t["peers"]]))
            return self.send(200, {"installed": wg_installed(), "job": WG_JOB, "tunnels": tunnels, "defaults": wg_defaults(cfg)})
        if path == "/api/wireguard/install" and method == "POST":
            wg_install()
            return self.send(200, {"ok": True})
        m = re.match(r"^/api/wireguard/tunnels(?:/([0-9a-f]{1,16}))?(?:/peers(?:/([0-9a-f]{1,16}))?(/config)?)?$", path)
        if m:
            return self.wireguard_api(method, path, m.group(1), m.group(2), bool(m.group(3)), user)
        if path == "/api/sdn" and method == "GET":
            return self.send(200, sdn_info())
        if path == "/api/sdn/install" and method == "POST":
            dnsmasq_install()
            log("%s started the dnsmasq installation" % user)
            return self.send(200, {"ok": True})
        if path == "/api/sdn/apply" and method == "POST":
            sdn_apply()
            log("%s applied the SDN configuration" % user)
            return self.send(200, {"ok": True})
        m = re.match(r"^/api/sdn/(zones|vnets)(?:/([a-z][a-z0-9]{1,7}))?(?:/(subnets|ips)(?:/([0-9a-z.-]{1,40}))?)?$", path)
        if m:
            return self.sdn_api(method, m.group(1), m.group(2), m.group(3), m.group(4), user)
        if path == "/api/firewall" and method == "GET":
            return self.send(200, dict(fw_state(cfg), client_ip=self.client_ip()))
        if path == "/api/firewall" and method == "PUT":
            with LOCK:
                new = dict(STATE["cfg"], firewall=validate_fw(self.body(), STATE["cfg"]["firewall"], STATE["cfg"]))
            fw_change(new, user)
            return self.send(200, dict(fw_state(STATE["cfg"]), client_ip=self.client_ip()))
        if path == "/api/firewall/confirm" and method == "POST":
            fw_confirm()
            log("%s confirmed the firewall change" % user)
            return self.send(200, {"ok": True})
        if path == "/api/firewall/revert" and method == "POST":
            if FW_PENDING.get("timer"):
                FW_PENDING["timer"].cancel()
                old = FW_PENDING["old"]
                cur = STATE["cfg"]["firewall"]
                STATE["cfg"] = dict(STATE["cfg"], firewall=old)
                apply_fw(STATE["cfg"], cur)
                FW_PENDING.clear()
            return self.send(200, {"ok": True})
        m = re.match(r"^/api/firewall/template/([\w-]{1,30})$", path)
        if m and method == "GET":
            return self.send(200, {"rules": fw_template_rules(m.group(1))})
        if path == "/api/fail2ban" and method == "GET":
            return self.send(200, dict(f2b_status(), settings=cfg["fail2ban"], jail_info={j: d for j, (d, _) in F2B_JAILS.items()},
                                       file=F2B_JAIL_FILE, client_ip=self.client_ip()))
        if path == "/api/fail2ban/install" and method == "POST":
            f2b_install()
            return self.send(200, {"ok": True})
        if path == "/api/fail2ban" and method == "PUT":
            with LOCK:
                new = dict(STATE["cfg"], fail2ban=validate_f2b(self.body(), STATE["cfg"]["fail2ban"]))
                err = apply_f2b(new)
                if err:
                    raise ApiError(err, 500)
                save_config(new)
                STATE["cfg"] = new
            log("%s changed fail2ban settings" % user)
            return self.send(200, {"ok": True})
        m = re.match(r"^/api/fail2ban/(ban|unban|unban-all)$", path)
        if m and method == "POST":
            d = self.body()
            ip, jail = str(d.get("ip", "")).strip(), str(d.get("jail", "")).strip()
            if m.group(1) == "unban-all":
                rc, out = run(["fail2ban-client", "unban", "--all"])
            else:
                if not _is_ip(ip) or not re.match(r"^[\w.-]{1,40}$", jail):
                    raise ApiError("give a jail and an IP address")
                if m.group(1) == "ban" and (ip == self.client_ip() or ipaddress.ip_address(ip).is_loopback):
                    raise ApiError("refusing to ban your own address or localhost")
                rc, out = run(["fail2ban-client", "set", jail, "%sip" % m.group(1), ip])
            if rc != 0:
                raise ApiError("fail2ban-client: %s" % out[-200:], 500)
            log("%s fail2ban %s %s %s" % (user, m.group(1), jail, ip))
            return self.send(200, {"ok": True})
        if path == "/api/monitors" and method == "GET":
            return self.send(200, {"monitors": cfg.get("monitors", []), "status": monitor_status(),
                                   "alerts": masked_alerts(cfg.get("alerts", {})),
                                   "scans": sorted(SCANS.values(), key=lambda x: -x["started"])})
        if path == "/api/monitors/suggest" and method == "POST":
            with LOCK:
                mons = list(STATE["cfg"].get("monitors", []))
                added = [validate_monitor(m, mons) for m in suggest_monitors(STATE["cfg"])]
                new = dict(STATE["cfg"], monitors=mons + added)
                save_config(new)
                STATE["cfg"] = new
            for m in added:
                threading.Thread(target=check_now, args=(m,), daemon=True).start()
            return self.send(200, {"added": len(added)})
        m = re.match(r"^/api/monitors(?:/([0-9a-f]{1,16}))?(/run)?$", path)
        if m:
            mid = m.group(1)
            if m.group(2):
                mon = next((x for x in cfg.get("monitors", []) if x["id"] == mid), None)
                if not mon or method != "POST":
                    raise ApiError("check not found", 404)
                check_now(mon)
                return self.send(200, {"status": monitor_status().get(mid)})
            with LOCK:
                mons = list(STATE["cfg"].get("monitors", []))
                idx = next((i for i, x in enumerate(mons) if x["id"] == mid), None) if mid else None
                if mid and idx is None:
                    raise ApiError("check not found", 404)
                if method == "POST" and not mid:
                    mon = validate_monitor(self.body(), mons)
                    mons.append(mon)
                elif method == "PUT" and mid:
                    mon = validate_monitor(self.body(), [x for x in mons if x["id"] != mid], mid)
                    mons[idx] = mon
                elif method == "DELETE" and mid:
                    mons.pop(idx)
                    mon = None
                    with MON_LOCK:
                        MON.pop(mid, None)
                else:
                    raise ApiError("method not allowed", 405)
                new = dict(STATE["cfg"], monitors=mons)
                save_config(new)
                STATE["cfg"] = new
            if mon and mon["enabled"]:
                threading.Thread(target=check_now, args=(mon,), daemon=True).start()
            return self.send(200, {"ok": True})
        if path == "/api/alerts" and method == "PUT":
            with LOCK:
                new = dict(STATE["cfg"], alerts=validate_alerts(self.body(), STATE["cfg"].get("alerts")))
                save_config(new)
                STATE["cfg"] = new
            return self.send(200, {"alerts": masked_alerts(new["alerts"])})
        if path == "/api/alerts/test" and method == "POST":
            send_alert("test alert", "If you can read this, alerts from pve-gateway reach you.")
            return self.send(200, {"ok": True})
        if path == "/api/scan" and method == "POST":
            d = self.body()
            return self.send(200, start_scan(str(d.get("target", "")).strip(), parse_port_list(d.get("ports", "common"))))
        m = re.match(r"^/api/scan/([0-9a-f]{1,16})$", path)
        if m and method == "GET":
            if m.group(1) not in SCANS:
                raise ApiError("scan not found", 404)
            return self.send(200, SCANS[m.group(1)])
        if path == "/api/update" and method == "GET":
            return self.send(200, update_info())
        if path == "/api/update/check" and method == "POST":
            return self.send(200, check_update())
        if path == "/api/update" and method == "POST":
            log("%s started an update" % user)
            return self.send(200, run_update())
        if path == "/api/settings" and method == "GET":
            return self.send(200, {"ui_allow": cfg.get("ui_allow", []), "allowed_hosts": cfg.get("allowed_hosts", []),
                                   "client_ip": self.client_ip(), "own_hosts": sorted(own_hostnames()),
                                   "allowed_users": cfg.get("allowed_users", []), "auth": "local" if cfg.get("pass_hash") else "pve",
                                   "auto_update": bool(cfg.get("auto_update"))})
        if path == "/api/settings" and method == "PUT":
            d = self.body()
            with LOCK:
                new = dict(STATE["cfg"])
                if "ui_allow" in d:
                    new["ui_allow"] = parse_networks(d["ui_allow"])
                if "allowed_hosts" in d:
                    new["allowed_hosts"] = parse_hostnames(d["allowed_hosts"])
                if "auto_update" in d:
                    new["auto_update"] = bool(d["auto_update"])
                if "allowed_users" in d:
                    users = [u.strip() for u in _as_list(d["allowed_users"]) if u.strip()]
                    bad = [u for u in users if not re.match(r"^[\w.-]{1,64}@[\w.-]{1,64}$", u)]
                    if bad:
                        raise ApiError("invalid Proxmox user '%s' (format: name@realm, e.g. admin@pve)" % bad[0])
                    if not new.get("pass_hash") and user not in users:
                        raise ApiError("this would lock you out: keep %s in the allowed users" % user)
                    new["allowed_users"] = users
                if not ui_client_allowed(self.client_ip(), new):
                    raise ApiError("this would lock you out: your IP %s is not in the allowed list" % self.client_ip())
                if not host_allowed(self.headers.get("Host"), new):
                    raise ApiError("this would lock you out: you opened the UI as %r, keep it in allowed hostnames"
                                   % self.headers.get("Host"))
                save_config(new)
                STATE["cfg"] = new
            log("%s changed settings: allow %s, hosts %s, users %s, auto-update %s" % (
                user, ", ".join(new["ui_allow"]) or "anyone", ", ".join(new["allowed_hosts"]) or "-",
                ", ".join(new.get("allowed_users", [])), "on" if new.get("auto_update") else "off"))
            return self.send(200, {"ok": True})
        if path == "/api/guests" and method == "GET":
            return self.send(200, {"guests": list_guests()})
        if path == "/api/apply" and method == "POST":
            err = apply_rules() or apply_nginx()
            if err:
                raise ApiError(err, 500)
            return self.send(200, {"ok": True})
        if path == "/api/debug" and method == "GET":
            return self.send(200, diagnostics())
        if path == "/api/debug/report" and method == "GET":
            return self.send(200, report_text(diagnostics()), "text/plain")
        if path == "/api/debug" and method == "POST":
            global VERBOSE
            VERBOSE = bool(self.body().get("verbose"))
            log("verbose logging %s by %s" % ("enabled" if VERBOSE else "disabled", user))
            return self.send(200, {"verbose": VERBOSE})
        if path == "/api/mock" and method == "POST":
            if not MOCK:
                raise ApiError("only available with --mock", 404)
            name = str(self.body().get("scenario", ""))
            try:
                desc = MOCK.scenario(name)
            except ValueError as e:
                raise ApiError(str(e))
            log("mock scenario '%s': %s" % (name, desc), "warn")
            return self.send(200, {"ok": True, "message": desc})
        m = re.match(r"^/api/domains/([0-9a-f]{1,16})/(test|cert)$", path)
        if m and method == "POST":
            dom = next((d for d in cfg["domains"] if d["id"] == m.group(1)), None)
            if not dom:
                raise ApiError("domain not found", 404)
            if m.group(2) == "test":
                return self.send(200, {"steps": test_domain(dom)})
            name, key = domain_cert(cfg, dom)
            if not name or not dom["enabled"]:
                raise ApiError("domain is disabled, HTTP only, or no wildcard covers it")
            CERT_JOBS.pop(key, None)
            issue_cert(dom["id"], force=True)
            return self.send(200, {"ok": True})
        m = re.match(r"^/api/wildcards/([0-9a-f]{1,16})/cert$", path)
        if m and method == "POST":
            w = next((x for x in cfg["wildcards"] if x["id"] == m.group(1)), None)
            if not w or not w["enabled"]:
                raise ApiError("wildcard not found or disabled", 404)
            CERT_JOBS.pop(w["id"], None)
            issue_wildcard(w["id"])
            return self.send(200, {"ok": True})
        m = re.match(r"^/api/wildcards(?:/([0-9a-f]{1,16}))?$", path)
        if m:
            return self.wildcards_api(method, m.group(1), cfg, user)
        m = re.match(r"^/api/domains(?:/([0-9a-f]{1,16}))?$", path)
        if m:
            return self.domains_api(method, m.group(1), cfg, user)
        m = re.match(r"^/api/rules/([0-9a-f]{1,16})/test$", path)
        if m and method == "POST":
            rule = next((r for r in cfg["rules"] if r["id"] == m.group(1)), None)
            if not rule:
                raise ApiError("rule not found", 404)
            return self.send(200, {"steps": test_rule(rule)})

        m = re.match(r"^/api/rules(?:/([0-9a-f]{1,16}))?$", path)
        if not m:
            raise ApiError("not found", 404)
        rid = m.group(1)
        with LOCK:
            rules = list(cfg["rules"])
            idx = next((i for i, r in enumerate(rules) if r["id"] == rid), None) if rid else None
            if rid and idx is None:
                raise ApiError("rule not found", 404)
            if method == "POST" and not rid:
                rule = validate_rule(self.body(), rules, cfg)
                rules.append(rule)
            elif method == "PUT" and rid:
                rule = validate_rule(self.body(), [r for r in rules if r["id"] != rid], cfg, rid)
                rules[idx] = rule
            elif method == "DELETE" and rid:
                rules.pop(idx)
            else:
                raise ApiError("method not allowed", 405)
            new = dict(cfg, rules=rules)
            err = apply_rules(new)  # atomic: on failure the old rules stay in place
            if err:
                apply_rules(cfg)
                raise ApiError(err, 500)
            save_config(new)
            STATE["cfg"] = new
            log("%s %s %s" % (user, method, rid or "new rule"))
        return self.send(200, {"ok": True, "rules": new["rules"]})


    def domains_api(self, method, did, cfg, user):
        with LOCK:
            domains = list(cfg["domains"])
            idx = next((i for i, d in enumerate(domains) if d["id"] == did), None) if did else None
            if did and idx is None:
                raise ApiError("domain not found", 404)
            dom, body = None, {}
            if method in ("POST", "PUT") and (method == "POST") == (not did):
                body = self.body()
                dom = validate_domain(body, [d for d in domains if d["id"] != did], cfg, did)
                if idx is None:
                    domains.append(dom)
                else:
                    domains[idx] = dom
            elif method == "DELETE" and did:
                domains.pop(idx)
            else:
                raise ApiError("method not allowed", 405)
            new = dict(cfg, domains=domains)
            email = str(body.get("acme_email", "") or "").strip()
            if email:
                if not EMAIL_RE.match(email):
                    raise ApiError("invalid Let's Encrypt email")
                new["acme_email"] = email
            err = apply_nginx(new)  # validated with nginx -t, old config restored on failure
            if err:
                raise ApiError(err, 500)
            if owns_web_ports(new) != owns_web_ports(cfg):
                err = apply_rules(new)  # take / release ports 80/443
                if err:
                    apply_nginx(cfg)
                    raise ApiError(err, 500)
            save_config(new)
            STATE["cfg"] = new
            log("%s %s domain %s" % (user, method, dom["domain"] if dom else did))
        if dom and dom["tls"] != "none" and dom["enabled"]:
            issue_cert(dom["id"])  # no-op for certbot if the cert already covers these names
        return self.send(200, {"ok": True})

    def wireguard_api(self, method, path, tid, pid, config, user):
        cfg = STATE["cfg"]
        tunnels = json.loads(json.dumps(cfg["wireguard"]["tunnels"]))
        t = next((x for x in tunnels if x["id"] == tid), None) if tid else None
        if tid and not t:
            raise ApiError("tunnel not found", 404)
        if "/peers" not in path:  # tunnel itself
            if method == "POST" and not tid:
                if not wg_installed():
                    raise ApiError("wireguard-tools is not installed - click Install first")
                new_t = validate_wg_tunnel(self.body(), tunnels, cfg)
                priv, new_t["public_key"] = wg_genkey()
                wg_secret(new_t["id"] + ".key", priv)
                tunnels.append(new_t)
                what = "created WireGuard tunnel %s" % new_t["name"]
            elif method == "PUT" and t:
                upd = validate_wg_tunnel(dict(t, **self.body()), [x for x in tunnels if x["id"] != tid], cfg, tid)
                upd.update(public_key=t["public_key"], peers=t["peers"])
                tunnels[tunnels.index(t)] = upd
                what = "changed WireGuard tunnel %s" % upd["name"]
            elif method == "DELETE" and t:
                tunnels.remove(t)
                for x in [t] + t["peers"]:
                    wg_forget(x["id"] + ".key")
                    wg_forget(x["id"] + ".psk")
                what = "deleted WireGuard tunnel %s" % t["name"]
            else:
                raise ApiError("method not allowed", 405)
            wg_save(dict(cfg, wireguard={"tunnels": tunnels}), cfg, user, what)
            return self.send(200, {"ok": True})
        if not t:
            raise ApiError("tunnel not found", 404)
        peer = next((x for x in t["peers"] if x["id"] == pid), None) if pid else None
        if pid and not peer:
            raise ApiError("peer not found", 404)
        if config:
            if method != "GET":
                raise ApiError("method not allowed", 405)
            conf = wg_client_conf(t, peer)
            fname = re.sub(r"[^A-Za-z0-9_.-]+", "-", peer["name"]).strip("-")[:30] or "peer"
            return self.send(200, conf, "text/plain", headers=[("Content-Disposition", 'attachment; filename="%s.conf"' % fname)])
        result = {"ok": True}
        if method == "POST" and not pid:
            np_ = validate_wg_peer(self.body(), t)
            if np_["kind"] == "device":
                priv, np_["public_key"] = wg_genkey()
                wg_secret(np_["id"] + ".key", priv)
            if np_["psk"]:
                rc, psk = run(["wg", "genpsk"], check_only=True)
                if rc == 0 and WG_KEY_RE.match(psk.strip()):
                    wg_secret(np_["id"] + ".psk", psk.strip())
            t["peers"].append(np_)
            what, peer = "added WireGuard peer %s to %s" % (np_["name"], t["name"]), np_
        elif method == "PUT" and peer:
            body = self.body()
            upd = validate_wg_peer(dict(peer, **body), t, pid)
            if upd["kind"] == "device":
                upd["public_key"] = peer["public_key"]
            t["peers"][t["peers"].index(peer)] = upd
            what, peer = "changed WireGuard peer %s" % upd["name"], upd
        elif method == "DELETE" and peer:
            t["peers"].remove(peer)
            wg_forget(peer["id"] + ".key")
            wg_forget(peer["id"] + ".psk")
            what, peer = "removed WireGuard peer %s" % peer["name"], None
        else:
            raise ApiError("method not allowed", 405)
        wg_save(dict(cfg, wireguard={"tunnels": tunnels}), cfg, user, what)
        if peer and method == "POST" and peer["kind"] == "device":
            result["config"] = wg_client_conf(t, peer)
            result["peer"] = peer["id"]
        return self.send(200, result)

    def sdn_api(self, method, kind, oid, sub, sid, user):
        with LOCK:
            sdn = sdn_state(fresh=True)
            if not sdn["available"]:
                raise ApiError(sdn["error"])
            if kind == "zones":
                z = next((x for x in sdn["zones"] if x["zone"] == oid), None) if oid else None
                if sub or (oid and not z):
                    raise ApiError("zone not found", 404)
                if method == "POST" and not oid:
                    opts, _ = validate_sdn_zone(self.body(), sdn)
                    pvesh_do("create", "/cluster/sdn/zones", opts)
                    what = "created SDN zone %s" % opts["zone"]
                elif method == "PUT" and z:
                    opts, delete = validate_sdn_zone(self.body(), sdn, oid)
                    pvesh_do("set", "/cluster/sdn/zones/" + oid, opts, delete)
                    what = "changed SDN zone %s" % oid
                elif method == "DELETE" and z:
                    left = [v["vnet"] for v in sdn["vnets"] if v["zone"] == oid and v["state"] != "deleted"]
                    if left:
                        raise ApiError("zone %s still has VNets (%s) - delete them first" % (oid, ", ".join(left)))
                    pvesh_do("delete", "/cluster/sdn/zones/" + oid)
                    what = "deleted SDN zone %s" % oid
                else:
                    raise ApiError("method not allowed", 405)
                log("%s %s" % (user, what))
                return self.send(200, {"ok": True})
            v = next((x for x in sdn["vnets"] if x["vnet"] == oid), None) if oid else None
            if oid and not v:
                raise ApiError("VNet not found", 404)
            base = "/cluster/sdn/vnets/%s" % oid
            if not sub:
                if method == "POST" and not oid:
                    opts, alias = validate_sdn_vnet(self.body(), sdn)
                    if alias:
                        opts["alias"] = alias
                    pvesh_do("create", "/cluster/sdn/vnets", opts)
                    what = "created SDN VNet %s" % opts["vnet"]
                elif method == "PUT" and v:
                    alias = str(self.body().get("alias", "") or "").strip()
                    if not NAME_RE.match(alias):
                        raise ApiError("description: up to 40 chars, letters/digits/space/_.:/@+- only")
                    pvesh_do("set", base, {"alias": alias} if alias else {}, [] if alias else ["alias"])
                    what = "changed SDN VNet %s" % oid
                elif method == "DELETE" and v:
                    nics = ["%s (%s)" % (n["name"] or n["vmid"], n["nic"]) for n in guest_nics() if n["bridge"] == oid]
                    if nics:
                        raise ApiError("still used by %s - move those network devices to another bridge first" % ", ".join(nics))
                    if any(s_["state"] != "deleted" for s_ in v["subnets"]):
                        raise ApiError("delete the subnets of %s first" % oid)
                    pvesh_do("delete", base)
                    what = "deleted SDN VNet %s" % oid
                else:
                    raise ApiError("method not allowed", 405)
            elif sub == "subnets" and v:
                s_ = next((x for x in v["subnets"] if x["id"] == sid), None) if sid else None
                if sid and (not s_ or not SDN_SUBNET_RE.match(sid)):
                    raise ApiError("subnet not found", 404)
                if method == "POST" and not sid:
                    opts, _ = validate_sdn_subnet(self.body(), v, sdn, STATE["cfg"])
                    pvesh_do("create", base + "/subnets", opts)
                    what = "added subnet %s to VNet %s" % (opts["subnet"], oid)
                elif method == "PUT" and s_:
                    opts, delete = validate_sdn_subnet(self.body(), v, sdn, STATE["cfg"], sid)
                    pvesh_do("set", base + "/subnets/" + sid, opts, delete)
                    what = "changed subnet %s" % s_["cidr"]
                elif method == "DELETE" and s_:
                    pvesh_do("delete", base + "/subnets/" + sid)
                    what = "deleted subnet %s" % s_["cidr"]
                else:
                    raise ApiError("method not allowed", 405)
            elif sub == "ips" and v:
                if method == "POST" and not sid:
                    opts = validate_sdn_ip(self.body(), v, sdn)
                    pvesh_do("create", base + "/ips", opts)
                    what = "reserved %s for %s on %s" % (opts["ip"], opts["mac"], oid)
                elif method == "DELETE" and sid:
                    e = next((x for x in sdn["ipam"] if x["vnet"] == oid and x["ip"] == sid), None)
                    if not e:
                        raise ApiError("no IPAM entry for %s on %s" % (sid, oid), 404)
                    if e["gateway"]:
                        raise ApiError("that is the subnet's gateway - change the subnet instead")
                    opts = {"zone": v["zone"], "ip": sid}
                    if e["mac"]:
                        opts["mac"] = e["mac"]
                    pvesh_do("delete", base + "/ips", opts)
                    what = "removed IPAM entry %s on %s" % (sid, oid)
                else:
                    raise ApiError("method not allowed", 405)
            else:
                raise ApiError("not found", 404)
        GUEST_CACHE["t"] = 0
        log("%s %s" % (user, what))
        return self.send(200, {"ok": True})

    def wildcards_api(self, method, wid, cfg, user):
        with LOCK:
            wcs = list(cfg["wildcards"])
            idx = next((i for i, w in enumerate(wcs) if w["id"] == wid), None) if wid else None
            if wid and idx is None:
                raise ApiError("wildcard not found", 404)
            old = wcs[idx] if idx is not None else None
            w, body, creds = None, {}, None
            if method in ("POST", "PUT") and (method == "POST") == (not wid):
                body = self.body()
                w = validate_wildcard(body, [x for x in wcs if x["id"] != wid], wid)
                if old and w["zone"] != old["zone"]:
                    raise ApiError("the zone can't be changed - add a new wildcard instead")
                creds = build_creds(w, body.get("credentials"), old)
                if idx is None:
                    wcs.append(w)
                else:
                    wcs[idx] = w
            elif method == "DELETE" and wid:
                wcs.pop(idx)
            else:
                raise ApiError("method not allowed", 405)
            new = dict(cfg, wildcards=wcs)
            orphans = [d["domain"] for d in cfg["domains"] if d["enabled"] and d["tls"] == "wildcard"
                       and wildcard_for(cfg, d) and not wildcard_for(new, d)]
            if orphans:
                raise ApiError("still used by %s - switch those domains to another HTTPS option first" % ", ".join(orphans))
            email = str(body.get("acme_email", "") or "").strip()
            if email:
                if not EMAIL_RE.match(email):
                    raise ApiError("invalid Let's Encrypt email")
                new["acme_email"] = email
            if creds is not None:
                write_creds(w, creds)
            elif old:
                try:
                    os.remove(cred_path(old))
                except OSError:
                    pass
            save_config(new)
            STATE["cfg"] = new
            log("%s %s wildcard *.%s" % (user, method, (w or old)["zone"]))
            err = apply_nginx(new)  # enabling/disabling changes which certificate domains use
        if w and w["enabled"]:
            issue_wildcard(w["id"])
        return self.send(200, {"ok": True, "warning": err})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    tls = False
    max_conns, max_per_ip = 64, 16  # one thread per connection: cap them (slowloris)

    def __init__(self, *a, **kw):
        self.conn_lock, self.active = threading.Lock(), {}
        super().__init__(*a, **kw)

    def verify_request(self, request, client_address):
        ip = norm_ip(client_address[0])
        if not ui_client_allowed(ip, STATE["cfg"]):
            log("refused connection from %s (not in ui_allow)" % ip, "debug")
            return False
        with self.conn_lock:
            if sum(self.active.values()) >= self.max_conns or self.active.get(ip, 0) >= self.max_per_ip:
                log("too many connections, dropping %s" % ip, "debug")
                return False
            self.active[ip] = self.active.get(ip, 0) + 1
        return True

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            ip = norm_ip(client_address[0])
            with self.conn_lock:
                self.active[ip] = self.active.get(ip, 1) - 1
                if self.active[ip] <= 0:
                    self.active.pop(ip, None)


def tls_context(cfg):
    pairs = [(cfg["cert"], cfg["key"])] if cfg.get("cert") else [
        ("/etc/pve/local/pveproxy-ssl.pem", "/etc/pve/local/pveproxy-ssl.key"),
        ("/etc/pve/local/pve-ssl.pem", "/etc/pve/local/pve-ssl.key"),
    ]
    for cert, key in pairs:
        if os.path.exists(cert) and os.path.exists(key):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert, key)
            return ctx, cert, key
    return None, None, None


def cert_reloader(ctx, cert, key):
    """Pick up renewed certificates (e.g. Proxmox ACME/Let's Encrypt) without a restart."""
    def mtime():
        try:
            return os.stat(cert).st_mtime, os.stat(key).st_mtime
        except OSError:
            return None
    last = mtime()
    while True:
        time.sleep(300)
        cur = mtime()
        if cur and cur != last:
            try:
                ctx.load_cert_chain(cert, key)  # new connections use the new cert
                last = cur
                log("reloaded TLS certificate %s" % cert)
            except (OSError, ssl.SSLError) as e:
                log("certificate reload failed: %s" % e, "error")


def serve(cfg):
    apply_rules()
    apply_nginx()
    if cfg["wireguard"]["tunnels"]:
        err = apply_wg(cfg)
        if err:
            log(err, "error")
    if cfg["firewall"]["enabled"] and cfg["firewall"]["backend"] == "custom":
        err = apply_fw(cfg)
        if err:
            log(err, "error")
    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=update_checker, daemon=True).start()
    threading.Thread(target=monitor_loop, daemon=True).start()
    try:
        httpd = Server((cfg["listen"], int(cfg["port"])), Handler)
    except OSError as e:
        sys.exit("cannot listen on %s:%s: %s\n(is it already running? stop it, or use --port N)"
                 % (cfg["listen"], cfg["port"], e.strerror or e))
    ctx, cert, key = tls_context(cfg)
    if ctx:
        threading.Thread(target=cert_reloader, args=(ctx, cert, key), daemon=True).start()
        # handshake happens lazily in the worker thread, so a slow client can't block accept()
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
        httpd.tls = True
    scheme = "https" if ctx else "http"
    log("listening on %s://%s:%s/%s" % (scheme, cfg["listen"], cfg["port"], " (cert %s)" % cert if cert else " (NO TLS!)"))
    if MOCK:
        log("MOCK MODE: simulated Proxmox host, state in %s" % MOCK.path)
    log("auth: " + ("local user '%s'" % cfg["local_user"] if cfg.get("pass_hash")
                    else "Proxmox login, allowed: %s" % ", ".join(cfg["allowed_users"])))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


# --------------------------------------------------------------------------- UI

INDEX_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PVE Gateway</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><link rel="stylesheet" href="/app.css">
</head><body>
<div id="login" class="center" hidden>
  <form id="loginForm" class="card login">
    <h1 class="brand"><img src="/favicon.svg" alt="" width="32" height="32">PVE Gateway</h1>
    <p class="muted" id="loginHint">Sign in with your Proxmox account</p>
    <label>User<input name="username" autocomplete="username" value="root@pam" required></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
    <label id="tfaRow" hidden>Two-factor code<input name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456 (or recovery:…)"></label>
    <button type="submit">Sign in</button>
    <p id="loginErr" class="err"></p>
  </form>
</div>
<div id="app" hidden>
  <header>
    <h1 class="brand"><img src="/favicon.svg" alt="" width="26" height="26">PVE Gateway</h1>
    <nav class="tabs"><a href="#rules" data-view="rules">Ports</a><a href="#domains" data-view="domains">Domains</a><a href="#monitor" data-view="monitor">Monitor</a><a href="#security" data-view="security">Security</a><a href="#vpn" data-view="vpn">VPN</a><a href="#network" data-view="network">Network</a><a href="#settings" data-view="settings">Settings</a><a href="#debug" data-view="debug">Debug</a></nav>
    <div id="status" class="chips"></div>
    <span class="spacer"></span>
    <span id="who" class="muted"></span>
    <button id="logout" class="ghost">Sign out</button>
  </header>
  <main id="view-rules">
    <div class="bar">
      <button id="addBtn">+ Add rule</button>
      <button id="reapply" class="ghost" title="Re-write iptables rules from saved config">Re-apply</button>
      <span id="msg"></span>
    </div>
    <div id="netRules" class="card netbar" hidden></div>
    <div class="card scroll">
      <table>
        <thead><tr><th>On</th><th>Name</th><th>Proto</th><th>Host port</th><th></th><th>Destination</th><th>Source</th><th>Iface</th><th class="num">Hits</th><th></th></tr></thead>
        <tbody id="rules"></tbody>
      </table>
      <p id="empty" class="muted pad" hidden>No forwarding rules yet. Click <b>+ Add rule</b>.</p>
    </div>
    <p class="muted small">Only traffic addressed to this host is forwarded. Rules are kept in iptables chains
      <code>PVEGW_*</code> and restored automatically when the service starts.</p>
  </main>
  <main id="view-domains" hidden>
    <div class="bar">
      <button id="addDomBtn">+ Add domain</button>
      <span id="domMsg"></span>
    </div>
    <div id="netDomains" class="card netbar" hidden></div>
    <div id="webPorts" class="card netbar" hidden></div>
    <div id="nginxErr" class="card banner" hidden></div>
    <div class="card scroll">
      <table>
        <thead><tr><th>On</th><th>Domain</th><th></th><th>Upstream</th><th>TLS</th><th>Allowed</th><th></th></tr></thead>
        <tbody id="domains"></tbody>
      </table>
      <p id="domEmpty" class="muted pad" hidden>No domains yet. Point a DNS A record at this host, then click <b>+ Add domain</b>.</p>
    </div>
    <div class="sub-head"><h2>Wildcard certificates</h2><button id="addWcBtn" class="ghost">+ Add wildcard</button></div>
    <div class="card scroll">
      <table>
        <thead><tr><th>On</th><th>Certificate</th><th>DNS provider</th><th>Status</th><th>Used by</th><th></th></tr></thead>
        <tbody id="wildcards"></tbody>
      </table>
      <p id="wcEmpty" class="muted pad" hidden>One certificate for <b>example.com</b> + <b>*.example.com</b>, verified through your
        DNS provider's API. It doesn't need port 80, and new subdomains get HTTPS instantly: pick <i>Wildcard</i> as the domain's HTTPS option.</p>
    </div>
    <p class="muted small">nginx on this host answers on ports 80/443 and proxies each domain to a guest
      (<code>/etc/nginx/conf.d/pve-gateway.conf</code>). With Let's Encrypt, certbot gets and renews certificates automatically.
      DNS must point at this host's public IP, and if the host is behind a router, the router must forward ports 80 and 443 to it.</p>
  </main>
  <main id="view-monitor" hidden>
    <div class="bar">
      <button id="addMonBtn">+ Add check</button>
      <button id="suggestMon" class="ghost" title="HTTP checks for every domain, TCP checks for every port rule">Add checks for my domains &amp; ports</button>
      <span id="monMsg" class="muted small"></span>
    </div>
    <div class="card scroll">
      <table>
        <thead><tr><th>Status</th><th>Name</th><th>Target</th><th>Last 60</th><th class="num">Response</th><th class="num">Uptime</th><th>Since</th><th></th></tr></thead>
        <tbody id="monitors"></tbody>
      </table>
      <p id="monEmpty" class="muted pad" hidden>No health checks yet. Click <b>Add checks for my domains &amp; ports</b> to start with one check per domain and port rule.</p>
    </div>
    <div class="sub-head"><h2>Alerts</h2></div>
    <div class="card form-card" id="alertsCard">
      <p class="muted small">Sent when a check goes down (after the configured number of failures), comes back up, or a certificate is about to expire.</p>
      <div class="grid">
        <label>E-mail to<input id="alEmail" placeholder="you@example.com (uses this host's mail system)"></label>
        <label>Webhook URL<input id="alHook" placeholder="Slack / Discord / any URL (JSON POST)"></label>
        <label>Telegram bot token<input id="alTgToken" type="password" autocomplete="off" placeholder="123456:ABC…"></label>
        <label>Telegram chat id<input id="alTgChat" placeholder="e.g. 123456789"></label>
        <label>Alert after failures in a row<input id="alFails" inputmode="numeric"></label>
        <label>Warn when a certificate expires within (days)<input id="alCert" inputmode="numeric"></label>
      </div>
      <p id="alErr" class="err"></p>
      <div class="actions"><span id="alMsg" class="muted small"></span><button type="button" class="ghost" id="alTest">Send test alert</button><button type="button" id="alSave">Save</button></div>
    </div>
    <div class="sub-head"><h2>Port scanner</h2></div>
    <div class="card form-card">
      <p class="muted small">TCP scan from this host. It shows what this host can reach - the view from the internet can differ (provider firewall, rules that only match outside traffic). Only this host, private networks and your guests can be scanned.</p>
      <div class="grid">
        <label>Target<input id="scanTarget" list="scanTargets" placeholder="IP address" autocomplete="off"><datalist id="scanTargets"></datalist></label>
        <label>Ports<select id="scanPorts"><option value="common">~90 common ports</option><option value="1-1024">1-1024</option><option value="1-5000">1-5000</option><option value="custom">custom…</option></select></label>
        <label class="wide" id="scanCustomRow" hidden>Custom ports<input id="scanCustom" placeholder="22,80,443,8000-8100"></label>
      </div>
      <p id="scanErr" class="err"></p>
      <div class="actions"><span id="scanMsg" class="muted small"></span><button type="button" id="scanBtn">Scan</button></div>
      <div class="scroll"><table id="scanTable" hidden><thead><tr><th class="num">Port</th><th>Service</th><th>Risk</th></tr></thead><tbody id="scanRows"></tbody></table></div>
    </div>
  </main>
  <main id="view-security" hidden>
    <div class="sub-head" style="margin-top:0"><h2>Firewall</h2><span id="fwState"></span><span class="spacer"></span>
      <span id="fwDirty" class="muted small"></span><button type="button" id="fwApply">Apply</button></div>
    <div id="fwPending" class="card banner warn-banner" hidden>The new firewall is active. <b>Can you still reach this page?</b>
      It is reverted in <b id="fwLeft"></b> s unless you keep it.
      <span class="spacer"></span><button type="button" id="fwKeep">Keep</button><button type="button" class="ghost" id="fwRevert">Revert now</button></div>
    <p id="fwErr" class="err"></p>
    <div class="card form-card">
      <div class="grid">
        <label>Backend<select id="fwBackend"><option value="custom">pve-gateway (iptables + ip6tables)</option>
          <option value="pve">Proxmox firewall (rules visible in the Proxmox UI)</option></select></label>
        <label>Traffic no rule matches<select id="fwPolicy"><option value="accept">allow (only DROP/REJECT rules block)</option>
          <option value="drop">drop (only allowed ports are open)</option></select></label>
        <label class="check"><input type="checkbox" id="fwEnabled"> Firewall enabled</label>
        <label class="check"><input type="checkbox" id="fwPing"> Answer ping</label>
      </div>
      <p class="hint" id="fwSafety"></p>
    </div>
    <div class="bar" style="margin-top:12px">
      <button type="button" class="ghost" id="fwAdd">+ Add rule</button>
      <select id="fwTemplate"><option value="">Add from template…</option></select>
    </div>
    <div class="card scroll">
      <table><thead><tr><th>#</th><th>On</th><th>Action</th><th>Proto</th><th>Ports</th><th>Source</th><th>Comment</th><th></th></tr></thead>
        <tbody id="fwRules"></tbody></table>
      <p id="fwEmpty" class="muted pad" hidden>No rules yet - add one or start from a template.</p>
    </div>
    <div id="fwOtherWrap" hidden>
      <div class="sub-head"><h2>Other Proxmox firewall rules</h2><span class="muted small">not managed by pve-gateway, evaluated after its rules</span></div>
      <div class="card scroll"><table><thead><tr><th>#</th><th>Action</th><th>Proto</th><th>Ports</th><th>Source</th><th>Comment</th></tr></thead>
        <tbody id="fwOther"></tbody></table></div>
    </div>
    <div class="sub-head"><h2>Fail2ban</h2><span id="f2bState"></span><span class="spacer"></span>
      <button type="button" id="f2bInstall" hidden>Install fail2ban</button>
      <button type="button" class="ghost" id="f2bUnbanAll" hidden>Unban all</button></div>
    <p id="f2bMsg" class="muted small"></p>
    <div class="card scroll" id="f2bJailsCard" hidden>
      <table><thead><tr><th>Jail</th><th class="num">Failed now / total</th><th class="num">Banned now / total</th><th></th></tr></thead>
        <tbody id="f2bJails"></tbody></table>
    </div>
    <div class="sub-head" id="f2bBannedHead" hidden><h2>Banned IPs <span id="f2bBannedCount" class="muted"></span></h2>
      <input id="f2bFilter" placeholder="filter by IP or jail" spellcheck="false" style="width:220px">
      <span class="spacer"></span><button type="button" class="ghost" id="f2bCopy">Copy list</button></div>
    <div class="card scroll" id="f2bBannedCard" hidden>
      <table><thead><tr><th>IP address</th><th>Jail</th><th>Network</th><th></th></tr></thead><tbody id="f2bBanned"></tbody></table>
      <p id="f2bBannedEmpty" class="muted pad" hidden>No banned IPs.</p>
      <p id="f2bBannedMore" class="muted pad small" hidden></p>
    </div>
    <div class="bar" id="f2bBanBar" hidden style="margin-top:12px">
      <input id="f2bBanIp" placeholder="IP to ban" spellcheck="false" style="width:180px"><select id="f2bBanJail"></select>
      <button type="button" class="ghost" id="f2bBan">Ban</button><span id="f2bActErr" class="err"></span>
    </div>
    <div class="card form-card" id="f2bSettings" hidden style="margin-top:14px">
      <h2>Fail2ban settings</h2>
      <label class="check"><input type="checkbox" id="f2bManaged"> Let pve-gateway manage fail2ban</label>
      <p class="hint">Writes <code id="f2bFile"></code> (read last, so it overrides jail.local) and its own <code>pvegw-*</code> filters; unticking removes it.</p>
      <div class="grid" id="f2bFields">
        <label>Ban time<input id="f2bBantime" placeholder="1h (10m, 1d, -1 = forever)"></label>
        <label>Count failures within<input id="f2bFindtime" placeholder="10m"></label>
        <label>Failures before a ban<input id="f2bMaxretry" inputmode="numeric"></label>
        <label class="wide">Never ban (IPs / networks)<textarea id="f2bIgnore" rows="2" spellcheck="false" placeholder="203.0.113.7&#10;10.20.0.0/24"></textarea></label>
        <p class="hint wide">Your IP: <b id="f2bMyIp" class="mono"></b> <button type="button" class="link" id="f2bAddMe">+ add it</button> - localhost is always excluded.</p>
        <div class="wide" id="f2bJailToggles"></div>
      </div>
      <p id="f2bErr" class="err"></p>
      <div class="actions"><span id="f2bSaved" class="muted small"></span><button type="button" id="f2bSave">Save &amp; apply</button></div>
    </div>
  </main>
  <main id="view-vpn" hidden>
    <div class="sub-head" style="margin-top:0"><h2>WireGuard VPN</h2><span id="wgState"></span><span class="spacer"></span>
      <button type="button" id="wgInstall" hidden>Install WireGuard</button>
      <button type="button" id="wgNewTunnel" class="ghost" hidden>+ New tunnel</button></div>
    <p id="wgMsg" class="muted small"></p>
    <div id="wgTunnels"></div>
    <p class="muted small">Clients reach the tunnel network and the routes you list (e.g. the guest bridges). With NAT on, guests see
      this host's bridge address, so they need no route back to the VPN. The WireGuard port is opened in pve-gateway's firewall automatically.</p>
  </main>
  <main id="view-network" hidden>
    <div class="sub-head" style="margin-top:0"><h2>Network: DHCP, IPAM &amp; DNS</h2><span id="sdnState"></span><span class="spacer"></span>
      <button type="button" id="sdnInstall" hidden>Install dnsmasq</button>
      <button type="button" id="sdnNewZone" class="ghost" hidden>+ Zone</button></div>
    <p id="sdnMsg" class="muted small"></p>
    <div id="sdnPending" class="card pending-bar" hidden><span>Changes are saved in Proxmox but not active yet.</span>
      <span class="spacer"></span><button type="button" id="sdnApply">Apply SDN changes</button></div>
    <ul id="sdnReq" class="checks card" hidden></ul>
    <div id="sdnZones"></div>
    <div id="sdnIpamBox" hidden>
      <div class="sub-head"><h2>IPAM</h2><span class="muted small">addresses Proxmox has handed out or reserved</span><span class="spacer"></span>
        <button type="button" id="sdnNewIp" class="ghost">+ Reservation</button></div>
      <div class="card scroll"><table>
        <thead><tr><th>IP</th><th>VNet</th><th>MAC</th><th>Guest / name</th><th>Type</th><th></th></tr></thead>
        <tbody id="sdnIpam"></tbody></table></div>
    </div>
    <p class="muted small">Uses Proxmox SDN (Datacenter &gt; SDN), so everything also shows up in the Proxmox UI. A VNet is a bridge:
      set a guest's network device to it (Hardware &gt; Network Device &gt; Bridge). With DHCP on, guests get an address from the subnet's
      range and Proxmox records it in the IPAM. With SNAT on, they reach the internet through this host, and you forward ports to them on the Ports tab.
      DNS names need a DNS plugin (PowerDNS), set up in the Proxmox UI under Datacenter &gt; SDN &gt; Options.</p>
  </main>
  <main id="view-settings" hidden>
    <div class="card form-card">
      <h2>Updates</h2>
      <p id="updStatus" class="muted"></p>
      <div id="updChanges" class="changes"></div>
      <p id="updErr" class="err"></p>
      <label class="check"><input type="checkbox" id="autoUpd"> Install new versions automatically (checked once a day)</label>
      <div class="actions"><a id="updLink" class="muted small" target="_blank" rel="noopener">changes on GitHub</a>
        <span class="spacer"></span><button type="button" class="ghost" id="updCheck">Check now</button>
        <button type="button" id="updRun" hidden>Update</button></div>
    </div>
    <div class="card form-card">
      <h2>Web UI access</h2>
      <p class="muted small">Only these source IPs / networks can open this page (port <span id="uiPort"></span>).
        Leave empty to allow everyone. Connections from this host itself (localhost) always work, so you can't lock yourself out
        of an ssh tunnel - and <code>pve-gateway ui-allow any</code> on the host resets it.</p>
      <label>Allowed source IPs / networks<textarea id="uiAllow" rows="4" spellcheck="false" placeholder="203.0.113.7&#10;10.20.0.0/24"></textarea></label>
      <p class="hint">Your IP: <b id="myIp" class="mono"></b> <button type="button" class="link" id="addMyIp">+ add it</button></p>
      <label id="usersRow">Proxmox users allowed to sign in<textarea id="uiUsers" rows="2" spellcheck="false" placeholder="root@pam&#10;admin@pve"></textarea></label>
      <label>Extra hostnames for this UI<textarea id="uiHosts" rows="2" spellcheck="false" placeholder="pve.example.com"></textarea></label>
      <p class="hint" id="ownHosts"></p>
      <p id="setErr" class="err"></p>
      <div class="actions"><span id="setMsg" class="muted small"></span><button type="button" id="saveSettings">Save</button></div>
    </div>
  </main>
  <main id="view-debug" hidden>
    <div class="bar">
      <button id="dbgRefresh">Refresh</button>
      <button id="dbgCopy" class="ghost">Copy report</button>
      <button id="dbgDownload" class="ghost">Download report</button>
      <label class="check inline"><input type="checkbox" id="dbgVerbose"> Verbose logging (every iptables command + request)</label>
      <span id="dbgMsg" class="muted small"></span>
    </div>
    <div id="mockBar" class="card mockbar" hidden>
      <b>Mock host</b><span class="muted small">Break the simulated host on purpose and see what the checks report:</span>
      <div id="mockBtns" class="mockbtns"></div>
    </div>
    <div class="card"><ul id="checks" class="checks"></ul></div>
    <div id="sections"></div>
    <p class="muted small">CLI on the host: <code>pve-gateway status</code>, <code>pve-gateway test [rule]</code>,
      <code>pve-gateway debug</code>, <code>pve-gateway -v serve</code>, <code>journalctl -u pve-gateway -f</code></p>
  </main>
</div>

<dialog id="domDlg">
  <form id="domForm" class="form">
    <h2 id="domTitle">Add domain</h2>
    <div class="grid">
      <label class="wide">Domain<input name="domain" required placeholder="cloud.example.com" autocapitalize="off" spellcheck="false"></label>
      <label class="wide">Aliases<input name="aliases" placeholder="www.example.com (optional, space separated)" autocapitalize="off" spellcheck="false"></label>
      <label class="check wide"><input type="checkbox" name="alias_redirect"> Aliases redirect (301) to the main domain instead of showing the same site</label>
      <label class="wide">Guest<select name="guest"><option value="">— pick a guest to fill its IP —</option></select></label>
      <label>Upstream IP<input name="ip" required placeholder="10.10.10.10"></label>
      <label>Upstream port<input name="port" required value="80" inputmode="numeric"></label>
      <label class="check wide"><input type="checkbox" name="upstream_https"> Upstream uses HTTPS (self-signed certificates are accepted)</label>
      <label>HTTPS<select name="tls"><option value="letsencrypt">Let's Encrypt (automatic)</option>
        <option value="wildcard">Wildcard certificate (DNS)</option><option value="none">None (HTTP only)</option></select></label>
      <label class="le-only">Let's Encrypt email<input name="acme_email" type="email" placeholder="expiry notices (optional)"></label>
      <p id="wcHint" class="hint wide" hidden></p>
      <label class="check wide tls-on"><input type="checkbox" name="force_https" checked> Redirect HTTP to HTTPS</label>
      <label class="check wide tls-on"><input type="checkbox" name="hsts"> HSTS: browsers insist on HTTPS for this domain for 180 days</label>
      <label class="check wide"><input type="checkbox" name="headers" checked> Security headers (nosniff, same-origin framing, referrer policy)</label>
      <label class="check wide"><input type="checkbox" name="cloudflare"> Behind the Cloudflare proxy (orange cloud): pass the real visitor IP to the guest and to "Allowed sources"</label>
      <label>Max upload size<input name="max_body" value="100m" placeholder="100m, 2g, 0 = unlimited"></label>
      <label>Allowed sources<input name="source" placeholder="anyone (or 203.0.113.0/24 …)"></label>
      <label class="check wide"><input type="checkbox" name="enabled" checked> Enabled</label>
    </div>
    <p id="domErr" class="err"></p>
    <div class="actions"><button type="button" id="domCancel" class="ghost">Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>

<dialog id="wcDlg">
  <form id="wcForm" class="form">
    <h2 id="wcTitle">Add wildcard certificate</h2>
    <div class="grid">
      <label class="wide">Zone<input name="zone" required placeholder="example.com" autocapitalize="off" spellcheck="false"></label>
      <p class="hint wide">Covers <b id="wcCovers">example.com and *.example.com</b>. One level only: a.example.com yes, a.b.example.com no.</p>
      <label class="wide">DNS provider<select name="provider"></select></label>
      <p id="wcHelp" class="hint wide"></p>
      <div id="wcFields" class="grid wide"></div>
      <label>Propagation wait (seconds)<input name="propagation" inputmode="numeric" placeholder="plugin default"></label>
      <label>Let's Encrypt email<input name="acme_email" type="email" placeholder="expiry notices (optional)"></label>
      <label class="check wide"><input type="checkbox" name="enabled" checked> Enabled</label>
    </div>
    <p class="hint">Credentials are stored on this host only (mode 0600) and are never shown again.</p>
    <p id="wcErr" class="err"></p>
    <div class="actions"><button type="button" id="wcCancel" class="ghost">Cancel</button><button type="submit">Save &amp; issue</button></div>
  </form>
</dialog>

<dialog id="monDlg">
  <form id="monForm" class="form">
    <h2 id="monTitle">Add check</h2>
    <div class="grid">
      <label>Name<input name="name" maxlength="40" placeholder="e.g. website"></label>
      <label>Type<select name="type"><option value="http">HTTP(S)</option><option value="tcp">TCP port</option><option value="ping">Ping</option></select></label>
      <label class="wide">Target<input name="target" required autocapitalize="off" spellcheck="false"></label>
      <label>Every (seconds)<input name="interval" inputmode="numeric" value="60"></label>
      <label>Timeout (seconds)<input name="timeout" inputmode="numeric" value="5"></label>
      <label class="http-only">Expected status<input name="expect" value="200-399"></label>
      <label class="check wide http-only"><input type="checkbox" name="verify_tls" checked> Verify the TLS certificate (and warn before it expires)</label>
      <label class="check wide"><input type="checkbox" name="alert" checked> Send alerts for this check</label>
      <label class="check wide"><input type="checkbox" name="enabled" checked> Enabled</label>
    </div>
    <p id="monErr" class="err"></p>
    <div class="actions"><button type="button" id="monCancel" class="ghost">Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>

<dialog id="fwDlg">
  <form id="fwForm" class="form">
    <h2 id="fwTitle">Add rule</h2>
    <div class="grid">
      <label>Action<select name="action"><option value="ACCEPT">ACCEPT - allow</option><option value="DROP">DROP - silently block</option>
        <option value="REJECT">REJECT - block and tell the sender</option></select></label>
      <label>Protocol<select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP (ping)</option><option value="any">any</option></select></label>
      <label class="fw-ports">Ports<input name="ports" placeholder="80,443 or 8000-8100" spellcheck="false"></label>
      <label>Source<input name="source" placeholder="anyone (or 203.0.113.0/24)" spellcheck="false"></label>
      <label class="wide">Comment<input name="comment" maxlength="40"></label>
      <label class="check wide"><input type="checkbox" name="enabled" checked> Enabled</label>
    </div>
    <p id="fwFormErr" class="err"></p>
    <div class="actions"><button type="button" id="fwCancel" class="ghost">Cancel</button><button type="submit">OK</button></div>
  </form>
</dialog>

<dialog id="sdnZDlg">
  <form id="sdnZForm" class="form">
    <h2 id="sdnZTitle">New zone</h2>
    <div class="grid">
      <label>Zone ID<input name="zone" maxlength="8" placeholder="e.g. lab" spellcheck="false"></label>
      <label class="check"><input type="checkbox" name="dhcp" checked> DHCP (dnsmasq)</label>
      <label>DNS plugin<select name="dns"></select></label>
      <label>Reverse DNS plugin<select name="reversedns"></select></label>
      <label class="wide">DNS zone (domain for guest names)<input name="dnszone" placeholder="optional, e.g. lab.example.com" spellcheck="false"></label>
    </div>
    <p class="muted small">New zones are "simple" zones: isolated bridges on this host, with no VLAN setup needed. The Proxmox IPAM keeps track of the addresses.</p>
    <p id="sdnZErr" class="err"></p>
    <div class="actions"><button type="button" class="ghost" data-close>Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>

<dialog id="sdnVDlg">
  <form id="sdnVForm" class="form">
    <h2 id="sdnVTitle">New VNet</h2>
    <div class="grid">
      <label>Name (bridge)<input name="vnet" maxlength="8" placeholder="e.g. labnet" spellcheck="false"></label>
      <label>Zone<select name="zone"></select></label>
      <label class="wide">Description<input name="alias" maxlength="40" placeholder="optional"></label>
    </div>
    <p id="sdnVErr" class="err"></p>
    <div class="actions"><button type="button" class="ghost" data-close>Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>

<dialog id="sdnSDlg">
  <form id="sdnSForm" class="form">
    <h2 id="sdnSTitle">New subnet</h2>
    <div class="grid">
      <label>Subnet<input name="cidr" placeholder="10.20.30.0/24" spellcheck="false"></label>
      <label>Gateway (this host)<input name="gateway" placeholder="first address" spellcheck="false"></label>
      <label class="wide dhcp-only">DHCP ranges (start-end, one per line)<textarea name="dhcp_range" rows="2" spellcheck="false" placeholder="10.20.30.100-10.20.30.200"></textarea></label>
      <label class="dhcp-only">DNS server for DHCP clients<input name="dns_server" placeholder="optional, e.g. 1.1.1.1" spellcheck="false"></label>
      <label class="check"><input type="checkbox" name="snat" checked> SNAT (internet through this host)</label>
    </div>
    <p id="sdnSErr" class="err"></p>
    <div class="actions"><button type="button" class="ghost" data-close>Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>

<dialog id="sdnIDlg">
  <form id="sdnIForm" class="form">
    <h2>New IP reservation</h2>
    <div class="grid">
      <label>VNet<select name="vnet"></select></label>
      <label>Guest network device<select name="nic"></select></label>
      <label>MAC address<input name="mac" placeholder="bc:24:11:12:34:56" spellcheck="false"></label>
      <label>IP address<input name="ip" spellcheck="false"></label>
      <label>VM / CT ID<input name="vmid" inputmode="numeric" placeholder="optional"></label>
    </div>
    <p class="muted small">The guest always gets this address from DHCP. A running guest picks it up when it renews its lease (or after a restart).</p>
    <p id="sdnIErr" class="err"></p>
    <div class="actions"><button type="button" class="ghost" data-close>Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>

<dialog id="wgTDlg">
  <form id="wgTForm" class="form">
    <h2 id="wgTTitle">New tunnel</h2>
    <div class="grid">
      <label>Interface<input name="name" placeholder="wg0" spellcheck="false"></label>
      <label>UDP port<input name="port" inputmode="numeric"></label>
      <label>Tunnel address (this host)<input name="address" placeholder="10.99.0.1/24" spellcheck="false"></label>
      <label>Public endpoint for clients<input name="endpoint" placeholder="this host's public IP or name" spellcheck="false"></label>
      <label class="wide">Networks clients can reach (besides the tunnel)<textarea name="client_routes" rows="2" spellcheck="false" placeholder="10.10.10.0/24"></textarea></label>
      <label>DNS for clients<input name="dns" placeholder="optional, e.g. 10.10.10.1" spellcheck="false"></label>
      <label class="check"><input type="checkbox" name="nat" checked> NAT to guest networks</label>
      <label class="check wide"><input type="checkbox" name="enabled" checked> Enabled (up now and at boot)</label>
    </div>
    <p id="wgTErr" class="err"></p>
    <div class="actions"><button type="button" class="ghost" id="wgTCancel">Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>

<dialog id="wgPDlg">
  <form id="wgPForm" class="form">
    <h2 id="wgPTitle">Add device</h2>
    <div class="grid">
      <label class="wide">Name<input name="name" maxlength="40" placeholder="e.g. laptop"></label>
      <label>Type<select name="kind"><option value="device">Device (phone, laptop) - keys generated here</option>
        <option value="site">Site / router - it has its own key</option></select></label>
      <label>VPN address<input name="address" placeholder="next free" spellcheck="false"></label>
      <label class="wide site-only">Its public key<input name="public_key" placeholder="44 characters, ends with =" spellcheck="false"></label>
      <label class="wide site-only">Networks behind it<input name="allowed_ips" placeholder="e.g. 192.168.77.0/24 (optional)" spellcheck="false"></label>
      <label class="site-only">Its endpoint<input name="endpoint" placeholder="optional: host:port" spellcheck="false"></label>
      <label class="site-only">Keepalive (s)<input name="keepalive" inputmode="numeric" placeholder="0"></label>
      <label class="check"><input type="checkbox" name="psk" checked> Pre-shared key (extra protection)</label>
      <label class="check"><input type="checkbox" name="enabled" checked> Enabled</label>
    </div>
    <p id="wgPErr" class="err"></p>
    <div class="actions"><button type="button" class="ghost" id="wgPCancel">Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>

<dialog id="wgCDlg">
  <h2 id="wgCTitle">Client configuration</h2>
  <p class="muted small">Import this into the WireGuard app on the device. It contains the device's private key - keep it private.</p>
  <textarea id="wgCText" rows="14" readonly style="width:100%"></textarea>
  <div class="actions"><button type="button" class="ghost" id="wgCCopy">Copy</button><button type="button" class="ghost" id="wgCDown">Download</button>
    <button type="button" id="wgCClose">Close</button></div>
</dialog>

<dialog id="testDlg">
  <h2 id="testTitle">Test</h2>
  <ul id="testSteps" class="checks"></ul>
  <p class="muted small">Tests run on the Proxmox host itself. They show whether the host and guest side work,
    not whether your router, ISP or DNS sends outside traffic here. Watch the port hit counters for that.</p>
  <div class="actions"><button type="button" id="testAgain" class="ghost">Run again</button><button type="button" id="testClose">Close</button></div>
</dialog>

<dialog id="dlg">
  <form id="ruleForm" class="form">
    <h2 id="dlgTitle">Add rule</h2>
    <div class="grid">
      <label class="wide">Name<input name="name" maxlength="40" placeholder="e.g. web server"></label>
      <label>Protocol<select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP + UDP</option></select></label>
      <label>Host port<input name="ext_port" required placeholder="8080 or 8000-8010"></label>
      <label class="wide">Guest<select name="guest"><option value="">— pick a guest to fill its IP —</option></select></label>
      <label>Destination IP<input name="ip" required placeholder="10.10.10.10"></label>
      <label>Destination port<input name="int_port" placeholder="same as host port"></label>
      <label>Allowed source<input name="source" placeholder="any (or 203.0.113.0/24)"></label>
      <label>Incoming interface<select name="iface"><option value="">any</option></select></label>
      <label class="check wide"><input type="checkbox" name="masq"> Masquerade (SNAT) &mdash; needed if the guest's gateway is not this host, or to reach it via the public IP from other guests</label>
      <label class="check wide"><input type="checkbox" name="enabled" checked> Enabled</label>
    </div>
    <p id="formErr" class="err"></p>
    <div class="actions"><button type="button" id="cancel" class="ghost">Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>
<script src="/app.js"></script>
</body></html>
"""

APP_CSS = r"""
:root{--bg:#f5f6f8;--card:#fff;--fg:#1d2330;--muted:#6b7280;--line:#e3e6eb;--accent:#e57000;--accent-fg:#fff;
--ok:#15803d;--ok-bg:#dcfce7;--bad:#b91c1c;--bad-bg:#fee2e2;--warn:#a16207;--warn-bg:#fef9c3;--input:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--fg:#e6e8eb;--muted:#9aa3ae;--line:#2d333c;
--accent:#ff8a1f;--accent-fg:#14171c;--ok:#4ade80;--ok-bg:#14301f;--bad:#f87171;--bad-bg:#3a1717;--warn:#facc15;--warn-bg:#3a3010;--input:#14171c}}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
h1{font-size:17px;margin:0}
h1.brand{display:flex;align-items:center;gap:9px}h1.brand img{flex:none;border-radius:6px}h2{font-size:16px;margin:0 0 14px}
code{font-size:12px;background:var(--line);padding:1px 4px;border-radius:4px}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line)}
main{max-width:1200px;margin:0 auto;padding:16px 20px}
.spacer{flex:1}.muted{color:var(--muted)}.small{font-size:12px}.pad{padding:16px;margin:0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px}
.scroll{overflow-x:auto}
.bar{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
button{font:inherit;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);padding:7px 14px;border-radius:7px;cursor:pointer;font-weight:600}
button:disabled{opacity:.5;cursor:default}
button.ghost{background:transparent;color:var(--fg);border-color:var(--line);font-weight:500}
button.ghost:hover{border-color:var(--muted)}
button.link{background:none;border:none;color:var(--muted);padding:4px 6px;font-weight:500}
button.link:hover{color:var(--fg)}button.link.del:hover{color:var(--bad)}
table{width:100%;border-collapse:collapse;white-space:nowrap}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
th{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
tbody tr:last-child td{border-bottom:none}
tr.off td:not(:first-child){opacity:.45}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.arrow{color:var(--muted);padding:0 2px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.tag{display:inline-block;font-size:11px;font-weight:600;padding:1px 7px;border-radius:99px;background:var(--line);text-transform:uppercase}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{font-size:12px;padding:2px 9px;border-radius:99px;font-weight:600}
.chip.ok{background:var(--ok-bg);color:var(--ok)}.chip.bad{background:var(--bad-bg);color:var(--bad)}.chip.warn{background:var(--warn-bg);color:var(--warn)}
.switch{appearance:none;width:32px;height:18px;border-radius:99px;background:var(--line);position:relative;cursor:pointer;margin:0;vertical-align:middle}
.switch:after{content:"";position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:#fff;transition:left .15s}
.switch:checked{background:var(--ok)}.switch:checked:after{left:16px}
.center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.login{width:100%;max-width:340px;padding:24px;display:flex;flex-direction:column;gap:12px}
label{display:flex;flex-direction:column;gap:4px;font-size:12px;font-weight:600;color:var(--muted)}
textarea{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--fg);background:var(--input);border:1px solid var(--line);border-radius:7px;padding:7px 9px;resize:vertical}
textarea:focus{outline:2px solid var(--accent);outline-offset:-1px}
.form-card{padding:18px 20px;max-width:680px;display:flex;flex-direction:column;gap:12px}.form-card h2{margin:0}
.form-card .actions{align-items:center}.form-card + .form-card{margin-top:14px}
.changes:empty{display:none}.changes{border-left:3px solid var(--ok);padding-left:12px}
.changes b{font-size:13px}.changes pre{white-space:pre-wrap;margin:4px 0 10px;font:13px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--muted)}
a.chip{text-decoration:none}
input,select{font:inherit;color:var(--fg);background:var(--input);border:1px solid var(--line);border-radius:7px;padding:7px 9px;font-weight:400}
input:focus,select:focus{outline:2px solid var(--accent);outline-offset:-1px}
label.check{flex-direction:row;align-items:flex-start;gap:8px;font-weight:400;color:var(--fg);font-size:13px}
label.check input{margin-top:3px}
.err{color:var(--bad);margin:0;min-height:1em;font-size:13px}
#msg{font-size:13px;color:var(--muted)}
dialog{border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--fg);padding:22px;width:min(560px,calc(100vw - 32px))}
dialog::backdrop{background:rgba(0,0,0,.45)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.grid .wide{grid-column:1/-1}
.actions{display:flex;justify-content:flex-end;gap:8px;margin-top:8px}
.tabs{display:flex;gap:2px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:2px}
.tabs a{padding:4px 12px;border-radius:6px;color:var(--muted);text-decoration:none;font-weight:600;font-size:13px}
.tabs a.on{background:var(--card);color:var(--fg);box-shadow:0 1px 2px rgba(0,0,0,.12)}
label.check.inline{display:inline-flex;align-items:center;margin-left:4px}label.check.inline input{margin:0}
.checks{list-style:none;margin:0;padding:4px 0}
.checks li{display:flex;gap:10px;align-items:flex-start;padding:8px 14px;border-bottom:1px solid var(--line)}
.checks li:last-child{border-bottom:none}
.checks .d{color:var(--muted);font-size:12px;white-space:pre-wrap;word-break:break-word}
.pill{flex:none;min-width:44px;text-align:center;font-size:11px;font-weight:700;padding:2px 6px;border-radius:5px;text-transform:uppercase;margin-top:1px}
.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.fail{background:var(--bad-bg);color:var(--bad)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.info{background:var(--line);color:var(--muted)}
details.sec{margin-top:10px}
details.sec summary{cursor:pointer;padding:10px 14px;font-weight:600;list-style-position:inside}
details.sec pre{margin:0;padding:12px 14px;border-top:1px solid var(--line);overflow:auto;max-height:480px;
font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre}
#testDlg{width:min(640px,calc(100vw - 32px))}#testDlg .checks{border:1px solid var(--line);border-radius:8px;margin-bottom:10px}
.spin{color:var(--muted);padding:14px}
.banner{padding:10px 14px;margin-bottom:12px;color:var(--bad);border-color:var(--bad);white-space:pre-wrap;font-size:13px}
.netbar{display:flex;flex-wrap:wrap;align-items:center;gap:6px 8px;padding:10px 14px;margin-bottom:12px}
.netbar .hint{flex-basis:100%;margin:2px 0 0}
button.net{display:inline-flex;gap:6px;align-items:center;background:var(--bg);color:var(--fg);border:1px solid var(--line);
padding:3px 10px;font-weight:400;font-size:12px;border-radius:99px}
button.net:hover{border-color:var(--muted)}button.net.wan{border-color:var(--accent)}
.net .nif{font-weight:600}.ntag{font-size:10px;font-weight:700;text-transform:uppercase;color:var(--accent)}.ntag.pub{color:var(--ok)}
.bars{display:flex;gap:1px;align-items:flex-end;height:18px}.bars i{width:3px;height:100%;border-radius:1px;background:var(--ok);opacity:.85}
.bars i.no{background:var(--bad)}.pill.up{background:var(--ok-bg);color:var(--ok)}.pill.down{background:var(--bad-bg);color:var(--bad)}
.pill.unknown{background:var(--line);color:var(--muted)}.pill.failing{background:var(--warn-bg);color:var(--warn)}.pill.high{background:var(--bad-bg);color:var(--bad)}
.pill.admin{background:var(--warn-bg);color:var(--warn)}.pill.low{background:var(--line);color:var(--muted)}
.warn-banner{color:var(--fg);border-color:var(--warn);background:var(--warn-bg);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.sub-head{display:flex;align-items:center;gap:10px;margin:22px 0 10px}.sub-head h2{margin:0;font-size:15px}
.sub-head button{padding:4px 12px;font-size:13px}
.hint{margin:-4px 0 0;font-size:12px;color:var(--muted)}.hint.bad{color:var(--bad)}
form > .hint{margin:12px 0 0}
#wcFields:empty{display:none}
.names a{color:var(--fg);text-decoration:none;font-weight:500}.names a:hover{text-decoration:underline}
.names .alias{display:block;color:var(--muted);font-size:12px}
.pending-bar{display:flex;align-items:center;gap:10px;padding:10px 14px;margin-bottom:12px;border-color:var(--warn);background:var(--warn-bg);color:var(--warn)}
#view-network .sub-head{flex-wrap:wrap}#view-network .sub-head button{white-space:nowrap}
tr.sub td:first-child{padding-left:22px}#sdnZones td .chip{margin-left:6px;font-family:inherit}
.mockbar{padding:12px 14px;margin-bottom:12px;display:flex;flex-direction:column;gap:6px;border-style:dashed;border-color:var(--warn)}
.mockbtns{display:flex;flex-wrap:wrap;gap:6px}.mockbtns button{padding:4px 10px;font-size:12px}
@media (max-width:560px){.grid{grid-template-columns:1fr}header,main{padding-left:16px;padding-right:16px}}
"""

APP_JS = r"""
'use strict';
const $ = s => document.querySelector(s);
load.n = 0;
let S = {rules: [], counters: {}, ifaces: []}, guests = null, editing = null, timer = null, view = 'rules', testing = null;

async function api(method, path, body) {
  const r = await fetch(path, {method, credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-PVEGW': '1'},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== '/api/login') { showLogin(); throw new Error('Login required'); }
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e[k] = v;
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}

function flash(t, isErr) {
  const m = $('#msg'); m.textContent = t; m.style.color = isErr ? 'var(--bad)' : '';
  clearTimeout(flash.t); flash.t = setTimeout(() => m.textContent = '', isErr ? 8000 : 3000);
}

function showLogin() {
  clearInterval(timer); timer = null;
  $('#app').hidden = true; $('#login').hidden = false;
  $('#loginForm').password.focus();
  fetch('/api/authinfo').then(r => r.json()).then(a => {
    $('#loginForm').username.value = a.user;
    $('#loginHint').textContent = a.mock ? 'Mock mode (simulated host): admin / admin'
      : a.mode === 'local' ? 'Sign in with the local pve-gateway account' : 'Sign in with your Proxmox account';
  }).catch(() => {});
}

async function load() {
  const prev = S.web_ports;
  S = await api('GET', '/api/state' + (view === 'domains' && !(load.n++ % 6) ? '?ports=1' : ''));  // ports check every ~30s
  if (S.web_ports === null && prev) S.web_ports = prev;
  $('#login').hidden = true; $('#app').hidden = false;
  render();
  if (!load.started) { load.started = true; setView(); }
  if (!timer) timer = setInterval(() => {
    if (!document.hidden && view !== 'debug' && view !== 'settings' && ![...document.querySelectorAll('dialog')].some(x => x.open)) load().catch(() => {});
    if (!document.hidden && view === 'monitor' && !$('#monDlg').open) loadMonitor();
    if (!document.hidden && view === 'security') { loadSecurity(); if (!$('#fwDlg').open) loadFirewall(); }
    if (!document.hidden && view === 'vpn' && ![...document.querySelectorAll('dialog')].some(x => x.open)) loadVpn();
    if (!document.hidden && view === 'network' && ![...document.querySelectorAll('dialog')].some(x => x.open)) loadNetwork();
  }, 5000);
}

function netLabel(iface) {
  const ips = (S.networks || []).filter(n => n.iface === iface);
  return ips.length ? iface + ' — ' + ips.map(n => n.cidr + (n.public ? ' public' : '') + (n.wan ? ' · WAN' : '')).join(', ') : iface;
}

function renderNet() {
  const nets = S.networks || [], pub = nets.filter(n => n.public), wan = nets.find(n => n.wan);
  const lan = nets.filter(n => !n.wan && !n.public);
  for (const [id, mode] of [['#netRules', 'ports'], ['#netDomains', 'domains']]) {
    const box = $(id); box.hidden = !nets.length;
    if (!nets.length) continue;
    let tip = '';
    if (pub.length) tip = (mode === 'domains' ? 'Point DNS A records at ' : 'Forwarded ports are reachable at ') + pub.map(n => n.ip).join(', ') + '.';
    else if (wan) tip = 'This host is behind NAT (' + wan.ip + ' is private): forward the ports on your router to ' + wan.ip +
      (mode === 'domains' ? ' and point DNS at the router\'s public IP.' : '.');
    if (mode === 'ports' && lan.length) tip += ' Guests on ' + lan.map(n => n.iface).join(', ') +
      ' answer forwarded traffic directly only if their gateway is this host (' + lan.map(n => n.ip).join(', ') +
      '); behind another router (e.g. a firewall VM), enable Masquerade on the rule.';
    box.replaceChildren(el('span', {class: 'muted small', textContent: 'Host network'}),
      ...nets.map(n => el('button', {type: 'button', class: 'net' + (n.wan ? ' wan' : ''), title: 'Copy ' + n.ip,
        onclick: () => navigator.clipboard.writeText(n.ip).then(() => (mode === 'domains' ? domFlash : flash)('Copied ' + n.ip), () => {})},
        el('span', {class: 'nif', textContent: n.iface}), el('span', {class: 'mono', textContent: n.cidr}),
        n.public ? el('span', {class: 'ntag pub', textContent: 'public'}) : null,
        n.wan ? el('span', {class: 'ntag', textContent: 'wan'}) : null)),
      tip ? el('p', {class: 'hint', textContent: tip}) : null);
  }
}

function render() {
  renderDomains();
  renderNet();
  $('#who').textContent = S.user + ' · v' + S.version;
  const st = $('#status'); st.replaceChildren();
  const chip = (cls, t, title) => st.append(el('span', {class: 'chip ' + cls, textContent: t, title: title || ''}));
  if (S.dry_run) chip('warn', 'DRY RUN', 'iptables commands are only printed');
  if (S.mock) chip('warn', 'MOCK', 'simulated Proxmox host - nothing real is touched');
  if (S.update && S.update.available) st.append(el('a', {class: 'chip ok', href: '#settings', textContent: 'v' + S.update.latest + ' available',
    title: 'a new pve-gateway version is available - update in Settings'}));
  if (S.ui_open) st.append(el('a', {class: 'chip warn', href: '#settings', textContent: 'UI open to all IPs',
    title: 'anyone can reach this login page - restrict it in Settings'}));
  chip(S.status.active ? 'ok' : 'bad', S.status.active ? 'rules active' : 'rules not loaded');
  chip(S.status.ip_forward ? 'ok' : 'bad', S.status.ip_forward ? 'ip_forward on' : 'ip_forward off');
  if (S.status.last_error) chip('bad', 'error', S.status.last_error);

  const tb = $('#rules'); tb.replaceChildren();
  $('#empty').hidden = S.rules.length > 0;
  for (const r of S.rules) {
    const c = S.counters[r.id];
    tb.append(el('tr', {class: r.enabled ? '' : 'off'},
      el('td', {}, el('input', {type: 'checkbox', class: 'switch', checked: r.enabled, title: r.enabled ? 'Disable' : 'Enable',
        onchange: e => save(r.id, Object.assign({}, r, {enabled: e.target.checked}))})),
      el('td', {textContent: r.name || '—'}),
      el('td', {}, el('span', {class: 'tag', textContent: r.proto === 'both' ? 'tcp+udp' : r.proto})),
      el('td', {class: 'mono', textContent: r.ext_port}),
      el('td', {class: 'arrow', textContent: '→'}),
      el('td', {class: 'mono', textContent: r.ip + ':' + (r.int_port || r.ext_port) + (r.masq ? ' ⇄' : ''), title: r.masq ? 'masquerade on' : ''}),
      el('td', {class: 'mono', textContent: r.source || 'any'}),
      el('td', {class: 'mono', textContent: r.iface || 'any'}),
      el('td', {class: 'num', textContent: c ? c[0] + ' · ' + fmtBytes(c[1]) : '—', title: 'new connections · bytes'}),
      el('td', {class: 'num'},
        el('button', {class: 'link', textContent: 'Test', onclick: () => runTest(r)}),
        el('button', {class: 'link', textContent: 'Edit', onclick: () => openDlg(r)}),
        el('button', {class: 'link del', textContent: 'Delete', onclick: () => del(r)}))));
  }
}

async function save(id, data) {
  try {
    await api(id ? 'PUT' : 'POST', id ? '/api/rules/' + id : '/api/rules', data);
    flash('Saved and applied'); await load(); return true;
  } catch (e) { flash(e.message, true); await load().catch(() => {}); throw e; }
}

async function del(r) {
  if (!confirm('Delete rule "' + (r.name || r.ext_port) + '"?')) return;
  try { await api('DELETE', '/api/rules/' + r.id); flash('Deleted'); await load(); } catch (e) { flash(e.message, true); }
}

async function fillGuests(sel = $('#ruleForm').guest) {
  if (!guests) {
    try { guests = (await api('GET', '/api/guests')).guests; } catch (e) { guests = []; }
    setTimeout(() => guests = null, 30000);
  }
  sel.replaceChildren(el('option', {value: '', textContent: guests.length ? '— pick a guest to fill its IP —' : '— no guests found —'}));
  for (const g of guests) {
    const label = g.vmid + ' ' + (g.name || '') + ' (' + (g.type === 'lxc' ? 'CT' : 'VM') + (g.status !== 'running' ? ', ' + g.status : '') + ')';
    const src = {agent: '', lxc: '', arp: ' · from ARP', ipam: ' · SDN IPAM', 'cloud-init': ' · cloud-init', config: ' · config'}[g.source] || '';
    if (!g.ips.length) sel.append(el('option', {value: '', disabled: true, title: g.hint || '',
      textContent: label + ' — IP unknown' + (g.hint && g.status === 'running' ? ' (' + (/agent/.test(g.hint) ? 'no guest agent' : g.hint) + ')' : '')}));
    for (const ip of g.ips) sel.append(el('option', {value: ip, textContent: label + ' — ' + ip + src}));
  }
}

function openDlg(r) {
  editing = r ? r.id : null;
  const f = $('#ruleForm');
  $('#dlgTitle').textContent = r ? 'Edit rule' : 'Add rule';
  $('#formErr').textContent = '';
  const iface = f.iface; iface.replaceChildren(el('option', {value: '', textContent: 'any'}));
  for (const i of S.ifaces) iface.append(el('option', {value: i, textContent: netLabel(i)}));
  r = r || {proto: 'tcp', enabled: true};
  for (const k of ['name', 'proto', 'ext_port', 'ip', 'int_port', 'source', 'iface']) f[k].value = r[k] || '';
  if (r.iface && !S.ifaces.includes(r.iface)) iface.append(el('option', {value: r.iface, textContent: r.iface, selected: true}));
  f.masq.checked = !!r.masq; f.enabled.checked = r.enabled !== false;
  $('#dlg').showModal();
  (r.id ? f.name : f.ext_port).focus();
  fillGuests();
}

$('#ruleForm').guest.addEventListener('change', e => {
  const f = $('#ruleForm');
  if (e.target.value) {
    f.ip.value = e.target.value;
    if (!f.name.value) f.name.value = e.target.selectedOptions[0].textContent.split(' (')[0].replace(/^\d+ /, '').slice(0, 40);
  }
});

$('#ruleForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target, d = {};
  for (const k of ['name', 'proto', 'ext_port', 'ip', 'int_port', 'source', 'iface']) d[k] = f[k].value.trim();
  d.masq = f.masq.checked; d.enabled = f.enabled.checked;
  try {
    await api(editing ? 'PUT' : 'POST', editing ? '/api/rules/' + editing : '/api/rules', d);
    $('#dlg').close(); flash('Saved and applied'); load();
  } catch (err) { $('#formErr').textContent = err.message; }
});

$('#cancel').onclick = () => $('#dlg').close();
$('#addBtn').onclick = () => openDlg(null);
$('#reapply').onclick = async () => {
  try { await api('POST', '/api/apply'); flash('Rules re-applied'); load(); } catch (e) { flash(e.message, true); }
};
$('#logout').onclick = async () => { await api('POST', '/api/logout').catch(() => {}); showLogin(); };

let tfaId = null;
function resetTfa() { tfaId = null; $('#tfaRow').hidden = true; $('#loginForm').code.required = false; $('#loginForm').code.value = ''; }
$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target, btn = f.querySelector('button');
  $('#loginErr').textContent = ''; btn.disabled = true;
  try {
    const r = await api('POST', '/api/login', tfaId ? {tfa_id: tfaId, code: f.code.value.trim()}
      : {username: f.username.value.trim(), password: f.password.value});
    if (r.tfa) {  // Proxmox account with two-factor: ask for the code
      tfaId = r.tfa; $('#tfaRow').hidden = false; f.code.required = true; f.code.focus();
    } else { resetTfa(); f.password.value = ''; await load(); }
  } catch (err) {
    $('#loginErr').textContent = err.message + (tfaId ? ' - enter your password again' : '');
    if (tfaId) resetTfa();
  }
  btn.disabled = false;
});

// ---- domains
function certChip(cert, job, label) {
  if (job && job.state === 'pending') return el('span', {class: 'chip warn', textContent: 'issuing…', title: job.msg});
  if (cert && cert.exists) return el('span', {class: 'chip ' + (cert.days < 14 ? 'warn' : 'ok'),
    textContent: label + ' · ' + cert.days + 'd', title: 'certificate expires in ' + cert.days + ' days (auto-renewed)'});
  if (job && job.state === 'error') return el('span', {class: 'chip bad', textContent: 'cert error', title: job.msg});
  return el('span', {class: 'chip bad', textContent: 'no certificate'});
}

function clickable(chip, d) {
  if (!/bad/.test(chip.className)) return chip;
  chip.style.cursor = 'pointer'; chip.title = (chip.title ? chip.title + '\n\n' : '') + 'Click to run the test and see why';
  chip.onclick = () => runTestUrl('Test: ' + d.domain + ' → ' + d.ip + ':' + d.port, '/api/domains/' + d.id + '/test');
  return chip;
}

function tlsCell(d) { return clickable(tlsCell0(d), d); }
function tlsCell0(d) {
  const st = (S.domain_status || {})[d.id] || {}, job = st.job, cert = st.cert;
  if (d.tls === 'none') return el('span', {class: 'tag', textContent: 'http only'});
  if (d.tls === 'wildcard') {
    if (!st.wildcard) return el('span', {class: 'chip bad', textContent: 'no wildcard', title: 'no enabled wildcard certificate covers this domain'});
    const c = certChip(cert, job, st.wildcard); return c;
  }
  if (job && job.state === 'pending') return el('span', {class: 'chip warn', textContent: 'issuing…'});
  if (cert && cert.exists) return el('span', {class: 'chip ' + (cert.days < 14 ? 'warn' : 'ok'),
    textContent: 'https · ' + cert.days + 'd', title: 'certificate expires in ' + cert.days + ' days (auto-renewed)'});
  if (job && job.state === 'error') return el('span', {class: 'chip bad', textContent: 'cert error', title: job.msg});
  return el('span', {class: 'chip bad', textContent: 'no certificate'});
}

function renderWildcards() {
  const tb = $('#wildcards'), ws = S.wildcards || [], prov = S.dns_providers || {};
  tb.replaceChildren();
  $('#wcEmpty').hidden = ws.length > 0;
  for (const w of ws) {
    const st = (S.wildcard_status || {})[w.id] || {};
    tb.append(el('tr', {class: w.enabled ? '' : 'off'},
      el('td', {}, el('input', {type: 'checkbox', class: 'switch', checked: w.enabled, title: w.enabled ? 'Disable' : 'Enable',
        onchange: e => saveWildcard(w.id, Object.assign({}, w, {enabled: e.target.checked}))})),
      el('td', {class: 'names'}, el('span', {class: 'mono', textContent: '*.' + w.zone}), el('span', {class: 'alias', textContent: '+ ' + w.zone})),
      el('td', {textContent: (prov[w.provider] || {}).label || w.provider}),
      el('td', {}, certChip(st.cert, st.job, 'valid')),
      el('td', {class: 'muted small', textContent: (st.used_by || []).join(', ') || '—'}),
      el('td', {class: 'num'},
        el('button', {class: 'link', textContent: 'Issue', title: 'Request / renew now', onclick: () => wcCert(w)}),
        el('button', {class: 'link', textContent: 'Edit', onclick: () => openWcDlg(w)}),
        el('button', {class: 'link del', textContent: 'Delete', onclick: () => delWildcard(w)}))));
  }
}

function renderWebPorts() {
  const box = $('#webPorts'), ps = S.web_ports;
  if (!ps) { if (!(S.domains || []).length) box.hidden = true; return; }
  const bad = ps.filter(p => p.status === 'fail' || p.status === 'warn');
  box.hidden = false;
  box.replaceChildren(el('span', {class: 'muted small', textContent: 'Ports 80/443'}),
    el('span', {class: 'chip ' + (bad.length ? 'bad' : 'ok'), textContent: bad.length ? bad.length + ' problem' + (bad.length > 1 ? 's' : '')
      : 'handled by nginx on this host → proxied to guests'}),
    ...bad.map(p => el('p', {class: 'hint bad', textContent: p.name + ': ' + p.detail})));
}

function renderDomains() {
  renderWildcards();
  renderWebPorts();
  const tb = $('#domains'), ds = S.domains || [];
  tb.replaceChildren();
  $('#domEmpty').hidden = ds.length > 0;
  const ne = $('#nginxErr'); ne.hidden = !(S.nginx && S.nginx.last_error); ne.textContent = ne.hidden ? '' : S.nginx.last_error;
  for (const d of ds) {
    tb.append(el('tr', {class: d.enabled ? '' : 'off'},
      el('td', {}, el('input', {type: 'checkbox', class: 'switch', checked: d.enabled, title: d.enabled ? 'Disable' : 'Enable',
        onchange: e => saveDomain(d.id, Object.assign({}, d, {enabled: e.target.checked}))})),
      el('td', {class: 'names'}, el('a', {href: (d.tls !== 'none' ? 'https://' : 'http://') + d.domain, target: '_blank', rel: 'noopener', textContent: d.domain}),
        ...d.aliases.map(a => el('span', {class: 'alias', textContent: d.alias_redirect ? '↳ ' + a + ' → 301' : a})),
        (d.cloudflare || d.hsts) ? el('span', {class: 'alias'},
          d.cloudflare ? el('span', {class: 'tag', textContent: 'cloudflare'}) : null, ' ',
          d.hsts ? el('span', {class: 'tag', textContent: 'hsts'}) : null) : null),
      el('td', {class: 'arrow', textContent: '→'}),
      el('td', {class: 'mono', textContent: (d.upstream_https ? 'https://' : 'http://') + d.ip + ':' + d.port}),
      el('td', {}, tlsCell(d)),
      el('td', {class: 'mono', textContent: d.source.length ? d.source.join(', ') : 'anyone'}),
      el('td', {class: 'num'},
        el('button', {class: 'link', textContent: 'Test', onclick: () => runTestUrl('Test: ' + d.domain + ' → ' + d.ip + ':' + d.port, '/api/domains/' + d.id + '/test')}),
        d.tls !== 'none' ? el('button', {class: 'link', textContent: 'Cert', title: 'Request / renew certificate now', onclick: () => cert(d)}) : null,
        el('button', {class: 'link', textContent: 'Edit', onclick: () => openDomDlg(d)}),
        el('button', {class: 'link del', textContent: 'Delete', onclick: () => delDomain(d)}))));
  }
}

function domFlash(t, isErr) {
  const m = $('#domMsg'); m.textContent = t; m.style.color = isErr ? 'var(--bad)' : 'var(--muted)';
  clearTimeout(domFlash.t); domFlash.t = setTimeout(() => m.textContent = '', isErr ? 10000 : 4000);
}

async function saveDomain(id, data) {
  try { await api(id ? 'PUT' : 'POST', id ? '/api/domains/' + id : '/api/domains', data); domFlash('Saved, nginx reloaded'); }
  catch (e) { domFlash(e.message, true); }
  load().catch(() => {});
}

async function delDomain(d) {
  if (!confirm('Delete domain "' + d.domain + '"? (its certificate is kept)')) return;
  try { await api('DELETE', '/api/domains/' + d.id); domFlash('Deleted'); } catch (e) { domFlash(e.message, true); }
  load().catch(() => {});
}

async function cert(d) {
  try { await api('POST', '/api/domains/' + d.id + '/cert', {}); domFlash('Requesting certificate for ' + d.domain + '…'); }
  catch (e) { domFlash(e.message, true); }
  load().catch(() => {});
}

let editingDom = null;
function openDomDlg(d) {
  editingDom = d ? d.id : null;
  const f = $('#domForm');
  $('#domTitle').textContent = d ? 'Edit domain' : 'Add domain';
  $('#domErr').textContent = '';
  d = d || {tls: 'letsencrypt', force_https: true, headers: true, enabled: true, port: 80, max_body: '100m', aliases: [], source: []};
  for (const k of ['alias_redirect', 'hsts', 'headers', 'cloudflare']) f[k].checked = !!d[k];
  f.domain.value = d.domain || ''; f.aliases.value = (d.aliases || []).join(' ');
  f.ip.value = d.ip || ''; f.port.value = d.port || 80; f.upstream_https.checked = !!d.upstream_https;
  f.tls.value = d.tls; f.force_https.checked = d.force_https !== false; f.max_body.value = d.max_body || '100m';
  f.source.value = (d.source || []).join(' '); f.enabled.checked = d.enabled !== false;
  f.acme_email.value = S.acme_email || '';
  toggleLe();
  $('#domDlg').showModal();
  f.domain.focus();
  fillGuests(f.guest);
}
const coversName = (zone, n) => n === zone || (n.endsWith('.' + zone) && !n.slice(0, -zone.length - 1).includes('.'));
function toggleLe() {
  const f = $('#domForm'), tls = f.tls.value, hint = $('#wcHint');
  for (const x of document.querySelectorAll('#domForm .le-only')) x.hidden = tls !== 'letsencrypt';
  for (const x of document.querySelectorAll('#domForm .tls-on')) x.hidden = tls === 'none';
  hint.hidden = tls !== 'wildcard';
  if (tls !== 'wildcard') return;
  const names = [f.domain.value, ...f.aliases.value.split(/[\s,]+/)].map(x => x.trim().toLowerCase()).filter(Boolean);
  const w = (S.wildcards || []).find(w => w.enabled && names.length && names.every(n => coversName(w.zone, n)));
  hint.classList.toggle('bad', !w);
  hint.textContent = !names.length ? 'Enter the domain to find its wildcard certificate.'
    : w ? 'Uses the wildcard certificate *.' + w.zone + '.'
    : 'No wildcard certificate covers ' + names.join(', ') + ' - add one below the domains table first.';
}
$('#domForm').tls.addEventListener('change', toggleLe);
$('#domForm').domain.addEventListener('input', toggleLe);
$('#domForm').aliases.addEventListener('input', toggleLe);
$('#domForm').upstream_https.addEventListener('change', e => {
  const p = $('#domForm').port; if (e.target.checked && p.value === '80') p.value = '443'; else if (!e.target.checked && p.value === '443') p.value = '80';
});
$('#domForm').guest.addEventListener('change', e => { if (e.target.value) $('#domForm').ip.value = e.target.value; });
$('#domForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target, d = {};
  for (const k of ['domain', 'aliases', 'ip', 'port', 'tls', 'max_body', 'source', 'acme_email']) d[k] = f[k].value.trim();
  d.upstream_https = f.upstream_https.checked; d.force_https = f.force_https.checked; d.enabled = f.enabled.checked;
  for (const k of ['alias_redirect', 'hsts', 'headers', 'cloudflare']) d[k] = f[k].checked;
  const btn = f.querySelector('button[type=submit]'); btn.disabled = true;
  try {
    await api(editingDom ? 'PUT' : 'POST', editingDom ? '/api/domains/' + editingDom : '/api/domains', d);
    $('#domDlg').close();
    domFlash(d.tls === 'letsencrypt' && d.enabled ? 'Saved - requesting certificate in the background…' : 'Saved, nginx reloaded');
    load().catch(() => {});
  } catch (err) { $('#domErr').textContent = err.message; }
  btn.disabled = false;
});
$('#domCancel').onclick = () => $('#domDlg').close();

let editingWc = null;
function wcFields() {
  const f = $('#wcForm'), p = (S.dns_providers || {})[f.provider.value] || {fields: []}, box = $('#wcFields');
  $('#wcHelp').textContent = (p.help ? p.help + '. ' : '') + 'Needs: apt install ' + p.package;
  box.replaceChildren(...p.fields.map(fd => el('label', {}, fd.label,
    el('input', {name: 'cred_' + fd.key, type: fd.secret ? 'password' : 'text', autocomplete: 'off', spellcheck: false,
      value: editingWc && editingWc.provider === f.provider.value && !fd.secret ? '' : (fd.default || ''),
      placeholder: editingWc && editingWc.provider === f.provider.value ? 'saved - leave empty to keep' : (fd.default || '')}))));
}
function openWcDlg(w) {
  editingWc = w || null;
  const f = $('#wcForm');
  $('#wcTitle').textContent = w ? 'Edit wildcard *.' + w.zone : 'Add wildcard certificate';
  $('#wcErr').textContent = '';
  f.provider.replaceChildren(...Object.entries(S.dns_providers || {}).map(([k, p]) => el('option', {value: k, textContent: p.label})));
  f.zone.value = w ? w.zone : ''; f.zone.disabled = !!w;
  f.provider.value = w ? w.provider : 'cloudflare';
  f.propagation.value = w && w.propagation ? w.propagation : '';
  f.acme_email.value = S.acme_email || ''; f.enabled.checked = w ? w.enabled : true;
  wcCovers(); wcFields();
  $('#wcDlg').showModal();
  (w ? f.provider : f.zone).focus();
}
function wcCovers() {
  const z = $('#wcForm').zone.value.trim().toLowerCase().replace(/^\*\./, '') || 'example.com';
  $('#wcCovers').textContent = z + ' and *.' + z;
}
$('#wcForm').zone.addEventListener('input', wcCovers);
$('#wcForm').provider.addEventListener('change', wcFields);
$('#wcForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target, creds = {};
  for (const i of $('#wcFields').querySelectorAll('input')) if (i.value.trim()) creds[i.name.slice(5)] = i.value.trim();
  const d = {zone: f.zone.value.trim(), provider: f.provider.value, propagation: f.propagation.value.trim() || 0,
    acme_email: f.acme_email.value.trim(), enabled: f.enabled.checked, credentials: creds};
  const btn = f.querySelector('button[type=submit]'); btn.disabled = true;
  try {
    await api(editingWc ? 'PUT' : 'POST', editingWc ? '/api/wildcards/' + editingWc.id : '/api/wildcards', d);
    $('#wcDlg').close(); domFlash(d.enabled ? 'Saved - requesting wildcard certificate (DNS check takes ~30s)…' : 'Saved');
    load().catch(() => {});
  } catch (err) { $('#wcErr').textContent = err.message; }
  btn.disabled = false;
});
$('#wcCancel').onclick = () => $('#wcDlg').close();
$('#addWcBtn').onclick = () => openWcDlg(null);
async function saveWildcard(id, w) {
  try { await api('PUT', '/api/wildcards/' + id, w); domFlash('Saved'); } catch (e) { domFlash(e.message, true); }
  load().catch(() => {});
}
async function delWildcard(w) {
  if (!confirm('Delete wildcard *.' + w.zone + '? Its stored DNS credentials are removed (the certificate files are kept).')) return;
  try { await api('DELETE', '/api/wildcards/' + w.id); domFlash('Deleted'); } catch (e) { domFlash(e.message, true); }
  load().catch(() => {});
}
async function wcCert(w) {
  try { await api('POST', '/api/wildcards/' + w.id + '/cert', {}); domFlash('Requesting *.' + w.zone + ' (DNS check takes ~30s)…'); }
  catch (e) { domFlash(e.message, true); }
  load().catch(() => {});
}
$('#addDomBtn').onclick = () => openDomDlg(null);

// ---- checks list (debug tab + rule test)
function renderChecks(ul, items) {
  ul.replaceChildren(...items.map(c => el('li', {},
    el('span', {class: 'pill ' + c.status, textContent: c.status}),
    el('div', {}, el('div', {textContent: c.name}), c.detail ? el('div', {class: 'd', textContent: c.detail}) : null))));
}

async function runTestUrl(title, url) {
  testing = [title, url];
  $('#testTitle').textContent = title;
  $('#testSteps').replaceChildren(el('li', {class: 'spin', textContent: 'Running checks…'}));
  if (!$('#testDlg').open) $('#testDlg').showModal();
  try { renderChecks($('#testSteps'), (await api('POST', url, {})).steps); }
  catch (e) { renderChecks($('#testSteps'), [{status: 'fail', name: 'test failed', detail: e.message}]); }
}
const runTest = r => runTestUrl('Test: ' + (r.name || r.id) + '  (' + r.proto + '/' + r.ext_port + ' → ' + r.ip + ':' + (r.int_port || r.ext_port) + ')',
  '/api/rules/' + r.id + '/test');
$('#testAgain').onclick = () => testing && runTestUrl(...testing);
$('#testClose').onclick = () => $('#testDlg').close();

// ---- debug view
async function loadDebug() {
  const b = $('#dbgRefresh'); b.disabled = true; $('#dbgMsg').textContent = 'collecting…';
  load().catch(() => {});  // keep header badges current
  try {
    const d = await api('GET', '/api/debug');
    $('#dbgVerbose').checked = d.verbose;
    $('#mockBar').hidden = !d.mock;
    if (d.mock) $('#mockBtns').replaceChildren(...Object.entries(d.mock).map(([k, desc]) =>
      el('button', {class: 'ghost', textContent: k, title: desc, onclick: async () => {
        try { const r = await api('POST', '/api/mock', {scenario: k}); $('#dbgMsg').textContent = k + ': ' + r.message; }
        catch (e) { $('#dbgMsg').textContent = e.message; }
        setTimeout(loadDebug, 300);
      }})));
    renderChecks($('#checks'), d.checks);
    const open = new Set([...document.querySelectorAll('details.sec[open]')].map(x => x.dataset.t));
    $('#sections').replaceChildren(...d.sections.map(sec => {
      const det = el('details', {class: 'sec card', open: open.size ? open.has(sec.title) : !!sec.open},
        el('summary', {textContent: sec.title}), el('pre', {textContent: sec.text}));
      det.dataset.t = sec.title;
      return det;
    }));
    const log = document.querySelector('details.sec pre'); if (log) log.scrollTop = log.scrollHeight;
    const n = k => d.checks.filter(c => c.status === k).length;
    $('#dbgMsg').textContent = d.generated + ' · ' + n('fail') + ' failed, ' + n('warn') + ' warnings';
  } catch (e) { $('#dbgMsg').textContent = e.message; }
  b.disabled = false;
}

async function reportText() {
  const r = await fetch('/api/debug/report', {credentials: 'same-origin'});
  if (!r.ok) throw new Error('report failed: ' + r.status);
  return r.text();
}
$('#dbgRefresh').onclick = loadDebug;
$('#dbgCopy').onclick = async () => {
  try { await navigator.clipboard.writeText(await reportText()); $('#dbgMsg').textContent = 'Report copied to clipboard'; }
  catch (e) { $('#dbgMsg').textContent = 'Copy failed (' + e.message + '), use Download'; }
};
$('#dbgDownload').onclick = async () => {
  try {
    const url = URL.createObjectURL(new Blob([await reportText()], {type: 'text/plain'}));
    const a = el('a', {href: url, download: 'pve-gateway-debug-' + new Date().toISOString().slice(0, 19).replace(/:/g, '') + '.txt'});
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) { $('#dbgMsg').textContent = e.message; }
};
$('#dbgVerbose').onchange = async e => {
  try { await api('POST', '/api/debug', {verbose: e.target.checked}); loadDebug(); }
  catch (err) { e.target.checked = !e.target.checked; $('#dbgMsg').textContent = err.message; }
};

// ---- monitoring
let MONS = {monitors: [], status: {}, alerts: {}}, editingMon = null;
const since = t => { if (!t) return '—'; const m = Math.round((Date.now() / 1000 - t) / 60);
  return m < 1 ? 'just now' : m < 60 ? m + ' min' : m < 1440 ? Math.round(m / 60) + ' h' : Math.round(m / 1440) + ' d'; };
async function loadMonitor() {
  try { MONS = await api('GET', '/api/monitors'); renderMonitor(); } catch (e) { $('#monMsg').textContent = e.message; }
}
function renderMonitor() {
  const tb = $('#monitors'); tb.replaceChildren();
  $('#monEmpty').hidden = MONS.monitors.length > 0;
  for (const m of MONS.monitors) {
    const st = MONS.status[m.id] || {status: 'unknown'};
    const s = !m.enabled ? 'unknown' : st.status !== 'down' && st.fails > 0 ? 'failing' : st.status;
    tb.append(el('tr', {class: m.enabled ? '' : 'off'},
      el('td', {}, el('span', {class: 'pill ' + s, textContent: m.enabled ? (st.running ? '…' : s) : 'off', title: st.detail || ''})),
      el('td', {class: 'names'}, m.name || '—', el('span', {class: 'alias', textContent: m.type.toUpperCase() + ' · every ' + m.interval + 's'})),
      el('td', {class: 'mono', textContent: m.target, title: st.detail || ''}),
      el('td', {}, el('div', {class: 'bars', title: 'last checks, oldest left'}, ...(st.history || []).map(h =>
        el('i', {class: h[1] ? '' : 'no', title: new Date(h[0] * 1000).toLocaleTimeString() + ' · ' + (h[1] ? h[2] + ' ms' : 'failed')})))),
      el('td', {class: 'num', textContent: st.ms != null ? Math.round(st.ms) + ' ms' : '—'}),
      el('td', {class: 'num', textContent: st.uptime != null ? st.uptime + ' %' : '—',
        title: st.cert_days != null ? 'certificate expires in ' + st.cert_days + ' days' : ''}),
      el('td', {class: 'small', textContent: since(st.since) + (st.cert_days != null && st.cert_days < 21 ? ' · cert ' + st.cert_days + 'd' : '')}),
      el('td', {class: 'num'},
        el('button', {class: 'link', textContent: 'Run', onclick: async () => {
          try { await api('POST', '/api/monitors/' + m.id + '/run', {}); } catch (e) { $('#monMsg').textContent = e.message; }
          loadMonitor(); }}),
        el('button', {class: 'link', textContent: 'Edit', onclick: () => openMonDlg(m)}),
        el('button', {class: 'link del', textContent: 'Delete', onclick: async () => {
          if (!confirm('Delete check "' + (m.name || m.target) + '"?')) return;
          await api('DELETE', '/api/monitors/' + m.id).catch(e => $('#monMsg').textContent = e.message); loadMonitor(); }}))));
  }
  const a = MONS.alerts || {};
  if (!document.activeElement || !document.activeElement.closest('#alertsCard')) {
    $('#alEmail').value = a.email || ''; $('#alHook').value = a.webhook || ''; $('#alTgToken').value = a.telegram_token || '';
    $('#alTgChat').value = a.telegram_chat || ''; $('#alFails').value = a.fail_after || 2; $('#alCert').value = a.cert_days || 14;
  }
}
function monTypeChanged() {
  const f = $('#monForm'), t = f.type.value;
  for (const x of document.querySelectorAll('#monForm .http-only')) x.hidden = t !== 'http';
  f.target.placeholder = {http: 'https://cloud.example.com/health', tcp: '10.10.10.11:5432', ping: '10.10.10.11'}[t];
}
function openMonDlg(m) {
  editingMon = m ? m.id : null;
  const f = $('#monForm');
  $('#monTitle').textContent = m ? 'Edit check' : 'Add check'; $('#monErr').textContent = '';
  m = m || {type: 'http', interval: 60, timeout: 5, expect: '200-399', verify_tls: true, alert: true, enabled: true};
  for (const k of ['name', 'type', 'target', 'interval', 'timeout', 'expect']) f[k].value = m[k] != null ? m[k] : '';
  for (const k of ['verify_tls', 'alert', 'enabled']) f[k].checked = !!m[k];
  monTypeChanged(); $('#monDlg').showModal(); f.target.focus();
}
$('#monForm').type.addEventListener('change', monTypeChanged);
$('#monForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target, d = {};
  for (const k of ['name', 'type', 'target', 'interval', 'timeout', 'expect']) d[k] = f[k].value.trim();
  for (const k of ['verify_tls', 'alert', 'enabled']) d[k] = f[k].checked;
  try { await api(editingMon ? 'PUT' : 'POST', editingMon ? '/api/monitors/' + editingMon : '/api/monitors', d); $('#monDlg').close(); loadMonitor(); }
  catch (err) { $('#monErr').textContent = err.message; }
});
$('#monCancel').onclick = () => $('#monDlg').close();
$('#addMonBtn').onclick = () => openMonDlg(null);
$('#suggestMon').onclick = async () => {
  try { const r = await api('POST', '/api/monitors/suggest', {}); $('#monMsg').textContent = r.added ? 'Added ' + r.added + ' check(s)' : 'Every domain and port rule already has a check'; }
  catch (e) { $('#monMsg').textContent = e.message; }
  setTimeout(loadMonitor, 1200);
};
$('#alSave').onclick = async () => {
  $('#alErr').textContent = '';
  try {
    await api('PUT', '/api/alerts', {email: $('#alEmail').value, webhook: $('#alHook').value, telegram_token: $('#alTgToken').value,
      telegram_chat: $('#alTgChat').value, fail_after: $('#alFails').value, cert_days: $('#alCert').value});
    $('#alMsg').textContent = 'Saved'; setTimeout(() => $('#alMsg').textContent = '', 3000); document.activeElement.blur(); loadMonitor();
  } catch (e) { $('#alErr').textContent = e.message; }
};
$('#alTest').onclick = async () => {
  try { await api('POST', '/api/alerts/test', {}); $('#alMsg').textContent = 'Test alert sent - check your e-mail / chat (and the Debug log if nothing arrives)'; }
  catch (e) { $('#alErr').textContent = e.message; }
};
$('#scanPorts').onchange = e => $('#scanCustomRow').hidden = e.target.value !== 'custom';
async function fillScanTargets() {
  const opts = (S.networks || []).map(n => [n.ip, n.iface + ' (this host)']);
  try { for (const g of (await api('GET', '/api/guests')).guests) for (const ip of g.ips) opts.push([ip, g.vmid + ' ' + g.name]); } catch (e) {}
  $('#scanTargets').replaceChildren(...opts.map(([v, l]) => el('option', {value: v, label: l})));
  if (!$('#scanTarget').value && opts.length) $('#scanTarget').value = opts[0][0];
}
$('#scanBtn').onclick = async () => {
  const b = $('#scanBtn'); $('#scanErr').textContent = '';
  const ports = $('#scanPorts').value === 'custom' ? $('#scanCustom').value : $('#scanPorts').value;
  b.disabled = true;
  try {
    let sc = await api('POST', '/api/scan', {target: $('#scanTarget').value.trim(), ports});
    while (sc.state === 'running') {
      $('#scanMsg').textContent = 'Scanning ' + sc.target + '… ' + sc.done + ' / ' + sc.total;
      await new Promise(r => setTimeout(r, 600));
      sc = await api('GET', '/api/scan/' + sc.id);
    }
    $('#scanMsg').textContent = sc.target + ': ' + sc.open.length + ' open of ' + sc.total + ' scanned';
    $('#scanTable').hidden = false;
    $('#scanRows').replaceChildren(...sc.open.map(o => el('tr', {},
      el('td', {class: 'num mono', textContent: o.port}), el('td', {textContent: o.service || '—'}),
      el('td', {}, el('span', {class: 'pill ' + o.risk, textContent: o.risk, title: {high: 'should not be reachable from the internet',
        admin: 'admin access - restrict who can reach it', low: ''}[o.risk]})))));
  } catch (e) { $('#scanErr').textContent = e.message; }
  b.disabled = false;
};

// ---- VPN: WireGuard
let WG = null, wgTEdit = null, wgPEdit = null, wgPTunnel = null, wgCName = 'peer';
async function loadVpn() {
  try { WG = await api('GET', '/api/wireguard'); renderVpn(); } catch (e) { $('#wgMsg').textContent = e.message; }
}
function renderVpn() {
  const job = WG.job || {};
  $('#wgState').replaceChildren(el('span', {class: 'chip ' + (WG.installed ? 'ok' : 'bad'), textContent: WG.installed ? 'installed' : 'not installed'}));
  $('#wgInstall').hidden = WG.installed; $('#wgInstall').disabled = job.state === 'pending';
  $('#wgNewTunnel').hidden = !WG.installed;
  $('#wgMsg').textContent = job.state === 'pending' || job.state === 'error' ? job.msg : !WG.installed ? 'WireGuard gives you secure access to this host and its guests from anywhere.' :
    !WG.tunnels.length ? 'No tunnel yet - click + New tunnel (the defaults are fine for most setups).' : '';
  $('#wgTunnels').replaceChildren(...WG.tunnels.map(t => {
    const st = t.status || {peers: {}};
    return el('div', {class: 'card form-card', style: 'margin-bottom:14px;max-width:none'},
      el('div', {class: 'sub-head', style: 'margin:0'}, el('h2', {textContent: t.name}),
        el('span', {class: 'chip ' + (st.up ? 'ok' : t.enabled ? 'bad' : 'warn'), textContent: st.up ? 'up' : t.enabled ? 'down' : 'disabled'}),
        el('span', {class: 'mono small', textContent: t.address + ' · UDP ' + t.port + (t.nat ? ' · NAT' : '')}),
        el('span', {class: 'spacer'}),
        el('button', {class: 'ghost', textContent: '+ Device', onclick: () => openWgPeer(t, null, 'device')}),
        el('button', {class: 'ghost', textContent: '+ Site', onclick: () => openWgPeer(t, null, 'site')}),
        el('button', {class: 'link', textContent: 'Edit', onclick: () => openWgTunnel(t)}),
        el('button', {class: 'link del', textContent: 'Delete', onclick: async () => {
          if (!confirm('Delete tunnel ' + t.name + ' and its ' + t.peers.length + ' peers? Their keys are deleted too.')) return;
          await api('DELETE', '/api/wireguard/tunnels/' + t.id).catch(e => $('#wgMsg').textContent = e.message); loadVpn(); }})),
      el('p', {class: 'hint'}, 'Server public key: ', el('span', {class: 'mono', textContent: t.public_key}), ' ',
        el('button', {class: 'link', textContent: 'copy', onclick: () => navigator.clipboard.writeText(t.public_key)})),
      el('div', {class: 'scroll'}, el('table', {},
        el('thead', {}, el('tr', {}, ...['', 'Peer', 'VPN address', 'Endpoint', 'Last handshake', 'Received / sent', ''].map(h => el('th', {textContent: h})))),
        el('tbody', {}, ...t.peers.map(p => {
          const ps = st.peers[p.public_key] || {};
          const s = !p.enabled ? 'unknown' : ps.online ? 'up' : 'down';
          return el('tr', {class: p.enabled ? '' : 'off'},
            el('td', {}, el('span', {class: 'pill ' + s, textContent: !p.enabled ? 'off' : ps.online ? 'online' : 'offline'})),
            el('td', {class: 'names'}, p.name, el('span', {class: 'alias', textContent: p.kind === 'site' ? 'site / router' : 'device'})),
            el('td', {class: 'mono', textContent: p.address.replace('/32', '') + (p.allowed_ips.length ? ' + ' + p.allowed_ips.join(', ') : '')}),
            el('td', {class: 'mono small', textContent: ps.endpoint || p.endpoint || '—'}),
            el('td', {class: 'small', textContent: ps.handshake ? since(ps.handshake).replace(/^(\d.*)$/, '$1 ago') : 'never'}),
            el('td', {class: 'num small', textContent: ps.rx || ps.tx ? fmtBytes(ps.rx) + ' / ' + fmtBytes(ps.tx) : '—'}),
            el('td', {class: 'num'},
              p.kind === 'device' && p.has_key ? el('button', {class: 'link', textContent: 'Config', onclick: () => showWgConfig(t, p)}) : null,
              el('button', {class: 'link', textContent: 'Edit', onclick: () => openWgPeer(t, p)}),
              el('button', {class: 'link del', textContent: 'Delete', onclick: async () => {
                if (!confirm('Remove ' + p.name + '? It can no longer connect.')) return;
                await api('DELETE', '/api/wireguard/tunnels/' + t.id + '/peers/' + p.id).catch(e => $('#wgMsg').textContent = e.message); loadVpn(); }})));
        }))),
        t.peers.length ? null : el('p', {class: 'muted pad', textContent: 'No peers yet - add a device (phone, laptop) or a site (another router).'})));
  }));
}
function openWgTunnel(t) {
  wgTEdit = t ? t.id : null; const f = $('#wgTForm'), d = t || WG.defaults;
  $('#wgTTitle').textContent = t ? 'Edit tunnel ' + t.name : 'New tunnel'; $('#wgTErr').textContent = '';
  f.name.value = d.name; f.name.disabled = !!t; f.port.value = d.port; f.address.value = d.address; f.endpoint.value = d.endpoint || '';
  f.client_routes.value = (d.client_routes || []).join('\n'); f.dns.value = (d.dns || []).join(', ');
  f.nat.checked = t ? t.nat : true; f.enabled.checked = t ? t.enabled : true; $('#wgTDlg').showModal();
}
$('#wgTForm').addEventListener('submit', async e => {
  e.preventDefault(); const f = e.target;
  const d = {name: f.name.value.trim(), port: f.port.value, address: f.address.value.trim(), endpoint: f.endpoint.value.trim(),
    client_routes: f.client_routes.value, dns: f.dns.value, nat: f.nat.checked, enabled: f.enabled.checked};
  try { await api(wgTEdit ? 'PUT' : 'POST', '/api/wireguard/tunnels' + (wgTEdit ? '/' + wgTEdit : ''), d); $('#wgTDlg').close(); loadVpn(); }
  catch (err) { $('#wgTErr').textContent = err.message; }
});
function wgKindChanged() { for (const x of document.querySelectorAll('#wgPForm .site-only')) x.hidden = $('#wgPForm').kind.value !== 'site'; }
function openWgPeer(t, p, kind) {
  wgPTunnel = t; wgPEdit = p ? p.id : null; const f = $('#wgPForm');
  $('#wgPTitle').textContent = p ? 'Edit ' + p.name : kind === 'site' ? 'Add site' : 'Add device'; $('#wgPErr').textContent = '';
  p = p || {kind, name: '', address: '', public_key: '', allowed_ips: [], endpoint: '', keepalive: kind === 'site' ? 25 : 0, psk: true, enabled: true};
  f.name.value = p.name; f.kind.value = p.kind; f.kind.disabled = !!wgPEdit; f.address.value = p.address.replace('/32', '');
  f.public_key.value = p.kind === 'site' ? p.public_key : ''; f.public_key.disabled = !!wgPEdit && p.kind !== 'site';
  f.allowed_ips.value = p.allowed_ips.join(', '); f.endpoint.value = p.endpoint; f.keepalive.value = p.keepalive || '';
  f.psk.checked = p.psk; f.psk.disabled = !!wgPEdit; f.enabled.checked = p.enabled;
  wgKindChanged(); $('#wgPDlg').showModal(); f.name.focus();
}
$('#wgPForm').kind.addEventListener('change', wgKindChanged);
$('#wgPForm').addEventListener('submit', async e => {
  e.preventDefault(); const f = e.target;
  const d = {name: f.name.value.trim(), kind: f.kind.value, address: f.address.value.trim(), public_key: f.public_key.value.trim(),
    allowed_ips: f.allowed_ips.value, endpoint: f.endpoint.value.trim(), keepalive: f.keepalive.value, psk: f.psk.checked, enabled: f.enabled.checked};
  try {
    const r = await api(wgPEdit ? 'PUT' : 'POST', '/api/wireguard/tunnels/' + wgPTunnel.id + '/peers' + (wgPEdit ? '/' + wgPEdit : ''), d);
    $('#wgPDlg').close(); await loadVpn();
    if (r.config) showWgConfigText(d.name, r.config);
  } catch (err) { $('#wgPErr').textContent = err.message; }
});
async function showWgConfig(t, p) {
  try { const r = await fetch('/api/wireguard/tunnels/' + t.id + '/peers/' + p.id + '/config', {credentials: 'same-origin'});
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
    showWgConfigText(p.name, await r.text()); } catch (e) { $('#wgMsg').textContent = e.message; }
}
function showWgConfigText(name, text) {
  wgCName = name.replace(/[^A-Za-z0-9_.-]+/g, '-') || 'peer';
  $('#wgCTitle').textContent = 'Client configuration - ' + name; $('#wgCText').value = text; $('#wgCDlg').showModal();
}
$('#wgCCopy').onclick = () => navigator.clipboard.writeText($('#wgCText').value).then(() => $('#wgCCopy').textContent = 'Copied', () => {});
$('#wgCDown').onclick = () => {
  const url = URL.createObjectURL(new Blob([$('#wgCText').value], {type: 'text/plain'}));
  const a = el('a', {href: url, download: wgCName + '.conf'}); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
};
$('#wgCClose').onclick = () => { $('#wgCText').value = ''; $('#wgCCopy').textContent = 'Copy'; $('#wgCDlg').close(); };
$('#wgTCancel').onclick = () => $('#wgTDlg').close();
$('#wgPCancel').onclick = () => $('#wgPDlg').close();
$('#wgNewTunnel').onclick = () => openWgTunnel(null);
$('#wgInstall').onclick = async () => { await api('POST', '/api/wireguard/install', {}).catch(e => $('#wgMsg').textContent = e.message); loadVpn(); };

// ---- Network: Proxmox SDN (zones, VNets, subnets with DHCP, IPAM, DNS)
let SDN = null, sdnZEdit = null, sdnSEdit = null, sdnSVnet = null, sdnErr = '';
const sdnState = s => s ? el('span', {class: 'chip warn', textContent: s, title: 'not applied yet - click Apply SDN changes'}) : null;
async function loadNetwork() {
  try { SDN = await api('GET', '/api/sdn'); renderNetwork(); } catch (e) { $('#sdnMsg').textContent = e.message; }
  if (SDN && SDN.job && SDN.job.state === 'pending' && view === 'network') setTimeout(loadNetwork, 1000);  // apply / install running
}
function renderNetwork() {
  const s = SDN, job = s.job || {};
  $('#sdnState').replaceChildren(el('span', {class: 'chip ' + (s.available ? 'ok' : 'bad'),
    textContent: s.available ? 'Proxmox SDN' + (s.version ? ' · PVE ' + s.version : '') : 'SDN not available'}));
  $('#sdnNewZone').hidden = !s.available;
  $('#sdnInstall').hidden = !s.available || s.dnsmasq; $('#sdnInstall').disabled = job.state === 'pending';
  $('#sdnPending').hidden = !s.pending; $('#sdnApply').disabled = job.state === 'pending';
  $('#sdnMsg').className = sdnErr ? 'err' : 'muted small';
  $('#sdnMsg').textContent = sdnErr || (!s.available || s.error) ? sdnErr || s.error : job.state === 'pending' || job.state === 'error' || (job.state === 'ok' && Date.now() / 1000 - job.t < 15) ? job.msg :
    !s.zones.length ? 'No zone yet - click + Zone, then add a VNet and a subnet with a DHCP range.' : '';
  const req = [];
  if (s.available && !s.dhcp_ok) req.push({status: 'warn', name: 'DHCP needs Proxmox VE 8.1 or newer', detail: 'This host runs ' + (s.version || 'an older version') + '. Zones and VNets work; DHCP ranges do not.'});
  if (s.available && !s.dnsmasq) req.push({status: s.zones.some(z => z.dhcp) ? 'fail' : 'warn', name: 'dnsmasq is not installed', detail: 'Proxmox uses it for SDN DHCP - click Install dnsmasq (or run: apt install dnsmasq && systemctl disable --now dnsmasq).'});
  if (s.available && !s.sourced) req.push({status: 'fail', name: '/etc/network/interfaces does not include interfaces.d', detail: 'Add this line at the end, or SDN bridges never come up:\nsource /etc/network/interfaces.d/*'});
  $('#sdnReq').hidden = !req.length; renderChecks($('#sdnReq'), req);
  const nicsOn = v => s.nics.filter(n => n.bridge === v);
  $('#sdnZones').replaceChildren(...s.zones.map(z => {
    const vnets = s.vnets.filter(v => v.zone === z.zone || (v.state === 'deleted' && !v.zone && z.state === 'deleted'));
    const rows = [];
    for (const v of vnets) {
      const g = nicsOn(v.vnet);
      rows.push(el('tr', {class: v.state === 'deleted' ? 'off' : ''},
        el('td', {class: 'names'}, el('b', {class: 'mono', textContent: v.vnet}), v.alias ? el('span', {class: 'alias', textContent: v.alias}) : null, sdnState(v.state)),
        el('td', {colSpan: 4, class: 'small', textContent: g.length ? 'Guests: ' + g.map(n => (n.name || n.vmid) + ' (' + n.nic + ')').join(', ') : v.state === 'deleted' ? '' : 'no guest uses it yet'}),
        el('td', {class: 'num'}, v.state === 'deleted' || z.type !== 'simple' ? null : el('button', {class: 'link', textContent: '+ Subnet', onclick: () => openSdnSubnet(v, null)}),
          v.state === 'deleted' ? null : el('button', {class: 'link', textContent: 'Edit', onclick: () => editSdnVnet(v)}),
          v.state === 'deleted' ? null : el('button', {class: 'link del', textContent: 'Delete', onclick: () => sdnDo('DELETE', '/api/sdn/vnets/' + v.vnet, null, 'Delete VNet ' + v.vnet + '?')}))));
      for (const sb of v.subnets) rows.push(el('tr', {class: 'sub' + (sb.state === 'deleted' ? ' off' : '')},
        el('td', {class: 'mono', textContent: '└ ' + sb.cidr}, sdnState(sb.state)),
        el('td', {class: 'mono', textContent: sb.gateway || '—'}),
        el('td', {class: 'mono small', textContent: sb.dhcp_range.length ? sb.dhcp_range.map(r => r.join(' – ')).join(', ') : z.dhcp ? 'no range (static only)' : '—'}),
        el('td', {class: 'mono small', textContent: sb.dns_server || '—'}),
        el('td', {}, sb.snat ? el('span', {class: 'tag', textContent: 'snat'}) : null),
        el('td', {class: 'num'}, sb.state === 'deleted' ? null : el('button', {class: 'link', textContent: 'Edit', onclick: () => openSdnSubnet(v, sb)}),
          sb.state === 'deleted' ? null : el('button', {class: 'link del', textContent: 'Delete', onclick: () => sdnDo('DELETE', '/api/sdn/vnets/' + v.vnet + '/subnets/' + sb.id, null, 'Delete subnet ' + sb.cidr + '?')}))));
    }
    return el('div', {class: 'card form-card', style: 'margin-bottom:14px;max-width:none'},
      el('div', {class: 'sub-head', style: 'margin:0'}, el('h2', {textContent: 'Zone ' + z.zone}),
        el('span', {class: 'tag', textContent: z.type || '?'}),
        el('span', {class: 'chip ' + (z.dhcp ? 'ok' : 'warn'), textContent: z.dhcp ? 'DHCP' : 'no DHCP'}),
        z.dns ? el('span', {class: 'chip ok', textContent: 'DNS ' + z.dns + (z.dnszone ? ' · ' + z.dnszone : '')}) : null,
        sdnState(z.state), el('span', {class: 'spacer'}),
        z.state === 'deleted' || z.type !== 'simple' ? null : el('button', {class: 'ghost', textContent: '+ VNet', onclick: () => openSdnVnet(z.zone)}),
        z.state === 'deleted' ? null : el('button', {class: 'link', textContent: 'Edit', onclick: () => openSdnZone(z)}),
        z.state === 'deleted' ? null : el('button', {class: 'link del', textContent: 'Delete', onclick: () => sdnDo('DELETE', '/api/sdn/zones/' + z.zone, null, 'Delete zone ' + z.zone + '?')})),
      z.type && z.type !== 'simple' ? el('p', {class: 'hint', textContent: 'A ' + z.type + ' zone - VNets and subnets are shown here, but create them in the Proxmox UI (they need VLAN/VXLAN settings).'}) : null,
      rows.length ? el('div', {class: 'scroll'}, el('table', {},
        el('thead', {}, el('tr', {}, ...['VNet / subnet', 'Gateway', 'DHCP range', 'DNS for clients', '', ''].map(h => el('th', {textContent: h})))),
        el('tbody', {}, ...rows))) : el('p', {class: 'muted pad', textContent: z.state === 'deleted' ? '' : 'No VNet yet - click + VNet.'}));
  }));
  $('#sdnIpamBox').hidden = !s.available || !s.vnets.length;
  const guest = id => s.nics.find(n => n.vmid === id);
  $('#sdnIpam').replaceChildren(...s.ipam.slice().sort((a, b) => a.vnet.localeCompare(b.vnet) || ipNum(a.ip) - ipNum(b.ip)).map(e => {
    const g = e.vmid ? guest(e.vmid) : null;
    return el('tr', {},
      el('td', {class: 'mono', textContent: e.ip}), el('td', {class: 'mono', textContent: e.vnet}),
      el('td', {class: 'mono small', textContent: e.mac || '—'}),
      el('td', {class: 'names'}, e.gateway ? 'this host' : g ? (g.name || '') + ' (' + e.vmid + ')' : e.vmid ? String(e.vmid) : '—',
        e.hostname ? el('span', {class: 'alias', textContent: e.hostname}) : null),
      el('td', {}, el('span', {class: 'tag', textContent: e.gateway ? 'gateway' : e.vmid ? 'guest' : 'reserved'})),
      el('td', {class: 'num'}, e.gateway ? null : el('button', {class: 'link del', textContent: 'Delete', onclick: () =>
        sdnDo('DELETE', '/api/sdn/vnets/' + e.vnet + '/ips/' + e.ip, null, 'Remove ' + e.ip + ' from the IPAM? A guest that still uses it keeps it until its lease ends.')})));
  }));
}
function ipNum(ip) { return ip.split('.').reduce((a, x) => a * 256 + (+x || 0), 0); }
async function sdnDo(method, url, body, ask) {
  if (ask && !confirm(ask)) return;
  sdnErr = '';
  try { await api(method, url, body || {}); } catch (e) { sdnErr = e.message; }
  loadNetwork();
}
async function sdnSubmit(e, dlg, errEl, method, url, data) {
  e.preventDefault();
  try { await api(method, url, data); $(dlg).close(); sdnErr = ''; loadNetwork(); } catch (err) { $(errEl).textContent = err.message; }
}
function plugins(sel, cur) {
  sel.replaceChildren(el('option', {value: '', textContent: SDN.dns.length ? 'none' : 'none (no DNS plugin in Proxmox)'}),
    ...SDN.dns.map(d => el('option', {value: d.dns, textContent: d.dns + ' (' + d.type + ')'})));
  sel.value = cur || '';
}
function openSdnZone(z) {
  sdnZEdit = z ? z.zone : null; const f = $('#sdnZForm');
  $('#sdnZTitle').textContent = z ? 'Edit zone ' + z.zone : 'New zone'; $('#sdnZErr').textContent = '';
  f.zone.value = z ? z.zone : ''; f.zone.disabled = !!z; f.dhcp.checked = z ? !!z.dhcp : SDN.dhcp_ok;
  plugins(f.dns, z && z.dns); plugins(f.reversedns, z && z.reversedns); f.dnszone.value = z ? z.dnszone : '';
  $('#sdnZDlg').showModal();
}
$('#sdnZForm').addEventListener('submit', e => { const f = e.target;
  sdnSubmit(e, '#sdnZDlg', '#sdnZErr', sdnZEdit ? 'PUT' : 'POST', '/api/sdn/zones' + (sdnZEdit ? '/' + sdnZEdit : ''),
    {zone: f.zone.value.trim(), dhcp: f.dhcp.checked, dns: f.dns.value, reversedns: f.reversedns.value, dnszone: f.dnszone.value.trim()}); });
function openSdnVnet(zone) {
  const f = $('#sdnVForm'); $('#sdnVErr').textContent = '';
  f.zone.replaceChildren(...SDN.zones.filter(z => z.type === 'simple' && z.state !== 'deleted').map(z => el('option', {value: z.zone, textContent: z.zone})));
  f.zone.value = zone; f.vnet.value = ''; f.alias.value = ''; $('#sdnVDlg').showModal(); f.vnet.focus();
}
$('#sdnVForm').addEventListener('submit', e => { const f = e.target;
  sdnSubmit(e, '#sdnVDlg', '#sdnVErr', 'POST', '/api/sdn/vnets', {vnet: f.vnet.value.trim(), zone: f.zone.value, alias: f.alias.value.trim()}); });
function editSdnVnet(v) {
  const alias = prompt('Description of VNet ' + v.vnet, v.alias || '');
  if (alias !== null) sdnDo('PUT', '/api/sdn/vnets/' + v.vnet, {alias});
}
function openSdnSubnet(v, sb) {
  sdnSVnet = v; sdnSEdit = sb ? sb.id : null; const f = $('#sdnSForm');
  const z = SDN.zones.find(x => x.zone === v.zone) || {};
  $('#sdnSTitle').textContent = sb ? 'Edit subnet ' + sb.cidr : 'New subnet on ' + v.vnet; $('#sdnSErr').textContent = '';
  f.cidr.value = sb ? sb.cidr : ''; f.cidr.disabled = !!sb; f.gateway.value = sb ? sb.gateway : '';
  f.dhcp_range.value = sb ? sb.dhcp_range.map(r => r.join('-')).join('\n') : ''; f.dns_server.value = sb ? sb.dns_server : '';
  f.snat.checked = sb ? sb.snat : true;
  for (const x of document.querySelectorAll('#sdnSForm .dhcp-only')) x.hidden = !z.dhcp;
  $('#sdnSDlg').showModal();
}
$('#sdnSForm').cidr.addEventListener('change', e => {  // suggest gateway .1 and a DHCP range in the upper half
  const f = $('#sdnSForm'), m = e.target.value.trim().match(/^(\d+\.\d+\.\d+)\.\d+\/24$/);
  if (m && !f.gateway.value) f.gateway.value = m[1] + '.1';
  if (m && !f.dhcp_range.value && !f.dhcp_range.closest('label').hidden) f.dhcp_range.value = m[1] + '.100-' + m[1] + '.200';
});
$('#sdnSForm').addEventListener('submit', e => { const f = e.target;
  sdnSubmit(e, '#sdnSDlg', '#sdnSErr', sdnSEdit ? 'PUT' : 'POST', '/api/sdn/vnets/' + sdnSVnet.vnet + '/subnets' + (sdnSEdit ? '/' + sdnSEdit : ''),
    {cidr: f.cidr.value.trim(), gateway: f.gateway.value.trim(), dhcp_range: f.dhcp_range.value.split(/[\n,]+/).map(x => x.trim()).filter(Boolean),
     dns_server: f.dns_server.value.trim(), snat: f.snat.checked}); });
function sdnNics() {
  const f = $('#sdnIForm'), list = SDN.nics.filter(n => n.bridge === f.vnet.value);
  f.nic.replaceChildren(el('option', {value: '', textContent: list.length ? 'type the MAC yourself' : 'no guest on this VNet - type the MAC'}),
    ...list.map((n, i) => el('option', {value: i, textContent: (n.name || n.vmid) + ' ' + n.nic + ' (' + n.mac + ')'})));
  f.nic.onchange = () => { const n = list[f.nic.value]; if (n) { f.mac.value = n.mac; f.vmid.value = n.vmid; } };
}
$('#sdnNewIp').onclick = () => {
  const f = $('#sdnIForm'); $('#sdnIErr').textContent = '';
  f.vnet.replaceChildren(...SDN.vnets.filter(v => v.state !== 'deleted' && v.subnets.length).map(v => el('option', {value: v.vnet, textContent: v.vnet + ' (' + v.subnets.map(x => x.cidr).join(', ') + ')'})));
  f.mac.value = ''; f.ip.value = ''; f.vmid.value = ''; sdnNics(); $('#sdnIDlg').showModal();
};
$('#sdnIForm').vnet.addEventListener('change', sdnNics);
$('#sdnIForm').addEventListener('submit', e => { const f = e.target;
  sdnSubmit(e, '#sdnIDlg', '#sdnIErr', 'POST', '/api/sdn/vnets/' + f.vnet.value + '/ips', {ip: f.ip.value.trim(), mac: f.mac.value.trim(), vmid: f.vmid.value.trim()}); });
$('#sdnNewZone').onclick = () => openSdnZone(null);
$('#sdnApply').onclick = () => sdnDo('POST', '/api/sdn/apply');
$('#sdnInstall').onclick = () => sdnDo('POST', '/api/sdn/install');
for (const b of document.querySelectorAll('[data-close]')) b.onclick = () => b.closest('dialog').close();

// ---- security: firewall (edits go to a draft; Apply activates it with a 60 s keep/revert window)
let FW = null, FWD = null, fwEditing = null, fwTick = null;
async function loadFirewall(force) {
  try {
    const r = await api('GET', '/api/firewall');
    const dirty = FWD && JSON.stringify(FWD) !== JSON.stringify(FW && FW.settings);
    FW = r; if (force || !dirty) FWD = JSON.parse(JSON.stringify(r.settings));
    renderFirewall();
  } catch (e) { $('#fwErr').textContent = e.message; }
}
function renderFirewall() {
  const d = FWD, dirty = JSON.stringify(FWD) !== JSON.stringify(FW.settings);
  $('#fwState').replaceChildren(el('span', {class: 'chip ' + (FW.settings.enabled ? 'ok' : 'warn'),
    textContent: FW.settings.enabled ? 'on · ' + (FW.settings.backend === 'pve' ? 'Proxmox firewall' : 'pve-gateway') + ' · policy ' + FW.settings.policy : 'off'}));
  $('#fwDirty').textContent = dirty ? 'unsaved changes' : ''; $('#fwApply').disabled = !dirty;
  $('#fwBackend').value = d.backend; $('#fwPolicy').value = d.policy; $('#fwEnabled').checked = d.enabled; $('#fwPing').checked = d.allow_ping;
  $('#fwSafety').textContent = 'Always open while enabled (so you are never locked out): ' +
    FW.safety.map(x => x.why.replace('safety: ', '') + (x.ports.length ? ' (' + x.proto + ' ' + x.ports.join(',') + ')' : '')).join(', ') +
    '. Already open connections are kept.' + (d.backend === 'custom' && FW.pve_enabled ? ' The Proxmox firewall is enabled too - pve-gateway\'s rules run first.' : '');
  $('#fwTemplate').replaceChildren(el('option', {value: '', textContent: 'Add from template…'}),
    ...Object.entries(FW.templates).map(([k, v]) => el('option', {value: k, textContent: v})),
    el('option', {value: 'risky-lan', textContent: 'Risky ports open right now → LAN only'}));
  $('#fwEmpty').hidden = d.rules.length > 0;
  const move = (i, k) => { const r = d.rules.splice(i, 1)[0]; d.rules.splice(i + k, 0, r); renderFirewall(); };
  $('#fwRules').replaceChildren(...d.rules.map((r, i) => el('tr', {class: r.enabled ? '' : 'off'},
    el('td', {class: 'muted', textContent: i + 1}),
    el('td', {}, el('input', {type: 'checkbox', class: 'switch', checked: r.enabled, onchange: e => { r.enabled = e.target.checked; renderFirewall(); }})),
    el('td', {}, el('span', {class: 'pill ' + (r.action === 'ACCEPT' ? 'up' : 'down'), textContent: r.action})),
    el('td', {}, el('span', {class: 'tag', textContent: r.proto})),
    el('td', {class: 'mono', textContent: r.ports.join(',') || '—'}),
    el('td', {class: 'mono', textContent: r.source || 'anyone'}),
    el('td', {textContent: r.comment || ''}),
    el('td', {class: 'num'},
      el('button', {class: 'link', textContent: '↑', title: 'move up', disabled: i === 0, onclick: () => move(i, -1)}),
      el('button', {class: 'link', textContent: '↓', title: 'move down', disabled: i === d.rules.length - 1, onclick: () => move(i, 1)}),
      el('button', {class: 'link', textContent: 'Edit', onclick: () => openFwDlg(i)}),
      el('button', {class: 'link del', textContent: 'Delete', onclick: () => { d.rules.splice(i, 1); renderFirewall(); }})))));
  $('#fwOtherWrap').hidden = !(FW.other_rules || []).length;
  $('#fwOther').replaceChildren(...(FW.other_rules || []).map(r => el('tr', {class: r.enable ? '' : 'off'},
    el('td', {class: 'muted', textContent: r.pos}), el('td', {textContent: r.action + (r.macro ? ' (' + r.macro + ')' : '')}),
    el('td', {textContent: r.proto || '—'}), el('td', {class: 'mono', textContent: r.dport || '—'}),
    el('td', {class: 'mono', textContent: r.source || 'anyone'}), el('td', {textContent: r.comment || ''}))));
  const pb = $('#fwPending'); pb.hidden = !FW.pending;
  if (FW.pending && !fwTick) {
    let left = FW.pending; $('#fwLeft').textContent = left;
    fwTick = setInterval(() => { left--; $('#fwLeft').textContent = Math.max(0, left); if (left <= 0) { clearInterval(fwTick); fwTick = null; loadFirewall(true); } }, 1000);
  }
}
for (const [id, key, prop] of [['#fwBackend', 'backend', 'value'], ['#fwPolicy', 'policy', 'value'], ['#fwEnabled', 'enabled', 'checked'], ['#fwPing', 'allow_ping', 'checked']])
  $(id).addEventListener('change', e => { FWD[key] = e.target[prop]; renderFirewall(); });
function fwProtoChanged() { $('#fwForm').querySelector('.fw-ports').hidden = !['tcp', 'udp'].includes($('#fwForm').proto.value); }
function openFwDlg(i) {
  fwEditing = i; const f = $('#fwForm'), r = i == null ? {action: 'ACCEPT', proto: 'tcp', ports: [], source: '', comment: '', enabled: true} : FWD.rules[i];
  $('#fwTitle').textContent = i == null ? 'Add rule' : 'Edit rule'; $('#fwFormErr').textContent = '';
  f.action.value = r.action; f.proto.value = r.proto; f.ports.value = r.ports.join(','); f.source.value = r.source; f.comment.value = r.comment; f.enabled.checked = r.enabled;
  fwProtoChanged(); $('#fwDlg').showModal();
}
$('#fwForm').proto.addEventListener('change', fwProtoChanged);
$('#fwForm').addEventListener('submit', e => {
  e.preventDefault();
  const f = e.target, r = {id: fwEditing != null ? FWD.rules[fwEditing].id : undefined, action: f.action.value, proto: f.proto.value,
    ports: ['tcp', 'udp'].includes(f.proto.value) ? f.ports.value.split(/[\s,]+/).filter(Boolean) : [], source: f.source.value.trim(),
    comment: f.comment.value.trim(), enabled: f.enabled.checked};
  if (['tcp', 'udp'].includes(r.proto) && !r.ports.length) { $('#fwFormErr').textContent = 'give the port(s)'; return; }
  if (fwEditing != null) FWD.rules[fwEditing] = r; else FWD.rules.push(r);
  $('#fwDlg').close(); renderFirewall();
});
$('#fwCancel').onclick = () => $('#fwDlg').close();
$('#fwAdd').onclick = () => openFwDlg(null);
$('#fwTemplate').onchange = async e => {
  if (!e.target.value) return;
  try { const r = await api('GET', '/api/firewall/template/' + e.target.value);
    FWD.rules.push(...r.rules.map(x => Object.assign({enabled: true}, x, {ports: x.ports ? String(x.ports).split(',') : []}))); }
  catch (err) { $('#fwErr').textContent = err.message; }
  e.target.value = ''; renderFirewall();
};
$('#fwApply').onclick = async () => {
  $('#fwErr').textContent = '';
  try { FW = Object.assign(await api('PUT', '/api/firewall', FWD), {}); FWD = JSON.parse(JSON.stringify(FW.settings)); renderFirewall(); }
  catch (e) { $('#fwErr').textContent = e.message; }
};
$('#fwKeep').onclick = async () => { await api('POST', '/api/firewall/confirm', {}).catch(e => $('#fwErr').textContent = e.message);
  clearInterval(fwTick); fwTick = null; loadFirewall(true); };
$('#fwRevert').onclick = async () => { await api('POST', '/api/firewall/revert', {}).catch(e => $('#fwErr').textContent = e.message);
  clearInterval(fwTick); fwTick = null; loadFirewall(true); };

// ---- security: fail2ban
let F2B = null;
async function loadSecurity() {
  try { F2B = await api('GET', '/api/fail2ban'); renderF2b(); } catch (e) { $('#f2bMsg').textContent = e.message; }
}
function renderF2b() {
  const f = F2B, st = $('#f2bState');
  st.replaceChildren(el('span', {class: 'chip ' + (f.running ? 'ok' : f.installed ? 'warn' : 'bad'),
    textContent: f.running ? 'running · ' + f.version : f.installed ? 'installed, not running' : 'not installed'}));
  const job = f.job || {};
  $('#f2bInstall').hidden = f.installed; $('#f2bInstall').disabled = job.state === 'pending';
  $('#f2bMsg').textContent = job.state === 'pending' ? job.msg : job.state === 'error' ? job.msg : f.installed ? '' :
    'fail2ban bans IPs that keep failing to log in (SSH, Proxmox, pve-gateway) or probe for files.';
  $('#f2bMsg').style.color = job.state === 'error' ? 'var(--bad)' : '';
  for (const id of ['#f2bJailsCard', '#f2bBanBar', '#f2bSettings']) $(id).hidden = !f.installed;
  $('#f2bUnbanAll').hidden = !f.jails.some(j => j.ips.length);
  $('#f2bJails').replaceChildren(...f.jails.map(j => el('tr', {},
    el('td', {class: 'names'}, el('b', {textContent: j.name}), el('span', {class: 'alias', textContent: f.jail_info[j.name] || ''})),
    el('td', {class: 'num', textContent: j.failed + ' / ' + j.failed_total}),
    el('td', {class: 'num', textContent: j.banned + ' / ' + j.banned_total}),
    el('td', {class: 'num'}, j.ips.length ? el('button', {class: 'link', textContent: 'show ' + j.ips.length + ' banned',
      onclick: () => { $('#f2bFilter').value = j.name; renderBanned(); $('#f2bFilter').focus(); }}) : null))));
  renderBanned();
  $('#f2bBanJail').replaceChildren(...f.jails.map(j => el('option', {value: j.name, textContent: j.name})));
  if (document.activeElement && document.activeElement.closest('#f2bSettings')) return;  // don't overwrite while typing
  const c = f.settings;
  $('#f2bManaged').checked = c.managed; $('#f2bFile').textContent = f.file;
  $('#f2bBantime').value = c.bantime; $('#f2bFindtime').value = c.findtime; $('#f2bMaxretry').value = c.maxretry;
  $('#f2bIgnore').value = c.ignoreip.join('\n'); $('#f2bMyIp').textContent = f.client_ip;
  $('#f2bJailToggles').replaceChildren(...Object.entries(f.jail_info).map(([j, d]) => el('label', {class: 'check'},
    el('input', {type: 'checkbox', name: 'jail', value: j, checked: !!c.jails[j]}), el('span', {}, el('b', {textContent: j}), ' - ' + d))));
  for (const x of $('#f2bFields').querySelectorAll('input,textarea,button')) x.disabled = !c.managed;
}
function ipNet(ip) {  // a rough "where is it from" without lookups: private/doc ranges or the /24 (/48 for IPv6)
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) return 'private network';
  if (/^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip)) return 'documentation range';
  return ip.includes(':') ? ip.split(':').slice(0, 3).join(':') + '::/48' : ip.split('.').slice(0, 3).join('.') + '.0/24';
}
function renderBanned() {
  const f = F2B; if (!f) return;
  const all = f.jails.flatMap(j => j.ips.map(ip => ({ip, jail: j.name})));
  const q = $('#f2bFilter').value.trim().toLowerCase();
  const rows = all.filter(b => !q || b.ip.includes(q) || b.jail.toLowerCase().includes(q))
    .sort((a, b) => a.ip.localeCompare(b.ip, undefined, {numeric: true}));
  const net = {}; for (const b of all) net[ipNet(b.ip)] = (net[ipNet(b.ip)] || 0) + 1;
  $('#f2bBannedHead').hidden = $('#f2bBannedCard').hidden = !f.installed;
  $('#f2bBannedCount').textContent = '(' + (q ? rows.length + ' of ' : '') + all.length + ')';
  $('#f2bBannedEmpty').hidden = rows.length > 0;
  const shown = rows.slice(0, 300);
  $('#f2bBannedMore').hidden = rows.length <= 300; $('#f2bBannedMore').textContent = 'Showing 300 of ' + rows.length + ' - use the filter.';
  $('#f2bBanned').replaceChildren(...shown.map(b => el('tr', {},
    el('td', {class: 'mono', textContent: b.ip}),
    el('td', {}, el('span', {class: 'tag', textContent: b.jail})),
    el('td', {class: 'small muted', textContent: ipNet(b.ip) + (net[ipNet(b.ip)] > 1 ? ' · ' + net[ipNet(b.ip)] + ' banned from it' : '')}),
    el('td', {class: 'num'}, el('button', {class: 'link', textContent: 'Unban', onclick: () => f2bAct('unban', {jail: b.jail, ip: b.ip})})))));
}
$('#f2bFilter').addEventListener('input', renderBanned);
$('#f2bCopy').onclick = () => {
  const txt = F2B.jails.flatMap(j => j.ips.map(ip => ip + '\t' + j.name)).join('\n');
  navigator.clipboard.writeText(txt).then(() => { $('#f2bCopy').textContent = 'Copied'; setTimeout(() => $('#f2bCopy').textContent = 'Copy list', 2000); }, () => {});
};
async function f2bAct(what, body) {
  $('#f2bActErr').textContent = '';
  try { await api('POST', '/api/fail2ban/' + what, body || {}); } catch (e) { $('#f2bActErr').textContent = e.message; }
  loadSecurity();
}
$('#f2bManaged').onchange = e => { for (const x of $('#f2bFields').querySelectorAll('input,textarea,button')) x.disabled = !e.target.checked; };
$('#f2bAddMe').onclick = () => { const t = $('#f2bIgnore'), ip = $('#f2bMyIp').textContent;
  if (!t.value.split(/[\s,]+/).includes(ip)) t.value = (t.value.trim() ? t.value.trim() + '\n' : '') + ip; };
$('#f2bSave').onclick = async () => {
  $('#f2bErr').textContent = '';
  const jails = {}; for (const c of document.querySelectorAll('#f2bJailToggles input')) jails[c.value] = c.checked;
  try {
    await api('PUT', '/api/fail2ban', {managed: $('#f2bManaged').checked, bantime: $('#f2bBantime').value, findtime: $('#f2bFindtime').value,
      maxretry: $('#f2bMaxretry').value, ignoreip: $('#f2bIgnore').value, jails});
    $('#f2bSaved').textContent = 'Applied'; setTimeout(() => $('#f2bSaved').textContent = '', 3000); document.activeElement.blur(); loadSecurity();
  } catch (e) { $('#f2bErr').textContent = e.message; }
};
$('#f2bInstall').onclick = () => f2bAct('install');
$('#f2bUnbanAll').onclick = () => confirm('Unban every banned IP in all jails?') && f2bAct('unban-all');
$('#f2bBan').onclick = () => f2bAct('ban', {jail: $('#f2bBanJail').value, ip: $('#f2bBanIp').value.trim()});

// ---- updates
const ago = t => { const m = Math.round((Date.now() / 1000 - t) / 60); return m < 1 ? 'just now' : m < 60 ? m + ' min ago' : Math.round(m / 60) + ' h ago'; };
function renderUpdate(u) {
  $('#updStatus').textContent = 'Installed v' + u.current + (u.latest ? ' · latest v' + u.latest + ' (' + u.ref + ')' : '') +
    (u.checked ? ' · checked ' + ago(u.checked) : ' · not checked yet') + (u.latest && !u.available ? ' · up to date' : '');
  $('#updErr').textContent = u.error || '';
  $('#updRun').hidden = !u.available; $('#updRun').textContent = 'Update to v' + u.latest; $('#updRun').disabled = false;
  $('#updLink').href = u.url;
  $('#updChanges').replaceChildren(...(u.changes || []).map(c =>
    el('div', {}, el('b', {textContent: 'v' + c.title}), el('pre', {textContent: c.notes}))));
}
async function loadUpdate(fresh) {
  $('#updCheck').disabled = true;
  try { renderUpdate(await api(fresh ? 'POST' : 'GET', fresh ? '/api/update/check' : '/api/update', fresh ? {} : undefined)); }
  catch (e) { $('#updErr').textContent = e.message; }
  $('#updCheck').disabled = false;
}
async function waitForRestart(ver) {
  clearInterval(timer); timer = null;
  const until = Date.now() + 180000;
  while (Date.now() < until) {
    await new Promise(r => setTimeout(r, 3000));
    try {
      const r = await fetch('/api/state', {credentials: 'same-origin'});
      if (r.status === 401) return location.reload();  // restarted (sessions live in memory): sign in again
      if (r.ok && (await r.json()).version === ver) return location.reload();
    } catch (e) { /* restarting */ }
  }
  $('#updErr').textContent = 'The update did not finish within 3 minutes - on the host run: journalctl -u pve-gateway-update';
}
$('#updCheck').onclick = () => loadUpdate(true);
$('#autoUpd').onchange = async e => {
  try { await api('PUT', '/api/settings', {auto_update: e.target.checked}); }
  catch (err) { e.target.checked = !e.target.checked; $('#updErr').textContent = err.message; }
};
$('#updRun').onclick = async () => {
  const b = $('#updRun');
  if (!confirm(b.textContent + ' now? pve-gateway restarts for a few seconds; port rules and domains keep working.')) return;
  b.disabled = true; $('#updErr').textContent = ''; $('#updStatus').textContent = 'Downloading…';
  try {
    const r = await api('POST', '/api/update', {});
    if (r.mock) { $('#updStatus').textContent = 'Mock mode: v' + r.version + ' was downloaded and checked; a real host would install it now.'; b.disabled = false; return; }
    $('#updStatus').textContent = 'Installing v' + r.version + '… the page reloads when pve-gateway is back (you will need to sign in again).';
    waitForRestart(r.version);
  } catch (e) { $('#updErr').textContent = e.message; b.disabled = false; }
};

// ---- settings
async function loadSettings() {
  loadUpdate(false);
  try {
    const d = await api('GET', '/api/settings');
    $('#uiAllow').value = d.ui_allow.join('\n'); $('#uiHosts').value = d.allowed_hosts.join('\n');
    $('#uiUsers').value = d.allowed_users.join('\n'); $('#usersRow').hidden = d.auth !== 'pve';
    $('#autoUpd').checked = d.auto_update;
    $('#myIp').textContent = d.client_ip; $('#uiPort').textContent = location.port || (location.protocol === 'https:' ? 443 : 80);
    $('#ownHosts').textContent = 'Always allowed: any IP address, ' + d.own_hosts.join(', ') + '.';
    $('#setErr').textContent = '';
  } catch (e) { $('#setErr').textContent = e.message; }
}
$('#addMyIp').onclick = () => {
  const t = $('#uiAllow'), ip = $('#myIp').textContent;
  if (!t.value.split(/[\s,]+/).includes(ip)) t.value = (t.value.trim() ? t.value.trim() + '\n' : '') + ip;
};
$('#saveSettings').onclick = async () => {
  $('#setErr').textContent = '';
  try {
    const body = {ui_allow: $('#uiAllow').value, allowed_hosts: $('#uiHosts').value};
    if (!$('#usersRow').hidden) body.allowed_users = $('#uiUsers').value;
    await api('PUT', '/api/settings', body);
    $('#setMsg').textContent = 'Saved'; setTimeout(() => $('#setMsg').textContent = '', 3000);
    loadSettings(); load().catch(() => {});
  } catch (e) { $('#setErr').textContent = e.message; }
};

function setView() {
  view = {'#debug': 'debug', '#domains': 'domains', '#settings': 'settings', '#monitor': 'monitor', '#security': 'security', '#vpn': 'vpn', '#network': 'network'}[location.hash] || 'rules';
  for (const a of document.querySelectorAll('.tabs a')) a.classList.toggle('on', a.dataset.view === view);
  for (const v of ['rules', 'domains', 'monitor', 'security', 'vpn', 'network', 'settings', 'debug']) $('#view-' + v).hidden = view !== v;
  if (view === 'vpn' && !$('#app').hidden) loadVpn();
  if (view === 'network' && !$('#app').hidden) loadNetwork();
  if (view === 'security' && !$('#app').hidden) { loadSecurity(); loadFirewall(); }
  if (view === 'monitor' && !$('#app').hidden) { loadMonitor(); fillScanTargets(); }
  if (view === 'settings' && !$('#app').hidden) loadSettings();
  if ($('#app').hidden) return;
  if (view === 'debug') loadDebug(); else load().catch(() => {});
}
window.addEventListener('hashchange', setView);

load().catch(() => {});
"""

# App logo / favicon: a gate (gateway) with three servers (guests) inside. Same file as docs/logo.svg.
LOGO_SVG = r"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#E57000"/><path d="M14 52V30a18 18 0 0 1 36 0v22" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round"/><g fill="#fff"><rect x="23" y="27" width="18" height="6.5" rx="2"/><rect x="23" y="36" width="18" height="6.5" rx="2"/><rect x="23" y="45" width="18" height="6.5" rx="2"/></g><g fill="#E57000"><circle cx="36.5" cy="30.25" r="1.4"/><circle cx="36.5" cy="39.25" r="1.4"/><circle cx="36.5" cy="48.25" r="1.4"/></g></svg>"""

STATIC = {
    "/": ("text/html", INDEX_HTML),
    "/app.css": ("text/css", APP_CSS),
    "/app.js": ("application/javascript", APP_JS),
    "/favicon.svg": ("image/svg+xml", LOGO_SVG),
}


# --------------------------------------------------------------------------- main

def start_mock(here):
    global MOCK
    import importlib.util
    path = os.path.join(here, "dev", "mock.py")
    if not os.path.exists(path):
        sys.exit("--mock needs %s (it is only in the source tree, not installed on hosts)" % path)
    spec = importlib.util.spec_from_file_location("pve_gateway_mock", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    MOCK = mod.Mock(CONF_DIR, socket.gethostname().split(".")[0])


def main():
    global DRY_RUN, CONF_DIR, VERBOSE
    ap = argparse.ArgumentParser(
        description="pve-gateway: port forwarding and domains for Proxmox VE guests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""commands:
  serve            run the web UI (default)
  status           rules, hit counters and hook status
  test [NAME...]   reachability test per rule or domain (id, name, host port or domain; default: all)
  debug            full diagnostic report (paste this when asking for help)
  show             print the generated iptables-restore payload
  apply            re-apply saved rules
  flush            remove all forwarding rules and chains (config is kept)
  passwd           set a local login instead of Proxmox accounts
  update [check]   check GitHub for a new version and install it ("check" = only check)
  monitors         run every health check once and show the results
  scan IP [PORTS]  TCP port scan from this host (PORTS: common | 22,80,8000-8100); own/private IPs only
  ui-allow [IP...]  limit the web UI to these IPs/networks ("any" = everyone); no args = show
  ui-host [NAME..] hostnames the UI may be opened by besides IPs ("none" = clear); no args = show
  domains          list domains, wildcard certificates and expiry
  cert NAME        request / renew a certificate now (domain, or *.zone for a wildcard)
  mock SCENARIO    (--mock only) break the simulated host: %s

local development (macOS etc.):
  ./pve-gateway.py --mock         simulated Proxmox host, http://127.0.0.1:8099, login admin / admin""" % (
            "reset, unhook, ip-forward-off, forward-drop, pvefw-first, foreign-dnat, traffic"))
    ap.add_argument("cmd", nargs="?", default="serve",
                    choices=["serve", "status", "test", "debug", "show", "apply", "flush", "passwd", "mock",
                             "domains", "cert", "ui-allow", "ui-host", "update", "monitors", "scan"])
    ap.add_argument("rules", nargs="*", help=argparse.SUPPRESS)
    ap.add_argument("-v", "--verbose", action="store_true", help="log every iptables command and HTTP request")
    ap.add_argument("--version", action="version", version="pve-gateway " + VERSION)
    ap.add_argument("--dry-run", action="store_true", help="log iptables changes instead of running them")
    ap.add_argument("--mock", action="store_true", help="simulate a Proxmox host (for local development, uses dev/mock.py)")
    ap.add_argument("--config-dir", help="default: %s (with --mock: ./.dev)" % CONF_DIR)
    ap.add_argument("--port", type=int, help="override listen port")
    a = ap.parse_args()
    DRY_RUN, VERBOSE = a.dry_run and not a.mock, a.verbose
    here = os.path.dirname(os.path.abspath(__file__))
    CONF_DIR = a.config_dir or (os.path.join(here, ".dev") if a.mock else CONF_DIR)

    if a.mock:
        start_mock(here)
    elif a.cmd == "mock":
        sys.exit("the 'mock' command needs --mock")
    elif not DRY_RUN and hasattr(os, "geteuid") and os.geteuid() != 0 and a.cmd != "show":
        sys.exit("must run as root (needs iptables); use --dry-run to preview or --mock to simulate")

    fresh = not os.path.exists(conf_file())
    cfg = load_config()
    if MOCK and fresh:
        for r in MOCK.sample_rules():
            cfg["rules"].append(validate_rule(r, cfg["rules"], cfg))
        for w in MOCK.sample_wildcards():
            wc = validate_wildcard(w, cfg["wildcards"])
            write_creds(wc, build_creds(wc, w["credentials"]))
            cfg["wildcards"].append(wc)
        for d in MOCK.sample_domains():
            cfg["domains"].append(validate_domain(d, cfg["domains"], cfg))
        for m in MOCK.sample_monitors():
            cfg["monitors"].append(validate_monitor(m, cfg["monitors"]))
        t = validate_wg_tunnel(wg_defaults(cfg), [], cfg)
        priv, t["public_key"] = wg_genkey()
        wg_secret(t["id"] + ".key", priv)
        for name, kind, extra in (("laptop", "device", {}), ("phone", "device", {}),
                                  ("office router", "site", {"public_key": wg_genkey()[1], "allowed_ips": "192.168.77.0/24",
                                                             "endpoint": "office.example.com:51820"})):
            peer = validate_wg_peer(dict(name=name, kind=kind, **extra), t)
            if kind == "device":
                pk, peer["public_key"] = wg_genkey()
                wg_secret(peer["id"] + ".key", pk)
            t["peers"].append(peer)
        cfg["wireguard"]["tunnels"].append(t)
        cfg["acme_email"] = "admin@example.com"
    if a.port:
        cfg["port"] = a.port
    if MOCK:
        cfg["listen"] = "127.0.0.1"
        if not cfg.get("pass_hash"):
            cfg["local_user"], cfg["pass_hash"] = "admin", hash_password("admin")
        if fresh or not os.path.exists(conf_file()):
            save_config(cfg)
    STATE["cfg"] = cfg

    if a.cmd == "show":
        sys.stdout.write(build_ruleset(cfg))
    elif a.cmd == "apply":
        sys.exit(1 if apply_rules() or apply_nginx() else 0)
    elif a.cmd == "monitors":
        if not cfg["monitors"]:
            print("no health checks (add them in the web UI: Monitor tab)")
        for m in cfg["monitors"]:
            ok, ms, detail, days = run_monitor(m)
            print("%-5s %-28s %-5s %-40s %6.0f ms  %s%s" % ("UP" if ok else "DOWN", (m["name"] or "-")[:28], m["type"],
                  m["target"][:40], ms, detail, "  cert %d days" % days if days is not None else ""))
    elif a.cmd == "scan":
        if not a.rules:
            sys.exit("usage: scan IP [common | 22,80,8000-8100]")
        try:
            sc = start_scan(a.rules[0], parse_port_list(a.rules[1] if len(a.rules) > 1 else "common"))
        except ApiError as e:
            sys.exit(str(e))
        while sc["state"] == "running":
            time.sleep(0.3)
        print("%s: %d open of %d scanned" % (sc["target"], len(sc["open"]), sc["total"]))
        for o in sc["open"]:
            print("  %5d/tcp  %-24s %s" % (o["port"], o["service"], o["risk"]))
    elif a.cmd == "update":
        info = check_update()
        if info["error"]:
            sys.exit(info["error"])
        print("installed %s, latest %s (%s)" % (info["current"], info["latest"], info["ref"]))
        for c in info["changes"]:
            print("\n## " + c["title"] + "\n" + c["notes"])
        if not info["available"]:
            print("up to date")
        elif a.rules[:1] != ["check"]:
            try:
                r = run_update()
            except ApiError as e:
                sys.exit(str(e))
            print("mock: %s downloaded and checked, nothing installed" % r["version"] if r.get("mock") else
                  "updating to %s - follow it with: journalctl -fu pve-gateway-update" % r["version"])
    elif a.cmd in ("ui-allow", "ui-host"):
        key = "ui_allow" if a.cmd == "ui-allow" else "allowed_hosts"
        if a.rules:
            clear = [x.lower() for x in a.rules] in (["any"], ["all"], ["none"])
            try:
                cfg[key] = [] if clear else (parse_networks if key == "ui_allow" else parse_hostnames)(a.rules)
            except ApiError as e:
                sys.exit(str(e))
            save_config(cfg)
            if not MOCK and not DRY_RUN and run(["systemctl", "try-restart", "pve-gateway"], check_only=True)[0] == 0:
                print("saved; pve-gateway restarted")
            else:
                print("saved; restart to apply: systemctl restart pve-gateway")
        if key == "ui_allow":
            print("web UI allowed from: " + (", ".join(cfg[key]) + " (and localhost)" if cfg[key] else "anyone"))
        else:
            print("allowed hostnames: " + ", ".join(sorted(own_hostnames()) + cfg[key]) + " (and any IP address)")
    elif a.cmd == "domains":
        if not cfg["domains"]:
            print("no domains (add them in the web UI)")
        fmt = "%-9s %-3s %-40s %-28s %s"
        if cfg["domains"]:
            print(fmt % ("ID", "ON", "DOMAIN", "UPSTREAM", "TLS"))
        for d in cfg["domains"]:
            tls = "http only"
            name = domain_cert(cfg, d)[0]
            if d["tls"] != "none":
                ci = cert_info(cfg, name)
                kind = "wildcard" if d["tls"] == "wildcard" else "LE"
                tls = ("%s: expires in %s days" % (kind, ci.get("days", "?")) if ci["exists"]
                       else "%s: no certificate yet" % kind if name else "wildcard: none covers it")
            print(fmt % (d["id"], "yes" if d["enabled"] else "no", " ".join(_names(d)),
                         "%s://%s:%d" % ("https" if d["upstream_https"] else "http", d["ip"], d["port"]), tls))
        if cfg["wildcards"]:
            print("\nWILDCARD CERTIFICATES")
            for w in cfg["wildcards"]:
                ci = cert_info(cfg, wc_cert_name(w))
                print("  %-9s %-3s *.%-30s %-14s %s" % (w["id"], "yes" if w["enabled"] else "no", w["zone"], w["provider"],
                      "expires in %s days" % ci.get("days", "?") if ci["exists"] else "not issued"))
    elif a.cmd == "cert":
        q = a.rules[0].lower() if a.rules else ""
        w = next((x for x in cfg["wildcards"] if q in (x["id"], x["zone"], "*." + x["zone"], wc_cert_name(x))), None)
        d = next((x for x in cfg["domains"] if q in (x["id"], x["domain"])), None)
        if w:
            key = w["id"]
            issue_wildcard(key)
        elif d:
            key = domain_cert(cfg, d)[1] or d["id"]
            issue_cert(d["id"], force=True)
        else:
            sys.exit("usage: cert DOMAIN|*.ZONE (one of: %s)" % ", ".join(
                [x["domain"] for x in cfg["domains"] if x["tls"] == "letsencrypt"] + ["*." + x["zone"] for x in cfg["wildcards"]]))
        time.sleep(0.1)
        while CERT_JOBS.get(key, {}).get("state") == "pending":
            time.sleep(0.5)
        job = CERT_JOBS.get(key) or {"state": "error", "msg": "disabled, HTTP only, or no wildcard covers it"}
        print("%s: %s" % (job["state"], job["msg"]))
        sys.exit(0 if job["state"] == "ok" else 1)
    elif a.cmd == "status":
        cnt = counters()
        print("hooks: %s   ip_forward: %s   rules: %d (%d enabled)%s" % (
            "active" if DRY_RUN or hooks_active() else "MISSING (run: pve-gateway apply)",
            "on" if ip_forward_on() else "OFF", len(cfg["rules"]), sum(r["enabled"] for r in cfg["rules"]),
            "   [dry-run]" if DRY_RUN else "   [mock]" if MOCK else ""))
        if cfg["rules"]:
            fmt = "%-9s %-3s %-6s %-12s %-31s %-18s %-8s %s"
            print("\n" + fmt % ("ID", "ON", "PROTO", "HOST PORT", "DESTINATION", "SOURCE", "IFACE", "HITS"))
            for r in cfg["rules"]:
                c = cnt.get(r["id"])
                print(fmt % (r["id"], "yes" if r["enabled"] else "no", r["proto"], r["ext_port"],
                             "%s:%s%s" % (r["ip"], r["int_port"] or r["ext_port"], " (masq)" if r["masq"] else ""),
                             r["source"] or "any", r["iface"] or "any",
                             "%d pkts / %d B" % tuple(c) if c else "-") + ("   " + r["name"] if r["name"] else ""))
    elif a.cmd == "test":
        sel = [r for r in cfg["rules"] if (r["id"] in a.rules or r["name"] in a.rules or r["ext_port"] in a.rules)
               or (not a.rules and r["enabled"])]
        dsel = [d for d in cfg["domains"] if (d["id"] in a.rules or set(_names(d)) & set(a.rules))
                or (not a.rules and d["enabled"])]
        if not sel and not dsel:
            sys.exit("nothing matched" + (" (give a rule id, name, host port or domain)" if a.rules else ""))
        failed = False
        for d in dsel:
            steps = test_domain(d)
            failed |= any(s["status"] == "fail" for s in steps)
            print("== %s -> %s:%d ==" % (" ".join(_names(d)), d["ip"], d["port"]))
            print(fmt_steps(steps) + "\n")
        for r in sel:
            steps = test_rule(r)
            failed |= any(s["status"] == "fail" for s in steps)
            print("== %s  %s/%s -> %s:%s ==" % (r["name"] or r["id"], r["proto"], r["ext_port"], r["ip"], r["int_port"] or r["ext_port"]))
            print(fmt_steps(steps) + "\n")
        sys.exit(1 if failed else 0)
    elif a.cmd == "debug":
        sys.stdout.write(report_text(diagnostics()))
    elif a.cmd == "mock":
        if not a.rules:
            sys.exit("usage: --mock mock SCENARIO\n" + "\n".join("  %-15s %s" % kv for kv in MOCK.scenarios().items()))
        try:
            print(MOCK.scenario(a.rules[0]))
        except ValueError as e:
            sys.exit(str(e))
    elif a.cmd == "flush":
        flush_rules()
        print("forwarding rules removed (config kept in %s)" % conf_file())
    elif a.cmd == "passwd":
        user = input("Local username [%s]: " % cfg.get("local_user", "admin")).strip() or cfg.get("local_user", "admin")
        pw = getpass.getpass("New password (empty = switch back to Proxmox login): ")
        if pw and pw != getpass.getpass("Repeat: "):
            sys.exit("passwords do not match")
        cfg["local_user"], cfg["pass_hash"] = user, hash_password(pw) if pw else ""
        save_config(cfg)
        print("saved; restart the service: systemctl restart pve-gateway")
    else:
        serve(cfg)


if __name__ == "__main__":
    main()
