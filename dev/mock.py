"""
Simulated Proxmox host for local development (macOS, or anywhere without iptables / root).

Loaded only with `pve-gateway.py --mock`; never installed on the real host.

Fakes: iptables, iptables-restore, iptables-save, ip, ping, ss, conntrack,
pve-firewall, pvesh, qm, pct, lxc-info, plus net.ipv4.ip_forward and TCP probes.
The fake "kernel" state lives in <config-dir>/mock-state.json, so the web UI
and CLI commands (status / test / debug / flush / mock ...) all see the same thing.
"""
import base64
import hashlib
import urllib.parse
import json
import os
import random
import re
import threading
import time

HOST_IP, BRIDGE_IP, PUBLIC_IP = "192.168.1.50", "10.10.10.1", "203.0.113.10"

# ports = what the guest listens on; agent = QEMU guest agent installed
GUESTS = [
    {"vmid": 100, "name": "web", "type": "qemu", "status": "running", "ip": "10.10.10.10", "ports": [80, 443], "agent": True},
    {"vmid": 101, "name": "db", "type": "lxc", "status": "running", "ip": "10.10.10.11", "ports": [22, 5432]},
    {"vmid": 102, "name": "game", "type": "qemu", "status": "stopped", "ip": "10.10.10.12", "ports": [27015], "agent": True},
    {"vmid": 103, "name": "nextcloud", "type": "lxc", "status": "running", "ip": "10.10.10.13", "ports": [80]},
    {"vmid": 104, "name": "win11", "type": "qemu", "status": "running", "ip": "10.10.10.14", "ports": [3389], "agent": False,
     "no_ping": True},
    {"vmid": 105, "name": "office-gw", "type": "qemu", "status": "running", "ip": "192.168.50.20", "ports": [443], "agent": True},
    # no guest agent and never talks to the host (gateway is another router): found by the ARP sweep
    {"vmid": 106, "name": "quiet-vm", "type": "qemu", "status": "running", "ip": "10.10.10.16", "ports": [22], "agent": False,
     "no_arp": True},
    # no guest agent, doesn't answer ARP, but cloud-init sets a static IP
    {"vmid": 107, "name": "ci-node", "type": "qemu", "status": "running", "ip": "10.10.10.17", "ports": [22, 9000],
     "agent": False, "no_arp": True, "silent": True, "cloudinit": True},
]


def _mac(vmid):
    return "bc:24:11:00:%02x:%02x" % (vmid // 256, vmid % 256)

SCENARIOS = {
    "reset": "fresh host: empty iptables, ip_forward on (rules are re-applied by the running server)",
    "unhook": "delete our jump rules, like `iptables -F PREROUTING` would (watchdog repairs it)",
    "ip-forward-off": "set net.ipv4.ip_forward = 0",
    "forward-drop": "set FORWARD policy to DROP",
    "pvefw-first": "move pve-firewall's jump above ours in FORWARD",
    "foreign-dnat": "insert someone else's DNAT rule at the top of PREROUTING",
    "traffic": "simulate a burst of incoming connections on all rules",
    "nginx-stopped": "stop nginx (domains stop answering)",
    "nginx-test-fails": "make the next `nginx -t` fail (shows the automatic rollback)",
    "cert-expiring": "make all certificates expire in 5 days",
    "foreign-site": "install another panel's nginx site bound to the host IP that redirects everything to HTTPS",
    "le-blocked": "Let's Encrypt can't reach port 80 (provider firewall) although it works from the host itself",
    "f2b-ban": "fail2ban banned Let's Encrypt's validation servers on ports 80/443 (after failed challenges)",
    "pvefw-no-http": "Proxmox firewall enabled without a rule accepting HTTP/HTTPS",
    "no-fail2ban": "fail2ban is not installed (use the Install button)",
    "no-wireguard": "wireguard-tools is not installed (use the Install button)",
    "dnat-80": "another tool's iptables rule forwards ports 80/443 to a firewall VM instead of the host's nginx",
}

PVEFW_OK = """[OPTIONS]
enable: 1

[RULES]
IN ACCEPT -p tcp -dport 22 -log nolog # ssh
IN ACCEPT -p tcp -dport 8006 -log nolog # web UI
IN HTTP(ACCEPT) -log nolog
IN HTTPS(ACCEPT) -log nolog
"""

# rules seeded into a fresh ./.dev config, chosen to show every test outcome
SAMPLE_RULES = [
    {"name": "web", "proto": "tcp", "ext_port": "8080", "ip": "10.10.10.10", "int_port": "80"},
    {"name": "db ssh", "proto": "tcp", "ext_port": "2222", "ip": "10.10.10.11", "int_port": "22", "source": "203.0.113.0/24"},
    {"name": "game", "proto": "both", "ext_port": "27015-27020", "ip": "10.10.10.12"},                # guest stopped
    {"name": "nextcloud tls", "proto": "tcp", "ext_port": "8443", "ip": "10.10.10.13", "int_port": "443"},  # refused
    {"name": "rdp", "proto": "tcp", "ext_port": "3389", "ip": "10.10.10.14", "iface": "vmbr0"},    # no ping, tcp ok
    {"name": "office", "proto": "tcp", "ext_port": "9443", "ip": "192.168.50.20", "int_port": "443", "masq": True},
    {"name": "old test", "proto": "udp", "ext_port": "5000", "ip": "10.10.10.10", "enabled": False},
]

# domains seeded into a fresh ./.dev config
SAMPLE_DOMAINS = [
    {"domain": "cloud.example.com", "ip": "10.10.10.13", "port": 80, "tls": "letsencrypt", "max_body": "10g",
     "headers": True},                                          # cert ok
    {"domain": "app.example.com", "aliases": "www.app.example.com", "ip": "10.10.10.10", "port": 80, "tls": "none",
     "alias_redirect": True},                                   # www -> 301 to app; has a stray AAAA record
    {"domain": "broken.invalid", "ip": "10.10.10.11", "port": 8080, "tls": "letsencrypt"},  # no DNS, nothing on 8080
    {"domain": "status.example.com", "ip": "10.10.10.10", "port": 80, "tls": "wildcard"},  # uses *.example.com
    {"domain": "shop.example.com", "ip": "10.10.10.10", "port": 443, "upstream_https": True, "tls": "wildcard",
     "cloudflare": True, "headers": True, "hsts": True},       # behind the Cloudflare proxy
]

# wildcard certificates seeded into a fresh ./.dev config (token "bad" makes the mock DNS API reject it)
SAMPLE_WILDCARDS = [
    {"zone": "example.com", "provider": "cloudflare", "credentials": {"dns_cloudflare_api_token": "mock-token"}},
]

# health checks seeded into a fresh ./.dev config
SAMPLE_MONITORS = [
    {"name": "cloud", "type": "http", "target": "https://cloud.example.com/", "interval": 60},
    {"name": "status page", "type": "http", "target": "https://status.example.com/", "interval": 60},
    {"name": "postgres", "type": "tcp", "target": "10.10.10.11:5432", "interval": 60},
    {"name": "game server", "type": "tcp", "target": "10.10.10.12:27015", "interval": 60},   # VM stopped -> down
    {"name": "broken", "type": "http", "target": "http://broken.invalid/", "interval": 120},  # no DNS -> down
    {"name": "office gateway", "type": "ping", "target": "192.168.50.20", "interval": 60},
]

# certbot DNS plugins "installed" on the mock host (others report as missing)
DNS_PLUGINS = ["dns-cloudflare", "dns-digitalocean", "dns-rfc2136"]

TARGETS = {"ACCEPT", "DROP", "REJECT", "RETURN", "DNAT", "SNAT", "MASQUERADE", "LOG"}

SS_LINES = [
    ("tcp", "LISTEN", "0.0.0.0:22", 'users:(("sshd",pid=1021,fd=3))'),
    ("tcp", "LISTEN", "0.0.0.0:111", 'users:(("rpcbind",pid=812,fd=4))'),
    ("tcp", "LISTEN", "127.0.0.1:25", 'users:(("master",pid=1290,fd=13))'),
    ("tcp", "LISTEN", "127.0.0.1:85", 'users:(("pvedaemon",pid=1410,fd=6))'),
    ("tcp", "LISTEN", "*:3128", 'users:(("spiceproxy",pid=1502,fd=6))'),
    ("tcp", "LISTEN", "*:8006", 'users:(("pveproxy",pid=1488,fd=6))'),
    ("tcp", "LISTEN", "0.0.0.0:8099", 'users:(("python3",pid=2211,fd=3))'),
    ("tcp", "LISTEN", "0.0.0.0:9100", 'users:(("node_exporter",pid=990,fd=3))'),
    ("udp", "UNCONN", "0.0.0.0:111", 'users:(("rpcbind",pid=812,fd=5))'),
    ("udp", "UNCONN", "%s:5405" % HOST_IP, 'users:(("corosync",pid=1150,fd=27))'),
]


def default_state():
    return {
        "ip_forward": True,
        "tables": {
            "nat": {
                "policy": {"PREROUTING": "ACCEPT", "INPUT": "ACCEPT", "OUTPUT": "ACCEPT", "POSTROUTING": "ACCEPT"},
                "chains": {"PREROUTING": [], "INPUT": [], "OUTPUT": [],
                           "POSTROUTING": ["-s 10.10.10.0/24 -o vmbr0 -j MASQUERADE"]},
            },
            "filter6": {
                "policy": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"},
                "chains": {"INPUT": [], "FORWARD": [], "OUTPUT": []},
            },
            "filter": {
                "policy": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"},
                "chains": {"INPUT": ["-j PVEFW-INPUT"], "FORWARD": ["-j PVEFW-FORWARD"], "OUTPUT": ["-j PVEFW-OUTPUT"],
                           "PVEFW-INPUT": [], "PVEFW-OUTPUT": [],
                           "PVEFW-FORWARD": ["-m conntrack --ctstate INVALID -j DROP",
                                             "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]},
            },
        },
        "counters": {},  # "table|chain|rule" -> [packets, bytes]
        "pvefw": {"options": {"enable": 0, "policy_in": "DROP"}, "node_enable": 1,
                  "rules": [{"type": "in", "action": "ACCEPT", "proto": "tcp", "dport": "2222", "source": "198.51.100.0/24",
                             "comment": "admin jump host", "enable": 1},
                            {"type": "in", "action": "DROP", "proto": "tcp", "dport": "3306", "comment": "no db from outside",
                             "enable": 1}]},
        "nginx_active": True,
        "wg": {"installed": True, "up": []},
        "f2b": {"installed": True, "jails": {"sshd": {"failed": 3, "failed_total": 412, "banned_total": 57,
                                                       "ips": ["198.51.100.23", "203.0.113.99", "192.0.2.150"] +
                                                              ["198.51.100.%d" % i for i in (41, 42, 57, 77, 120, 133, 201)] +
                                                              ["203.0.113.%d" % i for i in (5, 18, 64, 200)] +
                                                              ["2001:db8:7::%x" % i for i in (16, 80)]},
                                              "nginx-botsearch": {"failed": 0, "failed_total": 31, "banned_total": 4,
                                                                  "ips": ["66.133.109.36"]}}},
        "nginx_test_fail": False,
        "issued": {"cloud.example.com": {"names": ["cloud.example.com"], "expires": time.time() + 61 * 86400},
                   "wildcard.example.com": {"names": ["example.com", "*.example.com"], "expires": time.time() + 75 * 86400}},
    }


def _read_text(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _guest(ip):
    return next((g for g in GUESTS if g["ip"] == ip), None)


def _opt(rule, flag):
    m = re.search(r"(?:^| )%s (\S+)" % re.escape(flag), rule)
    return m.group(1) if m else None


class Mock:
    def __init__(self, conf_dir, node):
        self.path = os.path.join(conf_dir, "mock-state.json")
        self.root = os.path.join(conf_dir, "mock-fs")
        fw = os.path.join(self.root, "etc/pve/firewall/cluster.fw")
        if not os.path.exists(fw):
            os.makedirs(os.path.dirname(fw))
            with open(fw, "w") as f:
                f.write(PVEFW_OK)
        apt = os.path.join(self.root, "etc/apt/sources.list.d")
        if not os.path.isdir(apt):  # fresh PVE without subscription: enterprise repo still enabled
            os.makedirs(apt)
            with open(os.path.join(apt, "pve-enterprise.sources"), "w") as f:
                f.write("Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: bookworm\n"
                        "Components: pve-enterprise\nSigned-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n")
        self.node = node
        self.lock = threading.RLock()
        os.makedirs(conf_dir, exist_ok=True)
        if not os.path.exists(self.path):
            self._save(default_state())

    # ------------------------------------------------------------------ state
    def _load(self):
        try:
            with open(self.path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return default_state()

    def _save(self, st):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f, indent=1)
        os.replace(tmp, self.path)

    @property
    def ip_forward(self):
        return self._load()["ip_forward"]

    @ip_forward.setter
    def ip_forward(self, value):
        with self.lock:
            st = self._load()
            st["ip_forward"] = bool(value)
            self._save(st)

    def arp_sweep(self):
        """Guests that only answer ARP when asked appear in `ip neigh` after a sweep."""
        with self.lock:
            st = self._load()
            st["swept"] = True
            self._save(st)
        return True

    def remote_file(self, path):
        """Pretend GitHub: the local checkout, one minor version ahead, with a changelog entry for it."""
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, path), "rb") as f:
            data = f.read()
        if path == "pve-gateway.py":
            m = re.search(rb'^VERSION = "(\d+)\.(\d+)\.(\d+)"', data, re.M)
            if m:
                data = data.replace(m.group(0), b'VERSION = "%d.%d.0"' % (int(m.group(1)), int(m.group(2)) + 1), 1)
        elif path == "CHANGELOG.md":
            m = re.search(rb"^## (\d+)\.(\d+)\.", data, re.M)
            nxt = b"%d.%d.0" % (int(m.group(1)), int(m.group(2)) + 1) if m else b"9.9.0"
            data = data.replace(b"\n## ", b"\n## " + nxt + b" - upcoming\n- Release notes of the new version are listed here before you update.\n\n## ", 1)
        return data

    def path_for(self, real_path):
        """Map a real host path (e.g. /etc/nginx/conf.d/x.conf) into the mock filesystem under .dev."""
        return os.path.join(self.root, real_path.lstrip("/"))

    def sample_wildcards(self):
        return [dict(w) for w in SAMPLE_WILDCARDS]

    def sample_monitors(self):
        return [dict(m) for m in SAMPLE_MONITORS]

    def monitor_http(self, m):
        """HTTP check through the simulated DNS + nginx (or straight to a guest IP)."""
        u = urllib.parse.urlsplit(m["target"])
        tls, host = u.scheme == "https", u.hostname
        time.sleep(0.02)
        if self.resolve(host) == [] and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            return False, 3.0, "<urlopen error [Errno -2] Name or service not known>", None
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            res, ms = self.tcp_probe(host, u.port or (443 if tls else 80))
            return res == "ok", ms, "HTTP 200" if res == "ok" else res, None
        st, hdr, _ = self.http_get(HOST_IP, 443 if tls else 80, host, u.path or "/", tls)
        lo, _, hi = m["expect"].partition("-")
        ok = bool(st) and int(lo) <= st <= int(hi or lo)
        days = None
        if tls:
            c = self._load()["issued"].get(self._served_name(host) or "")
            days = int((c["expires"] - time.time()) // 86400) if c else None
        return ok, random.uniform(8, 60), ("HTTP %d" % st if st else "connection refused") + \
            ("" if ok or not st else " (expected %s)" % m["expect"]), days

    def port_open(self, ip, port):
        g = _guest(ip)
        if g:
            return g["status"] == "running" and port in g["ports"] + ([22] if g["type"] == "lxc" else [])
        if ip in (HOST_IP, BRIDGE_IP, "127.0.0.1"):
            return port in [int(a.rsplit(":", 1)[1]) for p_, s_, a, u_ in SS_LINES if p_ == "tcp"] + \
                ([80, 443] if self._load().get("nginx_active", True) else [])
        return False

    def sample_domains(self):
        return [dict(d) for d in SAMPLE_DOMAINS]

    def resolve(self, name):
        if name.endswith(".invalid") or name.startswith("nodns."):
            return []
        if name == "shop.example.com":
            return ["104.21.32.7", "172.67.150.2"]  # Cloudflare proxy addresses
        if name == "app.example.com":
            return [PUBLIC_IP, "2001:db8:ffff::10"]  # AAAA left over from an old server
        return [PUBLIC_IP]

    FOREIGN_SITE = """# another panel installed on the same host (e.g. its own setup script)
server {
    listen %(ip)s:80 default_server;
    server_name admin.example.net _;
    return 301 https://$host$request_uri;
}
server {
    listen %(ip)s:443 ssl default_server;
    server_name admin.example.net;
    ssl_certificate /etc/letsencrypt/live/admin.example.net/fullchain.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;
    return 403;
}
"""

    def _server_blocks(self):
        """[(file, listens, names, body)] for every server block nginx would load (ours + sites-enabled)."""
        files = [(self.path_for("/etc/nginx/conf.d"), "conf.d"), (self.path_for("/etc/nginx/sites-enabled"), "sites-enabled")]
        out = []
        for d, _ in files:
            for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
                with open(os.path.join(d, f)) as fh:
                    text = fh.read()
                for block in re.split(r"(?m)^server \{", text)[1:]:
                    listens = [l.split()[0] for l in re.findall(r"listen ([^;]+);", block)]
                    names = " ".join(re.findall(r"server_name ([^;]+);", block)).split()
                    out.append(("/etc/nginx/%s/%s" % (os.path.basename(d), f), listens, names, block))
        return out

    def http_get(self, ip, port, host, path, tls):
        """Answer like nginx: servers bound to exactly ip:port win over wildcard listens, then server_name decides."""
        if not self._load().get("nginx_active", True):
            return 0, {}, b"[Errno 111] Connection refused"
        def binds(l):
            a, _, p = l.rpartition(":") if ":" in l else ("", "", l)
            return int(p) == port, a in ("", "[::]", "0.0.0.0") or a == ip
        blocks = [b for b in self._server_blocks() if any(all(binds(l)) for l in b[1])]
        exact = [b for b in blocks if any(binds(l)[0] and l.rpartition(":")[0] == ip for l in b[1])]
        cands = exact or blocks
        if not cands:
            return 0, {}, b"[Errno 111] Connection refused"
        block = next((b for b in cands if host in b[2]), None) or \
            next((b for b in cands if any("default_server" in x for x in re.findall(r"listen ([^;]+);", b[3]))), cands[0])
        body = block[3]
        srv = {"server": "nginx/1.26.3"}
        acme = re.search(r"location \^~ /\.well-known/acme-challenge/ \{\s*root (\S+);", body)
        if acme and path.startswith("/.well-known/acme-challenge/"):
            f = os.path.join(self.path_for(acme.group(1)), path.lstrip("/"))
            if os.path.isfile(f):
                with open(f, "rb") as fh:
                    return 200, srv, fh.read()
            return 404, srv, b"<html>404 Not Found</html>"
        ret = re.search(r"return 301 (\S+);", body)
        if ret:
            return 301, dict(srv, location=ret.group(1).replace("$host", host).replace("$request_uri", path)), b""
        if re.search(r"return 403;", body):
            return 403, srv, b"<html>403 Forbidden</html>"
        m = re.search(r"proxy_pass https?://([\d.]+):(\d+);", body)
        if not m:
            return 404, srv, b"<html>404 Not Found</html>"
        res, _ = self.tcp_probe(m.group(1), int(m.group(2)))
        return (200, srv, b"guest says hello") if res == "ok" else (502, srv, b"<html>502 Bad Gateway</html>")

    def _nginx_conf(self):
        d = self.path_for("/etc/nginx/conf.d")
        out = ""
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if f.endswith(".conf"):
                with open(os.path.join(d, f)) as fh:
                    out += fh.read()
        return out

    def sample_rules(self):
        return [dict(r) for r in SAMPLE_RULES]

    def scenarios(self):
        return dict(SCENARIOS)

    def ifaces(self):
        return ["enp3s0", "vmbr0", "vmbr1"]

    def tcp_probe(self, ip, port):
        """('ok'|'refused'|'timeout', ms) for a TCP connect from the host."""
        g = _guest(ip)
        if not g or g["status"] != "running":
            return "timeout", 3000
        return ("ok" if port in g["ports"] else "refused"), random.randint(1, 6)

    def scenario(self, name):
        if name not in SCENARIOS:
            raise ValueError("unknown scenario '%s' (available: %s)" % (name, ", ".join(SCENARIOS)))
        with self.lock:
            st = default_state() if name == "reset" else self._load()
            if name == "reset":
                foreign = os.path.join(self.path_for("/etc/nginx/sites-enabled"), "other-panel")
                if os.path.exists(foreign):
                    os.remove(foreign)
                with open(self.path_for("/etc/pve/firewall/cluster.fw"), "w") as f:
                    f.write(PVEFW_OK)
            nat, flt = st["tables"]["nat"]["chains"], st["tables"]["filter"]["chains"]
            if name == "unhook":
                for chains in (nat, flt):
                    for c in ("PREROUTING", "POSTROUTING", "FORWARD"):
                        if c in chains:
                            chains[c] = [r for r in chains[c] if not r.startswith("-j PVEGW_")]
            elif name == "ip-forward-off":
                st["ip_forward"] = False
            elif name == "forward-drop":
                st["tables"]["filter"]["policy"]["FORWARD"] = "DROP"
            elif name == "pvefw-first":
                flt["FORWARD"] = ["-j PVEFW-FORWARD"] + [r for r in flt["FORWARD"] if r != "-j PVEFW-FORWARD"]
            elif name == "foreign-dnat":
                nat["PREROUTING"].insert(0, "-p tcp -m tcp --dport 8443 -j DNAT --to-destination 10.10.10.99:443")
            elif name == "traffic":
                self._bump(st, burst=True)
            elif name == "nginx-stopped":
                st["nginx_active"] = False
            elif name == "nginx-test-fails":
                st["nginx_test_fail"] = True
            elif name == "foreign-site":
                d = self.path_for("/etc/nginx/sites-enabled")
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, "other-panel"), "w") as f:
                    f.write(self.FOREIGN_SITE % {"ip": HOST_IP})
            elif name == "le-blocked":
                st["le_blocked"] = True
            elif name == "f2b-ban":
                st["le_blocked"] = True
                flt["f2b-nginx-botsearch"] = ["-s 66.133.109.36/32 -j REJECT --reject-with icmp-port-unreachable",
                                              "-s 64.78.149.164/32 -j REJECT --reject-with icmp-port-unreachable",
                                              "-j RETURN"]
                flt["INPUT"].insert(0, "-p tcp -m multiport --dports 80,443 -j f2b-nginx-botsearch")
            elif name == "dnat-80":
                nat["PREROUTING"].insert(0, "-d %s/32 -p tcp -m multiport --dports 80,443 -j DNAT --to-destination 10.10.10.254"
                                         % HOST_IP)
            elif name == "no-wireguard":
                st["wg"] = {"installed": False, "up": []}
            elif name == "no-fail2ban":
                st["f2b"] = {"installed": False, "jails": {}}
            elif name == "pvefw-no-http":
                st["pvefw"]["options"]["enable"] = 1
                with open(self.path_for("/etc/pve/firewall/cluster.fw"), "w") as f:
                    f.write(PVEFW_OK.replace("IN HTTP(ACCEPT) -log nolog\n", "").replace("IN HTTPS(ACCEPT) -log nolog\n", ""))
            elif name == "cert-expiring":
                for c in st["issued"].values():
                    c["expires"] = time.time() + 5 * 86400 + 3600
            self._save(st)
        return SCENARIOS[name]

    # ------------------------------------------------------------------ dispatch
    def exec(self, cmd, data=None):
        cmd = list(cmd)
        if cmd[:1] == ["timeout"]:
            cmd = cmd[2:]
        fn = getattr(self, "c_" + cmd[0].replace("-", "_"), None)
        if not fn:
            return 127, "(mock) command not found: %s" % cmd[0]
        with self.lock:
            st = self._load()
            rc, out, changed = fn(st, cmd[1:], data)
            if changed:
                self._save(st)
        time.sleep(0.005)
        return rc, out

    # ------------------------------------------------------------------ iptables
    def _hooked(self, st, table, chain, target):
        return ("-j " + target) in st["tables"][table]["chains"].get(chain, [])

    def _bump(self, st, burst=False):
        """Fake incoming traffic on our DNAT rules (only if they'd really be hit)."""
        if not self._hooked(st, "nat", "PREROUTING", "PVEGW_PRE"):
            return
        for rule in st["tables"]["nat"]["chains"].get("PVEGW_PRE", []):
            to = (_opt(rule, "--to-destination") or "").split(":")[0]
            g = _guest(to)
            if not g or g["status"] != "running" or (not burst and random.random() < 0.5):
                continue
            pk = random.randint(20, 80) if burst else random.randint(1, 4)
            c = st["counters"].setdefault("nat|PVEGW_PRE|" + rule, [0, 0])
            c[0] += pk
            c[1] += pk * random.randint(52, 1400)

    def c_iptables(self, st, a, data):
        if a == ["--version"]:
            return 0, "iptables v1.8.9 (nf_tables)  [mock]", False
        table = "filter"
        if a[:1] == ["-t"]:
            table, a = a[1], a[2:]
        if table not in st["tables"]:
            return 3, "iptables v1.8.9 (nf_tables): table '%s' does not exist" % table, False
        t = st["tables"][table]
        chains = t["chains"]
        op, chain = a[0], (a[1] if len(a) > 1 and not a[1].startswith("-") else None)
        if chain and chain not in chains:
            return 1, "iptables: No chain/target/match by that name.", False

        if op == "-S":
            out = []
            for c in ([chain] if chain else chains):
                out.append("-P %s %s" % (c, t["policy"][c]) if c in t["policy"] else "-N " + c)
            for c in ([chain] if chain else chains):
                out += ["-A %s %s" % (c, r) for r in chains[c]]
            return 0, "\n".join(out), False
        if op == "-L":
            return 0, self._list(st, table, chain), False
        if op in ("-C", "-D", "-I"):
            rest = a[2:]
            pos = 1
            if op == "-I" and rest and rest[0].isdigit():
                pos, rest = int(rest[0]), rest[1:]
            rule = " ".join(rest)
            target = _opt(rule, "-j")
            if target not in TARGETS and target not in chains:
                return 2, "iptables v1.8.9 (nf_tables): Chain '%s' does not exist" % target, False
            if op == "-I":
                chains[chain].insert(pos - 1, rule)
                return 0, "", True
            if rule not in chains[chain]:
                return 1, "iptables: Bad rule (does a matching rule exist in that chain?).", False
            if op == "-D":
                chains[chain].remove(rule)
                return 0, "", True
            return 0, "", False
        if op == "-F":
            chains[chain] = []
            st["counters"] = {k: v for k, v in st["counters"].items() if not k.startswith("%s|%s|" % (table, chain))}
            return 0, "", True
        if op == "-X":
            if chain in t["policy"]:
                return 1, "iptables: can't delete built-in chain", False
            if chains[chain] or any(("-j " + chain) in r for rs in chains.values() for r in rs):
                return 1, "iptables v1.8.9 (nf_tables): CHAIN_USER_DEL failed (Device or resource busy): chain %s" % chain, False
            del chains[chain]
            return 0, "", True
        return 2, "(mock) unsupported iptables call: %s" % " ".join(a), False

    def _list(self, st, table, chain):
        t = st["tables"][table]
        if chain in t["policy"]:
            head = "Chain %s (policy %s 0 packets, 0 bytes)" % (chain, t["policy"][chain])
        else:
            refs = sum(r.endswith("-j " + chain) for rs in t["chains"].values() for r in rs)
            head = "Chain %s (%d references)" % (chain, refs)
        out = [head, "num      pkts      bytes target         prot opt in     out     source               destination"]
        for i, r in enumerate(t["chains"][chain], 1):
            pk, by = st["counters"].get("%s|%s|%s" % (table, chain, r), [0, 0])
            extra = re.sub(r"(^| )(-[pjiosd]) \S+", "", r).strip()
            out.append("%-4d %9d %10d %-14s %-4s --  %-6s %-7s %-20s %-20s %s" % (
                i, pk, by, _opt(r, "-j"), _opt(r, "-p") or "all", _opt(r, "-i") or "*", _opt(r, "-o") or "*",
                _opt(r, "-s") or "0.0.0.0/0", _opt(r, "-d") or "0.0.0.0/0", extra))
        return "\n".join(out)

    def c_iptables_save(self, st, a, data):
        counts = "-c" in a
        tables = [a[a.index("-t") + 1]] if "-t" in a else list(st["tables"])
        if counts:
            self._bump(st)
        out = ["# Generated by iptables-save v1.8.9 (mock) on %s" % time.ctime()]
        for tn in tables:
            t = st["tables"][tn]
            out.append("*" + tn)
            out += [":%s %s [0:0]" % (c, t["policy"].get(c, "-")) for c in t["chains"]]
            for c, rules in t["chains"].items():
                for r in rules:
                    pk, by = st["counters"].get("%s|%s|%s" % (tn, c, r), [0, 0])
                    out.append(("[%d:%d] " % (pk, by) if counts else "") + "-A %s %s" % (c, r))
            out.append("COMMIT")
        return 0, "\n".join(out), counts

    def c_iptables_restore(self, st, a, data):
        new = json.loads(json.dumps(st))
        table = None
        for n, line in enumerate((data or "").splitlines(), 1):
            line = line.strip()
            fail = (1, "iptables-restore v1.8.9 (nf_tables): line %d failed: %s" % (n, line), False)
            if not line or line.startswith("#"):
                continue
            if line.startswith("*"):
                table = line[1:]
                if table not in new["tables"]:
                    return fail
            elif line == "COMMIT":
                table = None
            elif table is None:
                return fail
            elif line.startswith(":"):
                name = line[1:].split()[0]
                tb = new["tables"][table]
                tb["chains"][name] = []  # declared chains are flushed, even with --noflush
                new["counters"] = {k: v for k, v in new["counters"].items() if not k.startswith("%s|%s|" % (table, name))}
            else:
                m = re.match(r"^-A (\S+) (.+)$", line)
                chains = new["tables"][table]["chains"]
                if not m or m.group(1) not in chains:
                    return fail
                target = _opt(m.group(2), "-j")
                if target not in TARGETS and target not in chains:
                    return fail
                if line.count('"') % 2:
                    return fail
                chains[m.group(1)].append(m.group(2))
        if table is not None:
            return 1, "iptables-restore: COMMIT expected at line %d" % (n + 1), False
        st.clear()
        st.update(new)
        return 0, "", True

    # ------------------------------------------------------------------ network tools
    def c_pvesubscription(self, st, a, data):
        return 0, "message: There is no subscription key\nserverid: 0123456789ABCDEF0123456789ABCDEF\nstatus: notfound", False

    def c_ip(self, st, a, data):
        if "-6" in a and "addr" in a:
            return 0, "\n".join(["lo               UNKNOWN        ::1/128",
                                 "vmbr0            UP             fe80::be24:11ff:fe00:1/64",
                                 "vmbr1            UP             fe80::be24:11ff:fe00:2/64"]), False
        if "neigh" in a:
            out = ["192.168.1.1 dev vmbr0 lladdr 00:1a:2b:3c:4d:5e REACHABLE"]
            for g in GUESTS:
                visible = not g.get("no_arp") or (st.get("swept") and not g.get("silent"))
                if g["status"] == "running" and visible and g["ip"].startswith("10.10.10."):
                    out.append("%s dev vmbr1 lladdr %s %s" % (g["ip"], _mac(g["vmid"]), random.choice(["REACHABLE", "STALE"])))
            out.append("10.10.10.99 dev vmbr1 FAILED")
            return 0, "\n".join(out), False
        if a[:2] == ["route", "get"]:
            ip = a[2]
            if ip.startswith("10.10.10."):
                return 0, "%s dev vmbr1 src %s uid 0 \n    cache " % (ip, BRIDGE_IP), False
            if ip.startswith("192.168.50."):
                return 0, "%s via 10.10.10.254 dev vmbr1 src %s uid 0 \n    cache " % (ip, BRIDGE_IP), False
            if ip.startswith("192.168.1."):
                return 0, "%s dev vmbr0 src %s uid 0 \n    cache " % (ip, HOST_IP), False
            return 0, "%s via 192.168.1.1 dev vmbr0 src %s uid 0 \n    cache " % (ip, HOST_IP), False
        if "addr" in a:
            return 0, "\n".join([
                "lo               UNKNOWN        127.0.0.1/8",
                "enp3s0           UP             ",
                "vmbr0            UP             %s/24" % HOST_IP,
                "vmbr1            UP             %s/24" % BRIDGE_IP,
                "tap100i0         UNKNOWN        ",
                "veth101i0@if2    UP             ",
            ]), False
        if "route" in a:
            return 0, "\n".join([
                "default via 192.168.1.1 dev vmbr0 proto kernel onlink",
                "10.10.10.0/24 dev vmbr1 proto kernel scope link src %s" % BRIDGE_IP,
                "192.168.1.0/24 dev vmbr0 proto kernel scope link src %s" % HOST_IP,
                "192.168.50.0/24 via 10.10.10.254 dev vmbr1",
            ]), False
        return 1, "(mock) unsupported ip call", False

    def c_ping(self, st, a, data):
        ip = a[-1]
        g = _guest(ip)
        if g and g["status"] == "running" and not g.get("no_ping"):
            ms = random.uniform(0.15, 0.6)
            return 0, ("PING {0} ({0}) 56(84) bytes of data.\n64 bytes from {0}: icmp_seq=1 ttl=64 time={1:.3f} ms\n\n"
                       "--- {0} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms").format(ip, ms), False
        return 1, ("PING {0} ({0}) 56(84) bytes of data.\n\n--- {0} ping statistics ---\n"
                   "1 packets transmitted, 0 received, 100% packet loss, time 0ms").format(ip), False

    def c_ss(self, st, a, data):
        procs = "p" in (a[0] if a else "")
        lines = list(SS_LINES)
        if st.get("nginx_active", True):
            lines += [("tcp", "LISTEN", "0.0.0.0:80", 'users:(("nginx",pid=3010,fd=6))'),
                      ("tcp", "LISTEN", "0.0.0.0:443", 'users:(("nginx",pid=3010,fd=8))')]
        return 0, "\n".join("%-5s %-6s 0      4096  %21s %21s %s" % (
            p, s, addr, "*:*" if addr.startswith("*") else "0.0.0.0:*", u if procs else "") for p, s, addr, u in lines), False

    # ------------------------------------------------------------------ nginx / certbot / systemd
    def c_nginx(self, st, a, data):
        if a == ["-v"]:
            return 0, "nginx version: nginx/1.22.1", False
        if a == ["-T"]:
            out = ["nginx: the configuration file /etc/nginx/nginx.conf syntax is ok",
                   "# configuration file /etc/nginx/nginx.conf:",
                   "http {\n    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;\n}"]
            for d in ("conf.d", "sites-enabled"):
                p = self.path_for("/etc/nginx/" + d)
                for f in sorted(os.listdir(p)) if os.path.isdir(p) else []:
                    with open(os.path.join(p, f)) as fh:
                        out += ["# configuration file /etc/nginx/%s/%s:" % (d, f), fh.read()]
            return 0, "\n".join(out), False
        if a == ["-t"]:
            conf = self._nginx_conf()
            if st.get("nginx_test_fail"):
                st["nginx_test_fail"] = False
                return 1, ('nginx: [emerg] unknown directive "proxy_pas" in /etc/nginx/conf.d/pve-gateway.conf:42\n'
                           "nginx: configuration file /etc/nginx/nginx.conf test failed  [mock: nginx-test-fails]"), True
            if conf.count("{") != conf.count("}"):
                return 1, "nginx: [emerg] unexpected end of file, expecting \"}\" in /etc/nginx/conf.d/pve-gateway.conf", False
            for path in re.findall(r"ssl_certificate (\S+);", conf):
                if self._cert_name(path) not in st["issued"]:
                    return 1, ('nginx: [emerg] cannot load certificate "%s": BIO_new_file() failed\n'
                               "nginx: configuration file /etc/nginx/nginx.conf test failed" % path), False
            return 0, ("nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
                       "nginx: configuration file /etc/nginx/nginx.conf test is successful"), False
        return 1, "(mock) unsupported nginx call", False

    def _dns01(self, a, names):
        """Simulate certbot's DNS plugin talking to the provider API. Returns error text or None."""
        auth = a[a.index("--authenticator") + 1]
        if auth not in DNS_PLUGINS:
            return "Could not choose appropriate plugin: The requested %s plugin does not appear to be installed" % auth
        cred = a[a.index("--%s-credentials" % auth) + 1]
        try:
            with open(cred) as f:
                text = f.read()
        except OSError:
            return "Error: File not found: %s" % cred
        if re.search(r"=\s*bad\s*$", text, re.M):
            return ("Encountered exception during recovery: certbot.errors.PluginError: Error determining zone_id: "
                    "6003 Invalid request headers. Please confirm that you have supplied valid Cloudflare API credentials. "
                    "(Did you copy your entire API token/key? To use Cloudflare tokens, you'll need the python package "
                    "cloudflare>=2.3.1. This certbot is running cloudflare 2.11.1)")
        zone = names[0]
        if zone.endswith(".invalid"):
            return ("Encountered exception during recovery: certbot.errors.PluginError: Unable to determine zone identifier "
                    "for %s using zone names: ['%s', 'invalid']" % (zone, zone))
        time.sleep(1)  # "Waiting 10 seconds for DNS changes to propagate"
        return None

    def _le_log(self, domain, kind, detail):
        """A letsencrypt.log like certbot writes it (incl. lines that must be filtered out of the Debug view)."""
        p = self.path_for("/var/log/letsencrypt/letsencrypt.log")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        t = time.strftime("%Y-%m-%d %H:%M:%S,000")
        with open(p, "w") as f:
            f.write("\n".join([
                "%s:DEBUG:certbot._internal.main:certbot version: 4.0.0" % t,
                "%s:DEBUG:acme.client:Sending POST request to https://acme-v02.api.letsencrypt.org/acme/new-acct:" % t,
                '{"contact": ["mailto:someone@example.com"], "termsOfServiceAgreed": true}',
                '  "payload": "eyJjb250YWN0IjpbIm1haWx0bzpzb21lb25lQGV4YW1wbGUuY29tIl19",',
                "%s:INFO:certbot._internal.auth_handler:Performing the following challenges:" % t,
                "%s:INFO:certbot._internal.auth_handler:http-01 challenge for %s" % (t, domain),
                "%s:INFO:certbot._internal.auth_handler:Waiting for verification..." % t,
                '{', '  "identifier": {"type": "dns", "value": "%s"},' % domain, '  "status": "invalid",',
                '  "challenges": [{', '      "type": "http-01", "status": "invalid",',
                '      "error": {', '        "type": "urn:ietf:params:acme:error:%s",' % kind,
                '        "detail": "%s",' % detail, '        "status": 400', "      }", "  }]", "}",
                "%s:INFO:certbot._internal.auth_handler:Cleaning up challenges" % t,
                "%s:DEBUG:certbot._internal.log:Exiting abnormally:" % t,
                "certbot.errors.AuthorizationError: Some challenges have failed.",
                "%s:ERROR:certbot._internal.log:Some challenges have failed." % t, ""]))

    def c_fail2ban_client(self, st, a, data):
        f = st["f2b"]
        if not f["installed"]:
            return 127, "(mock) command not found: fail2ban-client", False
        if a == ["--version"]:
            return 0, "Fail2Ban v1.1.0", False
        if a == ["ping"]:
            return 0, "Server replied: pong", False
        if a == ["-t"]:
            conf = _read_text(self.path_for("/etc/fail2ban/jail.d/pve-gateway.local"))
            if "maxretry = 0" in conf:
                return 1, "ERROR  Failed during configuration: maxretry must be > 0", False
            return 0, "OK: configuration test is successful", False
        if a == ["reload"]:  # enable exactly the jails our file turns on
            conf = _read_text(self.path_for("/etc/fail2ban/jail.d/pve-gateway.local"))
            if conf:
                on = re.findall(r"^\[([\w-]+)\]\nenabled = true", conf, re.M)
                f["jails"] = {j: f["jails"].get(j, {"failed": 0, "failed_total": 0, "banned_total": 0, "ips": []}) for j in on}
            return 0, "OK", True
        if a == ["status"]:
            return 0, "Status\n|- Number of jail:\t%d\n`- Jail list:\t%s" % (len(f["jails"]), ", ".join(f["jails"])), False
        if a[0] == "status" and len(a) == 2:
            j = f["jails"].get(a[1])
            if not j:
                return 255, "Sorry but the jail '%s' does not exist" % a[1], False
            return 0, ("Status for the jail: %s\n|- Filter\n|  |- Currently failed:\t%d\n|  |- Total failed:\t%d\n"
                       "`- Actions\n   |- Currently banned:\t%d\n   |- Total banned:\t%d\n   `- Banned IP list:\t%s"
                       % (a[1], j["failed"], j["failed_total"], len(j["ips"]), j["banned_total"], " ".join(j["ips"]))), False
        if a[:2] == ["unban", "--all"]:
            n = sum(len(j["ips"]) for j in f["jails"].values())
            for j in f["jails"].values():
                j["ips"] = []
            return 0, str(n), True
        if a[0] == "set" and len(a) == 4 and a[2] in ("banip", "unbanip"):
            j = f["jails"].get(a[1])
            if not j:
                return 255, "Sorry but the jail '%s' does not exist" % a[1], False
            if a[2] == "banip" and a[3] not in j["ips"]:
                j["ips"].append(a[3])
                j["banned_total"] += 1
            elif a[2] == "unbanip":
                if a[3] not in j["ips"]:
                    return 255, "IP %s is not banned" % a[3], False
                j["ips"].remove(a[3])
            return 0, "1", True
        return 1, "(mock) unsupported fail2ban-client call", False

    def c_wg(self, st, a, data):
        if not st["wg"]["installed"]:
            return 127, "(mock) command not found: wg", False
        if a == ["--version"]:
            return 0, "wireguard-tools v1.0.20210914 - https://git.zx2c4.com/wireguard-tools/", False
        if a in (["genkey"], ["genpsk"]):
            return 0, base64.b64encode(os.urandom(32)).decode(), False
        if a == ["pubkey"]:
            return 0, base64.b64encode(hashlib.sha256((data or "").strip().encode()).digest()).decode(), False
        if a[:1] == ["syncconf"]:
            return (0, "", False) if a[1] in st["wg"]["up"] else (1, "Unable to access interface: No such device", False)
        if a[:1] == ["show"]:
            if len(a) == 1:
                return 0, "\n".join("interface: %s\n  public key: (mock)\n  private key: (hidden)\n  listening port: 51820"
                                    % n for n in st["wg"]["up"]), False
            if a[1] not in st["wg"]["up"]:
                return 1, "Unable to access interface: No such device", False
            if a[2:] == ["dump"]:
                conf = _read_text(self.path_for("/etc/wireguard/%s.conf" % a[1]))
                port = re.search(r"ListenPort = (\d+)", conf)
                out = ["(hidden)\t(mock-public)\t%s\toff" % (port.group(1) if port else "51820")]
                for i, block in enumerate(conf.split("[Peer]")[1:]):
                    pub = re.search(r"PublicKey = (\S+)", block).group(1)
                    allowed = re.search(r"AllowedIPs = (.+)", block).group(1).replace(" ", "")
                    online = i % 2 == 0
                    seed = int(hashlib.md5(pub.encode()).hexdigest()[:6], 16)
                    out.append("\t".join([pub, "(none)", "198.51.100.%d:%d" % (seed % 200 + 20, 40000 + seed % 20000) if online else "(none)",
                                          allowed, str(int(time.time()) - 25 - seed % 60) if online else "0",
                                          str(seed * 913 if online else 0), str(seed * 211 if online else 0), "off"]))
                return 0, "\n".join(out), False
            return 0, "interface: %s" % a[1], False
        return 1, "(mock) unsupported wg call", False

    def c_wg_quick(self, st, a, data):
        if not st["wg"]["installed"]:
            return 127, "(mock) command not found: wg-quick", False
        verb, name = a[0], a[1]
        conf = _read_text(self.path_for("/etc/wireguard/%s.conf" % name))
        if verb == "up":
            if name in st["wg"]["up"]:
                return 1, "wg-quick: `%s' already exists" % name, False
            if not conf:
                return 1, "wg-quick: `/etc/wireguard/%s.conf' does not exist" % name, False
            st["wg"]["up"].append(name)
            return 0, "[#] ip link add %s type wireguard" % name, True
        if verb == "down":
            if name not in st["wg"]["up"]:
                return 1, "wg-quick: `%s' is not a WireGuard interface" % name, False
            st["wg"]["up"].remove(name)
            return 0, "[#] ip link delete dev %s" % name, True
        if verb == "strip":
            return 0, "\n".join(l for l in conf.splitlines() if not re.match(r"^(Address|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown)\s*=", l)), False
        return 1, "(mock) unsupported wg-quick call", False

    def c_apt_get(self, st, a, data):
        time.sleep(1.5)
        if "wireguard-tools" in a:
            st["wg"]["installed"] = True
            return 0, "Setting up wireguard-tools (1.0.20210914-1.1) ...", True
        if "fail2ban" in a:
            st["f2b"] = {"installed": True, "jails": {"sshd": {"failed": 0, "failed_total": 0, "banned_total": 0, "ips": []}}}
            return 0, "Setting up fail2ban (1.1.0-7) ...", True
        return 0, "", False

    def c_sendmail(self, st, a, data):
        return 0, "", False

    def c_systemctl(self, st, a, data):
        if a[-1].startswith("wg-quick@"):
            return 0, "", False
        if a[-1] != "nginx":
            return 1, "(mock) only nginx is simulated", False
        if a[0] == "is-active":
            return (0, "active", False) if st.get("nginx_active", True) else (3, "inactive", False)
        if a[0] in ("reload", "reload-or-restart", "restart", "start"):
            if a[0] == "reload" and not st.get("nginx_active", True):
                return 1, "nginx.service is not active, cannot reload.", False
            st["nginx_active"] = True
            return 0, "", True
        return 1, "(mock) unsupported systemctl call", False

    def _cert_name(self, path):
        m = re.search(r"/live/([^/]+)/", path)
        return m.group(1) if m else ""

    def _served_name(self, host):
        """Cert name nginx would serve for host on 443 (SNI match, else the first TLS server = default)."""
        first = None
        for block in re.split(r"\nserver \{", self._nginx_conf())[1:]:
            if "listen 443" not in block:
                continue
            crt = re.search(r"ssl_certificate (\S+);", block)
            name = self._cert_name(crt.group(1)) if crt else None
            first = first or name
            names = re.search(r"server_name ([^;]+);", block)
            if names and host in names.group(1).split():
                return name
        return first

    def c_openssl(self, st, a, data):
        if a[:1] == ["s_client"]:
            host = a[a.index("-servername") + 1]
            if not st.get("nginx_active", True):
                return 1, "connect:errno=111\n40C7F3C4DF7F0000:error:8000006F:system library:BIO_connect:Connection refused", False
            name = self._served_name(host)
            if not name:
                return 1, "CONNECTED(00000003)\n40C7F3C4DF7F0000:error:0A000410:SSL routines:ssl3_read_bytes:" \
                          "sslv3 alert handshake failure\nno peer certificate available", False
            return 0, ("CONNECTED(00000003)\n---\nServer certificate\n-----BEGIN CERTIFICATE-----\nMOCK %s\n"
                       "-----END CERTIFICATE-----\nsubject=CN = %s\n---" % (name, name)), False
        if a[:1] == ["x509"] and "-in" not in a:
            m = re.search(r"MOCK (\S+)", data or "")
            c = st["issued"].get(m.group(1)) if m else None
            if not c:
                return 1, "Could not find certificate from <stdin>", False
            fp = ":".join("%02X" % b for b in hashlib.sha256(m.group(1).encode()).digest())
            return 0, ("notAfter=%s\nsha256 Fingerprint=%s\nX509v3 Subject Alternative Name: \n    %s" % (
                time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(c["expires"])), fp,
                ", ".join("DNS:" + n for n in c["names"]))), False
        path = a[a.index("-in") + 1] if "-in" in a else ""
        c = st["issued"].get(self._cert_name(path))
        if not c:
            return 1, "Could not open file or uri for loading certificate from %s" % path, False
        return 0, "notAfter=" + time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(c["expires"])), False

    def c_certbot(self, st, a, data):
        if a == ["--version"]:
            return 0, "certbot 2.1.0", False
        if a[:1] == ["certificates"]:
            if not st["issued"]:
                return 0, "No certificates found.", False
            out = ["Found the following certs:"]
            for name, c in sorted(st["issued"].items()):
                days = int((c["expires"] - time.time()) // 86400)
                out += ["  Certificate Name: " + name, "    Domains: " + " ".join(c["names"]),
                        "    Expiry Date: %s (VALID: %d days)" % (time.strftime("%Y-%m-%d %H:%M:%S+00:00", time.gmtime(c["expires"])), days),
                        "    Certificate Path: /etc/letsencrypt/live/%s/fullchain.pem" % name]
            return 0, "\n".join(out), False
        if a[:1] == ["plugins"]:
            out = ["Saving debug log to /var/log/letsencrypt/letsencrypt.log", "- " * 40]
            for p in ["standalone", "webroot"] + DNS_PLUGINS:
                out += ["* " + p, "Description: (mock)", "Interfaces: Authenticator, Plugin", "- " * 40]
            return 0, "\n".join(out), False
        if a[:1] != ["certonly"]:
            return 1, "(mock) unsupported certbot call", False
        names = [a[i + 1] for i, x in enumerate(a) if x == "-d"]
        name = a[a.index("--cert-name") + 1]
        if st.get("le_blocked") and "--webroot" in a:
            time.sleep(1)
            why = "Connection refused" if "f2b-nginx-botsearch" in st["tables"]["filter"]["chains"] else \
                "Timeout during connect (likely firewall problem)"
            self._le_log(names[0], "connection", "%s: Fetching http://%s/.well-known/acme-challenge/kQ9r2x: %s"
                         % (PUBLIC_IP, names[0], why))
            # like certbot 4: the short summary only, the details are in letsencrypt.log
            return 1, ("Saving debug log to /var/log/letsencrypt/letsencrypt.log\nSome challenges have failed.\n"
                       "Ask for help or search for solutions at https://community.letsencrypt.org. See the logfile "
                       "/var/log/letsencrypt/letsencrypt.log or re-run Certbot with -v for more details."), False
        if "--authenticator" in a:
            err = self._dns01(a, names)
            if err:
                return 1, err, False
        time.sleep(2)  # ACME round trips take a moment
        bad = [n for n in names if self.resolve(n) == []]
        if bad:
            return 1, ("Saving debug log to /var/log/letsencrypt/letsencrypt.log\n"
                       "Certbot failed to authenticate some domains (authenticator: webroot). "
                       "The Certificate Authority reported these problems:\n"
                       "  Domain: %s\n  Type:   dns\n  Detail: DNS problem: NXDOMAIN looking up A for %s - "
                       "check that a DNS record exists for this domain\n\n"
                       "Hint: The Certificate Authority failed to download the temporary challenge files "
                       "created by the --webroot plugin.\nSome challenges have failed." % (bad[0], bad[0])), False
        cur = st["issued"].get(name)
        if cur and set(names) <= set(cur["names"]) and cur["expires"] - time.time() > 30 * 86400:
            return 0, "Certificate not yet due for renewal; no action taken.", False
        st["issued"][name] = {"names": names, "expires": time.time() + 90 * 86400}
        return 0, ("Successfully received certificate.\nCertificate is saved at: /etc/letsencrypt/live/%s/fullchain.pem\n"
                   "Key is saved at:         /etc/letsencrypt/live/%s/privkey.pem\n"
                   "Certbot has set up a scheduled task to automatically renew this certificate in the background." % (name, name)), True

    def c_conntrack(self, st, a, data):
        out = []
        for rule in st["tables"]["nat"]["chains"].get("PVEGW_PRE", []):
            if not st["counters"].get("nat|PVEGW_PRE|" + rule):
                continue
            proto, dport = _opt(rule, "-p"), (_opt(rule, "--dport") or "0").split(":")[0]
            to = _opt(rule, "--to-destination") or ""
            ip, _, tport = to.partition(":")
            for _ in range(random.randint(1, 3)):
                cli, sp = "203.0.113.%d" % random.randint(2, 250), random.randint(40000, 65000)
                state = "ESTABLISHED " if proto == "tcp" else ""
                out.append("%s      %d %d %ssrc=%s dst=%s sport=%d dport=%s src=%s dst=%s sport=%s dport=%d [ASSURED] mark=0 use=1"
                           % (proto, 6 if proto == "tcp" else 17, random.randint(100, 431999), state, cli, HOST_IP,
                              sp, dport, ip, cli, tport or dport, sp))
        return 0, "\n".join(out), False

    def c_pve_firewall(self, st, a, data):
        return 0, "Status: %s/running" % ("enabled" if st["pvefw"]["options"].get("enable") else "disabled"), False

    # ------------------------------------------------------------------ proxmox tools
    def c_pvesh(self, st, a, data):
        verb, path = a[0], a[1] if len(a) > 1 else ""
        fw = st["pvefw"]
        opts = {a[i][2:]: a[i + 1] for i in range(2, len(a) - 1) if a[i].startswith("--")}
        if path == "/cluster/resources":
            return 0, json.dumps([{"id": "%s/%d" % (g["type"], g["vmid"]), "vmid": g["vmid"], "name": g["name"],
                                   "type": g["type"], "status": g["status"], "node": self.node, "template": 0}
                                  for g in GUESTS]), False
        if re.match(r"^/nodes/[^/]+/firewall/rules$", path):
            if verb == "get":
                return 0, json.dumps([dict(r, pos=i) for i, r in enumerate(fw["rules"])]), False
            if verb == "create":
                rule = {k: v for k, v in opts.items() if k != "pos"}
                rule["enable"] = int(rule.get("enable", 1))
                fw["rules"].insert(int(opts.get("pos", len(fw["rules"]))), rule)
                return 0, "", True
        m = re.match(r"^/nodes/[^/]+/firewall/rules/(\d+)$", path)
        if m and verb == "delete":
            if int(m.group(1)) >= len(fw["rules"]):
                return 1, "no rule at position %s" % m.group(1), False
            fw["rules"].pop(int(m.group(1)))
            return 0, "", True
        if path == "/cluster/firewall/options":
            if verb == "get":
                return 0, json.dumps(fw["options"]), False
            fw["options"].update({k: (int(v) if v.isdigit() else v) for k, v in opts.items()})
            return 0, "", True
        if re.match(r"^/nodes/[^/]+/firewall/options$", path) and verb == "set":
            fw["node_enable"] = int(opts.get("enable", 1))
            return 0, "", True
        return 1, "(mock) unsupported pvesh call: %s %s" % (verb, path), False

    def c_ip6tables(self, st, a, data):
        return self.c_iptables(st, ["-t", "filter6"] + (a[2:] if a[:2] == ["-t", "filter"] else a), data)

    def c_ip6tables_restore(self, st, a, data):
        return self.c_iptables_restore(st, a, (data or "").replace("*filter", "*filter6"))

    def c_qm(self, st, a, data):
        if a[0] == "config":
            g = next((x for x in GUESTS if x["vmid"] == int(a[1]) and x["type"] == "qemu"), None)
            if not g:
                return 2, "Configuration file 'nodes/%s/qemu-server/%s.conf' does not exist" % (self.node, a[1]), False
            lines = ["boot: order=scsi0", "cores: 2", "memory: 4096", "name: " + g["name"],
                     "net0: virtio=%s,bridge=vmbr1,firewall=1" % _mac(g["vmid"]).upper(), "ostype: l26",
                     "scsi0: local-lvm:vm-%d-disk-0,size=32G" % g["vmid"]]
            if g.get("agent"):
                lines.insert(0, "agent: 1")
            if g.get("cloudinit"):
                lines.append("ipconfig0: ip=%s/24,gw=%s" % (g["ip"], BRIDGE_IP))
            return 0, "\n".join(sorted(lines)), False
        vmid = int(a[2])
        g = next((x for x in GUESTS if x["vmid"] == vmid), None)
        if not g:
            return 2, "Configuration file 'nodes/%s/qemu-server/%d.conf' does not exist" % (self.node, vmid), False
        if g["status"] != "running":
            return 2, "VM %d is not running" % vmid, False
        if not g.get("agent"):
            return 2, "QEMU guest agent is not running", False
        return 0, json.dumps([
            {"name": "lo", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "127.0.0.1", "prefix": 8}]},
            {"name": "eth0", "hardware-address": "bc:24:11:00:00:%02x" % (vmid % 256),
             "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": g["ip"], "prefix": 24},
                              {"ip-address-type": "ipv6", "ip-address": "fe80::be24:11ff:fe00:%x" % vmid, "prefix": 64}]},
        ]), False

    def c_pct(self, st, a, data):
        g = next((x for x in GUESTS if x["vmid"] == int(a[1]) and x["type"] == "lxc"), None)
        if not g:
            return 2, "Configuration file does not exist", False
        return 0, ("arch: amd64\ncores: 2\nhostname: {name}\nmemory: 1024\n"
                   "net0: name=eth0,bridge=vmbr1,gw={gw},hwaddr=BC:24:11:00:01:{v:02X},ip={ip}/24,type=veth\n"
                   "ostype: debian\nrootfs: local-lvm:vm-{vmid}-disk-0,size=8G").format(
            name=g["name"], gw=BRIDGE_IP, v=g["vmid"] % 256, ip=g["ip"], vmid=g["vmid"]), False

    def c_lxc_info(self, st, a, data):
        g = next((x for x in GUESTS if str(x["vmid"]) == a[a.index("-n") + 1]), None)
        if not g or g["status"] != "running":
            return 1, "", False
        return 0, g["ip"], False
