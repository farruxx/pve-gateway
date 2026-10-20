<p align="center"><img src="docs/logo.svg" width="96" height="96" alt="pve-gateway logotipi"></p>

# pve-gateway

[English](README.md) · [Русский](README.ru.md) · **Oʻzbekcha**

Proxmox VE xostini undagi VM va konteynerlar uchun shlyuzga aylantiruvchi kichik veb UI:

- **Portlar:** xost portlarini mehmon tizimlarga yoʻnaltirish (iptables DNAT).
- **Domenlar:** `app.example.com` → mehmon tizimning `ip:port` manziliga nginx orqali marshrutlash, Let's Encrypt va wildcard (`*.example.com`) sertifikatlari avtomatik olinadi.

![Domenlar: Let's Encrypt va wildcard sertifikatlari bilan reverse proxy](docs/screenshots/domains.png)

## Skrinshotlar

| | |
|---|---|
| ![Jonli murojaatlar hisoblagichlari bilan port yoʻnaltirish qoidalari](docs/screenshots/ports.png) | ![Domen qoʻshish: mehmon tizimni va HTTPS turini tanlang](docs/screenshots/add-domain.png) |
| **Portlar**: xost portlarini mehmon tizimlarga yoʻnaltirish, manba/interfeys filtrlari va jonli murojaatlar hisoblagichlari bilan | **Domen qoʻshish**: mehmon tizimni tanlang, Let's Encrypt, wildcard sertifikat yoki oddiy HTTP ni belgilang |
| ![Ichki test nima notoʻgʻriligini tushuntiradi](docs/screenshots/domain-test.png) | ![DNS provayder API orqali wildcard sertifikat](docs/screenshots/wildcard.png) |
| **Tekshirish**: DNS, nginx, upstream, sertifikat va haqiqiy soʻrovni tekshiradi, har bir xatoni qanday tuzatishni koʻrsatadi | **Wildcard sertifikatlar**: `*.example.com` DNS provayderingiz API orqali ([qoʻllanma](wildcard.md)) |
| ![Veb UI ga kirish sozlamalari](docs/screenshots/settings.png) | ![Tekshiruvlar bilan Diagnostika boʻlimi](docs/screenshots/debug.png) |
| **Sozlamalar**: veb UI ga faqat siz koʻrsatgan IP/tarmoqlardan kirish mumkin | **Diagnostika**: tekshiruvlar, iptables/nginx/certbot xom chiqishi, log va yuklab olinadigan hisobot |
| ![Tekshiruvlar, ogohlantirishlar va port skaneri](docs/screenshots/monitor.png) | ![Fail2ban jail lari va sozlamalari](docs/screenshots/security.png) |
| **Monitoring**: uptime va tarixga ega tekshiruvlar, ogohlantirishlar (e-mail, webhook, Telegram), port skaneri | **Xavfsizlik**: fayrvol (oʻz iptables yoki Proxmox fayrvoli), fail2ban jail lari va bloklangan IP lar |
| ![Tugunlari bilan WireGuard tunneli](docs/screenshots/vpn.png) | ![Proxmox SDN zonalari, VNet, DHCP va IPAM](docs/screenshots/network.png) |
| **VPN**: WireGuard tunneli, yuklab olinadigan konfiguratsiyali qurilmalar, obyektlar, jonli holat | **Tarmoq**: Proxmox SDN zonalari va VNet lar, DHCP li quyi tarmoqlar, IPAM rezervatsiyalari, DNS |

<sub>Skrinshotlarda ichki mock rejimidagi (`./dev.sh`) namunaviy maʼlumotlar ishlatilgan. Ularni `dev/screenshots.sh` bilan qayta yaratishingiz mumkin.</sub>

- **Bogʻliqliklar yoʻq.** Bu faqat standart kutubxonadan foydalanadigan bitta Python 3 fayli boʻlib, `iptables` ni boshqaradi. Ikkalasi ham Proxmox VE 7 va 8 tarkibida allaqachon mavjud.
- **Proxmox akkauntingiz bilan kirish.** Kirish maʼlumotlari mahalliy PVE API orqali tekshiriladi, standart holatda faqat `root@pam` ga ruxsat beriladi. Buning oʻrniga mahalliy paroldan foydalanishga oʻtishingiz mumkin.
- **HTTPS darhol ishlaydi.** Proxmox sertifikatidan (`/etc/pve/local/pveproxy-ssl.*` yoki `pve-ssl.*`) qayta foydalaniladi.
- **Boshqa qoidalar bilan yonma-yon xavfsiz ishlaydi.** Hammasi alohida zanjirlarda (`PVEGW_PRE`, `PVEGW_POST`, `PVEGW_FWD`) saqlanadi va ular `iptables-restore` orqali atomar almashtiriladi. pve-firewall va sizning qoidalaringizga tegilmaydi.
- **Mehmon tizimni tanlash.** Mahalliy VM va CT lar IP manzillari bilan roʻyxatda koʻrsatiladi (QEMU guest agent, xostning ARP jadvali, cloud-init yoki LXC konfiguratsiyasidan; qarang: [Mehmon tizimlar IP manzillari](#mehmon-tizimlar-ip-manzillari)).
- **Xost tarmogʻi bir qarashda.** Portlar va Domenlar boʻlimlarida xostning interfeyslari va IP manzillari (ommaviy, WAN, mehmon koʻpriklari) hamda DNS va routerlar qayerga yoʻnaltirilishi kerakligi haqida maslahatlar koʻrsatiladi.
- TCP, UDP yoki ikkalasini, port diapazonlarini, manba IP/CIDR ruxsat roʻyxatini, kiruvchi interfeysni, ixtiyoriy masquerade ni qoʻllab-quvvatlaydi va har bir qoida uchun murojaatlar hisoblagichini koʻrsatadi.
- **Guruhlar.** Port qoidalari va domenlarni guruhlarga (masalan, *web*, *games*) ajratish mumkin. Har bir guruh oʻzining **+ Qoʻshish**, **Qayta nomlash** va **Guruhdan chiqarish** tugmalariga ega yigʻiladigan boʻlimdir. Guruhsiz hamma narsa, jumladan eski versiyalarda saqlanganlar ham, **standart** guruhda qoladi. Barcha elementlar standart guruhda boʻlsa, jadvallar avvalgidek koʻrinadi. Guruhlar faqat elementlarning roʻyxatda koʻrsatilishini oʻzgartiradi; iptables yoki nginx ga taʼsir qilmaydi.
- **Qulf.** 🔓 tugmasi port qoidasi yoki domenni qulflaydi (🔒). Qulflangan elementni qulfdan chiqarmaguningizcha tahrirlab, oʻchirib qoʻyib, oʻchirib yoki boshqa guruhga koʻchirib boʻlmaydi. Bu nafaqat UI da, balki server tomonida ham taʼminlanadi (HTTP 423). Tekshirish ishlashda davom etadi. Sertifikatni qoʻlda soʻrash (Cert) ham bloklanadi; avtomatik yangilash ishlayveradi, muvaffaqiyatsiz soʻrov esa ishlab turgan sertifikatni hech qachon almashtirmaydi.
- **Tillar.** Veb interfeys ingliz, rus va oʻzbek (lotin) tillarida mavjud. Til brauzerdan olinadi, uni **Sozlamalar → Til** boʻlimida yoki kirish sahifasida almashtirish mumkin. Server xabarlari, tekshiruvlar va xatolar ham tarjima qilinadi; CLI va jurnal ingliz tilida qoladi.
- **Himoya choralari.** 22, 8006, 3128, 111, 5405-5412 portlarini va oʻz portini yoʻnaltirishni rad etadi. Faqat **xostga yoʻnaltirilgan** trafik uzatiladi (`-m addrtype --dst-type LOCAL`), shuning uchun mehmon tizimlarning chiquvchi trafigi hech qachon ushlab olinmaydi.
- Agar biror narsa iptables ni tozalab yuborsa, watchdog zanjirlarni qayta ulaydi, qoidalar esa yuklanishda tiklanadi.

## Oʻrnatish (Proxmox xostida, root sifatida)

Bitta buyruq xizmatni yuklab oladi, oʻrnatadi va ishga tushiradi:

```bash
curl -fsSL https://raw.githubusercontent.com/farruxx/pve-gateway/master/install.sh | sh
```

Soʻng `https://<proxmox-ip>:8099` ni oching va `root@pam` sifatida kiring.

**Domenlar** boʻlimidan (xost nomi boʻyicha reverse proxy) foydalanish uchun nginx va certbot ni qoʻshing. Ular yagona ixtiyoriy bogʻliqliklar boʻlib, ikkalasi ham Debian dan olinadi:

```bash
curl -fsSL https://raw.githubusercontent.com/farruxx/pve-gateway/master/install.sh | sh -s -- --with-nginx
```

**Wildcard sertifikatlar** uchun DNS provayderingizning certbot plaginini ham qoʻshing, masalan Cloudflare (qarang: [wildcard.md](wildcard.md)):

```bash
curl -fsSL https://raw.githubusercontent.com/farruxx/pve-gateway/master/install.sh | sh -s -- --with-dns cloudflare
```

**Yangilash:** **Sozlamalar → Yangilanishlar** boʻlimida **vX.Y.Z ga yangilash** tugmasini bosing yoki *Yangi versiyalarni avtomatik oʻrnatish* ni belgilang. pve-gateway kuniga bir marta GitHub ni tekshiradi va yangi versiya chiqqanda sarlavhada belgi hamda nimalar oʻzgarganini ([CHANGELOG.md](CHANGELOG.md) dan) koʻrsatadi. Shell dan `pve-gateway update` ni ishga tushiring yoki oʻrnatish buyrugʻini qayta bajaring. Har ikki holatda ham qoidalaringiz, domenlaringiz va sertifikatlaringiz saqlanib qoladi.

- **Proxmox obunasi yoʻqmi?** Bu odatiy holat va u siz uchun hal qilinadi. Obunasiz Proxmox *enterprise* repozitoriylari `401 Unauthorized` javobini qaytaradi. Oʻrnatuvchi buni koʻrganda apt ni bepul **no-subscription** repozitoriylariga oʻtkazadi:
  - enterprise yozuvlari (pve va ceph) oʻchirilmaydi, faqat oʻchirib qoʻyiladi;
  - shu Debian relizi uchun mos no-subscription yozuvlari qoʻshiladi;
  - eski fayllarning zaxira nusxasi `/var/lib/pve-gateway/apt-backup/` ga saqlanadi.

  PVE 8 (`.list`) va PVE 9 (`.sources`) da ishlaydi. VM lar ishlab turganda ham xavfsiz; hech narsa yangilanmaydi yoki qayta ishga tushirilmaydi. Ishlaydigan obunaga ega xostlarga tegilmaydi. Oʻtkazishni oʻtkazib yuborish uchun `--keep-repos` dan foydalaning yoki faqat oʻtkazishni bajaring:

  ```bash
  curl -fsSL https://raw.githubusercontent.com/farruxx/pve-gateway/master/install.sh | sh -s -- fix-repos
  ```
- **Ishga tushirishdan oldin oʻqib chiqmoqchimisiz?** Repozitoriyni klonlang va skriptni undan ishga tushiring; bunda u yuklab olish oʻrniga mahalliy fayllardan foydalanadi:

  ```bash
  git clone https://github.com/farruxx/pve-gateway && cd pve-gateway && sh install.sh --with-nginx
  ```

### Mehmon tizimlar IP manzillari

Mehmon tizimni tanlashda VM ning IP manzili, agar ishlayotgan boʻlsa, **QEMU guest agent** dan olinadi. Agent boʻlmasa, VM ning MAC manzili boʻyicha xostning **ARP jadvali** ga, soʻng **SDN IPAM** ga (DHCP VNet dagi mehmon tizimlar, qarang: [Tarmoq](#tarmoq-dhcp-ipam-va-dns-proxmox-sdn)), keyin esa **cloud-init** `ipconfig` ga murojaat qilinadi.

Shlyuzi boshqa router boʻlgan VM (masalan, fayrvol VM) xostning oʻzi bilan hech qachon bogʻlanmaydi, shuning uchun u ARP jadvalida boʻlmaydi. Bunday holatlar uchun tanlash vositasi xostning xususiy koʻpriklaridagi manzillarni qisqa vaqt tekshiradi (koʻpi bilan 5 daqiqada bir marta va hech qachon uplink da emas), shunda ular ARP ga javob beradi va roʻyxatda paydo boʻladi. Konteynerlar uchun IP LXC yoki konteyner konfiguratsiyasidan olinadi. Agar VM hali ham *IP nomaʼlum* deb koʻrsatilsa:
- VM ichiga agentni oʻrnating (`apt install qemu-guest-agent`),
- Proxmox da VM uchun **Options → QEMU Guest Agent** ni yoqing va VM ni qayta ishga tushiring.

IP manzilni har doim qoʻlda kiritishingiz mumkin.

## Domenlar (nginx reverse proxy)

**Domenlar** boʻlimi xost nomlarini mehmon tizimlarga bogʻlaydi: `cloud.example.com` → `10.10.10.13:80`, `git.example.com` → `https://10.10.10.10:443` va hokazo. Xostdagi nginx 80 va 443 portlarida javob beradi va har bir soʻrovni uning `Host` sarlavhasi boʻyicha proksilaydi, shuning uchun koʻplab mehmon tizimlar bitta ommaviy IP va bir xil portlardan foydalanishi mumkin.

- Hammasi bitta generatsiya qilingan faylga yoziladi: `/etc/nginx/conf.d/pve-gateway.conf`. Boshqa nginx saytlariga tegilmaydi. Har bir oʻzgarish qayta yuklashdan oldin `nginx -t` bilan tekshiriladi; tekshiruv muvaffaqiyatsiz boʻlsa, oldingi fayl tiklanadi va xato UI da koʻrsatiladi.
- **Let's Encrypt** (ixtiyoriy, har bir domen uchun) `certbot certonly --webroot` dan foydalanadi. Sertifikat saqlangandan soʻng darhol fonda soʻraladi, uni certbot ning oʻz systemd taymeri yangilaydi va deploy hook orqali nginx ni qayta yuklaydi. *Cert* uni talab boʻyicha qayta soʻraydi, *Tekshirish* esa DNS, nginx, upstream, sertifikat va nginx orqali haqiqiy soʻrovni tekshiradi.
- **Har bir domen uchun parametrlar:**
  - taxalluslar (qoʻshimcha xost nomlari), ular xuddi shu sayt sifatida ochiladi yoki asosiy domenga **301 bilan qayta yoʻnaltiriladi**;
  - HTTPS upstream (oʻzi imzolagan sertifikatlar qabul qilinadi);
  - HTTP dan HTTPS ga qayta yoʻnaltirish va ixtiyoriy **HSTS**;
  - **xavfsizlik sarlavhalari** (nosniff, same-origin framing, referrer policy);
  - maksimal yuklash hajmi va ruxsat etilgan manba IP/CIDR lar;
  - **Cloudflare ortida**: toʻq sariq bulut ortidagi domenlar uchun nginx Cloudflare manzil diapazonlariga ishonadi, shunda loglar, mehmon tizim va *Ruxsat etilgan manbalar* tashrif buyuruvchining haqiqiy IP manzilini koʻradi.

  WebSocket lar har doim ishlaydi.
- **Tekshirish** DNS (A, AAAA va Cloudflare orqali proksilangan yozuvlar), nginx va upstream ni tekshiradi. Shuningdek, nginx **haqiqatda taqdim etayotgan** sertifikatni ham tekshiradi: u barcha nomlarni qamrashi, muddati tugashiga yaqin boʻlmasligi va IPv4 hamda IPv6 orqali bir xil boʻlishi kerak. Qayta yoʻnaltirishga sozlangan taxalluslar 301 bilan javob berishi shart.
- **Talablar:** har bir domenning DNS A yozuvi xostning ommaviy IP manziliga yoʻnaltirilgan boʻlishi kerak. Agar xost router ortida boʻlsa, router TCP 80 va 443 ni unga yoʻnaltirishi kerak.
- Biror domen yoqilgan ekan, port yoʻnaltirish qoidalari TCP 80 yoki 443 ni egallay olmaydi, chunki bu portlar nginx ga tegishli. Teskarisi ham taʼminlanadi.

### Wildcard sertifikatlar (`*.example.com`)

> Bosqichma-bosqich sozlash (DNS yozuvlari, API tokenlar, muammolarni bartaraf etish): qarang [wildcard.md](wildcard.md).

Bitta sertifikat `example.com` va barcha `*.example.com` subdomenlarini qamraydi. Let's Encrypt wildcard sertifikatlarni faqat **DNS-01** tekshiruvi orqali beradi, shuning uchun certbot DNS provayderingiz API orqali TXT yozuvi yaratadi. Buning uchun 80-port ochiq boʻlishi shart emas.

1. Provayderingiz uchun certbot plaginini oʻrnating (ularning barchasi Debian paketlari):

   ```bash
   apt install python3-certbot-dns-cloudflare
   ```

2. **Domenlar → Wildcard sertifikatlar → + Wildcard qoʻshish** ga oʻting va zonani (`example.com`), provayderni hamda API tokenni kiriting. Sertifikat darhol beriladi (~30 s).
3. Har bir domen uchun **HTTPS: Wildcard sertifikat (DNS)** ni tanlang. Mos sertifikat avtomatik tanlanadi, shuning uchun yangi subdomen darhol HTTPS da ishlaydi.

| Provayder | Paket | Kirish maʼlumotlari |
|---|---|---|
| Cloudflare | `python3-certbot-dns-cloudflare` | *Zone / DNS / Edit* huquqli API token |
| DigitalOcean | `python3-certbot-dns-digitalocean` | API token |
| Linode / Akamai | `python3-certbot-dns-linode` | API token |
| DNSimple | `python3-certbot-dns-dnsimple` | API token |
| OVH | `python3-certbot-dns-ovh` | endpoint + application key/secret + consumer key |
| RFC 2136 (BIND, PowerDNS, Knot) | `python3-certbot-dns-rfc2136` | server, TSIG kalit nomi/maxfiy kaliti/algoritmi |

- **Qamrov:** wildcard faqat bitta darajani qamraydi. `*.example.com` `a.example.com` ga mos keladi, lekin `a.b.example.com` ga emas; buning uchun `b.example.com` uchun wildcard qoʻshishingiz kerak.
- **Kirish maʼlumotlari** `/etc/pve-gateway/dns/<id>.ini` ga yoziladi (rejim 0600, katalog 0700). Ular hech qachon API orqali qaytarilmaydi va diagnostika hisobotiga kiritilmaydi. Tahrirlashda boʻsh qoldirilgan maydon saqlangan qiymatni oʻzgartirmaydi.
- **Yangilash:** certbot taymeri wildcard sertifikatlarni xuddi shu DNS plagini orqali yangilaydi. Domenlar hali foydalanayotgan wildcard sertifikatni oʻchirib yoki oʻchirib qoʻyib boʻlmaydi.

## Odatiy sozlash

Mehmon tizimlar xususiy koʻprikda (masalan, `vmbr1`, `10.10.10.0/24`) joylashgan va xost ular uchun NAT ni bajaradi. Quyidagicha qoida qoʻshing:

| Xost porti | Manzil | Maʼnosi |
|---|---|---|
| `8080` | `10.10.10.10:80` | `http://<host-ip>:8080` VM 100 ning veb serveriga yetib boradi |
| `27015-27020` TCP+UDP | `10.10.10.12` | port diapazoni, mehmon tizimda ham xuddi shu portlar |

**Masquerade** faqat mehmon tizimning standart shlyuzi Proxmox xosti *boʻlmasa* yoki boshqa mehmon tizimlar xizmatga xostning ommaviy IP manzili orqali murojaat qilishi kerak boʻlsa (hairpin NAT) kerak boʻladi. Eʼtibor bering: masquerade yoqilganda mehmon tizim mijozning haqiqiy IP manzili oʻrniga xostning IP manzilini koʻradi.

## CLI

```
pve-gateway serve           # web UI (what systemd runs)
pve-gateway status          # rules, hit counters, hook status
pve-gateway test [NAME...]  # reachability test (rule id/name/host port or domain; default: all enabled)
pve-gateway ui-allow IP...  # web UI only from these IPs/networks ("any" = everyone, no args = show)
pve-gateway ui-host NAME..  # extra hostnames the web UI may be opened by ("none" = clear)
pve-gateway --version       # installed version
pve-gateway update [check]  # install the latest version from GitHub ("check" = only check)
pve-gateway monitors        # run every health check once
pve-gateway scan IP [PORTS] # TCP port scan from this host (common | 22,80,8000-8100)
pve-gateway domains         # list domains, wildcard certificates and expiry
pve-gateway cert NAME       # request / renew now: a domain, or '*.example.com' for a wildcard
pve-gateway backup [FILE]   # backup (config + secrets; --no-secrets, --certs) to FILE or /etc/pve-gateway/backups
pve-gateway backup list     # list local backups
pve-gateway restore NAME|FILE all|PART...   # parts: rules domains monitoring firewall fail2ban vpn access updates
pve-gateway debug           # full diagnostic report, paste it when asking for help
pve-gateway show            # print the generated iptables-restore payload
pve-gateway apply           # re-apply saved rules
pve-gateway flush           # remove all forwarding rules/chains (config kept)
pve-gateway passwd          # use a local user/password instead of Proxmox login
pve-gateway -v ...          # verbose: log every iptables command and HTTP request
pve-gateway --dry-run ...   # log iptables commands instead of running them (for testing)
```

## Diagnostika

Veb UI dagi **Diagnostika boʻlimi**:
- **Tekshiruvlar:** root, iptables, `ip_forward`, har bir hook mavjudligi va u oʻz zanjirida qayerda turgani, yadro qoidalari konfiguratsiyaga mos kelishi, FORWARD siyosati, pve-firewall holati va yoʻnaltirilgan portni tinglayotgan xost xizmatlari.
- **Xom chiqish:** generatsiya qilingan qoidalar toʻplami, paket/bayt hisoblagichlari bilan yuklangan `PVEGW_*` qoidalari, toʻliq PREROUTING/POSTROUTING/FORWARD zanjirlari, mehmon tizimlarga kuzatilayotgan ulanishlar, interfeyslar, marshrutlar, tinglayotgan soketlar va konfiguratsiya (parol xeshi yashirilgan).
- **Xizmat logi:** xotirada saqlanadigan oxirgi 500 qator hamda qayta ishga tushirishsiz darhol kuchga kiradigan *Batafsil log* kaliti.
- **Hisobotni nusxalash / Hisobotni yuklab olish:** `pve-gateway debug` bilan bir xil matnni beradi.

Har bir qoidadagi **Tekshirish** tugmasi (yoki `pve-gateway test`) xostdan ishga tushadi va quyidagilarni tekshiradi:
- qoida yuklanganmi
- `ip_forward` yoqilganmi
- mehmon tizimgacha boʻlgan marshrut (va u shlyuz orqali oʻtadimi)
- mehmon tizimga ping
- mehmon tizim portiga TCP ulanish, bu rad etishni (hech narsa tinglamayapti) timeout dan (mehmon tizim ishlamayapti yoki fayrvol bilan yopilgan) ajratadi
- qoidaning murojaatlar hisoblagichi

Testlar faqat mehmon tizim tomonini tekshiradi. Agar tashqaridan tekshirayotganingizda hisoblagich 0 da qolsa, trafik xostga umuman yetib kelmayapti, shuning uchun routeringiz, provayderingiz yoki bulut fayrvolini tekshiring.

Xizmat loglari: `journalctl -u pve-gateway -f`. Batafsil logni doimiy yoqib qoʻyish uchun unit fayldagi `ExecStart` ni `... pve-gateway -v serve` ga oʻzgartiring.

## Mahalliy ishlab chiqish (macOS)

`--mock` hamma narsani simulyatsiya qilingan Proxmox xostida ishga tushiradi. Unga root, iptables yoki Proxmox kerak emas. Mock `iptables`, `iptables-restore`/`-save`, `ip`, `ping`, `ss`, `conntrack`, `pve-firewall`, `pvesh` (SDN bilan birga), `qm`, `pct`, `lxc-info`, `dnsmasq` va boshqalarni taqlid qiladi. Mock kodi [`dev/mock.py`](dev/mock.py) da joylashgan va xostga hech qachon oʻrnatilmaydi.

```bash
./dev.sh
```

http://127.0.0.1:8099 ni oching va **admin / admin** sifatida kiring.

Istalgan CLI buyrugʻini xuddi shu simulyatsiya qilingan xostda ishga tushirishingiz mumkin. Veb UI va CLI holatni `.dev/mock-state.json` orqali boʻlishadi:

```bash
./dev.sh status
```
```bash
./dev.sh test
```
```bash
./dev.sh debug
```

Xostni ataylab buzish uchun ssenariyni ishga tushiring. Ular Diagnostika boʻlimida tugmalar sifatida ham mavjud:

```bash
./dev.sh mock unhook
```

| Ssenariy | Nima qiladi |
|---|---|
| `unhook` | bizning jump qoidalarimizni olib tashlaydi. Tekshiruvlar xato beradi, watchdog esa 10 s ichida tuzatadi |
| `ip-forward-off` | `net.ipv4.ip_forward = 0` ni oʻrnatadi |
| `forward-drop` | FORWARD siyosatini DROP ga oʻrnatadi |
| `pvefw-first` | pve-firewall jump qoidasini biznikidan yuqoriga koʻchiradi (ogohlantirish) |
| `foreign-dnat` | bizning hook dan yuqoriga boshqa DNAT qoidasini qoʻyadi (ogohlantirish) |
| `traffic` | hisoblagichlarga bir toʻda murojaat yuboradi |
| `nginx-stopped` | nginx ni toʻxtatadi, shuning uchun domen testlari xato beradi |
| `nginx-test-fails` | navbatdagi `nginx -t` ni xato bilan yakunlaydi va orqaga qaytarishni koʻrsatadi |
| `cert-expiring` | barcha sertifikatlar muddatini 5 kunda tugaydigan qiladi |
| `no-dnsmasq` | dnsmasq yoʻq, shuning uchun SDN DHCP ishlay olmaydi (Tarmoq boʻlimida Oʻrnatish tugmasi) |
| `no-sdn` | SDN API siz eski Proxmox VE (7.4) |
| `sdn-pending` | boshqa joyda qilingan, hali qoʻllanmagan SDN oʻzgarishi |
| `reset` | simulyatsiya qilingan iptables ni tozalaydi |

Simulyatsiya qilingan mehmon tizimlar: 100 web, 101 db, 102 game (toʻxtatilgan), 103 nextcloud, 104 win11 (guest agent yoʻq, ping ga javob bermaydi), 105 office-gw (shlyuz ortida) va 108 builder (SDN VNet `labnet` da, IPAM orqali topiladi). Namunaviy SDN da `lab` zonasi (DHCP, PowerDNS plagini), `labnet` VNet va `10.20.30.0/24` quyi tarmogʻi bor. Namunaviy qoidalar barcha test natijalarini koʻrsatadi. Namunaviy domenlar: `cloud.example.com` (HTTPS ishlaydi), `app.example.com` (faqat HTTP, taxallus bilan) va `broken.invalid` (DNS yoʻq va upstream da hech narsa tinglamayapti). Namunaviy wildcard — `*.example.com` (Cloudflare), undan `status.example.com` foydalanadi. Mock certbot `.invalid` bilan tugaydigan nomlar uchun xato beradi, qolganlari uchun esa 2 s dan soʻng muvaffaqiyatli ishlaydi. Wildcard lar uchun `bad` API tokeni Cloudflare ning "invalid credentials" xatosini oladi, oʻrnatilgan deb faqat Cloudflare, DigitalOcean va RFC 2136 plaginlari hisoblanadi, shuning uchun OVH "plagin yoʻq" xabarini koʻrsatadi. Generatsiya qilingan nginx fayllari `.dev/mock-fs/` ostida saqlanadi. Boshidan boshlash uchun `.dev/` ni oʻchiring.

`--dry-run` boshqacha. U **haqiqiy** xost uchun moʻljallangan: faqat oʻqiydigan buyruqlar haqiqatda bajariladi, oʻzgarishlar esa faqat logga yoziladi.

## Monitoring

**Monitoring** boʻlimi mehmon tizimlaringiz va domenlaringizni kuzatadi:

- **Tekshiruvlar:** HTTP(S) (kutilgan status, sertifikat muddati), TCP port va ping, har N soniyada. Har bir tekshiruv ishlayapti / nosoz / ishlamayapti holatini, javob vaqtini, uptime va oxirgi 60 ta natijani koʻrsatadi. **Domenlarim va portlarim uchun tekshiruvlar qoʻshish** har bir domen va port qoidasi uchun bittadan tekshiruv yaratadi.
- **Ogohlantirishlar:** tekshiruv ketma-ket N marta ishlamasa, qayta ishlay boshlaganda va sertifikat muddati N kun ichida tugasa yuboriladi. Kanallar:
  - **e-mail**, xostning pochta tizimi orqali (Proxmox tarkibida postfix bor);
  - **webhook** (Slack, Discord yoki istalgan URL; `text`/`content` li JSON);
  - **Telegram** (bot token + chat id).

  **Test ogohlantirish yuborish** sozlamani tekshiradi. Tokenlar faqat xostda saqlanadi va qayta koʻrsatilmaydi.
- **Port skaneri:** xostdan TCP connect skanerlash (90 ga yaqin keng tarqalgan port yoki 5000 tagacha diapazonlar), xizmat nomlari va xavf darajalari bilan. U xostning oʻzi nimaga yeta olishini koʻrsatadi; internetdan koʻrinish farq qilishi mumkin. Suiisteʼmolning oldini olish uchun faqat shu xost, xususiy tarmoqlar va maʼlum mehmon tizimlarni skanerlash mumkin.

CLI: `pve-gateway monitors` barcha tekshiruvlarni bir marta ishga tushiradi; `pve-gateway scan 10.10.10.11 1-1024` shell dan skanerlaydi.

## WireGuard VPN

**VPN** boʻlimi xostda WireGuard ni sozlaydi:
- **Tunnellar:** yangi tunnel oqilona standart qiymatlar bilan oldindan toʻldiriladi: boʻsh `10.99.x.0/24` quyi tarmogʻi, UDP 51820, endpoint sifatida shu xostning ommaviy manzili va mijozlar yeta oladigan tarmoqlar sifatida mehmon koʻpriklari. Kalitlar xostda generatsiya qilinadi, tunnel esa hozir va yuklanishda ishga tushadi (`wg-quick@wg0`).
- **Qurilmalar** (telefon, noutbuk): ular uchun kalitlar generatsiya qilinadi va siz WireGuard ilovasiga import qilish uchun **mijoz konfiguratsiyasi** ni olasiz (koʻrish, nusxalash yoki yuklab olish).
- **Obyektlar** (boshqa router yoki ofis): uning ochiq kalitini, ortidagi tarmoqlarni, endpoint va keepalive ni kiriting.
- **Tugun tafsilotlari:** ixtiyoriy pre-shared kalitlar va har bir tugun uchun jonli holat: onlayn, oxirgi handshake, endpoint va trafik.

Tugunlardagi oʻzgarishlar `wg syncconf` bilan qoʻllanadi, shuning uchun ulangan mijozlar uzilmaydi. Erkin shakldagi `PostUp` qatorlari yoʻq. VPN mijozlari uchun NAT (*Mehmon tarmoqlariga NAT*) va yoʻnaltirish pve-gateway ning iptables qoidalari hisoblanadi, WireGuard porti esa pve-gateway fayrvolida avtomatik ochiladi. Maxfiy kalitlar `/etc/pve-gateway/wireguard/` va `/etc/wireguard/` da (rejim 0600) saqlanadi; ular hech qachon `config.json`, API yoki diagnostika hisobotida koʻrinmaydi.

## Tarmoq: DHCP, IPAM va DNS (Proxmox SDN)

**Tarmoq** boʻlimi [Proxmox SDN](https://pve.proxmox.com/pve-docs/chapter-pvesdn.html) ni Proxmox API orqali boshqaradi, shuning uchun hamma narsa Proxmox UI dagi *Datacenter → SDN* ostida ham koʻrinadi. pve-gateway uning nusxasini saqlamaydi. Proxmox VE 8.1 yoki undan yangisi talab qilinadi.

- **Zonalar:** yangi zonalar *simple* zonalardir: shu xostdagi izolyatsiyalangan koʻpriklar, VLAN sozlash talab qilinmaydi. Har bir zona **DHCP** tarqatishi mumkin (Proxmox har bir zona uchun bitta dnsmasq ishga tushiradi; **dnsmasq ni oʻrnatish** tugmasi uni oʻrnatadi va standart nusxani oʻchirib qoʻyadi). Manzillarni Proxmox ning ichki IPAM i hisobga oladi. Proxmox UI da yaratilgan VLAN, VXLAN va EVPN zonalari roʻyxatda koʻrsatiladi, lekin tahrirlanmaydi.
- **VNet lar** VNet nomi bilan ataladigan koʻpriklarga aylanadi. Mehmon tizimni ulash uchun uning tarmoq qurilmasi koʻprigini VNet ga oʻrnating (*Hardware → Network Device → Bridge*). Boʻlim qaysi mehmon tizimlar qaysi VNet dan foydalanayotganini koʻrsatadi va hali mehmon tizimlari bor VNet ni oʻchirishni rad etadi.
- **Quyi tarmoqlar:** shlyuz (shu xostning VNet dagi manzili), **SNAT** (mehmon tizimlar internetga xost orqali chiqadi), DHCP diapazonlari va DHCP mijozlariga beriladigan DNS server. Xost tarmoqlari, boshqa quyi tarmoqlar yoki WireGuard tunnellari bilan kesishadigan quyi tarmoqlar rad etiladi.
- **IPAM:** Proxmox tarqatgan (mehmon tizim va xost nomi bilan) yoki rezerv qilgan barcha manzillar. **+ Rezervatsiya** IP manzilni MAC manzilga biriktiradi, MAC ni yozish oʻrniga mehmon tizimning NIC ini tanlashingiz mumkin.
- **DNS:** har bir zona uchun Proxmox SDN DNS plaginini (PowerDNS) va domenni tanlang, shunda Proxmox mehmon tizimlar nomlarini roʻyxatdan oʻtkazadi. Plaginning oʻzini Proxmox UI da qoʻshing (*Datacenter → SDN → Options*), shunda uning API kaliti Proxmox da qoladi; pve-gateway uni hech qachon oʻqimaydi va koʻrsatmaydi.

Oʻzgarishlar **SDN oʻzgarishlarini qoʻllash** tugmasini bosmaguningizcha Proxmox da kutilmoqda holatida turadi, xuddi Proxmox UI dagidek. Qoʻllash SDN tarmoqlarini qayta yuklaydi. pve-gateway fayrvoli yoqilgan boʻlsa, DHCP (UDP 67) faqat DHCP VNet larida ruxsat etiladi, hech qachon uplink da emas. Manzilini SDN DHCP dan olgan mehmon tizimlar tanlash vositasida IPAM orqali topiladi, shuning uchun Portlar boʻlimida ularga portlarni yoʻnaltirishingiz mumkin. Diagnostika boʻlimi dnsmasq, `source /etc/network/interfaces.d/*`, kutilayotgan oʻzgarishlar, VNet koʻpriklari va har bir zona DHCP serverlarini tekshiradi.

## Fayrvol

**Xavfsizlik → Fayrvol** xostning oʻzini (kiruvchi trafikni) himoya qiladi. Backend ni siz tanlaysiz:
- **pve-gateway**: iptables va ip6tables uchun oʻzining `PVEGW_IN` zanjiri, `INPUT` da birinchi boʻlib ulanadi.
- **Proxmox fayrvoli**: pve-gateway oʻz qoidalarini (izoh `pvegw: …`) Proxmox API orqali tugun fayrvolining eng yuqorisida yaratadi, shuning uchun ular Proxmox UI da ham koʻrinadi. Sizning Proxmox qoidalaringizga tegilmaydi va ular pastda roʻyxatda koʻrsatiladi.

Qoidalar tartiblangan **allow / drop / reject** yozuvlaridan iborat:
- protokol TCP, UDP, ICMP yoki istalgan;
- port roʻyxatlari va diapazonlari;
- ixtiyoriy manba tarmogʻi;
- izoh.

Standart siyosat — *qolgan hammasiga ruxsat berish* yoki *qolgan hammasini drop qilish*. Shablonlar keng tarqalgan toʻplamlarni qoʻshadi (web, mail, DNS, WireGuard, SSH, Proxmox, faqat xususiy tarmoqlardan maʼlumotlar bazalari). **Hozir ochiq xavfli portlar → faqat LAN** rpcbind yoki maʼlumotlar bazalari kabi xizmatlarni internetdan yashirish uchun ochiqlik tekshiruvidan foydalanadi.

**Oʻzingizni bloklab qoʻya olmaysiz:**
- **Har doim ochiq:** SSH, Proxmox UI (8006), pve-gateway ning oʻz porti (uning ruxsat etilgan manbalaridan), domenlaringiz boʻlsa 80/443, klasterlarda klaster portlari va oʻrnatilgan ulanishlar. 22/8006/UI porti uchun *hamma* ga nisbatan drop qoidasi rad etiladi.
- **Har bir oʻzgarish dastlab vaqtinchalik:** **Saqlab qolish** tugmasini bosish uchun **60 soniya** vaqtingiz bor. Agar sahifa serverga ulana olmay qolsa, oldingi fayrvol oʻz-oʻzidan qaytadi. Tasdiqlanmagan oʻzgarishlar hech qachon saqlanmaydi, shuning uchun qayta ishga tushirish ham eski qoidalarni qaytaradi.

## Fail2ban

**Xavfsizlik** boʻlimi fail2ban jail larini muvaffaqiyatsiz urinishlar va bloklashlar soni bilan koʻrsatadi. Barcha bloklangan IP lar bitta qidiriladigan roʻyxatda (IP, jail va xuddi shu tarmoqdan nechta bloklash borligi), **Roʻyxatni nusxalash** tugmasi bilan. Bitta IP ni yoki barchasini **blokdan chiqarish**, shuningdek IP ni qoʻlda **bloklash** mumkin (hech qachon oʻz IP manzilingiz yoki localhost emas). Agar fail2ban yoʻq boʻlsa, **fail2ban ni oʻrnatish** uni sozlaydi.

UI dan sozlash uchun *fail2ban ni pve-gateway boshqarsin* ni belgilang: bloklash vaqti, qidiruv vaqti, bloklashdan oldingi muvaffaqiyatsiz urinishlar soni, **hech qachon bloklanmasin** roʻyxati va quyidagi jail lar:
- **sshd**: SSH orqali kirishlar.
- **proxmox**: Proxmox veb UI ga (8006-port) muvaffaqiyatsiz kirishlar, jurnaldagi `pvedaemon` dan oʻqiladi.
- **pve-gateway**: ushbu UI ga muvaffaqiyatsiz kirishlar.
- **nginx-botsearch**: mavjud boʻlmagan sahifalarni qidirayotgan botlar. `/.well-known/acme-challenge/` ga soʻrovlar hech qachon hisobga olinmaydi, shuning uchun Let's Encrypt tekshiruv serverlari muvaffaqiyatsiz sertifikat urinishidan soʻng bloklanib qolmaydi.
- **recidive**: bir kun ichida yana bloklangan → bir haftaga bloklanadi.

pve-gateway `/etc/fail2ban/jail.d/pve-gateway.local` ni (oxirgi boʻlib oʻqiladi, shuning uchun `jail.local` ni ustidan yozadi) hamda oʻzining `pvegw-*` filtrlarini yozadi. Har bir oʻzgarish `fail2ban-client -t` bilan tekshiriladi va xato boʻlsa, oldingi fayllar tiklanadi. Belgini olib tashlash faylni oʻchiradi.

## Veb UI xavfsizligi

UI root sifatida ishlaydi, xostning fayrvoli va nginx ni oʻzgartira oladi hamda `root@pam` bilan kiradi. Uni internetga ochiq qoldirmang:

- **Kim ulanishi mumkinligini cheklang:** **Sozlamalar → Veb UI ga kirish** boʻlimiga oʻting va sahifani ochishga ruxsat berilgan IP/tarmoqlarni, masalan, ofis IP manzilingizni yoki VPN diapazonini kiriting. Qolganlar kirish formasiga yetib bormasdanoq rad etiladi.
  - Xostning oʻzidan (`localhost`, masalan, ssh tunnel orqali) ulanishlar har doim ishlaydi.
  - UI siz saqlayotgan IP manzilni bloklab qoʻyadigan roʻyxatni rad etadi.
  - ssh sessiyasidan: `pve-gateway ui-allow 203.0.113.7 10.20.0.0/24`, bekor qilish uchun esa `pve-gateway ui-allow any`.
- **Kirishni himoyalash:**
  - 5 marta muvaffaqiyatsiz kirishdan soʻng IP 15 daqiqaga bloklanadi.
  - Bir IP dan bir vaqtda faqat bitta kirish tekshiriladi, shuning uchun parallel taxmin qilish yordam bermaydi.
  - **Ikki faktorli (TOTP)** autentifikatsiyali Proxmox akkauntlari ishlaydi: kirishda kod soʻraladi.
- **Sessiyalar** ular yaratilgan IP va brauzerga bogʻlanadi, shuning uchun nusxalangan cookie boshqa joyda foydasiz. Brauzerlar cookie larni port boʻyicha ajratmaydi, shuning uchun aks holda xuddi shu xost IP manzilida ochgan mehmon tizim xizmatingiz uni koʻrishi mumkin edi.
- **Ruxsat etilgan Proxmox foydalanuvchilari:** standart holatda faqat `root@pam`. Boshqa foydalanuvchilarni **Sozlamalar** da qoʻshing (format `name@realm`).
- **Ochiqlik tekshiruvi:** Diagnostika boʻlimi barcha interfeyslarda tinglayotgan xavfli xizmatlar (rpcbind, maʼlumotlar bazalari, Redis, Docker API, VNC, …) va obunasiz yoqilgan enterprise repozitoriylari haqida ogohlantiradi.
- **Xost nomi tekshiruvi:** UI faqat IP manzillarga, shu xostning oʻz nomlariga va siz qoʻshgan xost nomlariga (Sozlamalar yoki `pve-gateway ui-host pve.example.com`) javob beradi. Bu DNS-rebinding hujumlarini toʻsadi.

## Konfiguratsiya: `/etc/pve-gateway/config.json`

Qoidalar ham shu yerda saqlanadi. Qoʻlda tahrirlagandan soʻng xizmatni qayta ishga tushiring.

```json
{
  "listen": "0.0.0.0",
  "port": 8099,
  "allowed_users": ["root@pam"],
  "protected_ports": ["22", "8006", "3128", "111", "5405-5412"],
  "forward_accept": true
}
```

- `allowed_users`: kirishga ruxsat berilgan Proxmox foydalanuvchilari. TFA yoqilgan akkauntlar qoʻllab-quvvatlanmaydi; buning oʻrniga `passwd` dan foydalaning.
- `forward_accept`: yoʻnaltirilgan oqimlar uchun `FORWARD` ga tor `ACCEPT` qoidalarini qoʻshadi. Ular `PVEFW-FORWARD` dan oldin qoʻyiladi, shuning uchun mehmon tizim uchun Proxmox fayrvoli yoqilgan boʻlsa, yoʻnaltirilgan port shu mehmon tizim fayrvolini chetlab oʻtadi. Kirishni cheklash uchun qoidaning *Ruxsat etilgan manba* maydonidan foydalaning.
- `listen`: UI ni ommaviy interfeysdan uzoqda saqlash uchun uni LAN IP ga (masalan, `192.168.1.10`) oʻrnating.
- `group` (har bir qoida va domenda): u roʻyxatda koʻrsatiladigan guruh; yoʻq yoki notoʻgʻri boʻlsa, `default` hisoblanadi.
- `locked` (har bir qoida va domenda): `true` uni UI va API dagi oʻzgarishlardan himoya qiladi.

## Ishonchli HTTPS (Let's Encrypt)

Standart holatda Proxmox oʻzi imzolagan sertifikatdan foydalanadi, shuning uchun brauzerlar `:8006` da ham, `:8099` da ham ogohlantirish koʻrsatadi. Proxmox ga haqiqiy sertifikat bering, shunda pve-gateway ham undan foydalanadi. Yangilangan sertifikatlar 5 daqiqa ichida qayta ishga tushirishsiz olinadi.

Quyida Cloudflare DNS dagi domen uchun misol keltirilgan. U DNS-01 challenge dan foydalanadi, shuning uchun 80-port ochiq boʻlishi shart emas. Zona uchun *Zone → DNS → Edit* huquqli Cloudflare API token yarating, soʻng xostda quyidagini bajaring:

```bash
pvenode acme account register default you@example.com --directory https://acme-v02.api.letsencrypt.org/directory
printf 'CF_Token=<token>\n' > /root/cf.env
pvenode acme plugin add dns cloudflare --api cf --data /root/cf.env && rm /root/cf.env
pvenode config set --acmedomain0 pve.example.com,plugin=cloudflare
pvenode acme cert order
```

## Zaxira nusxa va tiklash

**Sozlamalar → Zaxira nusxalar** pve-gateway biladigan hamma narsani bitta `.tar.gz` faylga saqlaydi:
- konfiguratsiya: qoidalar, domenlar, wildcard sertifikatlar, tekshiruvlar va ogohlantirishlar, fayrvol, fail2ban, VPN va sozlamalar;
- xohlasangiz undan tashqarida saqlanadigan maxfiy maʼlumotlar: DNS API kirish maʼlumotlari, WireGuard kalitlari, ogohlantirish tokenlari va parol xeshi. **Maxfiy maʼlumotli faylni maxfiy saqlang.**
- xohlasangiz domenlarning Let's Encrypt sertifikatlari.

Nusxalar xostda `/etc/pve-gateway/backups` da saqlanadi (papka 0700, fayllar 0600):
- qoʻlda yaratilgan nusxalar;
- **har kuni avtomatik nusxa** (oxirgi 7 tasi);
- **har bir tiklashdan oldin olinadigan himoya nusxasi**, shuning uchun tiklashni har doim bekor qilish mumkin.

Boshqa joyda saqlash uchun nusxani yuklab oling. pve-gateway ni yangi xostga koʻchirish ham shunday: u yerga oʻrnating, faylni yuklang va tiklang.

**Tiklash** nusxa tarkibini koʻrsatadi va qismlarni tanlash imkonini beradi: port qoidalari, domenlar va wildcard sertifikatlar, tekshiruvlar va ogohlantirishlar, fayrvol, fail2ban, VPN, veb interfeysga kirish, yangilanish sozlamalari. Qolgan hammasi oʻzgarmaydi.
- **Hech qachon tiklanmaydi:** xostga bogʻliq sozlamalar (port, interfeysning TLS sertifikati, fayl yoʻllari).
- **Fayrvol:** tiklangan va yoqilgan fayrvolni, har qanday fayrvol oʻzgarishi kabi, 60 s ichida tasdiqlash kerak.
- **Kirishdan mahrum boʻlishdan himoya:** kirishni yopib qoʻyadigan veb interfeys sozlamalari rad etiladi.
- **Xato boʻlsa:** qoʻllash muvaffaqiyatsiz boʻlsa (masalan, `nginx -t`), avvalgi konfiguratsiya va maxfiy fayllar qaytariladi.
- **Sertifikatlar:** faqat xostda yoʻq boʻlsa tiklanadi, shuning uchun mavjudlari hech qachon ustidan yozilmaydi.
- **Maxfiy maʼlumotlarsiz nusxalar:** xostda bor DNS kirish maʼlumotlari, WireGuard kalitlari va parol saqlanadi.

Yuklangan fayllar qatʼiy tekshiriladi: faqat maʼlum fayl nomlari, nusxadan tashqaridagi yoʻllar yoʻq, simvolik havolalar faqat certbot ning `live/` va `archive/` papkalari orasida.

## Oʻchirib tashlash

```bash
sh install.sh uninstall
```
