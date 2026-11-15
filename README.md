# GoVPN (WireGuard Engine) — `govpn-wg`

`govpn-wg` adalah daemon Go yang mengelola interface WireGuard kernel di Linux lewat REST API (JSON, JWT). Daemon ini berperan sebagai **hub**:

- **Site-to-Site (VPN-Hub)**: setiap *site* (jaringan remote dengan gateway Linux/Windows) mendapat interface WireGuard sendiri (`wg-s1`, `wg-s2`, …).
- **Client-to-Site**: klien perorangan masuk ke sebuah *group*. Satu group adalah satu interface bersama (`wg-c1`, …). Group `default` dibuat otomatis saat klien pertama dibuat.
- Isolasi antar-interface dan hak akses (site→site, client→site, akses ke LAN server, full tunnel) diterapkan memakai iptables di chain milik `govpn-wg` sendiri.

Modul: `github.com/ica4me/govpn-wg` · Status: lihat [docs/testing.md](docs/testing.md). Belum semua jalur jaringan terbukti di lingkungan nyata, jadi jangan anggap siap produksi.

Dokumen lain:
- [docs/api.md](docs/api.md): referensi REST API (route, body, respons, error).
- [docs/testing.md](docs/testing.md): apa yang sudah diuji dan apa yang belum.

---

## 1. Arsitektur singkat

```
cmd/govpn-wg/main.go        CLI: serve | tune | reconcile | teardown | hash-password | version
internal/config             parsing /etc/govpn/wg.env, state.json (atomic + .bak)
internal/engine             transaksi state -> kernel (clone, validasi, apply, persist)
internal/wireguard          netlink + wgctrl (kernel), Fake untuk test/dry-run, alokasi subnet/port
internal/firewall           render & apply iptables-restore (chain GOVPN-*)
internal/sysopt             tuning sysctl, modul kernel, NIC (ethtool)
internal/generator          file .conf wg-quick, skrip Linux site/klien, QR PNG
internal/api                REST API + JWT HS256
scripts/install.sh          installer Debian/Ubuntu
scripts/uninstall.sh        uninstaller
```

Setiap perubahan lewat API berjalan sebagai satu transaksi: *clone state → ubah → validasi → apply ke kernel (WireGuard + iptables) → simpan ke disk*. Kalau apply ke kernel gagal, state lama di-apply ulang dan API membalas `502`. Kalau penyimpanan ke disk gagal, kernel juga dikembalikan ke state lama.

Daemon juga melakukan *reconcile* (apply ulang state yang tersimpan) setiap 30 detik dan setiap menerima `SIGHUP` (`systemctl reload govpn-wg`). Reconcile memperbaiki interface yang terhapus, rule yang ter-flush, dan perubahan interface publik.

### Pengalamatan

| Item | Nilai (dari kode) |
|---|---|
| Pool tunnel | `172.31.201.0/24` – `172.31.250.0/24`. Satu `/24` acak per interface, jadi maksimal 50 interface (site + group). |
| Alamat hub | `.1` di setiap subnet interface |
| Alamat site | `.2` |
| Alamat klien | `.2` – `.254` di subnet group (maksimal 253 klien per group) |
| Port UDP | mulai dari `GOVPN_BASE_PORT` (default `3478`), lalu port bebas terendah berikutnya untuk tiap interface baru. Port yang sudah dipakai di host (`/proc/net/udp`, `/proc/net/udp6`) dilewati. |
| Nama interface | `wg-sN` (site), `wg-cN` (group) |
| ID objek | *slug* dari nama/username, contoh `"Site A"` → `site-a`, `"budi.s"` → `budi-s` |

Subnet pool tidak dipakai kalau bentrok dengan route atau alamat yang sudah ada di kernel, LAN site, atau `GOVPN_SERVER_LAN`. Validasi juga menolak LAN yang saling tumpang tindih.

### Dataplane hanya IPv4

Kode hanya mengelola IPv4:
- Alamat interface, route LAN site, dan AllowedIPs di sisi hub semuanya IPv4 (`ParseCIDR4` menolak CIDR IPv6 dan `/0`).
- Firewall hanya memakai `iptables` (IPv4). Tidak ada aturan `ip6tables`.
- Deteksi interface publik dan endpoint memakai default route IPv4.

Tuning bawaan hanya menyalakan forwarding IPv4; tidak lagi menyalakan forwarding IPv6. Pengaturan `accept_ra=2` tetap dipakai untuk menjaga penerimaan RA pada host cloud. Ini tidak menambah dukungan tunnel IPv6 dan tidak otomatis membatalkan nilai forwarding IPv6 dari konfigurasi lama atau override admin.

### Full tunnel dan `::/0`

Untuk `tunnel_mode: "full"`, file `.conf` yang dihasilkan berisi `AllowedIPs = 0.0.0.0/0, ::/0`.

- **Di sisi klien** (wg-quick / aplikasi WireGuard): `::/0` membuat trafik IPv6 klien ikut masuk ke tunnel. Peer klien di hub hanya punya AllowedIPs `<ip-klien>/32` (IPv4), sehingga WireGuard di hub membuang paket IPv6 dari klien. Hasilnya, IPv6 diblokir alih-alih bocor keluar di luar tunnel. Perilaku ini mengikuti kode, tetapi **belum diverifikasi di jaringan nyata** (lihat testing.md).
- **Di gateway site Linux** (skrip `download/linux`), mode full memakai `Table = off` dan `route.sh` yang hanya memasang policy routing `ip -4`. `::/0` tetap ada di AllowedIPs, tetapi tidak ada route IPv6 ke tunnel. Jadi trafik IPv6 site **tidak** dibelokkan atau diblokir oleh skrip ini.
- Di hub, trafik full tunnel ke tujuan non-publik (RFC1918, CGNAT, loopback, link-local, dokumentasi, multicast, dll.) di-DROP kecuali ada grant eksplisit sebelumnya. Sisanya di-ACCEPT keluar lewat interface publik dan di-MASQUERADE. Kalau interface publik tidak terdeteksi, aturan full tunnel tidak dibuat dan trafik jatuh ke DROP.

### Port UDP 3478 BUKAN penyamaran STUN

Port default `3478` hanya angka port. Di IANA port ini terdaftar untuk STUN/TURN, tetapi:

- `govpn-wg` **tidak** membungkus, mengobfuscate, atau menyamarkan paket WireGuard sebagai STUN. Paket yang lewat adalah protokol WireGuard standar.
- DPI atau firewall yang memeriksa isi paket tetap bisa mengenali dan memblokir WireGuard.
- Port ini mungkin lolos dari firewall yang hanya memfilter berdasarkan nomor port, tetapi itu tidak dijamin.
- Port ini bisa bentrok dengan server STUN/TURN sungguhan (misalnya coturn) di host yang sama. Allocator melewati port yang sedang terikat saat interface dibuat.

Ganti dengan `--port` atau `GOVPN_BASE_PORT` sesuai kebutuhan. Buka rentang port UDP mulai dari base port sebanyak jumlah interface di firewall penyedia/host. Paket UDP WireGuard pada interface publik tetap mengikuti firewall INPUT host; jump `GOVPN-IN` hanya membatasi trafik yang masuk dari tunnel.

### Firewall (iptables)

Empat chain milik sendiri dikelola; jump pada chain bawaan juga dipasang/diperbaiki. Semuanya dimuat dengan satu `iptables-restore --noflush` (diuji dulu dengan `--test`):

| Tabel | Chain | Jump dari |
|---|---|---|
| filter | `GOVPN-FWD` | `FORWARD` (posisi 1) |
| filter | `GOVPN-IN` | `INPUT` (posisi 1) |
| nat | `GOVPN-POST` | `POSTROUTING` |
| mangle | `GOVPN-MSS` | `FORWARD` (clamp TCP MSS) |

Aturan per interface: ESTABLISHED/RELATED diterima, INVALID di-DROP, lalu grant eksplisit, lalu aturan full tunnel, lalu **DROP** untuk semua trafik lain yang masuk dari interface tersebut. Trafik yang di-route **ke** interface tunnel juga di-DROP kecuali cocok dengan grant atau conntrack.

- Grant bersifat satu arah dari sisi yang memulai koneksi. Balasannya lewat conntrack. Site tidak bisa memulai koneksi ke klien.
- Akses ke `GOVPN_SERVER_LAN` di-MASQUERADE kalau `GOVPN_LAN_NAT=1` (default), jadi host LAN tidak perlu route balik.
- Trafik site↔site dan client→site **tidak** di-NAT di hub. Skrip gateway site memasang masquerade sendiri (nftables, tabel `inet govpn_site`) ke arah LAN site.
- `GOVPN-IN` membatasi trafik tunnel→hub sendiri: hanya RELATED/ESTABLISHED dan ICMP echo-request (ping) yang diterima; trafik lain di-DROP. Ini berlaku juga ke IP LAN milik hub. Grant server LAN hanya mengizinkan **forwarding ke perangkat lain**, bukan akses baru ke SSH, API, DNS, atau layanan lokal hub.
- Catch-all untuk pola interface `wg-s+`/`wg-c+` tetap menutup trafik tanpa grant, termasuk ketika state kosong. Reconcile memulihkan isi chain dan posisi jump; pengujian kernel terbatas dijelaskan di testing.md, bukan bukti isolasi trafik peer.
- MSS: `GOVPN_MSS_MODE=mtu` → set MSS ke `MTU-40` (hanya menurunkan, tidak pernah menaikkan). `pmtu` → `--clamp-mss-to-pmtu`.

Field `hub_nat` memang ada di `state.json`, tetapi tidak bisa diatur lewat API dan tidak dipakai saat membangun rule. Anggap field ini belum berfungsi.

---

## 2. Persyaratan

- Debian 12/13 atau Ubuntu 22.04+ (dicek oleh installer). Butuh akses root.
- Kernel dengan modul `wireguard` (Linux ≥ 5.6).
- `iptables` dan `iptables-restore` (dicek saat start. Hanya backend `iptables` yang didukung).
- Go: `go.mod` menyatakan `go 1.27.4`. Installer menerima Go ≥ 1.24 yang sudah terpasang. Kalau versinya lebih rendah dari 1.27.4, build bergantung pada mekanisme toolchain Go (GOTOOLCHAIN) dan bisa gagal tanpa akses internet. Kalau Go tidak ada sama sekali, installer mengunduh versi terbaru dari `go.dev` ke `/usr/local/go`.

## 3. Instalasi

Jalankan dari checkout repositori:

```bash
# interaktif
sudo bash scripts/install.sh

# non-interaktif
sudo bash scripts/install.sh --yes \
  --admin-user admin --admin-password 'ganti-password-ini' \
  --port 3478 --mtu 1360 --server-lan 10.10.9.0/24 --api 127.0.0.1:8080
```

Opsi (`scripts/install.sh --help`):

| Opsi | Arti | Default |
|---|---|---|
| `--port N` | port UDP WireGuard pertama | `3478` |
| `--mtu N` | MTU default (1280–9000) | `1360` |
| `--server-lan CIDRS` | LAN di belakang server, dipisah koma (`""`/`none` = tidak ada) | hasil deteksi |
| `--api ADDR:PORT` | alamat listen REST API | `127.0.0.1:8080` |
| `--endpoint HOST` | IP/hostname publik yang ditulis ke config peer | auto (deteksi runtime) |
| `--admin-user NAME` | username admin API | `admin` |
| `--admin-password PW` | password admin (min. 8 karakter) | ditanya / dibuat acak |
| `--tune` / `--no-tune` | tuning kernel + NIC saat install dan setiap start | ya |
| `--mss mtu\|pmtu` | mode clamp MSS | `mtu` |
| `--yes`, `-y` | non-interaktif | – |
| `--skip-build` | pakai `./bin/govpn-wg` yang sudah ada | – |

Yang dilakukan installer:
1. Cek root, keberadaan `go.mod`, dan OS Debian/Ubuntu. Kalau stdin bukan TTY, mode otomatis menjadi `--yes`.
2. Deteksi interface/IP publik (`ip -4 route get 1.1.1.1`) dan LAN lain sebagai default `--server-lan`.
3. Ambil nilai lama dari `/etc/govpn/wg.env` kalau ada. Install ulang aman: state, key, dan `jwt.key` dipertahankan.
4. `apt-get install` paket `ca-certificates curl iproute2 iptables ethtool kmod wireguard-tools tar`, lalu `modprobe wireguard`.
5. Build statis (`CGO_ENABLED=0`, `-trimpath`, versi dari `git describe`) → `bin/govpn-wg`, dipasang ke `/opt/govpn/wg/govpn-wg` dengan symlink `/usr/local/bin/govpn-wg`. `uninstall.sh` ikut disalin ke `/opt/govpn/wg/`.
6. Hash password dengan bcrypt (cost 12) lewat `govpn-wg hash-password` (dikirim via stdin).
7. Tulis `/etc/govpn/wg.env` (mode 600) dan unit `/etc/systemd/system/govpn-wg.service`.
8. Kalau tuning aktif, jalankan `govpn-wg tune` dan simpan hasilnya ke `/var/lib/govpn/wg/tune-report.json`.
9. `systemctl enable` + `restart`, lalu tunggu `GET /api/v1/health` sampai 30 detik.
10. Tampilkan ringkasan. Password yang dibuat otomatis **hanya ditampilkan sekali**.

Catatan keamanan: `--admin-password` di command line bisa terlihat di riwayat shell dan daftar proses. Untuk mesin bersama, lebih baik pakai prompt interaktif.

Unit systemd: `ExecStartPre=/sbin/modprobe wireguard`, `Restart=on-failure`, `ProtectSystem=full`, `ReadWritePaths=/var/lib/govpn/wg /etc/sysctl.d /etc/modules-load.d /run`, `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`. Unit tidak menetapkan `User=`, jadi service berjalan sebagai root. Saat service berhenti, tunnel **tetap hidup** (interface dan rule tidak dihapus).

### Perhatian administrator pada host cloud

Pada investigasi sebelumnya, penambahan/penghapusan interface WireGuard virtual memicu `/usr/lib/cloud-init/hook-hotplug`, lalu terlihat DHCP berulang pada `ens3`. Ini bukti rangkaian kejadian, **bukan pembuktian bahwa cloud-init adalah penyebab tunggal hilangnya akses**. Periksa kebijakan hotplug cloud-init dan pengelola jaringan sebelum operasi interface; siapkan konsol out-of-band serta backup route/firewall. Jangan menonaktifkan layanan jaringan atau hotplug secara membabi buta melalui satu-satunya sesi SSH.

Pada akhir verifikasi ini server tetap dihentikan dan tidak ada deployment baru. Test namespace tidak membuktikan bahwa risiko operasional host cloud telah selesai; lihat [testing.md](docs/testing.md).

### Uninstall

```bash
sudo bash /opt/govpn/wg/uninstall.sh           # hapus service, interface wg-s*/wg-c*, chain GOVPN-*, binary
sudo bash /opt/govpn/wg/uninstall.sh --purge   # juga hapus /etc/govpn dan /var/lib/govpn/wg (KEY HILANG)
```

File `/etc/sysctl.d/99-govpn-wg.conf` dan `/etc/modules-load.d/govpn-wg.conf` ikut dihapus, tetapi nilai sysctl yang sudah aktif tetap berlaku sampai reboot.

## 4. CLI

```
govpn-wg serve        [-config /etc/govpn/wg.env]   jalankan REST API + engine
govpn-wg tune         [-config ...] [-dry-run]      tuning kernel + NIC, cetak laporan JSON
govpn-wg reconcile    [-config ...]                 apply state sekali lalu keluar
govpn-wg teardown     [-config ...]                 hapus semua interface & rule govpn-wg
govpn-wg hash-password                              baca password (TTY/stdin), cetak hash bcrypt
govpn-wg version
```

Path config juga bisa diatur lewat env `GOVPN_CONFIG`.

## 5. Konfigurasi (`/etc/govpn/wg.env`)

Format `KEY=VALUE`, baris `#` adalah komentar, kutip tunggal/ganda opsional, prefix `export` diizinkan. Variabel environment proses menimpa nilai di file. Ubah file, lalu jalankan `systemctl restart govpn-wg`.

| Variabel | Default | Keterangan |
|---|---|---|
| `GOVPN_LISTEN` | `127.0.0.1:8080` | alamat listen API (HTTP biasa, tanpa TLS) |
| `GOVPN_DATA_DIR` | `/var/lib/govpn/wg` | `state.json`, `jwt.key` (harus path absolut) |
| `GOVPN_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `GOVPN_ADMIN_USER` | `admin` | |
| `GOVPN_ADMIN_PASSWORD_HASH` | – | bcrypt, **wajib** untuk `serve` |
| `GOVPN_TOKEN_TTL` | `12h` | durasi Go |
| `GOVPN_ENDPOINT` | auto | IP/hostname di config peer. Auto = IPv4 global di interface default route |
| `GOVPN_PUBLIC_IF` | auto | interface egress full tunnel |
| `GOVPN_BASE_PORT` | `3478` | |
| `GOVPN_DEFAULT_MTU` | `1360` | 1280–9000 |
| `GOVPN_DNS` | `1.1.1.1` | DNS default klien, maks. 4, dipisah koma |
| `GOVPN_KEEPALIVE` | `25` | PersistentKeepalive di config peer (0–3600) |
| `GOVPN_SERVER_LAN` | kosong | CIDR IPv4 di belakang hub yang bisa diberikan aksesnya |
| `GOVPN_LAN_NAT` | `1` | MASQUERADE ke server LAN |
| `GOVPN_MSS_MODE` | `mtu` | `mtu` atau `pmtu` |
| `GOVPN_TUNE_ON_START` | `1` | tuning setiap `serve` start. Kalau `0`, hanya `ip_forward` yang dinyalakan |
| `GOVPN_TUNE_NIC` | `1` | tuning ethtool |
| `GOVPN_NIC_RING` | `max` | `max` atau `skip` |
| `GOVPN_SYSCTL_EXTRA` | kosong | `k=v;k=v` tambahan/override |
| `GOVPN_FIREWALL` | `iptables` | satu-satunya nilai valid |
| `GOVPN_DRY_RUN` | `0` | `1` = kernel & firewall disimulasikan (Fake), untuk test |

Kalau endpoint tidak diketahui (deteksi gagal dan `GOVPN_ENDPOINT` kosong), download config membalas `409`.

## 6. Tuning (`govpn-wg tune` / `POST /api/v1/system/tune`)

Prosesnya best-effort. Setiap langkah dilaporkan sebagai `applied`, `unchanged`, `unsupported`, `failed`, atau `skipped`, dan tidak ada yang dipalsukan.

- **Modul**: `wireguard tcp_bbr sch_fq nf_conntrack xt_TCPMSS iptable_mangle iptable_nat` (di-persist ke `/etc/modules-load.d/govpn-wg.conf`).
- **sysctl**: forwarding IPv4 (bukan IPv6), `rp_filter=2`, redirect off, `accept_ra=2`, `default_qdisc=fq`, `tcp_congestion_control=bbr` (hanya kalau tersedia), buffer socket/UDP, `tcp_mtu_probing=1`, conntrack (skala RAM: sekitar 256 entri per MiB, dibatasi 65536–1048576), dan lainnya. Hanya key yang diterima kernel yang ditulis ke `/etc/sysctl.d/99-govpn-wg.conf`.
- **NIC** (interface publik): ring buffer ke batas maksimum hardware, GRO/GSO/TSO on, `rx-udp-gro-forwarding` on, `rx-gro-list` off, `txqueuelen` 10000.

Catatan: BBR mengatur congestion control untuk koneksi TCP yang berakhir di host ini. Trafik yang hanya diteruskan (forward) lewat tunnel tidak memakai algoritma congestion control hub.

## 7. Artefak untuk peer

| Endpoint | Isi |
|---|---|
| `GET /api/v1/sites/{id}/download/linux` | `install-site-<id>.sh`: skrip gateway Debian/Ubuntu. Interface `wg-hub`, nftables MSS + masquerade ke LAN site, `net.ipv4.ip_forward=1`, `rp_filter=2`, unit `govpn-site-nat.service`, `wg-quick@wg-hub`. Mode full: `Table=off` + `/etc/govpn-site/route.sh` (policy routing IPv4, tabel/fwmark 51820). Ada opsi `--uninstall`. |
| `GET /api/v1/sites/{id}/download/windows` atau `/conf` | `site-<id>.conf` (format wg-quick / aplikasi WireGuard) |
| `GET /api/v1/clients/{id}/download/linux` | `config-<username>.sh`: pasang `wireguard-tools` (+`openresolv` kalau ada DNS dan belum ada resolver, `nftables` untuk mode full kalau belum ada), tulis `/etc/wireguard/govpn.conf`, `wg-quick@govpn`. Ada opsi `--uninstall`. |
| `GET /api/v1/clients/{id}/download/conf` | `<username>.conf` |
| `GET /api/v1/clients/{id}/download/qr` | PNG QR dari isi `.conf` |

DNS pada artefak klien disaring oleh `effectiveDNS`: mode split hanya menulis resolver yang berada di dalam AllowedIPs, sedangkan mode full mempertahankan semua DNS yang dikonfigurasi. Jika tidak ada DNS efektif, baris `DNS` dihilangkan dan skrip Linux tidak memasang shim resolver. Ini tidak menambah grant firewall; resolver pada hub sendiri tetap dibatasi oleh `GOVPN-IN`.

Semua artefak ini **berisi private key dan PSK**. Kirim lewat kanal aman, simpan dengan mode 600, dan hapus setelah dipakai.

## 8. File, secret, dan backup

| Path | Isi | Sensitif |
|---|---|---|
| `/etc/govpn/wg.env` (600) | konfigurasi + hash bcrypt admin | ya |
| `/var/lib/govpn/wg/state.json` (600) | **seluruh** state: private key server tiap interface, private key peer site, private key klien, semua PSK | **sangat** |
| `/var/lib/govpn/wg/state.json.bak` (600) | salinan state sebelum penulisan terakhir | **sangat** |
| `/var/lib/govpn/wg/jwt.key` (600) | key HMAC 64 byte untuk JWT | ya |
| `/var/lib/govpn/wg/tune-report.json` | laporan tuning terakhir dari installer | tidak |
| `/etc/sysctl.d/99-govpn-wg.conf`, `/etc/modules-load.d/govpn-wg.conf` | hasil tuning | tidak |
| `/opt/govpn/wg/` | binary + uninstall.sh | tidak |

Backup minimal: `/etc/govpn/wg.env` dan `/var/lib/govpn/wg/state.json` (opsional juga `jwt.key`). Contoh:

```bash
sudo tar -C / -czf govpn-wg-backup-$(date +%F).tgz etc/govpn var/lib/govpn/wg
sudo chmod 600 govpn-wg-backup-*.tgz
```

Arsip ini berisi semua private key. Enkripsi arsipnya (misalnya `gpg -c` atau `age`) dan simpan di luar server. Siapa pun yang memegang `state.json` bisa menyamar sebagai hub atau peer mana pun.

Restore: hentikan service, kembalikan file ke path yang sama (pemilik root, mode 600), lalu start service. Saat start, state di-apply ulang ke kernel. Kalau IP publik server berubah, set `GOVPN_ENDPOINT` dan bagikan ulang config peer. Kalau `state.json` rusak, daemon menolak start dan menyarankan memakai `state.json.bak`. `state.json` yang ditulis versi lebih baru juga ditolak.

Menghapus `jwt.key` lalu restart service membatalkan semua token yang sudah terbit. Key baru dibuat otomatis.

## 9. Keamanan API

- Default-nya API hanya listen di loopback `127.0.0.1:8080` lewat HTTP **tanpa TLS**. Akses dari jauh sebaiknya lewat SSH tunnel atau reverse proxy TLS. Jangan bind ke IP publik tanpa perlindungan.
- Satu akun admin. Token JWT HS256, TTL default 12 jam. Tidak ada endpoint logout atau revoke, dan tidak ada refresh token.
- Rate limit login: 10 percobaan per menit per IP remote (`RemoteAddr`). Login yang berhasil mereset hitungannya. Di belakang reverse proxy, semua klien terlihat sebagai IP proxy.
- Body JSON dibaca secara ketat: field tak dikenal dan data sisa setelah objek ditolak (`400`), ukuran maksimal 64 KiB.
- Respons API untuk site/klien/group tidak memuat private key atau PSK. Secret hanya ada di artefak download.

Detail endpoint ada di [docs/api.md](docs/api.md).

## 10. Pengembangan

```bash
go test ./...
go vet ./...
GOVPN_DRY_RUN=1 GOVPN_DATA_DIR=/tmp/govpn GOVPN_ADMIN_PASSWORD_HASH="$(echo 'password123' | go run ./cmd/govpn-wg hash-password)" \
  go run ./cmd/govpn-wg serve -config ""
```

Dengan `GOVPN_DRY_RUN=1`, kernel dan firewall disimulasikan, jadi tidak ada interface atau rule yang dibuat. Tuning juga berjalan sebagai dry-run.
