# Instalasi & Konfigurasi

Ringkasan langkah ada di [README utama](../README.md#instalasi-linux-fresh). Dokumen ini berisi detail lengkapnya.

## Persyaratan

- Debian 12/13 atau Ubuntu 22.04+, akses root.
- Kernel Linux ≥ 5.6 dengan modul `wireguard`.
- Akses internet saat instalasi untuk `apt` dan unduhan Go.
- Port UDP terbuka di firewall provider, mulai dari port pertama (default `3478`).

## Opsi `scripts/install.sh`

| Opsi | Fungsi | Default |
|---|---|---|
| `--port N` | port UDP WireGuard pertama; interface baru mengambil port bebas berikutnya | `3478` |
| `--mtu N` | MTU default (1280–9000) | `1360` |
| `--server-lan CIDRS` | LAN di belakang server, dipisah koma; `none` = tidak ada | hasil deteksi NIC selain NIC publik |
| `--api ADDR:PORT` | alamat listen REST API | `127.0.0.1:8080` |
| `--endpoint HOST` | IP/hostname publik di config peer; `auto` = deteksi saat runtime | `auto` |
| `--admin-user NAME` | username admin API | `admin` |
| `--admin-password PW` | password admin (min. 8 karakter); fresh install tanpa password memakai bootstrap `admin` (segera ganti), reinstall mempertahankan password | – |
| `--tune` / `--no-tune` | tuning kernel + NIC saat install dan setiap service start | `--tune` |
| `--mss mtu\|pmtu` | mode clamp TCP MSS | `mtu` (MSS = MTU − 40) |
| `--yes`, `-y` | non-interaktif; nilai yang tidak diberikan memakai default/nilai lama | – |
| `--skip-build` | pakai `./bin/govpn-wg` yang sudah ada, tanpa compile | – |

Catatan:
- Installer **aman dijalankan ulang**. Nilai yang tidak diberikan tetap memakai nilai lama dari `/etc/govpn/wg.env`, dan state, key, serta `jwt.key` tidak disentuh.
- `--admin-password` di command line bisa tersimpan di riwayat shell. Di mesin bersama, pakai prompt interaktif.

Yang dilakukan installer:
1. Cek root, OS, dan checkout source.
2. Deteksi NIC/IP publik dan LAN server.
3. `apt-get install` paket yang dibutuhkan, lalu `modprobe wireguard`.
4. Pasang Go kalau belum ada, lalu compile binary statis.
5. Pasang binary ke `/opt/govpn/wg/govpn-wg`.
6. Tulis `/etc/govpn/wg.env` (mode 600) dan unit systemd `govpn-wg.service`.
7. Jalankan tuning (kalau aktif).
8. Start service, lalu tunggu `GET /api/v1/health` siap.

## Mengubah port / pengaturan

```bash
cd /root/govpn-wg
bash scripts/install.sh --yes --port 51820            # ganti port pertama
bash scripts/install.sh --yes --server-lan 10.10.9.0/24,172.16.50.0/24
```

`--port` hanya mengubah port **awal** untuk interface yang dibuat setelahnya. Untuk memindahkan port site/group yang sudah ada, pakai API (`PUT /sites/{id}` atau `PUT /groups/{id}` dengan field `port`), lalu bagikan ulang config peer-nya.

## `/etc/govpn/wg.env`

Format `KEY=VALUE`. Setelah diubah, jalankan `systemctl restart govpn-wg`. Restart service tidak menghapus tunnel.

| Variabel | Default | Keterangan |
|---|---|---|
| `GOVPN_LISTEN` | `127.0.0.1:8080` | alamat REST API (HTTP, tanpa TLS) |
| `GOVPN_DATA_DIR` | `/var/lib/govpn/wg` | `state.json`, `jwt.key` |
| `GOVPN_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `GOVPN_ADMIN_USER` | `admin` | username admin |
| `GOVPN_ADMIN_PASSWORD_HASH` | – | hash bcrypt (wajib); buat dengan `govpn-wg hash-password` |
| `GOVPN_TOKEN_TTL` | `12h` | umur token JWT (5m–168h) |
| `GOVPN_ENDPOINT` | kosong = auto | IP/hostname publik di config peer |
| `GOVPN_PUBLIC_IF` | kosong = auto | NIC publik untuk NAT internet |
| `GOVPN_BASE_PORT` | `3478` | port UDP pertama |
| `GOVPN_DEFAULT_MTU` | `1360` | MTU default |
| `GOVPN_DNS` | `1.1.1.1` | DNS default client (maks. 4, dipisah koma) |
| `GOVPN_KEEPALIVE` | `25` | `PersistentKeepalive` di config peer |
| `GOVPN_SERVER_LAN` | kosong | LAN di belakang server yang boleh diberikan aksesnya |
| `GOVPN_LAN_NAT` | `1` | MASQUERADE trafik tunnel ke server LAN, jadi LAN tidak perlu route balik |
| `GOVPN_MSS_MODE` | `mtu` | `mtu` atau `pmtu` |
| `GOVPN_TUNE_ON_START` | `1` | tuning setiap service start |
| `GOVPN_TUNE_NIC` | `1` | tuning ethtool NIC publik |
| `GOVPN_NIC_RING` | `max` | `max` atau `skip` |
| `GOVPN_SYSCTL_EXTRA` | kosong | sysctl tambahan, format `k=v;k=v` |

Contoh lengkap: [`wg.env.example`](../wg.env.example).

## CLI

```
govpn-wg serve       [-config /etc/govpn/wg.env]   jalankan engine + REST API (dipakai systemd)
govpn-wg tune        [-config ...] [-dry-run]      tuning kernel + NIC, cetak laporan JSON
govpn-wg reconcile   [-config ...]                 apply ulang state sekali
govpn-wg teardown    [-config ...]                 hapus semua interface & rule GoVPN
govpn-wg hash-password                             baca password dari stdin, cetak hash bcrypt
govpn-wg version
```

Ganti password admin melalui [POST /auth/password](api/auth.md) (disarankan). Hash API tersimpan di `GOVPN_DATA_DIR/admin-password.hash` dan mengalahkan hash env. Untuk reset manual, stop service dan hapus override tersebut setelah mengganti hash env, lalu restart.

Reset hash env:

```bash
HASH=$(govpn-wg hash-password)        # ketik password baru
sed -i "s|^GOVPN_ADMIN_PASSWORD_HASH=.*|GOVPN_ADMIN_PASSWORD_HASH='$HASH'|" /etc/govpn/wg.env
systemctl restart govpn-wg
```

## Tuning

Prosesnya *best-effort*. Setiap langkah dilaporkan sebagai `applied`, `unchanged`, `unsupported`, `failed`, atau `skipped`. Hasilnya disimpan di `/etc/sysctl.d/99-govpn-wg.conf` dan `/var/lib/govpn/wg/tune-report.json`.

- **sysctl:**
  - forwarding IPv4 (IPv6 forwarding tidak diubah)
  - `rp_filter=2`, redirect off
  - BBR + fq (kalau kernel mendukung)
  - buffer socket/UDP
  - conntrack (ukuran disesuaikan dengan RAM)
- **NIC publik:** ring buffer maksimum, GRO/GSO/TSO, `rx-udp-gro-forwarding`, `txqueuelen`.

## File & backup

| Path | Isi |
|---|---|
| `/opt/govpn/wg/` | binary + `uninstall.sh` |
| `/etc/govpn/wg.env` (600) | konfigurasi + hash password admin |
| `/var/lib/govpn/wg/state.json` (600) | **semua private key dan PSK**, beserta data site/group/client |
| `/var/lib/govpn/wg/state.json.bak` (600) | salinan state sebelumnya |
| `/var/lib/govpn/wg/jwt.key` (600) | kunci tanda tangan JWT |
| `/etc/systemd/system/govpn-wg.service` | unit systemd |

Backup:

```bash
tar -C / -czf govpn-backup-$(date +%F).tgz etc/govpn var/lib/govpn/wg
chmod 600 govpn-backup-*.tgz
```

Arsip ini berisi semua private key. Enkripsi arsipnya dan simpan di luar server.

Untuk restore: hentikan service, kembalikan file ke path yang sama, lalu start service lagi.

Menghapus `jwt.key` lalu restart akan membatalkan semua token yang sudah terbit.

## Update

```bash
cd /root/govpn-wg && git pull && bash scripts/install.sh --yes
```

## Uninstall

```bash
bash /opt/govpn/wg/uninstall.sh          # service, interface wg-s*/wg-c*, chain GOVPN-*, binary
bash /opt/govpn/wg/uninstall.sh --purge  # + /etc/govpn dan /var/lib/govpn/wg (semua key hilang)
```

## Akses API dari luar server

API memakai HTTP tanpa TLS dan default-nya hanya listen di loopback. Gunakan salah satu cara berikut:
- SSH tunnel: `ssh -L 8080:127.0.0.1:8080 root@IP-SERVER`
- reverse proxy dengan TLS (nginx/caddy) di depan `127.0.0.1:8080`

Jangan bind API langsung ke IP publik.
