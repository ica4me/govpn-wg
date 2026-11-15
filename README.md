# GoVPN — WireGuard Engine (`govpn-wg`)

Engine VPN WireGuard berbasis Go untuk Linux, dikendalikan lewat REST API (JSON + JWT). Tanpa UI. Gratis dan open source untuk pemakaian individu.

- **VPN Hub / Site-to-Site** — tiap site (kantor/cabang) dapat interface WireGuard sendiri (`wg-s1`, `wg-s2`, …).
- **Client-to-Site** — client (laptop/HP) masuk ke *group*; satu group = satu interface (`wg-c1`, …).
- Subnet tunnel `/24` acak dari `172.31.201.0`–`172.31.250.0`, dicek agar tidak bentrok.
- Akses diatur per site/client dengan iptables. Defaultnya ditolak, kecuali diberi izin.
- Config client default **split-tunnel**, jadi internet client tetap lewat jalur aslinya. Server juga sudah menyiapkan NAT internet, sehingga client bisa pindah ke **full-tunnel** cukup dengan mengubah `.conf`-nya sendiri.
- Hanya IPv4. IPv6 dimatikan di setiap interface tunnel, sedangkan IPv6 host tidak diubah.
- Engine tidak menambah, menghapus, atau mengganti default gateway server.
- Perubahan lewat API diterapkan langsung tanpa restart interface.

> Status: masih tahap pengujian. Lihat [docs/testing.md](docs/testing.md) sebelum dipakai di produksi.

---

## Instalasi (Linux fresh)

Didukung: **Debian 12/13** dan **Ubuntu 22.04+**, kernel ≥ 5.6 (modul `wireguard`). Semua perintah dijalankan sebagai root.

### 1. Update sistem

```bash
apt update && apt -y upgrade
```

### 2. Pasang paket dasar

```bash
apt -y install git curl ca-certificates
```

Paket lain (`wireguard-tools`, `iptables`, `iproute2`, `ethtool`, dan sebagainya) dipasang otomatis oleh installer. Go juga diunduh otomatis kalau belum ada, jadi tidak perlu dipasang manual.

### 3. Ambil source code

```bash
cd /root
git clone https://github.com/ica4me/govpn-wg.git
cd govpn-wg
```

### 4. (VM cloud) Pasang pengaman cloud-init — disarankan

Pada image cloud (OpenStack, dan sejenisnya), cloud-init memproses **setiap** interface baru, termasuk interface WireGuard. Akibatnya DHCP di NIC publik bisa berjalan ulang dan route server berubah. Script berikut mengecualikan interface GoVPN saja. Hotplug untuk NIC fisik tetap berjalan seperti biasa.

```bash
bash deploy/cloud-init-guard.sh
```

Script ini aman dijalankan berulang. Kalau rule cloud-init tidak ada, script langsung keluar tanpa mengubah apa pun.

### 5. Jalankan installer

Mode interaktif (semua nilai ditanyakan):

```bash
bash scripts/install.sh
```

Atau langsung tentukan nilainya, misalnya mengganti port:

```bash
bash scripts/install.sh --yes \
  --port 51820 \
  --mtu 1360 \
  --server-lan 10.10.9.0/24 \
  --admin-user admin
```

Opsi yang sering dipakai:

| Opsi | Fungsi | Default |
|---|---|---|
| `--port N` | port UDP WireGuard pertama. Interface berikutnya memakai port selanjutnya (N+1, N+2, …) | `3478` |
| `--mtu N` | MTU default tunnel | `1360` |
| `--server-lan CIDR,...` | LAN di belakang server yang boleh diakses site/client (`none` = tidak ada) | hasil deteksi |
| `--api ADDR:PORT` | alamat REST API | `127.0.0.1:8080` |
| `--endpoint HOST` | IP/hostname publik yang ditulis ke config peer | otomatis |
| `--admin-user NAME` | username admin API | `admin` |
| `--admin-password PW` | password admin (minimal 8 karakter) | ditanya, atau dibuat acak |
| `--no-tune` | lewati tuning kernel/NIC | tuning aktif |

Semua opsi: `bash scripts/install.sh --help`, atau lihat [docs/installation.md](docs/installation.md).

Di akhir instalasi, installer menampilkan alamat API dan admin. Kalau password dibuat otomatis, password **hanya ditampilkan sekali**, jadi langsung simpan.

### 6. Buka port UDP di firewall provider

Buka UDP mulai dari port pertama (misalnya `3478`) sebanyak jumlah site + group yang akan dibuat.

### 7. Cek

```bash
systemctl status govpn-wg
curl -s http://127.0.0.1:8080/api/v1/health
```

API hanya listen di `127.0.0.1`. Dari komputer lain, akses lewat SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 root@IP-SERVER
# lalu buka http://127.0.0.1:8080 dari komputer sendiri
```

### Mengubah pengaturan setelah install

Jalankan ulang installer dengan opsi baru. State, key, dan token tetap aman:

```bash
cd /root/govpn-wg
bash scripts/install.sh --yes --port 51820
```

Bisa juga mengedit `/etc/govpn/wg.env`, lalu jalankan `systemctl restart govpn-wg`.

### Update ke versi terbaru

```bash
cd /root/govpn-wg
git pull
bash scripts/install.sh --yes
```

### Uninstall

```bash
bash /opt/govpn/wg/uninstall.sh           # hapus service, interface, dan rule; data tetap disimpan
bash /opt/govpn/wg/uninstall.sh --purge   # hapus juga config dan seluruh key
```

---

## Mulai cepat

```bash
API=http://127.0.0.1:8080/api/v1
TOKEN=$(curl -s $API/auth/login -d '{"username":"admin","password":"PASSWORD"}' \
  | sed -n 's/.*"access_token": *"\([^"]*\)".*/\1/p')

# site (VPN Hub)
curl -s -X POST $API/sites -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Kantor Pusat","local_subnets":["192.168.10.0/24"]}'

# client (client-to-site)
curl -s -X POST $API/clients -H "Authorization: Bearer $TOKEN" \
  -d '{"username":"budi","target_sites":["kantor-pusat"]}'

# unduh config client
curl -s -H "Authorization: Bearer $TOKEN" $API/clients/budi/download/conf -o budi.conf
```

---

## Dokumentasi

Semua dokumentasi ada di folder [`docs/`](docs/README.md):

- [Instalasi & konfigurasi lengkap](docs/installation.md)
- [Arsitektur, jaringan & firewall](docs/architecture.md)
- **REST API**
  - [Ringkasan, autentikasi & format error](docs/api/README.md)
  - [Sistem](docs/api/system.md)
  - [VPN Hub — Site-to-Site](docs/api/sites.md)
  - [Group client](docs/api/groups.md)
  - [VPN Client — Client-to-Site](docs/api/clients.md)
  - [Contoh alur lengkap](docs/api/examples.md)
- [Pengujian](docs/testing.md)

## Lisensi

Lihat [LICENSE](LICENSE).
