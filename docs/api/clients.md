# API — VPN Client / Client-to-Site

*Client* adalah perangkat perorangan (laptop, HP, PC) yang tersambung ke hub. Setiap client:

- masuk ke satu **group**, yaitu satu interface `wg-c-<nama group>` (misalnya `wg-c-default`) yang dipakai bersama. Defaultnya group `default`;
- mendapat satu alamat `/32` dari subnet group, mulai `.2`;
- mendapat keypair dan PSK yang **dibuat oleh server**;
- secara default memakai config **split-tunnel**: hanya subnet yang diizinkan yang lewat VPN, sedangkan internet tetap lewat jalur asli client.

**Full tunnel selalu tersedia di server.** Hub mengizinkan dan me-NAT trafik internet dari semua client. Ada dua cara memakai full tunnel:
1. Client mengubah config-nya sendiri menjadi `AllowedIPs = 0.0.0.0/0`. Tidak perlu panggil API apa pun.
2. Admin mengirim `"tunnel_mode": "full"`, sehingga config yang diunduh sudah dalam mode full.

Walaupun memakai full tunnel, client tetap **tidak bisa** mengakses alamat privat (LAN site atau server LAN) tanpa izin `target_sites` / `allow_server_lan`.

### Model akses

- **LAN di belakang server:** defaultnya **boleh** (`allow_server_lan: true`). Isi `false` untuk client yang tidak boleh mengaksesnya.
- **Site:** client cuma bisa ke site yang ada di `target_sites`. Satu client boleh ke banyak site, misalnya `["site-a", "site-b"]`. Daftarnya bisa ditambah atau dihapus belakangan lewat `PUT`.
- Site yang tidak ada di daftar **diblok di firewall hub**, walaupun client menambah subnetnya sendiri ke `AllowedIPs`.
- Client tidak tersambung ke interface site. Client masuk lewat interface group, lalu hub yang meneruskan ke interface site tujuan. Satu `.conf` cukup untuk akses ke semua site yang diizinkan.
- Setiap izin berubah, `.conf`/QR/script yang diunduh ikut ter-update. Client tinggal unduh dan import ulang. Pencabutan izin langsung berlaku di hub tanpa perlu import ulang.

Semua endpoint wajib memakai header `Authorization: Bearer <token>`.

| Method | Path | Fungsi |
|---|---|---|
| GET | `/clients` | daftar client |
| POST | `/clients` | buat client |
| GET | `/clients/{id}` | detail client |
| PUT | `/clients/{id}` | ubah client (parsial) |
| DELETE | `/clients/{id}` | hapus client |
| GET | `/clients/{id}/download/{kind}` | unduh config (`conf` / `qr` / `linux`) |

---

## Body request (`POST` / `PUT`)

| Field | Tipe | POST | Default | Aturan |
|---|---|---|---|---|
| `username` | string | **wajib** | – | 1–64 karakter `A-Z a-z 0-9 _ . @ -`, harus unik. ID = slug(username). **Tidak bisa diubah** |
| `group` | string | opsional | `"default"` | ID group. Hanya bisa diisi saat `POST`; di `PUT` menghasilkan `422`. Untuk pindah group, hapus lalu buat ulang client |
| `target_sites` | string[] | opsional | `[]` | ID site yang boleh diakses. Yang bisa diakses hanya subnet yang diekspos site tersebut |
| `allow_server_lan` | bool | opsional | `true` | boleh mengakses perangkat di `GOVPN_SERVER_LAN` (subnet di belakang server). Kirim `false` untuk mencabut |
| `tunnel_mode` | string | opsional | `"split"` | `"split"` atau `"full"`. Field ini hanya menentukan isi config yang diunduh; izin internet di server tetap terbuka untuk keduanya |
| `dns` | string[] | opsional | `GOVPN_DNS` (`["1.1.1.1"]`) | maksimal 4 alamat IP. Lihat [aturan DNS](#aturan-dns) |
| `enabled` | bool | opsional | `true` | `false` = peer dilepas dan client tidak bisa tersambung. Data client tetap disimpan |
| `rotate_keys` | bool | **hanya PUT** | – | `true` = buat ulang keypair + PSK client. Config lama langsung tidak berlaku |

## Response (`ClientView`)

Dipakai oleh `GET`, `POST` (`201`), dan `PUT` (`200`).

| Field | Arti |
|---|---|
| `id`, `username` | |
| `group`, `iface` | group dan interface hub (`wg-c-<nama group>`) |
| `address` | IP client di tunnel (`/32`) |
| `public_key` | public key client |
| `target_sites`, `allow_server_lan` | izin akses |
| `tunnel_mode` | mode config yang diunduh |
| `dns` | DNS yang tersimpan. Belum tentu semuanya ditulis ke config, lihat [aturan DNS](#aturan-dns) |
| `enabled` | |
| `allowed_ips` | `AllowedIPs` di config client |
| `runtime.status` | `online` (handshake ±3 menit terakhir) / `offline` / `disabled` / `unknown` |
| `runtime.endpoint`, `runtime.last_handshake`, `runtime.rx_bytes`, `runtime.tx_bytes` | statistik WireGuard |
| `created_at`, `updated_at` | |

Isi `allowed_ips`:
- **Mode `split`:**
  - subnet group;
  - subnet yang diekspos oleh setiap site di `target_sites`;
  - server LAN, kalau `allow_server_lan=true`.
- **Mode `full`:** `["0.0.0.0/0"]`. Hanya IPv4; `::/0` tidak pernah ditulis.

Private key dan PSK **tidak pernah** muncul di response.

---

## `POST /clients` — buat client

Minimal (masuk group `default`, split tunnel, boleh ke LAN server, tanpa akses site):

```bash
curl -s -X POST $API/clients -H "$AUTH" -d '{"username": "andi"}'
```

Dengan akses ke site dan server LAN:

```bash
curl -s -X POST $API/clients -H "$AUTH" -d '{
  "username": "budi",
  "target_sites": ["kantor-pusat"],
  "allow_server_lan": true
}'
```

Lengkap:

```bash
curl -s -X POST $API/clients -H "$AUTH" -d '{
  "username": "sari.it",
  "group": "tim-it",
  "target_sites": ["kantor-pusat", "cabang-bandung"],
  "allow_server_lan": false,
  "tunnel_mode": "split",
  "dns": ["192.168.10.53"],
  "enabled": true
}'
```

Response `201`:

```json
{
  "id": "sari-it",
  "username": "sari.it",
  "group": "tim-it",
  "iface": "wg-c-tim-it",
  "address": "172.31.250.2",
  "public_key": "94Kck7+//Yxo1z6uAuKPPf8OEAz6jkOps1Rsxjx4dVI=",
  "target_sites": ["kantor-pusat", "cabang-bandung"],
  "allow_server_lan": false,
  "tunnel_mode": "split",
  "dns": ["192.168.10.53"],
  "enabled": true,
  "allowed_ips": [
    "172.31.250.0/24",
    "192.168.10.0/24",
    "192.168.11.0/24",
    "192.168.20.0/25"
  ],
  "runtime": { "status": "unknown", "rx_bytes": 0, "tx_bytes": 0 },
  "created_at": "2026-11-15T21:19:34.301680364Z",
  "updated_at": "2026-11-15T21:19:34.301680364Z"
}
```

Pada contoh ini, `cabang-bandung` hanya mengekspos `192.168.20.0/25`. Karena itu client hanya mendapat `/25` tersebut, bukan seluruh `/24`.

Error yang sering muncul:

| Status | Contoh |
|---|---|
| `409` | `"username \"budi\" already exists"` |
| `404` | `"group \"x\" not found"` |
| `422` | `"client budi: target site \"x\" does not exist"` |
| `422` | `"tunnel_mode must be split or full"` |
| `422` | `"dns: \"abc\" is not an IP address"` |
| `409` | subnet group penuh (maksimal 253 client per group) |

## `GET /clients` dan `GET /clients/{id}`

```bash
curl -s -H "$AUTH" $API/clients          # array ClientView
curl -s -H "$AUTH" $API/clients/sari-it  # ID = slug(username), "sari.it" -> "sari-it"
```

## `PUT /clients/{id}` — ubah client

Cukup kirim field yang ingin diubah. Perubahan langsung berlaku di hub tanpa memutus client lain.

```bash
# tambah akses site
curl -s -X PUT $API/clients/budi -H "$AUTH" -d '{"target_sites": ["kantor-pusat", "cabang-bandung"]}'

# config yang diunduh menjadi full tunnel
curl -s -X PUT $API/clients/budi -H "$AUTH" -d '{"tunnel_mode": "full"}'

# blokir sementara
curl -s -X PUT $API/clients/budi -H "$AUTH" -d '{"enabled": false}'

# aktifkan lagi sekaligus ganti key (misalnya perangkat hilang)
curl -s -X PUT $API/clients/budi -H "$AUTH" -d '{"enabled": true, "rotate_keys": true}'
```

Response `200` berisi `ClientView` terbaru.

Kalau `target_sites`, `allow_server_lan`, `tunnel_mode`, `dns`, atau key berubah, client harus **mengunduh ulang** config-nya. Satu-satunya pengecualian: pencabutan akses langsung berlaku di firewall hub, walaupun client masih memakai config lama.

`{"group": "..."}` atau username yang berbeda menghasilkan `422`.

## `DELETE /clients/{id}`

```bash
curl -s -X DELETE $API/clients/budi -H "$AUTH"   # 204
```

---

## `GET /clients/{id}/download/{kind}` — config client

| `kind` | Hasil | Dipakai di |
|---|---|---|
| `conf` | `<username>.conf` | aplikasi WireGuard Windows / macOS / Android / iOS: *Import tunnel from file*. Bisa juga untuk `wg-quick` |
| `qr` | PNG (`image/png`) | scan dari aplikasi WireGuard Android/iOS |
| `linux` | `config-<username>.sh` | Linux Debian/Ubuntu: `sudo bash config-<username>.sh` |

```bash
curl -s -H "$AUTH" $API/clients/sari-it/download/conf  -o sari.it.conf
curl -s -H "$AUTH" $API/clients/sari-it/download/qr    -o sari.it.png
curl -s -H "$AUTH" $API/clients/sari-it/download/linux -o config-sari.it.sh
```

Contoh `.conf` split tunnel (key disensor):

```ini
[Interface]
PrivateKey = <private key client>
Address = 172.31.250.2/32
MTU = 1360
DNS = 192.168.10.53

[Peer]
PublicKey = 4D1MfGi9Vy/LFtRJUbDaL0lL/JCVkA1HpgKs/izOPiY=
PresharedKey = <psk>
Endpoint = 203.0.113.10:51950
AllowedIPs = 172.31.250.0/24, 192.168.10.0/24, 192.168.11.0/24, 192.168.20.0/25
PersistentKeepalive = 25
```

**Pindah ke full tunnel dari sisi client:** ganti baris `AllowedIPs` di atas menjadi

```ini
AllowedIPs = 0.0.0.0/0
```

Dengan begitu seluruh internet IPv4 client lewat hub. Kalau ingin DNS juga lewat VPN, tambahkan sendiri `DNS = 1.1.1.1` di bagian `[Interface]`.

Script `linux` melakukan hal berikut:
- memasang `wireguard-tools`;
- menulis `/etc/wireguard/govpn.conf`;
- mengaktifkan `wg-quick@govpn`;
- mematikan IPv6 hanya di interface `govpn`.

Script ini **tidak** mengubah default gateway atau DNS sistem pada mode split. Untuk mencabutnya: `sudo bash config-<username>.sh --uninstall`.

| Status | Arti |
|---|---|
| `404` | client tidak ada, atau `kind` bukan `conf`/`qr`/`linux` |
| `409` | endpoint publik server belum diketahui; set `GOVPN_ENDPOINT` |

## Aturan DNS

- **Split tunnel:** baris `DNS =` hanya ditulis kalau resolver-nya berada **di dalam** `allowed_ips`. Contohnya `192.168.10.53` di LAN site. DNS publik seperti `1.1.1.1` **tidak** ditulis. Alasannya, aplikasi WireGuard atau systemd-resolved akan menjadikan resolver itu DNS utama sistem, padahal alamatnya tidak lewat tunnel. Akibatnya resolusi nama di perangkat client gagal.
- **Full tunnel:** semua DNS ditulis.
- Kalau tidak ada DNS yang memenuhi syarat, baris `DNS` dihilangkan dan client memakai DNS aslinya.

## Nama file unduhan

Sejak v1.5.0, semua unduhan memakai `Content-Disposition: attachment` dengan `filename` dan `filename*` (RFC 5987), serta `X-Content-Type-Options: nosniff`. Profil WireGuard dikirim sebagai `application/octet-stream`, jadi browser menyimpannya sebagai `.conf`, bukan `.conf.txt`.

| Unduhan | Nama file |
|---|---|
| Client `conf` (Windows / macOS / mobile) | `<id>.conf` |
| Client `linux` | `config-<id>.sh` |
| Site `conf` / `windows` | `site-<id>.conf` |
| Site `linux` | `install-site-<id>.sh` |
