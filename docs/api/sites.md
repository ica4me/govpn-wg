# API — VPN Hub / Site-to-Site

*Site* adalah jaringan remote, misalnya kantor atau cabang, yang tersambung ke hub lewat sebuah **gateway** (Linux atau Windows). Setiap site mendapat:

- interface WireGuard sendiri di hub yang namanya diambil dari nama site: `wg-s-` + maksimal 10 karakter slug (`Kantor Pusat` → `wg-s-kantor-pus`, `Cabang Bandung` → `wg-s-cabang-ban`). Kalau bentrok, ditambah angka (`wg-s-kantor-pu2`). Batas kernel Linux 15 karakter;
- subnet tunnel `/24` acak, dengan hub di `.1` dan gateway site di `.2`;
- port UDP sendiri;
- keypair dan PSK yang **dibuat oleh server**.

Hub memasang route ke `local_subnets` site lewat interface tersebut. Akses antar-site, ke server LAN, dan dari client diatur dengan izin eksplisit. Tanpa izin, semua akses ditolak.

Semua endpoint wajib memakai header `Authorization: Bearer <token>`.

| Method | Path | Fungsi |
|---|---|---|
| GET | `/sites` | daftar semua site |
| POST | `/sites` | buat site |
| GET | `/sites/{id}` | detail site |
| PUT | `/sites/{id}` | ubah site (parsial) |
| DELETE | `/sites/{id}` | hapus site |
| GET | `/sites/{id}/download/{kind}` | unduh config gateway |

---

## Body request (`POST` / `PUT`)

| Field | Tipe | POST | Default | Aturan |
|---|---|---|---|---|
| `name` | string | **wajib** | – | 1–64 karakter `A-Z a-z 0-9 spasi _ . @ -`. ID = slug(name). ID tidak berubah walaupun nama di-`PUT` |
| `local_subnets` | string[] | **wajib** | – | 1–32 CIDR IPv4: LAN di belakang gateway site. Minimal `/8`. Tidak boleh bentrok dengan pool tunnel, server LAN, LAN site lain, atau jaringan host |
| `allow_all_subnets` | bool | opsional | `true` | `true` = semua `local_subnets` boleh diakses pihak lain yang diberi izin |
| `exposed_subnets` | string[] | opsional | `[]` | hanya dipakai kalau `allow_all_subnets=false`. Berisi bagian dari `local_subnets` yang boleh diakses. `[]` = tidak ada yang diekspos |
| `can_access_server_lan` | bool | opsional | `false` | site boleh mengakses perangkat di `GOVPN_SERVER_LAN` |
| `allowed_target_sites` | string[] | opsional | `[]` | ID site lain yang **boleh diakses oleh site ini** (satu arah). Site harus ada dan tidak boleh diri sendiri |
| `tunnel_mode` | string | opsional | `"split"` | `"split"` atau `"full"`. `full` = seluruh internet gateway site lewat hub |
| `port` | int | opsional | otomatis | port UDP 1–65535, tidak boleh dipakai interface lain |
| `mtu` | int | opsional | `GOVPN_DEFAULT_MTU` (1360) | 1280–9000 |
| `enabled` | bool | opsional | `true` | `false` = peer dilepas dan tunnel putus. Interface dan konfigurasi tetap disimpan |
| `rotate_keys` | bool | **hanya PUT** | – | `true` = buat ulang keypair + PSK peer site. Config gateway harus diunduh dan dipasang ulang |

Catatan:
- Mengirim `exposed_subnets` tanpa `allow_all_subnets` otomatis membuat `allow_all_subnets=false`.
- Izin bersifat **satu arah**. `allowed_target_sites: ["b"]` di site A berarti LAN A bisa memulai koneksi ke B, dan balasannya tetap jalan. Supaya B juga bisa memulai koneksi ke A, isi `allowed_target_sites: ["a"]` di B.
- Mengirim `rotate_keys` pada `POST` menghasilkan `422`.

## Response (`SiteView`)

Dipakai oleh `GET`, `POST` (`201`), dan `PUT` (`200`).

| Field | Arti |
|---|---|
| `id`, `name` | ID (slug) dan nama tampilan |
| `iface` | nama interface di hub (`wg-s-<nama>`) |
| `subnet` | subnet tunnel `/24` |
| `hub_address` | alamat hub di tunnel (`.1`) |
| `virtual_ip` | alamat gateway site di tunnel (`.2`) |
| `port`, `mtu` | port UDP dan MTU interface |
| `server_public_key` | public key hub untuk site ini |
| `peer_public_key` | public key gateway site |
| `local_subnets`, `allow_all_subnets`, `exposed_subnets` | LAN site dan bagian yang diekspos |
| `can_access_server_lan`, `allowed_target_sites` | izin akses |
| `tunnel_mode`, `enabled` | |
| `peer_allowed_ips` | `AllowedIPs` yang ditulis ke config gateway site |
| `runtime.status` | `online` (handshake ±3 menit terakhir) / `offline` / `disabled` / `unknown` |
| `runtime.endpoint`, `runtime.last_handshake`, `runtime.rx_bytes`, `runtime.tx_bytes` | statistik WireGuard |
| `created_at`, `updated_at` | waktu UTC |

Private key dan PSK **tidak pernah** muncul di response.

Isi `peer_allowed_ips`:
- **Mode `split`:**
  - seluruh pool tunnel `172.31.201–250.x`, ditulis sebagai CIDR ringkas;
  - subnet yang diekspos oleh site tujuan;
  - LAN site lain yang diizinkan mengakses site ini;
  - server LAN, kalau `can_access_server_lan=true`.
- **Mode `full`:** `["0.0.0.0/0"]`.

---

## `POST /sites` — buat site

Minimal:

```bash
curl -s -X POST $API/sites -H "$AUTH" -d '{
  "name": "Kantor Pusat",
  "local_subnets": ["192.168.10.0/24", "192.168.11.0/24"],
  "can_access_server_lan": true
}'
```

Lengkap:

```bash
curl -s -X POST $API/sites -H "$AUTH" -d '{
  "name": "Cabang Bandung",
  "local_subnets": ["192.168.20.0/24"],
  "allow_all_subnets": false,
  "exposed_subnets": ["192.168.20.0/25"],
  "can_access_server_lan": false,
  "allowed_target_sites": ["kantor-pusat"],
  "tunnel_mode": "split",
  "port": 51900,
  "mtu": 1380,
  "enabled": true
}'
```

Response `201`:

```json
{
  "id": "cabang-bandung",
  "name": "Cabang Bandung",
  "iface": "wg-s-cabang-ban",
  "subnet": "172.31.224.0/24",
  "hub_address": "172.31.224.1",
  "virtual_ip": "172.31.224.2",
  "port": 51900,
  "mtu": 1380,
  "server_public_key": "hqEK7V8X++0iDfiBbTmoqbujD/jyxO3eLUAFyHwBXA0=",
  "peer_public_key": "w9aSBaF5RItljieW2YIdQSnwb8nr7OMT7QBKHUzIVTc=",
  "local_subnets": ["192.168.20.0/24"],
  "allow_all_subnets": false,
  "exposed_subnets": ["192.168.20.0/25"],
  "can_access_server_lan": false,
  "allowed_target_sites": ["kantor-pusat"],
  "tunnel_mode": "split",
  "enabled": true,
  "peer_allowed_ips": [
    "172.31.201.0/24", "172.31.202.0/23", "172.31.204.0/22", "172.31.208.0/20",
    "172.31.224.0/20", "172.31.240.0/21", "172.31.248.0/23", "172.31.250.0/24",
    "192.168.10.0/24", "192.168.11.0/24"
  ],
  "runtime": { "status": "unknown", "rx_bytes": 0, "tx_bytes": 0 },
  "created_at": "2026-11-15T21:19:34.121605259Z",
  "updated_at": "2026-11-15T21:19:34.121605259Z"
}
```

Error yang sering muncul:

| Status | Contoh |
|---|---|
| `409` | `"192.168.10.0/24 (site kantor-pusat) overlaps 192.168.10.0/24 (site y)"` |
| `409` | `"10.10.9.0/24 (server LAN) overlaps 10.10.9.0/24 (site x)"` |
| `409` | `"site id \"kantor-pusat\" already exists"` |
| `422` | `"local_subnets: 0.0.0.0/1 is too broad (minimum /8)"` |
| `422` | `"local_subnets is required (LAN behind the site)"` |
| `422` | `"site cabang-bandung: target site \"x\" does not exist"` |

## `GET /sites` dan `GET /sites/{id}`

```bash
curl -s -H "$AUTH" $API/sites               # array SiteView
curl -s -H "$AUTH" $API/sites/kantor-pusat  # satu SiteView, 404 kalau tidak ada
```

## `PUT /sites/{id}` — ubah site

Cukup kirim field yang ingin diubah. Perubahan langsung diterapkan tanpa restart interface.

```bash
# izinkan Kantor Pusat mengakses Cabang Bandung
curl -s -X PUT $API/sites/kantor-pusat -H "$AUTH" -d '{"allowed_target_sites": ["cabang-bandung"]}'

# ganti port + MTU
curl -s -X PUT $API/sites/kantor-pusat -H "$AUTH" -d '{"port": 51901, "mtu": 1400}'

# matikan sementara
curl -s -X PUT $API/sites/kantor-pusat -H "$AUTH" -d '{"enabled": false}'

# ganti key peer site (config gateway harus dipasang ulang)
curl -s -X PUT $API/sites/kantor-pusat -H "$AUTH" -d '{"rotate_keys": true}'
```

Response `200` berisi `SiteView` terbaru.

Kalau `port`, `mtu`, `local_subnets`, mode, atau key berubah, unduh ulang config gateway lalu pasang lagi di site.

## `DELETE /sites/{id}`

```bash
curl -s -X DELETE $API/sites/cabang-bandung -H "$AUTH"   # 204
```

Interface site dihapus. Referensi ke site ini juga dibersihkan otomatis dari `allowed_target_sites` milik site lain dan dari `target_sites` milik client.

---

## `GET /sites/{id}/download/{kind}` — config gateway

| `kind` | Hasil | Dipakai di |
|---|---|---|
| `linux` | `install-site-<id>.sh` | gateway Debian/Ubuntu |
| `windows` / `conf` | `site-<id>.conf` | aplikasi WireGuard Windows/macOS, atau `wg-quick` |

```bash
curl -s -H "$AUTH" $API/sites/kantor-pusat/download/linux -o install-site-kantor-pusat.sh
curl -s -H "$AUTH" $API/sites/kantor-pusat/download/conf  -o site-kantor-pusat.conf
```

Script `linux` dijalankan di **gateway site** dengan `sudo bash install-site-<id>.sh`. Yang dilakukan script:
- memasang `wireguard-tools` dan `nftables`;
- membuat interface `wg-hub` (`wg-quick@wg-hub`);
- menyalakan `ip_forward`;
- memasang MSS clamp dan masquerade ke LAN site di tabel nft sendiri (`inet govpn_site`).

Pada mode `full`, script memakai policy routing di tabel `51820` agar endpoint hub dan LAN lokal tetap memakai jalur asli.

Untuk mencabut semuanya: `sudo bash install-site-<id>.sh --uninstall`.

Contoh `.conf` (key disensor):

```ini
[Interface]
PrivateKey = <private key gateway site>
Address = 172.31.224.2/24
MTU = 1380

[Peer]
PublicKey = hqEK7V8X++0iDfiBbTmoqbujD/jyxO3eLUAFyHwBXA0=
PresharedKey = <psk>
Endpoint = 203.0.113.10:51900
AllowedIPs = 172.31.201.0/24, 172.31.202.0/23, 172.31.204.0/22, 172.31.208.0/20, 172.31.224.0/20, 172.31.240.0/21, 172.31.248.0/23, 172.31.250.0/24, 192.168.10.0/24, 192.168.11.0/24
PersistentKeepalive = 25
```

Untuk gateway Windows, IP forwarding dan NAT ke LAN harus diatur sendiri di Windows.

| Status | Arti |
|---|---|
| `404` | site tidak ada, atau `kind` bukan `linux`/`windows`/`conf` |
| `409` | endpoint publik server belum diketahui; set `GOVPN_ENDPOINT` |
