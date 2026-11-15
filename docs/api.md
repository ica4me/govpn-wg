# REST API `govpn-wg`

Semua isi dokumen ini diambil dari `internal/api/api.go`, `internal/api/auth.go`, dan `internal/engine/*.go`.

- Base URL default: `http://127.0.0.1:8080` (`GOVPN_LISTEN`). HTTP tanpa TLS.
- Semua route ada di bawah `/api/v1`.
- Respons JSON memakai `Content-Type: application/json; charset=utf-8` dan diindentasi 2 spasi.
- Header pada semua respons: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`.

## Ringkasan route

| Method | Path | Auth | Handler |
|---|---|---|---|
| GET | `/api/v1/health` | – | health |
| POST | `/api/v1/auth/login` | – | login |
| GET | `/api/v1/system/status` | Bearer | status |
| POST | `/api/v1/system/tune` | Bearer | jalankan tuning |
| POST | `/api/v1/system/reconcile` | Bearer | apply ulang state |
| GET | `/api/v1/sites` | Bearer | daftar site |
| POST | `/api/v1/sites` | Bearer | buat site |
| GET | `/api/v1/sites/{id}` | Bearer | detail site |
| PUT | `/api/v1/sites/{id}` | Bearer | ubah site (merge parsial) |
| DELETE | `/api/v1/sites/{id}` | Bearer | hapus site |
| GET | `/api/v1/sites/{id}/download/{kind}` | Bearer | `linux` \| `windows` \| `conf` |
| GET | `/api/v1/groups` | Bearer | daftar group |
| POST | `/api/v1/groups` | Bearer | buat group |
| PUT | `/api/v1/groups/{id}` | Bearer | ubah group |
| DELETE | `/api/v1/groups/{id}` | Bearer | hapus group |
| GET | `/api/v1/clients` | Bearer | daftar klien |
| POST | `/api/v1/clients` | Bearer | buat klien |
| GET | `/api/v1/clients/{id}` | Bearer | detail klien |
| PUT | `/api/v1/clients/{id}` | Bearer | ubah klien (merge parsial) |
| DELETE | `/api/v1/clients/{id}` | Bearer | hapus klien |
| GET | `/api/v1/clients/{id}/download/{kind}` | Bearer | `linux` \| `conf` \| `qr` |

Tidak ada `GET /api/v1/groups/{id}`. Path lain di bawah `/api/` membalas `401` kalau tanpa token, dan `404` dari router kalau token valid.

## Autentikasi (JWT)

### `POST /api/v1/auth/login`

```json
{"username": "admin", "password": "rahasia-anda"}
```

Respons `200`:

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_at": "2026-11-15T12:00:00Z"
}
```

Detail implementasi:
- HS256, ditandatangani dengan `GOVPN_DATA_DIR/jwt.key` (64 byte acak, dibuat otomatis, mode 600).
- Claim: `iss = "govpn-wg"`, `sub = <admin user>`, `iat`, `exp`. Saat verifikasi, kode mewajibkan algoritma HS256, issuer `govpn-wg`, adanya `exp`, dan `sub` sama dengan admin yang sedang dikonfigurasi.
- TTL: `GOVPN_TOKEN_TTL` (default `12h`).
- Hanya ada satu akun, yaitu `GOVPN_ADMIN_USER` + `GOVPN_ADMIN_PASSWORD_HASH` (bcrypt). Bcrypt selalu dijalankan, bahkan untuk username yang salah.
- Rate limit: 10 percobaan per menit per IP remote. Kalau terlampaui, respons `429` dengan header `Retry-After: 60`. Login yang berhasil mereset hitungan.
- Kredensial salah → `401 {"error":"invalid username or password"}`.
- Tidak ada logout, revoke, atau refresh. Token bisa dicabut massal dengan menghapus `jwt.key` lalu me-restart service.

### Memakai token

```
Authorization: Bearer <access_token>
```

Header tidak ada atau formatnya salah → `401 {"error":"missing bearer token"}`. Token tidak valid atau kedaluwarsa → `401 {"error":"invalid or expired token"}`. Kedua kasus disertai header `WWW-Authenticate`.

```bash
API=http://127.0.0.1:8080
TOKEN=$(curl -s $API/api/v1/auth/login \
  -d '{"username":"admin","password":"..."}' | sed -n 's/.*"access_token": *"\([^"]*\)".*/\1/p')
curl -s -H "Authorization: Bearer $TOKEN" $API/api/v1/system/status
```

## Format request dan error

- Body dibaca secara ketat: maksimal 64 KiB, **field tak dikenal ditolak**, data sisa setelah objek JSON ditolak, dan body kosong ditolak. Semua kasus ini membalas `400`.
- Header `Content-Type` tidak diperiksa.
- Format error selalu: `{"error": "<pesan>"}`.

| Status | Arti |
|---|---|
| 400 | JSON tidak valid, field tak dikenal, body kosong, atau ada data sisa |
| 401 | belum login, token tidak valid, atau login gagal |
| 404 | objek tidak ditemukan, atau `kind` download tidak dikenal |
| 409 | konflik: ID/username sudah ada, overlap subnet, port terpakai, pool habis, group masih punya klien, endpoint server belum diketahui (saat download) |
| 422 | validasi gagal (nama, CIDR, mode, MTU, target tidak ada, dll.) |
| 429 | rate limit login |
| 500 | error internal (pesan disembunyikan dan dicatat di log) |
| 502 | apply ke kernel gagal (state dikembalikan), atau `system/reconcile` gagal |

## Sistem

### `GET /api/v1/health` (publik)

```json
{"status": "ok", "version": "dev"}
```

### `GET /api/v1/system/status`

```json
{
  "version": "…", "uptime_seconds": 123,
  "endpoint": "203.0.113.7", "public_interface": "ens3",
  "server_lan": ["10.10.9.0/24"], "default_mtu": 1360, "base_port": 3478, "mss_mode": "mtu",
  "sites": 2, "sites_online": 1, "groups": 1, "clients": 2, "clients_online": 1,
  "last_apply": "2026-11-15T05:00:00Z", "last_apply_error": ""
}
```

Status `online` berarti handshake terakhir terjadi kurang dari 3 menit 10 detik yang lalu.

### `POST /api/v1/system/tune`

Tanpa body. Menjalankan tuning yang sama dengan `govpn-wg tune` (termasuk menulis `/etc/sysctl.d/99-govpn-wg.conf`). Respons:

```json
{
  "public_if": "ens3",
  "sysctl":  [{"item": "net.ipv4.ip_forward", "value": "1", "status": "unchanged"}],
  "modules": [{"item": "tcp_bbr", "status": "applied", "detail": "loaded"}],
  "nic":     [{"item": "ens3 gro", "value": "on", "status": "unchanged"}]
}
```

Nilai `status`: `applied`, `unchanged`, `unsupported`, `failed`, `skipped`. Tuning bawaan mengaktifkan forwarding IPv4, bukan IPv6; `accept_ra=2` tetap dipertahankan. Override admin dan nilai dari instalasi lama perlu ditinjau terpisah.

### `POST /api/v1/system/reconcile`

Tanpa body. Mendeteksi ulang interface publik dan endpoint, lalu meng-apply ulang state. Berhasil → `200 {"ok": true}`. Gagal → `502`.

## Sites

### Body `SiteInput` (POST/PUT)

Semua field opsional di level JSON. Pada `PUT`, field yang tidak dikirim mempertahankan nilai lama.

| Field | Tipe | Aturan | Default saat create |
|---|---|---|---|
| `name` | string | **wajib saat create**. 1–64 karakter `A-Z a-z 0-9 spasi _ . @ -`. ID = slug(name) dan tidak berubah meski nama di-PUT | – |
| `local_subnets` | string[] | **wajib saat create**, 1–32 CIDR IPv4. Bukan `/0`, tidak boleh overlap pool `172.31.201–250.0/24`, server LAN, atau LAN site lain | – |
| `allow_all_subnets` | bool | `true` = semua `local_subnets` diekspos | `true` |
| `exposed_subnets` | string[] | 0–32 CIDR IPv4, harus berada di dalam `local_subnets`. Dipakai persis saat `allow_all_subnets=false`; `[]` berarti tidak mengekspos subnet apa pun | `[]` |
| `can_access_server_lan` | bool | site boleh meneruskan trafik ke perangkat di `GOVPN_SERVER_LAN`, bukan membuka layanan lokal hub | `false` |
| `allowed_target_sites` | string[] | ID site yang **boleh diakses oleh site ini**. Harus ada, tidak boleh berisi dirinya sendiri, duplikat dibuang | `[]` |
| `tunnel_mode` | string | `split` atau `full` | `split` |
| `port` | int | 1–65535, tidak dipakai interface lain | otomatis dari `GOVPN_BASE_PORT` |
| `mtu` | int | 1280–9000 | `GOVPN_DEFAULT_MTU` |
| `enabled` | bool | `false` = peer dilepas dari interface, interface tetap ada | `true` |
| `rotate_keys` | bool | **hanya PUT**: buat ulang keypair peer site + PSK. Key server tidak berubah. Config site harus diunduh dan dipasang ulang | – |

Jika `exposed_subnets` dikirim tanpa `allow_all_subnets`, engine memilih `allow_all_subnets=false` (termasuk daftar kosong). Jika `allow_all_subnets=true` dikirim eksplisit, semua `local_subnets` tetap diekspos.

`rotate_keys` pada POST → `422`. Port yang sudah terikat di host hanya dicek saat create, bukan saat update.

Hak akses bersifat satu arah. `allowed_target_sites: ["site-b"]` di site A membuat LAN A bisa memulai koneksi ke subnet yang diekspos B. Balasannya lewat conntrack. Supaya B juga bisa memulai koneksi ke A, isi juga `allowed_target_sites` di B.

### Contoh

```bash
curl -s -X POST $API/api/v1/sites -H "Authorization: Bearer $TOKEN" -d '{
  "name": "Site A",
  "local_subnets": ["192.168.10.0/24"],
  "can_access_server_lan": true
}'
curl -s -X PUT $API/api/v1/sites/site-a -H "Authorization: Bearer $TOKEN" \
  -d '{"allowed_target_sites": ["site-b"], "tunnel_mode": "full"}'
```

`POST` → `201`, `PUT` → `200`, keduanya mengembalikan `SiteView`. `DELETE` → `204`. Saat site dihapus, referensinya juga dihapus dari `allowed_target_sites` site lain dan dari `target_sites` klien.

### `SiteView` (GET / POST / PUT)

```json
{
  "id": "site-a", "name": "Site A", "iface": "wg-s1",
  "subnet": "172.31.214.0/24", "hub_address": "172.31.214.1", "virtual_ip": "172.31.214.2",
  "port": 3478, "mtu": 1360,
  "server_public_key": "…", "peer_public_key": "…",
  "local_subnets": ["192.168.10.0/24"], "allow_all_subnets": true, "exposed_subnets": [],
  "can_access_server_lan": true, "allowed_target_sites": [], "tunnel_mode": "split", "enabled": true,
  "peer_allowed_ips": ["10.10.9.0/24", "172.31.201.0/24", "…"],
  "runtime": {"status": "online", "endpoint": "198.51.100.4:51820",
              "last_handshake": "…", "rx_bytes": 0, "tx_bytes": 0},
  "created_at": "…", "updated_at": "…"
}
```

- `peer_allowed_ips` adalah AllowedIPs yang ditulis ke config site. Mode `split` berisi seluruh pool tunnel `172.31.201.0–172.31.250.255` (dalam bentuk CIDR ringkas), subnet yang diekspos oleh target, LAN site lain yang menargetkan site ini, dan server LAN kalau diizinkan. Mode `full` berisi `["0.0.0.0/0", "::/0"]`.
- `runtime.status`: `online`, `offline`, `disabled`, atau `unknown`.
- Private key dan PSK **tidak pernah** ada di respons JSON.

### `GET /api/v1/sites/{id}/download/{kind}`

| kind | Respons |
|---|---|
| `linux` | `text/x-shellscript`, attachment `install-site-<id>.sh` |
| `windows`, `conf` | `text/plain`, attachment `site-<id>.conf` |
| lainnya | `404` |

`409` kalau endpoint server belum diketahui (set `GOVPN_ENDPOINT`).

## Groups

Satu group adalah satu interface WireGuard (`wg-cN`) yang dipakai bersama oleh banyak klien. Group `default` dibuat otomatis saat klien pertama dibuat tanpa `group`.

### Body `GroupInput`

| Field | Tipe | Aturan |
|---|---|---|
| `name` | string | wajib saat create. Aturan sama dengan nama site. ID = slug(name). Pada PUT hanya nama tampilan yang berubah |
| `port` | int | 1–65535, bebas. Default otomatis |
| `mtu` | int | 1280–9000. Default `GOVPN_DEFAULT_MTU` |

`POST` → `201`, `PUT` → `200`, `DELETE` → `204`. Group yang masih punya klien tidak bisa dihapus (`409`). Rotasi key server group tidak didukung.

### `GroupView`

```json
{"id": "default", "name": "default", "iface": "wg-c1", "subnet": "172.31.233.0/24",
 "port": 3479, "mtu": 1360, "server_public_key": "…", "clients": 2, "created_at": "…"}
```

## Clients

### Body `ClientInput`

| Field | Tipe | Aturan | Default |
|---|---|---|---|
| `username` | string | **wajib saat create**, 1–64 karakter `A-Z a-z 0-9 _ . @ -`, unik. ID = slug(username). Tidak bisa diubah | – |
| `group` | string | ID group, hanya saat create. Kalau dikirim pada PUT → `422` | `default` |
| `target_sites` | string[] | ID site yang boleh diakses (hanya subnet yang diekspos site tersebut) | `[]` |
| `allow_server_lan` | bool | forwarding ke perangkat di `GOVPN_SERVER_LAN`, bukan layanan lokal hub | `false` |
| `tunnel_mode` | string | `split` atau `full` | `split` |
| `dns` | string[] | maksimal 4 alamat IP | `GOVPN_DNS` |
| `enabled` | bool | `false` = peer dilepas dari interface | `true` |
| `rotate_keys` | bool | **hanya PUT**: buat ulang keypair klien + PSK | – |

Alamat klien diambil otomatis dari host bebas terendah `.2`–`.254` di subnet group.

```bash
curl -s -X POST $API/api/v1/clients -H "Authorization: Bearer $TOKEN" -d '{
  "username": "andi", "target_sites": ["site-a"], "allow_server_lan": false,
  "tunnel_mode": "split", "dns": ["9.9.9.9"]
}'
```

`POST` → `201`, `PUT` → `200`, `DELETE` → `204`.

### `ClientView`

```json
{
  "id": "andi", "username": "andi", "group": "default", "iface": "wg-c1",
  "address": "172.31.233.2", "public_key": "…",
  "target_sites": ["site-a"], "allow_server_lan": false, "tunnel_mode": "split",
  "dns": ["9.9.9.9"], "enabled": true,
  "allowed_ips": ["172.31.233.0/24", "192.168.10.0/24"],
  "runtime": {"status": "offline", "rx_bytes": 0, "tx_bytes": 0},
  "created_at": "…", "updated_at": "…"
}
```

`allowed_ips` mode `split` berisi subnet group, subnet yang diekspos target site, dan server LAN kalau diizinkan. Mode `full` berisi `["0.0.0.0/0", "::/0"]`. Di hub, AllowedIPs peer klien hanya `<address>/32`. Hub tidak menerima paket IPv6 dari klien, sehingga IPv6 klien dalam mode full diblokir alih-alih bocor. Lihat bagian full tunnel di README.

### `GET /api/v1/clients/{id}/download/{kind}`

| kind | Respons |
|---|---|
| `linux` | `text/x-shellscript`, attachment `config-<username>.sh` |
| `conf` | `text/plain`, attachment `<username>.conf` |
| `qr` | `image/png`, `inline; filename="<username>.png"` |
| lainnya | `404` |

Field `dns` pada `ClientView` adalah nilai konfigurasi tersimpan, bukan jaminan baris DNS muncul di artefak. `effectiveDNS` mempertahankan semua DNS pada mode full; pada mode split hanya resolver di dalam `allowed_ips` yang ditulis ke `.conf`, QR, dan skrip Linux. Contoh `9.9.9.9` di atas tidak ditulis pada mode split jika tidak termasuk AllowedIPs. Jika hasilnya kosong, tidak ada baris `DNS` dan skrip Linux tidak memasang shim resolver. Penyaringan ini tidak memberikan izin firewall baru: DNS atau layanan lain pada hub sendiri tetap tidak dibuka melalui tunnel.

`GOVPN-IN` hanya menerima RELATED/ESTABLISHED dan ICMP echo-request dari tunnel; koneksi baru ke layanan lokal hub di-DROP walaupun grant server LAN aktif.

Semua artefak berisi private key + PSK peer.

## Catatan port

Port default `3478` **bukan** penyamaran STUN. Paket yang dikirim tetap paket WireGuard biasa. Lihat README bagian "Port UDP 3478 BUKAN penyamaran STUN".
