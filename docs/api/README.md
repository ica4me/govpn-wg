# REST API — Ringkasan

- **Base URL:** `http://127.0.0.1:8080/api/v1` (atur dengan `GOVPN_LISTEN`). Koneksi memakai HTTP tanpa TLS, jadi akses dari luar server lewat SSH tunnel atau reverse proxy TLS.
- **Format:** request dan response berupa JSON (`application/json; charset=utf-8`).
- **Auth:** JWT Bearer. Semua endpoint wajib memakai token, kecuali `health` dan `auth/login`.
- **ID objek** dibuat dari nama atau username yang diubah menjadi *slug*, lalu dipakai di URL. Contoh: `"Kantor Pusat"` → `kantor-pusat`, `"sari.it"` → `sari-it`.

Detail per modul:

| Modul | Dokumen |
|---|---|
| Authentication / password change | [auth.md](auth.md) |
| Sistem (health, status, tune, reconcile) | [system.md](system.md) |
| **VPN Hub — Site-to-Site** | [sites.md](sites.md) |
| Group client | [groups.md](groups.md) |
| **VPN Client — Client-to-Site** | [clients.md](clients.md) |
| Contoh alur lengkap | [examples.md](examples.md) |

## Daftar endpoint

| Method | Path | Auth | Fungsi |
|---|---|---|---|
| GET | `/health` | – | cek service hidup |
| POST | `/auth/login` | – | login, dapatkan token |
| POST | `/auth/password` | ✔ | ganti password; cabut semua token |
| GET | `/system/status` | ✔ | status engine |
| POST | `/system/tune` | ✔ | jalankan tuning kernel/NIC |
| POST | `/system/reconcile` | ✔ | terapkan ulang state ke kernel |
| GET | `/sites` | ✔ | daftar site |
| POST | `/sites` | ✔ | buat site |
| GET | `/sites/{id}` | ✔ | detail site |
| PUT | `/sites/{id}` | ✔ | ubah site (parsial) |
| DELETE | `/sites/{id}` | ✔ | hapus site |
| GET | `/sites/{id}/download/{kind}` | ✔ | unduh config gateway site (`linux` \| `windows` \| `conf`) |
| GET | `/groups` | ✔ | daftar group |
| POST | `/groups` | ✔ | buat group |
| PUT | `/groups/{id}` | ✔ | ubah group |
| DELETE | `/groups/{id}` | ✔ | hapus group |
| GET | `/clients` | ✔ | daftar client |
| POST | `/clients` | ✔ | buat client |
| GET | `/clients/{id}` | ✔ | detail client |
| PUT | `/clients/{id}` | ✔ | ubah client (parsial) |
| DELETE | `/clients/{id}` | ✔ | hapus client |
| GET | `/clients/{id}/download/{kind}` | ✔ | unduh config client (`conf` \| `qr` \| `linux`) |

## Autentikasi

### `POST /auth/login`

Request body:

| Field | Tipe | Wajib | Keterangan |
|---|---|---|---|
| `username` | string | ✔ | `GOVPN_ADMIN_USER` |
| `password` | string | ✔ | password admin |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -d '{"username":"admin","password":"PASSWORD"}'
```

Response `200`:

```json
{
  "access_token": "<jwt>",
  "expires_at": "2026-11-16T09:19:33.710677875Z",
  "token_type": "Bearer"
}
```

Response gagal:

| Status | Body |
|---|---|
| `401` | `{"error": "invalid username or password"}` |
| `429` | terlalu banyak percobaan (10 per menit per IP); disertai header `Retry-After: 60` |

### Memakai token

Kirim token di header pada setiap request:

```
Authorization: Bearer <access_token>
```

Contoh mengambil token ke variabel shell:

```bash
API=http://127.0.0.1:8080/api/v1
TOKEN=$(curl -s $API/auth/login -d '{"username":"admin","password":"PASSWORD"}' \
  | sed -n 's/.*"access_token": *"\([^"]*\)".*/\1/p')
AUTH="Authorization: Bearer $TOKEN"
curl -s -H "$AUTH" $API/system/status
```

Detail token:
- Token berlaku selama `GOVPN_TOKEN_TTL` (default `12h`).
- Tidak ada endpoint logout atau refresh. Kalau token kedaluwarsa, login ulang.
- Untuk membatalkan semua token sekaligus, hapus `/var/lib/govpn/wg/jwt.key` lalu jalankan `systemctl restart govpn-wg`.

Kalau token tidak valid:
- `401 {"error": "missing bearer token"}` — header tidak ada.
- `401 {"error": "invalid or expired token"}` — token salah atau kedaluwarsa.

## Aturan request

- Body harus berupa **satu objek JSON**, maksimal 64 KiB.
- **Field yang tidak dikenal ditolak** dengan `400`. Hal ini mencegah salah ketik nama field tanpa disadari.
- `PUT` bersifat **parsial**: field yang tidak dikirim tetap memakai nilai lama.
- Semua CIDR harus IPv4.

## Format error

Semua error memakai bentuk yang sama:

```json
{ "error": "pesan error" }
```

| Status | Arti |
|---|---|
| `200` | OK |
| `201` | objek dibuat |
| `204` | objek dihapus (tanpa body) |
| `400` | JSON tidak valid, field tak dikenal, body kosong |
| `401` | belum login atau token tidak valid |
| `404` | objek tidak ditemukan, atau `kind` download tidak dikenal |
| `409` | konflik: ID/username sudah ada, subnet bentrok, port terpakai, group masih punya client, endpoint server belum diketahui |
| `422` | validasi gagal: nama, CIDR, mode, MTU, target tidak ada, dll. |
| `429` | rate limit login |
| `500` | error internal (detail dicatat di log) |
| `502` | gagal menerapkan ke kernel; state otomatis dikembalikan ke kondisi sebelumnya |

Contoh error nyata:

```json
{ "error": "10.10.9.0/24 (server LAN) overlaps 10.10.9.0/24 (site x)" }
{ "error": "local_subnets: 0.0.0.0/1 is too broad (minimum /8)" }
{ "error": "invalid JSON: json: unknown field \"foo\"" }
{ "error": "site \"tidak-ada\" not found" }
```

## Keamanan

- Response JSON **tidak pernah** berisi private key atau PSK. Secret hanya ada di file hasil download config.
- File download (`.conf`, QR, script) berisi private key peer. Kirim lewat jalur aman.
