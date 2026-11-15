# API — Group Client

Satu *group* adalah satu interface WireGuard di hub (`wg-c-<nama group>`, misalnya `wg-c-tim-it`) dengan subnet `/24` dan port UDP sendiri. Interface itu dipakai bersama oleh banyak client.

- Group `default` dibuat otomatis saat client pertama dibuat tanpa field `group`.
- Group berguna untuk memisahkan client ke subnet, port, atau MTU yang berbeda, misalnya `Tim IT` dan `Vendor`.
- Hak akses tetap diatur **per client**, bukan per group. Lihat [clients.md](clients.md).

Semua endpoint wajib memakai header `Authorization: Bearer <token>`.

| Method | Path | Fungsi |
|---|---|---|
| GET | `/groups` | daftar group |
| POST | `/groups` | buat group |
| PUT | `/groups/{id}` | ubah group |
| DELETE | `/groups/{id}` | hapus group (harus kosong) |

## Body request

| Field | Tipe | POST | Default | Aturan |
|---|---|---|---|---|
| `name` | string | **wajib** | – | 1–64 karakter `A-Z a-z 0-9 spasi _ . @ -`. ID = slug(name). Pada `PUT`, hanya nama tampilan yang berubah |
| `port` | int | opsional | otomatis | port UDP 1–65535, tidak boleh dipakai interface lain |
| `mtu` | int | opsional | `GOVPN_DEFAULT_MTU` (1360) | 1280–9000 |

## Response (`GroupView`)

| Field | Arti |
|---|---|
| `id`, `name` | |
| `iface` | interface di hub (`wg-c-<nama group>`, misalnya `wg-c-tim-it`) |
| `subnet` | subnet tunnel group |
| `port`, `mtu` | |
| `server_public_key` | public key hub untuk group ini |
| `clients` | jumlah client di group |
| `created_at` | |

## Contoh

```bash
curl -s -X POST $API/groups -H "$AUTH" -d '{"name": "Tim IT", "mtu": 1360}'
```

Response `201`:

```json
{
  "id": "tim-it",
  "name": "Tim IT",
  "iface": "wg-c-tim-it",
  "subnet": "172.31.250.0/24",
  "port": 3479,
  "mtu": 1360,
  "server_public_key": "4D1MfGi9Vy/LFtRJUbDaL0lL/JCVkA1HpgKs/izOPiY=",
  "clients": 0,
  "created_at": "2026-11-15T21:19:34.216157724Z"
}
```

```bash
curl -s -X PUT $API/groups/tim-it -H "$AUTH" -d '{"name": "Tim IT Pusat", "port": 51950}'   # 200
curl -s -H "$AUTH" $API/groups                                                                # array
curl -s -X DELETE $API/groups/tim-it -H "$AUTH"                                               # 204
```

Kalau `port` atau `mtu` group diubah, semua client di group itu harus mengunduh ulang config-nya.

| Status | Contoh |
|---|---|
| `409` | `"group \"tim-it\" still has clients"` (hapus client-nya dulu) |
| `409` | `"group \"tim-it\" already exists"` |
| `422` | `"mtu: mtu must be 1280-9000"` |
