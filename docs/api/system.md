# API — Sistem

Semua endpoint, kecuali `health`, wajib memakai header `Authorization: Bearer <token>`. Lihat [README.md](README.md).

## `GET /health`

Endpoint ini publik, tanpa token. Dipakai untuk cek apakah service hidup.

```bash
curl -s http://127.0.0.1:8080/api/v1/health
```

```json
{ "status": "ok", "version": "0.1.0" }
```

## `GET /system/status`

Tanpa body.

```bash
curl -s -H "$AUTH" $API/system/status
```

Response `200` (ditangkap dari server test dengan engine fake, tanpa perubahan jaringan host):

```json
{
  "base_port": 3478,
  "clients": 0,
  "clients_online": 0,
  "default_mtu": 1360,
  "endpoint": "vpn.example.org",
  "groups": 0,
  "last_apply": "0001-01-01T00:00:00Z",
  "last_apply_error": "",
  "mss_mode": "mtu",
  "public_interface": "eth0",
  "server_lan": ["10.10.9.0/24"],
  "server_uptime_seconds": 33493,
  "sites": 0,
  "sites_online": 0,
  "uptime_seconds": 0,
  "version": "dev"
}
```

| Field | Arti |
|---|---|
| `uptime_seconds` | integer detik sejak instance service/API dimulai; tetap memakai perilaku lama dan reset saat service restart |
| `server_uptime_seconds` | integer detik sejak host Linux boot, dibaca langsung via `sysinfo(2)`; tidak reset saat service restart |
| `endpoint` | IP/hostname publik yang ditulis ke config peer |
| `public_interface` | NIC publik yang dipakai untuk NAT internet |
| `server_lan` | LAN di belakang server yang bisa diberikan aksesnya |
| `sites_online`, `clients_online` | jumlah peer yang melakukan handshake dalam ±3 menit terakhir |
| `last_apply`, `last_apply_error` | waktu dan error terakhir saat menerapkan state ke kernel |

Dashboard cukup mengambil kedua nilai ini melalui endpoint backend yang sama setiap 60 detik (sekali per menit); tidak perlu endpoint atau polling uptime terpisah. Backend hanya membaca uptime saat request status diterima, tanpa background polling. Jika pembacaan uptime host gagal, endpoint mengembalikan `500` (bukan mengganti nilainya dengan uptime service).

## `POST /system/tune`

Tanpa body. Menjalankan tuning kernel + NIC, sama seperti `govpn-wg tune`.

```bash
curl -s -X POST -H "$AUTH" $API/system/tune
```

Response `200`:

```json
{
  "public_if": "ens3",
  "sysctl": [
    { "item": "net.ipv4.ip_forward", "value": "1", "status": "unchanged" },
    { "item": "net.ipv4.tcp_congestion_control", "value": "bbr", "status": "applied" }
  ],
  "modules": [
    { "item": "tcp_bbr", "status": "applied", "detail": "loaded" }
  ],
  "nic": [
    { "item": "ens3 gro", "value": "on", "status": "unchanged" }
  ]
}
```

Nilai `status` yang mungkin muncul: `applied`, `unchanged`, `unsupported`, `failed`, `skipped`.

## `POST /system/reconcile`

Tanpa body. Endpoint ini:
1. mendeteksi ulang NIC publik dan endpoint;
2. menerapkan ulang seluruh state ke kernel (interface, peer, route, firewall).

Gunanya untuk memulihkan kondisi setelah ada pihak lain yang mengubah firewall atau interface. Engine juga menjalankan reconcile otomatis setiap 30 detik.

```bash
curl -s -X POST -H "$AUTH" $API/system/reconcile
```

| Status | Body |
|---|---|
| `200` | `{"ok": true}` |
| `502` | `{"error": "..."}` — penerapan ke kernel gagal |
