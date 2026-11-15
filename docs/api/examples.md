# Contoh Alur Lengkap

Skenario:
- Server hub mempunyai LAN `10.10.9.0/24`.
- Ada dua kantor: **Kantor Pusat** (`192.168.10.0/24`) dan **Cabang Bandung** (`192.168.20.0/24`).
- Ada satu karyawan, **budi**, yang memakai laptop.

## 0. Login

```bash
API=http://127.0.0.1:8080/api/v1
TOKEN=$(curl -s $API/auth/login -d '{"username":"admin","password":"PASSWORD"}' \
  | sed -n 's/.*"access_token": *"\([^"]*\)".*/\1/p')
AUTH="Authorization: Bearer $TOKEN"
```

## 1. Buat dua site (VPN Hub)

```bash
curl -s -X POST $API/sites -H "$AUTH" -d '{
  "name": "Kantor Pusat",
  "local_subnets": ["192.168.10.0/24"],
  "can_access_server_lan": true
}'

curl -s -X POST $API/sites -H "$AUTH" -d '{
  "name": "Cabang Bandung",
  "local_subnets": ["192.168.20.0/24"]
}'
```

## 2. Izinkan kedua site saling akses

Izin bersifat satu arah, jadi atur di kedua site:

```bash
curl -s -X PUT $API/sites/kantor-pusat   -H "$AUTH" -d '{"allowed_target_sites": ["cabang-bandung"]}'
curl -s -X PUT $API/sites/cabang-bandung -H "$AUTH" -d '{"allowed_target_sites": ["kantor-pusat"]}'
```

## 3. Pasang gateway di masing-masing site

Unduh script di hub:

```bash
curl -s -H "$AUTH" $API/sites/kantor-pusat/download/linux   -o install-site-kantor-pusat.sh
curl -s -H "$AUTH" $API/sites/cabang-bandung/download/linux -o install-site-cabang-bandung.sh
```

Salin setiap script ke gateway Linux di site masing-masing, lalu jalankan di gateway tersebut:

```bash
sudo bash install-site-kantor-pusat.sh
```

Untuk gateway Windows, pakai `download/windows` lalu impor file `.conf` ke aplikasi WireGuard.

## 4. Buat client

```bash
curl -s -X POST $API/clients -H "$AUTH" -d '{
  "username": "budi",
  "target_sites": ["kantor-pusat"],
  "allow_server_lan": true
}'
```

## 5. Kirim config ke client

```bash
curl -s -H "$AUTH" $API/clients/budi/download/conf -o budi.conf   # Windows/macOS/Linux
curl -s -H "$AUTH" $API/clients/budi/download/qr   -o budi.png    # Android/iOS
```

`budi.conf` berisi private key. Kirim lewat jalur aman.

Config ini **split tunnel**: budi hanya bisa mengakses `192.168.10.0/24` dan `10.10.9.0/24` lewat VPN. Internet budi tetap lewat jalur aslinya.

Kalau budi ingin full tunnel, ia cukup mengubah `AllowedIPs = 0.0.0.0/0` di `budi.conf`. Server tidak perlu diubah.

## 6. Cek status

```bash
curl -s -H "$AUTH" $API/clients/budi | grep -A5 runtime
curl -s -H "$AUTH" $API/system/status
```

`runtime.status` berubah menjadi `online` setelah client melakukan handshake.

## 7. Cabut akses

```bash
curl -s -X PUT    $API/clients/budi -H "$AUTH" -d '{"enabled": false}'   # blokir sementara
curl -s -X DELETE $API/clients/budi -H "$AUTH"                           # hapus permanen
```
