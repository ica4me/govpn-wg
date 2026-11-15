# Arsitektur, Jaringan & Firewall

## Komponen

```
cmd/govpn-wg            CLI: serve | tune | reconcile | teardown | hash-password | version
internal/api            REST API + JWT
internal/engine         transaksi state -> kernel (validasi, apply, rollback, persist)
internal/wireguard      netlink/wgctrl, alokasi subnet/port/nama interface
internal/firewall       render & apply iptables (chain GOVPN-*)
internal/sysopt         tuning sysctl, modul kernel, NIC
internal/generator      .conf WireGuard, script Linux site/client, QR
internal/config         wg.env, state.json
scripts/                install.sh, uninstall.sh
deploy/                 cloud-init-guard.sh
```

Setiap perubahan lewat API diproses sebagai satu transaksi:

1. Salin state.
2. Terapkan perubahan.
3. Validasi.
4. **Pasang firewall**.
5. Sinkronkan WireGuard.
6. Simpan ke disk.

Kalau salah satu langkah gagal, state lama diterapkan kembali dan API membalas `502`. Firewall selalu dipasang **sebelum** interface naik, sehingga kalau firewall gagal, interface tidak dibuat (*fail closed*).

Perubahan peer, AllowedIPs, port, dan MTU diterapkan langsung ke interface yang sedang berjalan tanpa restart interface.

Engine menjalankan *reconcile* setiap 30 detik dan setiap menerima `SIGHUP`. Reconcile memulihkan interface yang hilang, rule yang ter-flush, dan posisi jump firewall.

## Pengalamatan

| Item | Nilai |
|---|---|
| Pool tunnel | `172.31.201.0/24` – `172.31.250.0/24`, satu `/24` acak per interface (maks. 50 site + group) |
| Hub | `.1` di setiap subnet |
| Site | `.2` |
| Client | `.2` – `.254` di subnet group (maks. 253 per group) |
| Nama interface | `wg-s-<nama site>` (site), `wg-c-<nama group>` (group): maksimal 10 karakter dari slug nama, ditambah angka kalau bentrok (`wg-s-kantor-pu2`). Batas kernel 15 karakter. Nama lama `wg-s1`/`wg-c1` dari versi sebelumnya tetap dikenali dan tidak diganti |
| Port UDP | mulai `GOVPN_BASE_PORT` (3478); port yang sudah terpakai di host dilewati |
| ID objek | slug dari nama: `"Kantor Pusat"` → `kantor-pusat`, `"sari.it"` → `sari-it` |

Subnet acak dipilih agar tidak bentrok dengan route/alamat host, LAN site, atau server LAN.

LAN site juga ditolak kalau:
- terlalu lebar (lebih lebar dari `/8`);
- menimpa jaringan yang dipakai host;
- tumpang tindih dengan LAN lain.

## Split tunnel (default) & full tunnel

- **Default: split tunnel.** `AllowedIPs` di config client hanya berisi subnet tunnel, subnet site yang diizinkan, dan server LAN (kalau diizinkan). Internet client tetap lewat jalur aslinya.
- **Full tunnel tersedia di server untuk semua client.** Hub sudah mengizinkan dan me-NAT trafik internet dari setiap client. Untuk pindah ke full tunnel, client cukup mengubah satu baris di `.conf`-nya sendiri, tanpa mengubah apa pun di server:
  ```ini
  AllowedIPs = 0.0.0.0/0
  ```
  Opsi lain: admin mengirim `"tunnel_mode": "full"` lewat API, sehingga config yang diunduh sudah dalam bentuk full.
- Trafik full tunnel ke alamat privat/non-publik (RFC1918, CGNAT, link-local, dan sebagainya) tetap **diblokir**, kecuali ada izin eksplisit (`target_sites` / `allow_server_lan`).
- DNS: pada split tunnel, baris `DNS =` hanya ditulis kalau resolver-nya berada di dalam `AllowedIPs`. Tanpa aturan ini, resolver di luar tunnel bisa mengambil alih DNS sistem client dan membuat resolusi nama gagal. Pada full tunnel, semua DNS ditulis.

## IPv4 saja

- Semua alamat, route, AllowedIPs, dan firewall hanya IPv4. Tidak ada `::/0` dan tidak ada aturan `ip6tables`.
- IPv6 dimatikan di setiap interface tunnel (`net.ipv6.conf.wg-*.disable_ipv6=1`), jadi interface tunnel tidak punya alamat IPv6.
- IPv6 milik host **tidak** diubah, dan tuning tidak menyalakan forwarding IPv6.
- Kalau client punya IPv6 dari ISP-nya, trafik IPv6 tetap lewat jalur aslinya (di luar tunnel).

## Keamanan host hub

- Engine **tidak pernah** menulis, menghapus, atau mengganti default route server. Engine hanya menambah route spesifik untuk LAN site, dan route itu ditandai `proto 222` supaya bisa dibedakan dari route lain.
- Route milik pihak lain tidak ditimpa.
- DNS dan resolver server tidak disentuh.
- Pada VM cloud, jalankan `deploy/cloud-init-guard.sh` sebelum membuat interface. Lihat [installation.md](installation.md) dan [testing.md](testing.md).

## Firewall (iptables)

| Tabel | Chain | Dipanggil dari |
|---|---|---|
| filter | `GOVPN-FWD` | `FORWARD`, posisi 1 |
| filter | `GOVPN-IN` | `INPUT`, posisi 1 |
| nat | `GOVPN-POST` | `POSTROUTING` |
| mangle | `GOVPN-MSS` | `FORWARD` (clamp TCP MSS) |

Urutan aturan per interface:
1. ESTABLISHED/RELATED diterima, INVALID dibuang.
2. Grant eksplisit (site→site, site→server LAN, client→site, client→server LAN).
3. Internet (NAT keluar lewat NIC publik), dengan alamat non-publik diblokir.
4. Sisanya **DROP**.

Catatan lain:
- Izin bersifat satu arah dari pihak yang memulai koneksi. Balasannya lewat conntrack.
- `GOVPN-IN`: dari tunnel ke hub sendiri hanya ping dan balasan koneksi yang diizinkan. SSH, API, dan layanan lokal hub tidak bisa diakses dari tunnel, termasuk oleh peer yang punya izin server LAN.
- Catch-all `wg-s+` / `wg-c+` DROP tetap aktif walaupun belum ada site/client.
- MSS: `mtu` → MSS = MTU − 40; `pmtu` → `--clamp-mss-to-pmtu`.

## Port 3478

`3478` hanya nomor port default. Paketnya tetap WireGuard biasa, **bukan** penyamaran STUN, jadi DPI tetap bisa mengenalinya. Ganti dengan `--port` sesuai kebutuhan.
