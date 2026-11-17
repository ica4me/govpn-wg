# Pengujian `govpn-wg`

Dokumen ini membedakan pemeriksaan kode/unit test, integrasi kernel dalam namespace jaringan terpisah, dan percobaan manual terdahulu di server. **Belum ada uji trafik peer yang membuktikan isolasi aktual**, dan perubahan ini bukan pernyataan bahwa sistem sudah sepenuhnya diperkeras atau siap produksi.

## 1. Menjalankan pemeriksaan

```bash
cd /root/govpn-wg
go test -count=1 ./...
go vet ./...
bash -n scripts/install.sh scripts/uninstall.sh deploy/cloud-init-guard.sh
```

Unit test biasa memakai fake untuk sebagian besar operasi WireGuard/firewall. Hasil suite lama tidak boleh dianggap sebagai hasil eksekusi ulang setelah setiap perubahan. Pembaruan dokumentasi ini tidak menjalankan ulang suite, installer, atau deployment; hasil kernel di bawah berasal dari eksekusi yang dilaporkan pada sesi verifikasi ini.

### Test kernel terisolasi (opt-in)

Jalankan hanya sebagai root pada lingkungan yang mengizinkan network namespace, WireGuard kernel, netlink, dan iptables. Kompilasi test lebih dahulu, kemudian jalankan binary di namespace terpisah; jangan menjalankan test destruktif ini langsung pada jaringan host produksi.

```bash
# Pilih direktori scratch yang aman dan dapat ditulis.
TEST_DIR=$(mktemp -d)
go test -c -o "$TEST_DIR/engine.test" ./internal/engine
sudo unshare --net env GOVPN_TEST_NETNS=1 \
  "$TEST_DIR/engine.test" -test.run '^TestKernelIsolation$' -test.v
rm -rf "$TEST_DIR"
```

Tanpa opt-in/kemampuan lingkungan yang dibutuhkan, test dapat dilewati atau gagal; `SKIP` bukan bukti lulus integrasi. Namespace ini tidak meniru konfigurasi cloud-init, DHCP, atau pengelola jaringan host.

## 2. Bukti kernel yang sudah diperoleh

Eksekusi binary test `internal/engine` yang sudah dikompilasi melalui `unshare --net env GOVPN_TEST_NETNS=1 … -test.run TestKernelIsolation` menghasilkan **PASS**. Cakupannya:

- Membuat dan menghapus interface WireGuard kernel sungguhan.
- Menerapkan ruleset iptables sungguhan pada tabel **filter, nat, dan mangle**, bukan hanya mencocokkan teks hasil render.
- Memulihkan `GOVPN-FWD` setelah isinya di-flush.
- Memperbaiki jump yang digeser sehingga kembali ke posisi 1.
- Memastikan chain INPUT milik aplikasi (`GOVPN-IN`) ada.
- Memastikan default route namespace tidak berubah setelah create, reconcile, dan delete.

**Batas penting:** test ini belum mengirim trafik dari peer nyata untuk memverifikasi ACCEPT/DROP, NAT, DNS, atau akses layanan lokal hub. Nama `TestKernelIsolation` tidak berarti isolasi trafik end-to-end sudah terbukti. Default route yang tetap di namespace juga bukan jaminan tidak ada gangguan DHCP/hotplug pada host cloud.

## 3. Perilaku kode dan batas unit test

Test API/engine biasa menggunakan `httptest`, `wireguard.Fake`, dan `firewall.Fake` untuk memeriksa alur CRUD, validasi, persistensi state, AllowedIPs, serta teks rule dan artefak generator. Test firewall memeriksa bentuk rule; test sysopt memakai root palsu dan bukan perubahan sysctl host sungguhan.

Perilaku yang perlu diperhatikan pada kode saat ini:

- `allow_all_subnets=false` dengan `exposed_subnets=[]` mengekspos **nol subnet**, bukan seluruh LAN. Daftar eksplisit tanpa flag `allow_all_subnets` memilih mode daftar terbatas.
- `effectiveDNS` pada mode split hanya mempertahankan resolver yang berada di dalam AllowedIPs. Mode full mempertahankan semua DNS yang dikonfigurasi. Tanpa DNS efektif, artefak tidak berisi baris `DNS`, dan skrip Linux menghindari pemasangan shim resolver. Ini tidak membuktikan resolusi DNS end-to-end.
- `GOVPN-IN` menerima RELATED/ESTABLISHED dan ICMP echo-request (dibatasi 50/detik) dari tunnel, lalu DROP trafik lainnya. Uji dengan flood ping: paket di atas limit harus masuk counter DROP, sementara `ping` normal tetap 0% loss. Grant server LAN mengizinkan forwarding ke perangkat lain, **tidak membuka layanan lokal hub** seperti SSH/API/DNS, termasuk melalui IP LAN milik hub.
- Catch-all `wg-s+`/`wg-c+` di firewall tetap berlaku saat state kosong. Bukti penerapan ruleset di kernel tidak menggantikan pengujian paket.
- Tuning bawaan tidak lagi menyalakan forwarding IPv6; forwarding IPv4 dan pengaturan `accept_ra=2` tetap ada. Nilai IPv6 lama atau override admin perlu diperiksa terpisah.

Pemeriksaan sintaks `bash -n` atau isi `.conf` tidak membuktikan skrip berhasil dipasang atau routing/NAT bekerja. Test fake juga tidak membuktikan rollback kernel nyata, ethtool perangkat nyata, koeksistensi firewall host, loop reconcile 30 detik/SIGHUP, maupun pemulihan setelah reboot.

## 4. Percobaan manual terdahulu dan status operasional

Pada percobaan manual sebelumnya di Debian 13, service pernah aktif, tuning BBR/qdisc `fq` dan forwarding berjalan, serta dua site dan dua klien berhasil dibuat lewat API. Satu klien sungguhan berhasil handshake dan ping ke `.1` tunnel serta IP LAN milik hub.

Bukti tersebut hanya menunjukkan konektivitas klien→hub saat itu. Ping ke alamat LAN hub dijawab secara lokal melalui INPUT, **bukan FORWARD**, sehingga tidak membuktikan grant server LAN, NAT, atau akses ke perangkat lain. Percobaan itu mendahului pembatasan INPUT terbaru dan bukan validasi ulang kebijakan layanan lokal saat ini.

**Status akhir sesi verifikasi: server tetap dihentikan; tidak ada deployment baru.** Menghentikan daemon sendiri tidak otomatis menghapus interface dan rule yang sudah ada. Jangan menafsirkan status ini sebagai persetujuan untuk start ulang di produksi.

### Uji di server Debian 13 nyata (2026-11-16)

- `deploy/cloud-init-guard.sh` dipasang di server. Lalu interface WireGuard sementara (`wg-s999999`) dibuat dan dihapus di jaringan **host** dengan timer pembersih otomatis. `udevadm test` menunjukkan hook cloud-init tidak lagi terpanggil untuk interface itu, dan `ip -4 route show default` **identik** sebelum dan sesudah create/delete.
- `TestKernelIsolation` dijalankan di server (di dalam `unshare --net`): **PASS**, termasuk pengecekan IPv6 mati di interface tunnel.
- Service `govpn-wg` tetap dihentikan; uji service penuh + client nyata belum dilakukan ulang.

### Insiden cloud-init / hotplug

Bukti investigasi menunjukkan penambahan/penghapusan interface WireGuard virtual memanggil `/usr/lib/cloud-init/hook-hotplug`, kemudian terlihat DHCP berulang pada `ens3`. Hubungan ini belum membuktikan cloud-init sebagai penyebab tunggal hilangnya akses server. Risiko operasional belum dinyatakan selesai.

Sebelum operasi interface pada host cloud, siapkan konsol out-of-band dan cadangan konfigurasi/route/firewall, serta tinjau aturan hotplug cloud-init dan pengelola jaringan yang berlaku. Jangan menonaktifkan DHCP, network manager, atau hotplug secara membabi buta melalui satu-satunya koneksi SSH.

## 5. Belum terverifikasi end-to-end

| Area | Status |
|---|---|
| ACCEPT/DROP trafik peer tanpa grant dan lintas group/site | belum |
| Pemblokiran koneksi baru tunnel→SSH/API/DNS hub; ping dan balasan conntrack yang diizinkan | belum |
| Klien→perangkat lain di `GOVPN_SERVER_LAN` dengan/tanpa grant dan MASQUERADE | belum |
| Site-to-site LAN↔LAN melalui gateway Linux hasil generator | belum |
| Klien→LAN site, termasuk exposure kosong/terbatas | belum |
| Full tunnel: egress internet, NAT publik, DROP tujuan non-publik | belum |
| DNS efektif split/full pada perangkat klien nyata | belum |
| IPv6 dimatikan per interface tunnel; `::/0` tidak pernah ditulis | interface hub: diuji di namespace; perangkat klien nyata: belum |
| IPv6 gateway site full tunnel (`route.sh` hanya memasang policy IPv4) | belum |
| Windows/mobile/QR pada perangkat nyata | belum |
| Clamp MSS pada trafik nyata, PMTU, fragmentasi, throughput/beban | belum |
| Reconcile interface terhapus, perubahan IP publik, timer/SIGHUP | belum; repair chain/jump sudah diuji terpisah dalam namespace. Reboot sudah diuji (lihat uji plug-and-play) |
| Docker, ufw, firewalld, variasi backend iptables | belum menyeluruh |
| Install/uninstall/purge/reinstall serta variasi OS/arsitektur | belum menyeluruh |
| Lolos pemblokiran VPN dengan port 3478 | tidak diklaim; bukan penyamaran STUN |

## Uji plug-and-play dari VM kosong (Ubuntu 22.04)

Tanggal uji: 18 November 2026. Hub-nya VM **Ubuntu 22.04.5 LTS** kosong (kernel 5.15, wireguard 1.0.0, 1 vCPU / 2 GB, OpenStack). Backend dan UI dipasang **langsung dari GitHub** mengikuti [Panduan Cepat 1 VM](https://github.com/ica4me/govpn-wg-ui/blob/main/docs/quickstart-1-vm.md) tanpa langkah tambahan. Peer (2 gateway site, masing-masing dengan 1 host LAN, plus 2 client) berjalan di network namespace pada mesin lain dan terhubung lewat internet ke IP publik hub.

| Uji | Hasil |
|---|---|
| `install.sh --yes` di VM kosong (Go diunduh otomatis) | lolos, ±2 menit |
| Build + start UI Docker (`daemon.json` tanpa bridge/iptables), akses publik `:8090` | lolos, ±2 menit; API `:8080` tidak terbuka ke publik |
| Default route, ip rule, DNS hub sebelum/sesudah install backend, Docker, UI, pembuatan tunnel, reboot | **tidak berubah** |
| Login pertama admin/admin → API manajemen ditolak (403) sampai password diganti; UI mengarahkan ke halaman Account | lolos |
| Config site/client split tunnel (tanpa `0.0.0.0/0`); script Linux `bash -n` | lolos |
| **Site-to-site**: host LAN site A ↔ host LAN site B (izin dua arah) | lolos, 0% loss |
| **Client-to-site**: client → site A (diizinkan) | lolos |
| Client → site B (tanpa izin; AllowedIPs client sengaja diperlebar) | **diblok hub** |
| **Client-to-multisite**: satu config client → site A dan site B | lolos, 0% loss |
| Client ke client lain di group yang sama | diblok |
| Cabut izin site B lewat API, lalu kembalikan, tanpa reconnect client | blok seketika, lalu tersambung lagi |
| Full tunnel: client mengubah sendiri `AllowedIPs = 0.0.0.0/0` | internet lewat hub (IP keluar = IP hub) |
| Reboot hub | backend, UI, dan ketiga tunnel naik otomatis; seluruh uji konektivitas lolos lagi |
| `reset-admin` + restart backend | login kembali admin/admin; tunnel tetap tersambung |

## 6. Prioritas pengujian berikutnya

1. Gunakan lab terisolasi dengan hub dan peer sungguhan. Uji akses layanan lokal hub: ping harus diizinkan, koneksi baru TCP/UDP ke SSH/API/DNS harus ditolak, termasuk ketika grant server LAN aktif.
2. Siapkan perangkat di belakang server LAN (bukan hub). Bandingkan akses klien dengan grant aktif/nonaktif dan periksa counter `GOVPN-FWD` serta NAT.
3. Pasang dua gateway site; uji grant satu arah, penolakan arah balik, dan exposure kosong maupun terbatas.
4. Uji full tunnel IPv4, penolakan tujuan non-publik tanpa grant, IPv6 klien, dan DNS split/full. Periksa bahwa trafik tidak bocor ke jalur luar tunnel.
5. Uji pemulihan interface, timer/SIGHUP, reboot, dan interaksi firewall lain di lab. Jangan melakukan flush rule atau delete interface pada host remote tanpa akses pemulihan.
6. Setelah risiko hotplug/DHCP dipahami, rencanakan verifikasi operasional dan deployment terpisah dengan rollback; tidak ada langkah ini yang sudah dinyatakan selesai di sini.
