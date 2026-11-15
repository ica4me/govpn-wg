# Dokumentasi GoVPN (`govpn-wg`)

| Dokumen | Isi |
|---|---|
| [installation.md](installation.md) | Semua opsi installer, isi `/etc/govpn/wg.env`, CLI, file/backup, update, uninstall |
| [architecture.md](architecture.md) | Cara kerja engine: pengalamatan, split/full tunnel, IPv4-only, firewall, keamanan host |
| [api/README.md](api/README.md) | REST API: base URL, login JWT, format request/error, daftar endpoint |
| [api/system.md](api/system.md) | `health`, `status`, `tune`, `reconcile` |
| [api/sites.md](api/sites.md) | **VPN Hub / Site-to-Site**: body request, response, download config gateway |
| [api/groups.md](api/groups.md) | Group client (satu interface `wg-c-<nama>` per group) |
| [api/clients.md](api/clients.md) | **VPN Client / Client-to-Site**: body request, response, download `.conf`/QR/script |
| [api/examples.md](api/examples.md) | Contoh alur lengkap dari awal sampai client tersambung |
| [testing.md](testing.md) | Apa yang sudah dan belum diuji |
