package generator

import qrcode "github.com/skip2/go-qrcode"

// QR renders a config as a PNG QR code for the WireGuard mobile apps.
func QR(conf string) ([]byte, error) {
	return qrcode.Encode(conf, qrcode.Medium, 512)
}
