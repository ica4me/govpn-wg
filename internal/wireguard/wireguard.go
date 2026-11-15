// Package wireguard manages kernel WireGuard interfaces through netlink and
// wgctrl. Changes are applied as diffs: peers are added, updated or removed
// individually so live sessions on other peers are never reset and the
// interface is never taken down for a configuration change.
package wireguard

import (
	"fmt"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// IfaceSpec is the desired state of one WireGuard interface.
type IfaceSpec struct {
	Name       string
	PrivateKey string
	Port       int
	MTU        int
	Address    netip.Prefix // e.g. 172.31.214.1/24
	Peers      []PeerSpec
	Routes     []netip.Prefix // extra routes via this interface (site LANs)
}

type PeerSpec struct {
	PublicKey    string
	PresharedKey string
	AllowedIPs   []netip.Prefix
	Keepalive    int
}

// PeerStatus is the runtime view of a peer.
type PeerStatus struct {
	PublicKey     string    `json:"public_key"`
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
}

// Manager applies interface specs to the kernel.
type Manager interface {
	// Sync makes the kernel match specs. Interfaces accepted by owned() that
	// are not in specs are deleted.
	Sync(specs []IfaceSpec, owned func(name string) bool) error
	// Peers returns runtime state of every peer on an interface by public key.
	Peers(name string) (map[string]PeerStatus, error)
	// UsedPrefixes lists IPv4 prefixes already present in kernel routing
	// tables and on interface addresses, excluding owned interfaces.
	UsedPrefixes(owned func(name string) bool) ([]netip.Prefix, error)
	Close() error
}

// Keys holds a freshly generated keypair.
type Keys struct {
	Private string
	Public  string
}

// GenerateKeys returns a new Curve25519 keypair.
func GenerateKeys() (Keys, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Keys{}, err
	}
	return Keys{Private: k.String(), Public: k.PublicKey().String()}, nil
}

// GeneratePSK returns a random 256-bit preshared key.
func GeneratePSK() (string, error) {
	k, err := wgtypes.GenerateKey()
	if err != nil {
		return "", err
	}
	return k.String(), nil
}

// PublicFromPrivate derives the public key of a base64 private key.
func PublicFromPrivate(private string) (string, error) {
	k, err := wgtypes.ParseKey(private)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	return k.PublicKey().String(), nil
}

// Online reports whether a handshake is recent enough to call the peer up.
// WireGuard rekeys every 2 minutes while traffic flows; 3 minutes plus slack.
func Online(last time.Time, now time.Time) bool {
	return !last.IsZero() && now.Sub(last) < 3*time.Minute+10*time.Second
}
