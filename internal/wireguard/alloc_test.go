package wireguard

import (
	"net/netip"
	"testing"

	"github.com/ica4me/govpn-wg/internal/config"
)

func TestAllocateSubnetAvoidsUsed(t *testing.T) {
	var used []netip.Prefix
	for o := config.PoolFirst; o < config.PoolLast; o++ {
		used = append(used, config.PoolPrefix(o))
	}
	p, err := AllocateSubnet(used)
	if err != nil {
		t.Fatal(err)
	}
	if p != config.PoolPrefix(config.PoolLast) {
		t.Fatalf("got %s, want the only free /24", p)
	}
	if _, err := AllocateSubnet(append(used, p)); err != ErrPoolExhausted {
		t.Fatalf("want exhausted, got %v", err)
	}
}

func TestAllocateSubnetRandomAndInRange(t *testing.T) {
	seen := map[netip.Prefix]bool{}
	for i := 0; i < 200; i++ {
		p, err := AllocateSubnet(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !config.InPool(p) || p.Bits() != 24 {
			t.Fatalf("%s outside pool", p)
		}
		seen[p] = true
	}
	if len(seen) < 10 {
		t.Fatalf("allocation does not look random: %d distinct", len(seen))
	}
}

func TestPoolSummaryCoversExactly(t *testing.T) {
	sum := PoolSummary()
	for o := 0; o < 256; o++ {
		a := netip.AddrFrom4([4]byte{172, 31, byte(o), 9})
		in := false
		for _, p := range sum {
			if p.Contains(a) {
				in = true
			}
		}
		want := o >= config.PoolFirst && o <= config.PoolLast
		if in != want {
			t.Fatalf("172.31.%d.x covered=%v want %v (%v)", o, in, want, sum)
		}
	}
}

func TestNextIfaceNameAndPort(t *testing.T) {
	if n := NextIfaceName("wg-s", map[string]bool{"wg-s1": true, "wg-s2": true}); n != "wg-s3" {
		t.Fatal(n)
	}
	p, err := AllocatePort(3478, map[int]bool{3478: true, 3479: true})
	if err != nil || p != 3480 {
		t.Fatal(p, err)
	}
}

func TestKeys(t *testing.T) {
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicFromPrivate(k.Private)
	if err != nil || pub != k.Public {
		t.Fatal("public key mismatch")
	}
}
