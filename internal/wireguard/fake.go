package wireguard

import (
	"net/netip"
	"sync"
)

// Fake records specs in memory. Used by tests and GOVPN_DRY_RUN=1.
type Fake struct {
	mu     sync.Mutex
	Ifaces map[string]IfaceSpec
	Used   []netip.Prefix
	Status map[string]map[string]PeerStatus
	Calls  int
}

func NewFake() *Fake {
	return &Fake{Ifaces: map[string]IfaceSpec{}, Status: map[string]map[string]PeerStatus{}}
}

func (f *Fake) Sync(specs []IfaceSpec, owned func(string) bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls++
	next := map[string]IfaceSpec{}
	for _, s := range specs {
		next[s.Name] = s
	}
	for name, s := range f.Ifaces {
		if _, ok := next[name]; !ok && !owned(name) {
			next[name] = s
		}
	}
	f.Ifaces = next
	return nil
}

func (f *Fake) Peers(name string) (map[string]PeerStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]PeerStatus{}
	for k, v := range f.Status[name] {
		out[k] = v
	}
	return out, nil
}

func (f *Fake) UsedPrefixes(func(string) bool) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Prefix(nil), f.Used...), nil
}

func (f *Fake) Close() error { return nil }
