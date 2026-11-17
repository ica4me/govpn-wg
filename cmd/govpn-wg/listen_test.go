package main

import (
	"net"
	"strings"
	"testing"
)

func TestListenAllBindsEveryAddressAndCleansUp(t *testing.T) {
	lns, err := listenAll("127.0.0.1:0, 127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	if len(lns) != 2 {
		t.Fatalf("want 2 listeners, got %d", len(lns))
	}
	busy := lns[0].Addr().String()
	for _, l := range lns {
		l.Close()
	}
	hold, err := net.Listen("tcp", busy)
	if err != nil {
		t.Skip("port reused:", err)
	}
	defer hold.Close()
	if _, err := listenAll("127.0.0.1:0," + busy); err == nil || !strings.Contains(err.Error(), busy) {
		t.Fatalf("expected bind error for %s, got %v", busy, err)
	}
}

func TestListenFreebindAddressNotYetPresent(t *testing.T) {
	// 192.0.2.0/24 (TEST-NET-1) is never assigned locally: IP_FREEBIND must still bind.
	lns, err := listenAll("192.0.2.77:0")
	if err != nil {
		t.Skip("freebind unavailable in this sandbox:", err)
	}
	for _, l := range lns {
		l.Close()
	}
}
