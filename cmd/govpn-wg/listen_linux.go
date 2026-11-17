//go:build linux

package main

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{}
	if ap, err := netip.ParseAddrPort(addr); err == nil && !ap.Addr().IsLoopback() && !ap.Addr().IsUnspecified() {
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	return lc.Listen(context.Background(), "tcp", addr)
}
