//go:build !darwin

package settings

import (
	"net/netip"
	"os"
)

func NewDNSHijack(tcpAddress netip.AddrPort, udpAddress netip.AddrPort, excludeSource netip.Addr) (DNSHijack, error) {
	return nil, os.ErrInvalid
}
