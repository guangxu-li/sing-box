//go:build !darwin

package route

import (
	"net/netip"
	"os"

	"github.com/sagernet/sing/common/control"
)

const pinEndpointsSupported = false

func physicalDefaultGateway(interfaces []control.Interface, is4 bool) (netip.Addr, error) {
	return netip.Addr{}, os.ErrInvalid
}

func systemHostRouteGateways(destinations []netip.Addr) (map[netip.Addr]netip.Addr, error) {
	return nil, os.ErrInvalid
}

func pinHostRoute(destination netip.Addr, gateway netip.Addr) error {
	return os.ErrInvalid
}

func isRouteMissing(err error) bool {
	return false
}

func unpinHostRoute(destination netip.Addr, gateway netip.Addr) error {
	return os.ErrInvalid
}
