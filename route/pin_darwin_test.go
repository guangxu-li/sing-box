//go:build darwin

package route

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/sagernet/sing/common/control"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestIsPhysicalInterface(t *testing.T) {
	t.Parallel()
	// Flag sets observed on the target machine.
	const (
		ethernet = net.FlagUp | net.FlagBroadcast | net.FlagRunning | net.FlagMulticast
		tunnel   = net.FlagUp | net.FlagPointToPoint | net.FlagRunning | net.FlagMulticast
		loopback = net.FlagUp | net.FlagLoopback | net.FlagRunning | net.FlagMulticast
	)
	testCases := []struct {
		name     string
		flags    net.Flags
		expected bool
	}{
		{"ethernet or wifi", ethernet, true},
		// The whole point: a utun holding a default route must never be pinned to.
		{"tunnel", tunnel, false},
		{"loopback", loopback, false},
		{"down ethernet", ethernet &^ net.FlagUp, false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, testCase.expected, isPhysicalInterface(testCase.flags))
		})
	}
}

func TestPhysicalDefaultGatewayIgnoresTunnels(t *testing.T) {
	t.Parallel()
	finder := control.NewDefaultInterfaceFinder()
	require.NoError(t, finder.Update())
	gateway, err := physicalDefaultGateway(finder.Interfaces(), true)
	require.NoError(t, err)
	if !gateway.IsValid() {
		t.Skip("no physical default route on this host")
	}
	// The gateway must sit on the subnet of some physical interface. Asserting a
	// unique owner would be wrong: a tunnel interface may carry a prefix which also
	// contains the LAN gateway, and would then look like its owner.
	var reachableVia string
	for _, netInterface := range finder.Interfaces() {
		if !isPhysicalInterface(netInterface.Flags) {
			continue
		}
		for _, address := range netInterface.Addresses {
			if address.Contains(gateway) {
				reachableVia = netInterface.Name
			}
		}
	}
	require.NotEmpty(t, reachableVia, "gateway %s is on no physical interface", gateway)
	t.Logf("physical default gateway %s via %s", gateway, reachableVia)
}

func TestSystemHostRouteGateways(t *testing.T) {
	t.Parallel()
	// An address with no host route must simply be absent, not error or panic.
	absent := netip.MustParseAddr("192.0.2.1")
	gateways, err := systemHostRouteGateways([]netip.Addr{absent})
	require.NoError(t, err)
	require.NotContains(t, gateways, absent)
}

// A host route can only be installed through a gateway of the same family, so a
// v6 pin must never be handed the v4 default gateway.
func TestPhysicalDefaultGatewayIsPerFamily(t *testing.T) {
	t.Parallel()
	finder := control.NewDefaultInterfaceFinder()
	require.NoError(t, finder.Update())
	for _, is4 := range []bool{true, false} {
		gateway, err := physicalDefaultGateway(finder.Interfaces(), is4)
		require.NoError(t, err)
		if !gateway.IsValid() {
			continue
		}
		require.Equal(t, is4, gateway.Is4(), "asked for is4=%v, got %s", is4, gateway)
	}
}

// The install side and the read-back side must agree on the zone. netip.Addr
// equality counts the zone, so if only one side carried it, a link local gateway
// would never compare equal, every update would rewrite the pin, and the route
// message that rewrite emits would trigger the next update: a permanent loop.
func TestGatewayReadbackCarriesZone(t *testing.T) {
	t.Parallel()
	linkLocal := netip.MustParseAddr("fe80::1")
	addresses := []route.Addr{
		unix.RTAX_DST:     &route.Inet6Addr{IP: netip.MustParseAddr("2001:db8::1").As16()},
		unix.RTAX_GATEWAY: &route.Inet6Addr{IP: linkLocal.As16(), ZoneID: 14},
	}
	gateway := routeGatewayAt(addresses, 14)
	require.True(t, gateway.IsLinkLocalUnicast())
	require.Equal(t, "14", gateway.Zone(), "a link local gateway is ambiguous without its zone")

	// Same message, no explicit zone: the route's own interface index stands in.
	addresses[unix.RTAX_GATEWAY] = &route.Inet6Addr{IP: linkLocal.As16()}
	require.Equal(t, gateway, routeGatewayAt(addresses, 14), "install and read-back must produce the same value")

	// A global gateway needs no zone and must not acquire one.
	addresses[unix.RTAX_GATEWAY] = &route.Inet6Addr{IP: netip.MustParseAddr("2001:db8::ffff").As16(), ZoneID: 14}
	require.Empty(t, routeGatewayAt(addresses, 14).Zone())
}

// A pin whose address is no longer wanted must come out while the process runs, not
// linger until it exits. Removal has to use the same ownership rule as shutdown: the
// kernel deletes a host route by destination, so removing one that something else has
// since replaced would take theirs.
func TestRemovePinDisownsRouteTakenOver(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		// Correct code reaches no syscall here. A regressed disown branch would, and
		// as root the restore that follows would install a real route on the host,
		// which would also make this test pass without noticing the regression.
		t.Skip("needs to be unprivileged so a regression cannot mutate the routing table")
	}
	address := netip.MustParseAddr("192.0.2.55")
	ours := netip.MustParseAddr("192.168.0.1")
	theirs := netip.MustParseAddr("127.0.0.1")
	manager := &NetworkManager{pinnedRoutes: map[netip.Addr]pinnedRoute{
		address: {gateway: ours, displaced: theirs},
	}}

	// Installed gateway is not the one we recorded, so it belongs to someone else now.
	err := manager.removePinLocked(address, pinnedRoute{gateway: ours, displaced: theirs},
		map[netip.Addr]netip.Addr{address: theirs})
	require.NoError(t, err, "disowning must not attempt a removal, so it cannot fail")
	require.NotContains(t, manager.pinnedRoutes, address, "the record must be dropped")
}

// A removal that fails keeps its record, so a later attempt can retry rather than
// silently forgetting a route this process installed.
func TestRemovePinKeepsRecordOnFailure(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("needs to be unprivileged so the route write fails")
	}
	address := netip.MustParseAddr("192.0.2.56")
	gateway := netip.MustParseAddr("192.168.0.1")
	manager := &NetworkManager{pinnedRoutes: map[netip.Addr]pinnedRoute{
		address: {gateway: gateway},
	}}
	err := manager.removePinLocked(address, pinnedRoute{gateway: gateway},
		map[netip.Addr]netip.Addr{address: gateway})
	require.Error(t, err)
	require.Contains(t, manager.pinnedRoutes, address, "a failed removal must stay recorded")
}
