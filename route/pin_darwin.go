package route

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const pinEndpointsSupported = true

// physicalDefaultGateway returns the gateway of the first default route of the
// requested family leaving through a physical interface. Tunnels are skipped:
// pinning a transport into one is exactly the capture this option prevents.
//
// A gateway is looked up per family because a host route can only be installed
// through a gateway of the same family, and the two default routes need not leave
// through the same interface.
func physicalDefaultGateway(interfaces []control.Interface, is4 bool) (netip.Addr, error) {
	// Filtered in the kernel: only gateway routes are wanted, and this runs on
	// every network environment update.
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBType(unix.NET_RT_FLAGS), unix.RTF_GATEWAY)
	if err != nil {
		return netip.Addr{}, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, message := range messages {
		routeMessage, isRouteMessage := message.(*route.RouteMessage)
		if !isRouteMessage || routeMessage.Flags&unix.RTF_UP == 0 || routeMessage.Flags&unix.RTF_GATEWAY == 0 {
			continue
		}
		destination := routeAddressAt(routeMessage.Addrs, unix.RTAX_DST)
		if !destination.IsValid() || !destination.IsUnspecified() || destination.Is4() != is4 {
			continue
		}
		gateway := routeGatewayAt(routeMessage.Addrs, routeMessage.Index)
		if !gateway.IsValid() || gateway.Is4() != is4 {
			continue
		}
		index := slices.IndexFunc(interfaces, func(it control.Interface) bool {
			return it.Index == routeMessage.Index
		})
		if index == -1 || !isPhysicalInterface(interfaces[index].Flags) {
			continue
		}
		return gateway, nil
	}
	return netip.Addr{}, nil
}

// isPhysicalInterface matches the test the bridge backend uses to collect local
// segments: a physical link is up and broadcast capable, and is neither loopback
// nor a point to point tunnel.
func isPhysicalInterface(flags net.Flags) bool {
	return flags&net.FlagUp != 0 &&
		flags&net.FlagBroadcast != 0 &&
		flags&net.FlagLoopback == 0 &&
		flags&net.FlagPointToPoint == 0
}

// systemHostRouteGateways reports the gateway currently installed for each of
// destinations, so that unchanged pins are left alone.
//
// Per-route metrics are deliberately not consulted. An explicitly set MTU cannot be
// told apart from one the kernel wrote itself: path MTU discovery lowers rmx_mtu in
// place on an existing host route, and can set RTV_MTU in rmx_locks while doing so,
// so neither a value differing from the interface's nor the lock bit identifies an
// administrator's setting. Treating either as one would refuse to pin an address
// after a routine kernel event.
//
// Gateways are read exactly as they are written, zone included: netip.Addr
// equality counts the zone, so reading a link local gateway without one would
// never match what was installed, and every update would rewrite the pin, which
// emits the route message that triggers the next update.
func systemHostRouteGateways(destinations []netip.Addr) (map[netip.Addr]netip.Addr, error) {
	// Filtered in the kernel: only host routes are wanted. NET_RT_FLAGS matches any
	// of the requested flags rather than all of them, so a single flag is passed and
	// the rest of the predicate stays below.
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBType(unix.NET_RT_FLAGS), unix.RTF_HOST)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	gateways := make(map[netip.Addr]netip.Addr)
	for _, message := range messages {
		routeMessage, isRouteMessage := message.(*route.RouteMessage)
		if !isRouteMessage || routeMessage.Flags&unix.RTF_HOST == 0 {
			continue
		}
		if routeMessage.Flags&unix.RTF_IFSCOPE != 0 {
			// execHostRoute installs unscoped routes, so an interface scoped one is a
			// different object: reading it as this process's pin would either skip
			// installing the real one or leak it at shutdown.
			continue
		}
		destination := routeAddressAt(routeMessage.Addrs, unix.RTAX_DST)
		if !slices.Contains(destinations, destination) {
			continue
		}
		if routeMessage.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 {
			// Deny semantics execHostRoute cannot reproduce: it writes a fixed
			// UP|GATEWAY|HOST|STATIC, so putting such a route back would silently turn
			// it into an ordinary reachable one. Record it as unrepresentable, which
			// makes the caller leave it alone, exactly as it does for interface routes.
			gateways[destination] = netip.Addr{}
			continue
		}
		// Recorded even when the gateway is not an address: a route through an
		// interface (route.LinkAddr) has no IP gateway, and leaving it out would make
		// it indistinguishable from having no route at all, so teardown would delete
		// a route belonging to someone else. An invalid value therefore means "a route
		// exists here which this process cannot faithfully reproduce".
		gateway := routeGatewayAt(routeMessage.Addrs, routeMessage.Index)
		if recorded, found := gateways[destination]; found && recorded.IsValid() && !gateway.IsValid() {
			// A destination can still carry more than one unscoped host route, such as
			// a cloned neighbour entry whose gateway is a link address. Keep the
			// gateway that can be compared, so the result does not depend on the order
			// the table happens to be dumped in.
			continue
		}
		gateways[destination] = gateway
	}
	return gateways, nil
}

func pinHostRoute(destination netip.Addr, gateway netip.Addr) error {
	err := execHostRoute(unix.RTM_ADD, destination, gateway)
	if errors.Is(err, unix.EEXIST) {
		err = execHostRoute(unix.RTM_DELETE, destination, gateway)
		if err != nil {
			return E.Cause(err, "remove existing route")
		}
		err = execHostRoute(unix.RTM_ADD, destination, gateway)
	}
	return err
}

// isRouteMissing reports whether a removal failed because the route was already
// gone, which is not an error worth surfacing: the displaced route still needs
// putting back either way. The errno is platform specific, so the test lives here.
func isRouteMissing(err error) bool {
	return errors.Is(err, unix.ESRCH)
}

func unpinHostRoute(destination netip.Addr, gateway netip.Addr) error {
	return execHostRoute(unix.RTM_DELETE, destination, gateway)
}

// routeGatewayAt reads a gateway, preserving the scope an IPv6 gateway needs.
// Default gateways are usually link local, which are ambiguous without their
// zone, so the route's own interface index is used when the message omits one.
func routeGatewayAt(addresses []route.Addr, interfaceIndex int) netip.Addr {
	if len(addresses) <= unix.RTAX_GATEWAY {
		return netip.Addr{}
	}
	address, isInet6 := addresses[unix.RTAX_GATEWAY].(*route.Inet6Addr)
	if !isInet6 {
		return routeAddressAt(addresses, unix.RTAX_GATEWAY)
	}
	gateway := netip.AddrFrom16(address.IP)
	if !gateway.IsLinkLocalUnicast() {
		return gateway
	}
	zone := address.ZoneID
	if zone == 0 {
		zone = interfaceIndex
	}
	return gateway.WithZone(F.ToString(zone))
}

func execHostRoute(rtmType int, destination netip.Addr, gateway netip.Addr) error {
	routeMessage := route.RouteMessage{
		Type:    rtmType,
		Version: unix.RTM_VERSION,
		Flags:   unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_HOST,
		Seq:     1,
	}
	if rtmType == unix.RTM_ADD {
		routeMessage.Flags |= unix.RTF_UP
	}
	if destination.Is4() {
		routeMessage.Addrs = []route.Addr{
			unix.RTAX_DST:     &route.Inet4Addr{IP: destination.As4()},
			unix.RTAX_GATEWAY: &route.Inet4Addr{IP: gateway.As4()},
		}
	} else {
		var zone int
		if gateway.Zone() != "" {
			zone, _ = strconv.Atoi(gateway.Zone())
		}
		routeMessage.Addrs = []route.Addr{
			unix.RTAX_DST:     &route.Inet6Addr{IP: destination.As16()},
			unix.RTAX_GATEWAY: &route.Inet6Addr{IP: gateway.As16(), ZoneID: zone},
		}
	}
	request, err := routeMessage.Marshal()
	if err != nil {
		return err
	}
	socketFd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socketFd)
	return common.Error(unix.Write(socketFd, request))
}
