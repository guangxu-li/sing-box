package adapter

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

type NetworkManager interface {
	Lifecycle
	Initialize(ruleSets []RuleSet)
	InterfaceFinder() control.InterfaceFinder
	UpdateInterfaces() error
	// UpdatePinnedRoutes re-asserts pinned routes and removes those no longer wanted.
	// Endpoint membership is not observable here, so a caller which adds or removes
	// endpoints at runtime can call this to reconcile immediately. Nothing in-tree
	// does; a route change reconciles the same state anyway, just later.
	UpdatePinnedRoutes() error
	DefaultNetworkInterface() *NetworkInterface
	NetworkInterfaces() []NetworkInterface
	NetworkEnvironment() uint64
	AutoDetectInterface() bool
	AutoDetectInterfaceFunc() control.Func
	ProtectFunc() control.Func
	DefaultOptions() NetworkOptions
	RegisterAutoRedirectOutputMark(mark uint32) error
	AutoRedirectOutputMark() uint32
	AutoRedirectOutputMarkFunc() control.Func
	NetworkMonitor() tun.NetworkUpdateMonitor
	InterfaceMonitor() tun.DefaultInterfaceMonitor
	PackageManager() tun.PackageManager
	NeedWIFIState() bool
	WIFIState() WIFIState
	UpdateWIFIState(ctx context.Context)
	ResetNetwork(ctx context.Context)
}

type NetworkOptions struct {
	BindInterface        string
	RoutingMark          uint32
	DomainResolver       string
	DomainResolveOptions DNSQueryOptions
	NetworkStrategy      *C.NetworkStrategy
	NetworkType          []C.InterfaceType
	FallbackNetworkType  []C.InterfaceType
	FallbackDelay        time.Duration
}

type InterfaceUpdateListener interface {
	InterfaceUpdated(ctx context.Context)
}

// PinnedEndpoint is implemented by endpoints whose transport must never travel
// inside another tunnel, and reports the remote addresses to pin to the physical
// gateway. Domain endpoints are omitted, since they are resolved per dial.
type PinnedEndpoint interface {
	PinnedAddresses() []netip.Addr
}

type WIFIState struct {
	SSID  string
	BSSID string
}

func NormalizeWIFIBSSID(bssid string) string {
	bssid = strings.TrimSpace(bssid)
	if bssid == "" {
		return ""
	}
	parsed, err := net.ParseMAC(bssid)
	if err == nil && len(parsed) == 6 {
		return parsed.String()
	}
	if len(bssid) == 12 {
		decoded, err := hex.DecodeString(bssid)
		if err == nil {
			return net.HardwareAddr(decoded).String()
		}
	}
	return bssid
}

type NetworkInterface struct {
	control.Interface
	Type        C.InterfaceType
	DNSServers  []string
	Gateways    []netip.Addr
	Expensive   bool
	Constrained bool
}
