package settings

// DNSHijack redirects the system's loopback DNS port into a local listener.
//
// A tunnel cannot capture loopback by routing, so this is the only way to take
// over :53 from a VPN client which has registered itself as the system resolver.
type DNSHijack interface {
	IsEnabled() bool
	Enable() error
	Disable() error
	Close() error
}
