//go:build darwin

package settings

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/pf"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func newTestHijack(t *testing.T, tcp string, udp string, exclude string) *DarwinDNSHijack {
	t.Helper()
	var tcpAddr, udpAddr netip.AddrPort
	if tcp != "" {
		tcpAddr = netip.MustParseAddrPort(tcp)
	}
	if udp != "" {
		udpAddr = netip.MustParseAddrPort(udp)
	}
	var excludeAddr netip.Addr
	if exclude != "" {
		excludeAddr = netip.MustParseAddr(exclude)
	}
	hijack, err := NewDNSHijack(tcpAddr, udpAddr, excludeAddr)
	require.NoError(t, err)
	return hijack.(*DarwinDNSHijack)
}

// The ruleset these must reproduce, which ran as a hand written pf.conf:
//
//	rdr pass on lo0 inet proto { udp tcp } from ! 127.0.0.2 to 127.0.0.1 port 53 -> 127.0.0.1 port 5335
func TestDNSHijackRules(t *testing.T) {
	t.Parallel()
	rules := newTestHijack(t, "127.0.0.1:5335", "127.0.0.1:5335", "127.0.0.2").rules()
	require.Len(t, rules, 2, "one rule per listening protocol")

	protocols := make(map[uint8]bool)
	for _, anchorRule := range rules {
		rule := anchorRule.Rule
		// rdr has its own ruleset, distinct from nat: the kernel derives it from the
		// action and rejects the transaction with EBUSY if the ticket is the nat one.
		require.EqualValues(t, pf.RulesetRDR, anchorRule.RulesetIndex)
		require.EqualValues(t, pf.ActionRDR, rule.Action)
		require.EqualValues(t, pf.DirectionIn, rule.Direction)
		require.EqualValues(t, 1, rule.NatPass, "rdr pass")
		require.Equal(t, "lo0", string(rule.IfName[:3]))
		protocols[rule.Proto] = true

		// Destination port is network order inside a native uint16: 53 -> 0x3500.
		require.EqualValues(t, 53<<8, rule.Dst.Port[0])
		require.EqualValues(t, pf.OpEQ, rule.Dst.PortOp)
		// The redirect port is host order, because the kernel converts it itself.
		require.EqualValues(t, 5335, rule.RPool.ProxyPort[0])

		require.EqualValues(t, 1, rule.Src.Neg, "the loop break must be a negation")
		require.Equal(t, pf.HostAddress(netip.MustParseAddr("127.0.0.2")), rule.Src.Addr)
		require.Equal(t, pf.HostAddress(netip.MustParseAddr("127.0.0.1")), rule.Dst.Addr)
		require.Equal(t, pf.HostAddress(netip.MustParseAddr("127.0.0.1")), anchorRule.Pool.Addr)
	}
	require.Equal(t, map[uint8]bool{unix.IPPROTO_UDP: true, unix.IPPROTO_TCP: true}, protocols)
}

// Redirecting a protocol the listener never opened sends the host's DNS to a port
// nothing answers on, which breaks name resolution while startup reports success.
func TestDNSHijackOnlyRedirectsListeningProtocols(t *testing.T) {
	t.Parallel()
	tcpOnly := newTestHijack(t, "127.0.0.1:5335", "", "").rules()
	require.Len(t, tcpOnly, 1)
	require.EqualValues(t, unix.IPPROTO_TCP, tcpOnly[0].Rule.Proto)

	udpOnly := newTestHijack(t, "", "127.0.0.1:5335", "").rules()
	require.Len(t, udpOnly, 1)
	require.EqualValues(t, unix.IPPROTO_UDP, udpOnly[0].Rule.Proto)
}

// With listen_port left to the system, TCP and UDP bind different ephemeral ports.
// Each rule must carry its own socket's port.
func TestDNSHijackUsesEachSocketsOwnPort(t *testing.T) {
	t.Parallel()
	for _, anchorRule := range newTestHijack(t, "127.0.0.1:51111", "127.0.0.1:52222", "").rules() {
		switch anchorRule.Rule.Proto {
		case unix.IPPROTO_TCP:
			require.EqualValues(t, 51111, anchorRule.Rule.RPool.ProxyPort[0])
		case unix.IPPROTO_UDP:
			require.EqualValues(t, 52222, anchorRule.Rule.RPool.ProxyPort[0])
		}
	}
}

// An unspecified socket gives no way to tell which loopback it answers on, and a
// non-loopback one cannot be reached by an lo0 rdr rule at all, so both are
// refused rather than silently redirecting into nothing.
func TestDNSHijackRequiresLoopback(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"0.0.0.0:5335", "[::]:5335", "198.51.100.7:5335"} {
		_, err := NewDNSHijack(netip.MustParseAddrPort(address), netip.AddrPort{}, netip.Addr{})
		require.ErrorContains(t, err, "requires a loopback", address)
	}
	_, err := NewDNSHijack(netip.AddrPort{}, netip.AddrPort{}, netip.Addr{})
	require.ErrorContains(t, err, "no listening socket")
}

// Two listeners must not load into, and so flush, each other's anchor.
func TestDNSHijackAnchorIsPerListener(t *testing.T) {
	t.Parallel()
	// Nesting under com.apple/* is what lets the stock /etc/pf.conf evaluate these
	// rules without being edited; a top level anchor would silently never run.
	require.Equal(t, "com.apple/sing-box-dns-127-0-0-1-5335-tcp-udp",
		newTestHijack(t, "127.0.0.1:5335", "127.0.0.1:5335", "").anchorName)
	require.Equal(t, "com.apple/sing-box-dns---1-5335-tcp",
		newTestHijack(t, "[::1]:5335", "", "").anchorName)
	require.NotEqual(t,
		newTestHijack(t, "127.0.0.1:5335", "", "").anchorName,
		newTestHijack(t, "127.0.0.1:5336", "", "").anchorName)
	// TCP and UDP have separate port spaces, so the same address and port number
	// can legitimately belong to two different listeners.
	require.NotEqual(t,
		newTestHijack(t, "127.0.0.1:5335", "", "").anchorName,
		newTestHijack(t, "", "127.0.0.1:5335", "").anchorName)
	// Different exclusions mean different rules, so the anchors cannot be shared
	// either: one listener would otherwise load over the other's loop break.
	require.NotEqual(t,
		newTestHijack(t, "127.0.0.1:5335", "", "127.0.0.2").anchorName,
		newTestHijack(t, "127.0.0.1:5335", "", "127.0.0.3").anchorName)
}

func TestDNSHijackWithoutExcludeSource(t *testing.T) {
	t.Parallel()
	for _, anchorRule := range newTestHijack(t, "127.0.0.1:5335", "127.0.0.1:5335", "").rules() {
		require.Zero(t, anchorRule.Rule.Src.Neg)
		require.Equal(t, pf.AddrWrap{}, anchorRule.Rule.Src.Addr)
	}
}

// A v4 exclusion cannot be expressed in a v6 rule, so that family carries none,
// exactly as the hand written ruleset did.
func TestDNSHijackExclusionIsPerFamily(t *testing.T) {
	t.Parallel()
	rules := newTestHijack(t, "[::1]:5335", "", "127.0.0.2").rules()
	require.Len(t, rules, 1)
	require.Zero(t, rules[0].Rule.Src.Neg)
	require.EqualValues(t, pf.Family(false), rules[0].Rule.AF)
}

// pf rejects an anchor path component of 64 bytes or more, which a long IPv6
// exclusion reaches. The name must stay short without losing its distinctness.
func TestDNSHijackAnchorFitsPfLimit(t *testing.T) {
	t.Parallel()
	long := newTestHijack(t, "[::1]:5335", "[::1]:5335", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
	component := strings.TrimPrefix(long.anchorName, "com.apple/")
	require.Less(t, len(component), 64, "anchor component %q would be rejected by pf", component)

	// Still distinct: a different exclusion must not collapse onto the same name.
	other := newTestHijack(t, "[::1]:5335", "[::1]:5335", "2001:db8:ffff:ffff:ffff:ffff:ffff:fffe")
	require.NotEqual(t, long.anchorName, other.anchorName)

	// Short names are left readable rather than hashed.
	require.Contains(t, newTestHijack(t, "127.0.0.1:5335", "", "").anchorName, "127-0-0-1-5335")
}
