package dialer

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"

	"github.com/stretchr/testify/require"
)

func newTestInterface(index int, name string, flags net.Flags, addresses ...string) control.Interface {
	return control.Interface{
		Index:     index,
		Name:      name,
		Flags:     flags,
		Addresses: common.Map(addresses, netip.MustParsePrefix),
	}
}

func TestMatchInterfaceByAddressPrefix(t *testing.T) {
	t.Parallel()
	const up = net.FlagUp | net.FlagRunning
	testCases := []struct {
		name       string
		interfaces []control.Interface
		prefix     string
		expected   string
	}{
		{
			// The point of the option: the interface name is unstable, the address range is not.
			name: "selects the interface holding an address in the prefix",
			interfaces: []control.Interface{
				newTestInterface(1, "en0", up, "198.51.100.7/24"),
				newTestInterface(9, "tunA", up, "10.1.2.3/24"),
			},
			prefix:   "10.0.0.0/8",
			expected: "tunA",
		},
		{
			// Fail closed: an interface which is no longer carrying traffic must never be
			// selected, otherwise traffic silently leaks onto a path which cannot reach.
			name: "ignores interfaces which are not running",
			interfaces: []control.Interface{
				newTestInterface(9, "tunA", net.FlagUp, "10.1.2.3/24"),
			},
			prefix:   "10.0.0.0/8",
			expected: "",
		},
		{
			// Same rule as InterfaceFinder.ByAddr, so that address resolution behaves
			// consistently wherever it appears.
			name: "selects the first match when multiple interfaces match",
			interfaces: []control.Interface{
				newTestInterface(12, "tunC", up, "10.1.3.1/24"),
				newTestInterface(9, "tunA", up, "10.1.2.3/24"),
				newTestInterface(11, "tunB", up, "10.1.4.1/24"),
			},
			prefix:   "10.0.0.0/8",
			expected: "tunC",
		},
		{
			name: "returns nothing when no interface matches",
			interfaces: []control.Interface{
				newTestInterface(1, "en0", up, "198.51.100.7/24"),
			},
			prefix:   "10.0.0.0/8",
			expected: "",
		},
		{
			name: "matches IPv6 addresses",
			interfaces: []control.Interface{
				newTestInterface(1, "en0", up, "198.51.100.7/24", "fe80::1/64"),
				newTestInterface(9, "tunA", up, "2001:db8:1::1/64"),
			},
			prefix:   "2001:db8::/32",
			expected: "tunA",
		},
		{
			// An IPv4 address must not match an IPv6 prefix, or the reverse.
			name: "does not match across address families",
			interfaces: []control.Interface{
				newTestInterface(9, "tunA", up, "10.1.2.3/24"),
			},
			prefix:   "::/0",
			expected: "",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			selected := matchInterfaceByAddressPrefix(testCase.interfaces, netip.MustParsePrefix(testCase.prefix))
			if testCase.expected == "" {
				require.Nil(t, selected)
			} else {
				require.NotNil(t, selected)
				require.Equal(t, testCase.expected, selected.Name)
			}
		})
	}
}

// testInterfaceFinder is a finder whose Update() swaps in a new set of interfaces,
// standing in for an interface being renumbered while sing-box is running.
type testInterfaceFinder struct {
	control.InterfaceFinder
	interfaces  []control.Interface
	onUpdate    []control.Interface
	updateCount int
}

func (f *testInterfaceFinder) Interfaces() []control.Interface {
	return f.interfaces
}

func (f *testInterfaceFinder) Update() error {
	f.updateCount++
	f.interfaces = f.onUpdate
	return nil
}

func TestInterfaceAddressBinder(t *testing.T) {
	t.Parallel()
	const up = net.FlagUp | net.FlagRunning
	prefix := netip.MustParsePrefix("10.0.0.0/8")

	t.Run("does not update the finder when the cache already matches", func(t *testing.T) {
		t.Parallel()
		finder := &testInterfaceFinder{
			interfaces: []control.Interface{newTestInterface(9, "tunA", up, "10.1.2.3/24")},
		}
		binder := &interfaceAddressBinder{finder: finder, prefix: prefix}
		name, index, err := binder.bind("tcp4", "10.1.2.3:80")
		require.NoError(t, err)
		require.Equal(t, "tunA", name)
		require.Equal(t, 9, index)
		require.Zero(t, finder.updateCount)
	})

	t.Run("updates the finder once when the cache is stale", func(t *testing.T) {
		// The reason this option exists: the VPN reconnects onto a different interface.
		// The next dial must find it, without sing-box being restarted, even if the
		// interface monitor has not refreshed the cache yet.
		t.Parallel()
		finder := &testInterfaceFinder{
			interfaces: []control.Interface{newTestInterface(9, "tunA", up, "10.1.2.3/24")},
			onUpdate:   []control.Interface{newTestInterface(3, "tunD", up, "10.1.9.9/24")},
		}
		binder := &interfaceAddressBinder{finder: finder, prefix: prefix}
		_, _, err := binder.bind("tcp4", "10.1.2.3:80")
		require.NoError(t, err)
		require.Zero(t, finder.updateCount)

		// The interface is renumbered behind the cache.
		finder.interfaces = []control.Interface{newTestInterface(9, "tunA", up)}
		name, index, err := binder.bind("tcp4", "10.1.2.3:80")
		require.NoError(t, err)
		require.Equal(t, "tunD", name)
		require.Equal(t, 3, index)
		require.Equal(t, 1, finder.updateCount)
	})

	t.Run("fails the dial when no interface matches", func(t *testing.T) {
		// Fail closed: traffic for the prefix must never fall back to another path.
		t.Parallel()
		finder := &testInterfaceFinder{
			interfaces: []control.Interface{newTestInterface(1, "en0", up, "198.51.100.7/24")},
			onUpdate:   []control.Interface{newTestInterface(1, "en0", up, "198.51.100.7/24")},
		}
		binder := &interfaceAddressBinder{finder: finder, prefix: prefix}
		_, index, err := binder.bind("tcp4", "10.1.2.3:80")
		require.ErrorContains(t, err, "no interface with an address in 10.0.0.0/8")
		require.Equal(t, -1, index)
		require.Equal(t, 1, finder.updateCount)
	})

	t.Run("rate limits enumeration while nothing matches", func(t *testing.T) {
		// With the VPN down, a client that retries hard would otherwise enumerate
		// every interface and fire the finder's update callbacks on every dial.
		t.Parallel()
		finder := &testInterfaceFinder{
			interfaces: []control.Interface{newTestInterface(1, "en0", up, "198.51.100.7/24")},
			onUpdate:   []control.Interface{newTestInterface(1, "en0", up, "198.51.100.7/24")},
		}
		binder := &interfaceAddressBinder{finder: finder, prefix: prefix}
		for range 100 {
			_, _, err := binder.bind("tcp4", "10.1.2.3:80")
			require.Error(t, err)
		}
		require.Equal(t, 1, finder.updateCount, "100 failed dials must not mean 100 enumerations")

		// Once the interval has passed the next miss refreshes again, so the option
		// still recovers on its own when the interface comes back.
		binder.lastRefresh.Store(time.Now().Add(-interfaceRefreshInterval))
		finder.onUpdate = []control.Interface{newTestInterface(3, "tunD", up, "10.1.9.9/24")}
		name, _, err := binder.bind("tcp4", "10.1.2.3:80")
		require.NoError(t, err)
		require.Equal(t, "tunD", name)
		require.Equal(t, 2, finder.updateCount)
	})
}
