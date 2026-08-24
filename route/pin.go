package route

import (
	"maps"
	"net/netip"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

func (r *NetworkManager) pinningEnabled() bool {
	return r.pinEndpoints || len(r.pinnedRouteAddresses) > 0
}

// pinnedRoute is a host route this process installed, and the gateway of whatever
// route it replaced, if any.
type pinnedRoute struct {
	gateway   netip.Addr
	displaced netip.Addr
}

// pinnedAddresses collects the transport addresses which must never be captured
// by another tunnel's default route: those sing-box can derive from its own
// endpoints, plus any listed by hand.
//
// The hand listed ones are not redundant. A host route is process agnostic, and
// the addresses most in need of one often belong to a separate binary sing-box
// knows nothing about, such as another WireGuard client on the same machine.
func (r *NetworkManager) pinnedAddresses() []netip.Addr {
	addresses := append([]netip.Addr(nil), r.pinnedRouteAddresses...)
	if r.pinEndpoints && r.endpoint != nil {
		for _, it := range r.endpoint.Endpoints() {
			pinnedEndpoint, isPinned := it.(adapter.PinnedEndpoint)
			if !isPinned {
				continue
			}
			addresses = append(addresses, pinnedEndpoint.PinnedAddresses()...)
		}
	}
	return common.Filter(common.Uniq(addresses), func(it netip.Addr) bool {
		// A host route to an interface scoped address does not survive the routing
		// table read back used to decide whether a pin is already correct. Hand
		// listed ones are rejected at construction; a derived one is skipped here.
		return !it.IsLinkLocalUnicast() && it.Zone() == ""
	})
}

// UpdatePinnedRoutes re-asserts a host route towards every pinned address through
// the physical default gateway of that address's family, and removes any pin whose
// address is no longer wanted.
//
// Exported so a caller which adds or removes endpoints at runtime can ask for
// reconciliation: membership changes are not observable from here, and nothing in
// sing-box notifies dependents of them. This mirrors UpdateInterfaces in shape only
// — that one has in-tree cross-package callers, this has none today — so the export
// buys immediate reconciliation rather than waiting for the next route change, which
// would reconcile the same state anyway.
//
// Routes are only rewritten when the installed gateway differs. That is not just
// an optimization: writing a route emits a route message, which is what triggers
// this update in the first place, so rewriting unconditionally would loop.
func (r *NetworkManager) UpdatePinnedRoutes() error {
	if !r.pinningEnabled() {
		return nil
	}
	addresses := r.pinnedAddresses()
	interfaces := r.interfaceFinder.Interfaces()
	r.pinAccess.Lock()
	defer r.pinAccess.Unlock()
	if r.pinClosed {
		// Shutdown already removed the pins. A route change can still be in flight
		// here, and reinstalling now would leave them behind for good.
		return nil
	}
	if len(addresses) == 0 && len(r.pinnedRoutes) == 0 {
		// Nothing wanted and nothing recorded, which is the steady state while
		// pin_endpoints is set but no endpoint implements PinnedEndpoint yet. Reading
		// the routing table below costs a full dump whatever it is asked for, so it is
		// not worth paying on every route change for nothing.
		return nil
	}
	// Read for the recorded addresses as well as the wanted ones: an endpoint can be
	// removed at runtime, and its pin has to come out then rather than surviving
	// until the process exits.
	//
	// Deliberately under pinAccess, unlike the pre-reconciliation version: the
	// recorded set is part of the query, and snapshotting its keys before taking the
	// lock would let it change underneath. pinAccess is taken only here and by
	// shutdown, so the added hold time is uncontended.
	installed, err := systemHostRouteGateways(append(slices.Collect(maps.Keys(r.pinnedRoutes)), addresses...))
	if err != nil {
		// Without knowing what is installed, every address would look unpinned and be
		// rewritten, which emits the route messages that trigger the next update.
		return E.Cause(err, "read installed routes")
	}
	var pinErr error
	for address, pinned := range r.pinnedRoutes {
		if slices.Contains(addresses, address) {
			continue
		}
		removeErr := r.removePinLocked(address, pinned, installed)
		if removeErr != nil {
			pinErr = E.Errors(pinErr, removeErr)
			continue
		}
		r.logger.Info("unpinned ", address, ", no longer wanted")
	}
	if len(addresses) == 0 {
		return pinErr
	}
	// Resolved once per family rather than once per address: each lookup dumps the
	// whole routing table, and this runs on every route change.
	gateways := make(map[bool]netip.Addr, 2)
	for _, is4 := range []bool{true, false} {
		gateway, err := physicalDefaultGateway(interfaces, is4)
		if err != nil {
			pinErr = E.Errors(pinErr, E.Cause(err, "find default gateway"))
			continue
		}
		gateways[is4] = gateway
	}
	for _, address := range addresses {
		gateway := gateways[address.Is4()]
		if !gateway.IsValid() {
			// No physical default route for this family right now. Leave whatever is
			// installed alone rather than pinning into a tunnel, which is the capture
			// this prevents.
			continue
		}
		previous, hadRoute := installed[address]
		if hadRoute && !previous.IsValid() {
			// A route this process cannot reproduce: one through an interface rather
			// than a gateway, or one carrying deny semantics. The kernel deletes a host
			// route by destination, so replacing it would destroy it and it could not be
			// put back as it was. Leave it alone: everything else here refuses to remove
			// a route this process did not create.
			//
			// Reported as an error, not merely logged: the address is then unpinned, and
			// an unpinned transport is the capture this option exists to prevent, which
			// the start is supposed to refuse rather than run on with.
			pinErr = E.Errors(pinErr, E.New("cannot pin ", address,
				": a route to it exists which cannot be replaced reversibly, leaving its transport unprotected"))
			continue
		}
		if previous == gateway {
			// Already correct. Deliberately not recorded as ours unless it already is:
			// the route may belong to an administrator or another process, and removing
			// it on shutdown would break something this process never set up.
			continue
		}
		existing, hasRecord := r.pinnedRoutes[address]
		// A record is not ownership: another actor may have replaced the route since,
		// in which case theirs is what gets displaced now and what has to go back.
		isOurs := hasRecord && previous == existing.gateway
		err := pinHostRoute(address, gateway)
		if err != nil {
			pinErr = E.Errors(pinErr, E.Cause(err, "pin ", address, " to ", gateway))
			// Replacing is a delete followed by an add, so a failure here can already
			// have removed whatever was there, whether or not this process owned it.
			// Put it back rather than leaving the destination with no route.
			if previous.IsValid() {
				restoreErr := pinHostRoute(address, previous)
				if restoreErr != nil {
					r.logger.Error("restore ", address, " to ", previous, ": ", restoreErr)
					// Both the pin and putting back what it removed failed, so something is
					// still owed here. Only record it when the route just lost was not this
					// process's own: if it was, the existing record already names the right
					// obligation, and overwriting it would both discard the original
					// displaced gateway and claim a gateway which was never installed,
					// which teardown would then read as someone else's route and disown.
					if !isOurs {
						r.pinnedRoutes[address] = pinnedRoute{gateway: gateway, displaced: previous}
					}
				}
			}
			continue
		}
		pinned := pinnedRoute{gateway: gateway}
		switch {
		case isOurs, hasRecord && !previous.IsValid():
			// Keep the original displaced gateway, not the one just replaced, which was
			// this process's own. The second case is our route having been removed
			// outright rather than replaced: that cancels nothing this process still
			// owes whoever it displaced first.
			pinned.displaced = existing.displaced
		default:
			// Either nothing was there, or something another actor installed. Either
			// way that is what this process is displacing now.
			// Installing over a route this process did not create replaces it, since
			// the kernel deletes by destination. Remember it so teardown can put it
			// back rather than leaving the destination with no route at all.
			pinned.displaced = previous
		}
		r.pinnedRoutes[address] = pinned
		r.logger.Info("pinned ", address, " to ", gateway)
	}
	return pinErr
}

// clearPinnedRoutes removes the host routes installed by UpdatePinnedRoutes, so
// that a pin never outlives the process which owns it. Routes which could not be
// removed stay recorded, so a later attempt can still retry them.
func (r *NetworkManager) clearPinnedRoutes() error {
	if !r.pinningEnabled() {
		return nil
	}
	r.pinAccess.Lock()
	defer r.pinAccess.Unlock()
	r.pinClosed = true
	var err error
	// Re-read rather than trusting the record: another actor may have replaced a pin
	// since it was installed, and the kernel deletes a host route by destination, so
	// removing it blindly would take theirs.
	installed, readErr := systemHostRouteGateways(slices.Collect(maps.Keys(r.pinnedRoutes)))
	if readErr != nil {
		return E.Cause(readErr, "read installed routes")
	}
	for address, pinned := range r.pinnedRoutes {
		err = E.Errors(err, r.removePinLocked(address, pinned, installed))
	}
	return err
}

// removePinLocked removes one pin this process installed and puts back whatever it
// displaced. A pin which is no longer the installed route is disowned rather than
// removed, since the kernel deletes a host route by destination and taking it would
// take whatever replaced it. Callers hold pinAccess.
func (r *NetworkManager) removePinLocked(address netip.Addr, pinned pinnedRoute, installed map[netip.Addr]netip.Addr) error {
	if gateway, found := installed[address]; found && gateway != pinned.gateway {
		// No longer ours. Leave it, and leave the displaced route alone too.
		delete(r.pinnedRoutes, address)
		return nil
	}
	unpinErr := unpinHostRoute(address, pinned.gateway)
	if unpinErr != nil && !isRouteMissing(unpinErr) {
		// Kept recorded, so a later attempt can still retry it.
		return E.Cause(unpinErr, "unpin ", address)
	}
	// ESRCH means something already removed it, which still leaves the displaced
	// route to put back.
	if pinned.displaced.IsValid() {
		// Put back the route this process replaced, so a destination owned by
		// something else is not simply left without one.
		restoreErr := pinHostRoute(address, pinned.displaced)
		if restoreErr != nil {
			// Kept recorded, exactly as a failed unpin is: the next pass finds no route,
			// tolerates ESRCH on the unpin, and attempts the restore again.
			return E.Cause(restoreErr, "restore ", address, " to ", pinned.displaced)
		}
	}
	delete(r.pinnedRoutes, address)
	return nil
}
