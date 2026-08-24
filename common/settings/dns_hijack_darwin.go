package settings

import (
	"encoding/binary"
	"hash/fnv"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/common/pf"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"

	"golang.org/x/sys/unix"
)

const (
	dnsPort = 53

	// A pf anchor path component must be shorter than PF_ANCHOR_NAME_SIZE.
	anchorComponentLimit = 63
	anchorPrefix         = "sing-box-dns-"
)

// dnsHijackRulesets is the only ruleset these rules live in, so loading them never
// disturbs rules another component owns.
var dnsHijackRulesets = []int32{pf.RulesetRDR}

// dnsHijackTarget is one socket to redirect into: the protocol it speaks and the
// address it actually bound.
type dnsHijackTarget struct {
	protocol uint8
	address  netip.AddrPort
}

type DarwinDNSHijack struct {
	targets       []dnsHijackTarget
	excludeSource netip.Addr
	anchorName    string
	access        sync.Mutex
	device        *pf.Device
	token         uint64
	isEnabled     bool
}

// NewDNSHijack redirects the loopback DNS port into the given sockets. A zero
// address means that network is not listening and is left alone, so the redirect
// never points at a socket which does not exist.
func NewDNSHijack(tcpAddress netip.AddrPort, udpAddress netip.AddrPort, excludeSource netip.Addr) (DNSHijack, error) {
	var targets []dnsHijackTarget
	for _, target := range []dnsHijackTarget{
		{unix.IPPROTO_TCP, tcpAddress},
		{unix.IPPROTO_UDP, udpAddress},
	} {
		if !target.address.IsValid() {
			continue
		}
		address := target.address.Addr().Unmap()
		// Only loopback can be captured this way, and only an explicit address can
		// be captured correctly: an unspecified socket gives no way to tell which
		// loopback it answers on, and guessing would redirect a family into a port
		// nothing is listening on.
		if !address.IsLoopback() {
			return nil, E.New("`dns_hijack_loopback` requires a loopback `listen` address, got ", address)
		}
		target.address = netip.AddrPortFrom(address, target.address.Port())
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return nil, E.New("no listening socket to redirect into")
	}
	// The rules are nested under com.apple/*, which only exists where the stock
	// /etc/pf.conf references it. Without that file the anchor is never traversed
	// and the redirect would silently do nothing, so refuse instead.
	if _, err := os.Stat("/etc/pf.conf"); err != nil {
		return nil, E.Cause(err, "`dns_hijack_loopback` requires the system /etc/pf.conf")
	}
	return &DarwinDNSHijack{
		targets:       targets,
		excludeSource: excludeSource,
		// Nesting under com.apple/* means the stock /etc/pf.conf, whose rdr-anchor
		// and anchor lines already wildcard that prefix, evaluates these rules
		// without being edited. The address is part of the name so that two
		// listeners never load into, and flush, each other's anchor.
		anchorName: "com.apple/" + anchorPrefix + anchorLabel(targets, excludeSource),
	}, nil
}

// anchorLabel renders the targets for use inside a pf anchor name, which is a
// path component and so cannot carry the colons of an IPv6 address. The protocols
// are part of it because TCP and UDP have separate port spaces, so two listeners
// may legitimately hold the same address and port number, and so is the exclusion,
// which changes what the rules do.
func anchorLabel(targets []dnsHijackTarget, excludeSource netip.Addr) string {
	address := targets[0].address
	label := strings.NewReplacer(":", "-", ".", "-").Replace(address.Addr().String()) +
		"-" + F.ToString(address.Port())
	for _, target := range targets {
		if target.protocol == unix.IPPROTO_TCP {
			label += "-tcp"
		} else {
			label += "-udp"
		}
	}
	if excludeSource.IsValid() {
		// Two listeners which agree on address, port and protocol but not on the
		// exclusion do not produce interchangeable rules, so they cannot share.
		label += "-x" + strings.NewReplacer(":", "-", ".", "-").Replace(excludeSource.String())
	}
	if len(anchorPrefix)+len(label) > anchorComponentLimit {
		// pf rejects an anchor path component of anchorComponentLimit bytes or more,
		// which a long IPv6 exclusion can reach. Identity still has to be stable and
		// distinct, so fall back to a digest of the same inputs.
		digest := fnv.New64a()
		digest.Write([]byte(label))
		label = strconv.FormatUint(digest.Sum64(), 16)
	}
	return label
}

func (h *DarwinDNSHijack) IsEnabled() bool {
	h.access.Lock()
	defer h.access.Unlock()
	return h.isEnabled
}

func (h *DarwinDNSHijack) Enable() error {
	h.access.Lock()
	defer h.access.Unlock()
	if h.isEnabled {
		return nil
	}
	device, err := pf.OpenDevice()
	if err != nil {
		return err
	}
	// Reference counted, so disabling ours never switches pf off for anything else.
	token, err := device.StartReference()
	if err != nil {
		return E.Errors(E.Cause(err, "enable pf"), device.Close())
	}
	err = device.LoadAnchor(h.anchorName, dnsHijackRulesets, h.rules())
	if err != nil {
		// Reported alongside the load failure: a pf reference which could not be
		// dropped here outlives the process, so it should not be swallowed.
		return E.Errors(E.Cause(err, "load anchor ", h.anchorName), device.StopReference(token), device.Close())
	}
	h.device = device
	h.token = token
	h.isEnabled = true
	return nil
}

func (h *DarwinDNSHijack) Disable() error {
	h.access.Lock()
	defer h.access.Unlock()
	return h.disableLocked()
}

func (h *DarwinDNSHijack) disableLocked() error {
	if !h.isEnabled || h.device == nil {
		return nil
	}
	// Loading an empty anchor is the removal: leaving the rules behind would
	// redirect the system's DNS into a port nothing is listening on.
	err := h.device.LoadAnchor(h.anchorName, dnsHijackRulesets, nil)
	if err != nil {
		// Leave isEnabled set so the rules stay owned and a retry is still possible.
		return E.Cause(err, "unload anchor ", h.anchorName)
	}
	err = h.device.StopReference(h.token)
	// Released here rather than only in Close, so repeated Enable/Disable cycles do
	// not leak a descriptor each. Enable opens a fresh one.
	err = E.Errors(err, h.device.Close())
	h.device = nil
	h.isEnabled = false
	return err
}

// Close runs the removal and the fd release under a single acquisition, so no
// concurrent Enable can reload the anchor onto a device about to be closed.
func (h *DarwinDNSHijack) Close() error {
	h.access.Lock()
	defer h.access.Unlock()
	err := h.disableLocked()
	if h.device != nil {
		// Closing /dev/pf does not release a pf enable reference, so it has to be
		// dropped explicitly even when the anchor would not unload; otherwise pf
		// stays referenced until reboot.
		if h.isEnabled {
			err = E.Errors(err, h.device.StopReference(h.token))
		}
		err = E.Errors(err, h.device.Close())
		h.device = nil
	}
	// The handle is gone, so no retry is possible and claiming otherwise would let a
	// later Enable return success without loading anything. The error is returned.
	h.isEnabled = false
	return err
}

// rules mirrors, per target:
//
//	rdr pass on lo0 proto <protocol> from ! <excluded> to <listen> port 53 -> <listen> port <listen port>
func (h *DarwinDNSHijack) rules() []pf.AnchorRule {
	rules := make([]pf.AnchorRule, 0, len(h.targets))
	for _, target := range h.targets {
		rules = append(rules, h.redirectRule(target))
	}
	return rules
}

func (h *DarwinDNSHijack) redirectRule(target dnsHijackTarget) pf.AnchorRule {
	listenAddr := target.address.Addr()
	is4 := listenAddr.Is4()
	rule := pf.Rule{
		Action:    pf.ActionRDR,
		Direction: pf.DirectionIn,
		AF:        pf.Family(is4),
		Proto:     target.protocol,
		// `rdr pass`, so the redirected packet is not left to the filter rules.
		NatPass: 1,
		// KeepState is left zero, as in the hand written ruleset and as the bridge's
		// own translation rules do. Note this does not make the rule stateless: xnu
		// creates state for a translation rule regardless, so a flow established
		// before teardown can keep being redirected until its state expires.
	}
	copy(rule.IfName[:], "lo0")
	rule.Dst.Addr = pf.HostAddress(listenAddr)
	rule.Dst.Port = [2]uint16{hostToNetworkPort(dnsPort), hostToNetworkPort(dnsPort)}
	rule.Dst.PortOp = pf.OpEQ
	// The loop break: sing-box's own upstream query, sourced from this address,
	// must not be redirected back into sing-box. pf takes one source per rule, so
	// the other family simply carries no exclusion, as in a hand written ruleset.
	if h.excludeSource.IsValid() && h.excludeSource.Is4() == is4 {
		rule.Src.Addr = pf.HostAddress(h.excludeSource)
		rule.Src.Neg = 1
	}
	// Unlike Dst.Port, the kernel converts the proxy port itself.
	rule.RPool.ProxyPort = [2]uint16{target.address.Port(), target.address.Port()}
	rule.RPool.AF = pf.Family(is4)
	return pf.AnchorRule{
		RulesetIndex: pf.RulesetRDR,
		Rule:         rule,
		Pool:         pf.PoolAddr{Addr: pf.HostAddress(listenAddr)},
	}
}

// pf stores rule ports in network byte order inside a native uint16.
func hostToNetworkPort(port uint16) uint16 {
	var buffer [2]byte
	binary.BigEndian.PutUint16(buffer[:], port)
	return binary.NativeEndian.Uint16(buffer[:])
}
