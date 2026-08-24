package pf

import (
	"net"
	"net/netip"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// Layouts and values mirror bsd/net/pfvar.h from xnu, which the SDKs do not
// ship; unchanged from xnu-4570.1.46 (macOS 10.13) through xnu-12377.1.9.

const (
	RulesetScrub  = 0
	RulesetFilter = 1
	RulesetNat    = 2
	// The kernel derives the ruleset from the rule's action, and rdr has its own,
	// distinct from nat: pf_get_ruleset_number maps PF_RDR to PF_RULESET_RDR.
	RulesetRDR = 4

	ActionPass  = 0
	ActionDrop  = 1
	ActionScrub = 2
	ActionNat   = 4
	ActionRDR   = 8

	DirectionIn  = 1
	DirectionOut = 2

	AddrTypeAddressMask      = 0
	AddrTypeDynamicInterface = 2

	// xnu orders the route enum PF_NOPFROUTE, PF_FASTROUTE, PF_ROUTETO,
	// PF_DUPTO, PF_REPLYTO; reply-to is 4, unlike OpenBSD where it is 3.
	RouteActionRouteTo = 2
	RouteActionReplyTo = 4

	StateNormal = 1

	// Port comparison operators, verified against pfctl's rendering of a loaded
	// rule: 0 none, 1 range, 2 equal, 3 not equal, 4 less, 5 less or equal.
	OpEQ = 2

	NatProxyPortLow  = 50001
	NatProxyPortHigh = 65535
)

type Addr [16]byte

type AddrWrap struct {
	Addr   Addr
	Mask   Addr
	_      uint64
	Type   uint8
	IFlags uint8
	_      [6]byte
}

type RuleAddr struct {
	Addr AddrWrap
	// The union pf_rule_xport, in its pf_port_range form. Ports are in network
	// byte order here, unlike Pool.ProxyPort which the kernel converts itself.
	Port   [2]uint16
	PortOp uint8
	_      [3]byte
	Neg    uint8
	_      [7]byte
}

type Pool struct {
	_          [2]uint64
	_          uint64
	_          [16]byte
	_          Addr
	TableIndex int32
	ProxyPort  [2]uint16
	PortOp     uint8
	Opts       uint8
	AF         uint8
	_          [5]byte
}

type RuleUserGroup struct {
	Range [2]uint32
	Op    uint8
	_     [3]byte
}

type Rule struct {
	Src            RuleAddr
	Dst            RuleAddr
	_              [8]uint64
	Label          [64]byte
	IfName         [16]byte
	QName          [64]byte
	PQName         [64]byte
	TagName        [64]byte
	MatchTagName   [64]byte
	OverloadTable  [32]byte
	_              [2]uint64
	RPool          Pool
	Evaluations    uint64
	Packets        [2]uint64
	Bytes          [2]uint64
	Ticket         uint64
	Owner          [64]byte
	Priority       uint32
	_              uint32
	_              [3]uint64
	OSFingerprint  uint32
	RouteTableID   uint32
	Timeout        [26]uint32
	States         uint32
	MaxStates      uint32
	SrcNodes       uint32
	MaxSrcNodes    uint32
	MaxSrcStates   uint32
	MaxSrcConn     uint32
	MaxSrcConnRate [2]uint32
	QID            uint32
	PQID           uint32
	RouteListID    uint32
	Nr             uint32
	Prob           uint32
	CreatorUID     uint32
	CreatorPID     uint32
	ReturnICMP     uint16
	ReturnICMP6    uint16
	MaxMSS         uint16
	Tag            uint16
	MatchTag       uint16
	_              uint16
	UID            RuleUserGroup
	GID            RuleUserGroup
	RuleFlag       uint32
	Action         uint8
	Direction      uint8
	Log            uint8
	LogIf          uint8
	Quick          uint8
	IfNot          uint8
	MatchTagNot    uint8
	NatPass        uint8
	KeepState      uint8
	AF             uint8
	Proto          uint8
	Type           uint8
	Code           uint8
	Flags          uint8
	FlagSet        uint8
	MinTTL         uint8
	AllowOpts      uint8
	RouteAction    uint8
	ReturnTTL      uint8
	TOS            uint8
	AnchorRelative uint8
	AnchorWildcard uint8
	Flush          uint8
	ProtoVariant   uint8
	ExtFilter      uint8
	ExtMap         uint8
	_              uint16
	DummynetPipe   uint32
	DummynetType   uint32
}

type PoolAddr struct {
	Addr   AddrWrap
	_      [2]uint64
	IfName [16]byte
	_      uint64
}

type pfiocRule struct {
	Action     uint32
	Ticket     uint32
	PoolTicket uint32
	Nr         uint32
	Anchor     [1024]byte
	AnchorCall [1024]byte
	Rule       Rule
}

type pfiocPoolAddr struct {
	Action  uint32
	Ticket  uint32
	Nr      uint32
	RNum    uint32
	RAction uint8
	RLast   uint8
	AF      uint8
	Anchor  [1024]byte
	_       [5]byte
	Addr    PoolAddr
}

type pfiocTransElement struct {
	RulesetIndex int32
	Anchor       [1024]byte
	Ticket       uint32
}

type pfiocTrans struct {
	Size        int32
	ElementSize int32
	Array       *pfiocTransElement
}

type pfiocRemoveToken struct {
	Token    uint64
	RefCount uint64
}

const (
	iocParamMask = 0x1fff
	iocOut       = 0x40000000
	iocIn        = 0x80000000
	iocInOut     = iocIn | iocOut
)

const (
	diocAddRule    = iocInOut | (uint(unsafe.Sizeof(pfiocRule{}))&iocParamMask)<<16 | 'D'<<8 | 4
	diocStartRef   = iocOut | 8<<16 | 'D'<<8 | 8
	diocStopRef    = iocInOut | (uint(unsafe.Sizeof(pfiocRemoveToken{}))&iocParamMask)<<16 | 'D'<<8 | 9
	diocBeginAddrs = iocInOut | (uint(unsafe.Sizeof(pfiocPoolAddr{}))&iocParamMask)<<16 | 'D'<<8 | 51
	diocAddAddr    = iocInOut | (uint(unsafe.Sizeof(pfiocPoolAddr{}))&iocParamMask)<<16 | 'D'<<8 | 52
	diocXBegin     = iocInOut | (uint(unsafe.Sizeof(pfiocTrans{}))&iocParamMask)<<16 | 'D'<<8 | 81
	diocXCommit    = iocInOut | (uint(unsafe.Sizeof(pfiocTrans{}))&iocParamMask)<<16 | 'D'<<8 | 82
	diocXRollback  = iocInOut | (uint(unsafe.Sizeof(pfiocTrans{}))&iocParamMask)<<16 | 'D'<<8 | 83
)

type AnchorRule struct {
	RulesetIndex int32
	Rule         Rule
	Pool         PoolAddr
}

type Device struct {
	fd int
}

func OpenDevice() (*Device, error) {
	fd, err := unix.Open("/dev/pf", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, E.Cause(err, "open /dev/pf")
	}
	return &Device{fd: fd}, nil
}

func (d *Device) Close() error {
	return unix.Close(d.fd)
}

func (d *Device) ioctl(request uint, pointer unsafe.Pointer) error {
	return unixIoctlPtr(d.fd, request, pointer)
}

func (d *Device) StartReference() (uint64, error) {
	var token uint64
	err := d.ioctl(uint(diocStartRef), unsafe.Pointer(&token))
	if err != nil {
		return 0, E.Cause(err, "DIOCSTARTREF")
	}
	return token, nil
}

func (d *Device) StopReference(token uint64) error {
	remove := pfiocRemoveToken{Token: token}
	err := d.ioctl(uint(diocStopRef), unsafe.Pointer(&remove))
	if err != nil {
		return E.Cause(err, "DIOCSTOPREF")
	}
	return nil
}

// LoadAnchor atomically replaces the given rulesets of the anchor;
// empty rules flush the anchor.
func (d *Device) LoadAnchor(anchor string, rulesets []int32, rules []AnchorRule) error {
	// Only the caller's own rulesets are opened: committing a ruleset also clears
	// it, so touching one the caller does not use would wipe whatever else lives
	// there. That matters for the main ruleset, which is the anchor on platforms
	// without a stock /etc/pf.conf to nest under.
	elements := make([]pfiocTransElement, 0, len(rulesets))
	for _, ruleset := range rulesets {
		elements = append(elements, pfiocTransElement{RulesetIndex: ruleset})
	}
	for i := range elements {
		copy(elements[i].Anchor[:], anchor)
	}
	if len(elements) == 0 {
		return nil
	}
	trans := pfiocTrans{
		Size:        int32(len(elements)),
		ElementSize: int32(unsafe.Sizeof(pfiocTransElement{})),
		Array:       &elements[0],
	}
	err := d.ioctl(uint(diocXBegin), unsafe.Pointer(&trans))
	if err != nil {
		return E.Cause(err, "DIOCXBEGIN")
	}
	for _, rule := range rules {
		err = d.addRule(anchor, elements, rule)
		if err != nil {
			_ = d.ioctl(uint(diocXRollback), unsafe.Pointer(&trans))
			return err
		}
	}
	err = d.ioctl(uint(diocXCommit), unsafe.Pointer(&trans))
	if err != nil {
		return E.Cause(err, "DIOCXCOMMIT")
	}
	return nil
}

func (d *Device) addRule(anchor string, elements []pfiocTransElement, rule AnchorRule) error {
	var pool pfiocPoolAddr
	err := d.ioctl(uint(diocBeginAddrs), unsafe.Pointer(&pool))
	if err != nil {
		return E.Cause(err, "DIOCBEGINADDRS")
	}
	if rule.Pool != (PoolAddr{}) {
		pool.Addr = rule.Pool
		pool.AF = rule.Rule.AF
		err = d.ioctl(uint(diocAddAddr), unsafe.Pointer(&pool))
		if err != nil {
			return E.Cause(err, "DIOCADDADDR")
		}
	}
	var (
		ticket      uint32
		ticketFound bool
	)
	for _, element := range elements {
		if element.RulesetIndex == rule.RulesetIndex {
			ticket = element.Ticket
			ticketFound = true
		}
	}
	if !ticketFound {
		// The kernel would compare a zero ticket against the ruleset it derives from
		// the rule's action and reject the transaction with an unexplained EBUSY.
		return E.New("no open transaction for ruleset ", rule.RulesetIndex)
	}
	request := pfiocRule{
		Ticket:     ticket,
		PoolTicket: pool.Ticket,
		Rule:       rule.Rule,
	}
	copy(request.Anchor[:], anchor)
	err = d.ioctl(uint(diocAddRule), unsafe.Pointer(&request))
	if err != nil {
		return E.Cause(err, "DIOCADDRULE")
	}
	return nil
}

func AddrOf(address netip.Addr) (result Addr) {
	if address.Is4() {
		addr4 := address.As4()
		copy(result[:], addr4[:])
	} else {
		addr16 := address.As16()
		copy(result[:], addr16[:])
	}
	return
}

func MaskOf(bits int, is4 bool) (result Addr) {
	totalBits := 128
	if is4 {
		totalBits = 32
	}
	copy(result[:], net.CIDRMask(bits, totalBits))
	return
}

func HostAddress(address netip.Addr) AddrWrap {
	return PrefixAddress(netip.PrefixFrom(address, address.BitLen()))
}

func PrefixAddress(prefix netip.Prefix) AddrWrap {
	return AddrWrap{
		Type: AddrTypeAddressMask,
		Addr: AddrOf(prefix.Addr()),
		Mask: MaskOf(prefix.Bits(), prefix.Addr().Is4()),
	}
}

func DynamicInterfaceAddress(interfaceName string, is4 bool) AddrWrap {
	wrap := AddrWrap{
		Type: AddrTypeDynamicInterface,
	}
	if is4 {
		wrap.Mask = MaskOf(32, true)
	} else {
		wrap.Mask = MaskOf(128, false)
	}
	copy(wrap.Addr[:], interfaceName)
	return wrap
}

func Family(is4 bool) uint8 {
	if is4 {
		return unix.AF_INET
	}
	return unix.AF_INET6
}
