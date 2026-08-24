package listener

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/settings"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/vishvananda/netns"
)

type Listener struct {
	ctx                      context.Context
	logger                   logger.ContextLogger
	network                  []string
	listenOptions            option.ListenOptions
	connHandler              adapter.ConnectionHandler
	packetHandler            adapter.PacketHandler
	oobPacketHandler         adapter.OOBPacketHandler
	threadUnsafePacketWriter bool
	disablePacketOutput      bool
	setSystemProxy           bool
	dnsHijackLoopback        bool
	dnsHijackExcludeSource   netip.Addr
	systemProxySOCKS         bool
	tproxy                   bool

	tcpListener          net.Listener
	systemProxy          settings.SystemProxy
	dnsHijack            settings.DNSHijack
	udpConn              *net.UDPConn
	udpAddr              M.Socksaddr
	packetOutbound       chan *N.PacketBuffer
	packetOutboundClosed chan struct{}
	shutdown             atomic.Bool
}

type Options struct {
	Context                  context.Context
	Logger                   logger.ContextLogger
	Network                  []string
	Listen                   option.ListenOptions
	ConnectionHandler        adapter.ConnectionHandler
	PacketHandler            adapter.PacketHandler
	OOBPacketHandler         adapter.OOBPacketHandler
	ThreadUnsafePacketWriter bool
	DisablePacketOutput      bool
	SetSystemProxy           bool
	DNSHijackLoopback        bool
	DNSHijackExcludeSource   netip.Addr
	SystemProxySOCKS         bool
	TProxy                   bool
}

func New(
	options Options,
) *Listener {
	return &Listener{
		ctx:                      options.Context,
		logger:                   options.Logger,
		network:                  options.Network,
		listenOptions:            options.Listen,
		connHandler:              options.ConnectionHandler,
		packetHandler:            options.PacketHandler,
		oobPacketHandler:         options.OOBPacketHandler,
		threadUnsafePacketWriter: options.ThreadUnsafePacketWriter,
		disablePacketOutput:      options.DisablePacketOutput,
		setSystemProxy:           options.SetSystemProxy,
		dnsHijackLoopback:        options.DNSHijackLoopback,
		dnsHijackExcludeSource:   options.DNSHijackExcludeSource,
		systemProxySOCKS:         options.SystemProxySOCKS,
		tproxy:                   options.TProxy,
	}
}

func (l *Listener) Start() error {
	if l.dnsHijackLoopback && !C.IsDarwin {
		return E.New("`dns_hijack_loopback` is only supported on macOS")
	}
	if common.Contains(l.network, N.NetworkTCP) {
		_, err := l.ListenTCP()
		if err != nil {
			return err
		}
		go l.loopTCPIn()
	}
	if common.Contains(l.network, N.NetworkUDP) {
		_, err := l.ListenUDP()
		if err != nil {
			return err
		}
		l.packetOutboundClosed = make(chan struct{})
		l.packetOutbound = make(chan *N.PacketBuffer, 64)
		go l.loopUDPIn()
		if !l.disablePacketOutput {
			go l.loopUDPOut()
		}
	}
	if l.setSystemProxy {
		listenPort := M.SocksaddrFromNet(l.tcpListener.Addr()).Port
		var listenAddrString string
		listenAddr := l.listenOptions.Listen.Build(netip.IPv4Unspecified())
		if listenAddr.IsUnspecified() {
			listenAddrString = "127.0.0.1"
		} else {
			listenAddrString = listenAddr.String()
		}
		systemProxy, err := settings.NewSystemProxy(l.ctx, M.ParseSocksaddrHostPort(listenAddrString, listenPort), l.systemProxySOCKS, nil)
		if err != nil {
			return E.Cause(err, "initialize system proxy")
		}
		err = systemProxy.Enable()
		if err != nil {
			return E.Errors(E.Cause(err, "set system proxy"), systemProxy.Close())
		}
		l.systemProxy = systemProxy
	}
	if l.dnsHijackLoopback {
		// Built from the sockets themselves rather than from the options: TCP and UDP
		// get different ports when listen_port is left to the system, and only the
		// networks actually opened may be redirected. Installed only once the
		// listener is accepting, since redirecting DNS into a port nothing answers
		// on breaks all name resolution on the host.
		dnsHijack, err := settings.NewDNSHijack(
			l.boundTCPAddress(),
			l.boundUDPAddress(),
			l.dnsHijackExcludeSource,
		)
		if err != nil {
			return E.Cause(err, "initialize DNS hijack")
		}
		err = dnsHijack.Enable()
		if err != nil {
			return E.Errors(E.Cause(err, "enable DNS hijack"), dnsHijack.Close())
		}
		l.dnsHijack = dnsHijack
	}
	return nil
}

// boundTCPAddress and boundUDPAddress report what the sockets actually bound,
// which differs from the configured address when the port was left to the system.
// A zero value means that network is not listening.
func (l *Listener) boundTCPAddress() netip.AddrPort {
	if l.tcpListener == nil {
		return netip.AddrPort{}
	}
	return M.AddrPortFromNet(l.tcpListener.Addr())
}

func (l *Listener) boundUDPAddress() netip.AddrPort {
	if l.udpConn == nil {
		return netip.AddrPort{}
	}
	return M.AddrPortFromNet(l.udpConn.LocalAddr())
}

func (l *Listener) Close() error {
	l.shutdown.Store(true)
	var err error
	if l.systemProxy != nil {
		if l.systemProxy.IsEnabled() {
			err = l.systemProxy.Disable()
		}
		err = E.Errors(err, l.systemProxy.Close())
	}
	if l.dnsHijack != nil {
		err = E.Errors(err, l.dnsHijack.Close())
	}
	return E.Errors(err, common.Close(
		l.tcpListener,
		common.PtrOrNil(l.udpConn),
	))
}

func (l *Listener) TCPListener() net.Listener {
	return l.tcpListener
}

func (l *Listener) UDPConn() *net.UDPConn {
	return l.udpConn
}

func (l *Listener) ListenOptions() option.ListenOptions {
	return l.listenOptions
}

func ListenNetworkNamespace[T any](ctx context.Context, nameOrPath string, block func() (T, error)) (T, error) {
	if nameOrPath == "" {
		return block()
	}
	manager := service.FromContext[adapter.NetworkNamespaceManager](ctx)
	if manager != nil {
		nameOrPath = manager.ResolvePath(nameOrPath)
	}
	type blockResult struct {
		value T
		err   error
	}
	resultChannel := make(chan blockResult, 1)
	go func() {
		runtime.LockOSThread()
		value, err := listenNetworkNamespaceThread(nameOrPath, block)
		resultChannel <- blockResult{value, err}
	}()
	result := <-resultChannel
	return result.value, result.err
}

func listenNetworkNamespaceThread[T any](nameOrPath string, block func() (T, error)) (T, error) {
	var (
		targetNs netns.NsHandle
		err      error
	)
	if strings.HasPrefix(nameOrPath, "/") {
		targetNs, err = netns.GetFromPath(nameOrPath)
	} else {
		targetNs, err = netns.GetFromName(nameOrPath)
	}
	if err != nil {
		return common.DefaultValue[T](), E.Cause(err, "get netns ", nameOrPath)
	}
	defer targetNs.Close()
	err = netns.Set(targetNs)
	if err != nil {
		return common.DefaultValue[T](), E.Cause(err, "set netns to ", nameOrPath)
	}
	return block()
}
