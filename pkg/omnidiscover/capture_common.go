package omnidiscover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

type filterInsn struct {
	code   uint16
	jt, jf uint8
	k      uint32
}

func discoveryFilter(protocols ProtocolSet, snaplen int) []filterInsn {
	const (
		filterLLDP = iota
		filterCDP
		filterIPv4
		filterIPv6
	)
	b := filterBuilder{}
	udp := protocols&(ProtocolsMNDP|ProtocolsMDNS) != 0
	for depth := 0; depth <= maxVLANTags; depth++ {
		if protocols.Has(ProtocolLLDP) {
			b.emitProtocolPath(depth, filterLLDP, protocols, snaplen)
		}
		if protocols.Has(ProtocolCDP) {
			b.emitProtocolPath(depth, filterCDP, protocols, snaplen)
		}
		if udp {
			b.emitProtocolPath(depth, filterIPv4, protocols, snaplen)
			b.emitProtocolPath(depth, filterIPv6, protocols, snaplen)
		}
	}
	b.emit(filterInsn{code: bpfRETK, k: 0})
	return b.resolve()
}

const (
	bpfLDWABS  = 0x20
	bpfLDHABS  = 0x28
	bpfLDBABS  = 0x30
	bpfLDHIND  = 0x48
	bpfLDXBMSH = 0xb1
	bpfJEQK    = 0x15
	bpfJGEK    = 0x35
	bpfJSETK   = 0x45
	bpfRETK    = 0x06
)

type filterFixup struct {
	index       int
	true, false int
}

type filterBuilder struct {
	ins    []filterInsn
	labels []int
	fixups []filterFixup
}

func (b *filterBuilder) label() int {
	b.labels = append(b.labels, -1)
	return len(b.labels) - 1
}

func (b *filterBuilder) mark(label int)      { b.labels[label] = len(b.ins) }
func (b *filterBuilder) emit(ins filterInsn) { b.ins = append(b.ins, ins) }

func (b *filterBuilder) jump(code uint16, k uint32, trueLabel, falseLabel int) {
	b.fixups = append(b.fixups, filterFixup{index: len(b.ins), true: trueLabel, false: falseLabel})
	b.emit(filterInsn{code: code, k: k})
}

func (b *filterBuilder) tagGuard(depth, reject int) {
	for tag := 0; tag < depth; tag++ {
		checkQinQ, matched := b.label(), b.label()
		b.emit(filterInsn{code: bpfLDHABS, k: uint32(12 + tag*4)})
		b.jump(bpfJEQK, EtherTypeVLAN, matched, checkQinQ)
		b.mark(checkQinQ)
		b.jump(bpfJEQK, EtherTypeQinQ, matched, reject)
		b.mark(matched)
	}
}

func (b *filterBuilder) emitProtocolPath(depth, kind int, protocols ProtocolSet, snaplen int) {
	reject, accept := b.label(), b.label()
	b.tagGuard(depth, reject)
	typeOffset := 12 + depth*4
	payloadOffset := 14 + depth*4
	switch kind {
	case 0: // LLDP
		b.emit(filterInsn{code: bpfLDHABS, k: uint32(typeOffset)})
		b.jump(bpfJEQK, EtherTypeLLDP, accept, reject)
	case 1: // CDP LLC/SNAP: aa aa 03 00 00 0c 20 00.
		lengthOK := b.label()
		b.emit(filterInsn{code: bpfLDHABS, k: uint32(typeOffset)})
		b.jump(bpfJGEK, 0x0600, reject, lengthOK)
		b.mark(lengthOK)
		secondWord := b.label()
		b.emit(filterInsn{code: bpfLDWABS, k: uint32(payloadOffset)})
		b.jump(bpfJEQK, 0xaaaa0300, secondWord, reject)
		b.mark(secondWord)
		b.emit(filterInsn{code: bpfLDWABS, k: uint32(payloadOffset + 4)})
		b.jump(bpfJEQK, 0x000c2000, accept, reject)
	case 2: // Unfragmented IPv4 UDP, with the variable IHL in X.
		ipProtocol, fragments, ports := b.label(), b.label(), b.label()
		b.emit(filterInsn{code: bpfLDHABS, k: uint32(typeOffset)})
		b.jump(bpfJEQK, EtherTypeIPv4, ipProtocol, reject)
		b.mark(ipProtocol)
		b.emit(filterInsn{code: bpfLDBABS, k: uint32(payloadOffset + 9)})
		b.jump(bpfJEQK, 17, fragments, reject)
		b.mark(fragments)
		b.emit(filterInsn{code: bpfLDHABS, k: uint32(payloadOffset + 6)})
		b.jump(bpfJSETK, 0x3fff, reject, ports)
		b.mark(ports)
		b.emit(filterInsn{code: bpfLDXBMSH, k: uint32(payloadOffset)})
		b.emitUDPPortChecks(uint32(payloadOffset), protocols, accept, reject)
	case 3: // Direct IPv6 UDP is port-filtered; bounded extensions go to userspace.
		checkNext, directUDP, extension := b.label(), b.label(), b.label()
		b.emit(filterInsn{code: bpfLDHABS, k: uint32(typeOffset)})
		b.jump(bpfJEQK, EtherTypeIPv6, checkNext, reject)
		b.mark(checkNext)
		b.emit(filterInsn{code: bpfLDBABS, k: uint32(payloadOffset + 6)})
		b.jump(bpfJEQK, 17, directUDP, extension)
		b.mark(extension)
		b.emitIPv6ExtensionChecks(accept, reject)
		b.mark(directUDP)
		b.emitUDPPortChecks(uint32(payloadOffset+40), protocols, accept, reject)
	}
	b.mark(accept)
	b.emit(filterInsn{code: bpfRETK, k: uint32(snaplen)})
	b.mark(reject)
}

func (b *filterBuilder) emitUDPPortChecks(offset uint32, protocols ProtocolSet, accept, reject int) {
	checkDestination := b.label()
	b.emit(filterInsn{code: bpfLDHIND, k: offset})
	b.emitSelectedPortChecks(protocols, accept, checkDestination)
	b.mark(checkDestination)
	b.emit(filterInsn{code: bpfLDHIND, k: offset + 2})
	b.emitSelectedPortChecks(protocols, accept, reject)
}

func (b *filterBuilder) emitSelectedPortChecks(protocols ProtocolSet, accept, reject int) {
	if protocols.Has(ProtocolMDNS) && protocols.Has(ProtocolMNDP) {
		checkMNDP := b.label()
		b.jump(bpfJEQK, MDNSPort, accept, checkMNDP)
		b.mark(checkMNDP)
		b.jump(bpfJEQK, MNDPPort, accept, reject)
	} else if protocols.Has(ProtocolMDNS) {
		b.jump(bpfJEQK, MDNSPort, accept, reject)
	} else {
		b.jump(bpfJEQK, MNDPPort, accept, reject)
	}
}

func (b *filterBuilder) emitIPv6ExtensionChecks(accept, reject int) {
	for _, header := range [...]uint32{0, 43, 44, 51, 60} {
		next := b.label()
		b.jump(bpfJEQK, header, accept, next)
		b.mark(next)
	}
	// An unconditional false comparison keeps the symbolic jump resolver small.
	b.jump(bpfJEQK, ^uint32(0), accept, reject)
}

func (b *filterBuilder) resolve() []filterInsn {
	for _, fix := range b.fixups {
		base := fix.index + 1
		trueDistance := b.labels[fix.true] - base
		falseDistance := b.labels[fix.false] - base
		if trueDistance < 0 || trueDistance > 255 || falseDistance < 0 || falseDistance > 255 {
			panic("omnidiscover: internal BPF jump exceeds classic BPF range")
		}
		b.ins[fix.index].jt = uint8(trueDistance)
		b.ins[fix.index].jf = uint8(falseDistance)
	}
	return b.ins
}

func captureInterfaces(cfg Config) ([]net.Interface, error) {
	if len(cfg.Interfaces) != 0 {
		out := make([]net.Interface, 0, len(cfg.Interfaces))
		for _, name := range cfg.Interfaces {
			ifi, err := net.InterfaceByName(name)
			if err != nil {
				return nil, fmt.Errorf("omnidiscover: interface %q: %w", name, err)
			}
			out = append(out, *ifi)
		}
		return out, nil
	}
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		if !cfg.IncludeLoopback && ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, ifi)
	}
	if len(out) == 0 {
		return nil, errors.New("omnidiscover: no eligible multicast interfaces")
	}
	return out, nil
}

type udpBackend struct {
	conn        *net.UDPConn
	protocol    Protocol
	ifaceName   string
	ifaceIndex  int
	maxDatagram int
	prefixes    []interfacePrefix
	once        sync.Once
}

type interfacePrefix struct {
	name   string
	index  int
	prefix netip.Prefix
}

func (b *udpBackend) run(ctx context.Context, emit func(captureView)) error {
	buf := make([]byte, b.maxDatagram)
	for {
		_ = b.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := b.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		interfaceName, interfaceIndex := b.ifaceName, b.ifaceIndex
		sourceIP := addr.Addr().Unmap()
		if interfaceIndex == 0 {
			interfaceName, interfaceIndex = resolveInterface(sourceIP, b.prefixes)
		}
		emit(captureView{data: buf[:n], protocol: b.protocol, interfaceName: interfaceName, interfaceIndex: interfaceIndex, timestamp: time.Now().UTC(), sourceIP: sourceIP})
	}
}

func (b *udpBackend) close() error {
	var err error
	b.once.Do(func() { err = b.conn.Close() })
	return err
}

func openUDPBackends(cfg Config, ifaces []net.Interface) ([]captureBackend, error) {
	var out []captureBackend
	prefixes := captureInterfacePrefixes(ifaces)
	openedMDNS, openedMNDP := false, false
	if cfg.Protocols.Has(ProtocolMDNS) {
		for i := range ifaces {
			ifi := &ifaces[i]
			if c, err := net.ListenMulticastUDP("udp4", ifi, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: MDNSPort}); err == nil {
				_ = c.SetReadBuffer(cfg.MaxFrameSize * 64)
				out = append(out, &udpBackend{conn: c, protocol: ProtocolMDNS, ifaceName: ifi.Name, ifaceIndex: ifi.Index, maxDatagram: cfg.MaxFrameSize})
				openedMDNS = true
			}
			if c, err := net.ListenMulticastUDP("udp6", ifi, &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: MDNSPort, Zone: ifi.Name}); err == nil {
				_ = c.SetReadBuffer(cfg.MaxFrameSize * 64)
				out = append(out, &udpBackend{conn: c, protocol: ProtocolMDNS, ifaceName: ifi.Name, ifaceIndex: ifi.Index, maxDatagram: cfg.MaxFrameSize})
				openedMDNS = true
			}
		}
	}
	if cfg.Protocols.Has(ProtocolMNDP) {
		if c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: MNDPPort}); err == nil {
			_ = c.SetReadBuffer(cfg.MaxFrameSize * 64)
			out = append(out, &udpBackend{conn: c, protocol: ProtocolMNDP, maxDatagram: cfg.MaxFrameSize, prefixes: prefixes})
			openedMNDP = true
		}
		for i := range ifaces {
			ifi := &ifaces[i]
			if c, err := net.ListenMulticastUDP("udp6", ifi, &net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: MNDPPort, Zone: ifi.Name}); err == nil {
				_ = c.SetReadBuffer(cfg.MaxFrameSize * 64)
				out = append(out, &udpBackend{conn: c, protocol: ProtocolMNDP, ifaceName: ifi.Name, ifaceIndex: ifi.Index, maxDatagram: cfg.MaxFrameSize})
				openedMNDP = true
			}
		}
	}
	if (cfg.Protocols.Has(ProtocolMDNS) && !openedMDNS) || (cfg.Protocols.Has(ProtocolMNDP) && !openedMNDP) {
		for _, backend := range out {
			_ = backend.close()
		}
		return nil, errors.New("omnidiscover: unable to open every requested passive UDP protocol")
	}
	return out, nil
}

func captureInterfacePrefixes(ifaces []net.Interface) []interfacePrefix {
	out := make([]interfacePrefix, 0, len(ifaces)*2)
	for i := range ifaces {
		addresses, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil || !prefix.Addr().IsValid() {
				continue
			}
			out = append(out, interfacePrefix{name: ifaces[i].Name, index: ifaces[i].Index, prefix: prefix.Masked()})
		}
	}
	return out
}

func resolveInterface(source netip.Addr, prefixes []interfacePrefix) (string, int) {
	source = source.Unmap()
	for i := range prefixes {
		if prefixes[i].prefix.Contains(source) {
			return prefixes[i].name, prefixes[i].index
		}
	}
	return "", 0
}

func addrFromNetIP(ip net.IP) netip.Addr {
	if a, ok := netip.AddrFromSlice(ip); ok {
		return a.Unmap()
	}
	return netip.Addr{}
}
