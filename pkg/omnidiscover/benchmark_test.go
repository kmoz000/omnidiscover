package omnidiscover

import (
	"net/netip"
	"testing"
	"time"
)

func BenchmarkDecodeLLDP(b *testing.B) {
	pdu := sampleLLDP()
	var dst LLDPMessage
	b.ReportAllocs()
	for b.Loop() {
		DecodeLLDPDU(pdu, &dst)
	}
}

func BenchmarkDecodeCDP(b *testing.B) {
	payload := sampleCDP()
	var dst CDPMessage
	b.ReportAllocs()
	for b.Loop() {
		DecodeCDP(payload, &dst)
	}
}

func BenchmarkDecodeMNDP(b *testing.B) {
	payload := benchmarkMNDP()
	var dst MNDPMessage
	b.ReportAllocs()
	for b.Loop() {
		DecodeMNDP(payload, &dst)
	}
}

func BenchmarkDecodeMDNS(b *testing.B) {
	payload := sampleMDNS()
	var dst MDNSMessage
	b.ReportAllocs()
	for b.Loop() {
		DecodeMDNS(payload, &dst)
	}
}

func BenchmarkRouteFrame(b *testing.B) {
	e, err := New(Config{Protocols: ProtocolsLLDP, MaxDevices: 4, MaxLinks: 4, MaxDNSRecords: 4, ProtocolQueue: 256, MaxFrameSize: 2048})
	if err != nil {
		b.Fatal(err)
	}
	frame := ethernetFrame(MAC{1, 0, 0xc2, 0, 0, 0x0e}, MAC{0, 1, 2, 3, 4, 5}, EtherTypeLLDP, sampleLLDP(), 0)
	b.ReportAllocs()
	for b.Loop() {
		e.routeCapture(captureView{data: frame, interfaceIndex: 1, timestamp: time.Unix(1, 0), frame: true})
		select {
		case slot := <-e.queues[ProtocolLLDP]:
			e.releasePacket(slot)
		default:
			b.Fatal("route did not enqueue")
		}
	}
}

func BenchmarkClassifierRegexPruned(b *testing.B) {
	rules := make([]Rule, 0, 128)
	for i := 0; i < cap(rules); i++ {
		rules = append(rules, Rule{Name: "nonmatch", Class: "other", All: []Predicate{
			{Field: MatchFieldProtocol, Op: MatchProtocol, Protocol: ProtocolsLLDP},
			{Field: MatchFieldSystemName, Op: MatchRegex, Pattern: `^switch-[0-9]+$`},
		}})
	}
	c, err := CompileClassifier(rules)
	if err != nil {
		b.Fatal(err)
	}
	d := DiscoveredDevice{Protocols: ProtocolsMDNS, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	b.ReportAllocs()
	for b.Loop() {
		c.Classify(&d)
	}
}

func BenchmarkIdenticalRefreshFusion(b *testing.B) {
	cfg := Config{Protocols: ProtocolsMNDP, MaxDevices: 4, MaxLinks: 4, MaxDNSRecords: 4, MaxAlternatives: 4, MNDPIdleTTL: time.Minute, TimingWheelSlots: 64}
	s := newFusionState(cfg.withDefaults(), &Classifier{})
	var msg MNDPMessage
	DecodeMNDP(benchmarkMNDP(), &msg)
	meta := observationMeta{protocol: ProtocolMNDP, interfaceIndex: 1, interfaceName: "eth0", timestamp: time.Unix(1, 0), sourceIP: netip.MustParseAddr("192.0.2.2")}
	s.observeMNDP(meta, &msg, nil)
	b.ReportAllocs()
	for b.Loop() {
		meta.timestamp = meta.timestamp.Add(time.Second)
		if events := s.observeMNDP(meta, &msg, nil); len(events) != 0 {
			b.Fatal("identical refresh emitted an event")
		}
	}
}

func benchmarkMNDP() []byte {
	p := []byte{0, 0, 0, 1}
	p = append(p, mndpTLV(mndpTagMAC, []byte{0, 1, 2, 3, 4, 5})...)
	p = append(p, mndpTLV(mndpTagIdentity, []byte("router"))...)
	p = append(p, mndpTLV(mndpTagIPv4, []byte{192, 0, 2, 2})...)
	return p
}
