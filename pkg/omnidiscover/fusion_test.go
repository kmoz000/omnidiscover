package omnidiscover

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func testState(t *testing.T, rules []Rule) *fusionState {
	t.Helper()
	cfg := Config{MaxDevices: 16, MaxLinks: 32, MaxDNSRecords: 64, MaxAlternatives: 4, ProtocolQueue: 4, PendingEvents: 8, MaxFrameSize: 2048, MNDPIdleTTL: time.Minute, TimingWheelSlots: 16, Protocols: ProtocolsAll, Rules: rules}.withDefaults()
	c, err := CompileClassifier(rules)
	if err != nil {
		t.Fatal(err)
	}
	return newFusionState(cfg, c)
}

func usedDevices(s *fusionState) int {
	n := 0
	for i := range s.devices {
		if s.devices[i].used {
			n++
		}
	}
	return n
}
func usedLinks(s *fusionState) int {
	n := 0
	for i := range s.links {
		if s.links[i].used {
			n++
		}
	}
	return n
}

func TestFusionDeduplicatesAndEnriches(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(1000, 0).UTC()
	mac := MAC{0, 1, 2, 3, 4, 5}
	meta := observationMeta{protocol: ProtocolLLDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: now, sourceMAC: mac}
	var lldp LLDPMessage
	if st := DecodeLLDPDU(sampleLLDP(), &lldp); !st.Clean() {
		t.Fatal(st)
	}
	events := s.observeLLDP(meta, &lldp, nil)
	if len(events) != 1 || events[0].Kind != EventAdded {
		t.Fatalf("LLDP events: %+v", events)
	}
	var mndp MNDPMessage
	mndp.MAC = mac
	mndp.HasMAC = true
	mndp.Details.Identity = []byte("edge-switch")
	mndp.Details.Platform = []byte("RouterOS")
	mndp.Details.Board = []byte("RB952Ui-5ac2nD")
	mndp.Details.UptimeSeconds = 12345
	mndp.Details.HasUptime = true
	mndp.Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.9")}
	meta.protocol = ProtocolMNDP
	meta.timestamp = now.Add(time.Second)
	events = s.observeMNDP(meta, &mndp, events[:0])
	if len(events) != 1 || events[0].Kind != EventChanged {
		t.Fatalf("MNDP events: %+v", events)
	}
	// An identical refresh updates liveness without producing redundant output.
	meta.timestamp = now.Add(2 * time.Second)
	if got := s.observeMNDP(meta, &mndp, events[:0]); len(got) != 0 {
		t.Fatalf("identical refresh emitted: %+v", got)
	}
	var cdp CDPMessage
	if st := DecodeCDP(sampleCDP(), &cdp); !st.Clean() {
		t.Fatal(st)
	}
	meta.protocol = ProtocolCDP
	meta.timestamp = now.Add(3 * time.Second)
	events = s.observeCDP(meta, &cdp, events[:0])
	if len(events) != 1 {
		t.Fatal("CDP did not enrich")
	}
	var mdns MDNSMessage
	if st := DecodeMDNS(sampleMDNS(), &mdns); !st.Clean() {
		t.Fatal(st)
	}
	meta.protocol = ProtocolMDNS
	meta.timestamp = now.Add(4 * time.Second)
	meta.sourceIP = netip.MustParseAddr("192.0.2.44")
	events = s.observeMDNS(meta, &mdns, events[:0])
	if len(events) != 1 {
		t.Fatal("mDNS did not enrich")
	}
	if usedDevices(s) != 1 || usedLinks(s) != 1 {
		t.Fatalf("redundant state devices=%d links=%d", usedDevices(s), usedLinks(s))
	}
	var d *DiscoveredDevice
	for i := range s.devices {
		if s.devices[i].used {
			d = &s.devices[i].device
		}
	}
	if d.Protocols != ProtocolsAll || len(d.Services) != 1 || string(d.Platform.Current()) != "RouterOS" ||
		string(d.Model.Current()) != "RB952Ui-5ac2nD" || !d.Uptime.Valid || d.Uptime.Seconds != 12345 {
		t.Fatalf("fused device: %+v", d)
	}
}

func TestMNDPUptimeRefreshAndReboot(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(12000, 0).UTC()
	mac := MAC{0x48, 0xa9, 0x8a, 0, 0, 1}
	meta := observationMeta{protocol: ProtocolMNDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: now}
	msg := MNDPMessage{MAC: mac, HasMAC: true, Details: MNDPDetails{UptimeSeconds: 86400, HasUptime: true}}
	if events := s.observeMNDP(meta, &msg, nil); len(events) != 1 || events[0].Changed&FieldUptime == 0 || string(events[0].Device.Vendor.Current()) != "Routerboard.com" {
		t.Fatalf("initial uptime events=%+v", events)
	}
	meta.timestamp = now.Add(10 * time.Second)
	msg.Details.UptimeSeconds = 86410
	if events := s.observeMNDP(meta, &msg, nil); len(events) != 0 {
		t.Fatalf("normal uptime refresh emitted=%+v", events)
	}
	meta.timestamp = now.Add(20 * time.Second)
	msg.Details.UptimeSeconds = 3
	if events := s.observeMNDP(meta, &msg, nil); len(events) != 1 || events[0].Changed&FieldUptime == 0 {
		t.Fatalf("reboot uptime events=%+v", events)
	}
}

func TestFusionOneDeviceManyLinks(t *testing.T) {
	s := testState(t, nil)
	var msg LLDPMessage
	DecodeLLDPDU(sampleLLDP(), &msg)
	mac := MAC{0, 1, 2, 3, 4, 5}
	now := time.Now().UTC()
	s.observeLLDP(observationMeta{protocol: ProtocolLLDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: now, sourceMAC: mac}, &msg, nil)
	s.observeLLDP(observationMeta{protocol: ProtocolLLDP, interfaceName: "eth1", interfaceIndex: 2, timestamp: now, sourceMAC: mac}, &msg, nil)
	if usedDevices(s) != 1 || usedLinks(s) != 2 {
		t.Fatalf("devices=%d links=%d", usedDevices(s), usedLinks(s))
	}
}

func TestFusionExpiresLink(t *testing.T) {
	s := testState(t, nil)
	var msg LLDPMessage
	DecodeLLDPDU(sampleLLDP(), &msg)
	msg.TTLSeconds = 1
	now := time.Unix(100, 0).UTC()
	s.observeLLDP(observationMeta{protocol: ProtocolLLDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: now, sourceMAC: MAC{0, 1, 2, 3, 4, 5}}, &msg, nil)
	s.resetTombstones()
	events := s.tick(now.Add(2*time.Second), nil)
	if len(events) != 1 || events[0].Kind != EventExpired || usedLinks(s) != 0 || usedDevices(s) != 0 {
		t.Fatalf("expiry events=%+v devices=%d links=%d", events, usedDevices(s), usedLinks(s))
	}
}

func TestCompiledClassifier(t *testing.T) {
	c, err := CompileClassifier([]Rule{{Name: "mikrotik-router", Class: "infrastructure", Priority: 10, All: []Predicate{{Field: MatchFieldProtocol, Op: MatchProtocol, Protocol: ProtocolsMNDP}, {Field: MatchFieldPlatform, Op: MatchRegex, Pattern: "(?i)^routeros$"}}}})
	if err != nil {
		t.Fatal(err)
	}
	d := DiscoveredDevice{Protocols: ProtocolsMNDP}
	mergeText(&d.Platform, []byte("RouterOS"), ProtocolsMNDP, 3, time.Now(), 4)
	class, rule, ok := c.Classify(&d)
	if !ok || string(class) != "infrastructure" || string(rule) != "mikrotik-router" {
		t.Fatalf("class=%q rule=%q ok=%v", class, rule, ok)
	}
}

func TestClassifierRejectsBadRegex(t *testing.T) {
	_, err := CompileClassifier([]Rule{{Name: "bad", Class: "bad", All: []Predicate{{Field: MatchFieldModel, Op: MatchRegex, Pattern: "("}}}})
	if err == nil {
		t.Fatal("invalid regex accepted")
	}
}

func TestIdenticalFusionRefreshAllocations(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(1000, 0).UTC()
	mac := MAC{0, 1, 2, 3, 4, 5}
	meta := observationMeta{protocol: ProtocolMNDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: now, sourceMAC: mac}
	msg := MNDPMessage{MAC: mac, HasMAC: true, Details: MNDPDetails{Identity: []byte("router"), Platform: []byte("RouterOS")}}
	events := make([]EventView, 0, 2)
	events = s.observeMNDP(meta, &msg, events[:0])
	if len(events) == 0 {
		t.Fatal("initial observation missing")
	}
	allocs := testing.AllocsPerRun(1000, func() {
		meta.timestamp = meta.timestamp.Add(time.Second)
		events = s.observeMNDP(meta, &msg, events[:0])
		if len(events) != 0 {
			panic("redundant event")
		}
	})
	if allocs != 0 {
		t.Fatalf("identical fusion allocations=%v", allocs)
	}
}

func TestFusionPromotesSegmentPresence(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(2000, 0).UTC()
	mac := MAC{0, 1, 2, 3, 4, 5}
	mndp := MNDPMessage{MAC: mac, HasMAC: true, Details: MNDPDetails{Identity: []byte("edge-switch")}}
	events := s.observeMNDP(observationMeta{protocol: ProtocolMNDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: now}, &mndp, nil)
	if len(events) != 1 || events[0].Link.Kind != SegmentPresence {
		t.Fatalf("segment event: %+v", events)
	}
	var lldp LLDPMessage
	DecodeLLDPDU(sampleLLDP(), &lldp)
	events = s.observeLLDP(observationMeta{protocol: ProtocolLLDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: now.Add(time.Second), sourceMAC: mac}, &lldp, events[:0])
	if usedDevices(s) != 1 || usedLinks(s) != 1 || len(events) != 1 || events[0].Link.Kind != PhysicalAdjacency {
		t.Fatalf("promotion devices=%d links=%d events=%+v", usedDevices(s), usedLinks(s), events)
	}
	if events[0].Link.Protocols != (ProtocolsMNDP | ProtocolsLLDP) {
		t.Fatalf("lost provenance: %#x", events[0].Link.Protocols)
	}
}

func TestFusionDoesNotMergeSpoofedChassisMAC(t *testing.T) {
	s := testState(t, nil)
	var lldp LLDPMessage
	DecodeLLDPDU(sampleLLDP(), &lldp)
	now := time.Unix(3000, 0).UTC()
	first := MAC{0, 0xaa, 0, 0, 0, 1}
	second := MAC{0, 0xbb, 0, 0, 0, 2}
	s.observeLLDP(observationMeta{protocol: ProtocolLLDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: now, sourceMAC: first}, &lldp, nil)
	s.observeLLDP(observationMeta{protocol: ProtocolLLDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: now, sourceMAC: second}, &lldp, nil)
	if usedDevices(s) != 2 || usedLinks(s) != 2 {
		t.Fatalf("payload chassis incorrectly fused devices=%d links=%d", usedDevices(s), usedLinks(s))
	}
}

func TestFusionBoundsConflictingAlternatives(t *testing.T) {
	s := testState(t, nil)
	mac := MAC{0, 1, 2, 3, 4, 5}
	meta := observationMeta{protocol: ProtocolMNDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: time.Unix(4000, 0), sourceMAC: mac}
	for i := 0; i < 10; i++ {
		msg := MNDPMessage{MAC: mac, HasMAC: true, Details: MNDPDetails{Identity: []byte(fmt.Sprintf("name-%d", i))}}
		s.observeMNDP(meta, &msg, nil)
		meta.timestamp = meta.timestamp.Add(time.Second)
	}
	idx := s.deviceByKey[DeviceKey{Kind: DeviceKeyMAC, MAC: mac}]
	field := &s.devices[idx].device.SystemName
	if len(field.Values) != s.cfg.MaxAlternatives+1 {
		t.Fatalf("values=%d want=%d", len(field.Values), s.cfg.MaxAlternatives+1)
	}
	if got := string(field.Current()); got != "name-0" {
		t.Fatalf("equal-confidence winner was not stable: %q", got)
	}
}

func TestFusionEmitsEvicted(t *testing.T) {
	cfg := Config{MaxDevices: 1, MaxLinks: 1, MaxDNSRecords: 1, MaxAlternatives: 1, ProtocolQueue: 1, PendingEvents: 1, MaxFrameSize: 2048, MNDPIdleTTL: time.Minute, TimingWheelSlots: 16, Protocols: ProtocolsMNDP}.withDefaults()
	s := newFusionState(cfg, &Classifier{})
	now := time.Unix(5000, 0)
	first := MNDPMessage{MAC: MAC{0, 1, 2, 3, 4, 1}, HasMAC: true}
	second := MNDPMessage{MAC: MAC{0, 1, 2, 3, 4, 2}, HasMAC: true}
	s.observeMNDP(observationMeta{protocol: ProtocolMNDP, interfaceIndex: 1, timestamp: now}, &first, nil)
	s.resetTombstones()
	events := s.observeMNDP(observationMeta{protocol: ProtocolMNDP, interfaceIndex: 1, timestamp: now.Add(time.Second)}, &second, nil)
	if len(events) < 2 || events[0].Kind != EventEvicted || events[len(events)-1].Kind != EventAdded {
		t.Fatalf("eviction events: %+v", events)
	}
}

func TestMDNSCorrelatesAcrossPacketsAndHonorsGoodbye(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(6000, 0).UTC()
	meta := observationMeta{protocol: ProtocolMDNS, interfaceName: "eth0", interfaceIndex: 1, timestamp: now, sourceIP: netip.MustParseAddr("192.0.2.44")}
	instance := []byte("printer._http._tcp.local")
	ptr := MDNSMessage{Records: []DNSRecord{{Name: []byte("_http._tcp.local"), Type: DNSRecordPTR, Class: 1, TTL: 120, Target: instance}}}
	events := s.observeMDNS(meta, &ptr, nil)
	if len(events) != 1 || len(events[0].Device.Services) != 1 || events[0].Device.Services[0].Port != 0 {
		t.Fatalf("PTR event: %+v", events)
	}
	meta.timestamp = now.Add(time.Second)
	details := MDNSMessage{Records: []DNSRecord{
		{Name: instance, Type: DNSRecordSRV, Class: 1, TTL: 120, Target: []byte("printer.local"), Port: 631},
		{Name: instance, Type: DNSRecordTXT, Class: 1, TTL: 120, TXT: []byte{3, 'p', 'd', 'l'}},
		{Name: []byte("printer.local"), Type: DNSRecordA, Class: 1, TTL: 120, Address: netip.MustParseAddr("192.0.2.44")},
	}}
	events = s.observeMDNS(meta, &details, events[:0])
	if len(events) != 1 || len(events[0].Device.Services) != 1 {
		t.Fatalf("detail event: %+v", events)
	}
	svc := events[0].Device.Services[0]
	if svc.Port != 631 || svc.Addresses[0] != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("service=%+v", svc)
	}
	meta.timestamp = now.Add(2 * time.Second)
	goodbye := MDNSMessage{Records: []DNSRecord{{Name: []byte("_http._tcp.local"), Type: DNSRecordPTR, Class: 1, TTL: 0, Target: instance}}}
	events = s.observeMDNS(meta, &goodbye, events[:0])
	if len(events) != 0 || len(derefDevice(s, meta).Services) != 1 {
		t.Fatalf("goodbye removed without RFC grace: %+v", events)
	}
	events = s.tick(now.Add(3*time.Second), events[:0])
	if len(events) != 1 || len(events[0].Device.Services) != 0 {
		t.Fatalf("goodbye expiry event: %+v", events)
	}
}

func TestMDNSGoodbyeCanBeRescuedDuringGrace(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(6500, 0).UTC()
	ip := netip.MustParseAddr("192.0.2.45")
	meta := observationMeta{protocol: ProtocolMDNS, interfaceName: "eth0", interfaceIndex: 1, timestamp: now, sourceIP: ip}
	record := DNSRecord{Name: []byte("speaker.local"), Type: DNSRecordA, Class: 1, TTL: 120, Address: ip}
	s.observeMDNS(meta, &MDNSMessage{Records: []DNSRecord{record}}, nil)
	meta.timestamp = now.Add(2 * time.Second)
	goodbye := record
	goodbye.TTL = 0
	if events := s.observeMDNS(meta, &MDNSMessage{Records: []DNSRecord{goodbye}}, nil); len(events) != 0 {
		t.Fatalf("goodbye emitted before grace: %+v", events)
	}
	meta.timestamp = now.Add(2500 * time.Millisecond)
	if events := s.observeMDNS(meta, &MDNSMessage{Records: []DNSRecord{record}}, nil); len(events) != 0 {
		t.Fatalf("rescue refresh emitted: %+v", events)
	}
	if events := s.tick(now.Add(3*time.Second), nil); len(events) != 0 {
		t.Fatalf("rescued record expired: %+v", events)
	}
}

func TestMDNSCacheFlushUsesOneSecondGrace(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(6800, 0).UTC()
	source := netip.MustParseAddr("192.0.2.50")
	first := DNSRecord{Name: []byte("host.local"), Type: DNSRecordA, Class: 1, TTL: 120, Address: netip.MustParseAddr("192.0.2.51")}
	second := DNSRecord{Name: []byte("host.local"), Type: DNSRecordA, Class: 1, TTL: 120, Address: netip.MustParseAddr("192.0.2.52")}
	meta := observationMeta{protocol: ProtocolMDNS, interfaceName: "eth0", interfaceIndex: 1, timestamp: now, sourceIP: source}
	s.observeMDNS(meta, &MDNSMessage{Records: []DNSRecord{first, second}}, nil)
	meta.timestamp = now.Add(2 * time.Second)
	first.CacheFlush = true
	s.observeMDNS(meta, &MDNSMessage{Records: []DNSRecord{first}}, nil)
	device := derefDevice(s, meta)
	idx := s.deviceByKey[device.Key]
	if len(s.devices[idx].dns) != 2 {
		t.Fatalf("cache flush removed immediately: %d records", len(s.devices[idx].dns))
	}
	s.tick(now.Add(3*time.Second), nil)
	if len(s.devices[idx].dns) != 1 {
		t.Fatalf("stale RRSet member not expired: %d records", len(s.devices[idx].dns))
	}
}

func derefDevice(s *fusionState, meta observationMeta) *DiscoveredDevice {
	key := DeviceKey{Kind: DeviceKeyIP, IP: meta.sourceIP, InterfaceIndex: meta.interfaceIndex}
	return &s.devices[s.deviceByKey[key]].device
}

func TestFusionPromotesIPIdentityOnlyWithDirectMACEvidence(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(7000, 0).UTC()
	ip := netip.MustParseAddr("192.0.2.77")
	mdns := MDNSMessage{Records: []DNSRecord{{Name: []byte("shared.local"), Type: DNSRecordA, Class: 1, TTL: 120, Address: ip}}}
	s.observeMDNS(observationMeta{protocol: ProtocolMDNS, interfaceIndex: 1, timestamp: now, sourceIP: ip}, &mdns, nil)
	ipKey := DeviceKey{Kind: DeviceKeyIP, IP: ip, InterfaceIndex: 1}
	if _, ok := s.deviceByKey[ipKey]; !ok {
		t.Fatal("IP-keyed device missing")
	}
	mac := MAC{0, 1, 2, 3, 4, 0x77}
	mndp := MNDPMessage{MAC: mac, HasMAC: true}
	s.observeMNDP(observationMeta{protocol: ProtocolMNDP, interfaceIndex: 1, timestamp: now.Add(time.Second), sourceIP: ip}, &mndp, nil)
	if usedDevices(s) != 1 {
		t.Fatalf("devices=%d", usedDevices(s))
	}
	if _, ok := s.deviceByKey[DeviceKey{Kind: DeviceKeyMAC, MAC: mac}]; !ok {
		t.Fatal("device was not promoted to directly associated MAC")
	}
}

func TestFusionDoesNotMergeOnHostname(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(8000, 0).UTC()
	msg := MDNSMessage{Records: []DNSRecord{{Name: []byte("same.local"), Type: DNSRecordA, Class: 1, TTL: 120, Address: netip.MustParseAddr("192.0.2.1")}}}
	s.observeMDNS(observationMeta{protocol: ProtocolMDNS, interfaceIndex: 1, timestamp: now, sourceIP: netip.MustParseAddr("192.0.2.1")}, &msg, nil)
	msg.Records[0].Address = netip.MustParseAddr("192.0.2.2")
	s.observeMDNS(observationMeta{protocol: ProtocolMDNS, interfaceIndex: 1, timestamp: now, sourceIP: netip.MustParseAddr("192.0.2.2")}, &msg, nil)
	if usedDevices(s) != 2 {
		t.Fatalf("same hostname incorrectly fused devices=%d", usedDevices(s))
	}
}

func TestMNDPIPv4AndIPv6ShareInterfaceLink(t *testing.T) {
	s := testState(t, nil)
	now := time.Unix(9000, 0).UTC()
	mac := MAC{0x6c, 0x3b, 0x6b, 0x55, 0x9f, 0xa7}
	message := MNDPMessage{
		MAC: mac, HasMAC: true, Details: MNDPDetails{Identity: []byte("MikroTik")},
		Addresses: []netip.Addr{netip.MustParseAddr("10.10.23.250"), netip.MustParseAddr("fe80::6e3b:6bff:fe55:9fa7")},
	}
	meta := observationMeta{protocol: ProtocolMNDP, interfaceName: "en0", interfaceIndex: 11, timestamp: now, sourceIP: netip.MustParseAddr("10.10.23.250")}
	s.observeMNDP(meta, &message, nil)
	meta.timestamp = now.Add(time.Millisecond)
	meta.sourceIP = netip.MustParseAddr("fe80::6e3b:6bff:fe55:9fa7%en0")
	s.observeMNDP(meta, &message, nil)
	if usedDevices(s) != 1 || usedLinks(s) != 1 {
		t.Fatalf("devices=%d links=%d", usedDevices(s), usedLinks(s))
	}
	device := &s.devices[s.deviceByKey[DeviceKey{Kind: DeviceKeyMAC, MAC: mac}]].device
	if len(device.Addresses) != 2 {
		t.Fatalf("addresses=%v", device.Addresses)
	}
}
