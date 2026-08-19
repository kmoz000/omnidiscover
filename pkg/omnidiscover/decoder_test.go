package omnidiscover

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func lldpTLV(typ uint8, value []byte) []byte {
	out := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(out, uint16(typ)<<9|uint16(len(value)))
	copy(out[2:], value)
	return out
}

func sampleLLDP() []byte {
	var p []byte
	p = append(p, lldpTLV(lldpChassisID, []byte{4, 0, 1, 2, 3, 4, 5})...)
	p = append(p, lldpTLV(lldpPortID, append([]byte{5}, []byte("Gi0/1")...))...)
	p = append(p, lldpTLV(lldpTTL, []byte{0, 120})...)
	p = append(p, lldpTLV(lldpSystemName, []byte("edge-switch"))...)
	p = append(p, lldpTLV(lldpSystemCapabilities, []byte{0, 0x14, 0, 0x14})...)
	p = append(p, lldpTLV(lldpManagementAddress, []byte{5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 7, 0})...)
	p = append(p, lldpTLV(lldpOrganizational, []byte{0, 0x80, 0xc2, 1, 0, 42})...)
	p = append(p, lldpTLV(lldpOrganizational, []byte{0, 0x12, 0x0f, 4, 0x05, 0xdc})...)
	p = append(p, 0, 0)
	return p
}

func ethernetFrame(dst, src MAC, etherType uint16, payload []byte, vlans ...uint16) []byte {
	length := 14 + len(payload) + len(vlans)*4
	out := make([]byte, length)
	copy(out[:6], dst[:])
	copy(out[6:12], src[:])
	off := 12
	for i, vlan := range vlans {
		tag := uint16(EtherTypeVLAN)
		if i == 0 && len(vlans) > 1 {
			tag = EtherTypeQinQ
		}
		binary.BigEndian.PutUint16(out[off:off+2], tag)
		binary.BigEndian.PutUint16(out[off+2:off+4], vlan&0xfff)
		off += 4
	}
	binary.BigEndian.PutUint16(out[off:off+2], etherType)
	copy(out[off+2:], payload)
	return out
}

func TestDecodeLLDP(t *testing.T) {
	pdu := sampleLLDP()
	var got LLDPMessage
	if st := DecodeLLDPDU(pdu, &got); !st.Clean() {
		t.Fatalf("status: %s", st)
	}
	if string(got.SystemName) != "edge-switch" || got.TTLSeconds != 120 {
		t.Fatalf("unexpected LLDP: %+v", got)
	}
	if len(got.ManagementAddresses) != 1 || string(got.ManagementAddresses[0].Address) != string([]byte{192, 0, 2, 1}) {
		t.Fatalf("management address: %+v", got.ManagementAddresses)
	}
	if !got.Details.HasPVID || got.Details.PVID != 42 || !got.Details.HasMaximumFrameSize || got.Details.MaximumFrameSize != 1500 {
		t.Fatalf("organizational TLVs: %+v", got.Details)
	}
	src := MAC{0, 1, 2, 3, 4, 5}
	frame := ethernetFrame(MAC{1, 0, 0xc2, 0, 0, 0x0e}, src, EtherTypeLLDP, pdu, 100, 200)
	if st := DecodeLLDPFrame(frame, &got); !st.Clean() {
		t.Fatal(st)
	}
	if got.SourceMAC != src || got.CaptureVLANCount != 2 || got.CaptureVLANs[1] != 200 {
		t.Fatalf("frame metadata: %+v", got)
	}
}

func TestLLDPPartialAndFatal(t *testing.T) {
	pdu := sampleLLDP()
	badOptional := lldpTLV(lldpSystemCapabilities, []byte{1})
	withBad := append([]byte{}, pdu[:len(pdu)-2]...)
	withBad = append(withBad, badOptional...)
	withBad = append(withBad, 0, 0)
	var got LLDPMessage
	st := DecodeLLDPDU(withBad, &got)
	if st.Severity != DecodePartial || !st.Usable() || string(got.SystemName) != "edge-switch" {
		t.Fatalf("partial: %+v %+v", st, got)
	}
	truncated := pdu[:len(pdu)-1]
	st = DecodeLLDPDU(truncated, &got)
	if st.Severity != DecodeFatal {
		t.Fatalf("truncated accepted: %+v", st)
	}
}

func TestLLDPWarmDecodeAllocations(t *testing.T) {
	pdu := sampleLLDP()
	var got LLDPMessage
	DecodeLLDPDU(pdu, &got)
	allocs := testing.AllocsPerRun(1000, func() {
		if st := DecodeLLDPDU(pdu, &got); !st.Clean() {
			panic(st)
		}
	})
	if allocs != 0 {
		t.Fatalf("warm LLDP allocations = %v", allocs)
	}
}

func TestWarmDecoderAllocations(t *testing.T) {
	cdpPacket, mndpPacket, mdnsPacket := sampleCDP(), []byte{0, 0, 0, 1}, sampleMDNS()
	mndpPacket = append(mndpPacket, mndpTLV(mndpTagIdentity, []byte("router"))...)
	var c CDPMessage
	var n MNDPMessage
	var d MDNSMessage
	DecodeCDP(cdpPacket, &c)
	DecodeMNDP(mndpPacket, &n)
	DecodeMDNS(mdnsPacket, &d)
	if got := testing.AllocsPerRun(1000, func() { DecodeCDP(cdpPacket, &c) }); got != 0 {
		t.Fatalf("CDP allocations=%v", got)
	}
	if got := testing.AllocsPerRun(1000, func() { DecodeMNDP(mndpPacket, &n) }); got != 0 {
		t.Fatalf("MNDP allocations=%v", got)
	}
	if got := testing.AllocsPerRun(1000, func() { DecodeMDNS(mdnsPacket, &d) }); got != 0 {
		t.Fatalf("mDNS allocations=%v", got)
	}
}

func cdpTLV(typ uint16, value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(out[:2], typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	copy(out[4:], value)
	return out
}

func sampleCDP() []byte {
	p := []byte{2, 90, 0, 0}
	p = append(p, cdpTLV(cdpTLVDeviceID, []byte("core.example"))...)
	p = append(p, cdpTLV(cdpTLVPortID, []byte("GigabitEthernet1/0/1"))...)
	p = append(p, cdpTLV(cdpTLVCapabilities, []byte{0, 0, 0, 0x29})...)
	p = append(p, cdpTLV(cdpTLVPlatform, []byte("C9300"))...)
	p = append(p, cdpTLV(cdpTLVNativeVLAN, []byte{0, 10})...)
	sum := checksum16(p)
	binary.BigEndian.PutUint16(p[2:4], ^sum)
	return p
}

func TestDecodeCDP(t *testing.T) {
	p := sampleCDP()
	var got CDPMessage
	if st := DecodeCDP(p, &got); !st.Clean() {
		t.Fatalf("status: %s", st)
	}
	if string(got.DeviceID) != "core.example" || string(got.PortID) != "GigabitEthernet1/0/1" || got.Details.Platform == nil {
		t.Fatalf("CDP: %+v", got)
	}
	llc := append([]byte{0xaa, 0xaa, 0x03, 0, 0, 0x0c, 0x20, 0}, p...)
	src := MAC{0, 0x11, 0x22, 0x33, 0x44, 0x55}
	frame := ethernetFrame(MAC{1, 0, 0x0c, 0xcc, 0xcc, 0xcc}, src, uint16(len(llc)), llc)
	if st := DecodeCDPFrame(frame, &got); !st.Clean() {
		t.Fatalf("frame: %s", st)
	}
	if got.SourceMAC != src {
		t.Fatal("source MAC lost")
	}
}

func mndpTLV(tag uint16, value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(out[:2], tag)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(value)))
	copy(out[4:], value)
	return out
}

func TestDecodeMNDP(t *testing.T) {
	p := []byte{0, 0, 0, 1}
	p = append(p, mndpTLV(mndpTagMAC, []byte{0, 1, 2, 3, 4, 5})...)
	p = append(p, mndpTLV(mndpTagIdentity, []byte("router"))...)
	p = append(p, mndpTLV(mndpTagUptime, []byte{5, 0, 0, 0})...)
	p = append(p, mndpTLV(mndpTagIPv4, []byte{192, 0, 2, 9})...)
	var got MNDPMessage
	if st := DecodeMNDP(p, &got); !st.Clean() {
		t.Fatal(st)
	}
	if !got.HasMAC || string(got.Details.Identity) != "router" || got.Details.UptimeSeconds != 5 || got.Addresses[0] != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("MNDP: %+v", got)
	}
	if st := DecodeMNDP([]byte{0, 0, 0, 0}, &got); !st.Clean() || !got.IsRefresh {
		t.Fatal("refresh not recognized")
	}
}

func dnsName(name string) []byte {
	if name == "" {
		return []byte{0}
	}
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, name[start:i]...)
			start = i + 1
		}
	}
	return append(out, 0)
}

func dnsRR(name string, typ uint16, ttl uint32, data []byte) []byte {
	out := dnsName(name)
	var h [10]byte
	binary.BigEndian.PutUint16(h[:2], typ)
	binary.BigEndian.PutUint16(h[2:4], 0x8001)
	binary.BigEndian.PutUint32(h[4:8], ttl)
	binary.BigEndian.PutUint16(h[8:10], uint16(len(data)))
	out = append(out, h[:]...)
	return append(out, data...)
}

func sampleMDNS() []byte {
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p[2:4], 0x8400)
	binary.BigEndian.PutUint16(p[6:8], 4)
	p = append(p, dnsRR("_http._tcp.local", uint16(DNSRecordPTR), 120, dnsName("Printer._http._tcp.local"))...)
	srv := []byte{0, 0, 0, 0, 0, 80}
	srv = append(srv, dnsName("printer.local")...)
	p = append(p, dnsRR("Printer._http._tcp.local", uint16(DNSRecordSRV), 120, srv)...)
	p = append(p, dnsRR("Printer._http._tcp.local", uint16(DNSRecordTXT), 120, []byte{7, 'v', 'e', 'r', 's', '=', '1', '0'})...)
	p = append(p, dnsRR("printer.local", uint16(DNSRecordA), 120, []byte{192, 0, 2, 44})...)
	return p
}

func TestDecodeMDNS(t *testing.T) {
	var got MDNSMessage
	if st := DecodeMDNS(sampleMDNS(), &got); !st.Clean() {
		t.Fatal(st)
	}
	if len(got.Records) != 4 || string(got.Records[0].Target) != "printer._http._tcp.local" || got.Records[3].Address != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("mDNS: %+v", got)
	}
}

func TestMDNSQueryIsIgnoredNotMalformed(t *testing.T) {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[4:6], 1)
	query = append(query, dnsName("_googlecast._tcp.local")...)
	query = append(query, 0, byte(DNSRecordPTR), 0, 1)
	var got MDNSMessage
	status := DecodeMDNS(query, &got)
	if !status.Ignored() || status.Code != IssueNotResponse || status.Usable() {
		t.Fatalf("query status=%+v", status)
	}
}

func TestDNSCompressionLoop(t *testing.T) {
	p := make([]byte, 24)
	binary.BigEndian.PutUint16(p[2:4], 0x8400)
	binary.BigEndian.PutUint16(p[6:8], 1)
	p[12] = 0xc0
	p[13] = 12
	var got MDNSMessage
	st := DecodeMDNS(p, &got)
	if st.Severity != DecodeFatal || st.Code != IssueCompressionLoop {
		t.Fatalf("loop: %+v", st)
	}
}

func TestDecoderHeaderTruncationBoundaries(t *testing.T) {
	tests := []struct {
		name string
		max  int
		fn   func([]byte) DecodeStatus
	}{
		{"ethernet", 14, func(b []byte) DecodeStatus { var m EthernetFrame; return DecodeEthernetFrame(b, &m) }},
		{"cdp", 4, func(b []byte) DecodeStatus { var m CDPMessage; return DecodeCDP(b, &m) }},
		{"mndp", 4, func(b []byte) DecodeStatus { var m MNDPMessage; return DecodeMNDP(b, &m) }},
		{"mdns", 12, func(b []byte) DecodeStatus { var m MDNSMessage; return DecodeMDNS(b, &m) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for n := 0; n < tt.max; n++ {
				if st := tt.fn(make([]byte, n)); st.Severity != DecodeFatal {
					t.Fatalf("length %d: %+v", n, st)
				}
			}
		})
	}
}

func TestEthernetRejectsExcessiveVLANDepth(t *testing.T) {
	frame := ethernetFrame(MAC{}, MAC{}, EtherTypeLLDP, sampleLLDP(), 1, 2, 3, 4)
	var got EthernetFrame
	st := DecodeEthernetFrame(frame, &got)
	if st.Severity != DecodeFatal || st.Code != IssueTooManyVLANTags {
		t.Fatalf("status: %+v", st)
	}
}

func TestUDPRejectsFragmentsAndExtensionDepth(t *testing.T) {
	ipv4 := make([]byte, 28)
	ipv4[0] = 0x45
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(len(ipv4)))
	binary.BigEndian.PutUint16(ipv4[6:8], 0x2000)
	ipv4[9] = 17
	frame := EthernetFrame{EtherType: EtherTypeIPv4, Payload: ipv4}
	var udp UDPPacket
	if st := DecodeUDP(&frame, &udp); st.Code != IssueFragmented {
		t.Fatalf("IPv4 fragment: %+v", st)
	}

	ipv6 := make([]byte, 40+9*8)
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(ipv6)-40))
	ipv6[6] = 0
	for off := 40; off < len(ipv6); off += 8 {
		ipv6[off] = 0
	}
	frame = EthernetFrame{EtherType: EtherTypeIPv6, Payload: ipv6}
	if st := DecodeUDP(&frame, &udp); st.Severity != DecodeFatal || st.Code != IssueInvalidHeader {
		t.Fatalf("IPv6 extension depth: %+v", st)
	}
}

func FuzzDecodeLLDP(f *testing.F) {
	f.Add(sampleLLDP())
	f.Fuzz(func(t *testing.T, b []byte) { var m LLDPMessage; _ = DecodeLLDPDU(b, &m) })
}
func FuzzDecodeCDP(f *testing.F) {
	f.Add(sampleCDP())
	f.Fuzz(func(t *testing.T, b []byte) { var m CDPMessage; _ = DecodeCDP(b, &m) })
}
func FuzzDecodeMNDP(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { var m MNDPMessage; _ = DecodeMNDP(b, &m) })
}
func FuzzDecodeMDNS(f *testing.F) {
	f.Add(sampleMDNS())
	f.Fuzz(func(t *testing.T, b []byte) { var m MDNSMessage; _ = DecodeMDNS(b, &m) })
}
func FuzzDecodeEthernet(f *testing.F) {
	f.Add(ethernetFrame(MAC{}, MAC{}, EtherTypeLLDP, sampleLLDP()))
	f.Fuzz(func(t *testing.T, b []byte) { var m EthernetFrame; _ = DecodeEthernetFrame(b, &m) })
}
