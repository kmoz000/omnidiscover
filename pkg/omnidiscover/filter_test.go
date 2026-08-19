package omnidiscover

import (
	"encoding/binary"
	"testing"
)

func runFilter(ins []filterInsn, packet []byte) uint32 {
	var a, x uint32
	load := func(off, size int) (uint32, bool) {
		if off < 0 || off+size > len(packet) {
			return 0, false
		}
		switch size {
		case 1:
			return uint32(packet[off]), true
		case 2:
			return uint32(binary.BigEndian.Uint16(packet[off : off+2])), true
		default:
			return binary.BigEndian.Uint32(packet[off : off+4]), true
		}
	}
	for pc := 0; pc < len(ins); pc++ {
		i := ins[pc]
		switch i.code {
		case bpfLDWABS:
			var ok bool
			a, ok = load(int(i.k), 4)
			if !ok {
				return 0
			}
		case bpfLDHABS:
			var ok bool
			a, ok = load(int(i.k), 2)
			if !ok {
				return 0
			}
		case bpfLDBABS:
			var ok bool
			a, ok = load(int(i.k), 1)
			if !ok {
				return 0
			}
		case bpfLDHIND:
			var ok bool
			a, ok = load(int(i.k+x), 2)
			if !ok {
				return 0
			}
		case bpfLDXBMSH:
			v, ok := load(int(i.k), 1)
			if !ok {
				return 0
			}
			x = 4 * (v & 0x0f)
		case bpfJEQK, bpfJGEK, bpfJSETK:
			matched := (i.code == bpfJEQK && a == i.k) || (i.code == bpfJGEK && a >= i.k) || (i.code == bpfJSETK && a&i.k != 0)
			if matched {
				pc += int(i.jt)
			} else {
				pc += int(i.jf)
			}
		case bpfRETK:
			return i.k
		default:
			panic("unsupported test BPF instruction")
		}
	}
	return 0
}

func ipv4UDPFrame(port uint16, fragmented bool, vlans ...uint16) []byte {
	ip := make([]byte, 28)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	if fragmented {
		binary.BigEndian.PutUint16(ip[6:8], 0x2000)
	}
	ip[9] = 17
	binary.BigEndian.PutUint16(ip[20:22], 49152)
	binary.BigEndian.PutUint16(ip[22:24], port)
	return ethernetFrame(MAC{}, MAC{}, EtherTypeIPv4, ip, vlans...)
}

func TestDiscoveryFilterRoutesOnlySelectedTraffic(t *testing.T) {
	filter := discoveryFilter(ProtocolsAll, 9216)
	if len(filter) == 0 || len(filter) > 256 {
		t.Fatalf("filter length=%d", len(filter))
	}
	cdp := append([]byte{0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0}, sampleCDP()...)
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"lldp", ethernetFrame(MAC{}, MAC{}, EtherTypeLLDP, sampleLLDP()), true},
		{"lldp-three-vlans", ethernetFrame(MAC{}, MAC{}, EtherTypeLLDP, sampleLLDP(), 1, 2, 3), true},
		{"cdp", ethernetFrame(MAC{}, MAC{}, uint16(len(cdp)), cdp), true},
		{"mdns-ipv4", ipv4UDPFrame(MDNSPort, false, 10), true},
		{"mndp-ipv4", ipv4UDPFrame(MNDPPort, false), true},
		{"other-udp", ipv4UDPFrame(9999, false), false},
		{"fragment", ipv4UDPFrame(MDNSPort, true), false},
		{"arp", ethernetFrame(MAC{}, MAC{}, EtherTypeARP, make([]byte, 28)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runFilter(filter, tt.data) != 0; got != tt.want {
				t.Fatalf("accepted=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestDiscoveryFilterHonorsProtocolSelection(t *testing.T) {
	filter := discoveryFilter(ProtocolsMDNS, 2048)
	if runFilter(filter, ipv4UDPFrame(MDNSPort, false)) == 0 {
		t.Fatal("mDNS rejected")
	}
	if runFilter(filter, ipv4UDPFrame(MNDPPort, false)) != 0 {
		t.Fatal("disabled MNDP accepted")
	}
	if runFilter(filter, ethernetFrame(MAC{}, MAC{}, EtherTypeLLDP, sampleLLDP())) != 0 {
		t.Fatal("disabled LLDP accepted")
	}
}
