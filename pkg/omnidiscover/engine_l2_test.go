//go:build !windows

package omnidiscover

import (
	"testing"
	"time"
)

func TestRouteCaptureLLDPDirectDispatch(t *testing.T) {
	e, err := New(Config{Protocols: ProtocolsLLDP, MaxDevices: 4, MaxLinks: 4, MaxDNSRecords: 4, ProtocolQueue: 2, MaxFrameSize: 2048})
	if err != nil {
		t.Fatal(err)
	}
	source := MAC{0, 1, 2, 3, 4, 5}
	frame := ethernetFrame(MAC{1, 0, 0xc2, 0, 0, 0x0e}, source, EtherTypeLLDP, sampleLLDP(), 7)
	e.routeCapture(captureView{data: frame, interfaceName: "test0", interfaceIndex: 7, timestamp: time.Unix(1, 0), frame: true})
	select {
	case slot := <-e.queues[ProtocolLLDP]:
		defer e.releasePacket(slot)
		if slot.meta.sourceMAC != source || slot.meta.vlanCount != 1 || slot.meta.vlans[0] != 7 || len(slot.data) != len(sampleLLDP()) {
			t.Fatalf("metadata=%+v payload=%d", slot.meta, len(slot.data))
		}
	default:
		t.Fatal("LLDP was not routed")
	}
}
