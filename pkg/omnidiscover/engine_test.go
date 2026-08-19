package omnidiscover

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestRouteCaptureDirectDispatch(t *testing.T) {
	e, err := New(Config{Protocols: ProtocolsMDNS, MaxDevices: 4, MaxLinks: 4, MaxDNSRecords: 4, ProtocolQueue: 2, MaxFrameSize: 2048})
	if err != nil {
		t.Fatal(err)
	}
	frame := ipv4UDPFrame(MDNSPort, false, 7)
	copy(frame[6:12], []byte{0, 1, 2, 3, 4, 5})
	e.routeCapture(captureView{data: frame, interfaceName: "test0", interfaceIndex: 7, timestamp: time.Unix(1, 0), frame: true})
	select {
	case slot := <-e.queues[ProtocolMDNS]:
		if slot.meta.sourceMAC != (MAC{0, 1, 2, 3, 4, 5}) || slot.meta.vlanCount != 1 || slot.meta.vlans[0] != 7 {
			t.Fatalf("metadata: %+v", slot.meta)
		}
		if len(slot.data) != 0 {
			t.Fatalf("payload length=%d", len(slot.data))
		}
		e.releasePacket(slot)
	default:
		t.Fatal("mDNS was not routed")
	}
}

func TestResolveWildcardUDPInterface(t *testing.T) {
	prefixes := []interfacePrefix{
		{name: "en0", index: 11, prefix: netip.MustParsePrefix("10.10.23.0/24")},
		{name: "bridge100", index: 22, prefix: netip.MustParsePrefix("172.30.30.0/23")},
	}
	name, index := resolveInterface(netip.MustParseAddr("10.10.23.250"), prefixes)
	if name != "en0" || index != 11 {
		t.Fatalf("name=%q index=%d", name, index)
	}
	if name, index = resolveInterface(netip.MustParseAddr("203.0.113.1"), prefixes); name != "" || index != 0 {
		t.Fatalf("unexpected match name=%q index=%d", name, index)
	}
}

func TestRouteCaptureWarmAllocations(t *testing.T) {
	e, err := New(Config{Protocols: ProtocolsMDNS, MaxDevices: 4, MaxLinks: 4, MaxDNSRecords: 4, ProtocolQueue: 4, MaxFrameSize: 2048})
	if err != nil {
		t.Fatal(err)
	}
	frame := ipv4UDPFrame(MDNSPort, false)
	view := captureView{data: frame, interfaceName: "test0", interfaceIndex: 7, timestamp: time.Unix(1, 0), frame: true}
	allocs := testing.AllocsPerRun(1000, func() {
		e.routeCapture(view)
		select {
		case slot := <-e.queues[ProtocolMDNS]:
			e.releasePacket(slot)
		default:
			panic("mDNS route did not enqueue")
		}
	})
	if allocs != 0 {
		t.Fatalf("route allocations=%v", allocs)
	}
}

func TestOwnedStreamQueueCoalesces(t *testing.T) {
	var dropped atomic.Uint64
	q := newOwnedStreamQueue(2, &dropped)
	key := LinkKey{InterfaceIndex: 1, SourceMAC: MAC{0, 1, 2, 3, 4, 5}, Device: DeviceKey{Kind: DeviceKeyMAC, MAC: MAC{0, 1, 2, 3, 4, 5}}}
	d := DiscoveredDevice{Key: key.Device}
	l := DiscoveredLink{Key: key, Device: key.Device}
	q.enqueue(EventView{Kind: EventAdded, Changed: FieldIdentity, Device: &d, Link: &l})
	q.enqueue(EventView{Kind: EventChanged, Changed: FieldNames, Device: &d, Link: &l})
	event, ok := q.pop()
	if !ok || event.Kind != EventAdded || event.Changed != (FieldIdentity|FieldNames) {
		t.Fatalf("event=%+v ok=%v", event, ok)
	}
}

func TestSnapshotIsOwned(t *testing.T) {
	e, err := New(Config{Protocols: ProtocolsMNDP, MaxDevices: 4, MaxLinks: 4, MaxDNSRecords: 4, ProtocolQueue: 2, MaxFrameSize: 2048})
	if err != nil {
		t.Fatal(err)
	}
	mac := MAC{0, 1, 2, 3, 4, 5}
	msg := MNDPMessage{MAC: mac, HasMAC: true, Details: MNDPDetails{Identity: []byte("router")}}
	meta := observationMeta{protocol: ProtocolMNDP, interfaceName: "eth0", interfaceIndex: 1, timestamp: time.Now(), sourceMAC: mac}
	e.stateMu.Lock()
	e.state.observeMNDP(meta, &msg, nil)
	e.stateMu.Unlock()
	var snap Snapshot
	e.Snapshot(&snap)
	if len(snap.Devices) != 1 || len(snap.Links) != 1 {
		t.Fatalf("snapshot: %+v", snap)
	}
	snap.Devices[0].SystemName.Values[0].Value[0] = 'X'
	var second Snapshot
	e.Snapshot(&second)
	if second.Devices[0].SystemName.Current()[0] == 'X' {
		t.Fatal("snapshot aliases engine state")
	}
}
