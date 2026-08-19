package main

import (
	"testing"
	"time"

	"github.com/kmoz000/omnidiscover/pkg/omnidiscover"
)

func TestParseProtocols(t *testing.T) {
	tests := []struct {
		input string
		want  omnidiscover.ProtocolSet
	}{
		{"default", 0},
		{"all", omnidiscover.ProtocolsAll},
		{"LLDP, cdp", omnidiscover.ProtocolsLLDP | omnidiscover.ProtocolsCDP},
		{"bonjour,mndp", omnidiscover.ProtocolsMDNS | omnidiscover.ProtocolsMNDP},
	}
	for _, tt := range tests {
		got, err := parseProtocols(tt.input)
		if err != nil || got != tt.want {
			t.Fatalf("parseProtocols(%q)=%#x, %v; want %#x", tt.input, got, err, tt.want)
		}
	}
	if _, err := parseProtocols("arp"); err == nil {
		t.Fatal("unknown protocol accepted")
	}
}

func TestDashboardCategorizesAndSortsLinks(t *testing.T) {
	now := time.Unix(1000, 0)
	firstKey := omnidiscover.DeviceKey{Kind: omnidiscover.DeviceKeyMAC, MAC: omnidiscover.MAC{0, 1, 2, 3, 4, 5}}
	secondKey := omnidiscover.DeviceKey{Kind: omnidiscover.DeviceKeyMAC, MAC: omnidiscover.MAC{0, 1, 2, 3, 4, 6}}
	d := newDashboard(nil, dashboardConfig{})
	d.snapshot.Devices = []omnidiscover.DiscoveredDevice{
		{Key: firstKey, SystemName: textField("switch"), Protocols: omnidiscover.ProtocolsLLDP},
		{Key: secondKey, SystemName: textField("printer"), Protocols: omnidiscover.ProtocolsMDNS},
	}
	d.snapshot.Links = []omnidiscover.DiscoveredLink{
		{Device: firstKey, Kind: omnidiscover.PhysicalAdjacency, Protocols: omnidiscover.ProtocolsLLDP, LastSeen: now},
		{Device: secondKey, Kind: omnidiscover.SegmentPresence, Protocols: omnidiscover.ProtocolsMDNS, LastSeen: now.Add(time.Second)},
	}
	d.rebuildRows()
	if len(d.rows) != 2 || d.rows[0].name != "printer" {
		t.Fatalf("all rows=%+v", d.rows)
	}
	d.filter = filterPhysical
	d.rebuildRows()
	if len(d.rows) != 1 || d.rows[0].name != "switch" {
		t.Fatalf("physical rows=%+v", d.rows)
	}
	d.filter = filterMDNS
	d.rebuildRows()
	if len(d.rows) != 1 || d.rows[0].name != "printer" {
		t.Fatalf("mDNS rows=%+v", d.rows)
	}
}

func textField(value string) omnidiscover.TextField {
	return omnidiscover.TextField{Values: []omnidiscover.TextValue{{Value: []byte(value)}}}
}

func TestSplitList(t *testing.T) {
	got := splitList(" en0, eth0 ,, ")
	if len(got) != 2 || got[0] != "en0" || got[1] != "eth0" {
		t.Fatalf("interfaces=%v", got)
	}
}
