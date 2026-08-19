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

func TestDashboardShowsMACVendorModelAndUptime(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	mac := omnidiscover.MAC{0x48, 0xa9, 0x8a, 0x2c, 0x48, 0x32}
	key := omnidiscover.DeviceKey{Kind: omnidiscover.DeviceKeyMAC, MAC: mac}
	d := newDashboard(nil, dashboardConfig{})
	d.snapshot.Devices = []omnidiscover.DiscoveredDevice{{
		Key: key, ClaimedMACs: []omnidiscover.MAC{mac}, Model: textField("RB952Ui-5ac2nD"),
		Uptime:    omnidiscover.DeviceUptime{Seconds: 2*86400 + 17*3600 + 47*60 + 23, ObservedAt: now, Protocols: omnidiscover.ProtocolsMNDP, Valid: true},
		Protocols: omnidiscover.ProtocolsMNDP,
	}}
	d.snapshot.Links = []omnidiscover.DiscoveredLink{{Device: key, Kind: omnidiscover.SegmentPresence, Protocols: omnidiscover.ProtocolsMNDP, LastSeen: now}}
	d.rebuildRows()
	if len(d.rows) != 1 || d.rows[0].mac != "48:a9:8a:2c:48:32" || d.rows[0].vendor != "Routerboard.com" || d.rows[0].platform != "RB952Ui-5ac2nD" {
		t.Fatalf("row=%+v", d.rows)
	}
	if got := uptimeSummary(d.rows[0].device, now); got != "2d 17:47:23" {
		t.Fatalf("uptime=%q", got)
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
