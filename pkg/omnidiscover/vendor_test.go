package omnidiscover

import "testing"

func TestLookupMACVendorLongestIEEEPrefix(t *testing.T) {
	tests := []struct {
		mac    MAC
		name   string
		bits   uint8
		source MACVendorSource
	}{
		{MAC{0x48, 0xa9, 0x8a, 0x2c, 0x48, 0x32}, "Routerboard.com", 24, MACVendorIEEEMAL},
		{MAC{0xc8, 0x5c, 0xe2, 0x70, 0x00, 0x01}, "SYNERGY SYSTEMS AND SOLUTIONS", 28, MACVendorIEEEMAM},
		{MAC{0x8c, 0x1f, 0x64, 0xaf, 0xa0, 0x01}, "DATA ELECTRONIC DEVICES, INC", 36, MACVendorIEEEMAS},
		{MAC{0x02, 0, 0, 0, 0, 1}, "", 0, MACVendorLocallyAdministered},
		{MAC{0x01, 0, 0x5e, 0, 0, 0xfb}, "", 0, MACVendorMulticast},
	}
	for _, tt := range tests {
		got := LookupMACVendor(tt.mac)
		if got.Name != tt.name || got.PrefixBits != tt.bits || got.Source != tt.source {
			t.Fatalf("LookupMACVendor(%x)=%+v", tt.mac, got)
		}
	}
}

func TestLookupMACVendorAllocations(t *testing.T) {
	mac := MAC{0x48, 0xa9, 0x8a, 0x2c, 0x48, 0x32}
	if got := testing.AllocsPerRun(1000, func() { _ = LookupMACVendor(mac) }); got != 0 {
		t.Fatalf("allocations=%v", got)
	}
}
