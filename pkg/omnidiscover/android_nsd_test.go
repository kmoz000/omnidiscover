package omnidiscover

import "testing"

func TestAndroidNSDUsesMDNSDecoder(t *testing.T) {
	var message MDNSMessage
	status := DecodeAndroidNSD(sampleMDNS(), &message)
	if !status.Clean() || len(message.Records) != 4 || ProtocolAndroidNSD != ProtocolMDNS || ProtocolsAndroidNSD != ProtocolsMDNS {
		t.Fatalf("status=%+v records=%d", status, len(message.Records))
	}
}

func TestServiceTXTValueAndGoogleCastProfile(t *testing.T) {
	service := Service{
		Type: []byte("_googlecast._tcp.local"),
		TXT:  []byte{7, 'f', 'n', '=', 'L', 'o', 'f', 't', 8, 'm', 'd', '=', 'T', 'V', '4', 'K', 'X'},
	}
	if service.Profile() != ServiceProfileGoogleCast {
		t.Fatal("Google Cast profile not recognized")
	}
	if value, ok := service.TXTValue([]byte("FN")); !ok || string(value) != "Loft" {
		t.Fatalf("fn=%q ok=%v", value, ok)
	}
	if _, ok := service.TXTValue([]byte("missing")); ok {
		t.Fatal("missing TXT key found")
	}
	if allocs := testing.AllocsPerRun(1000, func() { _, _ = service.TXTValue([]byte("md")) }); allocs != 0 {
		t.Fatalf("TXT lookup allocations=%v", allocs)
	}
}
