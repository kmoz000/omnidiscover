//go:build windows

package omnidiscover

import (
	"errors"
	"testing"
)

func TestWindowsRejectsLiveLayer2Protocols(t *testing.T) {
	_, err := New(Config{Protocols: ProtocolsLLDP | ProtocolsMDNS})
	var unsupported *UnsupportedProtocolsError
	if !errors.As(err, &unsupported) || unsupported.GOOS != "windows" || unsupported.Protocols != ProtocolsLLDP {
		t.Fatalf("error=%v", err)
	}
}

func TestWindowsDefaultsToUDPProtocols(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if e.cfg.Protocols != ProtocolsMNDP|ProtocolsMDNS {
		t.Fatalf("protocols=%#x", e.cfg.Protocols)
	}
}
