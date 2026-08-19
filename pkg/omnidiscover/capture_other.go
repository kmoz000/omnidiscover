//go:build !linux && !darwin && !windows

package omnidiscover

import "runtime"

func openCaptureBackends(cfg Config) ([]captureBackend, error) {
	if unsupported := cfg.Protocols & (ProtocolsLLDP | ProtocolsCDP); unsupported != 0 {
		return nil, &UnsupportedProtocolsError{GOOS: runtime.GOOS, Protocols: unsupported}
	}
	ifaces, err := captureInterfaces(cfg)
	if err != nil {
		return nil, err
	}
	return openUDPBackends(cfg, ifaces)
}
