//go:build windows

package omnidiscover

func openCaptureBackends(cfg Config) ([]captureBackend, error) {
	if unsupported := cfg.Protocols & (ProtocolsLLDP | ProtocolsCDP); unsupported != 0 {
		return nil, &UnsupportedProtocolsError{GOOS: "windows", Protocols: unsupported}
	}
	ifaces, err := captureInterfaces(cfg)
	if err != nil {
		return nil, err
	}
	return openUDPBackends(cfg, ifaces)
}
