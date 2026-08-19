package omnidiscover

import (
	"errors"
	"fmt"
	"runtime"
	"time"
)

const (
	DefaultMaxDevices          = 4096
	DefaultMaxLinks            = 8192
	DefaultMaxDNSRecords       = 16384
	DefaultMaxAlternatives     = 4
	DefaultProtocolQueue       = 256
	DefaultPendingEvents       = 1024
	DefaultMaxFrameSize        = 9216
	DefaultMNDPIdleTTL         = 180 * time.Second
	DefaultTimingWheelSlots    = 512
	DefaultMaxClassification   = 256
	DefaultMaxRegexRules       = 128
	DefaultMaxRegexPatternSize = 1024
)

var ErrClosed = errors.New("omnidiscover: engine closed")
var ErrAlreadyRunning = errors.New("omnidiscover: engine already running")

type UnsupportedProtocolsError struct {
	GOOS      string
	Protocols ProtocolSet
}

func (e *UnsupportedProtocolsError) Error() string {
	return fmt.Sprintf("omnidiscover: live protocols %#x are unsupported on %s", uint8(e.Protocols), e.GOOS)
}

// Config controls capture, bounded state, classification, and delivery.
type Config struct {
	Interfaces       []string
	Protocols        ProtocolSet
	MaxDevices       int
	MaxLinks         int
	MaxDNSRecords    int
	MaxAlternatives  int
	ProtocolQueue    int
	PendingEvents    int
	MaxFrameSize     int
	MNDPIdleTTL      time.Duration
	TimingWheelSlots int
	Rules            []Rule
	IncludeLoopback  bool
}

func (c Config) withDefaults() Config {
	if c.Protocols == 0 {
		if runtime.GOOS == "windows" {
			c.Protocols = ProtocolsMNDP | ProtocolsMDNS
		} else {
			c.Protocols = ProtocolsAll
		}
	}
	if c.MaxDevices <= 0 {
		c.MaxDevices = DefaultMaxDevices
	}
	if c.MaxLinks <= 0 {
		c.MaxLinks = DefaultMaxLinks
	}
	if c.MaxDNSRecords <= 0 {
		c.MaxDNSRecords = DefaultMaxDNSRecords
	}
	if c.MaxAlternatives <= 0 {
		c.MaxAlternatives = DefaultMaxAlternatives
	}
	if c.ProtocolQueue <= 0 {
		c.ProtocolQueue = DefaultProtocolQueue
	}
	if c.PendingEvents <= 0 {
		c.PendingEvents = DefaultPendingEvents
	}
	if c.MaxFrameSize <= 0 {
		c.MaxFrameSize = DefaultMaxFrameSize
	}
	if c.MNDPIdleTTL <= 0 {
		c.MNDPIdleTTL = DefaultMNDPIdleTTL
	}
	if c.TimingWheelSlots <= 0 {
		c.TimingWheelSlots = DefaultTimingWheelSlots
	}
	return c
}

func (c Config) validate() error {
	if c.Protocols&^ProtocolsAll != 0 {
		return fmt.Errorf("omnidiscover: unknown protocol bits %#x", uint8(c.Protocols&^ProtocolsAll))
	}
	if runtime.GOOS == "windows" {
		if unsupported := c.Protocols & (ProtocolsLLDP | ProtocolsCDP); unsupported != 0 {
			return &UnsupportedProtocolsError{GOOS: runtime.GOOS, Protocols: unsupported}
		}
	}
	if c.MaxFrameSize < 512 || c.MaxFrameSize > 65535 {
		return fmt.Errorf("omnidiscover: MaxFrameSize must be between 512 and 65535")
	}
	if c.MaxDevices < 1 || c.MaxLinks < 1 || c.MaxDNSRecords < 1 {
		return fmt.Errorf("omnidiscover: cache limits must be positive")
	}
	if c.MaxAlternatives < 1 || c.MaxAlternatives > 32 {
		return fmt.Errorf("omnidiscover: MaxAlternatives must be between 1 and 32")
	}
	return nil
}
