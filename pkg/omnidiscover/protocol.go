package omnidiscover

import "fmt"

// Protocol identifies a discovery protocol.
type Protocol uint8

const (
	ProtocolUnknown Protocol = iota
	ProtocolLLDP
	ProtocolCDP
	ProtocolMNDP
	ProtocolMDNS
)

func (p Protocol) String() string {
	switch p {
	case ProtocolLLDP:
		return "lldp"
	case ProtocolCDP:
		return "cdp"
	case ProtocolMNDP:
		return "mndp"
	case ProtocolMDNS:
		return "mdns"
	default:
		return "unknown"
	}
}

// ProtocolSet is a compact set of enabled or observed protocols.
type ProtocolSet uint8

const (
	ProtocolsLLDP ProtocolSet = 1 << iota
	ProtocolsCDP
	ProtocolsMNDP
	ProtocolsMDNS
	ProtocolsAll = ProtocolsLLDP | ProtocolsCDP | ProtocolsMNDP | ProtocolsMDNS
)

func (p Protocol) Set() ProtocolSet {
	if p < ProtocolLLDP || p > ProtocolMDNS {
		return 0
	}
	return 1 << (p - 1)
}

func (s ProtocolSet) Has(p Protocol) bool { return s&p.Set() != 0 }

// DecodeSeverity describes whether decoded data may be used.
type DecodeSeverity uint8

const (
	DecodeClean DecodeSeverity = iota
	DecodeIgnored
	DecodePartial
	DecodeFatal
)

// DecodeIssue identifies a malformed or unsupported input condition.
type DecodeIssue uint8

const (
	IssueNone DecodeIssue = iota
	IssueNilDestination
	IssueTooShort
	IssueTooLarge
	IssueWrongProtocol
	IssueTooManyVLANTags
	IssueTruncatedTLV
	IssueInvalidTLVLength
	IssueInvalidMandatoryOrder
	IssueDuplicateTLV
	IssueMissingEnd
	IssueInvalidHeader
	IssueInvalidChecksum
	IssueCompressionLoop
	IssueTooManyLabels
	IssueFragmented
	IssueUnsupported
	IssueNotResponse
)

// DecodeStatus is returned by all parsers without allocating an error.
// Code, Offset, and TLVType describe the first issue at the greatest severity.
type DecodeStatus struct {
	Severity   DecodeSeverity
	Code       DecodeIssue
	Offset     int
	TLVType    uint16
	IssueCount uint16
}

func (s DecodeStatus) Clean() bool   { return s.Severity == DecodeClean }
func (s DecodeStatus) Ignored() bool { return s.Severity == DecodeIgnored }
func (s DecodeStatus) Usable() bool  { return s.Severity == DecodeClean || s.Severity == DecodePartial }

func (s DecodeStatus) String() string {
	if s.Clean() {
		return "clean"
	}
	return fmt.Sprintf("decode severity=%d issue=%d offset=%d type=%d count=%d",
		s.Severity, s.Code, s.Offset, s.TLVType, s.IssueCount)
}

func addIssue(s *DecodeStatus, severity DecodeSeverity, code DecodeIssue, off int, typ uint16) {
	if s.IssueCount != ^uint16(0) {
		s.IssueCount++
	}
	if severity > s.Severity || s.Code == IssueNone {
		s.Severity = severity
		s.Code = code
		s.Offset = off
		s.TLVType = typ
	}
}
