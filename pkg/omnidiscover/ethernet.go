package omnidiscover

import (
	"encoding/binary"
	"net/netip"
)

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeVLAN = 0x8100
	EtherTypeQinQ = 0x88a8
	EtherTypeIPv6 = 0x86dd
	EtherTypeLLDP = 0x88cc
	maxVLANTags   = 3
)

type LLCHeader struct {
	Present bool
	DSAP    uint8
	SSAP    uint8
	Control uint8
	SNAP    bool
	OUI     [3]byte
	PID     uint16
}

// EthernetFrame borrows Payload from the input frame.
type EthernetFrame struct {
	Destination MAC
	Source      MAC
	EtherType   uint16
	VLANs       [maxVLANTags]uint16
	VLANCount   uint8
	LLC         LLCHeader
	Payload     []byte
}

func (f *EthernetFrame) Reset() { *f = EthernetFrame{} }

// DecodeEthernetFrame parses Ethernet II or IEEE 802.3 LLC/SNAP framing.
func DecodeEthernetFrame(b []byte, dst *EthernetFrame) DecodeStatus {
	var st DecodeStatus
	if dst == nil {
		addIssue(&st, DecodeFatal, IssueNilDestination, 0, 0)
		return st
	}
	dst.Reset()
	if len(b) < 14 {
		addIssue(&st, DecodeFatal, IssueTooShort, len(b), 0)
		return st
	}
	copy(dst.Destination[:], b[:6])
	copy(dst.Source[:], b[6:12])
	et := binary.BigEndian.Uint16(b[12:14])
	off := 14
	for et == EtherTypeVLAN || et == EtherTypeQinQ {
		if dst.VLANCount == maxVLANTags {
			addIssue(&st, DecodeFatal, IssueTooManyVLANTags, off, et)
			return st
		}
		if off+4 > len(b) {
			addIssue(&st, DecodeFatal, IssueTooShort, off, et)
			return st
		}
		dst.VLANs[dst.VLANCount] = binary.BigEndian.Uint16(b[off:off+2]) & 0x0fff
		dst.VLANCount++
		et = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	if et >= 0x0600 {
		dst.EtherType = et
		dst.Payload = b[off:]
		return st
	}
	length := int(et)
	data := b[off:]
	if length < len(data) {
		data = data[:length]
	}
	if len(data) < 3 {
		addIssue(&st, DecodeFatal, IssueTooShort, off, 0)
		return st
	}
	dst.LLC = LLCHeader{Present: true, DSAP: data[0], SSAP: data[1], Control: data[2]}
	if data[0] == 0xaa && data[1] == 0xaa && data[2] == 0x03 {
		if len(data) < 8 {
			addIssue(&st, DecodeFatal, IssueTooShort, off+3, 0)
			return st
		}
		dst.LLC.SNAP = true
		copy(dst.LLC.OUI[:], data[3:6])
		dst.LLC.PID = binary.BigEndian.Uint16(data[6:8])
		dst.EtherType = dst.LLC.PID
		dst.Payload = data[8:]
		return st
	}
	dst.Payload = data[3:]
	return st
}

type UDPPacket struct {
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	SourcePort      uint16
	DestinationPort uint16
	Payload         []byte
}

func (u *UDPPacket) Reset() { *u = UDPPacket{} }

// DecodeUDP extracts a non-fragmented UDP datagram from a decoded frame.
func DecodeUDP(frame *EthernetFrame, dst *UDPPacket) DecodeStatus {
	var st DecodeStatus
	if frame == nil || dst == nil {
		addIssue(&st, DecodeFatal, IssueNilDestination, 0, 0)
		return st
	}
	dst.Reset()
	var payload []byte
	switch frame.EtherType {
	case EtherTypeIPv4:
		p := frame.Payload
		if len(p) < 20 || p[0]>>4 != 4 {
			addIssue(&st, DecodeFatal, IssueTooShort, 0, EtherTypeIPv4)
			return st
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || ihl > len(p) {
			addIssue(&st, DecodeFatal, IssueInvalidHeader, 0, EtherTypeIPv4)
			return st
		}
		total := int(binary.BigEndian.Uint16(p[2:4]))
		if total < ihl || total > len(p) {
			addIssue(&st, DecodeFatal, IssueInvalidHeader, 2, EtherTypeIPv4)
			return st
		}
		frag := binary.BigEndian.Uint16(p[6:8])
		if frag&0x3fff != 0 {
			addIssue(&st, DecodeFatal, IssueFragmented, 6, EtherTypeIPv4)
			return st
		}
		if p[9] != 17 {
			addIssue(&st, DecodeFatal, IssueWrongProtocol, 9, uint16(p[9]))
			return st
		}
		dst.SourceIP = netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]})
		dst.DestinationIP = netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
		payload = p[ihl:total]
	case EtherTypeIPv6:
		p := frame.Payload
		if len(p) < 40 || p[0]>>4 != 6 {
			addIssue(&st, DecodeFatal, IssueTooShort, 0, EtherTypeIPv6)
			return st
		}
		total := 40 + int(binary.BigEndian.Uint16(p[4:6]))
		if total > len(p) {
			addIssue(&st, DecodeFatal, IssueInvalidHeader, 4, EtherTypeIPv6)
			return st
		}
		var src, target [16]byte
		copy(src[:], p[8:24])
		copy(target[:], p[24:40])
		dst.SourceIP = netip.AddrFrom16(src)
		dst.DestinationIP = netip.AddrFrom16(target)
		next := p[6]
		off := 40
		for ext := 0; next != 17; ext++ {
			if ext == 8 {
				addIssue(&st, DecodeFatal, IssueInvalidHeader, off, uint16(next))
				return st
			}
			switch next {
			case 0, 43, 60:
				if off+2 > total {
					addIssue(&st, DecodeFatal, IssueTooShort, off, uint16(next))
					return st
				}
				n := int(p[off+1]+1) * 8
				if n < 8 || off+n > total {
					addIssue(&st, DecodeFatal, IssueInvalidHeader, off, uint16(next))
					return st
				}
				next = p[off]
				off += n
			case 44:
				addIssue(&st, DecodeFatal, IssueFragmented, off, uint16(next))
				return st
			case 51:
				if off+2 > total {
					addIssue(&st, DecodeFatal, IssueTooShort, off, uint16(next))
					return st
				}
				n := int(p[off+1]+2) * 4
				if off+n > total {
					addIssue(&st, DecodeFatal, IssueInvalidHeader, off, uint16(next))
					return st
				}
				next = p[off]
				off += n
			default:
				addIssue(&st, DecodeFatal, IssueWrongProtocol, off, uint16(next))
				return st
			}
		}
		payload = p[off:total]
	default:
		addIssue(&st, DecodeFatal, IssueWrongProtocol, 0, frame.EtherType)
		return st
	}
	if len(payload) < 8 {
		addIssue(&st, DecodeFatal, IssueTooShort, 0, 17)
		return st
	}
	udpLen := int(binary.BigEndian.Uint16(payload[4:6]))
	if udpLen < 8 || udpLen > len(payload) {
		addIssue(&st, DecodeFatal, IssueInvalidHeader, 4, 17)
		return st
	}
	dst.SourcePort = binary.BigEndian.Uint16(payload[0:2])
	dst.DestinationPort = binary.BigEndian.Uint16(payload[2:4])
	dst.Payload = payload[8:udpLen]
	return st
}
