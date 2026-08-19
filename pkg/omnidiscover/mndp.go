package omnidiscover

import (
	"encoding/binary"
	"net/netip"
)

const (
	MNDPPort          = 5678
	MaxMNDPPacketSize = 1500
	mndpTagMAC        = 1
	mndpTagIdentity   = 5
	mndpTagVersion    = 7
	mndpTagPlatform   = 8
	mndpTagUptime     = 10
	mndpTagSoftwareID = 11
	mndpTagBoard      = 12
	mndpTagIPv6       = 15
	mndpTagInterface  = 16
	mndpTagIPv4       = 17
)

type MNDPMessage struct {
	SourceIP  netip.Addr
	MAC       MAC
	HasMAC    bool
	Addresses []netip.Addr
	IsRefresh bool
	Details   MNDPDetails
}

func (m *MNDPMessage) Reset() {
	m.SourceIP = netip.Addr{}
	m.MAC = MAC{}
	m.HasMAC = false
	m.Addresses = m.Addresses[:0]
	m.IsRefresh = false
	m.Details.TypeTag = 0
	m.Details.Sequence = 0
	m.Details.Identity = m.Details.Identity[:0]
	m.Details.Version = m.Details.Version[:0]
	m.Details.Platform = m.Details.Platform[:0]
	m.Details.SoftwareID = m.Details.SoftwareID[:0]
	m.Details.Board = m.Details.Board[:0]
	m.Details.InterfaceName = m.Details.InterfaceName[:0]
	m.Details.UptimeSeconds = 0
	m.Details.HasUptime = false
}

func DecodeMNDP(packet []byte, dst *MNDPMessage) DecodeStatus {
	var st DecodeStatus
	if dst == nil {
		addIssue(&st, DecodeFatal, IssueNilDestination, 0, 0)
		return st
	}
	dst.Reset()
	if len(packet) < 4 {
		addIssue(&st, DecodeFatal, IssueTooShort, len(packet), 0)
		return st
	}
	if len(packet) > MaxMNDPPacketSize {
		addIssue(&st, DecodeFatal, IssueTooLarge, len(packet), 0)
		return st
	}
	dst.Details.TypeTag = binary.BigEndian.Uint16(packet[:2])
	dst.Details.Sequence = binary.BigEndian.Uint16(packet[2:4])
	dst.IsRefresh = dst.Details.TypeTag == 0 && dst.Details.Sequence == 0
	var seen [18]bool
	for off := 4; off < len(packet); {
		if off+4 > len(packet) {
			addIssue(&st, DecodeFatal, IssueTruncatedTLV, off, 0)
			return st
		}
		tag := binary.BigEndian.Uint16(packet[off : off+2])
		length := int(binary.BigEndian.Uint16(packet[off+2 : off+4]))
		if off+4+length > len(packet) {
			addIssue(&st, DecodeFatal, IssueInvalidTLVLength, off, tag)
			return st
		}
		v := packet[off+4 : off+4+length]
		if tag < uint16(len(seen)) && seen[tag] && tag != mndpTagIPv4 && tag != mndpTagIPv6 {
			addIssue(&st, DecodePartial, IssueDuplicateTLV, off, tag)
			off += 4 + length
			continue
		}
		valid := true
		switch tag {
		case mndpTagMAC:
			valid = len(v) == 6
			if valid {
				copy(dst.MAC[:], v)
				dst.HasMAC = dst.MAC.IsUnicast()
			}
		case mndpTagIdentity:
			dst.Details.Identity = copyBytes(dst.Details.Identity, v)
		case mndpTagVersion:
			dst.Details.Version = copyBytes(dst.Details.Version, v)
		case mndpTagPlatform:
			dst.Details.Platform = copyBytes(dst.Details.Platform, v)
		case mndpTagUptime:
			valid = len(v) == 4
			if valid {
				dst.Details.UptimeSeconds = binary.LittleEndian.Uint32(v)
				dst.Details.HasUptime = true
			}
		case mndpTagSoftwareID:
			dst.Details.SoftwareID = copyBytes(dst.Details.SoftwareID, v)
		case mndpTagBoard:
			dst.Details.Board = copyBytes(dst.Details.Board, v)
		case mndpTagInterface:
			dst.Details.InterfaceName = copyBytes(dst.Details.InterfaceName, v)
		case mndpTagIPv4:
			valid = len(v) == 4
			if valid {
				dst.Addresses = appendUniqueAddr(dst.Addresses, netip.AddrFrom4([4]byte{v[0], v[1], v[2], v[3]}))
			}
		case mndpTagIPv6:
			valid = len(v) == 16
			if valid {
				var a [16]byte
				copy(a[:], v)
				dst.Addresses = appendUniqueAddr(dst.Addresses, netip.AddrFrom16(a))
			}
		}
		if !valid {
			addIssue(&st, DecodePartial, IssueInvalidTLVLength, off, tag)
		} else if tag < uint16(len(seen)) {
			seen[tag] = true
		}
		off += 4 + length
	}
	return st
}
