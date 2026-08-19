package omnidiscover

import (
	"encoding/binary"
	"net/netip"
)

const (
	cdpPID                    = 0x2000
	cdpTLVDeviceID            = 0x0001
	cdpTLVAddresses           = 0x0002
	cdpTLVPortID              = 0x0003
	cdpTLVCapabilities        = 0x0004
	cdpTLVSoftware            = 0x0005
	cdpTLVPlatform            = 0x0006
	cdpTLVNativeVLAN          = 0x000a
	cdpTLVDuplex              = 0x000b
	cdpTLVSystemName          = 0x0014
	cdpTLVManagementAddresses = 0x0016
)

var ciscoOUI = [3]byte{0x00, 0x00, 0x0c}

type CDPMessage struct {
	SourceMAC        MAC
	CaptureVLANs     [maxVLANTags]uint16
	CaptureVLANCount uint8
	TTLSeconds       uint8
	DeviceID         []byte
	PortID           []byte
	SystemName       []byte
	Addresses        []netip.Addr
	Details          CDPDetails
}

func (m *CDPMessage) Reset() {
	m.SourceMAC = MAC{}
	m.CaptureVLANs = [maxVLANTags]uint16{}
	m.CaptureVLANCount = 0
	m.TTLSeconds = 0
	m.DeviceID = m.DeviceID[:0]
	m.PortID = m.PortID[:0]
	m.SystemName = m.SystemName[:0]
	m.Addresses = m.Addresses[:0]
	m.Details.Version = 0
	m.Details.Checksum = 0
	m.Details.NativeVLAN = 0
	m.Details.HasNativeVLAN = false
	m.Details.Duplex = 0
	m.Details.HasDuplex = false
	m.Details.Capabilities = 0
	m.Details.SoftwareVersion = m.Details.SoftwareVersion[:0]
	m.Details.Platform = m.Details.Platform[:0]
	m.Details.ManagementAddress = m.Details.ManagementAddress[:0]
}

func DecodeCDPFrame(frame []byte, dst *CDPMessage) DecodeStatus {
	var eth EthernetFrame
	st := DecodeEthernetFrame(frame, &eth)
	if !st.Usable() {
		if dst != nil {
			dst.Reset()
		}
		return st
	}
	if !eth.LLC.SNAP || eth.LLC.OUI != ciscoOUI || eth.LLC.PID != cdpPID {
		if dst != nil {
			dst.Reset()
		}
		addIssue(&st, DecodeFatal, IssueWrongProtocol, 14, eth.LLC.PID)
		return st
	}
	st = DecodeCDP(eth.Payload, dst)
	if dst != nil {
		dst.SourceMAC = eth.Source
		dst.CaptureVLANs = eth.VLANs
		dst.CaptureVLANCount = eth.VLANCount
	}
	return st
}

// DecodeCDP parses a CDP header followed by TLVs.
func DecodeCDP(packet []byte, dst *CDPMessage) DecodeStatus {
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
	if len(packet) > 65535 {
		addIssue(&st, DecodeFatal, IssueTooLarge, len(packet), 0)
		return st
	}
	dst.Details.Version = packet[0]
	dst.TTLSeconds = packet[1]
	dst.Details.Checksum = binary.BigEndian.Uint16(packet[2:4])
	if packet[0] != 1 && packet[0] != 2 {
		addIssue(&st, DecodePartial, IssueInvalidHeader, 0, uint16(packet[0]))
	}
	if checksum16(packet) != 0xffff {
		addIssue(&st, DecodePartial, IssueInvalidChecksum, 2, 0)
	}
	var seen [32]bool
	for off := 4; off < len(packet); {
		if off+4 > len(packet) {
			addIssue(&st, DecodeFatal, IssueTruncatedTLV, off, 0)
			return st
		}
		typ := binary.BigEndian.Uint16(packet[off : off+2])
		length := int(binary.BigEndian.Uint16(packet[off+2 : off+4]))
		if length < 4 || off+length > len(packet) {
			addIssue(&st, DecodeFatal, IssueInvalidTLVLength, off, typ)
			return st
		}
		v := packet[off+4 : off+length]
		if typ < uint16(len(seen)) && seen[typ] && cdpSingleton(typ) {
			addIssue(&st, DecodePartial, IssueDuplicateTLV, off, typ)
			off += length
			continue
		}
		valid := true
		switch typ {
		case cdpTLVDeviceID:
			dst.DeviceID = copyBytes(dst.DeviceID, v)
		case cdpTLVAddresses:
			valid = decodeCDPAddresses(v, &dst.Addresses)
		case cdpTLVPortID:
			dst.PortID = copyBytes(dst.PortID, v)
		case cdpTLVCapabilities:
			valid = len(v) == 4
			if valid {
				dst.Details.Capabilities = binary.BigEndian.Uint32(v)
			}
		case cdpTLVSoftware:
			dst.Details.SoftwareVersion = copyBytes(dst.Details.SoftwareVersion, v)
		case cdpTLVPlatform:
			dst.Details.Platform = copyBytes(dst.Details.Platform, v)
		case cdpTLVNativeVLAN:
			valid = len(v) == 2
			if valid {
				dst.Details.NativeVLAN = binary.BigEndian.Uint16(v)
				dst.Details.HasNativeVLAN = true
			}
		case cdpTLVDuplex:
			valid = len(v) == 1
			if valid {
				dst.Details.Duplex = v[0]
				dst.Details.HasDuplex = true
			}
		case cdpTLVSystemName:
			dst.SystemName = copyBytes(dst.SystemName, v)
		case cdpTLVManagementAddresses:
			valid = decodeCDPAddresses(v, &dst.Details.ManagementAddress)
		}
		if !valid {
			addIssue(&st, DecodePartial, IssueInvalidTLVLength, off, typ)
		} else if typ < uint16(len(seen)) {
			seen[typ] = true
		}
		off += length
	}
	return st
}

func cdpSingleton(t uint16) bool {
	switch t {
	case cdpTLVDeviceID, cdpTLVPortID, cdpTLVCapabilities, cdpTLVSoftware, cdpTLVPlatform,
		cdpTLVNativeVLAN, cdpTLVDuplex, cdpTLVSystemName:
		return true
	default:
		return false
	}
}

func decodeCDPAddresses(v []byte, dst *[]netip.Addr) bool {
	if len(v) < 4 {
		return false
	}
	count := int(binary.BigEndian.Uint32(v[:4]))
	if count > 1024 {
		return false
	}
	off := 4
	for i := 0; i < count; i++ {
		if off+1 > len(v) {
			return false
		}
		protoType := v[off]
		off++
		if off+1 > len(v) {
			return false
		}
		protoLen := int(v[off])
		off++
		if off+protoLen+2 > len(v) {
			return false
		}
		proto := v[off : off+protoLen]
		off += protoLen
		addrLen := int(binary.BigEndian.Uint16(v[off : off+2]))
		off += 2
		if off+addrLen > len(v) {
			return false
		}
		addrBytes := v[off : off+addrLen]
		off += addrLen
		isIP := (protoType == 1 && protoLen == 1 && proto[0] == 0xcc) ||
			(protoType == 2 && protoLen >= 2 && proto[protoLen-2] == 0x08 && proto[protoLen-1] == 0x00)
		if !isIP && addrLen != 16 {
			continue
		}
		var addr netip.Addr
		if addrLen == 4 {
			addr = netip.AddrFrom4([4]byte{addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3]})
		} else if addrLen == 16 {
			var x [16]byte
			copy(x[:], addrBytes)
			addr = netip.AddrFrom16(x)
		} else {
			continue
		}
		*dst = appendUniqueAddr(*dst, addr)
	}
	return off == len(v)
}

func appendUniqueAddr(dst []netip.Addr, a netip.Addr) []netip.Addr {
	if !a.IsValid() {
		return dst
	}
	a = a.Unmap()
	for _, v := range dst {
		if v == a {
			return dst
		}
	}
	return append(dst, a)
}

func checksum16(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}
