package omnidiscover

import "encoding/binary"

const MaxLLDPDUSize = 1500

const (
	lldpEnd uint8 = iota
	lldpChassisID
	lldpPortID
	lldpTTL
	lldpPortDescription
	lldpSystemName
	lldpSystemDescription
	lldpSystemCapabilities
	lldpManagementAddress
	lldpOrganizational
)

// LLDPMessage is an owned, caller-reusable LLDP result.
type LLDPMessage struct {
	SourceMAC           MAC
	CaptureVLANs        [maxVLANTags]uint16
	CaptureVLANCount    uint8
	ChassisID           Identifier
	PortID              Identifier
	TTLSeconds          uint16
	SystemName          []byte
	ManagementAddresses []ManagementAddress
	Details             LLDPDetails
}

func (m *LLDPMessage) Reset() {
	m.SourceMAC = MAC{}
	m.CaptureVLANs = [maxVLANTags]uint16{}
	m.CaptureVLANCount = 0
	m.ChassisID.Subtype = 0
	m.ChassisID.Value = m.ChassisID.Value[:0]
	m.PortID.Subtype = 0
	m.PortID.Value = m.PortID.Value[:0]
	m.TTLSeconds = 0
	m.SystemName = m.SystemName[:0]
	for i := range m.ManagementAddresses {
		m.ManagementAddresses[i].Address = m.ManagementAddresses[i].Address[:0]
		m.ManagementAddresses[i].OID = m.ManagementAddresses[i].OID[:0]
	}
	m.ManagementAddresses = m.ManagementAddresses[:0]
	m.Details.PortDescription = m.Details.PortDescription[:0]
	m.Details.SystemDescription = m.Details.SystemDescription[:0]
	for i := range m.Details.VLANs {
		m.Details.VLANs[i].Name = m.Details.VLANs[i].Name[:0]
	}
	m.Details.VLANs = m.Details.VLANs[:0]
	m.Details.SystemCapabilities = 0
	m.Details.EnabledCapabilities = 0
	m.Details.PVID = 0
	m.Details.HasPVID = false
	m.Details.LinkAggregation = LinkAggregation{}
	m.Details.MACPHY = MACPHY{}
	m.Details.MaximumFrameSize = 0
	m.Details.HasMaximumFrameSize = false
}

func DecodeLLDPFrame(frame []byte, dst *LLDPMessage) DecodeStatus {
	var eth EthernetFrame
	st := DecodeEthernetFrame(frame, &eth)
	if !st.Usable() {
		if dst != nil {
			dst.Reset()
		}
		return st
	}
	if eth.EtherType != EtherTypeLLDP {
		if dst != nil {
			dst.Reset()
		}
		addIssue(&st, DecodeFatal, IssueWrongProtocol, 12, eth.EtherType)
		return st
	}
	st = DecodeLLDPDU(eth.Payload, dst)
	if dst != nil {
		dst.SourceMAC = eth.Source
		dst.CaptureVLANCount = eth.VLANCount
		dst.CaptureVLANs = eth.VLANs
	}
	return st
}

func DecodeLLDPDU(pdu []byte, dst *LLDPMessage) DecodeStatus {
	var st DecodeStatus
	if dst == nil {
		addIssue(&st, DecodeFatal, IssueNilDestination, 0, 0)
		return st
	}
	dst.Reset()
	if len(pdu) > MaxLLDPDUSize {
		addIssue(&st, DecodeFatal, IssueTooLarge, len(pdu), 0)
		return st
	}
	var seen [128]bool
	off, mandatory, ended := 0, 0, false
	for off+2 <= len(pdu) {
		headerOff := off
		head := binary.BigEndian.Uint16(pdu[off : off+2])
		typ := uint8(head >> 9)
		length := int(head & 0x01ff)
		off += 2
		if off+length > len(pdu) {
			addIssue(&st, DecodeFatal, IssueTruncatedTLV, headerOff, uint16(typ))
			return st
		}
		value := pdu[off : off+length]
		off += length
		if mandatory < 3 {
			expected := uint8(mandatory + 1)
			if typ != expected {
				addIssue(&st, DecodeFatal, IssueInvalidMandatoryOrder, headerOff, uint16(typ))
				return st
			}
			mandatory++
		}
		if typ == lldpEnd {
			if length != 0 || mandatory != 3 {
				addIssue(&st, DecodeFatal, IssueInvalidTLVLength, headerOff, 0)
				return st
			}
			ended = true
			break
		}
		if seen[typ] && isLLDPSingleton(typ) {
			addIssue(&st, DecodePartial, IssueDuplicateTLV, headerOff, uint16(typ))
			continue
		}
		valid := true
		switch typ {
		case lldpChassisID:
			valid = length >= 2
			if valid {
				dst.ChassisID.Subtype = value[0]
				dst.ChassisID.Value = copyBytes(dst.ChassisID.Value, value[1:])
			}
		case lldpPortID:
			valid = length >= 2
			if valid {
				dst.PortID.Subtype = value[0]
				dst.PortID.Value = copyBytes(dst.PortID.Value, value[1:])
			}
		case lldpTTL:
			valid = length == 2
			if valid {
				dst.TTLSeconds = binary.BigEndian.Uint16(value)
			}
		case lldpPortDescription:
			dst.Details.PortDescription = copyBytes(dst.Details.PortDescription, value)
		case lldpSystemName:
			dst.SystemName = copyBytes(dst.SystemName, value)
		case lldpSystemDescription:
			dst.Details.SystemDescription = copyBytes(dst.Details.SystemDescription, value)
		case lldpSystemCapabilities:
			valid = length == 4
			if valid {
				dst.Details.SystemCapabilities = binary.BigEndian.Uint16(value[:2])
				dst.Details.EnabledCapabilities = binary.BigEndian.Uint16(value[2:])
			}
		case lldpManagementAddress:
			valid = decodeLLDPManagement(value, dst)
		case lldpOrganizational:
			valid = decodeLLDPOrganizational(value, dst)
		}
		if !valid {
			severity := DecodePartial
			if typ >= lldpChassisID && typ <= lldpTTL {
				severity = DecodeFatal
			}
			addIssue(&st, severity, IssueInvalidTLVLength, headerOff, uint16(typ))
			if severity == DecodeFatal {
				return st
			}
			continue
		}
		seen[typ] = true
	}
	if !ended {
		addIssue(&st, DecodeFatal, IssueMissingEnd, off, 0)
	}
	return st
}

func isLLDPSingleton(t uint8) bool {
	return t == lldpChassisID || t == lldpPortID || t == lldpTTL ||
		t == lldpPortDescription || t == lldpSystemName || t == lldpSystemDescription || t == lldpSystemCapabilities
}

func decodeLLDPManagement(v []byte, dst *LLDPMessage) bool {
	if len(v) < 8 {
		return false
	}
	addrLen := int(v[0])
	if addrLen < 1 || addrLen > 31 || 1+addrLen+6 > len(v) {
		return false
	}
	base := 1 + addrLen
	oidLen := int(v[base+5])
	if base+6+oidLen != len(v) {
		return false
	}
	i := len(dst.ManagementAddresses)
	if i < cap(dst.ManagementAddresses) {
		dst.ManagementAddresses = dst.ManagementAddresses[:i+1]
	} else {
		dst.ManagementAddresses = append(dst.ManagementAddresses, ManagementAddress{})
	}
	m := &dst.ManagementAddresses[i]
	m.Subtype = v[1]
	m.Address = copyBytes(m.Address, v[2:1+addrLen])
	m.InterfaceSubtype = v[base]
	m.InterfaceNumber = binary.BigEndian.Uint32(v[base+1 : base+5])
	m.OID = copyBytes(m.OID, v[base+6:])
	return true
}

func decodeLLDPOrganizational(v []byte, dst *LLDPMessage) bool {
	if len(v) < 4 {
		return false
	}
	body := v[4:]
	subtype := v[3]
	if v[0] == 0x00 && v[1] == 0x80 && v[2] == 0xc2 {
		switch subtype {
		case 1: // Port VLAN ID
			if len(body) != 2 {
				return false
			}
			dst.Details.PVID = binary.BigEndian.Uint16(body)
			dst.Details.HasPVID = true
		case 3: // VLAN name
			if len(body) < 3 {
				return false
			}
			n := int(body[2])
			if 3+n != len(body) {
				return false
			}
			i := len(dst.Details.VLANs)
			if i < cap(dst.Details.VLANs) {
				dst.Details.VLANs = dst.Details.VLANs[:i+1]
			} else {
				dst.Details.VLANs = append(dst.Details.VLANs, VLAN{})
			}
			dst.Details.VLANs[i].ID = binary.BigEndian.Uint16(body[:2])
			dst.Details.VLANs[i].Name = copyBytes(dst.Details.VLANs[i].Name, body[3:])
		case 7: // Link aggregation
			if len(body) != 5 {
				return false
			}
			dst.Details.LinkAggregation = LinkAggregation{Present: true, Supported: body[0]&1 != 0, Enabled: body[0]&2 != 0, ID: binary.BigEndian.Uint32(body[1:])}
		}
		return true
	}
	if v[0] == 0x00 && v[1] == 0x12 && v[2] == 0x0f {
		switch subtype {
		case 1: // MAC/PHY configuration/status
			if len(body) != 5 {
				return false
			}
			dst.Details.MACPHY = MACPHY{Present: true, AutonegSupported: body[0]&1 != 0, AutonegEnabled: body[0]&2 != 0, AdvertisedCapabilities: binary.BigEndian.Uint16(body[1:3]), OperationalMAUType: binary.BigEndian.Uint16(body[3:5])}
		case 4: // Maximum frame size
			if len(body) != 2 {
				return false
			}
			dst.Details.MaximumFrameSize = binary.BigEndian.Uint16(body)
			dst.Details.HasMaximumFrameSize = true
		}
	}
	return true
}
