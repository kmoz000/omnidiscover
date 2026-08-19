package omnidiscover

import "bytes"

// ProtocolAndroidNSD is an API alias documenting that Android Network Service
// Discovery uses DNS-SD over mDNS rather than a separate wire protocol.
const ProtocolAndroidNSD = ProtocolMDNS

// ProtocolsAndroidNSD enables Android NSD/DNS-SD traffic.
const ProtocolsAndroidNSD = ProtocolsMDNS

// DecodeAndroidNSD decodes an Android NSD packet using the mDNS/DNS-SD wire
// decoder. The packet must be a response; discovery questions are ignored.
func DecodeAndroidNSD(packet []byte, dst *MDNSMessage) DecodeStatus {
	return DecodeMDNS(packet, dst)
}

type ServiceProfile uint8

const (
	ServiceProfileDNSService ServiceProfile = iota + 1
	ServiceProfileGoogleCast
)

var googleCastServiceType = []byte("_googlecast._tcp.local")

// Profile identifies an interoperable DNS-SD service profile. Generic Android
// NSD advertisements have no Android-specific marker and remain DNSService.
func (s *Service) Profile() ServiceProfile {
	if s != nil && bytes.EqualFold(s.Type, googleCastServiceType) {
		return ServiceProfileGoogleCast
	}
	return ServiceProfileDNSService
}

// TXTValue returns one value from the DNS-SD length-prefixed TXT record. Keys
// are compared case-insensitively and the returned bytes alias Service.TXT.
func (s *Service) TXTValue(key []byte) ([]byte, bool) {
	if s == nil || len(key) == 0 {
		return nil, false
	}
	for offset := 0; offset < len(s.TXT); {
		length := int(s.TXT[offset])
		offset++
		if offset+length > len(s.TXT) {
			return nil, false
		}
		entry := s.TXT[offset : offset+length]
		offset += length
		separator := bytes.IndexByte(entry, '=')
		if separator < 0 {
			if bytes.EqualFold(entry, key) {
				return entry[len(entry):], true
			}
			continue
		}
		if bytes.EqualFold(entry[:separator], key) {
			return entry[separator+1:], true
		}
	}
	return nil, false
}
