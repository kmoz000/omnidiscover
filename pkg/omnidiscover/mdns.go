package omnidiscover

import (
	"encoding/binary"
	"net/netip"
)

const (
	MDNSPort                = 5353
	maxDNSLabels            = 32
	maxDNSRecordsPerMessage = 256
	maxDNSNameSize          = 255
)

type MDNSMessage struct {
	ID      uint16
	Flags   uint16
	Records []DNSRecord
}

func (m *MDNSMessage) Reset() {
	m.ID = 0
	m.Flags = 0
	for i := range m.Records {
		m.Records[i].Name = m.Records[i].Name[:0]
		m.Records[i].Target = m.Records[i].Target[:0]
		m.Records[i].TXT = m.Records[i].TXT[:0]
	}
	m.Records = m.Records[:0]
}

// DecodeMDNS decodes passive mDNS responses. Queries are rejected and never answered.
func DecodeMDNS(packet []byte, dst *MDNSMessage) DecodeStatus {
	var st DecodeStatus
	if dst == nil {
		addIssue(&st, DecodeFatal, IssueNilDestination, 0, 0)
		return st
	}
	dst.Reset()
	if len(packet) < 12 {
		addIssue(&st, DecodeFatal, IssueTooShort, len(packet), 0)
		return st
	}
	dst.ID = binary.BigEndian.Uint16(packet[:2])
	dst.Flags = binary.BigEndian.Uint16(packet[2:4])
	if dst.Flags&0x8000 == 0 {
		addIssue(&st, DecodeIgnored, IssueNotResponse, 2, dst.Flags)
		return st
	}
	qd := int(binary.BigEndian.Uint16(packet[4:6]))
	an := int(binary.BigEndian.Uint16(packet[6:8]))
	ns := int(binary.BigEndian.Uint16(packet[8:10]))
	ar := int(binary.BigEndian.Uint16(packet[10:12]))
	totalRecords := an + ns + ar
	if qd > maxDNSRecordsPerMessage || totalRecords > maxDNSRecordsPerMessage {
		addIssue(&st, DecodeFatal, IssueTooLarge, 4, uint16(totalRecords))
		return st
	}
	off := 12
	var scratch [maxDNSNameSize]byte
	for i := 0; i < qd; i++ {
		_, next, issue := decodeDNSName(packet, off, scratch[:0])
		if issue != IssueNone {
			addIssue(&st, DecodeFatal, issue, off, 0)
			return st
		}
		if next+4 > len(packet) {
			addIssue(&st, DecodeFatal, IssueTooShort, next, 0)
			return st
		}
		off = next + 4
	}
	for i := 0; i < totalRecords; i++ {
		name, next, issue := decodeDNSName(packet, off, scratch[:0])
		if issue != IssueNone {
			addIssue(&st, DecodeFatal, issue, off, 0)
			return st
		}
		if next+10 > len(packet) {
			addIssue(&st, DecodeFatal, IssueTooShort, next, 0)
			return st
		}
		typ := DNSRecordType(binary.BigEndian.Uint16(packet[next : next+2]))
		class := binary.BigEndian.Uint16(packet[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(packet[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
		rdata := next + 10
		end := rdata + rdlen
		if end > len(packet) {
			addIssue(&st, DecodeFatal, IssueTruncatedTLV, rdata, uint16(typ))
			return st
		}
		off = end
		if typ != DNSRecordA && typ != DNSRecordAAAA && typ != DNSRecordPTR && typ != DNSRecordSRV && typ != DNSRecordTXT {
			continue
		}
		ri := len(dst.Records)
		if ri < cap(dst.Records) {
			dst.Records = dst.Records[:ri+1]
		} else {
			dst.Records = append(dst.Records, DNSRecord{})
		}
		r := &dst.Records[ri]
		r.Name = copyBytes(r.Name, lowerDNSName(name))
		r.Type = typ
		r.Class = class & 0x7fff
		r.CacheFlush = class&0x8000 != 0
		r.TTL = ttl
		r.Target = r.Target[:0]
		r.TXT = r.TXT[:0]
		r.Address = netip.Addr{}
		r.Port = 0
		r.Priority = 0
		r.Weight = 0
		valid := true
		switch typ {
		case DNSRecordA:
			valid = rdlen == 4
			if valid {
				r.Address = netip.AddrFrom4([4]byte{packet[rdata], packet[rdata+1], packet[rdata+2], packet[rdata+3]})
			}
		case DNSRecordAAAA:
			valid = rdlen == 16
			if valid {
				var a [16]byte
				copy(a[:], packet[rdata:end])
				r.Address = netip.AddrFrom16(a)
			}
		case DNSRecordPTR:
			var target []byte
			var targetNext int
			target, targetNext, issue = decodeDNSName(packet, rdata, scratch[:0])
			valid = issue == IssueNone && targetNext == end
			if valid {
				r.Target = copyBytes(r.Target, lowerDNSName(target))
			}
		case DNSRecordSRV:
			valid = rdlen >= 7
			if valid {
				r.Priority = binary.BigEndian.Uint16(packet[rdata : rdata+2])
				r.Weight = binary.BigEndian.Uint16(packet[rdata+2 : rdata+4])
				r.Port = binary.BigEndian.Uint16(packet[rdata+4 : rdata+6])
				var target []byte
				var targetNext int
				target, targetNext, issue = decodeDNSName(packet, rdata+6, scratch[:0])
				valid = issue == IssueNone && targetNext == end
				if valid {
					r.Target = copyBytes(r.Target, lowerDNSName(target))
				}
			}
		case DNSRecordTXT:
			valid = validateTXT(packet[rdata:end])
			if valid {
				r.TXT = copyBytes(r.TXT, packet[rdata:end])
			}
		}
		if !valid {
			dst.Records = dst.Records[:ri]
			addIssue(&st, DecodePartial, IssueInvalidTLVLength, rdata, uint16(typ))
		}
	}
	return st
}

func decodeDNSName(packet []byte, off int, dst []byte) ([]byte, int, DecodeIssue) {
	start := off
	next := -1
	labels, jumps := 0, 0
	for {
		if off >= len(packet) {
			return dst[:0], start, IssueTooShort
		}
		length := int(packet[off])
		switch {
		case length == 0:
			if next < 0 {
				next = off + 1
			}
			return dst, next, IssueNone
		case length&0xc0 == 0xc0:
			if off+1 >= len(packet) {
				return dst[:0], start, IssueTooShort
			}
			if next < 0 {
				next = off + 2
			}
			off = int(binary.BigEndian.Uint16(packet[off:off+2]) & 0x3fff)
			jumps++
			if jumps > maxDNSLabels {
				return dst[:0], start, IssueCompressionLoop
			}
		case length&0xc0 != 0 || length > 63:
			return dst[:0], start, IssueInvalidHeader
		default:
			if off+1+length > len(packet) {
				return dst[:0], start, IssueTooShort
			}
			labels++
			if labels > maxDNSLabels {
				return dst[:0], start, IssueTooManyLabels
			}
			if len(dst) != 0 {
				if len(dst)+1 > maxDNSNameSize {
					return dst[:0], start, IssueTooLarge
				}
				dst = append(dst, '.')
			}
			if len(dst)+length > maxDNSNameSize {
				return dst[:0], start, IssueTooLarge
			}
			dst = append(dst, packet[off+1:off+1+length]...)
			off += 1 + length
		}
	}
}

func lowerDNSName(b []byte) []byte {
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return b
}

func validateTXT(b []byte) bool {
	for off := 0; off < len(b); {
		n := int(b[off])
		off++
		if off+n > len(b) {
			return false
		}
		off += n
	}
	return true
}
