package omnidiscover

// MACVendorSource describes how a MAC vendor result was determined.
type MACVendorSource uint8

const (
	MACVendorUnknown MACVendorSource = iota
	MACVendorIEEEMAL
	MACVendorIEEEMAM
	MACVendorIEEEMAS
	MACVendorLocallyAdministered
	MACVendorMulticast
)

// MACVendorResult is a borrowed, allocation-free IEEE assignment result.
// Name points into immutable package data and remains valid permanently.
type MACVendorResult struct {
	Name       string
	PrefixBits uint8
	Source     MACVendorSource
}

// LookupMACVendor performs longest-prefix matching against the IEEE MA-S
// (36-bit), MA-M (28-bit), and MA-L (24-bit) public registries. Locally
// administered and multicast addresses are identified before registry lookup.
func LookupMACVendor(mac MAC) MACVendorResult {
	if mac.IsZero() {
		return MACVendorResult{}
	}
	if mac.IsMulticast() {
		return MACVendorResult{Source: MACVendorMulticast}
	}
	if mac[0]&0x02 != 0 {
		return MACVendorResult{Source: MACVendorLocallyAdministered}
	}
	prefix36 := uint64(mac[0])<<28 | uint64(mac[1])<<20 | uint64(mac[2])<<12 | uint64(mac[3])<<4 | uint64(mac[4])>>4
	bucket := int(prefix36 >> 24)
	if i := searchUint64(vendor36Prefixes[:], prefix36, int(vendor36Buckets[bucket]), int(vendor36Buckets[bucket+1])); i >= 0 {
		return vendorResult(vendor36NameRefs[i], 36, MACVendorIEEEMAS)
	}
	prefix28 := uint32(mac[0])<<20 | uint32(mac[1])<<12 | uint32(mac[2])<<4 | uint32(mac[3])>>4
	bucket = int(prefix28 >> 16)
	if i := searchUint32(vendor28Prefixes[:], prefix28, int(vendor28Buckets[bucket]), int(vendor28Buckets[bucket+1])); i >= 0 {
		return vendorResult(vendor28NameRefs[i], 28, MACVendorIEEEMAM)
	}
	prefix24 := uint32(mac[0])<<16 | uint32(mac[1])<<8 | uint32(mac[2])
	bucket = int(prefix24 >> 12)
	if i := searchUint32(vendor24Prefixes[:], prefix24, int(vendor24Buckets[bucket]), int(vendor24Buckets[bucket+1])); i >= 0 {
		return vendorResult(vendor24NameRefs[i], 24, MACVendorIEEEMAL)
	}
	return MACVendorResult{}
}

func vendorResult(ref uint32, bits uint8, source MACVendorSource) MACVendorResult {
	offset, length := int(ref>>8), int(ref&0xff)
	if offset < 0 || length == 0 || offset+length > len(vendorNameData) {
		return MACVendorResult{}
	}
	return MACVendorResult{Name: vendorNameData[offset : offset+length], PrefixBits: bits, Source: source}
}

func searchUint32(values []uint32, target uint32, lo, hi int) int {
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if values[mid] < target {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(values) && values[lo] == target {
		return lo
	}
	return -1
}

func searchUint64(values []uint64, target uint64, lo, hi int) int {
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if values[mid] < target {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(values) && values[lo] == target {
		return lo
	}
	return -1
}
