// Package utils contains allocation-conscious helpers shared by the library
// and command-line tools.
package utils

// CopyBytes copies src into caller-reusable storage.
func CopyBytes(dst, src []byte) []byte {
	if cap(dst) < len(src) {
		dst = make([]byte, len(src))
	} else {
		dst = dst[:len(src)]
	}
	copy(dst, src)
	return dst
}

// CleanText trims surrounding ASCII whitespace and NUL bytes without
// allocating. The returned slice aliases src.
func CleanText(src []byte) []byte {
	start, end := 0, len(src)
	for start < end && isTrimByte(src[start]) {
		start++
	}
	for end > start && isTrimByte(src[end-1]) {
		end--
	}
	return src[start:end]
}

func isTrimByte(value byte) bool {
	return value == 0 || value == ' ' || value == '\t' || value == '\r' || value == '\n'
}
