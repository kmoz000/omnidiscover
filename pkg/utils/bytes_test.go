package utils

import "testing"

func TestCopyBytesReusesCapacity(t *testing.T) {
	dst := make([]byte, 0, 16)
	dst = CopyBytes(dst, []byte("neighbor"))
	if string(dst) != "neighbor" || cap(dst) != 16 {
		t.Fatalf("dst=%q cap=%d", dst, cap(dst))
	}
	if allocs := testing.AllocsPerRun(1000, func() { dst = CopyBytes(dst, []byte("neighbor")) }); allocs != 0 {
		t.Fatalf("warm allocations=%v", allocs)
	}
}

func TestCleanText(t *testing.T) {
	if got := string(CleanText([]byte(" \tdevice\x00\n"))); got != "device" {
		t.Fatalf("got=%q", got)
	}
}
