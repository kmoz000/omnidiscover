# Benchmarks

Reference run on 2026-08-19 using `CGO_ENABLED=0`, Darwin/arm64, Apple M1,
Go's three-second benchmark window:

```bash
CGO_ENABLED=0 go test ./pkg/omnidiscover \
  -run '^$' \
  -bench . \
  -benchmem \
  -benchtime=3s \
  -count=1
```

| Benchmark | Time | Heap bytes | Allocations |
| --- | ---: | ---: | ---: |
| Decode LLDP | 65.55 ns/op | 0 B/op | 0 allocs/op |
| Decode CDP | 55.16 ns/op | 0 B/op | 0 allocs/op |
| Decode MNDP | 22.50 ns/op | 0 B/op | 0 allocs/op |
| Decode mDNS | 222.8 ns/op | 0 B/op | 0 allocs/op |
| Route Ethernet frame | 87.87 ns/op | 0 B/op | 0 allocs/op |
| Classifier with regex candidates pruned | 14.73 ns/op | 0 B/op | 0 allocs/op |
| Identical MNDP refresh fusion | 174.4 ns/op | 0 B/op | 0 allocs/op |
| Identical mDNS refresh fusion | 225.5 ns/op | 0 B/op | 0 allocs/op |
| IEEE MA-S/MA-M/MA-L vendor lookup | 10.10 ns/op | 0 B/op | 0 allocs/op |

The mDNS refresh path previously kept two 256-entry scratch arrays in every
observation frame. It now finds the first fallback identity address with one
slot and detects duplicate cache-flush RRSets by scanning only preceding packet
records. Dual DNS cache hashes are also calculated in one pass, and exact RR
refreshes update only TTL/cache-flush metadata. The result is bounded stack use
and a roughly threefold improvement over the intermediate 770–1100 ns/op
refresh implementation while retaining zero allocations.

The IEEE lookup uses a 4096-bucket first-level index and searches only the
selected bucket, with longest-prefix order MA-S (36), MA-M (28), then MA-L
(24). Registry arrays and deduplicated vendor names remain immutable read-only
data rather than heap maps.
