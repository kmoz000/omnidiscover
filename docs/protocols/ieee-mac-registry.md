# IEEE MAC assignment registry

MAC vendor names are generated from the IEEE Registration Authority public
listings rather than inferred from protocol names or hostnames:

- [MA-L assignments](https://standards-oui.ieee.org/oui/oui.csv), 24-bit prefix
- [MA-M assignments](https://standards-oui.ieee.org/oui28/mam.csv), 28-bit prefix
- [MA-S assignments](https://standards-oui.ieee.org/oui36/oui36.csv), 36-bit prefix

The checked-in `vendor_registry_gen.go` records the SHA-256 digest of each CSV
used to generate it. Runtime lookup checks MA-S, then MA-M, then MA-L, giving
the most specific public assignment. Locally administered addresses are
reported as private/randomized and are never attributed to an IEEE assignee.

To update the generated registry after downloading all three official CSVs:

```bash
go run ./utils/genoui \
  -mal /path/to/oui.csv \
  -mam /path/to/mam.csv \
  -mas /path/to/oui36.csv \
  -out pkg/omnidiscover/vendor_registry_gen.go
```
