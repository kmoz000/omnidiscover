# Protocol references

These files are local reference copies downloaded from authoritative publishers
on 2026-08-19. They are documentation inputs, not Go dependencies.

| Protocol | Governing specification | Local copy | Upstream source |
| --- | --- | --- | --- |
| LLDP | IEEE 802.1AB | [`ieee-802.1ab-lldp.html`](ieee-802.1ab-lldp.html) | [IEEE Standards Association](https://standards.ieee.org/ieee/802.1AB/11787/) |
| CDP | Cisco proprietary protocol; no RFC exists | [`cisco-cdp-configuration-guide.pdf`](cisco-cdp-configuration-guide.pdf) | [Cisco Discovery Protocol Configuration Guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/cdp/configuration/xe-16/cdp-xe-16-book.pdf) |
| MNDP | MikroTik proprietary protocol; no RFC exists | [`mikrotik-neighbor-discovery.html`](mikrotik-neighbor-discovery.html) | [MikroTik Neighbor discovery](https://help.mikrotik.com/docs/spaces/ROS/pages/24805517/Neighbor%2Bdiscovery) |
| mDNS | RFC 6762 | [`rfc6762-mdns.txt`](rfc6762-mdns.txt) | [RFC Editor](https://www.rfc-editor.org/rfc/rfc6762.html) |
| DNS-SD | RFC 6763 | [`rfc6763-dns-sd.txt`](rfc6763-dns-sd.txt) | [RFC Editor](https://www.rfc-editor.org/rfc/rfc6763.html) |
| DNS wire format | RFC 1035 | [`rfc1035-dns.txt`](rfc1035-dns.txt) | [RFC Editor](https://www.rfc-editor.org/rfc/rfc1035.html) |
| Android NSD API | DNS-SD over mDNS | [`android-network-service-discovery.html`](android-network-service-discovery.html) | [Android Developers](https://developer.android.com/develop/connectivity/wifi/use-nsd) |

MAC vendor resolution uses the official IEEE MA-L, MA-M, and MA-S public
listings. Update and lookup details are documented in
[`ieee-mac-registry.md`](ieee-mac-registry.md).

Android's NSD API maps to the existing DNS-SD/mDNS standards; see
[`android-nsd.md`](android-nsd.md). Wi-Fi Aware/NAN is active radio discovery
and is not an IP protocol that this passive library can capture.

The IEEE file is the public standards landing page, not the copyrighted full
standard. The Cisco and MikroTik files are vendor documentation. Do not describe
LLDP, CDP, or MNDP as IETF RFC protocols.

`SHA256SUMS` records the exact downloaded artifacts so unintended documentation
changes can be detected in CI or during review.
