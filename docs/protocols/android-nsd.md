# Android discovery mapping

Android does not define a separate IP packet format for local Network Service
Discovery (NSD). `NsdManager.PROTOCOL_DNS_SD` uses DNS-Based Service Discovery,
which omnidiscover receives through its passive mDNS/DNS-SD implementation.

- [Android Network Service Discovery](https://developer.android.com/develop/connectivity/wifi/use-nsd)
- [RFC 6762: Multicast DNS](rfc6762-mdns.txt)
- [RFC 6763: DNS-Based Service Discovery](rfc6763-dns-sd.txt)

The public Go aliases `ProtocolAndroidNSD`, `ProtocolsAndroidNSD`, and
`DecodeAndroidNSD` make this mapping explicit. Generic DNS-SD records cannot
prove that a device runs Android, so omnidiscover does not infer an operating
system from them. Google Cast advertisements are identified by the documented
`_googlecast._tcp.local` service profile, without implying that every Cast
receiver is Android.

Android Wi-Fi Aware, also called Neighbor Awareness Networking (NAN), is a
different active, hardware-managed publish/subscribe system. It is not visible
as ordinary Ethernet or UDP traffic and is outside a passive raw-socket library.
Supporting it would require an Android application and platform permissions,
not another Go packet decoder.
