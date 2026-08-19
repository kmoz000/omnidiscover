package omnidiscover

import (
	"net/netip"
	"time"
)

// MAC is a fixed-size Ethernet address suitable for use as a map key.
type MAC [6]byte

func (m MAC) IsZero() bool      { return m == MAC{} }
func (m MAC) IsMulticast() bool { return m[0]&1 != 0 }
func (m MAC) IsUnicast() bool   { return !m.IsZero() && !m.IsMulticast() }

// Identifier preserves a protocol identifier subtype and its owned bytes.
type Identifier struct {
	Subtype uint8
	Value   []byte
}

// TextValue is one normalized text value and its provenance.
type TextValue struct {
	Value      []byte
	Protocols  ProtocolSet
	Confidence uint8
	FirstSeen  time.Time
	LastSeen   time.Time
}

// TextField retains a canonical value and bounded alternatives.
type TextField struct {
	Values    []TextValue
	Canonical uint8
}

func (f *TextField) Current() []byte {
	if len(f.Values) == 0 || int(f.Canonical) >= len(f.Values) {
		return nil
	}
	return f.Values[f.Canonical].Value
}

// ManagementAddress is a management address advertised by LLDP or CDP.
type ManagementAddress struct {
	Subtype          uint8
	Address          []byte
	InterfaceSubtype uint8
	InterfaceNumber  uint32
	OID              []byte
}

type VLAN struct {
	ID   uint16
	Name []byte
}

type LinkAggregation struct {
	Present   bool
	Supported bool
	Enabled   bool
	ID        uint32
}

type MACPHY struct {
	Present                bool
	AutonegSupported       bool
	AutonegEnabled         bool
	AdvertisedCapabilities uint16
	OperationalMAUType     uint16
}

// LLDPDetails contains fields that do not belong in every protocol model.
type LLDPDetails struct {
	PortDescription     []byte
	SystemDescription   []byte
	SystemCapabilities  uint16
	EnabledCapabilities uint16
	PVID                uint16
	HasPVID             bool
	VLANs               []VLAN
	LinkAggregation     LinkAggregation
	MACPHY              MACPHY
	MaximumFrameSize    uint16
	HasMaximumFrameSize bool
}

// CDPDetails contains Cisco Discovery Protocol fields.
type CDPDetails struct {
	Version           uint8
	Checksum          uint16
	NativeVLAN        uint16
	HasNativeVLAN     bool
	Duplex            uint8
	HasDuplex         bool
	Capabilities      uint32
	SoftwareVersion   []byte
	Platform          []byte
	ManagementAddress []netip.Addr
}

// MNDPDetails contains MikroTik Neighbor Discovery fields.
type MNDPDetails struct {
	TypeTag       uint16
	Sequence      uint16
	Identity      []byte
	Version       []byte
	Platform      []byte
	SoftwareID    []byte
	Board         []byte
	InterfaceName []byte
	UptimeSeconds uint32
	HasUptime     bool
}

type DNSRecordType uint16

const (
	DNSRecordA    DNSRecordType = 1
	DNSRecordPTR  DNSRecordType = 12
	DNSRecordTXT  DNSRecordType = 16
	DNSRecordAAAA DNSRecordType = 28
	DNSRecordSRV  DNSRecordType = 33
)

// DNSRecord is a bounded, owned representation of an mDNS resource record.
type DNSRecord struct {
	Name       []byte
	Type       DNSRecordType
	Class      uint16
	CacheFlush bool
	TTL        uint32
	Target     []byte
	Address    netip.Addr
	Port       uint16
	Priority   uint16
	Weight     uint16
	TXT        []byte
}

// Service is a correlated DNS-SD service.
type Service struct {
	Instance  []byte
	Type      []byte
	Domain    []byte
	Host      []byte
	Port      uint16
	TXT       []byte
	Addresses []netip.Addr
	Protocols ProtocolSet
	ExpiresAt time.Time
}

type DeviceKeyKind uint8

const (
	DeviceKeyUnknown DeviceKeyKind = iota
	DeviceKeyMAC
	DeviceKeyIP
)

// DeviceKey is stable for the lifetime of an Engine.
type DeviceKey struct {
	Kind           DeviceKeyKind
	MAC            MAC
	IP             netip.Addr
	InterfaceIndex int
}

// DeviceUptime is a protocol-reported uptime baseline. Current extrapolates
// the value between observations without mutating engine state.
type DeviceUptime struct {
	Seconds    uint64
	ObservedAt time.Time
	Protocols  ProtocolSet
	Valid      bool
}

func (u DeviceUptime) Current(now time.Time) time.Duration {
	seconds := u.Seconds
	if u.Valid && now.After(u.ObservedAt) {
		seconds += uint64(now.Sub(u.ObservedAt) / time.Second)
	}
	const maxDurationSeconds = uint64((1<<63 - 1) / int64(time.Second))
	if seconds > maxDurationSeconds {
		seconds = maxDurationSeconds
	}
	return time.Duration(seconds) * time.Second
}

// DiscoveredDevice is the fused device model shared by every protocol.
type DiscoveredDevice struct {
	Key              DeviceKey
	ObservedMACs     []MAC
	ClaimedMACs      []MAC
	Addresses        []netip.Addr
	SystemName       TextField
	HostName         TextField
	ProtocolDeviceID TextField
	Vendor           TextField
	Model            TextField
	Platform         TextField
	SoftwareVersion  TextField
	Uptime           DeviceUptime
	Capabilities     uint64
	Services         []Service
	Protocols        ProtocolSet
	Class            []byte
	MatchedRule      []byte
	FirstSeen        time.Time
	LastSeen         time.Time
}

type LinkKind uint8

const (
	PhysicalAdjacency LinkKind = iota + 1
	SegmentPresence
)

type LinkKey struct {
	InterfaceIndex int
	SourceMAC      MAC
	Device         DeviceKey
}

// DiscoveredLink describes either a physical adjacency or segment presence.
type DiscoveredLink struct {
	Key               LinkKey
	Kind              LinkKind
	LocalInterface    []byte
	Device            DeviceKey
	ObservedSourceMAC MAC
	RemoteChassis     Identifier
	RemotePort        Identifier
	RemoteInterface   TextField
	VLANs             []uint16
	Protocols         ProtocolSet
	TTL               time.Duration
	ExpiresAt         time.Time
	FirstSeen         time.Time
	LastSeen          time.Time
}

type EventKind uint8

const (
	EventAdded EventKind = iota + 1
	EventChanged
	EventExpired
	EventEvicted
)

// FieldSet marks changed fused fields.
type FieldSet uint64

const (
	FieldIdentity FieldSet = 1 << iota
	FieldAddresses
	FieldNames
	FieldModel
	FieldPlatform
	FieldSoftware
	FieldCapabilities
	FieldServices
	FieldLink
	FieldClassification
	FieldVendor
	FieldUptime
)

// EventView borrows Engine-owned storage and is valid only during Handler.
type EventView struct {
	Kind    EventKind
	Changed FieldSet
	Device  *DiscoveredDevice
	Link    *DiscoveredLink
}

// Event is an owned event returned by Stream.
type Event struct {
	Kind    EventKind
	Changed FieldSet
	Device  DiscoveredDevice
	Link    DiscoveredLink
}

type Handler func(EventView)

type Snapshot struct {
	Devices []DiscoveredDevice
	Links   []DiscoveredLink
}

// Reset releases logical contents while retaining reusable capacity.
func (d *DiscoveredDevice) Reset() {
	d.Key = DeviceKey{}
	d.ObservedMACs = d.ObservedMACs[:0]
	d.ClaimedMACs = d.ClaimedMACs[:0]
	d.Addresses = d.Addresses[:0]
	resetTextField(&d.SystemName)
	resetTextField(&d.HostName)
	resetTextField(&d.ProtocolDeviceID)
	resetTextField(&d.Vendor)
	resetTextField(&d.Model)
	resetTextField(&d.Platform)
	resetTextField(&d.SoftwareVersion)
	d.Uptime = DeviceUptime{}
	for i := range d.Services {
		d.Services[i].Instance = d.Services[i].Instance[:0]
		d.Services[i].Type = d.Services[i].Type[:0]
		d.Services[i].Domain = d.Services[i].Domain[:0]
		d.Services[i].Host = d.Services[i].Host[:0]
		d.Services[i].TXT = d.Services[i].TXT[:0]
		d.Services[i].Addresses = d.Services[i].Addresses[:0]
	}
	d.Services = d.Services[:0]
	d.Protocols = 0
	d.Class = d.Class[:0]
	d.MatchedRule = d.MatchedRule[:0]
	d.Capabilities = 0
	d.FirstSeen = time.Time{}
	d.LastSeen = time.Time{}
}

func resetTextField(f *TextField) {
	for i := range f.Values {
		f.Values[i].Value = f.Values[i].Value[:0]
	}
	f.Values = f.Values[:0]
	f.Canonical = 0
}
