package omnidiscover

import (
	"bytes"
	"math/bits"
	"net/netip"
	"time"
)

type deviceEntry struct {
	used       bool
	generation uint32
	device     DiscoveredDevice
	links      []int
	dns        []int
}

type linkEntry struct {
	used       bool
	link       DiscoveredLink
	device     int
	expires    [5]time.Time
	wheelSlot  int
	wheelRound int
	wheelPrev  int
	wheelNext  int
}

type dnsKey struct {
	device int
	h1     uint64
	h2     uint64
	typ    DNSRecordType
}

type dnsEntry struct {
	used       bool
	key        dnsKey
	record     DNSRecord
	device     int
	expiresAt  time.Time
	wheelSlot  int
	wheelRound int
	wheelPrev  int
	wheelNext  int
}

type fusionState struct {
	cfg             Config
	classifier      *Classifier
	devices         []deviceEntry
	deviceByKey     map[DeviceKey]int
	freeDevices     []int
	links           []linkEntry
	linkByKey       map[LinkKey]int
	freeLinks       []int
	dns             []dnsEntry
	dnsByKey        map[dnsKey]int
	freeDNS         []int
	linkHeads       []int
	dnsHeads        []int
	expiredDNS      []int
	wheelCursor     int
	tombstones      []Event
	deviceEvictions uint64
	linkEvictions   uint64
	dnsEvictions    uint64
}

func newFusionState(cfg Config, classifier *Classifier) *fusionState {
	s := &fusionState{
		cfg: cfg, classifier: classifier,
		devices:     make([]deviceEntry, cfg.MaxDevices),
		deviceByKey: make(map[DeviceKey]int, cfg.MaxDevices),
		links:       make([]linkEntry, cfg.MaxLinks),
		linkByKey:   make(map[LinkKey]int, cfg.MaxLinks),
		dns:         make([]dnsEntry, cfg.MaxDNSRecords),
		dnsByKey:    make(map[dnsKey]int, cfg.MaxDNSRecords),
		linkHeads:   make([]int, cfg.TimingWheelSlots),
		dnsHeads:    make([]int, cfg.TimingWheelSlots),
		expiredDNS:  make([]int, 0, min(cfg.MaxDevices, cfg.MaxDNSRecords)),
	}
	for i := range s.linkHeads {
		s.linkHeads[i] = -1
		s.dnsHeads[i] = -1
	}
	for i := cfg.MaxDevices - 1; i >= 0; i-- {
		s.freeDevices = append(s.freeDevices, i)
	}
	for i := cfg.MaxLinks - 1; i >= 0; i-- {
		s.freeLinks = append(s.freeLinks, i)
		s.links[i].wheelSlot = -1
	}
	for i := cfg.MaxDNSRecords - 1; i >= 0; i-- {
		s.freeDNS = append(s.freeDNS, i)
		s.dns[i].wheelSlot = -1
	}
	return s
}

func (s *fusionState) resetTombstones() {
	for i := range s.tombstones {
		s.tombstones[i].Device.Reset()
		resetLink(&s.tombstones[i].Link)
	}
	s.tombstones = s.tombstones[:0]
}

func (s *fusionState) tombstone(kind EventKind, changed FieldSet, d *DiscoveredDevice, l *DiscoveredLink) EventView {
	i := len(s.tombstones)
	if i < cap(s.tombstones) {
		s.tombstones = s.tombstones[:i+1]
	} else {
		s.tombstones = append(s.tombstones, Event{})
	}
	e := &s.tombstones[i]
	e.Kind, e.Changed = kind, changed
	cloneDeviceInto(&e.Device, d)
	cloneLinkInto(&e.Link, l)
	return EventView{Kind: kind, Changed: changed, Device: &e.Device, Link: &e.Link}
}

type observationMeta struct {
	protocol       Protocol
	interfaceName  string
	interfaceIndex int
	timestamp      time.Time
	sourceMAC      MAC
	sourceIP       netip.Addr
	vlans          [maxVLANTags]uint16
	vlanCount      uint8
}

func (s *fusionState) deviceFor(meta observationMeta, claimed MAC, addresses []netip.Addr, events []EventView) (int, []EventView) {
	key := DeviceKey{Kind: DeviceKeyUnknown, InterfaceIndex: meta.interfaceIndex}
	mac := meta.sourceMAC
	if !mac.IsUnicast() && claimed.IsUnicast() {
		mac = claimed
	}
	if mac.IsUnicast() {
		key = DeviceKey{Kind: DeviceKeyMAC, MAC: mac}
	} else if meta.sourceIP.IsValid() {
		key.Kind, key.IP = DeviceKeyIP, meta.sourceIP.Unmap()
	} else {
		for _, a := range addresses {
			if a.IsValid() {
				key.Kind, key.IP = DeviceKeyIP, a.Unmap()
				break
			}
		}
	}
	if key.Kind == DeviceKeyUnknown {
		return -1, events
	}
	if key.Kind == DeviceKeyMAC && meta.sourceIP.IsValid() {
		ipKey := DeviceKey{Kind: DeviceKeyIP, IP: meta.sourceIP.Unmap(), InterfaceIndex: meta.interfaceIndex}
		if ipIdx, ok := s.deviceByKey[ipKey]; ok {
			if macIdx, exists := s.deviceByKey[key]; exists && macIdx != ipIdx {
				events = s.mergeDevices(macIdx, ipIdx, events)
				return macIdx, events
			}
			s.promoteDevice(ipIdx, key)
			return ipIdx, events
		}
	}
	if idx, ok := s.deviceByKey[key]; ok {
		return idx, events
	}
	idx, events := s.allocDevice(events)
	if idx < 0 {
		return -1, events
	}
	d := &s.devices[idx]
	d.used = true
	d.generation++
	d.device.Reset()
	d.device.Key = key
	d.device.FirstSeen = meta.timestamp
	d.device.LastSeen = meta.timestamp
	s.deviceByKey[key] = idx
	return idx, events
}

func (s *fusionState) allocDevice(events []EventView) (int, []EventView) {
	if n := len(s.freeDevices); n > 0 {
		idx := s.freeDevices[n-1]
		s.freeDevices = s.freeDevices[:n-1]
		return idx, events
	}
	oldest := -1
	for i := range s.devices {
		if s.devices[i].used && (oldest < 0 || s.devices[i].device.LastSeen.Before(s.devices[oldest].device.LastSeen)) {
			oldest = i
		}
	}
	if oldest < 0 {
		return -1, events
	}
	s.deviceEvictions++
	events = s.removeDevice(oldest, EventEvicted, events)
	n := len(s.freeDevices)
	if n == 0 {
		return -1, events
	}
	idx := s.freeDevices[n-1]
	s.freeDevices = s.freeDevices[:n-1]
	return idx, events
}

func (s *fusionState) promoteDevice(idx int, key DeviceKey) {
	d := &s.devices[idx]
	old := d.device.Key
	delete(s.deviceByKey, old)
	d.device.Key = key
	s.deviceByKey[key] = idx
	for _, li := range d.links {
		if li < 0 || li >= len(s.links) || !s.links[li].used {
			continue
		}
		l := &s.links[li]
		delete(s.linkByKey, l.link.Key)
		l.link.Device = key
		l.link.Key.Device = key
		s.linkByKey[l.link.Key] = li
	}
	for _, di := range d.dns {
		if di < 0 || di >= len(s.dns) || !s.dns[di].used {
			continue
		}
		de := &s.dns[di]
		delete(s.dnsByKey, de.key)
		de.key.device = idx
		s.dnsByKey[de.key] = di
	}
}

func (s *fusionState) mergeDevices(dstIdx, srcIdx int, events []EventView) []EventView {
	if dstIdx == srcIdx || !s.devices[dstIdx].used || !s.devices[srcIdx].used {
		return events
	}
	dst, src := &s.devices[dstIdx], &s.devices[srcIdx]
	now := src.device.LastSeen
	for _, m := range src.device.ObservedMACs {
		dst.device.ObservedMACs = appendUniqueMAC(dst.device.ObservedMACs, m)
	}
	for _, m := range src.device.ClaimedMACs {
		dst.device.ClaimedMACs = appendUniqueMAC(dst.device.ClaimedMACs, m)
	}
	for _, a := range src.device.Addresses {
		dst.device.Addresses = appendUniqueAddr(dst.device.Addresses, a)
	}
	mergeTextField(&dst.device.SystemName, &src.device.SystemName, s.cfg.MaxAlternatives)
	mergeTextField(&dst.device.HostName, &src.device.HostName, s.cfg.MaxAlternatives)
	mergeTextField(&dst.device.ProtocolDeviceID, &src.device.ProtocolDeviceID, s.cfg.MaxAlternatives)
	mergeTextField(&dst.device.Model, &src.device.Model, s.cfg.MaxAlternatives)
	mergeTextField(&dst.device.Platform, &src.device.Platform, s.cfg.MaxAlternatives)
	mergeTextField(&dst.device.SoftwareVersion, &src.device.SoftwareVersion, s.cfg.MaxAlternatives)
	dst.device.Protocols |= src.device.Protocols
	dst.device.Capabilities |= src.device.Capabilities
	if dst.device.FirstSeen.IsZero() || src.device.FirstSeen.Before(dst.device.FirstSeen) {
		dst.device.FirstSeen = src.device.FirstSeen
	}
	if now.After(dst.device.LastSeen) {
		dst.device.LastSeen = now
	}
	for len(src.links) != 0 {
		li := src.links[len(src.links)-1]
		src.links = src.links[:len(src.links)-1]
		if li < 0 || li >= len(s.links) || !s.links[li].used {
			continue
		}
		l := &s.links[li]
		delete(s.linkByKey, l.link.Key)
		l.device = dstIdx
		l.link.Device = dst.device.Key
		l.link.Key.Device = dst.device.Key
		if existing, ok := s.linkByKey[l.link.Key]; ok && existing != li {
			events = s.mergeLinks(existing, li, events)
		} else {
			s.linkByKey[l.link.Key] = li
			dst.links = append(dst.links, li)
		}
	}
	for len(src.dns) != 0 {
		di := src.dns[len(src.dns)-1]
		src.dns = src.dns[:len(src.dns)-1]
		if di < 0 || di >= len(s.dns) || !s.dns[di].used {
			continue
		}
		de := &s.dns[di]
		delete(s.dnsByKey, de.key)
		de.device = dstIdx
		de.key.device = dstIdx
		if existing, ok := s.dnsByKey[de.key]; ok && existing != di {
			s.removeDNS(di)
		} else {
			s.dnsByKey[de.key] = di
			dst.dns = append(dst.dns, di)
		}
	}
	delete(s.deviceByKey, src.device.Key)
	src.used = false
	src.links = src.links[:0]
	src.dns = src.dns[:0]
	src.device.Reset()
	s.freeDevices = append(s.freeDevices, srcIdx)
	s.rebuildServices(dstIdx)
	return events
}

func mergeTextField(dst, src *TextField, max int) {
	for i := range src.Values {
		v := &src.Values[i]
		mergeText(dst, v.Value, v.Protocols, v.Confidence, v.LastSeen, max)
	}
}

func mergeText(field *TextField, value []byte, protocols ProtocolSet, confidence uint8, now time.Time, maxAlternatives int) bool {
	value = cleanText(value)
	if len(value) == 0 {
		return false
	}
	for i := range field.Values {
		v := &field.Values[i]
		if bytes.Equal(v.Value, value) {
			changed := v.Protocols|protocols != v.Protocols
			v.Protocols |= protocols
			if confidence > v.Confidence {
				v.Confidence = confidence
				changed = true
			}
			if now.After(v.LastSeen) {
				v.LastSeen = now
			}
			selectCanonical(field)
			return changed
		}
	}
	maxValues := maxAlternatives + 1
	if len(field.Values) < maxValues {
		i := len(field.Values)
		if i < cap(field.Values) {
			field.Values = field.Values[:i+1]
		} else {
			field.Values = append(field.Values, TextValue{})
		}
		v := &field.Values[i]
		v.Value = copyBytes(v.Value, value)
		v.Protocols = protocols
		v.Confidence = confidence
		v.FirstSeen = now
		v.LastSeen = now
		selectCanonical(field)
		return true
	}
	// Replace the weakest non-canonical alternative; the current winner is stable.
	replace := -1
	for i := range field.Values {
		if i == int(field.Canonical) {
			continue
		}
		if replace < 0 || textRank(&field.Values[i]) < textRank(&field.Values[replace]) ||
			(textRank(&field.Values[i]) == textRank(&field.Values[replace]) && field.Values[i].LastSeen.Before(field.Values[replace].LastSeen)) {
			replace = i
		}
	}
	if replace < 0 || textRank(&TextValue{Protocols: protocols, Confidence: confidence}) < textRank(&field.Values[replace]) {
		return false
	}
	v := &field.Values[replace]
	v.Value = copyBytes(v.Value, value)
	v.Protocols = protocols
	v.Confidence = confidence
	v.FirstSeen = now
	v.LastSeen = now
	selectCanonical(field)
	return true
}

func textRank(v *TextValue) int { return int(v.Confidence)*16 + bits.OnesCount8(uint8(v.Protocols)) }

func selectCanonical(field *TextField) {
	if len(field.Values) == 0 {
		field.Canonical = 0
		return
	}
	cur := int(field.Canonical)
	if cur >= len(field.Values) {
		cur = 0
	}
	best := cur
	for i := range field.Values {
		if textRank(&field.Values[i]) > textRank(&field.Values[best]) {
			best = i
		}
	}
	field.Canonical = uint8(best)
}

func (s *fusionState) upsertLink(meta observationMeta, deviceIdx int, kind LinkKind, ttl time.Duration, events []EventView) (int, bool, bool, []EventView) {
	d := &s.devices[deviceIdx]
	key := LinkKey{InterfaceIndex: meta.interfaceIndex, SourceMAC: meta.sourceMAC, Device: d.device.Key}
	if li, ok := s.linkByKey[key]; ok && s.links[li].used {
		changed := s.refreshLink(li, meta, kind, ttl)
		return li, changed, false, events
	}
	// A physical observation promotes segment presence on the same interface.
	if kind == PhysicalAdjacency {
		for _, li := range d.links {
			if li < 0 || li >= len(s.links) || !s.links[li].used {
				continue
			}
			l := &s.links[li]
			if l.link.Key.InterfaceIndex == meta.interfaceIndex && l.link.Kind == SegmentPresence {
				delete(s.linkByKey, l.link.Key)
				l.link.Key = key
				l.link.Device = d.device.Key
				l.link.ObservedSourceMAC = meta.sourceMAC
				l.link.Kind = PhysicalAdjacency
				s.linkByKey[key] = li
				s.refreshLink(li, meta, kind, ttl)
				return li, true, false, events
			}
		}
	} else {
		// Do not create redundant segment presence when a physical adjacency exists.
		for _, li := range d.links {
			if li < 0 || li >= len(s.links) || !s.links[li].used {
				continue
			}
			l := &s.links[li]
			if l.link.Key.InterfaceIndex == meta.interfaceIndex && l.link.Kind == PhysicalAdjacency {
				changed := s.refreshLink(li, meta, kind, ttl)
				return li, changed, false, events
			}
		}
	}
	li, events := s.allocLink(events)
	if li < 0 {
		return -1, false, false, events
	}
	l := &s.links[li]
	resetLink(&l.link)
	l.used = true
	l.device = deviceIdx
	l.link.Key = key
	l.link.Kind = kind
	l.link.Device = d.device.Key
	l.link.LocalInterface = copyBytes(l.link.LocalInterface, []byte(meta.interfaceName))
	l.link.ObservedSourceMAC = meta.sourceMAC
	l.link.FirstSeen = meta.timestamp
	l.link.LastSeen = meta.timestamp
	l.wheelSlot, l.wheelPrev, l.wheelNext = -1, -1, -1
	s.linkByKey[key] = li
	d.links = append(d.links, li)
	s.refreshLink(li, meta, kind, ttl)
	return li, true, true, events
}

func (s *fusionState) refreshLink(li int, meta observationMeta, kind LinkKind, ttl time.Duration) bool {
	l := &s.links[li]
	changed := false
	if kind == PhysicalAdjacency && l.link.Kind != PhysicalAdjacency {
		l.link.Kind = kind
		changed = true
	}
	if l.link.Protocols&meta.protocol.Set() == 0 {
		l.link.Protocols |= meta.protocol.Set()
		changed = true
	}
	if meta.timestamp.After(l.link.LastSeen) {
		l.link.LastSeen = meta.timestamp
	}
	if ttl <= 0 {
		ttl = time.Second
	}
	exp := meta.timestamp.Add(ttl)
	if int(meta.protocol) < len(l.expires) {
		l.expires[meta.protocol] = exp
	}
	l.link.TTL = ttl
	l.link.ExpiresAt = earliestExpiry(l.expires)
	s.scheduleLink(li, meta.timestamp, l.link.ExpiresAt)
	for i := 0; i < int(meta.vlanCount); i++ {
		vlan := meta.vlans[i]
		found := false
		for _, existing := range l.link.VLANs {
			if existing == vlan {
				found = true
				break
			}
		}
		if !found {
			l.link.VLANs = append(l.link.VLANs, vlan)
			changed = true
		}
	}
	return changed
}

func earliestExpiry(values [5]time.Time) time.Time {
	var out time.Time
	for i := ProtocolLLDP; i <= ProtocolMDNS; i++ {
		v := values[i]
		if !v.IsZero() && (out.IsZero() || v.Before(out)) {
			out = v
		}
	}
	return out
}

func latestExpiry(values [5]time.Time) time.Time {
	var out time.Time
	for i := ProtocolLLDP; i <= ProtocolMDNS; i++ {
		if values[i].After(out) {
			out = values[i]
		}
	}
	return out
}

func (s *fusionState) allocLink(events []EventView) (int, []EventView) {
	if n := len(s.freeLinks); n > 0 {
		idx := s.freeLinks[n-1]
		s.freeLinks = s.freeLinks[:n-1]
		return idx, events
	}
	oldest := -1
	for i := range s.links {
		if s.links[i].used && (oldest < 0 || s.links[i].link.LastSeen.Before(s.links[oldest].link.LastSeen)) {
			oldest = i
		}
	}
	if oldest < 0 {
		return -1, events
	}
	s.linkEvictions++
	events = s.removeLink(oldest, EventEvicted, events)
	n := len(s.freeLinks)
	if n == 0 {
		return -1, events
	}
	idx := s.freeLinks[n-1]
	s.freeLinks = s.freeLinks[:n-1]
	return idx, events
}

func (s *fusionState) mergeLinks(dstIdx, srcIdx int, events []EventView) []EventView {
	if dstIdx == srcIdx || !s.links[dstIdx].used || !s.links[srcIdx].used {
		return events
	}
	dst, src := &s.links[dstIdx], &s.links[srcIdx]
	dst.link.Protocols |= src.link.Protocols
	if src.link.Kind == PhysicalAdjacency {
		dst.link.Kind = PhysicalAdjacency
	}
	for p := ProtocolLLDP; p <= ProtocolMDNS; p++ {
		if src.expires[p].After(dst.expires[p]) {
			dst.expires[p] = src.expires[p]
		}
	}
	if src.link.LastSeen.After(dst.link.LastSeen) {
		dst.link.LastSeen = src.link.LastSeen
	}
	if src.link.FirstSeen.Before(dst.link.FirstSeen) {
		dst.link.FirstSeen = src.link.FirstSeen
	}
	for _, v := range src.link.VLANs {
		found := false
		for _, x := range dst.link.VLANs {
			if x == v {
				found = true
				break
			}
		}
		if !found {
			dst.link.VLANs = append(dst.link.VLANs, v)
		}
	}
	dst.link.ExpiresAt = earliestExpiry(dst.expires)
	s.scheduleLink(dstIdx, dst.link.LastSeen, dst.link.ExpiresAt)
	return s.removeLink(srcIdx, EventChanged, events)
}

func (s *fusionState) removeLink(idx int, kind EventKind, events []EventView) []EventView {
	if idx < 0 || idx >= len(s.links) || !s.links[idx].used {
		return events
	}
	l := &s.links[idx]
	d := &s.devices[l.device]
	events = append(events, s.tombstone(kind, FieldLink, &d.device, &l.link))
	s.unscheduleLink(idx)
	delete(s.linkByKey, l.link.Key)
	for i, x := range d.links {
		if x == idx {
			d.links[i] = d.links[len(d.links)-1]
			d.links = d.links[:len(d.links)-1]
			break
		}
	}
	l.used = false
	l.device = -1
	l.expires = [5]time.Time{}
	s.freeLinks = append(s.freeLinks, idx)
	return events
}

func (s *fusionState) removeDevice(idx int, kind EventKind, events []EventView) []EventView {
	if idx < 0 || idx >= len(s.devices) || !s.devices[idx].used {
		return events
	}
	d := &s.devices[idx]
	for len(d.links) != 0 {
		li := d.links[len(d.links)-1]
		events = s.removeLink(li, kind, events)
	}
	for len(d.dns) != 0 {
		di := d.dns[len(d.dns)-1]
		s.removeDNS(di)
	}
	delete(s.deviceByKey, d.device.Key)
	d.used = false
	d.links = d.links[:0]
	d.dns = d.dns[:0]
	d.device.Reset()
	s.freeDevices = append(s.freeDevices, idx)
	return events
}

func resetLink(l *DiscoveredLink) {
	l.Key = LinkKey{}
	l.Kind = 0
	l.LocalInterface = l.LocalInterface[:0]
	l.Device = DeviceKey{}
	l.ObservedSourceMAC = MAC{}
	l.RemoteChassis.Subtype = 0
	l.RemoteChassis.Value = l.RemoteChassis.Value[:0]
	l.RemotePort.Subtype = 0
	l.RemotePort.Value = l.RemotePort.Value[:0]
	resetTextField(&l.RemoteInterface)
	l.VLANs = l.VLANs[:0]
	l.Protocols = 0
	l.TTL = 0
	l.ExpiresAt = time.Time{}
	l.FirstSeen = time.Time{}
	l.LastSeen = time.Time{}
}

func (s *fusionState) scheduleLink(idx int, now, expiry time.Time) {
	s.unscheduleLink(idx)
	ticks := ceilDurationSeconds(expiry.Sub(now))
	if ticks < 1 {
		ticks = 1
	}
	slot := (s.wheelCursor + ticks) % len(s.linkHeads)
	l := &s.links[idx]
	l.wheelSlot = slot
	l.wheelRound = (ticks - 1) / len(s.linkHeads)
	l.wheelPrev = -1
	l.wheelNext = s.linkHeads[slot]
	if l.wheelNext >= 0 {
		s.links[l.wheelNext].wheelPrev = idx
	}
	s.linkHeads[slot] = idx
}

func (s *fusionState) unscheduleLink(idx int) {
	l := &s.links[idx]
	if l.wheelSlot < 0 {
		return
	}
	if l.wheelPrev >= 0 {
		s.links[l.wheelPrev].wheelNext = l.wheelNext
	} else {
		s.linkHeads[l.wheelSlot] = l.wheelNext
	}
	if l.wheelNext >= 0 {
		s.links[l.wheelNext].wheelPrev = l.wheelPrev
	}
	l.wheelSlot, l.wheelPrev, l.wheelNext = -1, -1, -1
}

func (s *fusionState) cacheDNS(deviceIdx int, record *DNSRecord, now time.Time) bool {
	if record == nil {
		return false
	}
	key := makeDNSKey(deviceIdx, record)
	if record.TTL == 0 {
		if idx, ok := s.dnsByKey[key]; ok {
			s.removeDNS(idx)
			return true
		}
		return false
	}
	expires := now.Add(time.Duration(record.TTL) * time.Second)
	if idx, ok := s.dnsByKey[key]; ok {
		e := &s.dns[idx]
		changed := !dnsRecordEqual(&e.record, record)
		cloneDNSRecord(&e.record, record)
		e.expiresAt = expires
		s.scheduleDNS(idx, now, expires)
		return changed
	}
	idx := s.allocDNS()
	if idx < 0 {
		return false
	}
	e := &s.dns[idx]
	e.used = true
	e.key = key
	e.device = deviceIdx
	e.expiresAt = expires
	e.wheelSlot, e.wheelPrev, e.wheelNext = -1, -1, -1
	cloneDNSRecord(&e.record, record)
	s.dnsByKey[key] = idx
	s.devices[deviceIdx].dns = append(s.devices[deviceIdx].dns, idx)
	s.scheduleDNS(idx, now, expires)
	return true
}

func makeDNSKey(device int, r *DNSRecord) dnsKey {
	h1 := hash64(1469598103934665603, r.Name)
	h2 := hash64(1099511628211, r.Name)
	var fixed [16]byte
	switch r.Type {
	case DNSRecordA, DNSRecordAAAA:
		if r.Address.IsValid() {
			fixed = r.Address.As16()
			h1 = hash64(h1, fixed[:])
			h2 = hash64(h2, fixed[:])
		}
	case DNSRecordPTR:
		h1 = hash64(h1, r.Target)
		h2 = hash64(h2, r.Target)
	case DNSRecordSRV:
		h1 = hash64(h1, r.Target)
		h2 = hash64(h2, r.Target)
		h1 ^= uint64(r.Port)<<32 | uint64(r.Priority)<<16 | uint64(r.Weight)
		h2 ^= uint64(r.Port)<<16 | uint64(r.Weight)
	case DNSRecordTXT:
		h1 = hash64(h1, r.TXT)
		h2 = hash64(h2, r.TXT)
	}
	return dnsKey{device: device, h1: h1, h2: h2, typ: r.Type}
}

func hash64(seed uint64, b []byte) uint64 {
	h := seed
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func dnsRecordEqual(a, b *DNSRecord) bool {
	return a.Type == b.Type && a.Class == b.Class && a.CacheFlush == b.CacheFlush && a.TTL == b.TTL &&
		a.Address == b.Address && a.Port == b.Port && a.Priority == b.Priority && a.Weight == b.Weight &&
		bytes.Equal(a.Name, b.Name) && bytes.Equal(a.Target, b.Target) && bytes.Equal(a.TXT, b.TXT)
}

func cloneDNSRecord(dst, src *DNSRecord) {
	dst.Name = copyBytes(dst.Name, src.Name)
	dst.Type = src.Type
	dst.Class = src.Class
	dst.CacheFlush = src.CacheFlush
	dst.TTL = src.TTL
	dst.Target = copyBytes(dst.Target, src.Target)
	dst.Address = src.Address
	dst.Port = src.Port
	dst.Priority = src.Priority
	dst.Weight = src.Weight
	dst.TXT = copyBytes(dst.TXT, src.TXT)
}

func (s *fusionState) allocDNS() int {
	if n := len(s.freeDNS); n > 0 {
		idx := s.freeDNS[n-1]
		s.freeDNS = s.freeDNS[:n-1]
		return idx
	}
	oldest := -1
	for i := range s.dns {
		if s.dns[i].used && (oldest < 0 || s.dns[i].expiresAt.Before(s.dns[oldest].expiresAt)) {
			oldest = i
		}
	}
	if oldest < 0 {
		return -1
	}
	s.dnsEvictions++
	s.removeDNS(oldest)
	n := len(s.freeDNS)
	if n == 0 {
		return -1
	}
	idx := s.freeDNS[n-1]
	s.freeDNS = s.freeDNS[:n-1]
	return idx
}

func (s *fusionState) removeDNS(idx int) {
	if idx < 0 || idx >= len(s.dns) || !s.dns[idx].used {
		return
	}
	e := &s.dns[idx]
	s.unscheduleDNS(idx)
	delete(s.dnsByKey, e.key)
	if e.device >= 0 && e.device < len(s.devices) && s.devices[e.device].used {
		d := &s.devices[e.device]
		for i, x := range d.dns {
			if x == idx {
				d.dns[i] = d.dns[len(d.dns)-1]
				d.dns = d.dns[:len(d.dns)-1]
				break
			}
		}
	}
	e.used = false
	e.device = -1
	e.expiresAt = time.Time{}
	e.key = dnsKey{}
	s.freeDNS = append(s.freeDNS, idx)
}

func (s *fusionState) scheduleDNS(idx int, now, expiry time.Time) {
	s.unscheduleDNS(idx)
	ticks := ceilDurationSeconds(expiry.Sub(now))
	if ticks < 1 {
		ticks = 1
	}
	slot := (s.wheelCursor + ticks) % len(s.dnsHeads)
	e := &s.dns[idx]
	e.wheelSlot = slot
	e.wheelRound = (ticks - 1) / len(s.dnsHeads)
	e.wheelPrev = -1
	e.wheelNext = s.dnsHeads[slot]
	if e.wheelNext >= 0 {
		s.dns[e.wheelNext].wheelPrev = idx
	}
	s.dnsHeads[slot] = idx
}

func (s *fusionState) unscheduleDNS(idx int) {
	e := &s.dns[idx]
	if e.wheelSlot < 0 {
		return
	}
	if e.wheelPrev >= 0 {
		s.dns[e.wheelPrev].wheelNext = e.wheelNext
	} else {
		s.dnsHeads[e.wheelSlot] = e.wheelNext
	}
	if e.wheelNext >= 0 {
		s.dns[e.wheelNext].wheelPrev = e.wheelPrev
	}
	e.wheelSlot, e.wheelPrev, e.wheelNext = -1, -1, -1
}

func (s *fusionState) rebuildServices(deviceIdx int) bool {
	d := &s.devices[deviceIdx].device
	oldCount := len(d.Services)
	for i := range d.Services {
		d.Services[i].Instance = d.Services[i].Instance[:0]
		d.Services[i].Type = d.Services[i].Type[:0]
		d.Services[i].Domain = d.Services[i].Domain[:0]
		d.Services[i].Host = d.Services[i].Host[:0]
		d.Services[i].TXT = d.Services[i].TXT[:0]
		d.Services[i].Addresses = d.Services[i].Addresses[:0]
		d.Services[i].Port = 0
		d.Services[i].ExpiresAt = time.Time{}
		d.Services[i].Protocols = 0
	}
	d.Services = d.Services[:0]
	indices := s.devices[deviceIdx].dns
	for _, idx := range indices {
		if idx < 0 || idx >= len(s.dns) || !s.dns[idx].used {
			continue
		}
		e := &s.dns[idx]
		if e.record.Type != DNSRecordPTR {
			continue
		}
		svc := ensureService(d, e.record.Target)
		svc.Type = copyBytes(svc.Type, e.record.Name)
		svc.Domain = copyBytes(svc.Domain, dnsDomain(e.record.Name))
		svc.Protocols |= ProtocolsMDNS
		svc.ExpiresAt = minNonZeroTime(svc.ExpiresAt, e.expiresAt)
	}
	for _, idx := range indices {
		if idx < 0 || idx >= len(s.dns) || !s.dns[idx].used {
			continue
		}
		e := &s.dns[idx]
		switch e.record.Type {
		case DNSRecordSRV:
			svc := findService(d, e.record.Name)
			if svc == nil {
				continue
			}
			svc.Host = copyBytes(svc.Host, e.record.Target)
			svc.Port = e.record.Port
			svc.Protocols |= ProtocolsMDNS
			svc.ExpiresAt = minNonZeroTime(svc.ExpiresAt, e.expiresAt)
		case DNSRecordTXT:
			svc := findService(d, e.record.Name)
			if svc == nil {
				continue
			}
			svc.TXT = copyBytes(svc.TXT, e.record.TXT)
			svc.Protocols |= ProtocolsMDNS
			svc.ExpiresAt = minNonZeroTime(svc.ExpiresAt, e.expiresAt)
		}
	}
	for _, idx := range indices {
		if idx < 0 || idx >= len(s.dns) || !s.dns[idx].used {
			continue
		}
		e := &s.dns[idx]
		if e.record.Type != DNSRecordA && e.record.Type != DNSRecordAAAA {
			continue
		}
		for i := range d.Services {
			if bytes.Equal(d.Services[i].Host, e.record.Name) {
				d.Services[i].Addresses = appendUniqueAddr(d.Services[i].Addresses, e.record.Address)
			}
		}
	}
	return oldCount != len(d.Services)
}

func findService(d *DiscoveredDevice, instance []byte) *Service {
	for i := range d.Services {
		if bytes.Equal(d.Services[i].Instance, instance) {
			return &d.Services[i]
		}
	}
	return nil
}

func ensureService(d *DiscoveredDevice, instance []byte) *Service {
	if service := findService(d, instance); service != nil {
		return service
	}
	i := len(d.Services)
	if i < cap(d.Services) {
		d.Services = d.Services[:i+1]
	} else {
		d.Services = append(d.Services, Service{})
	}
	s := &d.Services[i]
	s.Instance = copyBytes(s.Instance, instance)
	s.Protocols = ProtocolsMDNS
	return s
}

func dnsDomain(name []byte) []byte {
	dots := 0
	for i, c := range name {
		if c == '.' {
			dots++
			if dots == 2 && i+1 < len(name) {
				return name[i+1:]
			}
		}
	}
	return nil
}

func minNonZeroTime(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

func (s *fusionState) observeLLDP(meta observationMeta, msg *LLDPMessage, events []EventView) []EventView {
	var claimed MAC
	if msg.ChassisID.Subtype == 4 && len(msg.ChassisID.Value) == 6 {
		copy(claimed[:], msg.ChassisID.Value)
	}
	var addressStorage [32]netip.Addr
	addresses := lldpAddresses(addressStorage[:0], msg.ManagementAddresses)
	idx, events := s.deviceFor(meta, claimed, addresses, events)
	if idx < 0 {
		return events
	}
	d := &s.devices[idx].device
	wasNew := d.Protocols == 0
	changed := FieldSet(0)
	if meta.sourceMAC.IsUnicast() {
		before := len(d.ObservedMACs)
		d.ObservedMACs = appendUniqueMAC(d.ObservedMACs, meta.sourceMAC)
		if len(d.ObservedMACs) != before {
			changed |= FieldIdentity
		}
	}
	if claimed.IsUnicast() && claimed != meta.sourceMAC {
		before := len(d.ClaimedMACs)
		d.ClaimedMACs = appendUniqueMAC(d.ClaimedMACs, claimed)
		if len(d.ClaimedMACs) != before {
			changed |= FieldIdentity
		}
	}
	for _, a := range addresses {
		before := len(d.Addresses)
		d.Addresses = appendUniqueAddr(d.Addresses, a)
		if len(d.Addresses) != before {
			changed |= FieldAddresses
		}
	}
	if mergeText(&d.SystemName, msg.SystemName, ProtocolsLLDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		changed |= FieldNames
	}
	if d.Capabilities|uint64(msg.Details.EnabledCapabilities) != d.Capabilities {
		d.Capabilities |= uint64(msg.Details.EnabledCapabilities)
		changed |= FieldCapabilities
	}
	if d.Protocols&ProtocolsLLDP == 0 {
		d.Protocols |= ProtocolsLLDP
		changed |= FieldIdentity
	}
	updateDeviceTimes(d, meta.timestamp)
	li, linkChanged, added, events := s.upsertLink(meta, idx, PhysicalAdjacency, time.Duration(msg.TTLSeconds)*time.Second, events)
	if li < 0 {
		return events
	}
	l := &s.links[li].link
	if !identifierEqual(&l.RemoteChassis, &msg.ChassisID) {
		l.RemoteChassis.Subtype = msg.ChassisID.Subtype
		l.RemoteChassis.Value = copyBytes(l.RemoteChassis.Value, msg.ChassisID.Value)
		linkChanged = true
	}
	if l.RemotePort.Subtype != msg.PortID.Subtype || !bytes.Equal(l.RemotePort.Value, msg.PortID.Value) {
		l.RemotePort.Subtype = msg.PortID.Subtype
		l.RemotePort.Value = copyBytes(l.RemotePort.Value, msg.PortID.Value)
		linkChanged = true
	}
	if mergeText(&l.RemoteInterface, msg.Details.PortDescription, ProtocolsLLDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		linkChanged = true
	}
	if msg.Details.HasPVID {
		if appendLinkVLAN(l, msg.Details.PVID) {
			linkChanged = true
		}
	}
	for _, v := range msg.Details.VLANs {
		if appendLinkVLAN(l, v.ID) {
			linkChanged = true
		}
	}
	if linkChanged {
		changed |= FieldLink
	}
	if s.applyClassification(d) {
		changed |= FieldClassification
	}
	if changed != 0 || added || wasNew {
		kind := EventChanged
		if added || wasNew {
			kind = EventAdded
		}
		events = append(events, EventView{Kind: kind, Changed: changed, Device: d, Link: l})
	}
	return events
}

func (s *fusionState) observeCDP(meta observationMeta, msg *CDPMessage, events []EventView) []EventView {
	idx, events := s.deviceFor(meta, MAC{}, msg.Addresses, events)
	if idx < 0 {
		return events
	}
	d := &s.devices[idx].device
	wasNew := d.Protocols == 0
	changed := FieldSet(0)
	if meta.sourceMAC.IsUnicast() {
		before := len(d.ObservedMACs)
		d.ObservedMACs = appendUniqueMAC(d.ObservedMACs, meta.sourceMAC)
		if len(d.ObservedMACs) != before {
			changed |= FieldIdentity
		}
	}
	for _, a := range msg.Addresses {
		before := len(d.Addresses)
		d.Addresses = appendUniqueAddr(d.Addresses, a)
		if len(d.Addresses) != before {
			changed |= FieldAddresses
		}
	}
	for _, a := range msg.Details.ManagementAddress {
		before := len(d.Addresses)
		d.Addresses = appendUniqueAddr(d.Addresses, a)
		if len(d.Addresses) != before {
			changed |= FieldAddresses
		}
	}
	if mergeText(&d.ProtocolDeviceID, msg.DeviceID, ProtocolsCDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		changed |= FieldNames
	}
	if mergeText(&d.SystemName, msg.SystemName, ProtocolsCDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		changed |= FieldNames
	}
	if mergeText(&d.Platform, msg.Details.Platform, ProtocolsCDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		changed |= FieldPlatform
	}
	if mergeText(&d.SoftwareVersion, msg.Details.SoftwareVersion, ProtocolsCDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		changed |= FieldSoftware
	}
	if d.Capabilities|uint64(msg.Details.Capabilities) != d.Capabilities {
		d.Capabilities |= uint64(msg.Details.Capabilities)
		changed |= FieldCapabilities
	}
	if d.Protocols&ProtocolsCDP == 0 {
		d.Protocols |= ProtocolsCDP
		changed |= FieldIdentity
	}
	updateDeviceTimes(d, meta.timestamp)
	li, linkChanged, added, events := s.upsertLink(meta, idx, PhysicalAdjacency, time.Duration(msg.TTLSeconds)*time.Second, events)
	if li < 0 {
		return events
	}
	l := &s.links[li].link
	if len(msg.DeviceID) != 0 && !bytes.Equal(l.RemoteChassis.Value, msg.DeviceID) {
		l.RemoteChassis.Subtype = 7
		l.RemoteChassis.Value = copyBytes(l.RemoteChassis.Value, msg.DeviceID)
		linkChanged = true
	}
	if len(msg.PortID) != 0 && !bytes.Equal(l.RemotePort.Value, msg.PortID) {
		l.RemotePort.Subtype = 7
		l.RemotePort.Value = copyBytes(l.RemotePort.Value, msg.PortID)
		linkChanged = true
	}
	if mergeText(&l.RemoteInterface, msg.PortID, ProtocolsCDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		linkChanged = true
	}
	if msg.Details.HasNativeVLAN && appendLinkVLAN(l, msg.Details.NativeVLAN) {
		linkChanged = true
	}
	if linkChanged {
		changed |= FieldLink
	}
	if s.applyClassification(d) {
		changed |= FieldClassification
	}
	if changed != 0 || added || wasNew {
		kind := EventChanged
		if added || wasNew {
			kind = EventAdded
		}
		events = append(events, EventView{Kind: kind, Changed: changed, Device: d, Link: l})
	}
	return events
}

func (s *fusionState) observeMNDP(meta observationMeta, msg *MNDPMessage, events []EventView) []EventView {
	if msg.IsRefresh {
		return events
	}
	idx, events := s.deviceFor(meta, msg.MAC, msg.Addresses, events)
	if idx < 0 {
		return events
	}
	d := &s.devices[idx].device
	wasNew := d.Protocols == 0
	changed := FieldSet(0)
	if meta.sourceMAC.IsUnicast() {
		before := len(d.ObservedMACs)
		d.ObservedMACs = appendUniqueMAC(d.ObservedMACs, meta.sourceMAC)
		if len(d.ObservedMACs) != before {
			changed |= FieldIdentity
		}
	}
	if msg.HasMAC {
		before := len(d.ClaimedMACs)
		d.ClaimedMACs = appendUniqueMAC(d.ClaimedMACs, msg.MAC)
		if len(d.ClaimedMACs) != before {
			changed |= FieldIdentity
		}
	}
	if meta.sourceIP.IsValid() {
		before := len(d.Addresses)
		d.Addresses = appendUniqueAddr(d.Addresses, meta.sourceIP)
		if len(d.Addresses) != before {
			changed |= FieldAddresses
		}
	}
	for _, a := range msg.Addresses {
		if a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "" && meta.interfaceName != "" {
			a = a.WithZone(meta.interfaceName)
		}
		before := len(d.Addresses)
		d.Addresses = appendUniqueAddr(d.Addresses, a)
		if len(d.Addresses) != before {
			changed |= FieldAddresses
		}
	}
	if mergeText(&d.SystemName, msg.Details.Identity, ProtocolsMNDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		changed |= FieldNames
	}
	if mergeText(&d.Platform, msg.Details.Platform, ProtocolsMNDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		changed |= FieldPlatform
	}
	if mergeText(&d.Model, msg.Details.Board, ProtocolsMNDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		changed |= FieldModel
	}
	if mergeText(&d.SoftwareVersion, msg.Details.Version, ProtocolsMNDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		changed |= FieldSoftware
	}
	if d.Protocols&ProtocolsMNDP == 0 {
		d.Protocols |= ProtocolsMNDP
		changed |= FieldIdentity
	}
	updateDeviceTimes(d, meta.timestamp)
	li, linkChanged, added, events := s.upsertLink(meta, idx, SegmentPresence, s.cfg.MNDPIdleTTL, events)
	if li < 0 {
		return events
	}
	l := &s.links[li].link
	if mergeText(&l.RemoteInterface, msg.Details.InterfaceName, ProtocolsMNDP, 3, meta.timestamp, s.cfg.MaxAlternatives) {
		linkChanged = true
	}
	if linkChanged {
		changed |= FieldLink
	}
	if s.applyClassification(d) {
		changed |= FieldClassification
	}
	if changed != 0 || added || wasNew {
		kind := EventChanged
		if added || wasNew {
			kind = EventAdded
		}
		events = append(events, EventView{Kind: kind, Changed: changed, Device: d, Link: l})
	}
	return events
}

func (s *fusionState) observeMDNS(meta observationMeta, msg *MDNSMessage, events []EventView) []EventView {
	var addressStorage [maxDNSRecordsPerMessage]netip.Addr
	addresses := addressStorage[:0]
	for i := range msg.Records {
		if msg.Records[i].Address.IsValid() {
			addresses = appendUniqueAddr(addresses, msg.Records[i].Address)
		}
	}
	idx, events := s.deviceFor(meta, MAC{}, addresses, events)
	if idx < 0 {
		return events
	}
	d := &s.devices[idx].device
	wasNew := d.Protocols == 0
	changed := FieldSet(0)
	if meta.sourceMAC.IsUnicast() {
		before := len(d.ObservedMACs)
		d.ObservedMACs = appendUniqueMAC(d.ObservedMACs, meta.sourceMAC)
		if len(d.ObservedMACs) != before {
			changed |= FieldIdentity
		}
	}
	if meta.sourceIP.IsValid() {
		before := len(d.Addresses)
		d.Addresses = appendUniqueAddr(d.Addresses, meta.sourceIP)
		if len(d.Addresses) != before {
			changed |= FieldAddresses
		}
	}
	maxTTL := uint32(1)
	cacheChanged := false
	var flushed [maxDNSRecordsPerMessage]struct {
		name []byte
		typ  DNSRecordType
	}
	flushedCount := 0
	for i := range msg.Records {
		r := &msg.Records[i]
		if r.CacheFlush {
			seen := false
			for j := 0; j < flushedCount; j++ {
				if flushed[j].typ == r.Type && bytes.Equal(flushed[j].name, r.Name) {
					seen = true
					break
				}
			}
			if !seen {
				s.flushDNSSet(idx, r.Name, r.Type, msg.Records)
				flushed[flushedCount].name, flushed[flushedCount].typ = r.Name, r.Type
				flushedCount++
			}
		}
		if r.TTL > maxTTL {
			maxTTL = r.TTL
		}
		if s.cacheDNS(idx, r, meta.timestamp) {
			cacheChanged = true
		}
		if (r.Type == DNSRecordA || r.Type == DNSRecordAAAA) && r.Address.IsValid() {
			before := len(d.Addresses)
			d.Addresses = appendUniqueAddr(d.Addresses, r.Address)
			if len(d.Addresses) != before {
				changed |= FieldAddresses
			}
			if mergeText(&d.HostName, r.Name, ProtocolsMDNS, 2, meta.timestamp, s.cfg.MaxAlternatives) {
				changed |= FieldNames
			}
		}
	}
	if cacheChanged && s.rebuildServices(idx) {
		changed |= FieldServices
	} else if cacheChanged {
		changed |= FieldServices
	}
	if d.Protocols&ProtocolsMDNS == 0 {
		d.Protocols |= ProtocolsMDNS
		changed |= FieldIdentity
	}
	updateDeviceTimes(d, meta.timestamp)
	li, linkChanged, added, events := s.upsertLink(meta, idx, SegmentPresence, time.Duration(maxTTL)*time.Second, events)
	if li < 0 {
		return events
	}
	l := &s.links[li].link
	if linkChanged {
		changed |= FieldLink
	}
	if s.applyClassification(d) {
		changed |= FieldClassification
	}
	if changed != 0 || added || wasNew {
		kind := EventChanged
		if added || wasNew {
			kind = EventAdded
		}
		events = append(events, EventView{Kind: kind, Changed: changed, Device: d, Link: l})
	}
	return events
}

func (s *fusionState) flushDNSSet(deviceIdx int, name []byte, typ DNSRecordType, incoming []DNSRecord) {
	d := &s.devices[deviceIdx]
	for pos := 0; pos < len(d.dns); {
		idx := d.dns[pos]
		if idx < 0 || idx >= len(s.dns) || !s.dns[idx].used {
			pos++
			continue
		}
		r := &s.dns[idx].record
		if r.Type == typ && bytes.Equal(r.Name, name) {
			keep := false
			for i := range incoming {
				if incoming[i].Type == typ && bytes.Equal(incoming[i].Name, name) && makeDNSKey(deviceIdx, &incoming[i]) == s.dns[idx].key {
					keep = true
					break
				}
			}
			if !keep {
				s.removeDNS(idx)
				continue
			}
		}
		pos++
	}
}

func (s *fusionState) applyClassification(d *DiscoveredDevice) bool {
	class, rule, ok := s.classifier.Classify(d)
	if !ok {
		if len(d.Class) == 0 && len(d.MatchedRule) == 0 {
			return false
		}
		d.Class = d.Class[:0]
		d.MatchedRule = d.MatchedRule[:0]
		return true
	}
	if bytes.Equal(d.Class, class) && bytes.Equal(d.MatchedRule, rule) {
		return false
	}
	d.Class = copyBytes(d.Class, class)
	d.MatchedRule = copyBytes(d.MatchedRule, rule)
	return true
}

func updateDeviceTimes(d *DiscoveredDevice, now time.Time) {
	if d.FirstSeen.IsZero() || now.Before(d.FirstSeen) {
		d.FirstSeen = now
	}
	if now.After(d.LastSeen) {
		d.LastSeen = now
	}
}
func identifierEqual(a, b *Identifier) bool {
	return a.Subtype == b.Subtype && bytes.Equal(a.Value, b.Value)
}
func appendLinkVLAN(l *DiscoveredLink, vlan uint16) bool {
	for _, v := range l.VLANs {
		if v == vlan {
			return false
		}
	}
	l.VLANs = append(l.VLANs, vlan)
	return true
}

func lldpAddresses(out []netip.Addr, values []ManagementAddress) []netip.Addr {
	for _, m := range values {
		if m.Subtype == 1 && len(m.Address) == 4 {
			out = appendUniqueAddr(out, netip.AddrFrom4([4]byte{m.Address[0], m.Address[1], m.Address[2], m.Address[3]}))
		} else if m.Subtype == 2 && len(m.Address) == 16 {
			var a [16]byte
			copy(a[:], m.Address)
			out = appendUniqueAddr(out, netip.AddrFrom16(a))
		}
	}
	return out
}

func (s *fusionState) tick(now time.Time, events []EventView) []EventView {
	s.wheelCursor = (s.wheelCursor + 1) % len(s.linkHeads)
	for idx := s.linkHeads[s.wheelCursor]; idx >= 0; {
		next := s.links[idx].wheelNext
		l := &s.links[idx]
		if l.wheelRound > 0 {
			l.wheelRound--
			idx = next
			continue
		}
		s.unscheduleLink(idx)
		changed := false
		for p := ProtocolLLDP; p <= ProtocolMDNS; p++ {
			if !l.expires[p].IsZero() && !l.expires[p].After(now) {
				l.expires[p] = time.Time{}
				l.link.Protocols &^= p.Set()
				changed = true
			}
		}
		if l.link.Protocols == 0 {
			deviceIdx := l.device
			events = s.removeLink(idx, EventExpired, events)
			if s.devices[deviceIdx].used && len(s.devices[deviceIdx].links) == 0 && len(s.devices[deviceIdx].dns) == 0 {
				s.dropDevice(deviceIdx)
			}
		} else {
			l.link.ExpiresAt = earliestExpiry(l.expires)
			l.link.TTL = latestExpiry(l.expires).Sub(now)
			s.scheduleLink(idx, now, l.link.ExpiresAt)
			if changed {
				events = append(events, EventView{Kind: EventChanged, Changed: FieldLink, Device: &s.devices[l.device].device, Link: &l.link})
			}
		}
		idx = next
	}
	dnsDevices := s.expiredDNS[:0]
	for idx := s.dnsHeads[s.wheelCursor]; idx >= 0; {
		next := s.dns[idx].wheelNext
		e := &s.dns[idx]
		if e.wheelRound > 0 {
			e.wheelRound--
			idx = next
			continue
		}
		deviceIdx := e.device
		s.removeDNS(idx)
		found := false
		for _, x := range dnsDevices {
			if x == deviceIdx {
				found = true
				break
			}
		}
		if !found {
			dnsDevices = append(dnsDevices, deviceIdx)
		}
		idx = next
	}
	for _, di := range dnsDevices {
		if di < 0 || di >= len(s.devices) || !s.devices[di].used {
			continue
		}
		d := &s.devices[di].device
		s.rebuildServices(di)
		if li := s.firstLink(di); li >= 0 {
			events = append(events, EventView{Kind: EventChanged, Changed: FieldServices, Device: d, Link: &s.links[li].link})
		} else if len(s.devices[di].dns) == 0 {
			s.dropDevice(di)
		}
	}
	s.expiredDNS = dnsDevices[:0]
	return events
}

func (s *fusionState) firstLink(deviceIdx int) int {
	for _, li := range s.devices[deviceIdx].links {
		if li >= 0 && li < len(s.links) && s.links[li].used {
			return li
		}
	}
	return -1
}
func (s *fusionState) dropDevice(idx int) {
	d := &s.devices[idx]
	delete(s.deviceByKey, d.device.Key)
	d.used = false
	d.device.Reset()
	d.links = d.links[:0]
	d.dns = d.dns[:0]
	s.freeDevices = append(s.freeDevices, idx)
}

func ceilDurationSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	return int((d + time.Second - 1) / time.Second)
}
