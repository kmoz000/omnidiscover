package omnidiscover

func cloneTextFieldInto(dst, src *TextField) {
	for i := range dst.Values {
		dst.Values[i].Value = dst.Values[i].Value[:0]
	}
	if cap(dst.Values) < len(src.Values) {
		dst.Values = make([]TextValue, len(src.Values))
	} else {
		dst.Values = dst.Values[:len(src.Values)]
	}
	for i := range src.Values {
		dst.Values[i].Value = copyBytes(dst.Values[i].Value, src.Values[i].Value)
		dst.Values[i].Protocols = src.Values[i].Protocols
		dst.Values[i].Confidence = src.Values[i].Confidence
		dst.Values[i].FirstSeen = src.Values[i].FirstSeen
		dst.Values[i].LastSeen = src.Values[i].LastSeen
	}
	dst.Canonical = src.Canonical
}

func cloneDeviceInto(dst, src *DiscoveredDevice) {
	if src == nil {
		dst.Reset()
		return
	}
	dst.Key = src.Key
	dst.ObservedMACs = append(dst.ObservedMACs[:0], src.ObservedMACs...)
	dst.ClaimedMACs = append(dst.ClaimedMACs[:0], src.ClaimedMACs...)
	dst.Addresses = append(dst.Addresses[:0], src.Addresses...)
	cloneTextFieldInto(&dst.SystemName, &src.SystemName)
	cloneTextFieldInto(&dst.HostName, &src.HostName)
	cloneTextFieldInto(&dst.ProtocolDeviceID, &src.ProtocolDeviceID)
	cloneTextFieldInto(&dst.Model, &src.Model)
	cloneTextFieldInto(&dst.Platform, &src.Platform)
	cloneTextFieldInto(&dst.SoftwareVersion, &src.SoftwareVersion)
	dst.Capabilities = src.Capabilities
	for i := range dst.Services {
		dst.Services[i].Instance = dst.Services[i].Instance[:0]
		dst.Services[i].Type = dst.Services[i].Type[:0]
		dst.Services[i].Domain = dst.Services[i].Domain[:0]
		dst.Services[i].Host = dst.Services[i].Host[:0]
		dst.Services[i].TXT = dst.Services[i].TXT[:0]
		dst.Services[i].Addresses = dst.Services[i].Addresses[:0]
	}
	if cap(dst.Services) < len(src.Services) {
		dst.Services = make([]Service, len(src.Services))
	} else {
		dst.Services = dst.Services[:len(src.Services)]
	}
	for i := range src.Services {
		ds, ss := &dst.Services[i], &src.Services[i]
		ds.Instance = copyBytes(ds.Instance, ss.Instance)
		ds.Type = copyBytes(ds.Type, ss.Type)
		ds.Domain = copyBytes(ds.Domain, ss.Domain)
		ds.Host = copyBytes(ds.Host, ss.Host)
		ds.Port = ss.Port
		ds.TXT = copyBytes(ds.TXT, ss.TXT)
		ds.Addresses = append(ds.Addresses[:0], ss.Addresses...)
		ds.Protocols = ss.Protocols
		ds.ExpiresAt = ss.ExpiresAt
	}
	dst.Protocols = src.Protocols
	dst.Class = copyBytes(dst.Class, src.Class)
	dst.MatchedRule = copyBytes(dst.MatchedRule, src.MatchedRule)
	dst.FirstSeen = src.FirstSeen
	dst.LastSeen = src.LastSeen
}

func cloneLinkInto(dst, src *DiscoveredLink) {
	if src == nil {
		resetLink(dst)
		return
	}
	dst.Key = src.Key
	dst.Kind = src.Kind
	dst.LocalInterface = copyBytes(dst.LocalInterface, src.LocalInterface)
	dst.Device = src.Device
	dst.ObservedSourceMAC = src.ObservedSourceMAC
	dst.RemoteChassis.Subtype = src.RemoteChassis.Subtype
	dst.RemoteChassis.Value = copyBytes(dst.RemoteChassis.Value, src.RemoteChassis.Value)
	dst.RemotePort.Subtype = src.RemotePort.Subtype
	dst.RemotePort.Value = copyBytes(dst.RemotePort.Value, src.RemotePort.Value)
	cloneTextFieldInto(&dst.RemoteInterface, &src.RemoteInterface)
	dst.VLANs = append(dst.VLANs[:0], src.VLANs...)
	dst.Protocols = src.Protocols
	dst.TTL = src.TTL
	dst.ExpiresAt = src.ExpiresAt
	dst.FirstSeen = src.FirstSeen
	dst.LastSeen = src.LastSeen
}

func cloneEventInto(dst *Event, src EventView) {
	dst.Kind = src.Kind
	dst.Changed = src.Changed
	cloneDeviceInto(&dst.Device, src.Device)
	cloneLinkInto(&dst.Link, src.Link)
}
