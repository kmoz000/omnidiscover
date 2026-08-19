package omnidiscover

import (
	"bytes"
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"sort"
)

// MatchField selects normalized data used by a classification predicate.
type MatchField uint8

const (
	MatchFieldProtocol MatchField = iota + 1
	MatchFieldObservedMAC
	MatchFieldAddress
	MatchFieldCapabilities
	MatchFieldSystemName
	MatchFieldHostName
	MatchFieldDeviceID
	MatchFieldModel
	MatchFieldPlatform
	MatchFieldSoftwareVersion
	MatchFieldServiceInstance
	MatchFieldServiceType
	MatchFieldServiceTXT
)

type MatchOp uint8

const (
	MatchExact MatchOp = iota + 1
	MatchRegex
	MatchProtocol
	MatchMACPrefix
	MatchIPPrefix
	MatchCapabilityAll
)

type MACPrefix struct {
	Address MAC
	Bits    uint8
}

// Predicate is compiled once; Pattern is only meaningful for MatchRegex.
type Predicate struct {
	Field      MatchField
	Op         MatchOp
	Value      string
	Pattern    string
	Protocol   ProtocolSet
	MACPrefix  MACPrefix
	IPPrefix   netip.Prefix
	Capability uint64
	FoldASCII  bool
}

type Rule struct {
	Name     string
	Class    string
	Priority int
	All      []Predicate
	Any      []Predicate
	None     []Predicate
}

type compiledPredicate struct {
	Predicate
	exact []byte
	re    *regexp.Regexp
}

type compiledRule struct {
	name        []byte
	class       []byte
	priority    int
	specificity int
	order       int
	all         []compiledPredicate
	any         []compiledPredicate
	none        []compiledPredicate
	required    uint16
}

// Classifier is immutable and safe for concurrent use.
type Classifier struct {
	rules              []compiledRule
	protocolCandidates [16][4]uint64
}

func CompileClassifier(rules []Rule) (*Classifier, error) {
	if len(rules) > DefaultMaxClassification {
		return nil, fmt.Errorf("omnidiscover: at most %d classification rules are allowed", DefaultMaxClassification)
	}
	c := &Classifier{rules: make([]compiledRule, 0, len(rules))}
	regexCount := 0
	for i, r := range rules {
		if r.Name == "" || r.Class == "" {
			return nil, fmt.Errorf("omnidiscover: rule %d requires name and class", i)
		}
		cr := compiledRule{
			name: []byte(r.Name), class: []byte(r.Class), priority: r.Priority,
			order: i, specificity: len(r.All) + len(r.Any) + len(r.None),
		}
		var err error
		if cr.all, regexCount, err = compilePredicates(r.All, regexCount); err != nil {
			return nil, fmt.Errorf("rule %q all: %w", r.Name, err)
		}
		if cr.any, regexCount, err = compilePredicates(r.Any, regexCount); err != nil {
			return nil, fmt.Errorf("rule %q any: %w", r.Name, err)
		}
		if cr.none, regexCount, err = compilePredicates(r.None, regexCount); err != nil {
			return nil, fmt.Errorf("rule %q none: %w", r.Name, err)
		}
		for _, predicate := range cr.all {
			if isTextField(predicate.Field) {
				cr.required |= 1 << predicate.Field
			}
		}
		c.rules = append(c.rules, cr)
	}
	sort.SliceStable(c.rules, func(i, j int) bool {
		if c.rules[i].priority != c.rules[j].priority {
			return c.rules[i].priority > c.rules[j].priority
		}
		if c.rules[i].specificity != c.rules[j].specificity {
			return c.rules[i].specificity > c.rules[j].specificity
		}
		return c.rules[i].order < c.rules[j].order
	})
	for protocolBits := 0; protocolBits < len(c.protocolCandidates); protocolBits++ {
		observed := ProtocolSet(protocolBits)
		for i := range c.rules {
			possible := true
			for _, predicate := range c.rules[i].all {
				if predicate.Op == MatchProtocol && observed&predicate.Protocol == 0 {
					possible = false
					break
				}
			}
			if possible {
				c.protocolCandidates[protocolBits][i>>6] |= uint64(1) << uint(i&63)
			}
		}
	}
	return c, nil
}

func compilePredicates(in []Predicate, regexCount int) ([]compiledPredicate, int, error) {
	out := make([]compiledPredicate, 0, len(in))
	for _, p := range in {
		cp := compiledPredicate{Predicate: p}
		switch p.Op {
		case MatchExact:
			if !isTextField(p.Field) {
				return nil, regexCount, fmt.Errorf("exact match requires a text field")
			}
			cp.exact = []byte(p.Value)
		case MatchRegex:
			if !isTextField(p.Field) {
				return nil, regexCount, fmt.Errorf("regex requires a text field")
			}
			if len(p.Pattern) == 0 || len(p.Pattern) > DefaultMaxRegexPatternSize {
				return nil, regexCount, fmt.Errorf("regex length must be 1..%d", DefaultMaxRegexPatternSize)
			}
			regexCount++
			if regexCount > DefaultMaxRegexRules {
				return nil, regexCount, fmt.Errorf("at most %d regex predicates are allowed", DefaultMaxRegexRules)
			}
			var err error
			cp.re, err = regexp.Compile(p.Pattern)
			if err != nil {
				return nil, regexCount, err
			}
		case MatchProtocol:
			if p.Field != MatchFieldProtocol {
				return nil, regexCount, fmt.Errorf("protocol match requires protocol field")
			}
			if p.Protocol == 0 || p.Protocol&^ProtocolsAll != 0 {
				return nil, regexCount, fmt.Errorf("invalid protocol set")
			}
		case MatchMACPrefix:
			if p.Field != MatchFieldObservedMAC {
				return nil, regexCount, fmt.Errorf("MAC prefix match requires observed MAC field")
			}
			if p.MACPrefix.Bits > 48 {
				return nil, regexCount, fmt.Errorf("MAC prefix is longer than 48 bits")
			}
		case MatchIPPrefix:
			if p.Field != MatchFieldAddress {
				return nil, regexCount, fmt.Errorf("IP prefix match requires address field")
			}
			if !p.IPPrefix.IsValid() {
				return nil, regexCount, fmt.Errorf("invalid IP prefix")
			}
		case MatchCapabilityAll:
			if p.Field != MatchFieldCapabilities {
				return nil, regexCount, fmt.Errorf("capability match requires capabilities field")
			}
			if p.Capability == 0 {
				return nil, regexCount, fmt.Errorf("capability mask is empty")
			}
		default:
			return nil, regexCount, fmt.Errorf("invalid operation %d", p.Op)
		}
		out = append(out, cp)
	}
	sort.SliceStable(out, func(i, j int) bool { return predicateCost(out[i].Op) < predicateCost(out[j].Op) })
	return out, regexCount, nil
}

func predicateCost(op MatchOp) uint8 {
	switch op {
	case MatchProtocol, MatchCapabilityAll:
		return 0
	case MatchExact:
		return 1
	case MatchMACPrefix, MatchIPPrefix:
		return 2
	case MatchRegex:
		return 3
	default:
		return 4
	}
}

func isTextField(f MatchField) bool {
	return f >= MatchFieldSystemName && f <= MatchFieldServiceTXT
}

// Classify returns immutable bytes owned by the Classifier.
func (c *Classifier) Classify(d *DiscoveredDevice) (class, rule []byte, ok bool) {
	if c == nil || d == nil {
		return nil, nil, false
	}
	available := populatedTextFields(d)
	mask := c.protocolCandidates[uint8(d.Protocols&ProtocolsAll)]
	for word := range mask {
		for candidates := mask[word]; candidates != 0; candidates &= candidates - 1 {
			i := word*64 + bits.TrailingZeros64(candidates)
			if i >= len(c.rules) {
				break
			}
			r := &c.rules[i]
			if r.required&available != r.required || !allPredicates(r.all, d) || anyPredicates(r.none, d) {
				continue
			}
			if len(r.any) > 0 && !anyPredicates(r.any, d) {
				continue
			}
			return r.class, r.name, true
		}
	}
	return nil, nil, false
}

func populatedTextFields(d *DiscoveredDevice) uint16 {
	var fields uint16
	values := [...]struct {
		field MatchField
		value *TextField
	}{
		{MatchFieldSystemName, &d.SystemName},
		{MatchFieldHostName, &d.HostName},
		{MatchFieldDeviceID, &d.ProtocolDeviceID},
		{MatchFieldModel, &d.Model},
		{MatchFieldPlatform, &d.Platform},
		{MatchFieldSoftwareVersion, &d.SoftwareVersion},
	}
	for _, entry := range values {
		if len(entry.value.Values) != 0 {
			fields |= 1 << entry.field
		}
	}
	for i := range d.Services {
		if len(d.Services[i].Instance) != 0 {
			fields |= 1 << MatchFieldServiceInstance
		}
		if len(d.Services[i].Type) != 0 {
			fields |= 1 << MatchFieldServiceType
		}
		if len(d.Services[i].TXT) != 0 {
			fields |= 1 << MatchFieldServiceTXT
		}
	}
	return fields
}

func allPredicates(p []compiledPredicate, d *DiscoveredDevice) bool {
	for i := range p {
		if !matchPredicate(&p[i], d) {
			return false
		}
	}
	return true
}

func anyPredicates(p []compiledPredicate, d *DiscoveredDevice) bool {
	for i := range p {
		if matchPredicate(&p[i], d) {
			return true
		}
	}
	return false
}

func matchPredicate(p *compiledPredicate, d *DiscoveredDevice) bool {
	switch p.Op {
	case MatchProtocol:
		return d.Protocols&p.Protocol != 0
	case MatchMACPrefix:
		for _, m := range d.ObservedMACs {
			if macPrefixMatch(m, p.MACPrefix) {
				return true
			}
		}
		return false
	case MatchIPPrefix:
		for _, a := range d.Addresses {
			if p.IPPrefix.Contains(a) {
				return true
			}
		}
		return false
	case MatchCapabilityAll:
		return d.Capabilities&p.Capability == p.Capability
	case MatchExact, MatchRegex:
		return visitTextField(d, p.Field, func(v []byte) bool {
			if p.Op == MatchRegex {
				return p.re.Match(v)
			}
			if p.FoldASCII {
				return equalFoldASCII(v, p.exact)
			}
			return bytes.Equal(v, p.exact)
		})
	default:
		return false
	}
}

func macPrefixMatch(m MAC, p MACPrefix) bool {
	whole := int(p.Bits / 8)
	if !bytes.Equal(m[:whole], p.Address[:whole]) {
		return false
	}
	rem := p.Bits % 8
	if rem == 0 {
		return true
	}
	mask := byte(0xff << (8 - rem))
	return m[whole]&mask == p.Address[whole]&mask
}

func equalFoldASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func visitTextField(d *DiscoveredDevice, field MatchField, fn func([]byte) bool) bool {
	var f *TextField
	switch field {
	case MatchFieldSystemName:
		f = &d.SystemName
	case MatchFieldHostName:
		f = &d.HostName
	case MatchFieldDeviceID:
		f = &d.ProtocolDeviceID
	case MatchFieldModel:
		f = &d.Model
	case MatchFieldPlatform:
		f = &d.Platform
	case MatchFieldSoftwareVersion:
		f = &d.SoftwareVersion
	case MatchFieldServiceInstance, MatchFieldServiceType, MatchFieldServiceTXT:
		for i := range d.Services {
			var b []byte
			switch field {
			case MatchFieldServiceInstance:
				b = d.Services[i].Instance
			case MatchFieldServiceType:
				b = d.Services[i].Type
			default:
				b = d.Services[i].TXT
			}
			if fn(b) {
				return true
			}
		}
		return false
	default:
		return false
	}
	for i := range f.Values {
		if fn(f.Values[i].Value) {
			return true
		}
	}
	return false
}
