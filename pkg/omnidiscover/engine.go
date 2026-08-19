package omnidiscover

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type Statistics struct {
	Captured        uint64
	Routed          [5]uint64
	Dropped         [5]uint64
	Malformed       [5]uint64
	Ignored         [5]uint64
	Partial         [5]uint64
	Events          uint64
	OutputDropped   uint64
	DeviceHighWater uint64
	LinkHighWater   uint64
	DNSHighWater    uint64
	DeviceEvictions uint64
	LinkEvictions   uint64
	DNSEvictions    uint64
}

type engineCounters struct {
	captured        atomic.Uint64
	routed          [5]atomic.Uint64
	dropped         [5]atomic.Uint64
	malformed       [5]atomic.Uint64
	ignored         [5]atomic.Uint64
	partial         [5]atomic.Uint64
	events          atomic.Uint64
	outputDropped   atomic.Uint64
	deviceHighWater atomic.Uint64
	linkHighWater   atomic.Uint64
	dnsHighWater    atomic.Uint64
}

type packetSlot struct {
	data []byte
	meta observationMeta
}

type decodedEnvelope struct {
	protocol Protocol
	meta     observationMeta
	status   DecodeStatus
	lldp     *LLDPMessage
	cdp      *CDPMessage
	mndp     *MNDPMessage
	mdns     *MDNSMessage
	ack      chan struct{}
}

type captureView struct {
	data           []byte
	protocol       Protocol
	interfaceName  string
	interfaceIndex int
	timestamp      time.Time
	sourceIP       netip.Addr
	frame          bool
}

type captureBackend interface {
	run(context.Context, func(captureView)) error
	close() error
}

// Engine coordinates passive capture, bounded decoding queues, fusion, and delivery.
type Engine struct {
	cfg         Config
	classifier  *Classifier
	state       *fusionState
	stateMu     sync.RWMutex
	queues      [5]chan *packetSlot
	freePackets chan *packetSlot
	decoded     chan decodedEnvelope
	counters    engineCounters
	running     atomic.Bool
	started     atomic.Bool
	closed      atomic.Bool
	controlMu   sync.Mutex
	cancel      context.CancelFunc
}

func New(config Config) (*Engine, error) {
	cfg := config.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	classifier, err := CompileClassifier(cfg.Rules)
	if err != nil {
		return nil, err
	}
	e := &Engine{cfg: cfg, classifier: classifier, state: newFusionState(cfg, classifier), decoded: make(chan decodedEnvelope, 8)}
	enabled := 0
	for p := ProtocolLLDP; p <= ProtocolMDNS; p++ {
		if !cfg.Protocols.Has(p) {
			continue
		}
		e.queues[p] = make(chan *packetSlot, cfg.ProtocolQueue)
		enabled++
	}
	totalSlots := cfg.ProtocolQueue*enabled + enabled
	e.freePackets = make(chan *packetSlot, totalSlots)
	for i := 0; i < totalSlots; i++ {
		e.freePackets <- &packetSlot{data: make([]byte, cfg.MaxFrameSize)}
	}
	return e, nil
}

// Run captures until ctx is canceled, a backend fails, or Close is called.
// Handler receives borrowed data and must not retain or mutate it.
func (e *Engine) Run(ctx context.Context, handler Handler) error {
	if e.closed.Load() {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.started.Load() {
		return ErrAlreadyRunning
	}
	if !e.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer e.running.Store(false)
	runCtx, cancel := context.WithCancel(ctx)
	e.controlMu.Lock()
	e.cancel = cancel
	e.controlMu.Unlock()
	defer func() { cancel(); e.controlMu.Lock(); e.cancel = nil; e.controlMu.Unlock() }()

	backends, err := openCaptureBackends(e.cfg)
	if err != nil {
		return err
	}
	e.started.Store(true)
	defer func() {
		for _, b := range backends {
			_ = b.close()
		}
	}()

	var workerWG sync.WaitGroup
	for p := ProtocolLLDP; p <= ProtocolMDNS; p++ {
		if e.queues[p] == nil {
			continue
		}
		workerWG.Add(1)
		go func(proto Protocol) { defer workerWG.Done(); e.decodeWorker(proto) }(p)
	}
	fusionDone := make(chan struct{})
	go func() { e.fusionLoop(handler); close(fusionDone) }()

	errCh := make(chan error, len(backends))
	var backendWG sync.WaitGroup
	for _, backend := range backends {
		backendWG.Add(1)
		go func(b captureBackend) {
			defer backendWG.Done()
			if runErr := b.run(runCtx, e.routeCapture); runErr != nil && runCtx.Err() == nil {
				select {
				case errCh <- runErr:
				default:
				}
				cancel()
			}
		}(backend)
	}

	<-runCtx.Done()
	for _, b := range backends {
		_ = b.close()
	}
	backendWG.Wait()
	for p := ProtocolLLDP; p <= ProtocolMDNS; p++ {
		if e.queues[p] != nil {
			close(e.queues[p])
		}
	}
	workerWG.Wait()
	close(e.decoded)
	<-fusionDone
	select {
	case runErr := <-errCh:
		return runErr
	default:
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (e *Engine) Close() error {
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	e.controlMu.Lock()
	if e.cancel != nil {
		e.cancel()
	}
	e.controlMu.Unlock()
	return nil
}

func (e *Engine) decodeWorker(protocol Protocol) {
	ack := make(chan struct{}, 1)
	var lldp LLDPMessage
	var cdp CDPMessage
	var mndp MNDPMessage
	var mdns MDNSMessage
	for slot := range e.queues[protocol] {
		var env decodedEnvelope
		env.protocol, env.meta, env.ack = protocol, slot.meta, ack
		switch protocol {
		case ProtocolLLDP:
			env.status = DecodeLLDPDU(slot.data, &lldp)
			env.lldp = &lldp
		case ProtocolCDP:
			env.status = DecodeCDP(slot.data, &cdp)
			env.cdp = &cdp
		case ProtocolMNDP:
			env.status = DecodeMNDP(slot.data, &mndp)
			mndp.SourceIP = slot.meta.sourceIP
			env.mndp = &mndp
		case ProtocolMDNS:
			env.status = DecodeMDNS(slot.data, &mdns)
			env.mdns = &mdns
		}
		if env.status.Severity == DecodeFatal {
			e.counters.malformed[protocol].Add(1)
			e.releasePacket(slot)
			continue
		}
		if env.status.Severity == DecodeIgnored {
			e.counters.ignored[protocol].Add(1)
			e.releasePacket(slot)
			continue
		}
		if env.status.Severity == DecodePartial {
			e.counters.partial[protocol].Add(1)
		}
		e.decoded <- env
		<-ack
		e.releasePacket(slot)
	}
}

func (e *Engine) fusionLoop(handler Handler) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	events := make([]EventView, 0, 16)
	for {
		select {
		case env, ok := <-e.decoded:
			if !ok {
				return
			}
			events = events[:0]
			e.stateMu.Lock()
			e.state.resetTombstones()
			switch env.protocol {
			case ProtocolLLDP:
				events = e.state.observeLLDP(env.meta, env.lldp, events)
			case ProtocolCDP:
				events = e.state.observeCDP(env.meta, env.cdp, events)
			case ProtocolMNDP:
				events = e.state.observeMNDP(env.meta, env.mndp, events)
			case ProtocolMDNS:
				events = e.state.observeMDNS(env.meta, env.mdns, events)
			}
			e.updateHighWaterLocked()
			e.stateMu.Unlock()
			e.deliver(events, handler)
			env.ack <- struct{}{}
		case now := <-ticker.C:
			events = events[:0]
			e.stateMu.Lock()
			e.state.resetTombstones()
			events = e.state.tick(now, events)
			e.stateMu.Unlock()
			e.deliver(events, handler)
		}
	}
}

func (e *Engine) deliver(events []EventView, handler Handler) {
	if handler == nil {
		return
	}
	for _, event := range events {
		e.counters.events.Add(1)
		handler(event)
	}
}

func (e *Engine) routeCapture(view captureView) {
	e.counters.captured.Add(1)
	if view.timestamp.IsZero() {
		view.timestamp = time.Now().UTC()
	}
	if view.protocol != ProtocolUnknown {
		if e.cfg.Protocols.Has(view.protocol) {
			e.enqueue(view.protocol, view.data, observationMeta{protocol: view.protocol, interfaceName: view.interfaceName, interfaceIndex: view.interfaceIndex, timestamp: view.timestamp, sourceIP: view.sourceIP})
		}
		return
	}
	var frame EthernetFrame
	st := DecodeEthernetFrame(view.data, &frame)
	if !st.Usable() {
		return
	}
	meta := observationMeta{interfaceName: view.interfaceName, interfaceIndex: view.interfaceIndex, timestamp: view.timestamp, sourceMAC: frame.Source, vlans: frame.VLANs, vlanCount: frame.VLANCount}
	if frame.EtherType == EtherTypeLLDP && e.cfg.Protocols.Has(ProtocolLLDP) {
		meta.protocol = ProtocolLLDP
		e.enqueue(ProtocolLLDP, frame.Payload, meta)
		return
	}
	if frame.LLC.SNAP && frame.LLC.OUI == ciscoOUI && frame.LLC.PID == cdpPID && e.cfg.Protocols.Has(ProtocolCDP) {
		meta.protocol = ProtocolCDP
		e.enqueue(ProtocolCDP, frame.Payload, meta)
		return
	}
	if frame.EtherType != EtherTypeIPv4 && frame.EtherType != EtherTypeIPv6 {
		return
	}
	var udp UDPPacket
	ust := DecodeUDP(&frame, &udp)
	if !ust.Usable() {
		return
	}
	meta.sourceIP = udp.SourceIP
	if (udp.SourcePort == MDNSPort || udp.DestinationPort == MDNSPort) && e.cfg.Protocols.Has(ProtocolMDNS) {
		meta.protocol = ProtocolMDNS
		e.enqueue(ProtocolMDNS, udp.Payload, meta)
	} else if (udp.SourcePort == MNDPPort || udp.DestinationPort == MNDPPort) && e.cfg.Protocols.Has(ProtocolMNDP) {
		meta.protocol = ProtocolMNDP
		e.enqueue(ProtocolMNDP, udp.Payload, meta)
	}
}

func (e *Engine) enqueue(protocol Protocol, payload []byte, meta observationMeta) {
	if len(payload) > e.cfg.MaxFrameSize {
		e.counters.dropped[protocol].Add(1)
		return
	}
	var slot *packetSlot
	select {
	case slot = <-e.freePackets:
	default:
		e.counters.dropped[protocol].Add(1)
		return
	}
	slot.data = slot.data[:len(payload)]
	copy(slot.data, payload)
	slot.meta = meta
	slot.meta.protocol = protocol
	select {
	case e.queues[protocol] <- slot:
		e.counters.routed[protocol].Add(1)
	default:
		e.counters.dropped[protocol].Add(1)
		e.releasePacket(slot)
	}
}

func (e *Engine) releasePacket(slot *packetSlot) {
	slot.data = slot.data[:cap(slot.data)]
	slot.meta = observationMeta{}
	e.freePackets <- slot
}

// Stream runs the engine and returns owned event values plus one terminal error.
func (e *Engine) Stream(ctx context.Context) (<-chan Event, <-chan error) {
	out := make(chan Event, e.cfg.PendingEvents)
	errs := make(chan error, 1)
	queue := newOwnedStreamQueue(e.cfg.PendingEvents, &e.counters.outputDropped)
	pumpDone := make(chan struct{})
	go func() { queue.pump(ctx, out); close(out); close(pumpDone) }()
	go func() {
		defer close(errs)
		err := e.Run(ctx, queue.enqueue)
		queue.close()
		<-pumpDone
		if err != nil && !errors.Is(err, context.Canceled) {
			errs <- err
		}
	}()
	return out, errs
}

func (e *Engine) Stats() Statistics {
	var s Statistics
	s.Captured = e.counters.captured.Load()
	s.Events = e.counters.events.Load()
	s.OutputDropped = e.counters.outputDropped.Load()
	for p := ProtocolLLDP; p <= ProtocolMDNS; p++ {
		s.Routed[p] = e.counters.routed[p].Load()
		s.Dropped[p] = e.counters.dropped[p].Load()
		s.Malformed[p] = e.counters.malformed[p].Load()
		s.Ignored[p] = e.counters.ignored[p].Load()
		s.Partial[p] = e.counters.partial[p].Load()
	}
	s.DeviceHighWater = e.counters.deviceHighWater.Load()
	s.LinkHighWater = e.counters.linkHighWater.Load()
	s.DNSHighWater = e.counters.dnsHighWater.Load()
	e.stateMu.RLock()
	s.DeviceEvictions = e.state.deviceEvictions
	s.LinkEvictions = e.state.linkEvictions
	s.DNSEvictions = e.state.dnsEvictions
	e.stateMu.RUnlock()
	return s
}

func (e *Engine) updateHighWaterLocked() {
	atomicMax(&e.counters.deviceHighWater, uint64(e.cfg.MaxDevices-len(e.state.freeDevices)))
	atomicMax(&e.counters.linkHighWater, uint64(e.cfg.MaxLinks-len(e.state.freeLinks)))
	atomicMax(&e.counters.dnsHighWater, uint64(e.cfg.MaxDNSRecords-len(e.state.freeDNS)))
}

func atomicMax(dst *atomic.Uint64, value uint64) {
	for {
		old := dst.Load()
		if value <= old || dst.CompareAndSwap(old, value) {
			return
		}
	}
}

// Snapshot makes an owned, reusable copy of current fused state.
func (e *Engine) Snapshot(dst *Snapshot) {
	if dst == nil {
		return
	}
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	for i := range dst.Devices {
		dst.Devices[i].Reset()
	}
	dst.Devices = dst.Devices[:0]
	for i := range e.state.devices {
		if !e.state.devices[i].used {
			continue
		}
		n := len(dst.Devices)
		if n < cap(dst.Devices) {
			dst.Devices = dst.Devices[:n+1]
		} else {
			dst.Devices = append(dst.Devices, DiscoveredDevice{})
		}
		cloneDeviceInto(&dst.Devices[n], &e.state.devices[i].device)
	}
	for i := range dst.Links {
		resetLink(&dst.Links[i])
	}
	dst.Links = dst.Links[:0]
	for i := range e.state.links {
		if !e.state.links[i].used {
			continue
		}
		n := len(dst.Links)
		if n < cap(dst.Links) {
			dst.Links = dst.Links[:n+1]
		} else {
			dst.Links = append(dst.Links, DiscoveredLink{})
		}
		cloneLinkInto(&dst.Links[n], &e.state.links[i].link)
	}
}
