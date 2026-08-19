// Command omnidiscover passively prints discovered network devices and links.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/kmoz000/omnidiscover/pkg/omnidiscover"
)

type options struct {
	interfaces      string
	protocols       string
	duration        time.Duration
	json            bool
	plain           bool
	includeLoopback bool
	stats           bool
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("omnidiscover", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var opts options
	flags.StringVar(&opts.interfaces, "interfaces", "", "comma-separated interfaces; empty selects all eligible interfaces")
	flags.StringVar(&opts.protocols, "protocols", "default", "comma-separated lldp,cdp,mndp,mdns; use all or default")
	flags.DurationVar(&opts.duration, "duration", 0, "stop after this duration; zero runs until interrupted")
	flags.BoolVar(&opts.json, "json", false, "write newline-delimited JSON events")
	flags.BoolVar(&opts.plain, "plain", false, "write line-oriented text instead of the terminal dashboard")
	flags.BoolVar(&opts.includeLoopback, "include-loopback", false, "include eligible loopback interfaces")
	flags.BoolVar(&opts.stats, "stats", true, "print final capture statistics")
	flags.Usage = func() {
		fmt.Fprintf(stderr, "Passive LLDP, CDP, MNDP, and mDNS discovery. No probes are transmitted.\n\nUsage:\n  omnidiscover [options]\n\nOptions:\n")
		flags.PrintDefaults()
		fmt.Fprintf(stderr, "\nExamples:\n  omnidiscover -protocols mdns,mndp\n  omnidiscover -interfaces en0 -protocols all -json\n  omnidiscover -interfaces eth0 -protocols lldp,cdp -duration 30s\n")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "omnidiscover: unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return 2
	}

	protocols, err := parseProtocols(opts.protocols)
	if err != nil {
		fmt.Fprintf(stderr, "omnidiscover: %v\n", err)
		return 2
	}
	config := omnidiscover.Config{
		Interfaces:      splitList(opts.interfaces),
		Protocols:       protocols,
		IncludeLoopback: opts.includeLoopback,
	}
	engine, err := omnidiscover.New(config)
	if err != nil {
		var unsupported *omnidiscover.UnsupportedProtocolsError
		if errors.As(err, &unsupported) {
			fmt.Fprintf(stderr, "omnidiscover: %s live capture supports MNDP and mDNS only; use supplied frames with the standalone LLDP/CDP decoders\n", unsupported.GOOS)
		} else {
			fmt.Fprintf(stderr, "omnidiscover: %v\n", err)
		}
		return 1
	}
	defer engine.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if opts.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.duration)
		defer cancel()
	}

	printer := eventPrinter{out: stdout, json: opts.json}
	if opts.json {
		printer.encoder = json.NewEncoder(stdout)
		printer.encoder.SetEscapeHTML(false)
	} else if opts.plain {
		fmt.Fprintf(stdout, "omnidiscover: passive capture started on %s; protocols=%s; press Ctrl-C to stop\n", interfaceDescription(config.Interfaces), protocolDescription(protocols))
	}
	if !opts.json && !opts.plain {
		err = runDashboard(ctx, engine, dashboardConfig{interfaces: interfaceDescription(config.Interfaces), protocols: protocolDescription(protocols)})
		var initError *dashboardInitError
		if errors.As(err, &initError) {
			fmt.Fprintf(stderr, "omnidiscover: terminal dashboard unavailable (%v); using plain output\n", initError.err)
			fmt.Fprintf(stdout, "omnidiscover: passive capture started on %s; protocols=%s; press Ctrl-C to stop\n", interfaceDescription(config.Interfaces), protocolDescription(protocols))
			err = engine.Run(ctx, printer.handle)
		}
	} else {
		err = engine.Run(ctx, printer.handle)
	}
	if opts.stats && (opts.json || opts.plain) {
		printer.printStats(engine.Stats())
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(stderr, "omnidiscover: capture failed: %v\n", err)
		if runtime.GOOS == "linux" && protocols&(omnidiscover.ProtocolsLLDP|omnidiscover.ProtocolsCDP) != 0 {
			fmt.Fprintln(stderr, "hint: grant CAP_NET_RAW or run with sufficient raw-socket privileges")
		}
		if runtime.GOOS == "darwin" && protocols&(omnidiscover.ProtocolsLLDP|omnidiscover.ProtocolsCDP) != 0 {
			fmt.Fprintln(stderr, "hint: LLDP/CDP capture requires permission to open /dev/bpf")
		}
		return 1
	}
	return 0
}

func parseProtocols(value string) (omnidiscover.ProtocolSet, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || value == "default" {
		return 0, nil
	}
	if value == "all" {
		return omnidiscover.ProtocolsAll, nil
	}
	var result omnidiscover.ProtocolSet
	for _, name := range strings.Split(value, ",") {
		switch strings.TrimSpace(name) {
		case "lldp":
			result |= omnidiscover.ProtocolsLLDP
		case "cdp":
			result |= omnidiscover.ProtocolsCDP
		case "mndp":
			result |= omnidiscover.ProtocolsMNDP
		case "mdns", "bonjour", "dns-sd", "dnssd":
			result |= omnidiscover.ProtocolsMDNS
		case "":
			return 0, errors.New("empty protocol name")
		default:
			return 0, fmt.Errorf("unknown protocol %q", strings.TrimSpace(name))
		}
	}
	return result, nil
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := parts[:0]
	for _, part := range parts {
		if name := strings.TrimSpace(part); name != "" {
			out = append(out, name)
		}
	}
	return out
}

type eventPrinter struct {
	out     io.Writer
	json    bool
	encoder *json.Encoder
}

func (p *eventPrinter) handle(event omnidiscover.EventView) {
	if event.Device == nil || event.Link == nil {
		return
	}
	view := makeOutputEvent(event)
	if p.json {
		_ = p.encoder.Encode(view)
		return
	}
	fmt.Fprintf(p.out, "%s %-7s device=%s name=%q mac=%s vendor=%q uptime=%s addresses=%s link=%s interface=%s protocols=%s",
		view.Time, view.Event, view.DeviceKey, view.Name, view.MAC, view.Vendor, view.Uptime, strings.Join(view.Addresses, ","), view.LinkKind, view.Interface, strings.Join(view.Protocols, ","))
	if view.RemotePort != "" {
		fmt.Fprintf(p.out, " remote-port=%q", view.RemotePort)
	}
	if view.Class != "" {
		fmt.Fprintf(p.out, " class=%q rule=%q", view.Class, view.Rule)
	}
	fprintln(p.out)
}

func (p *eventPrinter) printStats(stats omnidiscover.Statistics) {
	view := statsOutput{
		Type: "stats", Captured: stats.Captured, Events: stats.Events,
		OutputDropped: stats.OutputDropped, DeviceHighWater: stats.DeviceHighWater,
		LinkHighWater: stats.LinkHighWater, DNSHighWater: stats.DNSHighWater,
		DeviceEvictions: stats.DeviceEvictions, LinkEvictions: stats.LinkEvictions,
		DNSEvictions: stats.DNSEvictions,
	}
	for protocol := omnidiscover.ProtocolLLDP; protocol <= omnidiscover.ProtocolMDNS; protocol++ {
		view.Protocols = append(view.Protocols, protocolStats{
			Protocol: protocol.String(), Routed: stats.Routed[protocol], Dropped: stats.Dropped[protocol],
			Malformed: stats.Malformed[protocol], Ignored: stats.Ignored[protocol], Partial: stats.Partial[protocol],
		})
	}
	if p.json {
		_ = p.encoder.Encode(view)
		return
	}
	var routed, dropped, ignored, malformed, partial uint64
	for protocol := omnidiscover.ProtocolLLDP; protocol <= omnidiscover.ProtocolMDNS; protocol++ {
		routed += stats.Routed[protocol]
		dropped += stats.Dropped[protocol]
		ignored += stats.Ignored[protocol]
		malformed += stats.Malformed[protocol]
		partial += stats.Partial[protocol]
	}
	fmt.Fprintf(p.out, "stats: captured=%d routed=%d ignored=%d malformed=%d partial=%d dropped=%d events=%d output-dropped=%d devices-high=%d links-high=%d dns-high=%d evictions=%d/%d/%d\n",
		view.Captured, routed, ignored, malformed, partial, dropped, view.Events, view.OutputDropped, view.DeviceHighWater, view.LinkHighWater,
		view.DNSHighWater, view.DeviceEvictions, view.LinkEvictions, view.DNSEvictions)
}

type outputEvent struct {
	Type       string   `json:"type"`
	Time       string   `json:"time"`
	Event      string   `json:"event"`
	Changed    uint64   `json:"changed"`
	DeviceKey  string   `json:"device_key"`
	Name       string   `json:"name,omitempty"`
	HostName   string   `json:"host_name,omitempty"`
	Model      string   `json:"model,omitempty"`
	Platform   string   `json:"platform,omitempty"`
	Software   string   `json:"software,omitempty"`
	Addresses  []string `json:"addresses,omitempty"`
	MAC        string   `json:"mac,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	Uptime     string   `json:"uptime,omitempty"`
	UptimeSecs uint64   `json:"uptime_seconds,omitempty"`
	Protocols  []string `json:"protocols"`
	Class      string   `json:"class,omitempty"`
	Rule       string   `json:"matched_rule,omitempty"`
	LinkKind   string   `json:"link_kind"`
	Interface  string   `json:"interface,omitempty"`
	SourceMAC  string   `json:"source_mac,omitempty"`
	RemotePort string   `json:"remote_port,omitempty"`
	VLANs      []uint16 `json:"vlans,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
}

func makeOutputEvent(event omnidiscover.EventView) outputEvent {
	d, link := event.Device, event.Link
	mac := bestDeviceMAC(d)
	now := time.Now()
	uptime := uptimeSummary(d, now)
	var uptimeSeconds uint64
	if d.Uptime.Valid {
		uptimeSeconds = uint64(d.Uptime.Current(now) / time.Second)
	} else {
		uptime = ""
	}
	out := outputEvent{
		Type: "event", Time: link.LastSeen.UTC().Format(time.RFC3339Nano), Event: eventKind(event.Kind),
		Changed: uint64(event.Changed), DeviceKey: deviceKey(d.Key), Name: string(d.SystemName.Current()),
		HostName: string(d.HostName.Current()), Model: string(d.Model.Current()), Platform: string(d.Platform.Current()),
		Software: string(d.SoftwareVersion.Current()), MAC: macString(mac), Vendor: vendorSummary(d), Uptime: uptime, UptimeSecs: uptimeSeconds, Protocols: protocolNames(d.Protocols), Class: string(d.Class),
		Rule: string(d.MatchedRule), LinkKind: linkKind(link.Kind), Interface: string(link.LocalInterface),
		SourceMAC: macString(link.ObservedSourceMAC), RemotePort: string(link.RemotePort.Value), VLANs: link.VLANs,
	}
	for _, address := range d.Addresses {
		out.Addresses = append(out.Addresses, address.String())
	}
	if !link.ExpiresAt.IsZero() {
		out.ExpiresAt = link.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

type protocolStats struct {
	Protocol  string `json:"protocol"`
	Routed    uint64 `json:"routed"`
	Dropped   uint64 `json:"dropped"`
	Malformed uint64 `json:"malformed"`
	Ignored   uint64 `json:"ignored"`
	Partial   uint64 `json:"partial"`
}

type statsOutput struct {
	Type            string          `json:"type"`
	Captured        uint64          `json:"captured"`
	Events          uint64          `json:"events"`
	OutputDropped   uint64          `json:"output_dropped"`
	DeviceHighWater uint64          `json:"device_high_water"`
	LinkHighWater   uint64          `json:"link_high_water"`
	DNSHighWater    uint64          `json:"dns_high_water"`
	DeviceEvictions uint64          `json:"device_evictions"`
	LinkEvictions   uint64          `json:"link_evictions"`
	DNSEvictions    uint64          `json:"dns_evictions"`
	Protocols       []protocolStats `json:"protocols"`
}

func protocolNames(set omnidiscover.ProtocolSet) []string {
	out := make([]string, 0, 4)
	for protocol := omnidiscover.ProtocolLLDP; protocol <= omnidiscover.ProtocolMDNS; protocol++ {
		if set.Has(protocol) {
			out = append(out, protocol.String())
		}
	}
	return out
}

func protocolDescription(set omnidiscover.ProtocolSet) string {
	if set == 0 {
		if runtime.GOOS == "windows" {
			return "mndp,mdns (platform default)"
		}
		return "lldp,cdp,mndp,mdns (platform default)"
	}
	return strings.Join(protocolNames(set), ",")
}

func interfaceDescription(interfaces []string) string {
	if len(interfaces) == 0 {
		return "all eligible interfaces"
	}
	return strings.Join(interfaces, ",")
}

func eventKind(kind omnidiscover.EventKind) string {
	switch kind {
	case omnidiscover.EventAdded:
		return "added"
	case omnidiscover.EventChanged:
		return "changed"
	case omnidiscover.EventExpired:
		return "expired"
	case omnidiscover.EventEvicted:
		return "evicted"
	default:
		return "unknown"
	}
}

func linkKind(kind omnidiscover.LinkKind) string {
	if kind == omnidiscover.PhysicalAdjacency {
		return "physical-adjacency"
	}
	if kind == omnidiscover.SegmentPresence {
		return "segment-presence"
	}
	return "unknown"
}

func deviceKey(key omnidiscover.DeviceKey) string {
	switch key.Kind {
	case omnidiscover.DeviceKeyMAC:
		return "mac:" + macString(key.MAC)
	case omnidiscover.DeviceKeyIP:
		return fmt.Sprintf("ip:%s%%%d", key.IP, key.InterfaceIndex)
	default:
		return "unknown"
	}
}

func macString(mac omnidiscover.MAC) string {
	if mac.IsZero() {
		return ""
	}
	return net.HardwareAddr(mac[:]).String()
}

func fprintln(w io.Writer) { _, _ = fmt.Fprintln(w) }
