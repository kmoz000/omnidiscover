package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/kmoz000/omnidiscover/pkg/omnidiscover"
)

const dashboardRefresh = 500 * time.Millisecond

type dashboardConfig struct {
	interfaces string
	protocols  string
}

type dashboardInitError struct{ err error }

func (e *dashboardInitError) Error() string { return "initialize terminal dashboard: " + e.err.Error() }
func (e *dashboardInitError) Unwrap() error { return e.err }

type dashboardFilter uint8

const (
	filterAll dashboardFilter = iota
	filterLLDP
	filterCDP
	filterMNDP
	filterMDNS
	filterPhysical
	filterSegment
)

type dashboard struct {
	engine        *omnidiscover.Engine
	config        dashboardConfig
	protocolTable *widgets.Table
	discovery     *widgets.Table
	help          *widgets.Paragraph
	snapshot      omnidiscover.Snapshot
	devices       map[omnidiscover.DeviceKey]*omnidiscover.DiscoveredDevice
	rows          []dashboardRow
	filter        dashboardFilter
	offset        int
	width         int
	height        int
}

type dashboardRow struct {
	device    *omnidiscover.DiscoveredDevice
	link      *omnidiscover.DiscoveredLink
	name      string
	address   string
	platform  string
	neighbor  string
	protocols string
	lastSeen  time.Time
}

func runDashboard(parent context.Context, engine *omnidiscover.Engine, config dashboardConfig) error {
	if err := ui.Init(); err != nil {
		return &dashboardInitError{err: err}
	}
	defer ui.Close()

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- engine.Run(ctx, nil) }()

	d := newDashboard(engine, config)
	d.refresh()
	events := ui.PollEvents()
	ticker := time.NewTicker(dashboardRefresh)
	defer ticker.Stop()
	for {
		select {
		case err := <-errCh:
			return normalizedRunError(err)
		case <-parent.Done():
			cancel()
			return normalizedRunError(<-errCh)
		case <-ticker.C:
			d.refresh()
		case event := <-events:
			if d.handleEvent(event) {
				cancel()
				return normalizedRunError(<-errCh)
			}
		}
	}
}

func normalizedRunError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func newDashboard(engine *omnidiscover.Engine, config dashboardConfig) *dashboard {
	protocolTable := widgets.NewTable()
	protocolTable.Title = " Protocol Findings "
	protocolTable.RowSeparator = false
	protocolTable.FillRow = true
	protocolTable.TextStyle = ui.NewStyle(ui.ColorWhite)
	protocolTable.BorderStyle = ui.NewStyle(ui.ColorCyan)
	protocolTable.RowStyles[0] = ui.NewStyle(ui.ColorCyan, ui.ColorClear, ui.ModifierBold)

	discovery := widgets.NewTable()
	discovery.Title = " Discovered Links · ALL "
	discovery.RowSeparator = false
	discovery.FillRow = true
	discovery.TextStyle = ui.NewStyle(ui.ColorWhite)
	discovery.BorderStyle = ui.NewStyle(ui.ColorBlue)
	discovery.RowStyles[0] = ui.NewStyle(ui.ColorWhite, ui.ColorBlue, ui.ModifierBold)

	help := widgets.NewParagraph()
	help.Border = false
	help.TextStyle = ui.NewStyle(ui.ColorWhite)

	return &dashboard{
		engine: engine, config: config, protocolTable: protocolTable, discovery: discovery, help: help,
		devices: make(map[omnidiscover.DeviceKey]*omnidiscover.DiscoveredDevice, 128), rows: make([]dashboardRow, 0, 128),
	}
}

func (d *dashboard) handleEvent(event ui.Event) bool {
	switch event.ID {
	case "q", "<C-c>":
		return true
	case "a", "0":
		d.setFilter(filterAll)
	case "1":
		d.setFilter(filterLLDP)
	case "2":
		d.setFilter(filterCDP)
	case "3":
		d.setFilter(filterMNDP)
	case "4":
		d.setFilter(filterMDNS)
	case "p":
		d.setFilter(filterPhysical)
	case "s":
		d.setFilter(filterSegment)
	case "<Up>", "k":
		if d.offset > 0 {
			d.offset--
		}
	case "<Down>", "j":
		d.offset++
	case "<PageUp>":
		d.offset -= max(1, d.visibleRows())
		if d.offset < 0 {
			d.offset = 0
		}
	case "<PageDown>":
		d.offset += max(1, d.visibleRows())
	case "g", "<Home>":
		d.offset = 0
	case "G", "<End>":
		d.offset = len(d.rows)
	case "r", "<Resize>":
	}
	d.refresh()
	return false
}

func (d *dashboard) setFilter(filter dashboardFilter) {
	d.filter = filter
	d.offset = 0
}

func (d *dashboard) refresh() {
	d.engine.Snapshot(&d.snapshot)
	stats := d.engine.Stats()
	d.width, d.height = ui.TerminalDimensions()
	if d.width < 40 || d.height < 14 {
		d.help.Text = "Terminal too small. Resize to at least 40x14, or press q to quit."
		d.help.SetRect(0, 0, max(1, d.width), max(1, d.height))
		ui.Render(d.help)
		return
	}
	d.rebuildRows()
	d.layout()
	d.updateProtocolTable(stats)
	d.updateDiscoveryTable(time.Now())
	d.help.Text = fmt.Sprintf("[a/0](fg:cyan) all  [1](fg:cyan) LLDP  [2](fg:cyan) CDP  [3](fg:cyan) MNDP  [4](fg:cyan) mDNS  [p](fg:cyan) physical  [s](fg:cyan) segment  [j/k](fg:cyan) scroll  [q](fg:red) quit   •   %s   •   %s", d.config.interfaces, d.config.protocols)
	ui.Render(d.protocolTable, d.discovery, d.help)
}

func (d *dashboard) layout() {
	statsHeight := 8
	d.protocolTable.SetRect(0, 0, d.width, statsHeight)
	d.discovery.SetRect(0, statsHeight, d.width, d.height-2)
	d.help.SetRect(0, d.height-2, d.width, d.height)
}

func (d *dashboard) updateProtocolTable(stats omnidiscover.Statistics) {
	deviceCounts, linkCounts := [5]int{}, [5]int{}
	for i := range d.snapshot.Devices {
		for protocol := omnidiscover.ProtocolLLDP; protocol <= omnidiscover.ProtocolMDNS; protocol++ {
			if d.snapshot.Devices[i].Protocols.Has(protocol) {
				deviceCounts[protocol]++
			}
		}
	}
	for i := range d.snapshot.Links {
		for protocol := omnidiscover.ProtocolLLDP; protocol <= omnidiscover.ProtocolMDNS; protocol++ {
			if d.snapshot.Links[i].Protocols.Has(protocol) {
				linkCounts[protocol]++
			}
		}
	}
	d.protocolTable.Rows = d.protocolTable.Rows[:0]
	d.protocolTable.Rows = append(d.protocolTable.Rows, []string{"Protocol", "Devices", "Links", "Routed", "Dropped", "Ignored", "Malformed", "Partial", "Health"})
	for protocol := omnidiscover.ProtocolLLDP; protocol <= omnidiscover.ProtocolMDNS; protocol++ {
		health := "OK"
		if stats.Dropped[protocol] != 0 {
			health = "DROPS"
		}
		if stats.Malformed[protocol] != 0 {
			health = "MALFORMED"
		}
		protocolName := strings.ToUpper(protocol.String())
		if protocol == omnidiscover.ProtocolMDNS {
			protocolName = "MDNS/NSD"
		}
		d.protocolTable.Rows = append(d.protocolTable.Rows, []string{
			protocolName, strconv.Itoa(deviceCounts[protocol]), strconv.Itoa(linkCounts[protocol]),
			formatCount(stats.Routed[protocol]), formatCount(stats.Dropped[protocol]), formatCount(stats.Ignored[protocol]), formatCount(stats.Malformed[protocol]),
			formatCount(stats.Partial[protocol]), health,
		})
	}
	d.protocolTable.ColumnWidths = fitWidths(d.width-2, []int{11, 9, 9, 11, 11, 11, 12, 10, 12})
	colors := [...]ui.Color{ui.ColorClear, ui.ColorGreen, ui.ColorYellow, ui.ColorMagenta, ui.ColorCyan}
	for protocol := omnidiscover.ProtocolLLDP; protocol <= omnidiscover.ProtocolMDNS; protocol++ {
		d.protocolTable.RowStyles[int(protocol)] = ui.NewStyle(colors[protocol])
	}
}

func (d *dashboard) rebuildRows() {
	clear(d.devices)
	for i := range d.snapshot.Devices {
		device := &d.snapshot.Devices[i]
		d.devices[device.Key] = device
	}
	d.rows = d.rows[:0]
	for i := range d.snapshot.Links {
		link := &d.snapshot.Links[i]
		device := d.devices[link.Device]
		if device == nil || !d.matches(link) {
			continue
		}
		name := firstNonEmpty(string(device.SystemName.Current()), string(device.HostName.Current()), string(device.ProtocolDeviceID.Current()), deviceKey(device.Key))
		platform := firstNonEmpty(string(device.Model.Current()), string(device.Platform.Current()), "-")
		if model, platformName := string(device.Model.Current()), string(device.Platform.Current()); model != "" && platformName != "" && model != platformName {
			platform = model + " / " + platformName
		}
		neighbor := firstNonEmpty(string(link.RemoteInterface.Current()), string(link.RemotePort.Value), serviceSummary(device), "-")
		protocolLabel := strings.Join(protocolNames(link.Protocols), "+")
		if link.Protocols.Has(omnidiscover.ProtocolMDNS) && len(device.Services) != 0 {
			protocolLabel = strings.Replace(protocolLabel, "mdns", "mdns/nsd", 1)
			for serviceIndex := range device.Services {
				if device.Services[serviceIndex].Profile() == omnidiscover.ServiceProfileGoogleCast {
					protocolLabel = strings.Replace(protocolLabel, "mdns/nsd", "mdns/cast", 1)
					break
				}
			}
		}
		d.rows = append(d.rows, dashboardRow{
			device: device, link: link, name: name, address: addressSummary(device), platform: platform,
			neighbor: neighbor, protocols: protocolLabel, lastSeen: link.LastSeen,
		})
	}
	sort.SliceStable(d.rows, func(i, j int) bool {
		if !d.rows[i].lastSeen.Equal(d.rows[j].lastSeen) {
			return d.rows[i].lastSeen.After(d.rows[j].lastSeen)
		}
		if d.rows[i].name != d.rows[j].name {
			return d.rows[i].name < d.rows[j].name
		}
		return d.rows[i].link.Key.InterfaceIndex < d.rows[j].link.Key.InterfaceIndex
	})
}

func (d *dashboard) matches(link *omnidiscover.DiscoveredLink) bool {
	switch d.filter {
	case filterLLDP:
		return link.Protocols.Has(omnidiscover.ProtocolLLDP)
	case filterCDP:
		return link.Protocols.Has(omnidiscover.ProtocolCDP)
	case filterMNDP:
		return link.Protocols.Has(omnidiscover.ProtocolMNDP)
	case filterMDNS:
		return link.Protocols.Has(omnidiscover.ProtocolMDNS)
	case filterPhysical:
		return link.Kind == omnidiscover.PhysicalAdjacency
	case filterSegment:
		return link.Kind == omnidiscover.SegmentPresence
	default:
		return true
	}
}

func (d *dashboard) updateDiscoveryTable(now time.Time) {
	d.discovery.Title = fmt.Sprintf(" Discovered Links · %s · %d rows ", d.filter, len(d.rows))
	available := d.visibleRows()
	maxOffset := max(0, len(d.rows)-available)
	if d.offset > maxOffset {
		d.offset = maxOffset
	}
	end := min(len(d.rows), d.offset+available)
	wide := d.width >= 118
	d.discovery.Rows = d.discovery.Rows[:0]
	if wide {
		d.discovery.Rows = append(d.discovery.Rows, []string{"Category", "Device", "Address", "Model / Platform", "Interface", "Neighbor / Service", "VLAN", "Protocols", "Age", "TTL"})
		d.discovery.ColumnWidths = fitWidths(d.width-2, []int{12, 20, 19, 20, 12, 20, 8, 14, 9, 9})
	} else {
		d.discovery.Rows = append(d.discovery.Rows, []string{"Device", "Address", "Interface", "Category", "Protocols", "Age"})
		d.discovery.ColumnWidths = fitWidths(d.width-2, []int{22, 21, 13, 12, 17, 10})
	}
	for _, row := range d.rows[d.offset:end] {
		category := "SEGMENT"
		if row.link.Kind == omnidiscover.PhysicalAdjacency {
			category = "PHYSICAL"
		}
		age := shortDuration(now.Sub(row.lastSeen))
		ttl := shortDuration(time.Until(row.link.ExpiresAt))
		if wide {
			d.discovery.Rows = append(d.discovery.Rows, []string{category, row.name, row.address, row.platform, string(row.link.LocalInterface), row.neighbor, vlanSummary(row.link.VLANs), row.protocols, age, ttl})
		} else {
			d.discovery.Rows = append(d.discovery.Rows, []string{row.name, row.address, string(row.link.LocalInterface), category, row.protocols, age})
		}
	}
}

func (d *dashboard) visibleRows() int { return max(1, d.height-13) }

func (f dashboardFilter) String() string {
	switch f {
	case filterLLDP:
		return "LLDP"
	case filterCDP:
		return "CDP"
	case filterMNDP:
		return "MNDP"
	case filterMDNS:
		return "mDNS"
	case filterPhysical:
		return "PHYSICAL"
	case filterSegment:
		return "SEGMENT"
	default:
		return "ALL"
	}
}

func addressSummary(device *omnidiscover.DiscoveredDevice) string {
	if len(device.Addresses) == 0 {
		return "-"
	}
	out := device.Addresses[0].String()
	if len(device.Addresses) > 1 {
		out += fmt.Sprintf(" +%d", len(device.Addresses)-1)
	}
	return out
}

func serviceSummary(device *omnidiscover.DiscoveredDevice) string {
	if len(device.Services) == 0 {
		return ""
	}
	name := string(device.Services[0].Type)
	if name == "" {
		name = string(device.Services[0].Instance)
	}
	if len(device.Services) > 1 {
		name += fmt.Sprintf(" +%d", len(device.Services)-1)
	}
	return name
}

func vlanSummary(vlans []uint16) string {
	if len(vlans) == 0 {
		return "-"
	}
	if len(vlans) == 1 {
		return strconv.Itoa(int(vlans[0]))
	}
	return fmt.Sprintf("%d +%d", vlans[0], len(vlans)-1)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "-"
}

func fitWidths(available int, desired []int) []int {
	total := 0
	for _, width := range desired {
		total += width
	}
	out := make([]int, len(desired))
	if available >= total {
		copy(out, desired)
		out[len(out)-1] += available - total
		return out
	}
	for i, width := range desired {
		out[i] = max(5, width*available/total)
	}
	return out
}

func formatCount(value uint64) string {
	if value < 1000 {
		return strconv.FormatUint(value, 10)
	}
	if value < 1_000_000 {
		return fmt.Sprintf("%.1fk", float64(value)/1000)
	}
	return fmt.Sprintf("%.1fm", float64(value)/1_000_000)
}

func shortDuration(duration time.Duration) string {
	if duration < 0 {
		duration = 0
	}
	if duration < time.Minute {
		return fmt.Sprintf("%ds", int(duration.Seconds()))
	}
	if duration < time.Hour {
		return fmt.Sprintf("%dm", int(duration.Minutes()))
	}
	return fmt.Sprintf("%dh", int(duration.Hours()))
}
