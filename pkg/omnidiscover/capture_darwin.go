//go:build darwin

package omnidiscover

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type darwinBPFBackend struct {
	fd         int
	iface      net.Interface
	bufferSize int
	once       sync.Once
}

func openCaptureBackends(cfg Config) ([]captureBackend, error) {
	ifaces, err := captureInterfaces(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Protocols&(ProtocolsLLDP|ProtocolsCDP) == 0 {
		return openUDPBackends(cfg, ifaces)
	}
	// Darwin uses BPF only for protocols that require link-layer visibility.
	// Passive UDP sockets are more reliable for multicast and broadcast traffic
	// on Wi-Fi interfaces and keep ordinary IP traffic out of the BPF path.
	l2cfg := cfg
	l2cfg.Protocols &= ProtocolsLLDP | ProtocolsCDP
	out := make([]captureBackend, 0, len(ifaces)+4)
	for i := range ifaces {
		b, openErr := newDarwinBPFBackend(l2cfg, ifaces[i])
		if openErr != nil {
			for _, x := range out {
				_ = x.close()
			}
			return nil, openErr
		}
		out = append(out, b)
	}
	if cfg.Protocols&(ProtocolsMNDP|ProtocolsMDNS) != 0 {
		udpCfg := cfg
		udpCfg.Protocols &= ProtocolsMNDP | ProtocolsMDNS
		udp, openErr := openUDPBackends(udpCfg, ifaces)
		if openErr != nil {
			for _, backend := range out {
				_ = backend.close()
			}
			return nil, openErr
		}
		out = append(out, udp...)
	}
	return out, nil
}

func newDarwinBPFBackend(cfg Config, ifi net.Interface) (*darwinBPFBackend, error) {
	fd := -1
	var err error
	for i := 0; i < 256; i++ {
		fd, err = unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EBUSY) {
			return nil, fmt.Errorf("omnidiscover: open BPF (root or BPF access required): %w", err)
		}
	}
	if fd < 0 {
		return nil, fmt.Errorf("omnidiscover: no free /dev/bpf device: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Close(fd)
		}
	}()
	var ifreq [32]byte
	copy(ifreq[:], ifi.Name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&ifreq[0]))); errno != 0 {
		return nil, fmt.Errorf("omnidiscover: bind BPF to %s: %w", ifi.Name, errno)
	}
	if err = unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return nil, fmt.Errorf("omnidiscover: enable immediate BPF reads on %s: %w", ifi.Name, err)
	}
	if err = unix.IoctlSetPointerInt(fd, unix.BIOCSSEESENT, 0); err != nil {
		return nil, fmt.Errorf("omnidiscover: disable locally sent BPF packets on %s: %w", ifi.Name, err)
	}
	bufferSize, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil {
		return nil, fmt.Errorf("omnidiscover: get BPF buffer length on %s: %w", ifi.Name, err)
	}
	ins := discoveryFilter(cfg.Protocols, cfg.MaxFrameSize)
	bpfIns := make([]unix.BpfInsn, len(ins))
	for i := range ins {
		bpfIns[i] = unix.BpfInsn{Code: ins[i].code, Jt: ins[i].jt, Jf: ins[i].jf, K: ins[i].k}
	}
	if len(bpfIns) != 0 {
		program := unix.BpfProgram{Len: uint32(len(bpfIns)), Insns: &bpfIns[0]}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETF), uintptr(unsafe.Pointer(&program))); errno != 0 {
			return nil, fmt.Errorf("omnidiscover: attach BPF filter: %w", errno)
		}
	}
	cleanup = false
	return &darwinBPFBackend{fd: fd, iface: ifi, bufferSize: bufferSize}, nil
}

func (b *darwinBPFBackend) run(ctx context.Context, emit func(captureView)) error {
	buf := make([]byte, b.bufferSize)
	for {
		_, err := unix.Poll([]unix.PollFd{{Fd: int32(b.fd), Events: unix.POLLIN}}, 500)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return nil
			}
			return err
		}
		n, err := unix.Read(b.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return nil
			}
			return err
		}
		for off := 0; off+unix.SizeofBpfHdr <= n; {
			h := buf[off:n]
			sec := int64(int32(binary.NativeEndian.Uint32(h[0:4])))
			usec := int64(int32(binary.NativeEndian.Uint32(h[4:8])))
			caplen := int(binary.NativeEndian.Uint32(h[8:12]))
			hdrlen := int(binary.NativeEndian.Uint16(h[16:18]))
			start, end := off+hdrlen, off+hdrlen+caplen
			if hdrlen >= unix.SizeofBpfHdr && caplen >= 14 && start >= off && end <= n {
				emit(captureView{data: buf[start:end], interfaceName: b.iface.Name, interfaceIndex: b.iface.Index, timestamp: time.Unix(sec, usec*1000).UTC(), frame: true})
			}
			recordLen := hdrlen + caplen
			aligned := (recordLen + unix.BPF_ALIGNMENT - 1) &^ (unix.BPF_ALIGNMENT - 1)
			if aligned <= 0 {
				break
			}
			off += aligned
		}
	}
}

func (b *darwinBPFBackend) close() error {
	var err error
	b.once.Do(func() { err = unix.Close(b.fd) })
	return err
}
