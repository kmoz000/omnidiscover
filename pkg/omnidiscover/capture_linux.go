//go:build linux

package omnidiscover

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const ethPAll = 0x0003

type linuxRawBackend struct {
	fd         int
	iface      net.Interface
	maxFrame   int
	ring       []byte
	blockSize  int
	blockCount int
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
	out := make([]captureBackend, 0, len(ifaces))
	for i := range ifaces {
		b, openErr := newLinuxRawBackend(cfg, ifaces[i])
		if openErr != nil {
			for _, x := range out {
				_ = x.close()
			}
			return nil, openErr
		}
		out = append(out, b)
	}
	return out, nil
}

func newLinuxRawBackend(cfg Config, ifi net.Interface) (*linuxRawBackend, error) {
	fd, err := openLinuxPacketSocket(cfg, ifi)
	if err != nil {
		return nil, err
	}
	b := &linuxRawBackend{fd: fd, iface: ifi, maxFrame: cfg.MaxFrameSize}
	if ring, blockSize, blockCount, ringErr := setupTPacketV3(fd, cfg.MaxFrameSize); ringErr == nil {
		b.ring, b.blockSize, b.blockCount = ring, blockSize, blockCount
		return b, nil
	}
	_ = unix.Close(fd)
	fd, err = openLinuxPacketSocket(cfg, ifi)
	if err != nil {
		return nil, err
	}
	b.fd = fd
	return b, nil
}

func openLinuxPacketSocket(cfg Config, ifi net.Interface) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(htons16(ethPAll)))
	if err != nil {
		return -1, fmt.Errorf("omnidiscover: AF_PACKET on %s (CAP_NET_RAW required): %w", ifi.Name, err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Close(fd)
		}
	}()
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(ethPAll), Ifindex: ifi.Index}); err != nil {
		return -1, fmt.Errorf("omnidiscover: bind %s: %w", ifi.Name, err)
	}
	_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_ALLMULTI})
	ins := discoveryFilter(cfg.Protocols, cfg.MaxFrameSize)
	filters := make([]unix.SockFilter, len(ins))
	for i := range ins {
		filters[i] = unix.SockFilter{Code: ins[i].code, Jt: ins[i].jt, Jf: ins[i].jf, K: ins[i].k}
	}
	if len(filters) != 0 {
		prog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
		if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
			return -1, fmt.Errorf("omnidiscover: attach packet filter on %s: %w", ifi.Name, err)
		}
	}
	cleanup = false
	return fd, nil
}

func setupTPacketV3(fd, maxFrame int) ([]byte, int, int, error) {
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
		return nil, 0, 0, err
	}
	frameSize := 2048
	for frameSize < maxFrame+256 {
		frameSize <<= 1
	}
	page := unix.Getpagesize()
	blockSize := 1 << 20
	for blockSize < frameSize*16 {
		blockSize <<= 1
	}
	if rem := blockSize % page; rem != 0 {
		blockSize += page - rem
	}
	blockCount := 4
	req := &unix.TpacketReq3{Block_size: uint32(blockSize), Block_nr: uint32(blockCount), Frame_size: uint32(frameSize), Frame_nr: uint32(blockSize / frameSize * blockCount), Retire_blk_tov: 64}
	if err := unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, req); err != nil {
		return nil, 0, 0, err
	}
	ring, err := unix.Mmap(fd, 0, blockSize*blockCount, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		zero := &unix.TpacketReq3{}
		_ = unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, zero)
		return nil, 0, 0, err
	}
	return ring, blockSize, blockCount, nil
}

func (b *linuxRawBackend) run(ctx context.Context, emit func(captureView)) error {
	if len(b.ring) != 0 {
		defer unix.Munmap(b.ring)
		return b.runRing(ctx, emit)
	}
	buf := make([]byte, b.maxFrame)
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
		n, _, err := unix.Recvfrom(b.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return nil
			}
			return err
		}
		emit(captureView{data: buf[:n], interfaceName: b.iface.Name, interfaceIndex: b.iface.Index, timestamp: time.Now().UTC(), frame: true})
	}
}

func (b *linuxRawBackend) runRing(ctx context.Context, emit func(captureView)) error {
	blockIndex := 0
	for {
		block := b.ring[blockIndex*b.blockSize : (blockIndex+1)*b.blockSize]
		if binary.NativeEndian.Uint32(block[8:12])&unix.TP_STATUS_USER == 0 {
			_, err := unix.Poll([]unix.PollFd{{Fd: int32(b.fd), Events: unix.POLLIN}}, 500)
			if ctx.Err() != nil {
				return nil
			}
			if err != nil && !errors.Is(err, unix.EINTR) {
				if errors.Is(err, unix.EBADF) {
					return nil
				}
				return err
			}
			continue
		}
		num := int(binary.NativeEndian.Uint32(block[12:16]))
		off := int(binary.NativeEndian.Uint32(block[16:20]))
		blockLen := int(binary.NativeEndian.Uint32(block[20:24]))
		if blockLen <= 0 || blockLen > len(block) {
			blockLen = len(block)
		}
		for i := 0; i < num && off+40 <= blockLen; i++ {
			h := block[off:blockLen]
			next := int(binary.NativeEndian.Uint32(h[0:4]))
			sec := int64(binary.NativeEndian.Uint32(h[4:8]))
			nsec := int64(binary.NativeEndian.Uint32(h[8:12]))
			snap := int(binary.NativeEndian.Uint32(h[12:16]))
			mac := int(binary.NativeEndian.Uint16(h[24:26]))
			start := off + mac
			end := start + snap
			if snap >= 14 && snap <= b.maxFrame && start >= off && end <= blockLen {
				emit(captureView{data: block[start:end], interfaceName: b.iface.Name, interfaceIndex: b.iface.Index, timestamp: time.Unix(sec, nsec).UTC(), frame: true})
			}
			if next <= 0 {
				break
			}
			off += next
		}
		binary.NativeEndian.PutUint32(block[8:12], unix.TP_STATUS_KERNEL)
		blockIndex = (blockIndex + 1) % b.blockCount
	}
}

func (b *linuxRawBackend) close() error {
	var err error
	b.once.Do(func() { err = unix.Close(b.fd) })
	return err
}
func htons16(v uint16) uint16 { return v<<8 | v>>8 }
