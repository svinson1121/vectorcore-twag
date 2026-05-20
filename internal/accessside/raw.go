package accessside

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	etherTypeAll  = 0x0003
)

type packetConn interface {
	ReadFrame([]byte) (int, error)
	WriteFrame([]byte, net.HardwareAddr) error
	Close() error
}

type packetSocket struct {
	fd      int
	ifindex int
}

func openPacketSocket(iface string, proto uint16) (*packetSocket, net.Interface, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, net.Interface{}, fmt.Errorf("lookup interface %q: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(proto)))
	if err != nil {
		return nil, *ifi, fmt.Errorf("open packet socket on %s: %w", iface, err)
	}
	addr := &unix.SockaddrLinklayer{Protocol: htons(proto), Ifindex: ifi.Index}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, *ifi, fmt.Errorf("bind packet socket on %s: %w", iface, err)
	}
	return &packetSocket{fd: fd, ifindex: ifi.Index}, *ifi, nil
}

func (s *packetSocket) ReadFrame(buf []byte) (int, error) {
	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	return n, err
}

func (s *packetSocket) WriteFrame(frame []byte, dst net.HardwareAddr) error {
	var addr [8]byte
	copy(addr[:], dst)
	return unix.Sendto(s.fd, frame, 0, &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeAll),
		Ifindex:  s.ifindex,
		Halen:    uint8(len(dst)),
		Addr:     addr,
	})
}

func (s *packetSocket) Close() error {
	if s == nil || s.fd < 0 {
		return nil
	}
	err := unix.Close(s.fd)
	s.fd = -1
	return err
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func runReader(done <-chan struct{}, conn packetConn, fn func([]byte)) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-done:
			return
		default:
		}
		_ = unix.SetsockoptTimeval(getFD(conn), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
		n, err := conn.ReadFrame(buf)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n > 0 {
			frame := append([]byte(nil), buf[:n]...)
			fn(frame)
		}
	}
}

func getFD(conn packetConn) int {
	if ps, ok := conn.(*packetSocket); ok {
		return ps.fd
	}
	return -1
}
