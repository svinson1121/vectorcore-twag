package accessside

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
	"github.com/vishvananda/netlink"
)

type Manager struct {
	cfg      *config.Config
	sessions *session.Manager
	log      *slog.Logger
	dhcp     *DHCPServer
	arp      *ARPProxy
	nl       netlinkHandle
}

type netlinkHandle interface {
	LinkByName(string) (netlink.Link, error)
	NeighSet(*netlink.Neigh) error
	NeighDel(*netlink.Neigh) error
}

func New(cfg *config.Config, sessions *session.Manager, log *slog.Logger) *Manager {
	return &Manager{
		cfg:      cfg,
		sessions: sessions,
		log:      log,
		dhcp:     NewDHCPServer(cfg.Access.DHCP, sessions, log),
		arp:      NewARPProxy(cfg.Access.ARPProxy, sessions, log),
	}
}

func (m *Manager) Start(context.Context) error {
	if m.cfg == nil {
		return nil
	}
	if err := m.dhcp.Start(); err != nil {
		return err
	}
	if err := m.arp.Start(); err != nil {
		_ = m.dhcp.Stop()
		return err
	}
	if m.cfg.Access.Forwarding.Enabled {
		handle, err := netlink.NewHandle()
		if err != nil {
			_ = m.dhcp.Stop()
			_ = m.arp.Stop()
			return fmt.Errorf("open access forwarding netlink handle: %w", err)
		}
		m.nl = handle
		m.log.Info("access forwarding initialized", "interface", m.cfg.Access.Forwarding.Interface, "virtual_gateway_ip", m.cfg.Access.Forwarding.VirtualGatewayIP)
	}
	return nil
}

func (m *Manager) Stop() error {
	var errs []error
	if m.dhcp != nil {
		errs = append(errs, m.dhcp.Stop())
	}
	if m.arp != nil {
		errs = append(errs, m.arp.Stop())
	}
	if h, ok := m.nl.(*netlink.Handle); ok {
		h.Close()
	}
	return joinErrors(errs...)
}

func (m *Manager) AddSession(ctx context.Context, sess *session.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sess == nil || !m.cfg.Access.Forwarding.Enabled {
		return nil
	}
	if m.cfg.Access.Forwarding.RequireAuthorizedSession && sess.State != session.Active {
		return nil
	}
	if sess.SubscriberIP == nil || sess.MACAddress == "" {
		return nil
	}
	if err := m.installNeighbor(sess); err != nil {
		return err
	}
	m.log.Info("access forwarding neighbor installed",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"mac", sess.MACAddress,
		"subscriber_ip", sess.SubscriberIP.String(),
		"interface", m.cfg.Access.Forwarding.Interface,
	)
	return nil
}

func (m *Manager) RemoveSession(ctx context.Context, sess *session.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sess == nil {
		return nil
	}
	if m.dhcp != nil {
		m.dhcp.RemoveSession(sess)
	}
	if !m.cfg.Access.Forwarding.Enabled || sess.SubscriberIP == nil || sess.MACAddress == "" {
		return nil
	}
	if err := m.removeNeighbor(sess); err != nil {
		return err
	}
	m.log.Info("access forwarding neighbor removed",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"mac", sess.MACAddress,
		"subscriber_ip", sess.SubscriberIP.String(),
		"interface", m.cfg.Access.Forwarding.Interface,
	)
	return nil
}

func (m *Manager) installNeighbor(sess *session.Session) error {
	if m.nl == nil {
		return nil
	}
	link, err := m.nl.LinkByName(m.cfg.Access.Forwarding.Interface)
	if err != nil {
		return fmt.Errorf("lookup access forwarding interface %q: %w", m.cfg.Access.Forwarding.Interface, err)
	}
	mac, err := net.ParseMAC(sess.MACAddress)
	if err != nil {
		return fmt.Errorf("parse session MAC %q: %w", sess.MACAddress, err)
	}
	return m.nl.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       netlink.FAMILY_V4,
		State:        netlink.NUD_PERMANENT,
		IP:           sess.SubscriberIP.To4(),
		HardwareAddr: mac,
	})
}

func (m *Manager) removeNeighbor(sess *session.Session) error {
	if m.nl == nil {
		return nil
	}
	link, err := m.nl.LinkByName(m.cfg.Access.Forwarding.Interface)
	if err != nil {
		return fmt.Errorf("lookup access forwarding interface %q: %w", m.cfg.Access.Forwarding.Interface, err)
	}
	mac, err := net.ParseMAC(sess.MACAddress)
	if err != nil {
		return fmt.Errorf("parse session MAC %q: %w", sess.MACAddress, err)
	}
	err = m.nl.NeighDel(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       netlink.FAMILY_V4,
		IP:           sess.SubscriberIP.To4(),
		HardwareAddr: mac,
	})
	if err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func ethernetSrc(frame []byte) net.HardwareAddr {
	if len(frame) < 12 {
		return nil
	}
	return append(net.HardwareAddr(nil), frame[6:12]...)
}

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func firstIP(values ...net.IP) net.IP {
	for _, ip := range values {
		if ip != nil {
			return ip
		}
	}
	return nil
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func joinErrors(errs ...error) error {
	return errors.Join(errs...)
}

func isNotFound(err error) bool {
	var linkNotFound netlink.LinkNotFoundError
	return errors.As(err, &linkNotFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
}
