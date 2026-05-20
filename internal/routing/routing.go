package routing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
	"github.com/vishvananda/netlink"
)

type Manager struct {
	cfg     config.RoutingConfig
	log     *slog.Logger
	procSys string
	nl      netlinkHandle
}

type netlinkHandle interface {
	LinkByName(string) (netlink.Link, error)
	RouteReplace(*netlink.Route) error
	RouteDel(*netlink.Route) error
}

func New(cfg config.RoutingConfig, log *slog.Logger) *Manager {
	return &Manager{cfg: cfg, log: log, procSys: "/proc/sys"}
}

func (m *Manager) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.cfg.EnableIPForwarding {
		if err := m.writeSysctl("net/ipv4/ip_forward", "1\n"); err != nil {
			return fmt.Errorf("enable linux ip forwarding: %w", err)
		}
		m.log.Info("linux ip forwarding enabled")
	}
	if m.cfg.DisableRPFilter {
		for _, path := range []string{
			"net/ipv4/conf/all/rp_filter",
			"net/ipv4/conf/default/rp_filter",
		} {
			if err := m.writeSysctl(path, "0\n"); err != nil {
				return fmt.Errorf("disable rp_filter %s: %w", path, err)
			}
		}
		m.log.Info("linux rp_filter disabled", "scope", "all,default")
	}
	if m.cfg.InstallRoutes && m.nl == nil {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open routing netlink handle: %w", err)
		}
		m.nl = handle
	}
	return nil
}

func (m *Manager) writeSysctl(path, value string) error {
	return os.WriteFile(filepath.Join(m.procSys, filepath.FromSlash(path)), []byte(value), 0644)
}

func (m *Manager) Install(sess *session.Session) error {
	if sess == nil {
		return fmt.Errorf("session is required")
	}
	if sess.SubscriberIP == nil {
		return fmt.Errorf("subscriber ip is required for routing install")
	}
	if m.cfg.InstallRoutes {
		if sess.AccessInterface == "" {
			return fmt.Errorf("access interface is required for subscriber route install")
		}
		if m.nl == nil {
			handle, err := netlink.NewHandle()
			if err != nil {
				return fmt.Errorf("open routing netlink handle: %w", err)
			}
			m.nl = handle
		}
		link, err := m.nl.LinkByName(sess.AccessInterface)
		if err != nil {
			return fmt.Errorf("lookup access interface %q: %w", sess.AccessInterface, err)
		}
		route := accessRoute(link, sess.SubscriberIP)
		if err := m.nl.RouteReplace(route); err != nil {
			return fmt.Errorf("install subscriber access route %s dev %s: %w", route.Dst.String(), sess.AccessInterface, err)
		}
		m.log.Info("subscriber access route installed",
			"session_id", sess.ID,
			"imsi", sess.IMSI,
			"msisdn", sess.MSISDN,
			"mac", sess.MACAddress,
			"apn", sess.APN,
			"subscriber_ip", sess.SubscriberIP.String(),
			"state", sess.State,
			"reason", sess.Reason,
			"gateway_ip", ipString(sess.GatewayIP),
			"access_interface", sess.AccessInterface,
		)
	}
	return nil
}

func (m *Manager) Remove(sess *session.Session) error {
	if sess == nil {
		return fmt.Errorf("session is required")
	}
	if sess.SubscriberIP == nil {
		return fmt.Errorf("subscriber ip is required for routing remove")
	}
	if m.cfg.InstallRoutes {
		if sess.AccessInterface == "" {
			return fmt.Errorf("access interface is required for subscriber route remove")
		}
		if m.nl == nil {
			return nil
		}
		link, err := m.nl.LinkByName(sess.AccessInterface)
		if err != nil {
			return fmt.Errorf("lookup access interface %q: %w", sess.AccessInterface, err)
		}
		route := accessRoute(link, sess.SubscriberIP)
		if err := m.nl.RouteDel(route); err != nil && !isNotFound(err) {
			return fmt.Errorf("remove subscriber access route %s dev %s: %w", route.Dst.String(), sess.AccessInterface, err)
		}
		m.log.Info("subscriber access route removed",
			"session_id", sess.ID,
			"imsi", sess.IMSI,
			"msisdn", sess.MSISDN,
			"mac", sess.MACAddress,
			"apn", sess.APN,
			"subscriber_ip", sess.SubscriberIP.String(),
			"state", sess.State,
			"reason", sess.Reason,
			"access_interface", sess.AccessInterface,
		)
	}
	return nil
}

func accessRoute(link netlink.Link, ip net.IP) *netlink.Route {
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
	}
}

func isNotFound(err error) bool {
	var linkNotFound netlink.LinkNotFoundError
	return errors.As(err, &linkNotFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
