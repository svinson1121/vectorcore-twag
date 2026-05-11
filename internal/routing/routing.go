package routing

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

type Manager struct {
	cfg config.RoutingConfig
	log *slog.Logger
}

func New(cfg config.RoutingConfig, log *slog.Logger) *Manager {
	return &Manager{cfg: cfg, log: log}
}

func (m *Manager) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.cfg.EnableIPForwarding {
		m.log.Info("routing hook would enable linux ip forwarding")
	}
	if m.cfg.NATEnabled {
		if m.cfg.NATInterface == "" {
			return fmt.Errorf("routing nat_interface is required when nat is enabled")
		}
		m.log.Info("routing hook would enable nat", "interface", m.cfg.NATInterface)
	}
	return nil
}

func (m *Manager) Install(sess *session.Session) error {
	if sess == nil {
		return fmt.Errorf("session is required")
	}
	if sess.SubscriberIP == nil {
		return fmt.Errorf("subscriber ip is required for routing install")
	}
	if m.cfg.InstallRoutes {
		m.log.Info("routing hook would install subscriber route",
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
		m.log.Info("routing hook would remove subscriber route",
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

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
