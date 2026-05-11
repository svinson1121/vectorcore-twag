package pgw

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

type StubClient struct {
	cfg config.PGWConfig
	log *slog.Logger
}

func NewStub(cfg config.PGWConfig, log *slog.Logger) *StubClient {
	log.Info("PGW stub initialized", "apn", cfg.APN)
	return &StubClient{cfg: cfg, log: log}
}

func (c *StubClient) Probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (c *StubClient) CreateSession(ctx context.Context, sess *session.Session) (*CreateSessionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, fmt.Errorf("session is required")
	}
	c.log.Info("PGW session create simulated",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"msisdn", sess.MSISDN,
		"mac", sess.MACAddress,
		"apn", sess.APN,
		"subscriber_ip", ipString(sess.SubscriberIP),
		"pgw_control_ip", firstNonEmptyIP(c.cfg.RemotePGWGTPCIP, sess.PGWControlIP),
		"pgw_user_ip", firstNonEmptyIP(c.cfg.RemotePGWGTPUIP, sess.PGWUserIP),
		"state", sess.State,
		"reason", sess.Reason,
	)
	return &CreateSessionResult{
		SubscriberIP: sess.SubscriberIP,
		GatewayIP:    sess.GatewayIP,
		PGWControlIP: net.ParseIP(c.cfg.RemotePGWGTPCIP),
		PGWUserIP:    net.ParseIP(c.cfg.RemotePGWGTPUIP),
	}, nil
}

func (c *StubClient) DeleteSession(ctx context.Context, sess *session.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sess == nil {
		return fmt.Errorf("session is required")
	}
	c.log.Info("PGW session delete simulated", "session_id", sess.ID, "imsi", sess.IMSI, "msisdn", sess.MSISDN, "mac", sess.MACAddress, "apn", sess.APN, "subscriber_ip", ipString(sess.SubscriberIP), "state", sess.State, "reason", sess.Reason)
	return nil
}

func (c *StubClient) Type() string { return ModeStub }

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func firstNonEmptyIP(configured string, fallback net.IP) string {
	if configured != "" {
		return configured
	}
	return ipString(fallback)
}
