package pgw

import (
	"context"
	"log/slog"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/gtp"
	"github.com/vectorcore/twag/internal/session"
)

type GTPClient struct {
	inner *gtp.GTPClient
}

func NewGTP(cfg config.PGWConfig, gtpCfg config.GTPConfig, log *slog.Logger) (*GTPClient, error) {
	inner, err := gtp.NewGTP(cfg, gtpCfg.ControlEcho, log)
	if err != nil {
		return nil, err
	}
	return &GTPClient{inner: inner}, nil
}

func (c *GTPClient) Probe(ctx context.Context) error {
	return c.inner.Probe(ctx)
}

func (c *GTPClient) StartEchoWatchdog(ctx context.Context) {
	c.inner.StartEchoWatchdog(ctx)
}

func (c *GTPClient) CreateSession(ctx context.Context, sess *session.Session) (*CreateSessionResult, error) {
	result, err := c.inner.CreateSession(ctx, sess)
	if err != nil {
		return nil, err
	}
	return &CreateSessionResult{
		SubscriberIP:   result.SubscriberIP,
		GatewayIP:      result.GatewayIP,
		PGWControlIP:   result.PGWControlIP,
		PGWUserIP:      result.PGWUserIP,
		GTPCTEID:       result.GTPCTEID,
		LocalGTPUTEID:  result.LocalGTPUTEID,
		RemoteGTPUTEID: result.RemoteGTPUTEID,
	}, nil
}

func (c *GTPClient) DeleteSession(ctx context.Context, sess *session.Session) error {
	return c.inner.DeleteSession(ctx, sess)
}

func (c *GTPClient) Type() string { return ModeGTP }

func (c *GTPClient) Close() error {
	return c.inner.Close()
}
