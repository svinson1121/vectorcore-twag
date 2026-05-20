package pgw

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/gtp"
	"github.com/vectorcore/twag/internal/session"
)

const ModeGTP = "gtp"

var ErrNotImplemented = errors.New("pgw client not implemented")

type Client interface {
	Probe(ctx context.Context) error
	StartEchoWatchdog(ctx context.Context)
	CreateSession(ctx context.Context, sess *session.Session) (*CreateSessionResult, error)
	DeleteSession(ctx context.Context, sess *session.Session) error
	Close() error
	Type() string
}

type CreateSessionResult struct {
	SubscriberIP   net.IP
	GatewayIP      net.IP
	PGWControlIP   net.IP
	PGWUserIP      net.IP
	GTPCTEID       uint32
	LocalGTPUTEID  uint32
	RemoteGTPUTEID uint32
}

func IsContextNotFound(err error) bool {
	return gtp.IsContextNotFound(err)
}

func NewClient(cfg config.GTPConfig, log *slog.Logger) (Client, error) {
	return NewGTP(cfg, cfg, log)
}
