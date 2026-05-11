package pgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

const (
	ModeStub = "stub"
	ModeGTP  = "gtp"
)

var ErrNotImplemented = errors.New("pgw client not implemented")

type Client interface {
	Probe(ctx context.Context) error
	CreateSession(ctx context.Context, sess *session.Session) (*CreateSessionResult, error)
	DeleteSession(ctx context.Context, sess *session.Session) error
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

func NewClient(cfg config.PGWConfig, log *slog.Logger) (Client, error) {
	switch cfg.Mode {
	case "", ModeStub:
		return NewStub(cfg, log), nil
	case ModeGTP:
		return NewGTP(cfg, log)
	default:
		return nil, fmt.Errorf("unsupported pgw mode %q", cfg.Mode)
	}
}
