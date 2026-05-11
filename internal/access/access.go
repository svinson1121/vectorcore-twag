package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/vectorcore/twag/internal/config"
)

const (
	ModeEthernet = "ethernet"
	ModeGRE      = "gre"
	ModeL2TPv3   = "l2tpv3"
)

var ErrNotImplemented = errors.New("access driver not implemented")

type Driver interface {
	Start(ctx context.Context) error
	Stop() error
	Type() string
}

func NewDriver(cfg config.AccessConfig, log *slog.Logger) (Driver, error) {
	switch cfg.Mode {
	case "", ModeEthernet:
		return NewEthernet(cfg.Interface, log), nil
	case ModeGRE:
		return NewGRE(log), nil
	case ModeL2TPv3:
		return NewL2TPv3(log), nil
	default:
		return nil, fmt.Errorf("unsupported access mode %q", cfg.Mode)
	}
}
