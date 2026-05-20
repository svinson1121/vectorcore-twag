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
	if cfg.Interface == "" {
		return nil, fmt.Errorf("access.interface is required")
	}
	return NewEthernet(cfg.Interface, log), nil
}
