package access

import (
	"context"
	"fmt"
	"log/slog"
)

type L2TPv3Driver struct {
	log *slog.Logger
}

func NewL2TPv3(log *slog.Logger) *L2TPv3Driver {
	return &L2TPv3Driver{log: log}
}

func (d *L2TPv3Driver) Start(context.Context) error {
	if d.log != nil {
		d.log.Warn("L2TPv3 access driver requested but not implemented")
	}
	return fmt.Errorf("%w: l2tpv3", ErrNotImplemented)
}
func (d *L2TPv3Driver) Stop() error  { return nil }
func (d *L2TPv3Driver) Type() string { return ModeL2TPv3 }
