package access

import (
	"context"
	"fmt"
	"log/slog"
)

type GREDriver struct {
	log *slog.Logger
}

func NewGRE(log *slog.Logger) *GREDriver {
	return &GREDriver{log: log}
}

func (d *GREDriver) Start(context.Context) error {
	if d.log != nil {
		d.log.Warn("GRE access driver requested but not implemented")
	}
	return fmt.Errorf("%w: gre", ErrNotImplemented)
}
func (d *GREDriver) Stop() error  { return nil }
func (d *GREDriver) Type() string { return ModeGRE }
