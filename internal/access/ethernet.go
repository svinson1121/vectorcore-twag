package access

import (
	"context"
	"fmt"
	"log/slog"
)

type EthernetDriver struct {
	iface string
	log   *slog.Logger
}

func NewEthernet(iface string, log *slog.Logger) *EthernetDriver {
	return &EthernetDriver{iface: iface, log: log}
}

func (d *EthernetDriver) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.iface == "" {
		return fmt.Errorf("ethernet access interface is required")
	}
	d.log.Info("access driver ethernet initialized", "interface", d.iface)
	return nil
}

func (d *EthernetDriver) Stop() error {
	d.log.Info("access driver ethernet stopped", "interface", d.iface)
	return nil
}

func (d *EthernetDriver) Type() string { return ModeEthernet }
