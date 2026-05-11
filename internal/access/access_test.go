package access

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/vectorcore/twag/internal/config"
)

func TestNewDriverSelectsEthernetByDefault(t *testing.T) {
	d, err := NewDriver(config.AccessConfig{Interface: "eth1"}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewDriver() error = %v", err)
	}
	if d.Type() != ModeEthernet {
		t.Fatalf("driver type = %q", d.Type())
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatalf("ethernet Start() error = %v", err)
	}
	if err := d.Stop(); err != nil {
		t.Fatalf("ethernet Stop() error = %v", err)
	}
}

func TestEthernetRequiresInterface(t *testing.T) {
	d := NewEthernet("", slog.New(slog.DiscardHandler))
	if err := d.Start(context.Background()); err == nil {
		t.Fatalf("expected missing interface error")
	}
}

func TestEthernetHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := NewEthernet("eth1", slog.New(slog.DiscardHandler))
	if err := d.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context.Canceled", err)
	}
}

func TestGREStubIsExplicitlyNotImplemented(t *testing.T) {
	d, err := NewDriver(config.AccessConfig{Mode: ModeGRE}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewDriver(gre) error = %v", err)
	}
	if d.Type() != ModeGRE {
		t.Fatalf("driver type = %q", d.Type())
	}
	if err := d.Start(context.Background()); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("Start() error = %v, want ErrNotImplemented", err)
	}
	if err := d.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestL2TPv3StubIsExplicitlyNotImplemented(t *testing.T) {
	d, err := NewDriver(config.AccessConfig{Mode: ModeL2TPv3}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewDriver(l2tpv3) error = %v", err)
	}
	if d.Type() != ModeL2TPv3 {
		t.Fatalf("driver type = %q", d.Type())
	}
	if err := d.Start(context.Background()); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("Start() error = %v, want ErrNotImplemented", err)
	}
	if err := d.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestNewDriverRejectsUnknownMode(t *testing.T) {
	_, err := NewDriver(config.AccessConfig{Mode: "wifi"}, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatalf("expected unknown mode error")
	}
}
