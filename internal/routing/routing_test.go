package routing

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

func TestStartHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := New(config.RoutingConfig{}, slog.New(slog.DiscardHandler))
	if err := m.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context.Canceled", err)
	}
}

func TestStartValidatesNATInterface(t *testing.T) {
	m := New(config.RoutingConfig{NATEnabled: true}, slog.New(slog.DiscardHandler))
	if err := m.Start(context.Background()); err == nil {
		t.Fatalf("expected nat interface error")
	}
}

func TestInstallAndRemoveRouteHooks(t *testing.T) {
	m := New(config.RoutingConfig{
		EnableIPForwarding: true,
		InstallRoutes:      true,
		NATEnabled:         true,
		NATInterface:       "eth0",
	}, slog.New(slog.DiscardHandler))
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	sess := &session.Session{
		ID:              "twag-test",
		IMSI:            "001010000000001",
		SubscriberIP:    net.ParseIP("10.200.0.2"),
		GatewayIP:       net.ParseIP("10.200.0.1"),
		AccessInterface: "eth1",
	}
	if err := m.Install(sess); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if err := m.Remove(sess); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
}

func TestInstallAndRemoveValidateSession(t *testing.T) {
	m := New(config.RoutingConfig{InstallRoutes: true}, slog.New(slog.DiscardHandler))
	if err := m.Install(nil); err == nil {
		t.Fatalf("expected nil session install error")
	}
	if err := m.Remove(nil); err == nil {
		t.Fatalf("expected nil session remove error")
	}
	sess := &session.Session{ID: "twag-test"}
	if err := m.Install(sess); err == nil {
		t.Fatalf("expected missing subscriber ip install error")
	}
	if err := m.Remove(sess); err == nil {
		t.Fatalf("expected missing subscriber ip remove error")
	}
}
