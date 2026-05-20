package routing

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
	"github.com/vishvananda/netlink"
)

func TestStartHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := New(config.RoutingConfig{}, slog.New(slog.DiscardHandler))
	if err := m.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context.Canceled", err)
	}
}

func TestInstallAndRemoveRouteHooks(t *testing.T) {
	m := New(config.RoutingConfig{
		InstallRoutes: true,
	}, slog.New(slog.DiscardHandler))
	fake := &fakeNetlink{link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 44, Name: "eth1"}}}
	m.nl = fake
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
	if fake.replaced != 1 || fake.deleted != 1 {
		t.Fatalf("routes replaced/deleted = %d/%d, want 1/1", fake.replaced, fake.deleted)
	}
}

func TestStartWritesForwardingAndRPFilterSysctls(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		"net/ipv4/ip_forward",
		"net/ipv4/conf/all/rp_filter",
		"net/ipv4/conf/default/rp_filter",
	} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir sysctl path: %v", err)
		}
		if err := os.WriteFile(full, []byte("0\n"), 0644); err != nil {
			t.Fatalf("write sysctl file: %v", err)
		}
	}
	m := New(config.RoutingConfig{EnableIPForwarding: true, DisableRPFilter: true}, slog.New(slog.DiscardHandler))
	m.procSys = root
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	assertFileContent(t, filepath.Join(root, "net/ipv4/ip_forward"), "1\n")
	assertFileContent(t, filepath.Join(root, "net/ipv4/conf/all/rp_filter"), "0\n")
	assertFileContent(t, filepath.Join(root, "net/ipv4/conf/default/rp_filter"), "0\n")
}

type fakeNetlink struct {
	link     netlink.Link
	replaced int
	deleted  int
}

func (f *fakeNetlink) LinkByName(name string) (netlink.Link, error) {
	if f.link != nil && f.link.Attrs().Name == name {
		return f.link, nil
	}
	return nil, netlink.LinkNotFoundError{}
}

func (f *fakeNetlink) RouteReplace(route *netlink.Route) error {
	f.replaced++
	return nil
}

func (f *fakeNetlink) RouteDel(route *netlink.Route) error {
	f.deleted++
	return nil
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

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, string(got), want)
	}
}
