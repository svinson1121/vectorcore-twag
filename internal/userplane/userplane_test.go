package userplane

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
	"github.com/vishvananda/netlink"
)

func TestNewUserPlaneCreatesKernelGTP(t *testing.T) {
	up, err := New(config.Config{
		GTP: config.GTPConfig{KernelInterface: "gtp0"},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if up.Type() != ModeKernelGTP {
		t.Fatalf("type = %q, want %q", up.Type(), ModeKernelGTP)
	}
}

func TestKernelGTPAddSessionRequiresStart(t *testing.T) {
	up := NewKernelGTP(config.UserPlaneConfig{
		Mode:         ModeKernelGTP,
		GTPInterface: "gtp0",
	}, config.PGWConfig{}, config.RoutingConfig{}, slog.New(slog.DiscardHandler))
	err := up.AddSession(context.Background(), &session.Session{
		ID:             "sess-1",
		IMSI:           "001010000000001",
		SubscriberIP:   net.ParseIP("100.64.0.10"),
		PGWUserIP:      net.ParseIP("10.90.250.92"),
		LocalGTPUTEID:  0x11111111,
		RemoteGTPUTEID: 0x22222222,
	})
	if err == nil {
		t.Fatal("expected not started error")
	}
	if err.Error() != "kernel GTP user plane is not started" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUserEchoConfigClampsIntervalBelowMinimum(t *testing.T) {
	up := NewKernelGTP(config.UserPlaneConfig{
		Mode:         ModeKernelGTP,
		GTPInterface: "gtp0",
	}, config.PGWConfig{
		UserEcho: config.GTPUserEchoConfig{
			Enabled:         true,
			Mode:            gtpUEchoModeKernelNetlink,
			IntervalSeconds: 1,
			TimeoutSeconds:  1,
			MaxFailures:     3,
		},
	}, config.RoutingConfig{}, slog.New(slog.DiscardHandler))
	if up.userEchoCfg.IntervalSeconds != config.MinGTPEchoIntervalSeconds {
		t.Fatalf("user echo interval = %d, want %d", up.userEchoCfg.IntervalSeconds, config.MinGTPEchoIntervalSeconds)
	}
}

func TestKernelSessionValidation(t *testing.T) {
	if err := validateKernelSession(nil); err == nil {
		t.Fatal("expected nil session error")
	}
	base := &session.Session{
		ID:             "sess-1",
		SubscriberIP:   net.ParseIP("100.64.0.10"),
		LocalGTPUTEID:  0x11111111,
		RemoteGTPUTEID: 0x22222222,
	}
	if err := validateKernelSession(base); err != nil {
		t.Fatalf("validateKernelSession() error = %v", err)
	}
	noIP := *base
	noIP.SubscriberIP = nil
	if err := validateKernelSession(&noIP); err == nil {
		t.Fatal("expected missing subscriber IP error")
	}
	noLocal := *base
	noLocal.LocalGTPUTEID = 0
	if err := validateKernelSession(&noLocal); err == nil {
		t.Fatal("expected missing local TEID error")
	}
	noRemote := *base
	noRemote.RemoteGTPUTEID = 0
	if err := validateKernelSession(&noRemote); err == nil {
		t.Fatal("expected missing remote TEID error")
	}
}

func TestKernelRouteUsesHostRouteOnGTPInterface(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 12, Name: "gtp0"}}
	route := kernelRoute(link, net.ParseIP("100.64.0.10"))
	if route.LinkIndex != 12 {
		t.Fatalf("route link index = %d, want 12", route.LinkIndex)
	}
	if route.Dst.String() != "100.64.0.10/32" {
		t.Fatalf("route dst = %s, want 100.64.0.10/32", route.Dst.String())
	}
}

func TestKernelPolicyRouteAndRuleUseConfiguredTable(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 12, Name: "gtp0"}}
	route := kernelPolicyDefaultRoute(link, 200)
	if route.LinkIndex != 12 {
		t.Fatalf("route link index = %d, want 12", route.LinkIndex)
	}
	if route.Table != 200 {
		t.Fatalf("route table = %d, want 200", route.Table)
	}
	if route.Dst.String() != "0.0.0.0/0" {
		t.Fatalf("route dst = %s, want 0.0.0.0/0", route.Dst.String())
	}
	rule := kernelPolicyRule(net.ParseIP("100.64.0.10"), 200, 10000)
	if rule.Table != 200 {
		t.Fatalf("rule table = %d, want 200", rule.Table)
	}
	if rule.Priority != 10000 {
		t.Fatalf("rule priority = %d, want 10000", rule.Priority)
	}
	if rule.Src.String() != "100.64.0.10/32" {
		t.Fatalf("rule src = %s, want 100.64.0.10/32", rule.Src.String())
	}
}

func TestDebugHelpersHandleNilValues(t *testing.T) {
	if fdValue(nil) != 0 {
		t.Fatalf("nil fd value = %d, want 0", fdValue(nil))
	}
	if localAddrString(nil) != "" {
		t.Fatalf("nil local addr = %q, want empty", localAddrString(nil))
	}
}

func TestUDPConnFDKeepsReadDeadlineUsable(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer conn.Close() //nolint:errcheck

	fd, err := udpConnFD(conn)
	if err != nil {
		t.Fatalf("udpConnFD() error = %v", err)
	}
	if fd < 0 {
		t.Fatalf("udpConnFD() fd = %d, want non-negative", fd)
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, _, err := conn.ReadFromUDP(buf)
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	select {
	case err := <-done:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("ReadFromUDP() error = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFromUDP() did not unblock after SetReadDeadline")
	}
}
