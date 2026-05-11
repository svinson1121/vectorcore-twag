package ipam

import (
	"log/slog"
	"testing"

	"github.com/vectorcore/twag/internal/config"
)

func TestMemoryAllocatesOneIPPerSession(t *testing.T) {
	m := newTestIPAM(t, "10.200.0.0/29", "10.200.0.1")

	ip1, err := m.Allocate("sess-1")
	if err != nil {
		t.Fatalf("Allocate(sess-1) error = %v", err)
	}
	if got := ip1.String(); got != "10.200.0.2" {
		t.Fatalf("first allocation = %s", got)
	}
	ip1Again, err := m.Allocate("sess-1")
	if err != nil {
		t.Fatalf("Allocate(sess-1 again) error = %v", err)
	}
	if !ip1Again.Equal(ip1) {
		t.Fatalf("repeat allocation changed IP from %s to %s", ip1, ip1Again)
	}
	ip2, err := m.Allocate("sess-2")
	if err != nil {
		t.Fatalf("Allocate(sess-2) error = %v", err)
	}
	if ip2.Equal(ip1) {
		t.Fatalf("duplicate allocation: %s", ip2)
	}
}

func TestMemoryReleasesAndReusesIP(t *testing.T) {
	m := newTestIPAM(t, "10.200.0.0/29", "10.200.0.1")

	ip, err := m.Allocate("sess-1")
	if err != nil {
		t.Fatalf("Allocate(sess-1) error = %v", err)
	}
	if err := m.Release("sess-1"); err != nil {
		t.Fatalf("Release(sess-1) error = %v", err)
	}
	if _, ok := m.Lookup("sess-1"); ok {
		t.Fatalf("lease still present after release")
	}
	reused, err := m.Allocate("sess-2")
	if err != nil {
		t.Fatalf("Allocate(sess-2) error = %v", err)
	}
	if !reused.Equal(ip) {
		t.Fatalf("released IP was not reused: got %s want %s", reused, ip)
	}
}

func TestMemorySkipsGatewayAndBroadcast(t *testing.T) {
	m := newTestIPAM(t, "10.200.0.0/30", "10.200.0.1")

	ip, err := m.Allocate("sess-1")
	if err != nil {
		t.Fatalf("Allocate(sess-1) error = %v", err)
	}
	if got := ip.String(); got != "10.200.0.2" {
		t.Fatalf("allocation = %s, want only usable non-gateway host", got)
	}
	if _, err := m.Allocate("sess-2"); err == nil {
		t.Fatalf("expected pool exhaustion")
	}
}

func TestMemoryRejectsUnusablePool(t *testing.T) {
	_, err := NewMemory(config.IPAMConfig{
		Pool:    "10.200.0.0/31",
		Gateway: "10.200.0.1",
	}, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatalf("expected unusable pool error")
	}
}

func TestMemoryStatus(t *testing.T) {
	m := newTestIPAM(t, "10.200.0.0/29", "10.200.0.1")
	if _, err := m.Allocate("sess-2"); err != nil {
		t.Fatalf("Allocate(sess-2) error = %v", err)
	}
	if _, err := m.Allocate("sess-1"); err != nil {
		t.Fatalf("Allocate(sess-1) error = %v", err)
	}

	st := m.Status()
	if st.Pool != "10.200.0.0/29" || st.Gateway.String() != "10.200.0.1" {
		t.Fatalf("unexpected status pool=%s gateway=%s", st.Pool, st.Gateway)
	}
	if st.TotalUsable != 5 || st.Used != 2 || st.Free != 3 {
		t.Fatalf("unexpected usage total=%d used=%d free=%d", st.TotalUsable, st.Used, st.Free)
	}
	if len(st.Leases) != 2 || st.Leases[0].SessionID != "sess-1" || st.Leases[1].SessionID != "sess-2" {
		t.Fatalf("leases not sorted by session id: %#v", st.Leases)
	}
}

func TestMemoryRequiresSessionID(t *testing.T) {
	m := newTestIPAM(t, "10.200.0.0/29", "10.200.0.1")
	if _, err := m.Allocate(""); err == nil {
		t.Fatalf("expected empty session id allocation error")
	}
	if err := m.Release(""); err == nil {
		t.Fatalf("expected empty session id release error")
	}
	if _, ok := m.Lookup(""); ok {
		t.Fatalf("empty session lookup should fail")
	}
}

func newTestIPAM(t *testing.T, pool, gateway string) *MemoryIPAM {
	t.Helper()
	m, err := NewMemory(config.IPAMConfig{Pool: pool, Gateway: gateway}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewMemory() error = %v", err)
	}
	return m
}
