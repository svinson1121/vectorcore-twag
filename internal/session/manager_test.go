package session

import (
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestSessionStateTransitionsAndLookups(t *testing.T) {
	m := NewManager(slog.New(slog.DiscardHandler))
	s := m.Create(CreateInput{
		IMSI:       "001010000000001",
		MSISDN:     "17892000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
		APN:        "internet",
		Realm:      "ims.example",
		GatewayIP:  net.ParseIP("10.200.0.1"),
	})
	if s.State != Pending {
		t.Fatalf("initial state = %q", s.State)
	}
	mustTransition(t, func() (*Session, error) { return m.MarkAuthPending(s.ID) }, AuthPending)
	mustTransition(t, func() (*Session, error) { return m.MarkAuthorized(s.ID) }, Authorized)
	ipAllocated := mustTransition(t, func() (*Session, error) { return m.SetSubscriberIP(s.ID, net.ParseIP("10.200.0.2")) }, IPAllocated)
	if !ipAllocated.SubscriberIP.Equal(net.ParseIP("10.200.0.2")) {
		t.Fatalf("subscriber ip = %s", ipAllocated.SubscriberIP)
	}
	mustTransition(t, func() (*Session, error) { return m.MarkPGWPending(s.ID) }, PGWPending)
	mustTransition(t, func() (*Session, error) { return m.MarkActive(s.ID) }, Active)

	if _, ok := m.LookupByIMSI("001010000000001"); !ok {
		t.Fatal("missing IMSI lookup")
	}
	if _, ok := m.LookupByMAC("aa:bb:cc:dd:ee:01"); !ok {
		t.Fatal("missing MAC lookup")
	}
	if _, ok := m.LookupByIP(net.ParseIP("10.200.0.2")); !ok {
		t.Fatal("missing IP lookup")
	}
}

func TestInvalidTransition(t *testing.T) {
	m := NewManager(slog.New(slog.DiscardHandler))
	s := m.Create(CreateInput{IMSI: "001010000000001"})
	_, err := m.MarkActive(s.ID)
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("MarkActive() error = %v, want ErrInvalidTransition", err)
	}
}

func TestApplyAuthResultReindexesIMSI(t *testing.T) {
	m := NewManager(slog.New(slog.DiscardHandler))
	s := m.Create(CreateInput{MACAddress: "aa:bb:cc:dd:ee:01"})
	mustTransition(t, func() (*Session, error) { return m.MarkAuthPending(s.ID) }, AuthPending)
	updated := mustTransition(t, func() (*Session, error) {
		return m.ApplyAuthResult(s.ID, "001010000000001", "17892000001", "internet", "accepted")
	}, Authorized)
	if updated.IMSI != "001010000000001" {
		t.Fatalf("updated imsi = %q", updated.IMSI)
	}
	if _, ok := m.LookupByIMSI("001010000000001"); !ok {
		t.Fatal("new IMSI not indexed")
	}
	if _, ok := m.LookupByMAC("aa:bb:cc:dd:ee:01"); !ok {
		t.Fatal("MAC index lost")
	}
}

func TestBindTEIDsAndLookup(t *testing.T) {
	m := NewManager(slog.New(slog.DiscardHandler))
	s := m.Create(CreateInput{IMSI: "001010000000001"})
	updated, err := m.BindTEIDs(s.ID, 1001, 2001, 3001)
	if err != nil {
		t.Fatalf("BindTEIDs() error = %v", err)
	}
	if updated.GTPCTEID != 1001 || updated.LocalGTPUTEID != 2001 || updated.RemoteGTPUTEID != 3001 {
		t.Fatalf("unexpected TEIDs %#v", updated)
	}
	if got, ok := m.LookupByTEID(1001); !ok || got.ID != s.ID {
		t.Fatalf("TEID lookup = %#v ok=%v", got, ok)
	}
	if _, err := m.BindTEIDs(s.ID, 1002, 2002, 3002); err != nil {
		t.Fatalf("BindTEIDs update error = %v", err)
	}
	if _, ok := m.LookupByTEID(1001); ok {
		t.Fatal("old TEID still indexed")
	}
	if _, ok := m.LookupByTEID(1002); !ok {
		t.Fatal("new TEID not indexed")
	}
}

func TestDeleteRemovesIndexes(t *testing.T) {
	m := NewManager(slog.New(slog.DiscardHandler))
	s := m.Create(CreateInput{IMSI: "001010000000001", MACAddress: "aa:bb:cc:dd:ee:01"})
	mustTransition(t, func() (*Session, error) { return m.MarkAuthPending(s.ID) }, AuthPending)
	mustTransition(t, func() (*Session, error) { return m.MarkAuthorized(s.ID) }, Authorized)
	mustTransition(t, func() (*Session, error) { return m.SetSubscriberIP(s.ID, net.ParseIP("10.200.0.2")) }, IPAllocated)
	mustTransition(t, func() (*Session, error) { return m.MarkPGWPending(s.ID) }, PGWPending)
	mustTransition(t, func() (*Session, error) { return m.MarkActive(s.ID) }, Active)
	mustTransition(t, func() (*Session, error) { return m.MarkTerminating(s.ID) }, Terminating)
	terminated, ok := m.Delete(s.ID)
	if !ok || terminated.State != Terminated {
		t.Fatalf("Delete() = %#v ok=%v", terminated, ok)
	}
	if _, ok := m.Get(s.ID); ok {
		t.Fatal("session still indexed by ID")
	}
	if _, ok := m.LookupByIMSI("001010000000001"); ok {
		t.Fatal("session still indexed by IMSI")
	}
	if _, ok := m.LookupByIP(net.ParseIP("10.200.0.2")); ok {
		t.Fatal("session still indexed by IP")
	}
}

func TestExpireInactive(t *testing.T) {
	m := NewManager(slog.New(slog.DiscardHandler))
	s := m.Create(CreateInput{
		IMSI: "001010000000001",
		TTL:  time.Second,
	})
	expired := m.ExpireInactive(s.CreatedAt.Add(2 * time.Second))
	if len(expired) != 1 || expired[0].ID != s.ID || expired[0].State != Terminated {
		t.Fatalf("expired = %#v", expired)
	}
	if _, ok := m.Get(s.ID); ok {
		t.Fatal("expired session still indexed")
	}
}

func mustTransition(t *testing.T, fn func() (*Session, error), want State) *Session {
	t.Helper()
	s, err := fn()
	if err != nil {
		t.Fatalf("state transition error = %v", err)
	}
	if s.State != want {
		t.Fatalf("state = %q, want %q", s.State, want)
	}
	return s
}
