package lifecycle

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/vectorcore/twag/internal/aaa"
	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/ipam"
	"github.com/vectorcore/twag/internal/pgw"
	"github.com/vectorcore/twag/internal/routing"
	"github.com/vectorcore/twag/internal/session"
)

func TestAttachSuccessCreatesActiveSession(t *testing.T) {
	svc, deps := newTestService(t)
	resp, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MSISDN:     "17892000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if resp.State != session.Active {
		t.Fatalf("state = %q", resp.State)
	}
	if resp.SubscriberIP != "10.200.0.2" {
		t.Fatalf("subscriber ip = %q", resp.SubscriberIP)
	}
	if deps.pgw.created != 1 {
		t.Fatalf("pgw creates = %d", deps.pgw.created)
	}
	if _, ok := deps.sessions.LookupByIMSI("001010000000001"); !ok {
		t.Fatal("session not indexed by IMSI")
	}
}

func TestAttachRejectedMarksSessionFailed(t *testing.T) {
	svc, deps := newTestService(t)
	deps.aaa.result = &aaa.AuthResult{
		Allowed:    false,
		IMSI:       "001010000000001",
		APN:        "internet",
		Reason:     "unknown user",
		ResultCode: 5001,
	}
	deps.aaa.err = aaa.ErrRejected
	resp, err := svc.Attach(context.Background(), AttachRequest{IMSI: "001010000000001"})
	if !errors.Is(err, aaa.ErrRejected) {
		t.Fatalf("Attach() error = %v, want ErrRejected", err)
	}
	if resp == nil || resp.State != session.Failed {
		t.Fatalf("unexpected response %#v", resp)
	}
	if deps.pgw.created != 0 {
		t.Fatalf("pgw creates = %d", deps.pgw.created)
	}
	if _, ok := deps.ipam.Lookup(resp.SessionID); ok {
		t.Fatal("rejected session should not have an IP lease")
	}
}

func TestAttachPGWFailureReleasesIPAndMarksFailed(t *testing.T) {
	svc, deps := newTestService(t)
	deps.pgw.createErr = errors.New("pgw down")
	resp, err := svc.Attach(context.Background(), AttachRequest{IMSI: "001010000000001"})
	if err == nil {
		t.Fatal("expected attach error")
	}
	if resp == nil || resp.State != session.Failed {
		t.Fatalf("unexpected response %#v", resp)
	}
	if _, ok := deps.ipam.Lookup(resp.SessionID); ok {
		t.Fatal("failed PGW session should release IP lease")
	}
}

func TestDetachDeletesPGWRouteAndLease(t *testing.T) {
	svc, deps := newTestService(t)
	resp, err := svc.Attach(context.Background(), AttachRequest{IMSI: "001010000000001"})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	detachResp, err := svc.Detach(context.Background(), DetachRequest{SessionID: resp.SessionID})
	if err != nil {
		t.Fatalf("Detach() error = %v", err)
	}
	if detachResp == nil || detachResp.State != session.Terminated {
		t.Fatalf("unexpected detach response %#v", detachResp)
	}
	if deps.pgw.deleted != 1 {
		t.Fatalf("pgw deletes = %d", deps.pgw.deleted)
	}
	if _, ok := deps.ipam.Lookup(resp.SessionID); ok {
		t.Fatal("detached session should release IP lease")
	}
	if _, ok := deps.sessions.Get(resp.SessionID); ok {
		t.Fatal("detached session should be deleted")
	}
}

func TestDuplicateAttachDetachesExistingSession(t *testing.T) {
	svc, deps := newTestService(t)
	first, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("first Attach() error = %v", err)
	}
	second, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("second Attach() error = %v", err)
	}
	if first.SessionID == second.SessionID {
		t.Fatal("duplicate attach should create a replacement session")
	}
	if second.SubscriberIP != "10.200.0.2" {
		t.Fatalf("replacement subscriber ip = %q", second.SubscriberIP)
	}
	if deps.pgw.deleted != 1 {
		t.Fatalf("pgw deletes = %d", deps.pgw.deleted)
	}
	if _, ok := deps.ipam.Lookup(first.SessionID); ok {
		t.Fatal("duplicate attach should release old IP lease")
	}
	if _, ok := deps.sessions.Get(first.SessionID); ok {
		t.Fatal("duplicate attach should delete old session")
	}
	if _, ok := deps.ipam.Lookup(second.SessionID); !ok {
		t.Fatal("replacement session should have IP lease")
	}
}

func TestAttachAfterRejectedSessionDoesNotDetachFailedSession(t *testing.T) {
	svc, deps := newTestService(t)
	deps.aaa.result = &aaa.AuthResult{
		Allowed:    false,
		IMSI:       "001010000000001",
		APN:        "internet",
		Reason:     "unknown user",
		ResultCode: 5001,
	}
	deps.aaa.err = aaa.ErrRejected
	failed, err := svc.Attach(context.Background(), AttachRequest{IMSI: "001010000000001"})
	if !errors.Is(err, aaa.ErrRejected) {
		t.Fatalf("Attach() error = %v, want ErrRejected", err)
	}

	deps.aaa.result = &aaa.AuthResult{
		Allowed:    true,
		IMSI:       "001010000000001",
		APN:        "internet",
		Reason:     "accepted",
		ResultCode: 2001,
	}
	deps.aaa.err = nil
	active, err := svc.Attach(context.Background(), AttachRequest{IMSI: "001010000000001"})
	if err != nil {
		t.Fatalf("reattach error = %v", err)
	}
	if active.State != session.Active {
		t.Fatalf("reattach state = %q", active.State)
	}
	if failed.SessionID == active.SessionID {
		t.Fatal("reattach should create a new session")
	}
	if deps.pgw.deleted != 0 {
		t.Fatalf("pgw deletes = %d", deps.pgw.deleted)
	}
}

func TestShutdownDetachesActiveSessions(t *testing.T) {
	svc, deps := newTestService(t)
	first, err := svc.Attach(context.Background(), AttachRequest{IMSI: "001010000000001"})
	if err != nil {
		t.Fatalf("first Attach() error = %v", err)
	}
	deps.aaa.result.IMSI = "001010000000002"
	second, err := svc.Attach(context.Background(), AttachRequest{IMSI: "001010000000002"})
	if err != nil {
		t.Fatalf("second Attach() error = %v", err)
	}

	if err := svc.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if deps.pgw.deleted != 2 {
		t.Fatalf("pgw deletes = %d", deps.pgw.deleted)
	}
	for _, id := range []string{first.SessionID, second.SessionID} {
		if _, ok := deps.ipam.Lookup(id); ok {
			t.Fatalf("session %s should release IP lease", id)
		}
		if _, ok := deps.sessions.Get(id); ok {
			t.Fatalf("session %s should be deleted", id)
		}
	}
}

func TestShutdownSkipsFailedSessions(t *testing.T) {
	svc, deps := newTestService(t)
	deps.aaa.result = &aaa.AuthResult{
		Allowed:    false,
		IMSI:       "001010000000001",
		APN:        "internet",
		Reason:     "unknown user",
		ResultCode: 5001,
	}
	deps.aaa.err = aaa.ErrRejected
	resp, err := svc.Attach(context.Background(), AttachRequest{IMSI: "001010000000001"})
	if !errors.Is(err, aaa.ErrRejected) {
		t.Fatalf("Attach() error = %v, want ErrRejected", err)
	}

	if err := svc.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if deps.pgw.deleted != 0 {
		t.Fatalf("pgw deletes = %d", deps.pgw.deleted)
	}
	if _, ok := deps.sessions.Get(resp.SessionID); !ok {
		t.Fatal("failed session should remain available for inspection")
	}
}

type testDeps struct {
	aaa      *fakeAAA
	ipam     *ipam.MemoryIPAM
	pgw      *fakePGW
	sessions *session.Manager
}

func newTestService(t *testing.T) (*Service, testDeps) {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	cfg := &config.Config{
		TWAG: config.TWAGConfig{Name: "twag-test", Realm: "epc.example"},
		Access: config.AccessConfig{
			Mode:      "ethernet",
			Interface: "eth1",
		},
		Subscriber: config.SubscriberConfig{
			DefaultAPN:   "internet",
			DefaultRealm: "ims.example",
		},
		IPAM: config.IPAMConfig{
			Pool:    "10.200.0.0/24",
			Gateway: "10.200.0.1",
		},
	}
	memIPAM, err := ipam.NewMemory(cfg.IPAM, log)
	if err != nil {
		t.Fatalf("NewMemory() error = %v", err)
	}
	deps := testDeps{
		aaa: &fakeAAA{result: &aaa.AuthResult{
			Allowed:    true,
			IMSI:       "001010000000001",
			MSISDN:     "17892000001",
			APN:        "internet",
			Reason:     "accepted",
			ResultCode: 2001,
		}},
		ipam:     memIPAM,
		pgw:      &fakePGW{},
		sessions: session.NewManager(log),
	}
	return New(cfg, deps.aaa, deps.sessions, deps.ipam, deps.pgw, routing.New(cfg.Routing, log), log), deps
}

type fakeAAA struct {
	result *aaa.AuthResult
	err    error
}

func (f *fakeAAA) Start(context.Context) error { return nil }
func (f *fakeAAA) Stop() error                 { return nil }
func (f *fakeAAA) Type() string                { return "fake" }
func (f *fakeAAA) Authenticate(context.Context, aaa.AuthRequest) (*aaa.AuthResult, error) {
	return f.result, f.err
}

type fakePGW struct {
	created   int
	deleted   int
	createErr error
	deleteErr error
}

func (f *fakePGW) Probe(context.Context) error { return nil }

func (f *fakePGW) CreateSession(_ context.Context, sess *session.Session) (*pgw.CreateSessionResult, error) {
	f.created++
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &pgw.CreateSessionResult{
		SubscriberIP: sess.SubscriberIP,
		GatewayIP:    sess.GatewayIP,
	}, nil
}

func (f *fakePGW) DeleteSession(context.Context, *session.Session) error {
	f.deleted++
	return f.deleteErr
}

func (f *fakePGW) Type() string { return "fake" }
