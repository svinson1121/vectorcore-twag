package lifecycle

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/vectorcore/twag/internal/aaa"
	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/gtp"
	"github.com/vectorcore/twag/internal/gtpu"
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

func TestDuplicateAttachReusesExistingActiveSession(t *testing.T) {
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
	if first.SessionID != second.SessionID {
		t.Fatal("duplicate attach should reuse the existing active session")
	}
	if second.SubscriberIP != first.SubscriberIP {
		t.Fatalf("reused subscriber ip = %q, want %q", second.SubscriberIP, first.SubscriberIP)
	}
	if deps.pgw.deleted != 0 {
		t.Fatalf("pgw deletes = %d", deps.pgw.deleted)
	}
	if deps.pgw.created != 1 {
		t.Fatalf("pgw creates = %d", deps.pgw.created)
	}
	if _, ok := deps.ipam.Lookup(first.SessionID); !ok {
		t.Fatal("reused session should keep old IP lease")
	}
	if _, ok := deps.sessions.Get(first.SessionID); !ok {
		t.Fatal("reused session should remain stored")
	}
}

func TestDuplicateAttachContinuesWhenOldPGWContextNotFound(t *testing.T) {
	svc, deps := newTestService(t)
	svc.cfg.Lifecycle.DuplicateAttachPolicy = "replace_existing"
	first, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("first Attach() error = %v", err)
	}
	deps.pgw.deleteErr = &gtp.GTPError{Operation: "GTP-C Delete Session", Cause: gtp.GTPv2CauseContextNotFound}

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
	if second.State != session.Active {
		t.Fatalf("replacement state = %q", second.State)
	}
	if deps.pgw.deleted != 1 {
		t.Fatalf("pgw deletes = %d", deps.pgw.deleted)
	}
	if deps.pgw.created != 2 {
		t.Fatalf("pgw creates = %d", deps.pgw.created)
	}
	if _, ok := deps.sessions.Get(first.SessionID); ok {
		t.Fatal("stale old session should be removed locally")
	}
	if _, ok := deps.sessions.Get(second.SessionID); !ok {
		t.Fatal("replacement session should be stored")
	}
}

func TestGTPUErrorIndicationCreatesRecoveryTombstoneAndCleansUp(t *testing.T) {
	svc, deps := newTestService(t)
	svc.cfg.Recovery = config.RecoveryConfig{Enabled: true, ReasonGTPUError: true, RecoveryWindowSeconds: 60, AllowSameMACReattach: true}
	resp, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if _, err := deps.sessions.ApplyPGWResult(resp.SessionID, nil, nil, 0x1001, 0x4e80a8e9, 0x80122006); err != nil {
		t.Fatalf("ApplyPGWResult() error = %v", err)
	}
	if err := svc.HandleGTPUErrorIndication(context.Background(), gtpu.ErrorIndication{
		RemoteAddr:    &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 2152},
		OffendingTEID: 0x80122006,
	}); err != nil {
		t.Fatalf("HandleGTPUErrorIndication() error = %v", err)
	}
	if deps.pgw.deleted != 1 {
		t.Fatalf("pgw deletes = %d, want 1", deps.pgw.deleted)
	}
	if _, ok := deps.sessions.Get(resp.SessionID); ok {
		t.Fatal("old session should be deleted after recovery cleanup")
	}
	if tombstone, ok := deps.sessions.FindRecovery("001010000000001", "aa:bb:cc:dd:ee:01"); !ok {
		t.Fatal("expected recovery tombstone")
	} else if tombstone.OldRemoteTEID != 0x80122006 {
		t.Fatalf("old remote TEID = %#x", tombstone.OldRemoteTEID)
	}
}

func TestGTPUErrorIndicationSendsRadiusDisconnectWhenEnabled(t *testing.T) {
	svc, deps := newTestService(t)
	svc.cfg.Recovery = config.RecoveryConfig{
		Enabled:               true,
		ReasonGTPUError:       true,
		RecoveryWindowSeconds: 60,
		AllowSameMACReattach:  true,
		RadiusDisconnect: config.RadiusDisconnectConfig{
			Enabled:                     true,
			NASIP:                       "192.0.2.10",
			NASPort:                     3799,
			Secret:                      "secret",
			RequestType:                 "disconnect",
			FallbackToRecoveryTombstone: true,
		},
	}
	da := &fakeDynamicAuthorizer{}
	svc.SetDynamicAuthorizer(da)
	resp, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if _, err := deps.sessions.ApplyPGWResult(resp.SessionID, nil, nil, 0x1001, 0x4e80a8e9, 0x80122006); err != nil {
		t.Fatalf("ApplyPGWResult() error = %v", err)
	}
	if err := svc.HandleGTPUErrorIndication(context.Background(), gtpu.ErrorIndication{OffendingTEID: 0x80122006}); err != nil {
		t.Fatalf("HandleGTPUErrorIndication() error = %v", err)
	}
	if da.calls != 1 {
		t.Fatalf("dynamic authorization calls = %d, want 1", da.calls)
	}
	if tombstone, ok := deps.sessions.FindRecovery("001010000000001", "aa:bb:cc:dd:ee:01"); !ok {
		t.Fatal("expected recovery tombstone")
	} else if tombstone.State != session.RecoveryWaitingReauth {
		t.Fatalf("recovery state = %q", tombstone.State)
	}
}

func TestGTPUErrorIndicationDynamicAuthorizationFailureFallsBack(t *testing.T) {
	svc, deps := newTestService(t)
	svc.cfg.Recovery = config.RecoveryConfig{
		Enabled:               true,
		ReasonGTPUError:       true,
		RecoveryWindowSeconds: 60,
		AllowSameMACReattach:  true,
		RadiusDisconnect: config.RadiusDisconnectConfig{
			Enabled:                     true,
			NASIP:                       "192.0.2.10",
			NASPort:                     3799,
			Secret:                      "secret",
			RequestType:                 "disconnect",
			FallbackToRecoveryTombstone: true,
		},
	}
	svc.SetDynamicAuthorizer(&fakeDynamicAuthorizer{err: errors.New("timeout")})
	resp, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if _, err := deps.sessions.ApplyPGWResult(resp.SessionID, nil, nil, 0x1001, 0x4e80a8e9, 0x80122006); err != nil {
		t.Fatalf("ApplyPGWResult() error = %v", err)
	}
	if err := svc.HandleGTPUErrorIndication(context.Background(), gtpu.ErrorIndication{OffendingTEID: 0x80122006}); err != nil {
		t.Fatalf("HandleGTPUErrorIndication() error = %v", err)
	}
	if tombstone, ok := deps.sessions.FindRecovery("001010000000001", "aa:bb:cc:dd:ee:01"); !ok {
		t.Fatal("expected recovery tombstone")
	} else if tombstone.State != session.RecoveryFallback {
		t.Fatalf("recovery state = %q", tombstone.State)
	}
}

func TestFreshAttachCompletesRecovery(t *testing.T) {
	svc, deps := newTestService(t)
	svc.cfg.Recovery = config.RecoveryConfig{Enabled: true, ReasonGTPUError: true, RecoveryWindowSeconds: 60, AllowSameMACReattach: true}
	first, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("first Attach() error = %v", err)
	}
	if _, err := deps.sessions.ApplyPGWResult(first.SessionID, nil, nil, 0x1001, 0x4e80a8e9, 0x80122006); err != nil {
		t.Fatalf("ApplyPGWResult() error = %v", err)
	}
	if err := svc.HandleGTPUErrorIndication(context.Background(), gtpu.ErrorIndication{OffendingTEID: 0x80122006}); err != nil {
		t.Fatalf("HandleGTPUErrorIndication() error = %v", err)
	}
	second, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("second Attach() error = %v", err)
	}
	if second.SessionID == first.SessionID {
		t.Fatal("recovery attach should create a fresh session")
	}
	if _, ok := deps.sessions.FindRecovery("001010000000001", "aa:bb:cc:dd:ee:01"); ok {
		t.Fatal("recovery tombstone should be removed after fresh attach")
	}
}

func TestDuplicateAttachKeepsOtherDeleteFailuresFatal(t *testing.T) {
	svc, deps := newTestService(t)
	svc.cfg.Lifecycle.DuplicateAttachPolicy = "replace_existing"
	if _, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	}); err != nil {
		t.Fatalf("first Attach() error = %v", err)
	}
	deps.pgw.deleteErr = errors.New("GTP-C transport timeout")

	resp, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err == nil {
		t.Fatal("expected duplicate attach to fail for non-context-not-found delete error")
	}
	if resp != nil {
		t.Fatalf("unexpected response %#v", resp)
	}
	if deps.pgw.deleted != 1 {
		t.Fatalf("pgw deletes = %d", deps.pgw.deleted)
	}
	if deps.pgw.created != 1 {
		t.Fatalf("pgw creates = %d", deps.pgw.created)
	}
}

func TestDuplicateAttachReplacePolicyDetachesBeforeCreate(t *testing.T) {
	svc, deps := newTestService(t)
	svc.cfg.Lifecycle.DuplicateAttachPolicy = "replace_existing"
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
		t.Fatal("replace policy should create a replacement session")
	}
	if deps.pgw.deleted != 1 {
		t.Fatalf("pgw deletes = %d", deps.pgw.deleted)
	}
	if deps.pgw.created != 2 {
		t.Fatalf("pgw creates = %d", deps.pgw.created)
	}
	if deps.pgw.maxInflightCreates > 1 {
		t.Fatalf("overlapping creates = %d", deps.pgw.maxInflightCreates)
	}
}

func TestConcurrentAttachAndRecoveryDoNotOverlapCreateSession(t *testing.T) {
	svc, deps := newTestService(t)
	svc.cfg.Recovery = config.RecoveryConfig{Enabled: true, ReasonGTPUError: true, RecoveryWindowSeconds: 60, AllowSameMACReattach: true}
	first, err := svc.Attach(context.Background(), AttachRequest{
		IMSI:       "001010000000001",
		MACAddress: "aa:bb:cc:dd:ee:01",
	})
	if err != nil {
		t.Fatalf("first Attach() error = %v", err)
	}
	if _, err := deps.sessions.ApplyPGWResult(first.SessionID, nil, nil, 0x1001, 0x4e80a8e9, 0x80122006); err != nil {
		t.Fatalf("ApplyPGWResult() error = %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.AttachAuthorized(context.Background(), AttachRequest{
				IMSI:       "001010000000001",
				MACAddress: "aa:bb:cc:dd:ee:01",
			}, nil)
			errs <- err
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		errs <- svc.HandleGTPUErrorIndication(context.Background(), gtpu.ErrorIndication{OffendingTEID: 0x80122006})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := svc.Detach(context.Background(), DetachRequest{SessionID: first.SessionID})
		if err != nil && err.Error() == "session not found" {
			err = nil
		}
		errs <- err
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent lifecycle error = %v", err)
		}
	}
	if deps.pgw.maxInflightCreates > 1 {
		t.Fatalf("overlapping creates = %d", deps.pgw.maxInflightCreates)
	}
	active := 0
	for _, sess := range deps.sessions.List() {
		if sess.State == session.Active {
			active++
		}
	}
	if active > 1 {
		t.Fatalf("active sessions = %d", active)
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
func (f *fakeAAA) ExchangeEAP(context.Context, aaa.EAPRequest) (*aaa.EAPResult, error) {
	return &aaa.EAPResult{
		State:      aaa.EAPStateSuccess,
		Allowed:    true,
		IMSI:       f.result.IMSI,
		MSISDN:     f.result.MSISDN,
		APN:        f.result.APN,
		Reason:     f.result.Reason,
		ResultCode: f.result.ResultCode,
	}, nil
}

type fakePGW struct {
	mu                 sync.Mutex
	created            int
	deleted            int
	inflightCreates    int
	maxInflightCreates int
	createErr          error
	deleteErr          error
}

func (f *fakePGW) Probe(context.Context) error { return nil }

func (f *fakePGW) StartEchoWatchdog(context.Context) {}

func (f *fakePGW) CreateSession(_ context.Context, sess *session.Session) (*pgw.CreateSessionResult, error) {
	f.mu.Lock()
	f.created++
	f.inflightCreates++
	if f.inflightCreates > f.maxInflightCreates {
		f.maxInflightCreates = f.inflightCreates
	}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflightCreates--
		f.mu.Unlock()
	}()
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &pgw.CreateSessionResult{
		SubscriberIP: sess.SubscriberIP,
		GatewayIP:    sess.GatewayIP,
	}, nil
}

func (f *fakePGW) DeleteSession(context.Context, *session.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted++
	return f.deleteErr
}

func (f *fakePGW) Type() string { return "fake" }

func (f *fakePGW) Close() error { return nil }

type fakeDynamicAuthorizer struct {
	calls int
	err   error
}

func (f *fakeDynamicAuthorizer) DisconnectOrCoA(context.Context, *session.RecoveryTombstone) error {
	f.calls++
	return f.err
}
