package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vectorcore/twag/internal/aaa"
	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/gtpu"
	"github.com/vectorcore/twag/internal/ipam"
	"github.com/vectorcore/twag/internal/pgw"
	"github.com/vectorcore/twag/internal/routing"
	"github.com/vectorcore/twag/internal/session"
	"github.com/vectorcore/twag/internal/userplane"
)

type AttachRequest struct {
	IMSI       string `json:"imsi,omitempty"`
	MSISDN     string `json:"msisdn,omitempty"`
	MACAddress string `json:"mac,omitempty"`
	Username   string `json:"username,omitempty"`
	Realm      string `json:"realm,omitempty"`
	APN        string `json:"apn,omitempty"`
	Ki         string `json:"ki,omitempty"`
	OPc        string `json:"opc,omitempty"`
}

type AttachResponse struct {
	SessionID    string        `json:"session_id"`
	State        session.State `json:"state"`
	IMSI         string        `json:"imsi,omitempty"`
	SubscriberIP string        `json:"subscriber_ip,omitempty"`
	APN          string        `json:"apn,omitempty"`
	Reason       string        `json:"reason,omitempty"`
}

type DetachResponse struct {
	SessionID    string        `json:"session_id"`
	State        session.State `json:"state"`
	IMSI         string        `json:"imsi,omitempty"`
	SubscriberIP string        `json:"subscriber_ip,omitempty"`
	APN          string        `json:"apn,omitempty"`
	Reason       string        `json:"reason,omitempty"`
}

type DetachRequest struct {
	SessionID  string `json:"session_id,omitempty"`
	IMSI       string `json:"imsi,omitempty"`
	MACAddress string `json:"mac,omitempty"`
}

type EAPRequest struct {
	SessionID  string
	IMSI       string
	MSISDN     string
	MACAddress string
	Username   string
	Realm      string
	APN        string
	EAPPayload []byte
}

type EAPResponse struct {
	SessionID    string `json:"session_id,omitempty"`
	State        string `json:"state"`
	IMSI         string `json:"imsi,omitempty"`
	SubscriberIP string `json:"subscriber_ip,omitempty"`
	APN          string `json:"apn,omitempty"`
	Reason       string `json:"reason,omitempty"`
	EAPPayload   []byte `json:"-"`
	MSK          []byte `json:"-"`
}

type Service struct {
	cfg      *config.Config
	aaa      aaa.Provider
	sessions *session.Manager
	ipam     ipam.IPAM
	pgw      pgw.Client
	routing  *routing.Manager
	user     userplane.UserPlane
	access   AccessSessionBinder
	log      *slog.Logger
	locks    sync.Map
	counters lifecycleCounters
}

type lifecycleCounters struct {
	duplicateAttachEvents              atomic.Uint64
	duplicateAttachReusedExisting      atomic.Uint64
	duplicateAttachReplacedExisting    atomic.Uint64
	duplicateAttachSuppressedCreate    atomic.Uint64
	controlledReplacement              atomic.Uint64
	overlapPrevented                   atomic.Uint64
	createSessionBlockedExistingActive atomic.Uint64
}

type AccessSessionBinder interface {
	AddSession(ctx context.Context, sess *session.Session) error
	RemoveSession(ctx context.Context, sess *session.Session) error
}

func New(cfg *config.Config, aaaProvider aaa.Provider, sessions *session.Manager, ipam ipam.IPAM, pgwClient pgw.Client, routingMgr *routing.Manager, log *slog.Logger) *Service {
	return &Service{
		cfg:      cfg,
		aaa:      aaaProvider,
		sessions: sessions,
		ipam:     ipam,
		pgw:      pgwClient,
		routing:  routingMgr,
		log:      log,
	}
}

func (s *Service) SetUserPlane(user userplane.UserPlane) {
	s.user = user
}

func (s *Service) SetAccessSessionBinder(access AccessSessionBinder) {
	s.access = access
}

func (s *Service) sessionGatewayIP() net.IP {
	return nil
}

func (s *Service) releaseIP(sessionID string) (bool, error) {
	if s.ipam == nil {
		return false, nil
	}
	return true, s.ipam.Release(sessionID)
}

func (s *Service) Attach(ctx context.Context, req AttachRequest) (*AttachResponse, error) {
	req = s.withDefaults(req)
	unlock, err := s.lockSubscriber(ctx, req.IMSI, req.MACAddress, req.APN)
	if err != nil {
		return nil, err
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	s.log.Info("subscriber attach requested", requestLogAttrs(req)...)
	recovery, recovering := s.logRecoveryAttachIfPresent(req)
	if existing := s.findAttachExisting(req); existing != nil {
		resp, proceed, err := s.handleExistingBeforeAttach(ctx, existing, req)
		if err != nil {
			return nil, err
		}
		if !proceed {
			if recovering {
				s.completeRecovery(existing, resp, recovery)
			}
			return resp, nil
		}
	}
	sess := s.sessions.Create(session.CreateInput{
		IMSI:            req.IMSI,
		MSISDN:          req.MSISDN,
		MACAddress:      req.MACAddress,
		APN:             req.APN,
		Realm:           req.Realm,
		AccessType:      "ethernet",
		AccessInterface: s.cfg.Access.Interface,
		GatewayIP:       s.sessionGatewayIP(),
	})
	if _, err := s.sessions.MarkAuthPending(sess.ID); err != nil {
		return nil, err
	}
	auth, err := s.aaa.Authenticate(ctx, aaa.AuthRequest{
		IMSI:       req.IMSI,
		MSISDN:     req.MSISDN,
		MACAddress: req.MACAddress,
		Username:   req.Username,
		Realm:      req.Realm,
		APN:        req.APN,
		Ki:         req.Ki,
		OPc:        req.OPc,
	})
	if err != nil {
		reason := err.Error()
		if auth != nil && auth.Reason != "" {
			reason = auth.Reason
		}
		s.log.Warn("subscriber rejected", append(sessionLogAttrs(sess), "reason", reason)...)
		failed, markErr := s.sessions.MarkFailed(sess.ID, reason)
		if markErr != nil {
			return nil, errors.Join(err, markErr)
		}
		return responseFromSession(failed), err
	}
	authIMSI := coalesceString(auth.IMSI, req.IMSI)
	authAPN := coalesceString(auth.APN, req.APN)
	if subscriberLockKey(authIMSI, req.MACAddress, authAPN) != subscriberLockKey(req.IMSI, req.MACAddress, req.APN) {
		unlock()
		unlock = nil
		unlock, err = s.lockSubscriber(ctx, authIMSI, req.MACAddress, authAPN)
		if err != nil {
			return nil, err
		}
		if existing := s.findAttachExisting(AttachRequest{IMSI: authIMSI, MACAddress: req.MACAddress, APN: authAPN}); existing != nil {
			resp, proceed, err := s.handleExistingBeforeAttach(ctx, existing, req)
			if err != nil {
				return nil, err
			}
			if !proceed {
				s.discardPreAuthSession(sess)
				if recovering {
					s.completeRecovery(existing, resp, recovery)
				}
				return resp, nil
			}
		}
	}
	resp, err := s.activateAuthorizedSession(ctx, sess, auth)
	if err == nil && recovering {
		s.completeRecovery(sess, resp, recovery)
	}
	return resp, err
}

func (s *Service) discardPreAuthSession(sess *session.Session) {
	if sess == nil {
		return
	}
	terminating, err := s.sessions.MarkTerminating(sess.ID)
	if err != nil {
		s.log.Warn("discard pending duplicate attach session failed", append(sessionLogAttrs(sess), "reason", err.Error())...)
		return
	}
	if terminated, ok := s.sessions.Delete(terminating.ID); ok {
		s.log.Info("discarded pending duplicate attach session", sessionLogAttrs(terminated)...)
	}
}

func (s *Service) AttachAuthorized(ctx context.Context, req AttachRequest, auth *aaa.AuthResult) (*AttachResponse, error) {
	req = s.withDefaults(req)
	if auth == nil {
		auth = &aaa.AuthResult{
			Allowed: true,
			IMSI:    req.IMSI,
			MSISDN:  req.MSISDN,
			APN:     req.APN,
			Reason:  "authorized",
		}
	}
	if !auth.Allowed {
		return nil, aaa.ErrRejected
	}
	lockIMSI := coalesceString(auth.IMSI, req.IMSI)
	lockAPN := coalesceString(auth.APN, req.APN)
	unlock, err := s.lockSubscriber(ctx, lockIMSI, req.MACAddress, lockAPN)
	if err != nil {
		return nil, err
	}
	defer unlock()
	s.log.Info("authorized subscriber attach requested", requestLogAttrs(req)...)
	recovery, recovering := s.logRecoveryAttachIfPresent(req)
	if existing := s.findAttachExisting(AttachRequest{IMSI: lockIMSI, MACAddress: req.MACAddress, APN: lockAPN}); existing != nil {
		resp, proceed, err := s.handleExistingBeforeAttach(ctx, existing, req)
		if err != nil {
			return nil, err
		}
		if !proceed {
			if recovering {
				s.completeRecovery(existing, resp, recovery)
			}
			return resp, nil
		}
	}
	sess := s.sessions.Create(session.CreateInput{
		IMSI:            coalesceString(auth.IMSI, req.IMSI),
		MSISDN:          coalesceString(auth.MSISDN, req.MSISDN),
		MACAddress:      req.MACAddress,
		APN:             coalesceString(auth.APN, req.APN),
		Realm:           req.Realm,
		AccessType:      "ethernet",
		AccessInterface: s.cfg.Access.Interface,
		GatewayIP:       s.sessionGatewayIP(),
	})
	if _, err := s.sessions.MarkAuthPending(sess.ID); err != nil {
		return nil, err
	}
	resp, err := s.activateAuthorizedSession(ctx, sess, auth)
	if err == nil && recovering {
		s.completeRecovery(sess, resp, recovery)
	}
	return resp, err
}

func (s *Service) ExchangeEAP(ctx context.Context, req EAPRequest) (*EAPResponse, error) {
	req = s.eapWithDefaults(req)
	res, err := s.aaa.ExchangeEAP(ctx, aaa.EAPRequest{
		SessionID:  req.SessionID,
		IMSI:       req.IMSI,
		MSISDN:     req.MSISDN,
		MACAddress: req.MACAddress,
		Username:   req.Username,
		Realm:      req.Realm,
		APN:        req.APN,
		EAPPayload: req.EAPPayload,
	})
	if err != nil && res == nil {
		return nil, err
	}
	if res.State == aaa.EAPStateChallenge {
		return &EAPResponse{
			SessionID:  res.SessionID,
			State:      string(res.State),
			IMSI:       res.IMSI,
			APN:        res.APN,
			Reason:     res.Reason,
			EAPPayload: res.EAPPayload,
			MSK:        append([]byte(nil), res.MSK...),
		}, nil
	}
	if err != nil {
		return &EAPResponse{
			SessionID:  res.SessionID,
			State:      string(res.State),
			IMSI:       res.IMSI,
			APN:        res.APN,
			Reason:     res.Reason,
			EAPPayload: res.EAPPayload,
			MSK:        append([]byte(nil), res.MSK...),
		}, err
	}
	if res.State != aaa.EAPStateSuccess || !res.Allowed {
		return &EAPResponse{
			SessionID:  res.SessionID,
			State:      string(aaa.EAPStateFailure),
			IMSI:       res.IMSI,
			APN:        res.APN,
			Reason:     coalesceString(res.Reason, "eap rejected"),
			EAPPayload: res.EAPPayload,
			MSK:        append([]byte(nil), res.MSK...),
		}, aaa.ErrRejected
	}
	attach, err := s.AttachAuthorized(ctx, AttachRequest{
		IMSI:       coalesceString(res.IMSI, req.IMSI),
		MSISDN:     coalesceString(res.MSISDN, req.MSISDN),
		MACAddress: req.MACAddress,
		Username:   req.Username,
		Realm:      req.Realm,
		APN:        coalesceString(res.APN, req.APN),
	}, &aaa.AuthResult{
		Allowed:      true,
		IMSI:         coalesceString(res.IMSI, req.IMSI),
		MSISDN:       coalesceString(res.MSISDN, req.MSISDN),
		APN:          coalesceString(res.APN, req.APN),
		SubscriberID: res.SubscriberID,
		Reason:       res.Reason,
		ResultCode:   res.ResultCode,
	})
	if err != nil {
		return nil, err
	}
	return &EAPResponse{
		SessionID:    coalesceString(attach.SessionID, res.SessionID),
		State:        string(aaa.EAPStateSuccess),
		IMSI:         attach.IMSI,
		SubscriberIP: attach.SubscriberIP,
		APN:          attach.APN,
		Reason:       attach.Reason,
		EAPPayload:   res.EAPPayload,
		MSK:          append([]byte(nil), res.MSK...),
	}, nil
}

func (s *Service) activateAuthorizedSession(ctx context.Context, sess *session.Session, auth *aaa.AuthResult) (*AttachResponse, error) {
	authorized, err := s.sessions.ApplyAuthResult(sess.ID, auth.IMSI, auth.MSISDN, auth.APN, auth.Reason)
	if err != nil {
		return nil, err
	}
	allocated := authorized
	if s.pgw.Type() != pgw.ModeGTP {
		ip, err := s.ipam.Allocate(authorized.ID)
		if err != nil {
			s.log.Warn("subscriber ip allocation failed", append(sessionLogAttrs(authorized), "reason", err.Error())...)
			failed, markErr := s.sessions.MarkFailed(authorized.ID, err.Error())
			if markErr != nil {
				return nil, errors.Join(err, markErr)
			}
			return responseFromSession(failed), err
		}
		allocated, err = s.sessions.SetSubscriberIP(authorized.ID, ip)
		if err != nil {
			s.releaseIP(authorized.ID)
			return nil, err
		}
		s.log.Info("IP allocated", sessionLogAttrs(allocated)...)
	}
	pending, err := s.sessions.MarkPGWPending(allocated.ID)
	if err != nil {
		s.releaseIP(allocated.ID)
		return nil, err
	}
	if existing, ok := s.findLiveSessionDifferentFrom(pending); ok {
		s.counters.createSessionBlockedExistingActive.Add(1)
		s.counters.overlapPrevented.Add(1)
		s.log.Warn("PGW Create Session blocked because live session exists",
			"session_id", pending.ID,
			"imsi", pending.IMSI,
			"mac", pending.MACAddress,
			"apn", pending.APN,
			"existing_session_id", existing.ID,
			"existing_state", existing.State,
			"subscriber_ip", ipString(existing.SubscriberIP),
		)
		err := fmt.Errorf("live PGW session already exists for subscriber")
		s.releaseIP(pending.ID)
		failed, markErr := s.sessions.MarkFailed(pending.ID, err.Error())
		if markErr != nil {
			return nil, errors.Join(err, markErr)
		}
		return responseFromSession(failed), err
	}
	s.log.Info("PGW Create Session decision", append(sessionLogAttrs(pending), "decision", "create_new", "existing_session_id", "", "existing_state", "", "reason", "no existing live session")...)
	s.log.Info("PGW Create Session permitted", append(sessionLogAttrs(pending), "no_existing_live_session", true)...)
	s.log.Info("PGW session requested", sessionLogAttrs(pending)...)
	pgwResult, err := s.pgw.CreateSession(ctx, pending)
	if err != nil {
		s.log.Warn("PGW session failed", append(sessionLogAttrs(pending), "reason", err.Error())...)
		s.releaseIP(pending.ID)
		failed, markErr := s.sessions.MarkFailed(pending.ID, err.Error())
		if markErr != nil {
			return nil, errors.Join(err, markErr)
		}
		return responseFromSession(failed), err
	}
	routable := pending
	if pgwResult != nil {
		if pgwResult.SubscriberIP != nil && (pending.SubscriberIP == nil || !pgwResult.SubscriberIP.Equal(pending.SubscriberIP)) {
			if pending.SubscriberIP != nil {
				s.releaseIP(pending.ID)
			}
			updated, updateErr := s.sessions.UpdateSubscriberIP(pending.ID, pgwResult.SubscriberIP)
			if updateErr != nil {
				return nil, updateErr
			}
			routable = updated
			s.log.Info("PGW assigned subscriber IP", sessionLogAttrs(routable)...)
		}
		if pgwResult.PGWControlIP != nil || pgwResult.PGWUserIP != nil || pgwResult.GTPCTEID != 0 || pgwResult.LocalGTPUTEID != 0 || pgwResult.RemoteGTPUTEID != 0 {
			updated, updateErr := s.sessions.ApplyPGWResult(routable.ID, pgwResult.PGWControlIP, pgwResult.PGWUserIP, pgwResult.GTPCTEID, pgwResult.LocalGTPUTEID, pgwResult.RemoteGTPUTEID)
			if updateErr != nil {
				return nil, updateErr
			}
			routable = updated
		}
	}
	if routable.SubscriberIP == nil {
		err := fmt.Errorf("PGW Create Session Response missing subscriber IPv4 PAA")
		s.log.Warn("PGW session failed", append(sessionLogAttrs(routable), "reason", err.Error())...)
		_ = s.pgw.DeleteSession(ctx, routable)
		s.releaseIP(routable.ID)
		failed, markErr := s.sessions.MarkFailed(routable.ID, err.Error())
		if markErr != nil {
			return nil, errors.Join(err, markErr)
		}
		return responseFromSession(failed), err
	}
	if err := s.routing.Install(routable); err != nil {
		s.log.Warn("routing install failed", append(sessionLogAttrs(routable), "reason", err.Error())...)
		_ = s.pgw.DeleteSession(ctx, routable)
		s.releaseIP(routable.ID)
		failed, markErr := s.sessions.MarkFailed(routable.ID, err.Error())
		if markErr != nil {
			return nil, errors.Join(err, markErr)
		}
		return responseFromSession(failed), err
	}
	if s.user != nil {
		if err := s.user.AddSession(ctx, routable); err != nil {
			s.log.Warn("user plane session bind failed", append(sessionLogAttrs(routable), "reason", err.Error(), "user_plane", s.user.Type())...)
			_ = s.routing.Remove(routable)
			_ = s.pgw.DeleteSession(ctx, routable)
			s.releaseIP(routable.ID)
			failed, markErr := s.sessions.MarkFailed(routable.ID, err.Error())
			if markErr != nil {
				return nil, errors.Join(err, markErr)
			}
			return responseFromSession(failed), err
		}
	}
	active, err := s.sessions.MarkActive(routable.ID)
	if err != nil {
		return nil, err
	}
	if s.access != nil {
		if err := s.access.AddSession(ctx, active); err != nil {
			s.log.Warn("access-side session bind failed", append(sessionLogAttrs(active), "reason", err.Error())...)
			_ = s.user.RemoveSession(ctx, active)
			_ = s.routing.Remove(active)
			_ = s.pgw.DeleteSession(ctx, active)
			s.releaseIP(active.ID)
			failed, markErr := s.sessions.MarkFailed(active.ID, err.Error())
			if markErr != nil {
				return nil, errors.Join(err, markErr)
			}
			return responseFromSession(failed), err
		}
	}
	s.log.Info("session active", sessionLogAttrs(active)...)
	return responseFromSession(active), nil
}

func (s *Service) Detach(ctx context.Context, req DetachRequest) (*DetachResponse, error) {
	sess, err := s.findDetachSession(req)
	if err != nil {
		return nil, err
	}
	unlock, err := s.lockSubscriber(ctx, sess.IMSI, sess.MACAddress, sess.APN)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.detachSessionLocked(ctx, sess)
}

func (s *Service) detachSessionLocked(ctx context.Context, sess *session.Session) (*DetachResponse, error) {
	terminating, err := s.sessions.MarkTerminating(sess.ID)
	if err != nil {
		return nil, err
	}
	var errs []error
	if err := s.pgw.DeleteSession(ctx, terminating); err != nil {
		errs = append(errs, err)
	}
	if err := s.routing.Remove(terminating); err != nil {
		errs = append(errs, err)
	}
	if s.user != nil {
		if err := s.user.RemoveSession(ctx, terminating); err != nil {
			errs = append(errs, err)
		}
	}
	if s.access != nil {
		if err := s.access.RemoveSession(ctx, terminating); err != nil {
			errs = append(errs, err)
		}
	}
	if released, err := s.releaseIP(terminating.ID); err != nil {
		errs = append(errs, err)
	} else if released {
		s.log.Info("IP released", sessionLogAttrs(terminating)...)
	}
	terminated, _ := s.sessions.Delete(terminating.ID)
	if terminated != nil {
		s.log.Info("session terminated", sessionLogAttrs(terminated)...)
	}
	return detachResponseFromSession(terminated), errors.Join(errs...)
}

func (s *Service) HandleGTPUErrorIndication(ctx context.Context, ind gtpu.ErrorIndication) error {
	if ind.OffendingTEID == 0 {
		s.log.Warn("GTP-U Error Indication unmapped",
			"remote_ip", ipStringFromAddr(ind.RemoteAddr),
			"offending_teid", fmt.Sprintf("0x%08x", ind.OffendingTEID),
			"mapped", false,
			"action", "log_only",
		)
		return nil
	}
	sess, ok := s.sessions.LookupByRemoteGTPUTEID(ind.OffendingTEID)
	if !ok {
		s.log.Warn("GTP-U Error Indication unmapped",
			"remote_ip", ipStringFromAddr(ind.RemoteAddr),
			"offending_teid", fmt.Sprintf("0x%08x", ind.OffendingTEID),
			"mapped", false,
			"action", "log_only",
		)
		return nil
	}
	updated, err := s.sessions.RecordGTPUError(sess.ID, ind.OffendingTEID, time.Now().UTC())
	if err == nil && updated != nil {
		sess = updated
	}
	s.log.Warn("GTP-U Error Indication received",
		"remote_ip", ipStringFromAddr(ind.RemoteAddr),
		"offending_teid", fmt.Sprintf("0x%08x", ind.OffendingTEID),
		"mapped", true,
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"mac", sess.MACAddress,
		"subscriber_ip", ipString(sess.SubscriberIP),
		"remote_gtpu_teid", fmt.Sprintf("0x%08x", sess.RemoteGTPUTEID),
		"local_gtpu_teid", fmt.Sprintf("0x%08x", sess.LocalGTPUTEID),
		"action", "cleanup_session",
	)
	if sess.State != session.Active {
		s.log.Info("GTP-U Error Indication matched non-active session; cleanup skipped",
			"session_id", sess.ID,
			"state", sess.State,
			"offending_teid", fmt.Sprintf("0x%08x", ind.OffendingTEID),
		)
		return nil
	}
	unlock, err := s.lockSubscriber(ctx, sess.IMSI, sess.MACAddress, sess.APN)
	if err != nil {
		return err
	}
	defer unlock()
	latest, ok := s.sessions.Get(sess.ID)
	if !ok {
		return nil
	}
	sess = latest
	if sess.State != session.Active {
		s.log.Info("GTP-U Error Indication matched non-active session; cleanup skipped",
			"session_id", sess.ID,
			"state", sess.State,
			"offending_teid", fmt.Sprintf("0x%08x", ind.OffendingTEID),
		)
		return nil
	}
	reason := fmt.Sprintf("GTP-U Error Indication for TEID 0x%08x", ind.OffendingTEID)
	recovering, err := s.sessions.MarkRecovering(sess.ID, reason)
	if err == nil && recovering != nil {
		sess = recovering
	}
	if s.cfg.Recovery.Enabled && s.cfg.Recovery.ReasonGTPUError {
		tombstone, ok := s.sessions.AddRecoveryTombstone(sess, reason, time.Duration(s.cfg.Recovery.RecoveryWindowSeconds)*time.Second)
		if ok {
			s.log.Warn("session recovery pending after GTP-U Error Indication",
				"session_id", sess.ID,
				"imsi", sess.IMSI,
				"mac", sess.MACAddress,
				"old_subscriber_ip", ipString(tombstone.OldSubscriberIP),
				"offending_teid", fmt.Sprintf("0x%08x", ind.OffendingTEID),
				"recovery_window_seconds", s.cfg.Recovery.RecoveryWindowSeconds,
			)
		}
	}
	s.log.Warn("session cleanup triggered by GTP-U Error Indication",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"mac", sess.MACAddress,
		"subscriber_ip", ipString(sess.SubscriberIP),
		"remote_gtpu_teid", fmt.Sprintf("0x%08x", sess.RemoteGTPUTEID),
		"local_gtpu_teid", fmt.Sprintf("0x%08x", sess.LocalGTPUTEID),
	)
	if _, err := s.detachSessionLocked(ctx, sess); err != nil {
		if pgw.IsContextNotFound(err) {
			s.log.Warn("PGW session not found during GTP-U Error Indication cleanup; local cleanup already attempted",
				"session_id", sess.ID,
				"offending_teid", fmt.Sprintf("0x%08x", ind.OffendingTEID),
				"gtp_cause", 64,
			)
			return nil
		}
		return err
	}
	return nil
}

func (s *Service) logRecoveryAttachIfPresent(req AttachRequest) (*session.RecoveryTombstone, bool) {
	if !s.cfg.Recovery.Enabled || !s.cfg.Recovery.AllowSameMACReattach {
		return nil, false
	}
	t, ok := s.sessions.FindRecovery(req.IMSI, req.MACAddress)
	if !ok {
		return nil, false
	}
	s.log.Info("fresh attach accepted during recovery window",
		"imsi", req.IMSI,
		"mac", req.MACAddress,
		"old_session_id", t.OldSessionID,
		"old_subscriber_ip", ipString(t.OldSubscriberIP),
	)
	return t, true
}

func (s *Service) completeRecovery(created *session.Session, resp *AttachResponse, old *session.RecoveryTombstone) {
	if resp == nil || old == nil {
		return
	}
	active, ok := s.sessions.Get(resp.SessionID)
	if !ok && created != nil {
		active, ok = s.sessions.Get(created.ID)
	}
	if !ok {
		return
	}
	if completed, ok := s.sessions.CompleteRecoveryFor(active); ok {
		s.log.Info("session recovery completed",
			"old_session_id", completed.OldSessionID,
			"new_session_id", active.ID,
			"old_subscriber_ip", ipString(completed.OldSubscriberIP),
			"new_subscriber_ip", ipString(active.SubscriberIP),
			"imsi", active.IMSI,
			"mac", active.MACAddress,
		)
	}
}

func (s *Service) Shutdown(ctx context.Context) error {
	sessions := s.sessions.List()
	var errs []error
	detached := 0
	for i := range sessions {
		sess := sessions[i]
		if !shutdownShouldDetach(sess.State) {
			continue
		}
		if _, err := s.Detach(ctx, DetachRequest{SessionID: sess.ID}); err != nil {
			errs = append(errs, fmt.Errorf("detach session %s: %w", sess.ID, err))
			s.log.Warn("session shutdown detach failed", append(sessionLogAttrs(&sess), "error", err)...)
			continue
		}
		detached++
	}
	s.log.Info("session shutdown complete", "sessions_detached", detached, "errors", len(errs))
	return errors.Join(errs...)
}

func (s *Service) handleExistingBeforeAttach(ctx context.Context, existing *session.Session, req AttachRequest) (*AttachResponse, bool, error) {
	if existing == nil {
		return nil, true, nil
	}
	if !isLivePGWOwner(existing.State) {
		return nil, true, nil
	}
	s.counters.duplicateAttachEvents.Add(1)
	decision := "reuse_existing"
	reason := "existing active session is healthy"
	if s.shouldReplaceExisting(existing, req) {
		decision = "controlled_replace"
		reason = "duplicate attach policy requires replacement or existing session is stale"
	}
	s.log.Info("PGW Create Session decision",
		"imsi", coalesceString(req.IMSI, existing.IMSI),
		"mac", coalesceString(req.MACAddress, existing.MACAddress),
		"apn", coalesceString(req.APN, existing.APN),
		"decision", decision,
		"existing_session_id", existing.ID,
		"existing_state", existing.State,
		"reason", reason,
	)
	if decision == "reuse_existing" {
		s.counters.duplicateAttachReusedExisting.Add(1)
		s.counters.duplicateAttachSuppressedCreate.Add(1)
		s.counters.overlapPrevented.Add(1)
		s.counters.createSessionBlockedExistingActive.Add(1)
		s.log.Info("duplicate attach suppressed; existing active PGW session reused",
			"imsi", existing.IMSI,
			"mac", existing.MACAddress,
			"apn", existing.APN,
			"existing_session_id", existing.ID,
			"subscriber_ip", ipString(existing.SubscriberIP),
			"state", existing.State,
		)
		s.log.Info("PGW Create Session blocked because live session exists",
			"existing_session_id", existing.ID,
			"existing_state", existing.State,
			"subscriber_ip", ipString(existing.SubscriberIP),
		)
		return responseFromSession(existing), false, nil
	}
	s.counters.duplicateAttachReplacedExisting.Add(1)
	s.counters.controlledReplacement.Add(1)
	s.log.Warn("duplicate attach requires controlled replacement",
		"imsi", existing.IMSI,
		"mac", existing.MACAddress,
		"apn", existing.APN,
		"old_session_id", existing.ID,
		"reason", "new EAP success for existing active subscriber",
	)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.Lifecycle.DuplicateAttachCleanupTimeoutSeconds)*time.Second)
	defer cancel()
	if err := s.detachExistingBeforeAttach(ctx, existing); err != nil {
		return nil, false, err
	}
	s.log.Info("old session cleanup complete; creating replacement PGW session",
		"old_session_id", existing.ID,
		"imsi", existing.IMSI,
		"mac", existing.MACAddress,
		"apn", existing.APN,
	)
	return nil, true, nil
}

func (s *Service) shouldReplaceExisting(existing *session.Session, req AttachRequest) bool {
	if existing == nil {
		return false
	}
	if s.cfg.Lifecycle.DuplicateAttachPolicy == "replace_existing" {
		return true
	}
	if existing.State != session.Active {
		return true
	}
	if existing.SubscriberIP == nil {
		return true
	}
	if existing.GTPUErrorCount > 0 || existing.State == session.Recovering || existing.State == session.Failed {
		return true
	}
	if req.APN != "" && existing.APN != "" && !strings.EqualFold(req.APN, existing.APN) {
		return true
	}
	return false
}

func (s *Service) findLiveSessionDifferentFrom(sess *session.Session) (*session.Session, bool) {
	if sess == nil {
		return nil, false
	}
	candidates := s.sessions.FindByIMSIAPN(sess.IMSI, sess.APN)
	if sess.MACAddress != "" {
		candidates = append(candidates, s.sessions.FindByMAC(sess.MACAddress)...)
	}
	for _, candidate := range candidates {
		if candidate == nil || candidate.ID == sess.ID || !isLivePGWOwner(candidate.State) {
			continue
		}
		if subscriberSame(candidate, sess) {
			return candidate, true
		}
	}
	return nil, false
}

func subscriberSame(a, b *session.Session) bool {
	if a == nil || b == nil {
		return false
	}
	if a.IMSI != "" && b.IMSI != "" && a.IMSI != b.IMSI {
		return false
	}
	if a.MACAddress != "" && b.MACAddress != "" && normalizeMAC(a.MACAddress) != normalizeMAC(b.MACAddress) {
		return false
	}
	if a.APN != "" && b.APN != "" && !strings.EqualFold(a.APN, b.APN) {
		return false
	}
	return (a.IMSI != "" && a.IMSI == b.IMSI) || (a.MACAddress != "" && normalizeMAC(a.MACAddress) == normalizeMAC(b.MACAddress))
}

func (s *Service) lockSubscriber(ctx context.Context, imsi, mac, apn string) (func(), error) {
	key := subscriberLockKey(imsi, mac, apn)
	raw, _ := s.locks.LoadOrStore(key, make(chan struct{}, 1))
	ch := raw.(chan struct{})
	timeout := time.Duration(s.cfg.Lifecycle.PerSubscriberLockTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("timed out waiting for subscriber lifecycle lock for %s", key)
	}
}

func subscriberLockKey(imsi, mac, apn string) string {
	return strings.TrimSpace(imsi) + "|" + normalizeMAC(mac) + "|" + strings.ToLower(strings.TrimSpace(apn))
}

func (s *Service) withDefaults(req AttachRequest) AttachRequest {
	if req.APN == "" {
		req.APN = s.cfg.Subscriber.DefaultAPN
	}
	if req.Realm == "" {
		req.Realm = s.cfg.Subscriber.DefaultRealm
	}
	return req
}

func (s *Service) eapWithDefaults(req EAPRequest) EAPRequest {
	if req.APN == "" {
		req.APN = s.cfg.Subscriber.DefaultAPN
	}
	if req.Realm == "" {
		req.Realm = s.cfg.Subscriber.DefaultRealm
	}
	return req
}

func (s *Service) findDetachSession(req DetachRequest) (*session.Session, error) {
	if req.SessionID == "" && req.IMSI == "" && req.MACAddress == "" {
		return nil, fmt.Errorf("detach request requires session_id, imsi, or mac")
	}
	if req.SessionID != "" {
		if sess, ok := s.sessions.Get(req.SessionID); ok {
			return sess, nil
		}
	}
	if req.IMSI != "" {
		if sess, ok := s.sessions.LookupByIMSI(req.IMSI); ok {
			return sess, nil
		}
	}
	if req.MACAddress != "" {
		if sess, ok := s.sessions.LookupByMAC(req.MACAddress); ok {
			return sess, nil
		}
	}
	return nil, fmt.Errorf("session not found")
}

func (s *Service) detachExistingBeforeAttach(ctx context.Context, existing *session.Session) error {
	s.log.Warn("existing subscriber session found; detaching before attach", sessionLogAttrs(existing)...)
	if _, err := s.detachSessionLocked(ctx, existing); err != nil {
		if pgw.IsContextNotFound(err) {
			s.log.Warn("existing PGW session not found during duplicate attach cleanup; treating as stale local session",
				"imsi", existing.IMSI,
				"mac", existing.MACAddress,
				"apn", existing.APN,
				"old_session_id", existing.ID,
				"gtp_cause", 64,
				"action", "clear_local_session_and_continue",
			)
			return nil
		}
		return fmt.Errorf("detach existing session before attach: %w", err)
	}
	return nil
}

func (s *Service) findAttachExisting(req AttachRequest) *session.Session {
	if sess, ok := s.sessions.FindAnyBySubscriber(req.IMSI, req.MACAddress, req.APN); ok {
		if sess.State != session.Failed && sess.State != session.Terminated {
			return sess
		}
	}
	return nil
}

func isLivePGWOwner(state session.State) bool {
	switch state {
	case session.Pending, session.AuthPending, session.Authorized, session.IPAllocated, session.PGWPending, session.Active, session.Recovering, session.Terminating:
		return true
	default:
		return false
	}
}

func normalizeMAC(mac string) string {
	if hw, err := net.ParseMAC(mac); err == nil {
		return strings.ToLower(hw.String())
	}
	return strings.ToLower(strings.TrimSpace(mac))
}

func shutdownShouldDetach(state session.State) bool {
	switch state {
	case session.IPAllocated, session.PGWPending, session.Active:
		return true
	default:
		return false
	}
}

func coalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func responseFromSession(sess *session.Session) *AttachResponse {
	if sess == nil {
		return nil
	}
	return &AttachResponse{
		SessionID:    sess.ID,
		State:        sess.State,
		IMSI:         sess.IMSI,
		SubscriberIP: ipString(sess.SubscriberIP),
		APN:          sess.APN,
		Reason:       sess.Reason,
	}
}

func detachResponseFromSession(sess *session.Session) *DetachResponse {
	if sess == nil {
		return nil
	}
	return &DetachResponse{
		SessionID:    sess.ID,
		State:        sess.State,
		IMSI:         sess.IMSI,
		SubscriberIP: ipString(sess.SubscriberIP),
		APN:          sess.APN,
		Reason:       sess.Reason,
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func ipStringFromAddr(addr *net.UDPAddr) string {
	if addr == nil || addr.IP == nil {
		return ""
	}
	return addr.IP.String()
}

func requestLogAttrs(req AttachRequest) []any {
	return []any{
		"imsi", req.IMSI,
		"msisdn", req.MSISDN,
		"mac", req.MACAddress,
		"apn", req.APN,
		"reason", "",
	}
}

func sessionLogAttrs(sess *session.Session) []any {
	if sess == nil {
		return []any{"session_id", "", "imsi", "", "msisdn", "", "mac", "", "apn", "", "subscriber_ip", "", "state", "", "reason", ""}
	}
	return []any{
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"msisdn", sess.MSISDN,
		"mac", sess.MACAddress,
		"apn", sess.APN,
		"subscriber_ip", ipString(sess.SubscriberIP),
		"state", sess.State,
		"reason", sess.Reason,
	}
}
