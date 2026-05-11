package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/vectorcore/twag/internal/aaa"
	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/ipam"
	"github.com/vectorcore/twag/internal/pgw"
	"github.com/vectorcore/twag/internal/routing"
	"github.com/vectorcore/twag/internal/session"
)

type AttachRequest struct {
	IMSI       string `json:"imsi,omitempty"`
	MSISDN     string `json:"msisdn,omitempty"`
	MACAddress string `json:"mac,omitempty"`
	Username   string `json:"username,omitempty"`
	Realm      string `json:"realm,omitempty"`
	APN        string `json:"apn,omitempty"`
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

type Service struct {
	cfg      *config.Config
	aaa      aaa.Provider
	sessions *session.Manager
	ipam     ipam.IPAM
	pgw      pgw.Client
	routing  *routing.Manager
	log      *slog.Logger
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

func (s *Service) Attach(ctx context.Context, req AttachRequest) (*AttachResponse, error) {
	req = s.withDefaults(req)
	s.log.Info("subscriber attach requested", requestLogAttrs(req)...)
	if existing := s.findAttachExisting(req); existing != nil {
		s.log.Warn("existing subscriber session found; detaching before attach", sessionLogAttrs(existing)...)
		if _, err := s.Detach(ctx, DetachRequest{SessionID: existing.ID}); err != nil {
			return nil, fmt.Errorf("detach existing session before attach: %w", err)
		}
	}
	sess := s.sessions.Create(session.CreateInput{
		IMSI:            req.IMSI,
		MSISDN:          req.MSISDN,
		MACAddress:      req.MACAddress,
		APN:             req.APN,
		Realm:           req.Realm,
		AccessType:      s.cfg.Access.Mode,
		AccessInterface: s.cfg.Access.Interface,
		GatewayIP:       net.ParseIP(s.cfg.IPAM.Gateway),
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
	authorized, err := s.sessions.ApplyAuthResult(sess.ID, auth.IMSI, auth.MSISDN, auth.APN, auth.Reason)
	if err != nil {
		return nil, err
	}
	ip, err := s.ipam.Allocate(authorized.ID)
	if err != nil {
		s.log.Warn("subscriber ip allocation failed", append(sessionLogAttrs(authorized), "reason", err.Error())...)
		failed, markErr := s.sessions.MarkFailed(authorized.ID, err.Error())
		if markErr != nil {
			return nil, errors.Join(err, markErr)
		}
		return responseFromSession(failed), err
	}
	allocated, err := s.sessions.SetSubscriberIP(authorized.ID, ip)
	if err != nil {
		_ = s.ipam.Release(authorized.ID)
		return nil, err
	}
	s.log.Info("IP allocated", sessionLogAttrs(allocated)...)
	pending, err := s.sessions.MarkPGWPending(allocated.ID)
	if err != nil {
		_ = s.ipam.Release(allocated.ID)
		return nil, err
	}
	s.log.Info("PGW session requested", sessionLogAttrs(pending)...)
	pgwResult, err := s.pgw.CreateSession(ctx, pending)
	if err != nil {
		s.log.Warn("PGW session failed", append(sessionLogAttrs(pending), "reason", err.Error())...)
		_ = s.ipam.Release(pending.ID)
		failed, markErr := s.sessions.MarkFailed(pending.ID, err.Error())
		if markErr != nil {
			return nil, errors.Join(err, markErr)
		}
		return responseFromSession(failed), err
	}
	routable := pending
	if pgwResult != nil {
		if pgwResult.SubscriberIP != nil && !pgwResult.SubscriberIP.Equal(pending.SubscriberIP) {
			_ = s.ipam.Release(pending.ID)
			updated, updateErr := s.sessions.UpdateSubscriberIP(pending.ID, pgwResult.SubscriberIP)
			if updateErr != nil {
				return nil, updateErr
			}
			routable = updated
		}
		if pgwResult.PGWControlIP != nil || pgwResult.PGWUserIP != nil || pgwResult.GTPCTEID != 0 || pgwResult.LocalGTPUTEID != 0 || pgwResult.RemoteGTPUTEID != 0 {
			updated, updateErr := s.sessions.ApplyPGWResult(routable.ID, pgwResult.PGWControlIP, pgwResult.PGWUserIP, pgwResult.GTPCTEID, pgwResult.LocalGTPUTEID, pgwResult.RemoteGTPUTEID)
			if updateErr != nil {
				return nil, updateErr
			}
			routable = updated
		}
	}
	if err := s.routing.Install(routable); err != nil {
		s.log.Warn("routing install failed", append(sessionLogAttrs(routable), "reason", err.Error())...)
		_ = s.pgw.DeleteSession(ctx, routable)
		_ = s.ipam.Release(routable.ID)
		failed, markErr := s.sessions.MarkFailed(routable.ID, err.Error())
		if markErr != nil {
			return nil, errors.Join(err, markErr)
		}
		return responseFromSession(failed), err
	}
	active, err := s.sessions.MarkActive(routable.ID)
	if err != nil {
		return nil, err
	}
	s.log.Info("session active", sessionLogAttrs(active)...)
	return responseFromSession(active), nil
}

func (s *Service) Detach(ctx context.Context, req DetachRequest) (*DetachResponse, error) {
	sess, err := s.findDetachSession(req)
	if err != nil {
		return nil, err
	}
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
	if err := s.ipam.Release(terminating.ID); err != nil {
		errs = append(errs, err)
	} else {
		s.log.Info("IP released", sessionLogAttrs(terminating)...)
	}
	terminated, _ := s.sessions.Delete(terminating.ID)
	if terminated != nil {
		s.log.Info("session terminated", sessionLogAttrs(terminated)...)
	}
	return detachResponseFromSession(terminated), errors.Join(errs...)
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

func (s *Service) withDefaults(req AttachRequest) AttachRequest {
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

func (s *Service) findAttachExisting(req AttachRequest) *session.Session {
	if req.IMSI != "" {
		if sess, ok := s.sessions.LookupByIMSI(req.IMSI); ok {
			if sess.State != session.Failed && sess.State != session.Terminated {
				return sess
			}
		}
	}
	if req.MACAddress != "" {
		if sess, ok := s.sessions.LookupByMAC(req.MACAddress); ok {
			if sess.State != session.Failed && sess.State != session.Terminated {
				return sess
			}
		}
	}
	return nil
}

func shutdownShouldDetach(state session.State) bool {
	switch state {
	case session.IPAllocated, session.PGWPending, session.Active:
		return true
	default:
		return false
	}
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
