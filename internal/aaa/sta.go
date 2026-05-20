package aaa

import (
	"context"
	"log/slog"

	"github.com/vectorcore/twag/internal/diameter"
)

type STaProvider struct {
	client diameter.STaClient
	log    *slog.Logger
}

func NewSTaProvider(client diameter.STaClient, log *slog.Logger) *STaProvider {
	return &STaProvider{client: client, log: log}
}

func (p *STaProvider) Start(ctx context.Context) error {
	if err := p.client.Start(ctx); err != nil {
		return err
	}
	p.log.Info("STa provider initialized")
	return nil
}

func (p *STaProvider) Stop() error {
	return p.client.Stop()
}

func (p *STaProvider) Authenticate(ctx context.Context, req AuthRequest) (*AuthResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	res, err := p.client.Authenticate(ctx, diameter.STaAuthRequest{
		IMSI:     req.IMSI,
		MSISDN:   req.MSISDN,
		Username: req.Username,
		Realm:    req.Realm,
		APN:      req.APN,
		Ki:       req.Ki,
		OPc:      req.OPc,
	})
	if err != nil {
		return nil, err
	}
	if !res.Allowed {
		p.log.Warn("subscriber rejected", "imsi", req.IMSI, "msisdn", req.MSISDN, "mac", req.MACAddress, "apn", req.APN, "subscriber_ip", "", "state", "failed", "reason", res.Reason, "diameter_result_code", res.ResultCode)
		return &AuthResult{
			Allowed:      false,
			IMSI:         coalesce(res.IMSI, req.IMSI),
			MSISDN:       coalesce(res.MSISDN, req.MSISDN),
			APN:          coalesce(res.APN, req.APN),
			SubscriberID: coalesce(res.IMSI, req.IMSI, req.Username, req.MACAddress),
			Reason:       res.Reason,
			ResultCode:   res.ResultCode,
		}, ErrRejected
	}
	p.log.Info("subscriber authorized", "imsi", res.IMSI, "msisdn", res.MSISDN, "mac", req.MACAddress, "apn", res.APN, "subscriber_ip", "", "state", "authorized", "reason", res.Reason, "diameter_result_code", res.ResultCode)
	return &AuthResult{
		Allowed:      true,
		IMSI:         coalesce(res.IMSI, req.IMSI),
		MSISDN:       coalesce(res.MSISDN, req.MSISDN),
		APN:          coalesce(res.APN, req.APN),
		SubscriberID: coalesce(res.IMSI, req.IMSI, req.Username, req.MACAddress),
		Reason:       res.Reason,
		ResultCode:   res.ResultCode,
	}, nil
}

func (p *STaProvider) ExchangeEAP(ctx context.Context, req EAPRequest) (*EAPResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	res, err := p.client.ExchangeEAP(ctx, diameter.STaEAPRequest{
		SessionID:  req.SessionID,
		IMSI:       req.IMSI,
		MSISDN:     req.MSISDN,
		Username:   req.Username,
		Realm:      req.Realm,
		APN:        req.APN,
		EAPPayload: req.EAPPayload,
	})
	if err != nil {
		return nil, err
	}
	state := EAPState(res.State)
	result := &EAPResult{
		SessionID:    res.SessionID,
		State:        state,
		Allowed:      res.Allowed,
		IMSI:         coalesce(res.IMSI, req.IMSI),
		MSISDN:       coalesce(res.MSISDN, req.MSISDN),
		APN:          coalesce(res.APN, req.APN),
		SubscriberID: coalesce(res.IMSI, req.IMSI, req.Username, req.MACAddress),
		Reason:       res.Reason,
		ResultCode:   res.ResultCode,
		EAPPayload:   res.EAPPayload,
		MSK:          append([]byte(nil), res.MSK...),
	}
	if result.State == EAPStateFailure || !result.Allowed && result.State != EAPStateChallenge {
		p.log.Warn("subscriber eap rejected", "session_id", result.SessionID, "imsi", result.IMSI, "msisdn", result.MSISDN, "mac", req.MACAddress, "apn", result.APN, "subscriber_ip", "", "state", "failed", "reason", result.Reason, "diameter_result_code", result.ResultCode)
		return result, ErrRejected
	}
	p.log.Info("subscriber eap result", "session_id", result.SessionID, "imsi", result.IMSI, "msisdn", result.MSISDN, "mac", req.MACAddress, "apn", result.APN, "subscriber_ip", "", "state", result.State, "reason", result.Reason, "diameter_result_code", result.ResultCode, "msk_present", len(result.MSK) == 64, "msk_len", len(result.MSK))
	return result, nil
}

func (p *STaProvider) Type() string { return "sta" }

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
