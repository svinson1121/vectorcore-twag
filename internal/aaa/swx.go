package aaa

import (
	"context"
	"log/slog"

	"github.com/vectorcore/twag/internal/diameter"
)

type SWxProvider struct {
	client diameter.SWxClient
	log    *slog.Logger
}

func NewSWxProvider(client diameter.SWxClient, log *slog.Logger) *SWxProvider {
	return &SWxProvider{client: client, log: log}
}

func (p *SWxProvider) Start(ctx context.Context) error {
	if err := p.client.Start(ctx); err != nil {
		return err
	}
	p.log.Info("AAA/SWx provider initialized")
	return nil
}

func (p *SWxProvider) Stop() error {
	return p.client.Stop()
}

func (p *SWxProvider) Authenticate(ctx context.Context, req AuthRequest) (*AuthResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	res, err := p.client.Authenticate(ctx, diameter.SWxAuthRequest{
		IMSI:     req.IMSI,
		MSISDN:   req.MSISDN,
		Username: req.Username,
		Realm:    req.Realm,
		APN:      req.APN,
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

func (p *SWxProvider) Type() string { return "swx" }

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
