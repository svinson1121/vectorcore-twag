package aaa

import (
	"context"
	"log/slog"
)

type StaticProvider struct {
	log *slog.Logger
}

func NewStaticProvider(log *slog.Logger) *StaticProvider {
	return &StaticProvider{log: log}
}

func (p *StaticProvider) Start(context.Context) error {
	if p.log != nil {
		p.log.Warn("static AAA provider started; this is not for production authentication")
	}
	return nil
}

func (p *StaticProvider) Stop() error  { return nil }
func (p *StaticProvider) Type() string { return "static" }

func (p *StaticProvider) Authenticate(_ context.Context, req AuthRequest) (*AuthResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return &AuthResult{
		Allowed:      true,
		IMSI:         req.IMSI,
		MSISDN:       req.MSISDN,
		APN:          req.APN,
		SubscriberID: coalesce(req.IMSI, req.Username, req.MACAddress),
		Reason:       "static accepted",
		ResultCode:   2001,
	}, nil
}
