package aaa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/diameter"
)

type Provider interface {
	Start(ctx context.Context) error
	Stop() error
	Authenticate(ctx context.Context, req AuthRequest) (*AuthResult, error)
	Type() string
}

type AuthRequest struct {
	IMSI       string
	MSISDN     string
	MACAddress string
	Username   string
	Realm      string
	APN        string
}

func (r AuthRequest) Validate() error {
	if r.IMSI == "" && r.Username == "" && r.MACAddress == "" {
		return fmt.Errorf("auth request requires imsi, username, or mac address")
	}
	if r.APN == "" {
		return fmt.Errorf("auth request requires apn")
	}
	if r.Realm == "" {
		return fmt.Errorf("auth request requires realm")
	}
	return nil
}

type AuthResult struct {
	Allowed      bool
	IMSI         string
	MSISDN       string
	APN          string
	SubscriberID string
	Reason       string
	ResultCode   uint32
}

var ErrRejected = errors.New("subscriber rejected")

func NewProvider(cfg config.AAAConfig, swx diameter.SWxClient, log *slog.Logger) (Provider, error) {
	switch cfg.Mode {
	case "swx":
		if swx == nil {
			return nil, fmt.Errorf("swx aaa provider requires swx client")
		}
		return NewSWxProvider(swx, log), nil
	case "static":
		if log != nil {
			log.Warn("static AAA provider enabled; use only for local development fallback")
		}
		return NewStaticProvider(log), nil
	default:
		return nil, fmt.Errorf("unsupported aaa mode %q", cfg.Mode)
	}
}
