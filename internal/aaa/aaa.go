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
	ExchangeEAP(ctx context.Context, req EAPRequest) (*EAPResult, error)
	Type() string
}

type AuthRequest struct {
	IMSI       string
	MSISDN     string
	MACAddress string
	Username   string
	Realm      string
	APN        string
	Ki         string
	OPc        string
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

type EAPState string

const (
	EAPStateChallenge EAPState = "challenge"
	EAPStateSuccess   EAPState = "success"
	EAPStateFailure   EAPState = "failure"
)

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

func (r EAPRequest) Validate() error {
	if r.IMSI == "" && r.Username == "" && r.MACAddress == "" {
		return fmt.Errorf("eap request requires imsi, username, or mac address")
	}
	if r.APN == "" {
		return fmt.Errorf("eap request requires apn")
	}
	if r.Realm == "" {
		return fmt.Errorf("eap request requires realm")
	}
	if len(r.EAPPayload) == 0 {
		return fmt.Errorf("eap request requires eap payload")
	}
	return nil
}

type EAPResult struct {
	SessionID    string
	State        EAPState
	Allowed      bool
	IMSI         string
	MSISDN       string
	APN          string
	SubscriberID string
	Reason       string
	ResultCode   uint32
	EAPPayload   []byte
	MSK          []byte
}

var ErrRejected = errors.New("subscriber rejected")

func NewProvider(cfg config.AAAConfig, sta diameter.STaClient, log *slog.Logger) (Provider, error) {
	if sta == nil {
		return nil, fmt.Errorf("sta aaa provider requires sta client")
	}
	return NewSTaProvider(sta, log), nil
}
