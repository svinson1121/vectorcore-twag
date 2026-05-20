package aaa

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/diameter"
)

func TestNewProviderSelectsSTa(t *testing.T) {
	provider, err := NewProvider(config.AAAConfig{}, &fakeSTaClient{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}
	if provider.Type() != "sta" {
		t.Fatalf("provider type = %q", provider.Type())
	}
}

func TestNewProviderRequiresSTaClient(t *testing.T) {
	_, err := NewProvider(config.AAAConfig{}, nil, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("expected missing STa client error")
	}
}

func TestSTaProviderAuthenticateAllowed(t *testing.T) {
	client := &fakeSTaClient{
		result: &diameter.STaAuthResult{
			ResultCode: 2001,
			Allowed:    true,
			IMSI:       "001010000000001",
			MSISDN:     "17892000001",
			APN:        "internet",
			Reason:     "accepted",
		},
	}
	provider := NewSTaProvider(client, slog.New(slog.DiscardHandler))
	result, err := provider.Authenticate(context.Background(), AuthRequest{
		IMSI:   "001010000000001",
		MSISDN: "17892000001",
		Realm:  "ims.example",
		APN:    "internet",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed result")
	}
	if client.last.IMSI != "001010000000001" {
		t.Fatalf("client IMSI = %q", client.last.IMSI)
	}
	if result.SubscriberID != "001010000000001" {
		t.Fatalf("subscriber id = %q", result.SubscriberID)
	}
}

func TestSTaProviderAuthenticateRejected(t *testing.T) {
	client := &fakeSTaClient{
		result: &diameter.STaAuthResult{
			ResultCode: 5001,
			Allowed:    false,
			Reason:     "unknown user",
		},
	}
	provider := NewSTaProvider(client, slog.New(slog.DiscardHandler))
	result, err := provider.Authenticate(context.Background(), AuthRequest{
		IMSI:  "001010000000001",
		Realm: "ims.example",
		APN:   "internet",
	})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("Authenticate() error = %v, want ErrRejected", err)
	}
	if result == nil || result.Allowed {
		t.Fatalf("unexpected result %#v", result)
	}
	if result.ResultCode != 5001 {
		t.Fatalf("result code = %d", result.ResultCode)
	}
}

func TestSTaProviderAuthenticateValidatesRequest(t *testing.T) {
	provider := NewSTaProvider(&fakeSTaClient{}, slog.New(slog.DiscardHandler))
	_, err := provider.Authenticate(context.Background(), AuthRequest{
		IMSI: "001010000000001",
		APN:  "internet",
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

type fakeSTaClient struct {
	result *diameter.STaAuthResult
	eap    *diameter.STaEAPResult
	err    error
	last   diameter.STaAuthRequest
	eapReq diameter.STaEAPRequest
}

func (f *fakeSTaClient) Start(context.Context) error { return nil }
func (f *fakeSTaClient) Stop() error                 { return nil }
func (f *fakeSTaClient) Status() diameter.STaStatus  { return diameter.STaStatus{} }

func (f *fakeSTaClient) Authenticate(_ context.Context, req diameter.STaAuthRequest) (*diameter.STaAuthResult, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func (f *fakeSTaClient) ExchangeEAP(_ context.Context, req diameter.STaEAPRequest) (*diameter.STaEAPResult, error) {
	f.eapReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.eap, nil
}
