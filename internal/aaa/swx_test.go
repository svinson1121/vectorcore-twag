package aaa

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/diameter"
)

func TestNewProviderSelectsSWx(t *testing.T) {
	provider, err := NewProvider(config.AAAConfig{Mode: "swx"}, &fakeSWxClient{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}
	if provider.Type() != "swx" {
		t.Fatalf("provider type = %q", provider.Type())
	}
}

func TestNewProviderSelectsStatic(t *testing.T) {
	provider, err := NewProvider(config.AAAConfig{Mode: "static"}, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}
	if provider.Type() != "static" {
		t.Fatalf("provider type = %q", provider.Type())
	}
}

func TestSWxProviderAuthenticateAllowed(t *testing.T) {
	client := &fakeSWxClient{
		result: &diameter.SWxAuthResult{
			ResultCode: 2001,
			Allowed:    true,
			IMSI:       "001010000000001",
			MSISDN:     "17892000001",
			APN:        "internet",
			Reason:     "accepted",
		},
	}
	provider := NewSWxProvider(client, slog.New(slog.DiscardHandler))
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

func TestSWxProviderAuthenticateRejected(t *testing.T) {
	client := &fakeSWxClient{
		result: &diameter.SWxAuthResult{
			ResultCode: 5001,
			Allowed:    false,
			Reason:     "unknown user",
		},
	}
	provider := NewSWxProvider(client, slog.New(slog.DiscardHandler))
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

func TestSWxProviderAuthenticateValidatesRequest(t *testing.T) {
	provider := NewSWxProvider(&fakeSWxClient{}, slog.New(slog.DiscardHandler))
	_, err := provider.Authenticate(context.Background(), AuthRequest{
		IMSI: "001010000000001",
		APN:  "internet",
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestStaticProviderValidatesAndAccepts(t *testing.T) {
	provider := NewStaticProvider(slog.New(slog.DiscardHandler))
	result, err := provider.Authenticate(context.Background(), AuthRequest{
		MACAddress: "aa:bb:cc:dd:ee:01",
		Realm:      "ims.example",
		APN:        "internet",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected static provider to allow")
	}
	if result.SubscriberID != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("subscriber id = %q", result.SubscriberID)
	}
}

type fakeSWxClient struct {
	result *diameter.SWxAuthResult
	err    error
	last   diameter.SWxAuthRequest
}

func (f *fakeSWxClient) Start(context.Context) error { return nil }
func (f *fakeSWxClient) Stop() error                 { return nil }
func (f *fakeSWxClient) Status() diameter.SWxStatus  { return diameter.SWxStatus{} }

func (f *fakeSWxClient) Authenticate(_ context.Context, req diameter.SWxAuthRequest) (*diameter.SWxAuthResult, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}
