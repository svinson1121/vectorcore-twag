package pgw

import (
	"log/slog"
	"testing"

	"github.com/vectorcore/twag/internal/config"
)

func TestNewClientCreatesGTPClient(t *testing.T) {
	client, err := NewClient(config.GTPConfig{
		LocalGTPCIP:     "127.0.0.1",
		RemotePGWGTPCIP: "127.0.0.1",
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.Type() != ModeGTP {
		t.Fatalf("client type = %q", client.Type())
	}
	if closer, ok := client.(*GTPClient); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
}
