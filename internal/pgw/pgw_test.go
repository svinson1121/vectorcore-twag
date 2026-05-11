package pgw

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

func TestNewClientDefaultsToStub(t *testing.T) {
	client, err := NewClient(config.PGWConfig{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.Type() != ModeStub {
		t.Fatalf("client type = %q", client.Type())
	}
}

func TestNewClientCreatesGTPClient(t *testing.T) {
	client, err := NewClient(config.PGWConfig{
		Mode:            ModeGTP,
		LocalGTPCIP:     "127.0.0.1",
		RemotePGWGTPCIP: "127.0.0.1",
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewClient(gtp) error = %v", err)
	}
	if client.Type() != ModeGTP {
		t.Fatalf("client type = %q", client.Type())
	}
}

func TestNewClientRejectsUnknownMode(t *testing.T) {
	_, err := NewClient(config.PGWConfig{Mode: "s2a"}, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatalf("expected unknown mode error")
	}
}

func TestStubCreateDeleteSession(t *testing.T) {
	client := NewStub(config.PGWConfig{
		APN:             "internet",
		RemotePGWGTPCIP: "10.90.250.10",
		RemotePGWGTPUIP: "10.90.250.11",
	}, slog.New(slog.DiscardHandler))
	sess := &session.Session{
		ID:           "twag-test",
		IMSI:         "001010000000001",
		APN:          "internet",
		SubscriberIP: net.ParseIP("10.200.0.2"),
		State:        session.PGWPending,
	}
	if err := client.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if _, err := client.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if err := client.DeleteSession(context.Background(), sess); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}
}

func TestStubValidatesSessionAndContext(t *testing.T) {
	client := NewStub(config.PGWConfig{}, slog.New(slog.DiscardHandler))
	if _, err := client.CreateSession(context.Background(), nil); err == nil {
		t.Fatalf("expected nil session create error")
	}
	if err := client.DeleteSession(context.Background(), nil); err == nil {
		t.Fatalf("expected nil session delete error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sess := &session.Session{ID: "twag-test"}
	if _, err := client.CreateSession(ctx, sess); !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateSession canceled error = %v", err)
	}
	if err := client.DeleteSession(ctx, sess); !errors.Is(err, context.Canceled) {
		t.Fatalf("DeleteSession canceled error = %v", err)
	}
}

func TestGTPClientEcho(t *testing.T) {
	addr, done := startEchoPGW(t)
	client, err := NewGTP(config.PGWConfig{
		LocalGTPCIP:     "127.0.0.1",
		RemotePGWGTPCIP: addr.IP.String(),
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewGTP() error = %v", err)
	}
	client.remote.Port = addr.Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Probe(ctx); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	<-done
}

func TestGTPClientCreateDeleteSession(t *testing.T) {
	addr, done := startCreateDeletePGW(t)
	client, err := NewGTP(config.PGWConfig{
		LocalGTPCIP:     "127.0.0.1",
		LocalGTPUIP:     "127.0.0.1",
		RemotePGWGTPCIP: addr.IP.String(),
		RemotePGWGTPUIP: addr.IP.String(),
		APN:             "internet",
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewGTP() error = %v", err)
	}
	client.remote.Port = addr.Port
	sess := &session.Session{
		ID:           "twag-test",
		IMSI:         "001010000000001",
		MSISDN:       "17892000001",
		APN:          "internet",
		Realm:        "epc.mnc001.mcc001.3gppnetwork.org",
		SubscriberIP: net.ParseIP("10.200.0.2"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := client.CreateSession(ctx, sess)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if result.SubscriberIP.String() != "10.200.0.99" {
		t.Fatalf("subscriber ip = %s", result.SubscriberIP)
	}
	if result.GTPCTEID != 0x01020304 || result.RemoteGTPUTEID != 0x05060708 {
		t.Fatalf("unexpected TEIDs %#v", result)
	}
	sess.GTPCTEID = result.GTPCTEID
	if err := client.DeleteSession(ctx, sess); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}
	<-done
}

func startEchoPGW(t *testing.T) (*net.UDPAddr, <-chan struct{}) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer conn.Close() //nolint:errcheck
		buf := make([]byte, 4096)
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read udp: %v", err)
			return
		}
		req, err := decodeGTPv2Message(buf[:n])
		if err != nil {
			t.Errorf("decode echo request: %v", err)
			return
		}
		if req.Type != gtpv2EchoRequest || req.HasTEID {
			t.Errorf("unexpected echo request %#v", req)
			return
		}
		resp, err := (gtpv2Message{
			Type:     gtpv2EchoResponse,
			Sequence: req.Sequence,
		}).encode()
		if err != nil {
			t.Errorf("encode echo response: %v", err)
			return
		}
		if _, err := conn.WriteToUDP(resp, peer); err != nil {
			t.Errorf("write udp: %v", err)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), done
}

func startCreateDeletePGW(t *testing.T) (*net.UDPAddr, <-chan struct{}) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer conn.Close() //nolint:errcheck
		buf := make([]byte, 4096)
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read create: %v", err)
			return
		}
		createReq, err := decodeGTPv2Message(buf[:n])
		if err != nil {
			t.Errorf("decode create: %v", err)
			return
		}
		if createReq.Type != gtpv2CreateSessionReq || !createReq.HasTEID || createReq.TEID != 0 {
			t.Errorf("unexpected create request %#v", createReq)
			return
		}
		ies, err := decodeIEs(createReq.Payload)
		if err != nil {
			t.Errorf("decode create IEs: %v", err)
			return
		}
		if _, ok := findIE(ies, ieIMSI, 0); !ok {
			t.Errorf("create request missing IMSI")
			return
		}
		if _, ok := findIE(ies, ieServingNetwork, 0); !ok {
			t.Errorf("create request missing Serving Network")
			return
		}
		createResp, err := (gtpv2Message{
			Type:     gtpv2CreateSessionResp,
			HasTEID:  true,
			TEID:     0,
			Sequence: createReq.Sequence,
			Payload: encodeIEs(
				gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted}},
				fteidIE(0, ifaceS2aTWANGTPC, 0x01020304, net.ParseIP("127.0.0.1")),
				paaIE(net.ParseIP("10.200.0.99")),
				gtpv2IE{Type: ieBearerContext, Payload: encodeIEs(
					gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted}},
					fteidIE(2, ifaceS2aTWANGTPU, 0x05060708, net.ParseIP("127.0.0.1")),
				)},
			),
		}).encode()
		if err != nil {
			t.Errorf("encode create response: %v", err)
			return
		}
		if _, err := conn.WriteToUDP(createResp, peer); err != nil {
			t.Errorf("write create response: %v", err)
			return
		}
		n, peer, err = conn.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read delete: %v", err)
			return
		}
		deleteReq, err := decodeGTPv2Message(buf[:n])
		if err != nil {
			t.Errorf("decode delete: %v", err)
			return
		}
		if deleteReq.Type != gtpv2DeleteSessionReq || deleteReq.TEID != 0x01020304 {
			t.Errorf("unexpected delete request %#v", deleteReq)
			return
		}
		deleteResp, err := (gtpv2Message{
			Type:     gtpv2DeleteSessionResp,
			HasTEID:  true,
			TEID:     deleteReq.TEID,
			Sequence: deleteReq.Sequence,
			Payload: encodeIEs(
				gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted}},
			),
		}).encode()
		if err != nil {
			t.Errorf("encode delete response: %v", err)
			return
		}
		if _, err := conn.WriteToUDP(deleteResp, peer); err != nil {
			t.Errorf("write delete response: %v", err)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), done
}
