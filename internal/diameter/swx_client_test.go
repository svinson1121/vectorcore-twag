package diameter

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/vectorcore/twag/internal/config"
)

func TestSWxClientConnectsAndAuthenticates(t *testing.T) {
	addr, done := startTestSWxPeer(t, 2001)
	client := NewSWxClient(testSWxConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Stop() //nolint:errcheck

	authCtx, authCancel := context.WithTimeout(ctx, 3*time.Second)
	defer authCancel()
	result, err := client.Authenticate(authCtx, SWxAuthRequest{
		IMSI:   "001010000000001",
		MSISDN: "17892000001",
		Realm:  "ims.example",
		APN:    "internet",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !result.Allowed || result.ResultCode != 2001 {
		t.Fatalf("unexpected result %#v", result)
	}
	<-done
}

func TestSWxClientRejectsNonSuccessResult(t *testing.T) {
	addr, done := startTestSWxPeer(t, 5001)
	client := NewSWxClient(testSWxConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Stop() //nolint:errcheck

	authCtx, authCancel := context.WithTimeout(ctx, 3*time.Second)
	defer authCancel()
	result, err := client.Authenticate(authCtx, SWxAuthRequest{
		IMSI:  "001010000000001",
		Realm: "ims.example",
		APN:   "internet",
	})
	if err != nil {
		t.Fatalf("Authenticate() transport error = %v", err)
	}
	if result.Allowed || result.ResultCode != 5001 {
		t.Fatalf("unexpected result %#v", result)
	}
	<-done
}

func TestSWxClientStartWaitsForCEA(t *testing.T) {
	addr, cerCh, releaseCEA := holdCEAPeer(t)
	client := NewSWxClient(testSWxConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer client.Stop() //nolint:errcheck

	startErr := make(chan error, 1)
	go func() {
		startErr <- client.Start(ctx)
	}()

	select {
	case <-cerCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CER")
	}

	select {
	case err := <-startErr:
		t.Fatalf("Start returned before CEA: %v", err)
	default:
	}

	close(releaseCEA)

	select {
	case err := <-startErr:
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Start did not return after CEA")
	}
}

func TestCERIncludesDRACompatibleCapabilities(t *testing.T) {
	addr, cerCh := captureCERPeer(t)
	client := NewSWxClient(testSWxConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Stop() //nolint:errcheck

	select {
	case cer := <-cerCh:
		if cer.AppID != 0 || cer.Flags&flagProxiable != 0 {
			t.Fatalf("unexpected CER header app_id=%d flags=0x%x", cer.AppID, cer.Flags)
		}
		if got, _ := avpUint32(cer.AVPs, avpVendorID, 0); got != 0 {
			t.Fatalf("CER Vendor-Id = %d, want 0", got)
		}
		product, ok := findAVP(cer.AVPs, avpProductName, 0)
		if !ok {
			t.Fatalf("CER missing Product-Name")
		}
		if product.Flags&flagMandatory != 0 {
			t.Fatalf("CER Product-Name mandatory flag set: 0x%x", product.Flags)
		}
		if got, _ := avpUint32(cer.AVPs, avpFirmwareRevision, 0); got != firmwareRevOne {
			t.Fatalf("CER Firmware-Revision = %d, want %d", got, firmwareRevOne)
		}
		if got, _ := avpUint32(cer.AVPs, avpInbandSecurityID, 0); got != inbandNoSec {
			t.Fatalf("CER Inband-Security-Id = %d, want %d", got, inbandNoSec)
		}
		if got, _ := avpUint32(cer.AVPs, avpAuthApplicationID, 0); got != config.SWxAuthApplicationID {
			t.Fatalf("CER Auth-Application-Id = %d, want SWx %d", got, config.SWxAuthApplicationID)
		}
		if got, _ := avpUint32(cer.AVPs, avpSupportedVendorID, 0); got != vendor3GPP {
			t.Fatalf("CER Supported-Vendor-Id = %d, want %d", got, vendor3GPP)
		}
		vendorID, appID := cerVendorSpecificApplication(t, cer)
		if vendorID != config.SWxVendorID || appID != config.SWxAuthApplicationID {
			t.Fatalf("CER VSAI vendor=%d app=%d", vendorID, appID)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CER")
	}
}

func TestSWxClientWatchdogSuccess(t *testing.T) {
	addr, dwrCh := watchdogSuccessPeer(t)
	client := NewSWxClient(testSWxConfig(addr), slog.New(slog.DiscardHandler))
	client.watchdogInterval = 10 * time.Millisecond
	client.watchdogTimeout = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Stop() //nolint:errcheck

	select {
	case dwr := <-dwrCh:
		if dwr.CommandCode != commandDWR || !dwr.isRequest() {
			t.Fatalf("unexpected watchdog request %#v", dwr)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for DWR")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status := client.Status()
		if !status.LastWatchdog.IsZero() {
			if status.WatchdogFailures != 0 {
				t.Fatalf("watchdog failures = %d", status.WatchdogFailures)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("LastWatchdog was not updated")
}

func TestSWxClientWatchdogFailureClosesPeer(t *testing.T) {
	addr, dwrCh := watchdogFailurePeer(t)
	client := NewSWxClient(testSWxConfig(addr), slog.New(slog.DiscardHandler))
	client.watchdogInterval = 10 * time.Millisecond
	client.watchdogTimeout = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Stop() //nolint:errcheck

	select {
	case dwr := <-dwrCh:
		if dwr.CommandCode != commandDWR || !dwr.isRequest() {
			t.Fatalf("unexpected watchdog request %#v", dwr)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for DWR")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status := client.Status()
		if status.WatchdogFailures > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("WatchdogFailures was not incremented")
}

func startTestSWxPeer(t *testing.T, sarResult uint32) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ln.Close() //nolint:errcheck
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close() //nolint:errcheck
		cer, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode CER: %v", err)
			return
		}
		if cer.CommandCode != commandCER || !cer.isRequest() {
			t.Errorf("unexpected CER header %#v", cer)
			return
		}
		cea := answer(cer, []avp{
			uint32AVP(avpResultCode, 0, 2001),
			utf8AVP(avpOriginHost, 0, "hss.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		})
		if _, err := conn.Write(cea.encode()); err != nil {
			t.Errorf("write CEA: %v", err)
			return
		}
		sar, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode SAR: %v", err)
			return
		}
		if sar.CommandCode != commandSAR || !sar.isRequest() {
			t.Errorf("unexpected SAR header %#v", sar)
			return
		}
		if got := avpString(sar.AVPs, avpUserName, 0); got != "001010000000001" {
			t.Errorf("SAR User-Name = %q", got)
			return
		}
		saa := answer(sar, []avp{
			uint32AVP(avpResultCode, 0, sarResult),
			utf8AVP(avpOriginHost, 0, "hss.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		})
		if _, err := conn.Write(saa.encode()); err != nil {
			t.Errorf("write SAA: %v", err)
		}
	}()
	return ln.Addr().String(), done
}

func watchdogSuccessPeer(t *testing.T) (string, <-chan message) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dwrCh := make(chan message, 1)
	go func() {
		defer ln.Close() //nolint:errcheck
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close() //nolint:errcheck
		cer, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode CER: %v", err)
			return
		}
		cea := answer(cer, []avp{
			uint32AVP(avpResultCode, 0, 2001),
			utf8AVP(avpOriginHost, 0, "hss.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		})
		if _, err := conn.Write(cea.encode()); err != nil {
			t.Errorf("write CEA: %v", err)
			return
		}
		sentFirst := false
		for {
			dwr, err := decodeMessage(conn)
			if err != nil {
				return
			}
			if !sentFirst {
				dwrCh <- dwr
				sentFirst = true
			}
			dwa := answer(dwr, []avp{
				uint32AVP(avpResultCode, 0, 2001),
				utf8AVP(avpOriginHost, 0, "hss.ims.example"),
				utf8AVP(avpOriginRealm, 0, "ims.example"),
			})
			if _, err := conn.Write(dwa.encode()); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), dwrCh
}

func watchdogFailurePeer(t *testing.T) (string, <-chan message) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dwrCh := make(chan message, 1)
	go func() {
		defer ln.Close() //nolint:errcheck
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close() //nolint:errcheck
		cer, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode CER: %v", err)
			return
		}
		cea := answer(cer, []avp{
			uint32AVP(avpResultCode, 0, 2001),
			utf8AVP(avpOriginHost, 0, "hss.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		})
		if _, err := conn.Write(cea.encode()); err != nil {
			t.Errorf("write CEA: %v", err)
			return
		}
		dwr, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode DWR: %v", err)
			return
		}
		dwrCh <- dwr
		_, _ = decodeMessage(conn)
	}()
	return ln.Addr().String(), dwrCh
}

func holdCEAPeer(t *testing.T) (string, <-chan message, chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cerCh := make(chan message, 1)
	releaseCEA := make(chan struct{})
	go func() {
		defer ln.Close() //nolint:errcheck
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close() //nolint:errcheck
		cer, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode CER: %v", err)
			return
		}
		cerCh <- cer
		<-releaseCEA
		cea := answer(cer, []avp{
			uint32AVP(avpResultCode, 0, 2001),
			utf8AVP(avpOriginHost, 0, "hss.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		})
		_, _ = conn.Write(cea.encode())
	}()
	return ln.Addr().String(), cerCh, releaseCEA
}

func captureCERPeer(t *testing.T) (string, <-chan message) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cerCh := make(chan message, 1)
	go func() {
		defer ln.Close() //nolint:errcheck
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close() //nolint:errcheck
		cer, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode CER: %v", err)
			return
		}
		cerCh <- cer
		cea := answer(cer, []avp{
			uint32AVP(avpResultCode, 0, 2001),
			utf8AVP(avpOriginHost, 0, "dra.epc.example"),
			utf8AVP(avpOriginRealm, 0, "epc.example"),
		})
		_, _ = conn.Write(cea.encode())
	}()
	return ln.Addr().String(), cerCh
}

func cerVendorSpecificApplication(t *testing.T, cer message) (uint32, uint32) {
	t.Helper()
	vsai, ok := findAVP(cer.AVPs, avpVendorSpecificApplicationID, 0)
	if !ok {
		t.Fatalf("CER missing Vendor-Specific-Application-Id")
	}
	children, err := decodeAVPs(vsai.Data)
	if err != nil {
		t.Fatalf("decode VSAI: %v", err)
	}
	vendorID, _ := avpUint32(children, avpVendorID, 0)
	appID, _ := avpUint32(children, avpAuthApplicationID, 0)
	return vendorID, appID
}

func answer(req message, avps []avp) message {
	return message{
		Flags:       req.Flags &^ flagRequest,
		CommandCode: req.CommandCode,
		AppID:       req.AppID,
		HopByHop:    req.HopByHop,
		EndToEnd:    req.EndToEnd,
		AVPs:        avps,
	}
}

func testSWxConfig(addr string) config.SWxConfig {
	return config.SWxConfig{
		OriginHost:        "twag.epc.example",
		OriginRealm:       "epc.example",
		DestinationRealm:  "ims.example",
		DestinationHost:   "hss.ims.example",
		PeerAddr:          addr,
		VendorID:          config.SWxVendorID,
		AuthApplicationID: config.SWxAuthApplicationID,
	}
}
