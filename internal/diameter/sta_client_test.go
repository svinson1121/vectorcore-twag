package diameter

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vectorcore/twag/internal/config"
)

func TestSTaClientConnectsAndAuthenticates(t *testing.T) {
	addr, done := startTestSTaPeer(t, 2001)
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Stop() //nolint:errcheck

	authCtx, authCancel := context.WithTimeout(ctx, 3*time.Second)
	defer authCancel()
	result, err := client.Authenticate(authCtx, STaAuthRequest{
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

func TestSTaClientSendsDERToAAAAndReturnsDEA(t *testing.T) {
	addr, captured, done := startCapturingSTaAAA(t, 2001)
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Stop() //nolint:errcheck

	authCtx, authCancel := context.WithTimeout(ctx, 3*time.Second)
	defer authCancel()
	result, err := client.Authenticate(authCtx, STaAuthRequest{
		IMSI:   "001010000000001",
		MSISDN: "17892000001",
		Realm:  "ims.example",
		APN:    "internet",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !result.Allowed || result.ResultCode != 2001 || result.IMSI != "001010000000001" || result.APN != "internet" {
		t.Fatalf("unexpected DEA result %#v", result)
	}

	select {
	case der := <-captured:
		if der.CommandCode != commandDER || !der.isRequest() || der.AppID != config.STaAuthApplicationID {
			t.Fatalf("unexpected DER header command=%d request=%t app_id=%d", der.CommandCode, der.isRequest(), der.AppID)
		}
		assertAVPString(t, der.AVPs, avpUserName, 0, "001010000000001")
		assertAVPString(t, der.AVPs, avpOriginHost, 0, "twag.epc.example")
		assertAVPString(t, der.AVPs, avpOriginRealm, 0, "epc.example")
		assertAVPString(t, der.AVPs, avpDestinationRealm, 0, "ims.example")
		assertAVPString(t, der.AVPs, avpDestinationHost, 0, "aaa.ims.example")
		assertAVPString(t, der.AVPs, avpServiceSelection, 0, "internet")
		assertEAPResponseIdentity(t, der.AVPs, "001010000000001")
		assertAVPUint32(t, der.AVPs, avpAuthApplicationID, 0, config.STaAuthApplicationID)
		assertAVPUint32(t, der.AVPs, avpAuthRequestType, 0, 3)
		assertAVPAbsent(t, der.AVPs, avpVendorSpecificApplicationID, 0)
		assertAVPAbsent(t, der.AVPs, avpAuthSessionState, 0)
		assertAVPAbsent(t, der.AVPs, avpServiceSelection, vendor3GPP)
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for captured DER")
	}
	<-done
}

func TestSTaClientAnswersDERMissingEAPPayload(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close() //nolint:errcheck
	defer serverSide.Close() //nolint:errcheck

	client := NewSTaClient(testSTaConfig("127.0.0.1:3868"), slog.New(slog.DiscardHandler))
	req := message{
		Flags:       flagRequest | flagProxiable,
		CommandCode: commandDER,
		AppID:       config.STaAuthApplicationID,
		HopByHop:    10,
		EndToEnd:    20,
		AVPs: []avp{
			utf8AVP(avpSessionID, 0, "peer;1"),
			utf8AVP(avpUserName, 0, "001010000000001"),
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		client.handleRequest(serverSide, req)
	}()

	resp, err := decodeMessage(clientSide)
	if err != nil {
		t.Fatalf("decode DEA: %v", err)
	}
	<-done
	if resp.CommandCode != commandDER || resp.isRequest() || resp.AppID != config.STaAuthApplicationID {
		t.Fatalf("unexpected DEA header command=%d request=%t app_id=%d", resp.CommandCode, resp.isRequest(), resp.AppID)
	}
	assertAVPUint32(t, resp.AVPs, avpResultCode, 0, 5005)
	failed, ok := findAVP(resp.AVPs, avpFailedAVP, 0)
	if !ok {
		t.Fatalf("DEA missing Failed-AVP")
	}
	children, err := decodeAVPs(failed.Data)
	if err != nil {
		t.Fatalf("decode Failed-AVP: %v", err)
	}
	if _, ok := findAVP(children, avpEAPPayload, 0); !ok {
		t.Fatalf("Failed-AVP did not identify EAP-Payload")
	}
}

func TestSTaClientAnswersASRAndNotifiesHandler(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close() //nolint:errcheck
	defer serverSide.Close() //nolint:errcheck

	client := NewSTaClient(testSTaConfig("127.0.0.1:3868"), slog.New(slog.DiscardHandler))
	events := make(chan STaDisconnectEvent, 1)
	client.SetDisconnectHandler(func(_ context.Context, event STaDisconnectEvent) {
		events <- event
	})
	req := message{
		Flags:       flagRequest | flagProxiable,
		CommandCode: commandASR,
		AppID:       config.STaAuthApplicationID,
		HopByHop:    11,
		EndToEnd:    21,
		AVPs: []avp{
			utf8AVP(avpSessionID, 0, "aaa.ims.example;asr;1"),
			utf8AVP(avpUserName, 0, "0311435000070571@wlan.mnc435.mcc311.3gppnetwork.org"),
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		client.handleRequest(serverSide, req)
	}()

	resp, err := decodeMessage(clientSide)
	if err != nil {
		t.Fatalf("decode ASA: %v", err)
	}
	<-done
	if resp.CommandCode != commandASR || resp.isRequest() || resp.AppID != config.STaAuthApplicationID {
		t.Fatalf("unexpected ASA header command=%d request=%t app_id=%d", resp.CommandCode, resp.isRequest(), resp.AppID)
	}
	assertAVPUint32(t, resp.AVPs, avpResultCode, 0, 2001)
	assertAVPString(t, resp.AVPs, avpSessionID, 0, "aaa.ims.example;asr;1")
	assertAVPString(t, resp.AVPs, avpUserName, 0, "0311435000070571@wlan.mnc435.mcc311.3gppnetwork.org")

	select {
	case event := <-events:
		if event.Command != "ASR" || event.SessionID != "aaa.ims.example;asr;1" || event.IMSI != "311435000070571" {
			t.Fatalf("unexpected disconnect event %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for disconnect event")
	}
}

func TestSTaClientRejectsASRWithoutSessionID(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close() //nolint:errcheck
	defer serverSide.Close() //nolint:errcheck

	client := NewSTaClient(testSTaConfig("127.0.0.1:3868"), slog.New(slog.DiscardHandler))
	events := make(chan STaDisconnectEvent, 1)
	client.SetDisconnectHandler(func(_ context.Context, event STaDisconnectEvent) {
		events <- event
	})
	req := message{
		Flags:       flagRequest | flagProxiable,
		CommandCode: commandASR,
		AppID:       config.STaAuthApplicationID,
		HopByHop:    12,
		EndToEnd:    22,
		AVPs: []avp{
			utf8AVP(avpUserName, 0, "311435000070571"),
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		client.handleRequest(serverSide, req)
	}()

	resp, err := decodeMessage(clientSide)
	if err != nil {
		t.Fatalf("decode ASA: %v", err)
	}
	<-done
	assertAVPUint32(t, resp.AVPs, avpResultCode, 0, 5005)
	select {
	case event := <-events:
		t.Fatalf("unexpected disconnect event %#v", event)
	default:
	}
}

func TestSTaClientRejectsNonSuccessResult(t *testing.T) {
	addr, done := startTestSTaPeer(t, 5001)
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Stop() //nolint:errcheck

	authCtx, authCancel := context.WithTimeout(ctx, 3*time.Second)
	defer authCancel()
	result, err := client.Authenticate(authCtx, STaAuthRequest{
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

func TestSTaClientDoesNotAuthorizeEAPAKAChallengeDEA(t *testing.T) {
	eapChallenge := []byte{
		1, 1, 0, 48, 23, 1, 0, 0,
		1, 5, 0, 0, 47, 237, 4, 163, 76, 166, 11, 184, 252, 41, 57, 49, 42, 136, 125, 212,
		2, 5, 0, 0, 200, 216, 250, 135, 23, 131, 128, 0, 165, 18, 130, 236, 207, 49, 97, 59,
	}
	addr, done := startTestSTaPeerWithDEAAVPs(t, []avp{
		uint32AVP(avpResultCode, 0, 2001),
		utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
		utf8AVP(avpOriginRealm, 0, "ims.example"),
		{Code: avpEAPPayload, Flags: flagMandatory, Data: eapChallenge},
	})
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Stop() })

	authCtx, authCancel := context.WithTimeout(context.Background(), time.Second)
	defer authCancel()
	result, err := client.Authenticate(authCtx, STaAuthRequest{
		IMSI:  "001010000000001",
		Realm: "ims.example",
		APN:   "internet",
	})
	if err != nil {
		t.Fatalf("Authenticate() transport error = %v", err)
	}
	if result.Allowed {
		t.Fatalf("Allowed = true for intermediate EAP-AKA challenge")
	}
	if result.ResultCode != 2001 {
		t.Fatalf("ResultCode = %d, want 2001", result.ResultCode)
	}
	if !strings.Contains(result.Reason, "eap authentication incomplete") {
		t.Fatalf("Reason = %q, want eap authentication incomplete", result.Reason)
	}
	<-done
}

func TestSTaClientDoesNotAuthorizeEAPAKAPrimeChallengeDEA(t *testing.T) {
	eapChallenge := []byte{1, 1, 0, 8, eapTypeAKAPrime, eapAKASubtypeChallenge, 0, 0}
	addr, done := startTestSTaPeerWithDEAAVPs(t, []avp{
		uint32AVP(avpResultCode, 0, 2001),
		utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
		utf8AVP(avpOriginRealm, 0, "ims.example"),
		{Code: avpEAPPayload, Flags: flagMandatory, Data: eapChallenge},
	})
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Stop() })

	authCtx, authCancel := context.WithTimeout(context.Background(), time.Second)
	defer authCancel()
	result, err := client.Authenticate(authCtx, STaAuthRequest{
		IMSI:  "001010000000001",
		Realm: "ims.example",
		APN:   "internet",
	})
	if err != nil {
		t.Fatalf("Authenticate() transport error = %v", err)
	}
	if result.Allowed {
		t.Fatalf("Allowed = true for intermediate EAP-AKA' challenge")
	}
	if result.ResultCode != 2001 {
		t.Fatalf("ResultCode = %d, want 2001", result.ResultCode)
	}
	if !strings.Contains(result.Reason, "eap-aka-prime challenge") {
		t.Fatalf("Reason = %q, want eap-aka-prime challenge", result.Reason)
	}
	<-done
}

func TestSTaClientCompletesEAPAKAChallengeWithTestUECredentials(t *testing.T) {
	challenge := append([]byte{1, 1, 0, 48, 23, 1, 0, 0},
		append(eapAKAAttr(eapAKAAttrRAND, mustBytes(t, "23553cbe9637a89d218ae64dae47bf35")),
			eapAKAAttr(eapAKAAttrAUTN, mustBytes(t, "55f328b43577b9b94a9ffac354dfafb3"))...)...)
	addr, secondDER, done := startEAPAKASTaAAA(t, challenge)
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Stop() })

	authCtx, authCancel := context.WithTimeout(context.Background(), time.Second)
	defer authCancel()
	result, err := client.Authenticate(authCtx, STaAuthRequest{
		IMSI:  "001010000000001",
		Realm: "ims.example",
		APN:   "internet",
		Ki:    "465b5ce8b199b49faa5f0a2ee238a6bc",
		OPc:   "cd63cb71954a9f4e48a5994e37a02baf",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !result.Allowed || result.Reason != "eap success" {
		t.Fatalf("unexpected result %#v", result)
	}
	der := <-secondDER
	eap, ok := findAVP(der.AVPs, avpEAPPayload, 0)
	if !ok {
		t.Fatalf("second DER missing EAP-Payload")
	}
	res, ok := eapAKAAttrValue(eap.Data, eapAKAAttrRES)
	if !ok {
		t.Fatalf("second DER missing AT_RES")
	}
	if got := hex.EncodeToString(res); got != "a54211d5e3ba50bf" {
		t.Fatalf("AT_RES = %s", got)
	}
	<-done
}

func TestSTaEAPExchangeResultParsesMSK(t *testing.T) {
	client := NewSTaClient(testSTaConfig("127.0.0.1:3868"), slog.New(slog.DiscardHandler))
	msk := make([]byte, 64)
	for i := range msk {
		msk[i] = byte(i)
	}
	eapSuccess := []byte{eapCodeSuccess, 9, 0, 4}
	result := client.eapExchangeResult(STaEAPRequest{
		SessionID:  "session-1",
		IMSI:       "001010000000001",
		MSISDN:     "17892000001",
		APN:        "internet",
		EAPPayload: []byte{2, 9, 0, 5, 1},
	}, "session-1", message{AVPs: []avp{
		uint32AVP(avpResultCode, 0, 2001),
		utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
		utf8AVP(avpOriginRealm, 0, "ims.example"),
		{Code: avpEAPPayload, Flags: flagMandatory, Data: eapSuccess},
		{Code: avpEAPMasterSessionKey, Flags: flagMandatory, Data: msk},
	}})
	if !result.Allowed || result.State != STaEAPStateSuccess {
		t.Fatalf("unexpected result state=%s allowed=%t reason=%q", result.State, result.Allowed, result.Reason)
	}
	if len(result.MSK) != 64 {
		t.Fatalf("MSK length = %d, want 64", len(result.MSK))
	}
	if !bytes.Equal(result.MSK, msk) {
		t.Fatalf("MSK = %x, want %x", result.MSK, msk)
	}
}

func TestSTaClientStartWaitsForCEA(t *testing.T) {
	addr, cerCh, releaseCEA := holdCEAPeer(t)
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
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
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
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
		if got, _ := avpUint32(cer.AVPs, avpAuthApplicationID, 0); got != config.STaAuthApplicationID {
			t.Fatalf("CER Auth-Application-Id = %d, want STa %d", got, config.STaAuthApplicationID)
		}
		if got, _ := avpUint32(cer.AVPs, avpSupportedVendorID, 0); got != vendor3GPP {
			t.Fatalf("CER Supported-Vendor-Id = %d, want %d", got, vendor3GPP)
		}
		vendorID, appID := cerVendorSpecificApplication(t, cer)
		if vendorID != config.STaVendorID || appID != config.STaAuthApplicationID {
			t.Fatalf("CER VSAI vendor=%d app=%d", vendorID, appID)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CER")
	}
}

func TestSTaClientWatchdogSuccess(t *testing.T) {
	addr, dwrCh := watchdogSuccessPeer(t)
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
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

func TestSTaClientWatchdogFailureClosesPeer(t *testing.T) {
	addr, dwrCh := watchdogFailurePeer(t)
	client := NewSTaClient(testSTaConfig(addr), slog.New(slog.DiscardHandler))
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

func startTestSTaPeer(t *testing.T, deaResult uint32) (string, <-chan struct{}) {
	t.Helper()
	return startTestSTaPeerWithDEAAVPs(t, []avp{
		uint32AVP(avpResultCode, 0, deaResult),
		utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
		utf8AVP(avpOriginRealm, 0, "ims.example"),
	})
}

func startTestSTaPeerWithDEAAVPs(t *testing.T, deaAVPs []avp) (string, <-chan struct{}) {
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
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		})
		if _, err := conn.Write(cea.encode()); err != nil {
			t.Errorf("write CEA: %v", err)
			return
		}
		der, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode DER: %v", err)
			return
		}
		if der.CommandCode != commandDER || !der.isRequest() {
			t.Errorf("unexpected DER header %#v", der)
			return
		}
		if got := avpString(der.AVPs, avpUserName, 0); got != "001010000000001" {
			t.Errorf("DER User-Name = %q", got)
			return
		}
		dea := answer(der, deaAVPs)
		if _, err := conn.Write(dea.encode()); err != nil {
			t.Errorf("write DEA: %v", err)
		}
	}()
	return ln.Addr().String(), done
}

func startEAPAKASTaAAA(t *testing.T, challenge []byte) (string, <-chan message, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	secondDER := make(chan message, 1)
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
		cea := answer(cer, []avp{
			uint32AVP(avpResultCode, 0, 2001),
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		})
		if _, err := conn.Write(cea.encode()); err != nil {
			t.Errorf("write CEA: %v", err)
			return
		}
		first, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode first DER: %v", err)
			return
		}
		deaChallenge := answer(first, []avp{
			uint32AVP(avpResultCode, 0, 2001),
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
			{Code: avpEAPPayload, Flags: flagMandatory, Data: challenge},
		})
		if _, err := conn.Write(deaChallenge.encode()); err != nil {
			t.Errorf("write challenge DEA: %v", err)
			return
		}
		second, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode second DER: %v", err)
			return
		}
		secondDER <- second
		eapSuccess := []byte{eapCodeSuccess, 1, 0, 4}
		deaSuccess := answer(second, []avp{
			uint32AVP(avpResultCode, 0, 2001),
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
			{Code: avpEAPPayload, Flags: flagMandatory, Data: eapSuccess},
		})
		if _, err := conn.Write(deaSuccess.encode()); err != nil {
			t.Errorf("write success DEA: %v", err)
		}
	}()
	return ln.Addr().String(), secondDER, done
}

func startCapturingSTaAAA(t *testing.T, deaResult uint32) (string, <-chan message, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	derCh := make(chan message, 1)
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
		cea := answer(cer, []avp{
			uint32AVP(avpResultCode, 0, 2001),
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		})
		if _, err := conn.Write(cea.encode()); err != nil {
			t.Errorf("write CEA: %v", err)
			return
		}
		der, err := decodeMessage(conn)
		if err != nil {
			t.Errorf("decode DER: %v", err)
			return
		}
		derCh <- der
		dea := answer(der, []avp{
			uint32AVP(avpResultCode, 0, deaResult),
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
			utf8AVP(avpOriginRealm, 0, "ims.example"),
		})
		if _, err := conn.Write(dea.encode()); err != nil {
			t.Errorf("write DEA: %v", err)
		}
	}()
	return ln.Addr().String(), derCh, done
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
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
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
				utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
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
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
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
			utf8AVP(avpOriginHost, 0, "aaa.ims.example"),
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

func testSTaConfig(addr string) config.STaConfig {
	return config.STaConfig{
		OriginHost:        "twag.epc.example",
		OriginRealm:       "epc.example",
		DestinationRealm:  "ims.example",
		DestinationHost:   "aaa.ims.example",
		PeerAddr:          addr,
		VendorID:          config.STaVendorID,
		AuthApplicationID: config.STaAuthApplicationID,
	}
}

func assertAVPString(t *testing.T, avps []avp, code uint32, vendor uint32, want string) {
	t.Helper()
	if got := avpString(avps, code, vendor); got != want {
		t.Fatalf("AVP %d/%d = %q, want %q", code, vendor, got, want)
	}
}

func assertAVPUint32(t *testing.T, avps []avp, code uint32, vendor uint32, want uint32) {
	t.Helper()
	got, ok := avpUint32(avps, code, vendor)
	if !ok || got != want {
		t.Fatalf("AVP %d/%d = %d ok=%v, want %d", code, vendor, got, ok, want)
	}
}

func assertAVPAbsent(t *testing.T, avps []avp, code uint32, vendor uint32) {
	t.Helper()
	if _, ok := findAVP(avps, code, vendor); ok {
		t.Fatalf("AVP %d/%d is present, want absent", code, vendor)
	}
}

func assertEAPResponseIdentity(t *testing.T, avps []avp, wantIdentity string) {
	t.Helper()
	eap, ok := findAVP(avps, avpEAPPayload, 0)
	if !ok {
		t.Fatalf("DER missing EAP-Payload")
	}
	if len(eap.Data) != 5+len(wantIdentity) {
		t.Fatalf("EAP-Payload length = %d, want %d", len(eap.Data), 5+len(wantIdentity))
	}
	if eap.Data[0] != 2 || eap.Data[4] != 1 {
		t.Fatalf("EAP-Payload code/type = %d/%d, want response/identity", eap.Data[0], eap.Data[4])
	}
	gotLen := int(eap.Data[2])<<8 | int(eap.Data[3])
	if gotLen != len(eap.Data) {
		t.Fatalf("EAP-Payload encoded length = %d, want %d", gotLen, len(eap.Data))
	}
	if got := string(eap.Data[5:]); got != wantIdentity {
		t.Fatalf("EAP identity = %q, want %q", got, wantIdentity)
	}
}

func assertVendorSpecificApplication(t *testing.T, msg message, wantVendor uint32, wantApp uint32) {
	t.Helper()
	gotVendor, gotApp := cerVendorSpecificApplication(t, msg)
	if gotVendor != wantVendor || gotApp != wantApp {
		t.Fatalf("Vendor-Specific-Application-Id vendor=%d app=%d, want vendor=%d app=%d", gotVendor, gotApp, wantVendor, wantApp)
	}
}

func eapAKAAttr(attrType byte, value []byte) []byte {
	attrLen := pad4(4 + len(value))
	out := make([]byte, attrLen)
	out[0] = attrType
	out[1] = byte(attrLen / 4)
	copy(out[4:], value)
	return out
}

func eapAKAAttrValue(eap []byte, attrType byte) ([]byte, bool) {
	if len(eap) < 8 {
		return nil, false
	}
	length := int(eap[2])<<8 | int(eap[3])
	if length < 8 || length > len(eap) {
		return nil, false
	}
	attrs := eap[8:length]
	for len(attrs) > 0 {
		if len(attrs) < 4 {
			return nil, false
		}
		attrLen := int(attrs[1]) * 4
		if attrLen < 4 || attrLen > len(attrs) {
			return nil, false
		}
		if attrs[0] == attrType {
			switch attrType {
			case eapAKAAttrRES:
				resBits := int(attrs[2])<<8 | int(attrs[3])
				resLen := resBits / 8
				if 4+resLen > attrLen {
					return nil, false
				}
				return attrs[4 : 4+resLen], true
			default:
				return attrs[4:attrLen], true
			}
		}
		attrs = attrs[attrLen:]
	}
	return nil, false
}

func mustBytes(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return raw
}
