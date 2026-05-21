package gtp

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

func TestGTPClientEcho(t *testing.T) {
	addr, done := startEchoPGW(t)
	client, err := NewGTP(config.PGWConfig{
		LocalGTPCIP:     "127.0.0.1",
		RemotePGWGTPCIP: addr.IP.String(),
	}, config.GTPEchoConfig{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewGTP() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.remote.Port = addr.Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Probe(ctx); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	<-done
}

func TestEchoSuccessMarksPeerHealthy(t *testing.T) {
	addr, done := startEchoPGW(t)
	client := newTestGTPClient(t, addr, config.GTPEchoConfig{MaxFailures: 3})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client.runEchoProbe(ctx)
	<-done

	health := client.PeerHealth()
	if health.Health != PeerHealthHealthy {
		t.Fatalf("peer health = %s, want %s", health.Health, PeerHealthHealthy)
	}
	if health.ConsecutiveFailures != 0 {
		t.Fatalf("consecutive failures = %d, want 0", health.ConsecutiveFailures)
	}
	if health.LastSuccess.IsZero() {
		t.Fatal("last success was not updated")
	}
}

func TestEchoConfigClampsIntervalBelowMinimum(t *testing.T) {
	client := newTestGTPClient(t, silentUDPAddr(t), config.GTPEchoConfig{
		IntervalSeconds: 1,
		TimeoutSeconds:  1,
		MaxFailures:     3,
	})
	if client.echoCfg.IntervalSeconds != config.MinGTPEchoIntervalSeconds {
		t.Fatalf("echo interval = %d, want %d", client.echoCfg.IntervalSeconds, config.MinGTPEchoIntervalSeconds)
	}
}

func TestEchoTimeoutIncrementsFailureCount(t *testing.T) {
	client := newTestGTPClient(t, silentUDPAddr(t), config.GTPEchoConfig{MaxFailures: 3})
	client.peerHealth = PeerHealthHealthy
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	client.runEchoProbe(ctx)

	health := client.PeerHealth()
	if health.Health != PeerHealthHealthy {
		t.Fatalf("peer health = %s, want %s before max failures", health.Health, PeerHealthHealthy)
	}
	if health.ConsecutiveFailures != 1 {
		t.Fatalf("consecutive failures = %d, want 1", health.ConsecutiveFailures)
	}
	if health.LastFailure.IsZero() {
		t.Fatal("last failure was not updated")
	}
}

func TestMaxEchoFailuresMarksPeerUnhealthy(t *testing.T) {
	client := newTestGTPClient(t, silentUDPAddr(t), config.GTPEchoConfig{MaxFailures: 3})
	client.peerHealth = PeerHealthHealthy
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		client.runEchoProbe(ctx)
		cancel()
	}

	health := client.PeerHealth()
	if health.Health != PeerHealthUnhealthy {
		t.Fatalf("peer health = %s, want %s", health.Health, PeerHealthUnhealthy)
	}
	if health.ConsecutiveFailures != 3 {
		t.Fatalf("consecutive failures = %d, want 3", health.ConsecutiveFailures)
	}
}

func TestEchoRecoveryResetsFailures(t *testing.T) {
	addr, done := startEchoPGW(t)
	client := newTestGTPClient(t, addr, config.GTPEchoConfig{MaxFailures: 3})
	client.peerHealth = PeerHealthUnhealthy
	client.consecutiveEchoFailures = 3
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client.runEchoProbe(ctx)
	<-done

	health := client.PeerHealth()
	if health.Health != PeerHealthHealthy {
		t.Fatalf("peer health = %s, want %s", health.Health, PeerHealthHealthy)
	}
	if health.ConsecutiveFailures != 0 {
		t.Fatalf("consecutive failures = %d, want 0", health.ConsecutiveFailures)
	}
}

func TestEchoWatchdogStopsOnContextCancel(t *testing.T) {
	client := newTestGTPClient(t, silentUDPAddr(t), config.GTPEchoConfig{
		Enabled:         true,
		IntervalSeconds: 1,
		TimeoutSeconds:  1,
		MaxFailures:     3,
	})
	ctx, cancel := context.WithCancel(context.Background())
	client.StartEchoWatchdog(ctx)
	cancel()

	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("watchdog did not stop after context cancel")
		case <-ticker.C:
			if !client.echoWatchdogStarted.Load() {
				return
			}
		}
	}
}

func TestDeleteSessionIgnoresUnrelatedEchoResponse(t *testing.T) {
	addr, done := startDeletePGWWithUnrelatedEcho(t, false)
	client := newTestGTPClient(t, addr, config.GTPEchoConfig{})
	client.seq.seq.Store(6434601)
	sess := &session.Session{ID: "twag-test", IMSI: "311435000070571", GTPCTEID: 0x80080001}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.DeleteSession(ctx, sess); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}
	<-done
}

func TestInboundGTPCEchoRequestIsAnswered(t *testing.T) {
	client := newTestGTPClient(t, silentUDPAddr(t), config.GTPEchoConfig{})
	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen peer udp: %v", err)
	}
	defer peerConn.Close() //nolint:errcheck
	client.remote = peerConn.LocalAddr().(*net.UDPAddr)

	req := gtpv2Message{Type: gtpv2EchoRequest, Sequence: 1, Payload: recoveryIE(0).encode()}
	encoded, err := req.encode()
	if err != nil {
		t.Fatalf("encode echo request: %v", err)
	}
	if _, err := peerConn.WriteToUDP(encoded, client.local); err != nil {
		t.Fatalf("write echo request: %v", err)
	}
	_ = peerConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read echo response: %v", err)
	}
	resp, err := decodeGTPv2Message(buf[:n])
	if err != nil {
		t.Fatalf("decode echo response: %v", err)
	}
	if resp.Type != gtpv2EchoResponse || resp.Sequence != req.Sequence || resp.HasTEID {
		t.Fatalf("unexpected echo response %#v", resp)
	}
}

func TestInboundGTPCEchoRequestDoesNotInterfereWithCreateTransaction(t *testing.T) {
	addr, done := startCreatePGWWithInboundEcho(t)
	client := newTestGTPClient(t, addr, config.GTPEchoConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.doTransaction(ctx, gtpv2Message{
		Type:    gtpv2CreateSessionReq,
		HasTEID: true,
		TEID:    0,
	}, gtpv2CreateSessionResp, "Create Session")
	if err != nil {
		t.Fatalf("create transaction error = %v", err)
	}
	<-done
}

func TestDeleteSessionTimeoutAfterUnrelatedEchoResponse(t *testing.T) {
	addr, done := startDeletePGWWithUnrelatedEcho(t, true)
	client := newTestGTPClient(t, addr, config.GTPEchoConfig{})
	client.seq.seq.Store(6434601)
	sess := &session.Session{ID: "twag-test", IMSI: "311435000070571", GTPCTEID: 0x80080001}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := client.DeleteSession(ctx, sess)
	if err == nil {
		t.Fatal("expected DeleteSession timeout")
	}
	if !strings.Contains(err.Error(), "Delete Session timeout waiting for response sequence 6434602") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "sequence mismatch") {
		t.Fatalf("unexpected sequence mismatch error: %v", err)
	}
	<-done
}

func TestConcurrentCreateAndEchoTransactionsMatchBySequence(t *testing.T) {
	addr, done := startReverseOrderCreateEchoPGW(t)
	client := newTestGTPClient(t, addr, config.GTPEchoConfig{})
	client.seq.seq.Store(99)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	echoErr := make(chan error, 1)
	createErr := make(chan error, 1)
	go func() {
		_, _, err := client.echo(ctx)
		echoErr <- err
	}()
	go func() {
		_, err := client.doTransaction(ctx, gtpv2Message{
			Type:    gtpv2CreateSessionReq,
			HasTEID: true,
			TEID:    0,
			Payload: nil,
		}, gtpv2CreateSessionResp, "Create Session")
		createErr <- err
	}()

	if err := <-echoErr; err != nil {
		t.Fatalf("echo transaction error = %v", err)
	}
	if err := <-createErr; err != nil {
		t.Fatalf("create transaction error = %v", err)
	}
	<-done
}

func TestMatchingSequenceWrongMessageTypeFailsTransaction(t *testing.T) {
	addr, done := startWrongTypePGW(t)
	client := newTestGTPClient(t, addr, config.GTPEchoConfig{})
	sess := &session.Session{ID: "twag-test", IMSI: "311435000070571", GTPCTEID: 0x80080001}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.DeleteSession(ctx, sess)
	if err == nil {
		t.Fatal("expected response type mismatch")
	}
	if !strings.Contains(err.Error(), "response type mismatch") {
		t.Fatalf("unexpected error: %v", err)
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
	}, config.GTPEchoConfig{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewGTP() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
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

func TestSequenceNeverZero(t *testing.T) {
	a := &gtpv2SequenceAllocator{}
	for i := 0; i < 1000; i++ {
		if seq := a.next(); seq == 0 {
			t.Fatalf("sequence = 0")
		}
	}
}

func TestSequenceNeverExceeds7FFFFF(t *testing.T) {
	a := &gtpv2SequenceAllocator{}
	a.seq.Store(maxGTPv2Sequence - 10)
	for i := 0; i < 100; i++ {
		if seq := a.next(); seq > maxGTPv2Sequence {
			t.Fatalf("sequence = 0x%06x, exceeds max", seq)
		}
	}
}

func TestSequenceWrapsFrom7FFFFFTo000001(t *testing.T) {
	a := &gtpv2SequenceAllocator{}
	a.seq.Store(maxGTPv2Sequence)
	if seq := a.next(); seq != minGTPv2Sequence {
		t.Fatalf("wrapped sequence = 0x%06x, want 0x%06x", seq, minGTPv2Sequence)
	}
}

func TestSequenceRandomInitializerMasksTo7FFFFF(t *testing.T) {
	for i := 0; i < 1000; i++ {
		seq := randomInitialGTPv2Sequence()
		if seq == 0 || seq > maxGTPv2Sequence {
			t.Fatalf("random initial sequence = 0x%06x", seq)
		}
	}
}

func TestEncodeSequenceAndSpare(t *testing.T) {
	msg := gtpv2Message{Type: gtpv2EchoRequest, Sequence: 0x01a9d7}
	encoded, err := msg.encode()
	if err != nil {
		t.Fatalf("encode echo: %v", err)
	}
	if got, want := encoded[4:8], []byte{0x01, 0xa9, 0xd7, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("sequence/spare = % x, want % x", got, want)
	}
}

func TestEchoRequestHeaderNoTEID(t *testing.T) {
	encoded, err := (gtpv2Message{Type: gtpv2EchoRequest, Sequence: 0x404bcc, Payload: recoveryIE(0).encode()}).encode()
	if err != nil {
		t.Fatalf("encode echo: %v", err)
	}
	want := []byte{0x40, 0x01, 0x00, 0x09, 0x40, 0x4b, 0xcc, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("echo request = % x, want % x", encoded, want)
	}
}

func TestEchoRequestLengthWithRecoveryIE(t *testing.T) {
	encoded, err := (gtpv2Message{Type: gtpv2EchoRequest, Sequence: 1, Payload: recoveryIE(0).encode()}).encode()
	if err != nil {
		t.Fatalf("encode echo: %v", err)
	}
	if len(encoded) != 13 {
		t.Fatalf("echo packet length = %d, want 13", len(encoded))
	}
	if encoded[2] != 0x00 || encoded[3] != 0x09 {
		t.Fatalf("echo length field = %02x%02x, want 0009", encoded[2], encoded[3])
	}
	if got, want := encoded[8:], []byte{0x03, 0x00, 0x01, 0x00, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("echo recovery IE = % x, want % x", got, want)
	}
}

func TestCreateSessionRequestHeaderHasTEID(t *testing.T) {
	payload := make([]byte, 0x009d-8)
	encoded, err := (gtpv2Message{
		Type:     gtpv2CreateSessionReq,
		HasTEID:  true,
		TEID:     0,
		Sequence: 0x01a9d8,
		Payload:  payload,
	}).encode()
	if err != nil {
		t.Fatalf("encode create session: %v", err)
	}
	wantPrefix := []byte{0x48, 0x20, 0x00, 0x9d, 0x00, 0x00, 0x00, 0x00, 0x01, 0xa9, 0xd8, 0x00}
	if !bytes.Equal(encoded[:12], wantPrefix) {
		t.Fatalf("create header = % x, want % x", encoded[:12], wantPrefix)
	}
}

func TestCreateSessionRequestInitialTEIDZero(t *testing.T) {
	encoded, err := (gtpv2Message{
		Type:     gtpv2CreateSessionReq,
		HasTEID:  true,
		TEID:     0,
		Sequence: 1,
	}).encode()
	if err != nil {
		t.Fatalf("encode create session: %v", err)
	}
	if got := encoded[4:8]; !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Fatalf("initial TEID = % x, want 00 00 00 00", got)
	}
}

func TestFTEIDEncoderS2aTWANControlPlane(t *testing.T) {
	ie := fteidIE(0, ifaceS2aTWANGTPC, 0x5471bcb4, net.ParseIP("10.90.250.186"))
	if len(ie.Payload) != 9 {
		t.Fatalf("F-TEID payload length = %d, want 9", len(ie.Payload))
	}
	if ie.Payload[0] != 0xa3 {
		t.Fatalf("S2a TWAN GTP-C F-TEID first octet = 0x%02x, want 0xa3", ie.Payload[0])
	}
	if iface, _, ip, ok := parseFTEID(ie); !ok || iface != 35 || ip.String() != "10.90.250.186" {
		t.Fatalf("parsed F-TEID iface=%d ip=%s ok=%v", iface, ip, ok)
	}
}

func TestFTEIDEncoderS2aTWANUserPlane(t *testing.T) {
	ie := fteidIE(0, ifaceS2aTWANGTPU, 0x5471bcb5, net.ParseIP("10.90.250.186"))
	if len(ie.Payload) != 9 {
		t.Fatalf("F-TEID payload length = %d, want 9", len(ie.Payload))
	}
	if ie.Payload[0] != 0xa2 {
		t.Fatalf("S2a TWAN GTP-U F-TEID first octet = 0x%02x, want 0xa2", ie.Payload[0])
	}
	if iface, _, ip, ok := parseFTEID(ie); !ok || iface != 34 || ip.String() != "10.90.250.186" {
		t.Fatalf("parsed F-TEID iface=%d ip=%s ok=%v", iface, ip, ok)
	}
}

func TestFTEIDEncoderRejectsInvalidInterfaceType(t *testing.T) {
	ie := fteidIE(0, 64, 0x5471bcb4, net.ParseIP("10.90.250.186"))
	if len(ie.Payload) != 0 {
		t.Fatalf("invalid interface type encoded payload % x", ie.Payload)
	}
}

func TestChargingCharacteristicsIEEncoding(t *testing.T) {
	ie := chargingCharacteristicsIE(0, defaultChargingCharacteristics)
	encoded := ie.encode()
	want := []byte{0x5f, 0x00, 0x02, 0x00, 0x08, 0x00}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("charging characteristics IE = % x, want % x", encoded, want)
	}
}

func TestChargingCharacteristicsHexParser(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  uint16
	}{
		{input: "0800", want: 0x0800},
		{input: "0000", want: 0x0000},
		{input: "ABcd", want: 0xabcd},
	} {
		got, err := parseChargingCharacteristicsHex(tc.input)
		if err != nil {
			t.Fatalf("parseChargingCharacteristicsHex(%q): %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("parseChargingCharacteristicsHex(%q) = 0x%04x, want 0x%04x", tc.input, got, tc.want)
		}
	}
	for _, input := range []string{"", "08", "080000", "xyz"} {
		if _, err := parseChargingCharacteristicsHex(input); err == nil {
			t.Fatalf("expected parse error for %q", input)
		}
	}
}

func TestCreateSessionRequestUsesS2aTWANFTEIDs(t *testing.T) {
	client := &GTPClient{cfg: config.PGWConfig{
		LocalGTPCIP: "10.90.250.186",
		LocalGTPUIP: "10.90.250.186",
		APN:         "internet",
	}}
	sess := &session.Session{
		IMSI:         "001010000000001",
		MSISDN:       "17892000001",
		APN:          "internet",
		Realm:        "epc.mnc001.mcc001.3gppnetwork.org",
		SubscriberIP: net.ParseIP("10.200.0.2"),
	}
	msg := gtpv2Message{
		Type:     gtpv2CreateSessionReq,
		HasTEID:  true,
		TEID:     0,
		Sequence: 0x404bcd,
		Payload:  client.createSessionPayload(sess, 0x5471bcb4, 0x5471bcb5),
	}
	encoded, err := msg.encode()
	if err != nil {
		t.Fatalf("encode create session: %v", err)
	}
	if len(encoded) != 167 {
		t.Fatalf("CSR packet length = %d, want 167", len(encoded))
	}
	if got := int(encoded[2])<<8 | int(encoded[3]); got != 163 {
		t.Fatalf("CSR length field = %d, want 163", got)
	}
	decoded, err := decodeGTPv2Message(encoded)
	if err != nil {
		t.Fatalf("decode create session: %v", err)
	}
	if decoded.Type != gtpv2CreateSessionReq || !decoded.HasTEID || decoded.TEID != 0 {
		t.Fatalf("unexpected decoded CSR header %#v", decoded)
	}
	if decoded.Sequence == 0 || decoded.Sequence > maxGTPv2Sequence {
		t.Fatalf("CSR sequence = 0x%06x", decoded.Sequence)
	}
	if encoded[11] != 0x00 {
		t.Fatalf("CSR spare byte = 0x%02x", encoded[11])
	}
	ies, err := decodeIEs(decoded.Payload)
	if err != nil {
		t.Fatalf("decode CSR IEs: %v", err)
	}
	sender, ok := findIE(ies, ieFTEID, 0)
	if !ok {
		t.Fatalf("CSR missing top-level sender F-TEID")
	}
	if got := sender.Payload[0]; got != 0xa3 {
		t.Fatalf("sender F-TEID first octet = 0x%02x, want 0xa3", got)
	}
	if iface, _, ip, ok := parseFTEID(sender); !ok || iface != ifaceS2aTWANGTPC || ip.String() != "10.90.250.186" {
		t.Fatalf("sender F-TEID iface=%d ip=%s ok=%v", iface, ip, ok)
	}
	if sender.Instance != 0 {
		t.Fatalf("top-level sender F-TEID instance = %d, want 0", sender.Instance)
	}
	charging, ok := findIE(ies, ieChargingChars, 0)
	if !ok {
		t.Fatalf("CSR missing top-level Charging Characteristics IE")
	}
	if !bytes.Equal(charging.Payload, []byte{0x08, 0x00}) {
		t.Fatalf("charging characteristics payload = % x, want 08 00", charging.Payload)
	}
	paa, ok := findIE(ies, iePAA, 0)
	if !ok {
		t.Fatalf("CSR missing PAA IE")
	}
	if !bytes.Equal(paa.Payload, []byte{pdnTypeIPv4, 0x00, 0x00, 0x00, 0x00}) {
		t.Fatalf("dynamic PAA payload = % x, want IPv4 PDN type with 0.0.0.0", paa.Payload)
	}
	var bearerFTEID gtpv2IE
	var bearerHasEBI bool
	var bearerHasQoS bool
	for _, ie := range ies {
		if ie.Type != ieBearerContext {
			continue
		}
		children, err := decodeIEs(ie.Payload)
		if err != nil {
			t.Fatalf("decode bearer context: %v", err)
		}
		if _, ok := findIE(children, ieEBI, 0); ok {
			bearerHasEBI = true
		}
		if found, ok := findIE(children, ieFTEID, 6); ok {
			bearerFTEID = found
		}
		if _, ok := findIE(children, ieFTEID, 0); ok {
			t.Fatalf("bearer F-TEID instance 0 present, want instance 6")
		}
		if _, ok := findIE(children, ieBearerQoS, 0); ok {
			bearerHasQoS = true
		}
		if _, ok := findIE(children, ieChargingChars, 0); ok {
			t.Fatalf("Charging Characteristics IE must be top-level, not inside Bearer Context")
		}
	}
	if !bearerHasEBI {
		t.Fatalf("CSR bearer context missing EPS Bearer ID")
	}
	if len(bearerFTEID.Payload) == 0 {
		t.Fatalf("CSR missing bearer F-TEID instance 6")
	}
	if bearerFTEID.Instance != 6 {
		t.Fatalf("bearer F-TEID instance = %d, want 6", bearerFTEID.Instance)
	}
	if got := bearerFTEID.Payload[0]; got != 0xa2 {
		t.Fatalf("bearer F-TEID first octet = 0x%02x, want 0xa2", got)
	}
	if iface, _, ip, ok := parseFTEID(bearerFTEID); !ok || iface != ifaceS2aTWANGTPU || ip.String() != "10.90.250.186" {
		t.Fatalf("bearer F-TEID iface=%d ip=%s ok=%v", iface, ip, ok)
	}
	if !bearerHasQoS {
		t.Fatalf("CSR bearer context missing Bearer QoS")
	}
	for _, ie := range append(ies, bearerFTEID) {
		if ie.Type != ieFTEID || len(ie.Payload) == 0 {
			continue
		}
		if iface := ie.Payload[0] & 0x3f; iface == 16 || iface == 17 {
			t.Fatalf("CSR contains non-S2a interface type %d", iface)
		}
	}
}

func TestCreateSessionRequestChargingCharacteristicsOverride(t *testing.T) {
	client := &GTPClient{cfg: config.PGWConfig{
		LocalGTPCIP:             "10.90.250.186",
		LocalGTPUIP:             "10.90.250.186",
		APN:                     "internet",
		ChargingCharacteristics: "0000",
	}}
	sess := &session.Session{
		IMSI:         "001010000000001",
		APN:          "internet",
		Realm:        "epc.mnc001.mcc001.3gppnetwork.org",
		SubscriberIP: net.ParseIP("10.200.0.2"),
	}
	payload := client.createSessionPayload(sess, 0x5471bcb4, 0x5471bcb5)
	ies, err := decodeIEs(payload)
	if err != nil {
		t.Fatalf("decode CSR IEs: %v", err)
	}
	charging, ok := findIE(ies, ieChargingChars, 0)
	if !ok {
		t.Fatalf("CSR missing top-level Charging Characteristics IE")
	}
	if !bytes.Equal(charging.Payload, []byte{0x00, 0x00}) {
		t.Fatalf("charging characteristics override payload = % x, want 00 00", charging.Payload)
	}
}

func TestParseCreateSessionResponseUsesStarOSS2aFTEIDInstances(t *testing.T) {
	client := &GTPClient{cfg: config.PGWConfig{
		RemotePGWGTPCIP: "10.90.250.92",
		RemotePGWGTPUIP: "10.90.250.92",
	}}
	resp := gtpv2Message{
		Type:     gtpv2CreateSessionResp,
		HasTEID:  true,
		TEID:     0x5a62da72,
		Sequence: 0x78d833,
		Payload: encodeIEs(
			gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
			fteidIE(1, ifaceS2aPGWGTPC, 0x80072007, net.ParseIP("10.90.250.92")),
			paaIE(net.ParseIP("100.64.0.134")),
			gtpv2IE{Type: ieBearerContext, Payload: encodeIEs(
				uint8IE(ieEBI, 5),
				gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
				fteidIE(5, ifaceS2aPGWGTPU, 0x80104007, net.ParseIP("10.90.250.92")),
			)},
		),
	}
	result, cause, err := client.parseCreateSessionResponse(resp, 0x5a62da73)
	if err != nil {
		t.Fatalf("parseCreateSessionResponse() error = %v", err)
	}
	if cause != causeRequestAccepted {
		t.Fatalf("cause = %d, want %d", cause, causeRequestAccepted)
	}
	if result.GTPCTEID != 0x80072007 {
		t.Fatalf("GTPCTEID = %#x, want 0x80072007", result.GTPCTEID)
	}
	if result.RemoteGTPUTEID != 0x80104007 {
		t.Fatalf("RemoteGTPUTEID = %#x, want 0x80104007", result.RemoteGTPUTEID)
	}
	if result.SubscriberIP.String() != "100.64.0.134" {
		t.Fatalf("SubscriberIP = %s, want 100.64.0.134", result.SubscriberIP)
	}
}

func TestHeaderSpareByteAlwaysZero(t *testing.T) {
	for _, msg := range []gtpv2Message{
		{Type: gtpv2EchoRequest, Sequence: 1},
		{Type: gtpv2CreateSessionReq, HasTEID: true, Sequence: 1},
	} {
		encoded, err := msg.encode()
		if err != nil {
			t.Fatalf("encode type %d: %v", msg.Type, err)
		}
		spareOffset := 7
		if msg.HasTEID {
			spareOffset = 11
		}
		if encoded[spareOffset] != 0x00 {
			t.Fatalf("type %d spare byte = 0x%02x", msg.Type, encoded[spareOffset])
		}
	}
}

func TestStarOSCompatibleEchoSequenceMSBZero(t *testing.T) {
	a := &gtpv2SequenceAllocator{}
	a.seq.Store(maxGTPv2Sequence - 1)
	for i := 0; i < 4; i++ {
		seq := a.next()
		encoded, err := (gtpv2Message{Type: gtpv2EchoRequest, Sequence: seq, Payload: recoveryIE(0).encode()}).encode()
		if err != nil {
			t.Fatalf("encode echo: %v", err)
		}
		if encoded[4]&0x80 != 0 {
			t.Fatalf("echo sequence MSB set: % x", encoded[4:7])
		}
	}
}

func TestStarOSCompatibleCSRSequenceMSBZero(t *testing.T) {
	a := &gtpv2SequenceAllocator{}
	a.seq.Store(maxGTPv2Sequence - 1)
	for i := 0; i < 4; i++ {
		seq := a.next()
		encoded, err := (gtpv2Message{Type: gtpv2CreateSessionReq, HasTEID: true, Sequence: seq}).encode()
		if err != nil {
			t.Fatalf("encode create session: %v", err)
		}
		if encoded[8]&0x80 != 0 {
			t.Fatalf("create session sequence MSB set: % x", encoded[8:11])
		}
	}
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
		ies, err := decodeIEs(req.Payload)
		if err != nil {
			t.Errorf("decode echo IEs: %v", err)
			return
		}
		recovery, ok := findIE(ies, ieRecovery, 0)
		if !ok || len(recovery.Payload) != 1 {
			t.Errorf("echo request missing Recovery IE")
			return
		}
		resp, err := (gtpv2Message{
			Type:     gtpv2EchoResponse,
			Sequence: req.Sequence,
			Payload:  recoveryIE(0).encode(),
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

func newTestGTPClient(t *testing.T, remote *net.UDPAddr, echoCfg config.GTPEchoConfig) *GTPClient {
	t.Helper()
	client, err := NewGTP(config.PGWConfig{
		LocalGTPCIP:     "127.0.0.1",
		RemotePGWGTPCIP: remote.IP.String(),
	}, echoCfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewGTP() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.remote.Port = remote.Port
	return client
}

func silentUDPAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr)
}

func startDeletePGWWithUnrelatedEcho(t *testing.T, omitDeleteResponse bool) (*net.UDPAddr, <-chan struct{}) {
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
		req, peer := readGTPv2FromUDP(t, conn)
		if req.Type != gtpv2DeleteSessionReq {
			t.Errorf("request type = %d, want Delete Session Request", req.Type)
			return
		}
		writeGTPv2ToUDP(t, conn, peer, gtpv2Message{Type: gtpv2EchoResponse, Sequence: 1, Payload: recoveryIE(0).encode()})
		if omitDeleteResponse {
			return
		}
		writeGTPv2ToUDP(t, conn, peer, gtpv2Message{
			Type:     gtpv2DeleteSessionResp,
			HasTEID:  true,
			TEID:     req.TEID,
			Sequence: req.Sequence,
			Payload:  gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}}.encode(),
		})
	}()
	return conn.LocalAddr().(*net.UDPAddr), done
}

func startReverseOrderCreateEchoPGW(t *testing.T) (*net.UDPAddr, <-chan struct{}) {
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
		first, firstPeer := readGTPv2FromUDP(t, conn)
		second, secondPeer := readGTPv2FromUDP(t, conn)
		var echoReq, createReq gtpv2Message
		var echoPeer, createPeer *net.UDPAddr
		for _, item := range []struct {
			msg  gtpv2Message
			peer *net.UDPAddr
		}{{first, firstPeer}, {second, secondPeer}} {
			switch item.msg.Type {
			case gtpv2EchoRequest:
				echoReq, echoPeer = item.msg, item.peer
			case gtpv2CreateSessionReq:
				createReq, createPeer = item.msg, item.peer
			default:
				t.Errorf("unexpected request type %d", item.msg.Type)
				return
			}
		}
		if echoReq.Sequence == 0 || createReq.Sequence == 0 {
			t.Error("missing echo or create request")
			return
		}
		writeGTPv2ToUDP(t, conn, createPeer, gtpv2Message{
			Type:     gtpv2CreateSessionResp,
			HasTEID:  true,
			TEID:     0x01020304,
			Sequence: createReq.Sequence,
			Payload:  gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}}.encode(),
		})
		writeGTPv2ToUDP(t, conn, echoPeer, gtpv2Message{
			Type:     gtpv2EchoResponse,
			Sequence: echoReq.Sequence,
			Payload:  recoveryIE(0).encode(),
		})
	}()
	return conn.LocalAddr().(*net.UDPAddr), done
}

func startCreatePGWWithInboundEcho(t *testing.T) (*net.UDPAddr, <-chan struct{}) {
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
		req, peer := readGTPv2FromUDP(t, conn)
		if req.Type != gtpv2CreateSessionReq {
			t.Errorf("request type = %d, want Create Session Request", req.Type)
			return
		}
		writeGTPv2ToUDP(t, conn, peer, gtpv2Message{
			Type:     gtpv2EchoRequest,
			Sequence: 1,
			Payload:  recoveryIE(0).encode(),
		})
		echoResp, _ := readGTPv2FromUDP(t, conn)
		if echoResp.Type != gtpv2EchoResponse || echoResp.Sequence != 1 {
			t.Errorf("unexpected inbound echo response %#v", echoResp)
			return
		}
		writeGTPv2ToUDP(t, conn, peer, gtpv2Message{
			Type:     gtpv2CreateSessionResp,
			HasTEID:  true,
			TEID:     0x01020304,
			Sequence: req.Sequence,
			Payload:  gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}}.encode(),
		})
	}()
	return conn.LocalAddr().(*net.UDPAddr), done
}

func startWrongTypePGW(t *testing.T) (*net.UDPAddr, <-chan struct{}) {
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
		req, peer := readGTPv2FromUDP(t, conn)
		writeGTPv2ToUDP(t, conn, peer, gtpv2Message{
			Type:     gtpv2CreateSessionResp,
			HasTEID:  true,
			TEID:     req.TEID,
			Sequence: req.Sequence,
			Payload:  gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}}.encode(),
		})
	}()
	return conn.LocalAddr().(*net.UDPAddr), done
}

func readGTPv2FromUDP(t *testing.T, conn *net.UDPConn) (gtpv2Message, *net.UDPAddr) {
	t.Helper()
	buf := make([]byte, 4096)
	n, peer, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read udp: %v", err)
	}
	msg, err := decodeGTPv2Message(buf[:n])
	if err != nil {
		t.Fatalf("decode gtpv2: %v", err)
	}
	return msg, peer
}

func writeGTPv2ToUDP(t *testing.T, conn *net.UDPConn, peer *net.UDPAddr, msg gtpv2Message) {
	t.Helper()
	encoded, err := msg.encode()
	if err != nil {
		t.Fatalf("encode gtpv2: %v", err)
	}
	if _, err := conn.WriteToUDP(encoded, peer); err != nil {
		t.Fatalf("write udp: %v", err)
	}
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
		if sender, ok := findIE(ies, ieFTEID, 0); !ok || len(sender.Payload) == 0 || sender.Payload[0] != 0xa3 {
			t.Errorf("create request sender F-TEID = %#v, want first octet 0xa3", sender)
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
		createPeer := peer
		n, peer, err = conn.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read delete: %v", err)
			return
		}
		if peer.String() != createPeer.String() {
			t.Errorf("delete request peer = %s, want stable peer %s", peer.String(), createPeer.String())
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
		deleteIEs, err := decodeIEs(deleteReq.Payload)
		if err != nil {
			t.Errorf("decode delete IEs: %v", err)
			return
		}
		ebi, ok := findIE(deleteIEs, ieEBI, 0)
		if !ok || len(ebi.Payload) != 1 || ebi.Payload[0]&0x0f != 5 {
			t.Errorf("delete request missing linked EBI 5")
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
