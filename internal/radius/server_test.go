package radius

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"log/slog"
	"net"
	"testing"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/lifecycle"
	radiustransport "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3580"
	"layeh.com/radius/vendors/microsoft"
)

func TestEAPRequestUsesConfiguredDefaultsAndRadiusIdentity(t *testing.T) {
	s := New(config.RadiusConfig{}, config.SubscriberConfig{
		DefaultAPN:   "internet",
		DefaultRealm: "epc.example",
	}, nil, slog.New(slog.DiscardHandler))
	p := radiustransport.New(radiustransport.CodeAccessRequest, []byte("secret"))
	if err := rfc2865.UserName_SetString(p, "311435300070580"); err != nil {
		t.Fatalf("set username: %v", err)
	}
	if err := rfc2865.CallingStationID_SetString(p, "AA-BB-CC-DD-EE-01"); err != nil {
		t.Fatalf("set calling station id: %v", err)
	}
	if err := rfc2869.EAPMessage_Set(p, []byte{2, 1, 0, 10, 1, 'i', 'd', 'e', 'n', 't'}); err != nil {
		t.Fatalf("set eap message: %v", err)
	}
	req := s.eapRequest(p)
	if req.IMSI != "311435300070580" {
		t.Fatalf("imsi = %q", req.IMSI)
	}
	if req.MACAddress != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("mac = %q", req.MACAddress)
	}
	if req.Username != "311435300070580" || req.APN != "internet" || req.Realm != "epc.example" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestEAPRequestParsesPrefixed3GPPNAIIMSI(t *testing.T) {
	s := New(config.RadiusConfig{}, config.SubscriberConfig{
		DefaultAPN:   "internet",
		DefaultRealm: "epc.example",
	}, nil, slog.New(slog.DiscardHandler))
	p := radiustransport.New(radiustransport.CodeAccessRequest, []byte("secret"))
	if err := rfc2865.UserName_SetString(p, "0311435000070570@wlan.mnc435.mcc311.3gppnetwork.org"); err != nil {
		t.Fatalf("set username: %v", err)
	}
	if err := rfc2869.EAPMessage_Set(p, eapResponseIdentity(1, "0311435000070570@wlan.mnc435.mcc311.3gppnetwork.org")); err != nil {
		t.Fatalf("set eap message: %v", err)
	}
	req := s.eapRequest(p)
	if req.IMSI != "311435000070570" {
		t.Fatalf("imsi = %q", req.IMSI)
	}
	if req.Username != "0311435000070570@wlan.mnc435.mcc311.3gppnetwork.org" {
		t.Fatalf("username = %q", req.Username)
	}
}

func TestEAPRequestUsesEAPIdentityWhenUserNameMissing(t *testing.T) {
	s := New(config.RadiusConfig{}, config.SubscriberConfig{
		DefaultAPN:   "internet",
		DefaultRealm: "epc.example",
	}, nil, slog.New(slog.DiscardHandler))
	p := radiustransport.New(radiustransport.CodeAccessRequest, []byte("secret"))
	if err := rfc2869.EAPMessage_Set(p, eapResponseIdentity(7, "0311435000070570@wlan.mnc435.mcc311.3gppnetwork.org")); err != nil {
		t.Fatalf("set eap message: %v", err)
	}
	req := s.eapRequest(p)
	if req.IMSI != "311435000070570" {
		t.Fatalf("imsi = %q", req.IMSI)
	}
	if req.Username != "0311435000070570@wlan.mnc435.mcc311.3gppnetwork.org" {
		t.Fatalf("username = %q", req.Username)
	}
}

func TestDescribeEAPNamesAKAPrimeSubtype(t *testing.T) {
	info := describeEAP([]byte{1, 7, 0, 8, 50, 1, 0, 0})
	if info.Code != "request" {
		t.Fatalf("code = %q", info.Code)
	}
	if info.Identifier != 7 {
		t.Fatalf("identifier = %d", info.Identifier)
	}
	if info.Type != 50 || info.TypeName != "aka-prime" {
		t.Fatalf("type = %d/%q", info.Type, info.TypeName)
	}
	if info.Subtype != 1 || info.SubtypeName != "challenge" {
		t.Fatalf("subtype = %d/%q", info.Subtype, info.SubtypeName)
	}
}

func TestHandleAccessRequestChallengesWithStateAndEAPMessage(t *testing.T) {
	akaPrimeChallenge := []byte{1, 2, 0, 8, 50, 1, 0, 0}
	service := &fakeEAPService{resp: &lifecycle.EAPResponse{
		SessionID:  "diam-session-1",
		State:      "challenge",
		IMSI:       "311435300070580",
		EAPPayload: akaPrimeChallenge,
		Reason:     "eap-aka-prime challenge",
	}}
	s := New(config.RadiusConfig{}, config.SubscriberConfig{DefaultAPN: "internet"}, service, slog.New(slog.DiscardHandler))
	reqPacket := accessRequestPacket(t)
	writer := &captureWriter{}
	s.handle(writer, &radiustransport.Request{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000},
		Packet:     reqPacket,
	})
	if writer.packet == nil {
		t.Fatal("expected response packet")
	}
	if writer.packet.Code != radiustransport.CodeAccessChallenge {
		t.Fatalf("code = %s", writer.packet.Code)
	}
	if got := rfc2865.State_GetString(writer.packet); got != "diam-session-1" {
		t.Fatalf("state = %q", got)
	}
	if got := rfc2869.EAPMessage_Get(writer.packet); !bytes.Equal(got, akaPrimeChallenge) {
		t.Fatalf("eap message = %x", got)
	}
	if service.last.SessionID != "" {
		t.Fatalf("unexpected request state = %q", service.last.SessionID)
	}
}

func TestHandleAccessRequestAcceptsWithFramedIP(t *testing.T) {
	service := &fakeEAPService{resp: &lifecycle.EAPResponse{
		SessionID:    "sess-1",
		State:        "success",
		IMSI:         "311435300070580",
		SubscriberIP: "100.64.0.10",
		APN:          "internet",
	}}
	s := New(config.RadiusConfig{}, config.SubscriberConfig{DefaultAPN: "internet"}, service, slog.New(slog.DiscardHandler))
	reqPacket := accessRequestPacket(t)
	if err := rfc2865.State_SetString(reqPacket, "diam-session-1"); err != nil {
		t.Fatalf("set state: %v", err)
	}
	writer := &captureWriter{}
	s.handle(writer, &radiustransport.Request{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000},
		Packet:     reqPacket,
	})
	if writer.packet == nil {
		t.Fatal("expected response packet")
	}
	if writer.packet.Code != radiustransport.CodeAccessAccept {
		t.Fatalf("code = %s", writer.packet.Code)
	}
	if got := rfc2865.FramedIPAddress_Get(writer.packet); !got.Equal(net.ParseIP("100.64.0.10")) {
		t.Fatalf("framed ip = %s", got)
	}
	if service.last.SessionID != "diam-session-1" {
		t.Fatalf("request state = %q", service.last.SessionID)
	}
}

func TestHandleAccessRequestAcceptIncludesConfiguredVLANTunnelAttributes(t *testing.T) {
	service := &fakeEAPService{resp: &lifecycle.EAPResponse{
		SessionID:    "sess-1",
		State:        "success",
		IMSI:         "311435300070580",
		SubscriberIP: "100.64.0.10",
		APN:          "internet",
	}}
	s := New(config.RadiusConfig{VLANID: 37}, config.SubscriberConfig{DefaultAPN: "internet"}, service, slog.New(slog.DiscardHandler))
	reqPacket := accessRequestPacket(t)
	writer := &captureWriter{}
	s.handle(writer, &radiustransport.Request{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000},
		Packet:     reqPacket,
	})
	if writer.packet == nil {
		t.Fatal("expected response packet")
	}
	if writer.packet.Code != radiustransport.CodeAccessAccept {
		t.Fatalf("code = %s", writer.packet.Code)
	}
	if tag, got := rfc2868.TunnelType_Get(writer.packet); tag != 0 || got != rfc3580.TunnelType_Value_VLAN {
		t.Fatalf("tunnel type tag=%d value=%s", tag, got)
	}
	if tag, got := rfc2868.TunnelMediumType_Get(writer.packet); tag != 0 || got != rfc2868.TunnelMediumType_Value_IEEE802 {
		t.Fatalf("tunnel medium type tag=%d value=%s", tag, got)
	}
	if tag, got := rfc2868.TunnelPrivateGroupID_GetString(writer.packet); tag != 0 || got != "37" {
		t.Fatalf("tunnel private group id tag=%d value=%q", tag, got)
	}
}

func TestHandleAccessRequestAcceptIncludesSessionLifetimeAttributes(t *testing.T) {
	service := &fakeEAPService{resp: &lifecycle.EAPResponse{
		SessionID:    "sess-1",
		State:        "success",
		IMSI:         "311435300070580",
		SubscriberIP: "100.64.0.10",
		APN:          "internet",
	}}
	s := New(config.RadiusConfig{AccessAccept: config.RadiusAccessAcceptConfig{
		SessionTimeoutSeconds: 300,
		TerminationAction:     "radius_request",
		IdleTimeoutSeconds:    60,
	}}, config.SubscriberConfig{DefaultAPN: "internet"}, service, slog.New(slog.DiscardHandler))
	reqPacket := accessRequestPacket(t)
	writer := &captureWriter{}
	s.handle(writer, &radiustransport.Request{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000},
		Packet:     reqPacket,
	})
	if writer.packet == nil {
		t.Fatal("expected response packet")
	}
	if got := rfc2865.SessionTimeout_Get(writer.packet); got != rfc2865.SessionTimeout(300) {
		t.Fatalf("session timeout = %s", got)
	}
	if got := rfc2865.TerminationAction_Get(writer.packet); got != rfc2865.TerminationAction_Value_RADIUSRequest {
		t.Fatalf("termination action = %s", got)
	}
	if got := rfc2865.IdleTimeout_Get(writer.packet); got != rfc2865.IdleTimeout(60) {
		t.Fatalf("idle timeout = %s", got)
	}
}

func TestHandleAccessRequestAcceptIncludesMPPEKeysAndValidMessageAuthenticator(t *testing.T) {
	msk := make([]byte, 64)
	for i := range msk {
		msk[i] = byte(i)
	}
	service := &fakeEAPService{resp: &lifecycle.EAPResponse{
		SessionID:    "sess-1",
		State:        "success",
		IMSI:         "311435300070580",
		SubscriberIP: "100.64.0.203",
		APN:          "internet",
		EAPPayload:   []byte{3, 1, 0, 4},
		MSK:          msk,
	}}
	s := New(config.RadiusConfig{}, config.SubscriberConfig{DefaultAPN: "internet"}, service, slog.New(slog.DiscardHandler))
	reqPacket := accessRequestPacket(t)
	writer := &captureWriter{}
	s.handle(writer, &radiustransport.Request{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000},
		Packet:     reqPacket,
	})
	if writer.packet == nil {
		t.Fatal("expected response packet")
	}
	if writer.packet.Code != radiustransport.CodeAccessAccept {
		t.Fatalf("code = %s", writer.packet.Code)
	}
	if got := rfc2865.FramedIPAddress_Get(writer.packet); !got.Equal(net.ParseIP("100.64.0.203")) {
		t.Fatalf("framed ip = %s", got)
	}
	if got := rfc2865.Class_GetString(writer.packet); got != "sess-1" {
		t.Fatalf("class = %q", got)
	}
	if got := rfc2869.EAPMessage_Get(writer.packet); !bytes.Equal(got, []byte{3, 1, 0, 4}) {
		t.Fatalf("eap message = %x", got)
	}
	recvKey, err := microsoft.MSMPPERecvKey_Lookup(writer.packet, reqPacket)
	if err != nil {
		t.Fatalf("MS-MPPE-Recv-Key missing: %v", err)
	}
	if !bytes.Equal(recvKey, msk[:32]) {
		t.Fatalf("recv key = %x, want %x", recvKey, msk[:32])
	}
	sendKey, err := microsoft.MSMPPESendKey_Lookup(writer.packet, reqPacket)
	if err != nil {
		t.Fatalf("MS-MPPE-Send-Key missing: %v", err)
	}
	if !bytes.Equal(sendKey, msk[32:64]) {
		t.Fatalf("send key = %x, want %x", sendKey, msk[32:64])
	}
	if !validMessageAuthenticator(t, writer.packet) {
		t.Fatal("Message-Authenticator is invalid")
	}
}

func accessRequestPacket(t *testing.T) *radiustransport.Packet {
	t.Helper()
	p := radiustransport.New(radiustransport.CodeAccessRequest, []byte("secret"))
	if err := rfc2865.UserName_SetString(p, "311435300070580"); err != nil {
		t.Fatalf("set username: %v", err)
	}
	if err := rfc2869.EAPMessage_Set(p, []byte{2, 1, 0, 10, 1, 'i', 'd', 'e', 'n', 't'}); err != nil {
		t.Fatalf("set eap message: %v", err)
	}
	return p
}

func validMessageAuthenticator(t *testing.T, packet *radiustransport.Packet) bool {
	t.Helper()
	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal packet: %v", err)
	}
	var got []byte
	attrs := wire[20:]
	for len(attrs) > 0 {
		if len(attrs) < 2 || int(attrs[1]) < 2 || int(attrs[1]) > len(attrs) {
			t.Fatalf("invalid radius attribute encoding")
		}
		if attrs[0] == byte(rfc2869.MessageAuthenticator_Type) {
			if attrs[1] != 18 {
				t.Fatalf("Message-Authenticator length = %d", attrs[1])
			}
			got = append([]byte(nil), attrs[2:18]...)
			for i := 2; i < 18; i++ {
				attrs[i] = 0
			}
			break
		}
		attrs = attrs[attrs[1]:]
	}
	if len(got) == 0 {
		return false
	}
	mac := hmac.New(md5.New, packet.Secret)
	_, _ = mac.Write(wire)
	return hmac.Equal(got, mac.Sum(nil))
}

func eapResponseIdentity(id byte, identity string) []byte {
	length := 5 + len(identity)
	payload := make([]byte, length)
	payload[0] = 2
	payload[1] = id
	payload[2] = byte(length >> 8)
	payload[3] = byte(length)
	payload[4] = 1
	copy(payload[5:], identity)
	return payload
}

type fakeEAPService struct {
	resp *lifecycle.EAPResponse
	err  error
	last lifecycle.EAPRequest
}

func (f *fakeEAPService) ExchangeEAP(ctx context.Context, req lifecycle.EAPRequest) (*lifecycle.EAPResponse, error) {
	f.last = req
	return f.resp, f.err
}

type captureWriter struct {
	packet *radiustransport.Packet
}

func (w *captureWriter) Write(packet *radiustransport.Packet) error {
	w.packet = packet
	return nil
}
