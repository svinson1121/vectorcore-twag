package radius

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/lifecycle"
	radiustransport "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3580"
)

const radiusDefaultVLANID = 10

type EAPService interface {
	ExchangeEAP(ctx context.Context, req lifecycle.EAPRequest) (*lifecycle.EAPResponse, error)
}

type Server struct {
	cfg    config.RadiusConfig
	sub    config.SubscriberConfig
	eap    EAPService
	log    *slog.Logger
	server *radiustransport.PacketServer
}

func New(cfg config.RadiusConfig, sub config.SubscriberConfig, eap EAPService, logger *slog.Logger) *Server {
	if cfg.VLANID == 0 {
		cfg.VLANID = radiusDefaultVLANID
	}
	return &Server{cfg: cfg, sub: sub, eap: eap, log: logger}
}

func (s *Server) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.cfg.Enabled {
		return nil
	}
	if s.eap == nil {
		return fmt.Errorf("radius eap service is required")
	}
	if s.cfg.Secret == "" {
		return fmt.Errorf("radius secret is required")
	}
	s.server = &radiustransport.PacketServer{
		Addr:         s.cfg.ListenAddr,
		SecretSource: radiustransport.StaticSecretSource([]byte(s.cfg.Secret)),
		Handler:      radiustransport.HandlerFunc(s.handle),
		ErrorLog:     log.New(radiusLogWriter{s.log}, "", 0),
	}
	errCh := make(chan error, 1)
	go func() {
		err := s.server.ListenAndServe()
		if errors.Is(err, radiustransport.ErrServerShutdown) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("start radius server: %w", err)
		}
	case <-time.After(50 * time.Millisecond):
		s.log.Info("RADIUS server started", "listen_addr", s.cfg.ListenAddr)
	case <-ctx.Done():
		_ = s.Stop(context.Background())
		return ctx.Err()
	}
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.server.Shutdown(ctx); err != nil {
		return err
	}
	s.log.Info("RADIUS server stopped", "listen_addr", s.cfg.ListenAddr)
	return nil
}

func (s *Server) handle(w radiustransport.ResponseWriter, r *radiustransport.Request) {
	if r.Code != radiustransport.CodeAccessRequest {
		s.log.Warn("RADIUS request rejected", "remote_addr", r.RemoteAddr.String(), "code", r.Code.String(), "reason", "unsupported packet type")
		_ = w.Write(r.Response(radiustransport.CodeAccessReject))
		return
	}
	req := s.eapRequest(r.Packet, r.RemoteAddr)
	eapInfo := describeEAP(req.EAPPayload)
	s.log.Info("RADIUS Access-Request received",
		"remote_addr", r.RemoteAddr.String(),
		"radius_id", r.Identifier,
		"radius_code", r.Code.String(),
		"username", req.Username,
		"imsi", req.IMSI,
		"mac", req.MACAddress,
		"apn", req.APN,
		"radius_state", req.SessionID,
		"has_state", req.SessionID != "",
		"has_message_authenticator", hasMessageAuthenticator(r.Packet),
		"eap_payload_len", len(req.EAPPayload),
		"eap_code", eapInfo.Code,
		"eap_id", eapInfo.Identifier,
		"eap_type", eapInfo.Type,
		"eap_type_name", eapInfo.TypeName,
		"eap_subtype", eapInfo.Subtype,
		"eap_subtype_name", eapInfo.SubtypeName,
	)
	if len(req.EAPPayload) == 0 {
		s.reject(w, r, req, "missing EAP-Message")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	resp, err := s.eap.ExchangeEAP(ctx, req)
	if err != nil {
		reason := err.Error()
		if resp != nil && resp.Reason != "" {
			reason = resp.Reason
		}
		s.reject(w, r, req, reason)
		return
	}
	if resp != nil && resp.State == "challenge" {
		challenge := r.Response(radiustransport.CodeAccessChallenge)
		challengeEAP := describeEAP(resp.EAPPayload)
		if len(resp.EAPPayload) > 0 {
			_ = rfc2869.EAPMessage_Set(challenge, resp.EAPPayload)
		}
		if resp.SessionID != "" {
			_ = rfc2865.State_SetString(challenge, resp.SessionID)
		}
		if len(resp.EAPPayload) > 0 {
			if err := s.setMessageAuthenticator(challenge); err != nil {
				s.reject(w, r, req, err.Error())
				return
			}
		}
		s.log.Info("RADIUS Access-Challenge sent",
			"remote_addr", r.RemoteAddr.String(),
			"radius_id", challenge.Identifier,
			"radius_code", challenge.Code.String(),
			"session_id", resp.SessionID,
			"username", req.Username,
			"imsi", coalesceString(resp.IMSI, req.IMSI),
			"mac", req.MACAddress,
			"reason", resp.Reason,
			"eap_payload_len", len(resp.EAPPayload),
			"eap_code", challengeEAP.Code,
			"eap_id", challengeEAP.Identifier,
			"eap_type", challengeEAP.Type,
			"eap_type_name", challengeEAP.TypeName,
			"eap_subtype", challengeEAP.Subtype,
			"eap_subtype_name", challengeEAP.SubtypeName,
			"has_message_authenticator", hasMessageAuthenticator(challenge),
		)
		_ = w.Write(challenge)
		return
	}
	accept := r.Response(radiustransport.CodeAccessAccept)
	if resp != nil && resp.SubscriberIP != "" {
		_ = rfc2865.FramedIPAddress_Set(accept, net.ParseIP(resp.SubscriberIP))
	}
	if resp != nil && resp.SessionID != "" {
		_ = rfc2865.Class_SetString(accept, resp.SessionID)
	}
	if err := s.addAccessAcceptLifetime(accept); err != nil {
		s.reject(w, r, req, err.Error())
		return
	}
	if err := addVLAN(accept, s.cfg.VLANID); err != nil {
		s.reject(w, r, req, err.Error())
		return
	}
	if resp != nil && len(resp.EAPPayload) > 0 {
		_ = rfc2869.EAPMessage_Set(accept, resp.EAPPayload)
		if len(resp.MSK) == 64 {
			if err := addMPPEKeys(accept, resp.MSK); err != nil {
				s.reject(w, r, req, err.Error())
				return
			}
			s.log.Info("RADIUS Access-Accept keying attributes added",
				"imsi", coalesceString(resp.IMSI, req.IMSI),
				"mac", req.MACAddress,
				"has_mppe_send_key", true,
				"has_mppe_recv_key", true,
				"msk_len", len(resp.MSK),
			)
		} else {
			s.log.Warn("RADIUS Access-Accept missing MPPE keys because STa DEA did not include MSK",
				"imsi", coalesceString(resp.IMSI, req.IMSI),
				"mac", req.MACAddress,
				"msk_present", len(resp.MSK) > 0,
				"msk_len", len(resp.MSK),
			)
		}
		if err := s.setMessageAuthenticator(accept); err != nil {
			s.reject(w, r, req, err.Error())
			return
		}
	}
	s.log.Info("RADIUS Access-Accept sent",
		"remote_addr", r.RemoteAddr.String(),
		"radius_id", accept.Identifier,
		"radius_code", accept.Code.String(),
		"session_id", eapStringValue(resp, func(r *lifecycle.EAPResponse) string { return r.SessionID }),
		"username", req.Username,
		"imsi", coalesceString(eapStringValue(resp, func(r *lifecycle.EAPResponse) string { return r.IMSI }), req.IMSI),
		"mac", req.MACAddress,
		"subscriber_ip", eapStringValue(resp, func(r *lifecycle.EAPResponse) string { return r.SubscriberIP }),
		"vlan_id", s.cfg.VLANID,
		"session_timeout_seconds", s.cfg.AccessAccept.SessionTimeoutSeconds,
		"termination_action", s.cfg.AccessAccept.TerminationAction,
		"idle_timeout_seconds", s.cfg.AccessAccept.IdleTimeoutSeconds,
		"has_message_authenticator", hasMessageAuthenticator(accept),
	)
	_ = w.Write(accept)
}

func (s *Server) addAccessAcceptLifetime(packet *radiustransport.Packet) error {
	if s.cfg.AccessAccept.SessionTimeoutSeconds > 0 {
		if err := rfc2865.SessionTimeout_Set(packet, rfc2865.SessionTimeout(s.cfg.AccessAccept.SessionTimeoutSeconds)); err != nil {
			return fmt.Errorf("set radius session timeout: %w", err)
		}
	}
	switch s.cfg.AccessAccept.TerminationAction {
	case "", "radius_request":
		if err := rfc2865.TerminationAction_Set(packet, rfc2865.TerminationAction_Value_RADIUSRequest); err != nil {
			return fmt.Errorf("set radius termination action: %w", err)
		}
	case "default":
		if err := rfc2865.TerminationAction_Set(packet, rfc2865.TerminationAction_Value_Default); err != nil {
			return fmt.Errorf("set radius termination action: %w", err)
		}
	default:
		return fmt.Errorf("unsupported radius termination action %q", s.cfg.AccessAccept.TerminationAction)
	}
	if s.cfg.AccessAccept.IdleTimeoutSeconds > 0 {
		if err := rfc2865.IdleTimeout_Set(packet, rfc2865.IdleTimeout(s.cfg.AccessAccept.IdleTimeoutSeconds)); err != nil {
			return fmt.Errorf("set radius idle timeout: %w", err)
		}
	}
	return nil
}

func addVLAN(packet *radiustransport.Packet, vlanID int) error {
	const tunnelTag byte = 0
	if err := rfc2868.TunnelType_Set(packet, tunnelTag, rfc3580.TunnelType_Value_VLAN); err != nil {
		return fmt.Errorf("set radius tunnel type: %w", err)
	}
	if err := rfc2868.TunnelMediumType_Set(packet, tunnelTag, rfc2868.TunnelMediumType_Value_IEEE802); err != nil {
		return fmt.Errorf("set radius tunnel medium type: %w", err)
	}
	if err := rfc2868.TunnelPrivateGroupID_SetString(packet, tunnelTag, fmt.Sprintf("%d", vlanID)); err != nil {
		return fmt.Errorf("set radius tunnel private group id: %w", err)
	}
	return nil
}

func (s *Server) reject(w radiustransport.ResponseWriter, r *radiustransport.Request, req lifecycle.EAPRequest, reason string) {
	s.log.Warn("RADIUS Access-Reject sent",
		"remote_addr", r.RemoteAddr.String(),
		"radius_id", r.Identifier,
		"username", req.Username,
		"imsi", req.IMSI,
		"mac", req.MACAddress,
		"reason", reason,
	)
	reject := r.Response(radiustransport.CodeAccessReject)
	_ = rfc2865.ReplyMessage_SetString(reject, reason)
	_ = w.Write(reject)
}

type eapDescription struct {
	Code        string
	Identifier  int
	Type        int
	TypeName    string
	Subtype     int
	SubtypeName string
}

func describeEAP(payload []byte) eapDescription {
	desc := eapDescription{Identifier: -1, Type: -1, Subtype: -1}
	if len(payload) < 4 {
		return desc
	}
	desc.Code = eapCodeName(payload[0])
	desc.Identifier = int(payload[1])
	length := int(payload[2])<<8 | int(payload[3])
	if length > len(payload) || length < 4 {
		desc.Code = "invalid"
		return desc
	}
	if payload[0] == 1 || payload[0] == 2 {
		if length >= 5 {
			desc.Type = int(payload[4])
			desc.TypeName = eapTypeName(payload[4])
		}
		if (payload[4] == 23 || payload[4] == 50) && length >= 6 {
			desc.Subtype = int(payload[5])
			desc.SubtypeName = eapAKASubtypeName(payload[5])
		}
	}
	return desc
}

func eapCodeName(code byte) string {
	switch code {
	case 1:
		return "request"
	case 2:
		return "response"
	case 3:
		return "success"
	case 4:
		return "failure"
	default:
		return fmt.Sprintf("code-%d", code)
	}
}

func eapTypeName(typ byte) string {
	switch typ {
	case 1:
		return "identity"
	case 18:
		return "sim"
	case 23:
		return "aka"
	case 50:
		return "aka-prime"
	default:
		return fmt.Sprintf("type-%d", typ)
	}
}

func eapAKASubtypeName(subtype byte) string {
	switch subtype {
	case 1:
		return "challenge"
	case 2:
		return "authentication-rejection"
	case 4:
		return "synchronization-failure"
	case 5:
		return "identity"
	case 12:
		return "client-error"
	case 14:
		return "notification"
	default:
		return fmt.Sprintf("subtype-%d", subtype)
	}
}

func hasMessageAuthenticator(packet *radiustransport.Packet) bool {
	return len(rfc2869.MessageAuthenticator_Get(packet)) > 0
}

func (s *Server) setMessageAuthenticator(packet *radiustransport.Packet) error {
	if err := rfc2869.MessageAuthenticator_Set(packet, make([]byte, md5.Size)); err != nil {
		return err
	}
	wire, err := packet.MarshalBinary()
	if err != nil {
		return err
	}
	mac := hmac.New(md5.New, packet.Secret)
	_, _ = mac.Write(wire)
	return rfc2869.MessageAuthenticator_Set(packet, mac.Sum(nil))
}

func (s *Server) eapRequest(packet *radiustransport.Packet, remoteAddr net.Addr) lifecycle.EAPRequest {
	username := rfc2865.UserName_GetString(packet)
	eapPayload := rfc2869.EAPMessage_Get(packet)
	eapID := eapIdentity(eapPayload)
	if username == "" {
		username = eapID
	}
	mac := normalizeMAC(rfc2865.CallingStationID_GetString(packet))
	imsi := imsiFromNAI(username)
	nasIP := ""
	if ip := rfc2865.NASIPAddress_Get(packet); ip != nil && ip.To4() != nil {
		nasIP = ip.String()
	}
	if nasIP == "" {
		nasIP = radiusSourceIP(remoteAddr)
	}
	return lifecycle.EAPRequest{
		SessionID:        rfc2865.State_GetString(packet),
		IMSI:             imsi,
		MACAddress:       mac,
		Username:         username,
		EAPIdentity:      eapID,
		Realm:            s.sub.DefaultRealm,
		APN:              s.sub.DefaultAPN,
		CallingStationID: rfc2865.CallingStationID_GetString(packet),
		CalledStationID:  rfc2865.CalledStationID_GetString(packet),
		NASIP:            nasIP,
		NASIdentifier:    rfc2865.NASIdentifier_GetString(packet),
		AcctSessionID:    rfc2866.AcctSessionID_GetString(packet),
		RadiusClass:      append([]byte(nil), rfc2865.Class_Get(packet)...),
		ConnectInfo:      rfc2869.ConnectInfo_GetString(packet),
		FramedMTU:        uint32(rfc2865.FramedMTU_Get(packet)),
		EAPPayload:       eapPayload,
	}
}

func radiusSourceIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a != nil && a.IP != nil {
			return a.IP.String()
		}
	case *net.TCPAddr:
		if a != nil && a.IP != nil {
			return a.IP.String()
		}
	}
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return host
}

func imsiFromNAI(username string) string {
	local := username
	if at := strings.IndexByte(local, '@'); at >= 0 {
		local = local[:at]
	}
	local = strings.TrimSpace(local)

	// EAP-AKA permanent identity:
	//   0<IMSI>@realm
	//
	// EAP-AKA' / AKA-Prime permanent identity:
	//   6<IMSI>@realm
	//
	// Android sends AKA-Prime as:
	//   6311435000070571@wlan.mnc435.mcc311.3gppnetwork.org
	//
	// The leading 6 is not part of the IMSI.
	if len(local) > 1 && (local[0] == '0' || local[0] == '6') && looksLikeIMSI(local[1:]) {
		return local[1:]
	}

	if looksLikeIMSI(local) {
		return local
	}

	return ""
}

func looksLikeIMSI(s string) bool {
	// Real IMSI max length is 15 digits.
	// Do not allow 16 here, because decorated AKA identities like
	// 6<IMSI> are 16 digits and must be normalized first.
	if len(s) < 5 || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func normalizeMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	replacer := strings.NewReplacer("-", ":", ".", "")
	s = replacer.Replace(s)
	if strings.Count(s, ":") == 5 {
		return s
	}
	if len(s) != 12 {
		return s
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

func eapIdentity(payload []byte) string {
	if len(payload) < 5 {
		return ""
	}
	code := payload[0]
	length := int(payload[2])<<8 | int(payload[3])
	if code != 2 || length > len(payload) || payload[4] != 1 {
		return ""
	}
	return string(payload[5:length])
}

func coalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func eapStringValue(resp *lifecycle.EAPResponse, fn func(*lifecycle.EAPResponse) string) string {
	if resp == nil {
		return ""
	}
	return fn(resp)
}

type radiusLogWriter struct {
	log *slog.Logger
}

func (w radiusLogWriter) Write(p []byte) (int, error) {
	if w.log != nil {
		w.log.Warn("RADIUS server error", "error", strings.TrimSpace(string(p)))
	}
	return len(p), nil
}
