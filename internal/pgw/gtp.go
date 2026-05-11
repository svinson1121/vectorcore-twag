package pgw

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

const gtpControlPort = 2123

type GTPClient struct {
	cfg      config.PGWConfig
	log      *slog.Logger
	local    *net.UDPAddr
	remote   *net.UDPAddr
	nextSeq  atomic.Uint32
	nextTEID atomic.Uint32
}

func NewGTP(cfg config.PGWConfig, log *slog.Logger) (*GTPClient, error) {
	localIP := net.ParseIP(cfg.LocalGTPCIP)
	if localIP == nil {
		return nil, fmt.Errorf("pgw.local_gtpc_ip is invalid")
	}
	remoteIP := net.ParseIP(cfg.RemotePGWGTPCIP)
	if remoteIP == nil {
		return nil, fmt.Errorf("pgw.remote_pgw_gtpc_ip is invalid")
	}
	c := &GTPClient{
		cfg:    cfg,
		log:    log,
		local:  &net.UDPAddr{IP: localIP, Port: 0},
		remote: &net.UDPAddr{IP: remoteIP, Port: gtpControlPort},
	}
	c.nextSeq.Store(uint32(time.Now().UnixNano()) & 0x00ffffff)
	c.nextTEID.Store(uint32(time.Now().UnixNano()))
	log.Info("GTP-C PGW client initialized",
		"local_gtpc_ip", cfg.LocalGTPCIP,
		"remote_pgw_gtpc_ip", cfg.RemotePGWGTPCIP,
		"remote_pgw_gtpc_port", gtpControlPort,
		"apn", cfg.APN,
	)
	return c, nil
}

func (c *GTPClient) CreateSession(ctx context.Context, sess *session.Session) (*CreateSessionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, fmt.Errorf("session is required")
	}
	localGTPC := c.nextTEIDValue()
	localGTPU := c.nextTEIDValue()
	msg := gtpv2Message{
		Type:     gtpv2CreateSessionReq,
		HasTEID:  true,
		TEID:     0,
		Sequence: c.nextSequence(),
		Payload:  c.createSessionPayload(sess, localGTPC, localGTPU),
	}
	c.log.Info("GTP-C Create Session Request sent",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"local_gtpc_ip", c.cfg.LocalGTPCIP,
		"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
		"local_gtpc_teid", localGTPC,
		"local_gtpu_teid", localGTPU,
	)
	resp, err := c.roundTrip(ctx, msg)
	if err != nil {
		return nil, err
	}
	if resp.Type != gtpv2CreateSessionResp {
		return nil, fmt.Errorf("expected GTPv2 Create Session Response, got message type %d", resp.Type)
	}
	result, cause, err := c.parseCreateSessionResponse(resp, localGTPU)
	if err != nil {
		return nil, err
	}
	c.log.Info("GTP-C Create Session Response received",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"gtp_cause", cause,
		"subscriber_ip", ipString(result.SubscriberIP),
		"pgw_control_ip", ipString(result.PGWControlIP),
		"pgw_user_ip", ipString(result.PGWUserIP),
		"gtpc_teid", result.GTPCTEID,
		"local_gtpu_teid", result.LocalGTPUTEID,
		"remote_gtpu_teid", result.RemoteGTPUTEID,
	)
	return result, nil
}

func (c *GTPClient) DeleteSession(ctx context.Context, sess *session.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sess == nil {
		return fmt.Errorf("session is required")
	}
	if sess.GTPCTEID == 0 {
		return fmt.Errorf("session has no PGW control TEID")
	}
	msg := gtpv2Message{
		Type:     gtpv2DeleteSessionReq,
		HasTEID:  true,
		TEID:     sess.GTPCTEID,
		Sequence: c.nextSequence(),
	}
	c.log.Info("GTP-C Delete Session Request sent", "session_id", sess.ID, "imsi", sess.IMSI, "gtpc_teid", sess.GTPCTEID)
	resp, err := c.roundTrip(ctx, msg)
	if err != nil {
		return err
	}
	if resp.Type != gtpv2DeleteSessionResp {
		return fmt.Errorf("expected GTPv2 Delete Session Response, got message type %d", resp.Type)
	}
	ies, err := decodeIEs(resp.Payload)
	if err != nil {
		return err
	}
	cause := parseCause(ies)
	if cause != causeRequestAccepted {
		return fmt.Errorf("GTP-C Delete Session rejected with cause %d", cause)
	}
	c.log.Info("GTP-C Delete Session Response received", "session_id", sess.ID, "imsi", sess.IMSI, "gtp_cause", cause)
	return nil
}

func (c *GTPClient) Type() string { return ModeGTP }

func (c *GTPClient) Probe(ctx context.Context) error {
	c.log.Info("GTP-C echo request sent",
		"local_gtpc_ip", c.cfg.LocalGTPCIP,
		"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
		"remote_pgw_gtpc_port", c.remote.Port,
	)
	if err := c.Echo(ctx); err != nil {
		c.log.Warn("GTP-C echo failed",
			"local_gtpc_ip", c.cfg.LocalGTPCIP,
			"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
			"remote_pgw_gtpc_port", c.remote.Port,
			"error", err,
		)
		return err
	}
	c.log.Info("GTP-C echo response received",
		"local_gtpc_ip", c.cfg.LocalGTPCIP,
		"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
		"remote_pgw_gtpc_port", c.remote.Port,
	)
	return nil
}

func (c *GTPClient) Echo(ctx context.Context) error {
	resp, err := c.roundTrip(ctx, gtpv2Message{
		Type:     gtpv2EchoRequest,
		Sequence: c.nextSequence(),
	})
	if err != nil {
		return err
	}
	if resp.Type != gtpv2EchoResponse {
		return fmt.Errorf("expected GTPv2 Echo Response, got message type %d", resp.Type)
	}
	c.log.Debug("GTP-C echo response decoded", "remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP, "sequence", resp.Sequence)
	return nil
}

func (c *GTPClient) roundTrip(ctx context.Context, req gtpv2Message) (gtpv2Message, error) {
	if err := ctx.Err(); err != nil {
		return gtpv2Message{}, err
	}
	conn, err := net.DialUDP("udp", c.local, c.remote)
	if err != nil {
		return gtpv2Message{}, fmt.Errorf("dial GTP-C PGW: %w", err)
	}
	defer conn.Close() //nolint:errcheck
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	encoded, err := req.encode()
	if err != nil {
		return gtpv2Message{}, err
	}
	c.log.Debug("GTP-C message encoded", "message_type", req.Type, "sequence", req.Sequence, "teid", req.TEID, "bytes", fmt.Sprintf("%x", encoded))
	if _, err := conn.Write(encoded); err != nil {
		return gtpv2Message{}, fmt.Errorf("send GTP-C message: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return gtpv2Message{}, ctxErr
		}
		return gtpv2Message{}, fmt.Errorf("receive GTP-C message: %w", err)
	}
	resp, err := decodeGTPv2Message(buf[:n])
	if err != nil {
		return gtpv2Message{}, err
	}
	if resp.Sequence != req.Sequence {
		return gtpv2Message{}, fmt.Errorf("GTP-C sequence mismatch: got %d want %d", resp.Sequence, req.Sequence)
	}
	return resp, nil
}

func (c *GTPClient) nextSequence() uint32 {
	seq := c.nextSeq.Add(1) & 0x00ffffff
	if seq == 0 {
		seq = c.nextSeq.Add(1) & 0x00ffffff
	}
	return seq
}

func (c *GTPClient) nextTEIDValue() uint32 {
	teid := c.nextTEID.Add(1)
	if teid == 0 {
		teid = c.nextTEID.Add(1)
	}
	return teid
}

func (c *GTPClient) createSessionPayload(sess *session.Session, localGTPC, localGTPU uint32) []byte {
	localGTPCIP := net.ParseIP(c.cfg.LocalGTPCIP)
	localGTPUIP := net.ParseIP(c.cfg.LocalGTPUIP)
	apn := firstNonEmpty(c.cfg.APN, sess.APN)
	ies := []gtpv2IE{
		bcdIE(ieIMSI, sess.IMSI),
		uint8IE(ieRecovery, 0),
		apnIE(apn),
	}
	if servingNetwork, ok := servingNetworkIE(sess.Realm); ok {
		ies = append(ies, servingNetwork)
	}
	ies = append(ies,
		uint8IE(ieRATType, ratTypeWLAN),
		fteidIE(0, ifaceS2aTWANGTPC, localGTPC, localGTPCIP),
		uint8IE(ieSelectionMode, 0),
		uint8IE(iePDNType, pdnTypeIPv4),
		paaIE(sess.SubscriberIP),
		uint8IE(ieAPNRestriction, 0),
		ambrIE(0, 0),
		gtpv2IE{Type: ieBearerContext, Payload: encodeIEs(
			uint8IE(ieEBI, 5),
			fteidIE(0, ifaceS2aTWANGTPU, localGTPU, localGTPUIP),
			bearerQoSIE(9),
		)},
	)
	if sess.MSISDN != "" {
		ies = append(ies, bcdIE(ieMSISDN, sess.MSISDN))
	}
	return encodeIEs(ies...)
}

func (c *GTPClient) parseCreateSessionResponse(resp gtpv2Message, localGTPU uint32) (*CreateSessionResult, uint8, error) {
	ies, err := decodeIEs(resp.Payload)
	if err != nil {
		return nil, 0, err
	}
	cause := parseCauseInfo(ies)
	if cause.Cause != causeRequestAccepted {
		if cause.OffendingIEType != 0 {
			return nil, cause.Cause, fmt.Errorf("GTP-C Create Session rejected with cause %d offending_ie_type=%d offending_ie_instance=%d offending_ie_length=%d", cause.Cause, cause.OffendingIEType, cause.OffendingIEInstance, cause.OffendingIELength)
		}
		return nil, cause.Cause, fmt.Errorf("GTP-C Create Session rejected with cause %d", cause.Cause)
	}
	result := &CreateSessionResult{
		SubscriberIP:  parsePAA(ies),
		PGWControlIP:  net.ParseIP(c.cfg.RemotePGWGTPCIP),
		PGWUserIP:     net.ParseIP(c.cfg.RemotePGWGTPUIP),
		LocalGTPUTEID: localGTPU,
	}
	if fteid, ok := findIE(ies, ieFTEID, 0); ok {
		iface, teid, ip, parsed := parseFTEID(fteid)
		if parsed {
			if iface != ifaceS2aPGWGTPC {
				c.log.Debug("GTP-C Create Session Response control F-TEID interface type", "interface_type", iface)
			}
			result.GTPCTEID = teid
			if ip != nil {
				result.PGWControlIP = ip
			}
		}
	}
	for _, ie := range ies {
		if ie.Type != ieBearerContext {
			continue
		}
		children, err := decodeIEs(ie.Payload)
		if err != nil {
			continue
		}
		if fteid, ok := findIE(children, ieFTEID, 2); ok {
			iface, teid, ip, parsed := parseFTEID(fteid)
			if parsed {
				if iface != ifaceS2aPGWGTPU {
					c.log.Debug("GTP-C Create Session Response bearer F-TEID interface type", "interface_type", iface)
				}
				result.RemoteGTPUTEID = teid
				if ip != nil {
					result.PGWUserIP = ip
				}
			}
		}
	}
	return result, cause.Cause, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
