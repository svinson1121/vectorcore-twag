package diameter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vectorcore/twag/internal/config"
)

type STaClient interface {
	Start(ctx context.Context) error
	Stop() error
	Authenticate(ctx context.Context, req STaAuthRequest) (*STaAuthResult, error)
	ExchangeEAP(ctx context.Context, req STaEAPRequest) (*STaEAPResult, error)
	Status() STaStatus
}

type STaAuthRequest struct {
	IMSI     string
	MSISDN   string
	Username string
	Realm    string
	APN      string
	Ki       string
	OPc      string
}

type STaAuthResult struct {
	ResultCode uint32
	Allowed    bool
	IMSI       string
	MSISDN     string
	APN        string
	Reason     string
}

type STaEAPState string

const (
	STaEAPStateChallenge STaEAPState = "challenge"
	STaEAPStateSuccess   STaEAPState = "success"
	STaEAPStateFailure   STaEAPState = "failure"
)

type STaEAPRequest struct {
	SessionID  string
	IMSI       string
	MSISDN     string
	Username   string
	Realm      string
	APN        string
	EAPPayload []byte
}

type STaEAPResult struct {
	SessionID  string
	ResultCode uint32
	State      STaEAPState
	Allowed    bool
	IMSI       string
	MSISDN     string
	APN        string
	Reason     string
	EAPPayload []byte
	MSK        []byte
}

type STaStatus struct {
	PeerAddr          string    `json:"peer_addr"`
	State             string    `json:"state"`
	LastError         string    `json:"last_error,omitempty"`
	ResultCode        uint32    `json:"last_result_code,omitempty"`
	CERComplete       bool      `json:"cer_complete"`
	LastWatchdog      time.Time `json:"last_watchdog,omitempty"`
	WatchdogFailures  uint64    `json:"watchdog_failures"`
	ReconnectAttempts uint64    `json:"reconnect_attempts"`
}

const (
	defaultWatchdogInterval = 30 * time.Second
	defaultWatchdogTimeout  = 10 * time.Second
)

type STaDiameterClient struct {
	cfg config.STaConfig
	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.RWMutex
	conn     net.Conn
	status   STaStatus
	pending  map[uint32]chan diameterResponse
	openedCh chan struct{}
	writeMu  sync.Mutex
	nextHop  atomic.Uint32
	nextEnd  atomic.Uint32

	watchdogInterval time.Duration
	watchdogTimeout  time.Duration
}

type diameterResponse struct {
	msg message
	err error
}

func NewSTaClient(cfg config.STaConfig, log *slog.Logger) *STaDiameterClient {
	c := &STaDiameterClient{
		cfg:              cfg,
		log:              log,
		pending:          make(map[uint32]chan diameterResponse),
		openedCh:         make(chan struct{}),
		watchdogInterval: defaultWatchdogInterval,
		watchdogTimeout:  defaultWatchdogTimeout,
		status: STaStatus{
			PeerAddr: cfg.PeerAddr,
			State:    "initialized",
		},
	}
	c.nextHop.Store(uint32(time.Now().UnixNano()))
	c.nextEnd.Store(uint32(time.Now().Unix()))
	return c
}

func (c *STaDiameterClient) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.cancel != nil {
		c.mu.Unlock()
		return c.waitOpen(ctx)
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.status.State = "starting"
	c.mu.Unlock()

	c.log.Info("Diameter STa client initialized", "peer_addr", c.cfg.PeerAddr)
	go c.connectLoop()
	return c.waitOpen(ctx)
}

func (c *STaDiameterClient) Stop() error {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.status.State = "stopped"
	c.failPendingLocked(errors.New("sta client stopped"))
	c.mu.Unlock()
	c.log.Info("Diameter STa client stopped", "peer_addr", c.cfg.PeerAddr)
	return nil
}

func (c *STaDiameterClient) Authenticate(ctx context.Context, req STaAuthRequest) (*STaAuthResult, error) {
	if req.IMSI == "" && req.Username == "" {
		return nil, fmt.Errorf("sta auth requires imsi or username")
	}
	if err := c.waitOpen(ctx); err != nil {
		return nil, err
	}
	sessionID := fmt.Sprintf("%s;%d", c.cfg.OriginHost, time.Now().UnixNano())
	userName := req.IMSI
	if userName == "" {
		userName = req.Username
	}
	eapPayload, err := eapResponseIdentity(1, userName)
	if err != nil {
		return nil, err
	}
	msg := c.newDER(sessionID, userName, req.APN, eapPayload)
	c.log.Info("STa authentication request sent", "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "reason", "", "command", "DER")
	answer, err := c.sendRequest(ctx, msg)
	if err != nil {
		return nil, err
	}
	akaResponsesSent := 0
	for i := 0; i < 4; i++ {
		nextPayload, ok, err := c.nextEAPResponse(req, userName, answer)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if akaResponsesSent > 0 {
			nextPayload = osmoAAAAuthCompletePayload(parseEAPResult(nextPayload).Identifier)
			c.log.Info("STa osmo-aaa compatibility auth-complete marker generated", "imsi", req.IMSI)
		}
		msg = c.newDER(sessionID, userName, req.APN, nextPayload)
		c.log.Info("STa authentication request sent", "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "reason", "eap response", "command", "DER")
		answer, err = c.sendRequest(ctx, msg)
		if err != nil {
			return nil, err
		}
		akaResponsesSent++
	}
	return c.authResult(req, answer)
}

func (c *STaDiameterClient) ExchangeEAP(ctx context.Context, req STaEAPRequest) (*STaEAPResult, error) {
	if req.IMSI == "" && req.Username == "" {
		return nil, fmt.Errorf("sta eap exchange requires imsi or username")
	}
	if len(req.EAPPayload) == 0 {
		return nil, fmt.Errorf("sta eap exchange requires eap payload")
	}
	if err := c.waitOpen(ctx); err != nil {
		return nil, err
	}
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("%s;%d", c.cfg.OriginHost, time.Now().UnixNano())
	}
	userName := req.IMSI
	if userName == "" {
		userName = req.Username
	}
	msg := c.newDER(sessionID, userName, req.APN, req.EAPPayload)
	c.log.Info("STa EAP request sent", "session_id", sessionID, "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "reason", "", "command", "DER")
	answer, err := c.sendRequest(ctx, msg)
	if err != nil {
		return nil, err
	}
	return c.eapExchangeResult(req, sessionID, answer), nil
}

func (c *STaDiameterClient) newDER(sessionID, userName, apn string, eapPayload []byte) message {
	msg := c.newRequest(commandDER, c.cfg.AuthApplicationID, true, []avp{
		utf8AVP(avpSessionID, 0, sessionID),
		uint32AVP(avpAuthApplicationID, 0, c.cfg.AuthApplicationID),
		utf8AVP(avpOriginHost, 0, c.cfg.OriginHost),
		utf8AVP(avpOriginRealm, 0, c.cfg.OriginRealm),
		utf8AVP(avpDestinationRealm, 0, c.cfg.DestinationRealm),
		uint32AVP(avpAuthRequestType, 0, 3),
		{Code: avpEAPPayload, Flags: flagMandatory, Data: eapPayload},
	})
	if c.cfg.DestinationHost != "" {
		msg.AVPs = append(msg.AVPs, utf8AVP(avpDestinationHost, 0, c.cfg.DestinationHost))
	}
	msg.AVPs = append(msg.AVPs, utf8AVP(avpUserName, 0, userName))
	if apn != "" {
		msg.AVPs = append(msg.AVPs, utf8AVP(avpServiceSelection, 0, apn))
	}
	return msg
}

func (c *STaDiameterClient) nextEAPResponse(req STaAuthRequest, identity string, answer message) ([]byte, bool, error) {
	eapPayload, ok := findAVP(answer.AVPs, avpEAPPayload, 0)
	if !ok {
		return nil, false, nil
	}
	eapResult := parseEAPResult(eapPayload.Data)
	if eapResult.State != eapStateRequest {
		c.log.Debug("STa EAP response not generated", "eap_state", eapResult.State, "reason", eapResult.Description)
		return nil, false, nil
	}
	if eapResult.Description == "eap-aka-prime challenge" {
		c.log.Warn("STa EAP-AKA' challenge response generation is not implemented", "imsi", req.IMSI)
		return nil, false, nil
	}
	if eapResult.Description != "eap-aka challenge" {
		c.log.Debug("STa EAP response not generated", "eap_state", eapResult.State, "reason", eapResult.Description)
		return nil, false, nil
	}
	if req.Ki == "" || req.OPc == "" {
		c.log.Warn("STa EAP-AKA challenge cannot be answered without test UE credentials", "imsi", req.IMSI, "has_ki", req.Ki != "", "has_opc", req.OPc != "")
		return nil, false, nil
	}
	nextPayload, err := buildEAPAKAChallengeResponse(identity, eapPayload.Data, req.Ki, req.OPc)
	if err != nil {
		return nil, false, err
	}
	c.log.Info("STa EAP-AKA challenge response generated", "imsi", req.IMSI, "eap_identifier", eapResult.Identifier)
	return nextPayload, true, nil
}

func (c *STaDiameterClient) authResult(req STaAuthRequest, answer message) (*STaAuthResult, error) {
	resultCode, ok := avpUint32(answer.AVPs, avpResultCode, 0)
	if !ok {
		resultCode, ok = experimentalResultCode(answer.AVPs)
	}
	if !ok {
		resultCode = 0
	}
	allowed := resultCode == 2001 || resultCode == 2002
	reason := resultReason(resultCode)
	if eapPayload, ok := findAVP(answer.AVPs, avpEAPPayload, 0); ok {
		eapResult := parseEAPResult(eapPayload.Data)
		switch eapResult.State {
		case eapStateSuccess:
			allowed = resultCode == 2001 || resultCode == 2002
			reason = "eap success"
		case eapStateFailure:
			allowed = false
			reason = "eap failure"
		case eapStateRequest:
			allowed = false
			reason = "eap authentication incomplete: " + eapResult.Description
		case eapStateInvalid:
			allowed = false
			reason = "invalid eap payload: " + eapResult.Description
		case eapStateUnknown:
			allowed = false
			reason = "unsupported eap payload: " + eapResult.Description
		}
	}
	c.mu.Lock()
	c.status.ResultCode = resultCode
	c.mu.Unlock()
	c.log.Info("STa authentication answer received", "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "diameter_result_code", resultCode, "allowed", allowed, "reason", reason, "command", "DEA")
	return &STaAuthResult{
		ResultCode: resultCode,
		Allowed:    allowed,
		IMSI:       req.IMSI,
		MSISDN:     req.MSISDN,
		APN:        req.APN,
		Reason:     reason,
	}, nil
}

func (c *STaDiameterClient) eapExchangeResult(req STaEAPRequest, sessionID string, answer message) *STaEAPResult {
	resultCode, ok := avpUint32(answer.AVPs, avpResultCode, 0)
	if !ok {
		resultCode, ok = experimentalResultCode(answer.AVPs)
	}
	if !ok {
		resultCode = 0
	}
	state := STaEAPStateFailure
	allowed := false
	reason := resultReason(resultCode)
	var responsePayload []byte
	var msk []byte
	if eapPayload, ok := findAVP(answer.AVPs, avpEAPPayload, 0); ok {
		responsePayload = append([]byte(nil), eapPayload.Data...)
		eapResult := parseEAPResult(eapPayload.Data)
		switch eapResult.State {
		case eapStateRequest:
			state = STaEAPStateChallenge
			reason = eapResult.Description
		case eapStateSuccess:
			state = STaEAPStateSuccess
			allowed = resultCode == 2001 || resultCode == 2002
			reason = "eap success"
		case eapStateFailure:
			state = STaEAPStateFailure
			reason = "eap failure"
		case eapStateInvalid:
			state = STaEAPStateFailure
			reason = "invalid eap payload: " + eapResult.Description
		case eapStateUnknown:
			state = STaEAPStateFailure
			reason = "unsupported eap payload: " + eapResult.Description
		}
	} else if resultCode == 2001 || resultCode == 2002 {
		state = STaEAPStateSuccess
		allowed = true
	}
	if state == STaEAPStateSuccess && allowed {
		if key, ok := findAVP(answer.AVPs, avpEAPMasterSessionKey, 0); ok {
			if len(key.Data) == 64 {
				msk = append([]byte(nil), key.Data...)
				c.log.Info("STa EAP success keying material received", "session_id", sessionID, "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "msk_present", true, "msk_len", len(msk), "key_avp", "EAP-Master-Session-Key", "key_avp_code", avpEAPMasterSessionKey)
			} else {
				c.log.Warn("STa DEA success included invalid EAP MSK/keying material length", "session_id", sessionID, "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "msk_present", true, "msk_len", len(key.Data), "key_avp", "EAP-Master-Session-Key", "key_avp_code", avpEAPMasterSessionKey)
			}
		} else {
			c.log.Warn("STa DEA success missing EAP MSK/keying material; RADIUS Access-Accept cannot include MPPE keys", "session_id", sessionID, "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "msk_present", false, "msk_len", 0)
		}
	}
	c.mu.Lock()
	c.status.ResultCode = resultCode
	c.mu.Unlock()
	c.log.Info("STa EAP answer received", "session_id", sessionID, "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "diameter_result_code", resultCode, "eap_state", state, "allowed", allowed, "reason", reason, "command", "DEA", "msk_present", len(msk) == 64, "msk_len", len(msk))
	return &STaEAPResult{
		SessionID:  sessionID,
		ResultCode: resultCode,
		State:      state,
		Allowed:    allowed,
		IMSI:       req.IMSI,
		MSISDN:     req.MSISDN,
		APN:        req.APN,
		Reason:     reason,
		EAPPayload: responsePayload,
		MSK:        msk,
	}
}

func (c *STaDiameterClient) Status() STaStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *STaDiameterClient) connectLoop() {
	backoff := time.Second
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		c.setStatus("connecting", "", false)
		c.mu.Lock()
		c.status.ReconnectAttempts++
		c.mu.Unlock()
		c.log.Info("connecting to 3GPP AAA Diameter peer", "peer_addr", c.cfg.PeerAddr)
		dialer := net.Dialer{Timeout: 5 * time.Second}
		conn, err := dialer.DialContext(c.ctx, "tcp", c.cfg.PeerAddr)
		if err != nil {
			c.setStatus("disconnected", err.Error(), false)
			c.log.Warn("Diameter STa peer connect failed", "peer_addr", c.cfg.PeerAddr, "error", err)
			c.sleep(backoff)
			backoff = minDuration(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if err := c.handshake(conn); err != nil {
			_ = conn.Close()
			c.setStatus("disconnected", err.Error(), false)
			c.log.Warn("Diameter STa handshake failed", "peer_addr", c.cfg.PeerAddr, "error", err)
			c.sleep(backoff)
			continue
		}
		c.mu.Lock()
		c.conn = conn
		c.status.State = "open"
		c.status.LastError = ""
		c.status.CERComplete = true
		close(c.openedCh)
		c.openedCh = make(chan struct{})
		c.mu.Unlock()
		c.log.Info("Diameter peer ready", "peer_addr", c.cfg.PeerAddr)
		errCh := make(chan error, 1)
		go c.readLoop(conn, errCh)
		go c.watchdogLoop(conn)
		select {
		case <-c.ctx.Done():
			_ = conn.Close()
			return
		case err := <-errCh:
			_ = conn.Close()
			c.mu.Lock()
			if c.conn == conn {
				c.conn = nil
			}
			c.status.State = "disconnected"
			c.status.LastError = err.Error()
			c.status.CERComplete = false
			c.failPendingLocked(err)
			c.mu.Unlock()
			c.log.Warn("Diameter peer disconnected", "peer_addr", c.cfg.PeerAddr, "error", err)
		}
	}
}

func (c *STaDiameterClient) handshake(conn net.Conn) error {
	localIP := [4]byte{127, 0, 0, 1}
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		if ip4 := addr.IP.To4(); ip4 != nil {
			copy(localIP[:], ip4)
		}
	}
	cer := c.newRequest(commandCER, 0, false, []avp{
		utf8AVP(avpOriginHost, 0, c.cfg.OriginHost),
		utf8AVP(avpOriginRealm, 0, c.cfg.OriginRealm),
		uint32AVP(avpOriginStateID, 0, uint32(time.Now().Unix())),
		addressAVP(avpHostIPAddress, localIP),
		uint32AVP(avpVendorID, 0, 0),
		utf8AVPFlags(avpProductName, 0, 0, "VectorCore TWAG"),
		uint32AVPFlags(avpFirmwareRevision, 0, 0, firmwareRevOne),
		uint32AVP(avpInbandSecurityID, 0, inbandNoSec),
		uint32AVP(avpAuthApplicationID, 0, c.cfg.AuthApplicationID),
		uint32AVP(avpSupportedVendorID, 0, vendor3GPP),
		groupedAVP(avpVendorSpecificApplicationID, 0,
			uint32AVP(avpVendorID, 0, c.cfg.VendorID),
			uint32AVP(avpAuthApplicationID, 0, c.cfg.AuthApplicationID),
		),
	})
	encoded := cer.encode()
	c.log.Debug("CER encoded",
		"peer_addr", c.cfg.PeerAddr,
		"origin_host", c.cfg.OriginHost,
		"origin_realm", c.cfg.OriginRealm,
		"sta_application_id", c.cfg.AuthApplicationID,
		"supported_vendor_id", vendor3GPP,
		"bytes", fmt.Sprintf("%x", encoded),
	)
	c.log.Info("CER sent", "peer_addr", c.cfg.PeerAddr)
	if _, err := conn.Write(encoded); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	cea, err := decodeMessage(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("peer closed or rejected CER before CEA: %w", err)
	}
	if cea.CommandCode != commandCER || cea.isRequest() {
		return fmt.Errorf("expected CEA, got command=%d request=%t", cea.CommandCode, cea.isRequest())
	}
	rc, _ := avpUint32(cea.AVPs, avpResultCode, 0)
	c.log.Info("CEA received", "peer_addr", c.cfg.PeerAddr, "diameter_result_code", rc)
	if rc != 2001 && rc != 2002 {
		return fmt.Errorf("CEA result code %d", rc)
	}
	return nil
}

func (c *STaDiameterClient) readLoop(conn net.Conn, errCh chan<- error) {
	for {
		msg, err := decodeMessage(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				errCh <- io.EOF
				return
			}
			errCh <- err
			return
		}
		if msg.isRequest() {
			c.handleRequest(conn, msg)
			continue
		}
		c.mu.Lock()
		ch := c.pending[msg.HopByHop]
		delete(c.pending, msg.HopByHop)
		c.mu.Unlock()
		if ch != nil {
			ch <- diameterResponse{msg: msg}
		}
	}
}

func (c *STaDiameterClient) handleRequest(conn net.Conn, req message) {
	switch req.CommandCode {
	case commandDWR:
		resp := c.newAnswer(req, []avp{
			utf8AVP(avpOriginHost, 0, c.cfg.OriginHost),
			utf8AVP(avpOriginRealm, 0, c.cfg.OriginRealm),
			uint32AVP(avpResultCode, 0, 2001),
		})
		c.writeMu.Lock()
		_, _ = conn.Write(resp.encode())
		c.writeMu.Unlock()
	case commandDER:
		if req.AppID == c.cfg.AuthApplicationID {
			c.answerMalformedDER(conn, req)
			return
		}
		c.log.Warn("Diameter inbound request ignored", "command_code", req.CommandCode, "application_id", req.AppID)
	case commandPPR, commandRTR:
		c.log.Warn("STa inbound request not implemented", "command_code", req.CommandCode, "user_name", avpString(req.AVPs, avpUserName, 0))
	default:
		c.log.Warn("Diameter inbound request ignored", "command_code", req.CommandCode)
	}
}

func (c *STaDiameterClient) answerMalformedDER(conn net.Conn, req message) {
	if _, ok := findAVP(req.AVPs, avpEAPPayload, 0); ok {
		c.log.Warn("STa inbound DER not implemented", "user_name", avpString(req.AVPs, avpUserName, 0))
		return
	}
	resp := c.newAnswer(req, []avp{
		utf8AVP(avpOriginHost, 0, c.cfg.OriginHost),
		utf8AVP(avpOriginRealm, 0, c.cfg.OriginRealm),
		uint32AVP(avpResultCode, 0, 5005),
		groupedAVP(avpFailedAVP, 0, avp{Code: avpEAPPayload, Flags: flagMandatory}),
	})
	c.writeMu.Lock()
	_, _ = conn.Write(resp.encode())
	c.writeMu.Unlock()
	c.log.Warn("STa inbound DER missing mandatory AVP", "user_name", avpString(req.AVPs, avpUserName, 0), "missing_avp", avpEAPPayload, "diameter_result_code", 5005)
}

func (c *STaDiameterClient) watchdogLoop(conn net.Conn) {
	ticker := time.NewTicker(c.watchdogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			req := c.newRequest(commandDWR, 0, false, []avp{
				utf8AVP(avpOriginHost, 0, c.cfg.OriginHost),
				utf8AVP(avpOriginRealm, 0, c.cfg.OriginRealm),
			})
			ctx, cancel := context.WithTimeout(c.ctx, c.watchdogTimeout)
			ans, err := c.sendRequestOnConn(ctx, conn, req)
			cancel()
			if err != nil {
				c.mu.Lock()
				c.status.WatchdogFailures++
				c.mu.Unlock()
				c.log.Warn("Diameter watchdog failure", "peer_addr", c.cfg.PeerAddr, "error", err)
				_ = conn.Close()
				return
			}
			rc, _ := avpUint32(ans.AVPs, avpResultCode, 0)
			c.mu.Lock()
			c.status.LastWatchdog = time.Now().UTC()
			c.mu.Unlock()
			c.log.Debug("Diameter watchdog success", "peer_addr", c.cfg.PeerAddr, "diameter_result_code", rc)
		}
	}
}

func (c *STaDiameterClient) sendRequest(ctx context.Context, req message) (message, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return message{}, fmt.Errorf("Diameter peer is not open")
	}
	return c.sendRequestOnConn(ctx, conn, req)
}

func (c *STaDiameterClient) sendRequestOnConn(ctx context.Context, conn net.Conn, req message) (message, error) {
	ch := make(chan diameterResponse, 1)
	c.mu.Lock()
	c.pending[req.HopByHop] = ch
	c.mu.Unlock()
	c.writeMu.Lock()
	_, err := conn.Write(req.encode())
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, req.HopByHop)
		c.mu.Unlock()
		return message{}, err
	}
	select {
	case resp := <-ch:
		return resp.msg, resp.err
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, req.HopByHop)
		c.mu.Unlock()
		return message{}, ctx.Err()
	}
}

func (c *STaDiameterClient) newRequest(command, appID uint32, proxiable bool, avps []avp) message {
	flags := flagRequest
	if proxiable {
		flags |= flagProxiable
	}
	return message{
		Flags:       flags,
		CommandCode: command,
		AppID:       appID,
		HopByHop:    c.nextHop.Add(1),
		EndToEnd:    c.nextEnd.Add(1),
		AVPs:        avps,
	}
}

func (c *STaDiameterClient) newAnswer(req message, avps []avp) message {
	return message{
		Flags:       req.Flags &^ flagRequest,
		CommandCode: req.CommandCode,
		AppID:       req.AppID,
		HopByHop:    req.HopByHop,
		EndToEnd:    req.EndToEnd,
		AVPs:        avps,
	}
}

func (c *STaDiameterClient) waitOpen(ctx context.Context) error {
	c.mu.RLock()
	if c.status.State == "open" && c.conn != nil {
		c.mu.RUnlock()
		return nil
	}
	opened := c.openedCh
	c.mu.RUnlock()
	select {
	case <-opened:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timed out waiting for Diameter peer")
	}
}

func (c *STaDiameterClient) setStatus(state, lastErr string, cerComplete bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.State = state
	c.status.LastError = lastErr
	c.status.CERComplete = cerComplete
}

func (c *STaDiameterClient) failPendingLocked(err error) {
	for hop, ch := range c.pending {
		delete(c.pending, hop)
		ch <- diameterResponse{err: err}
	}
}

func (c *STaDiameterClient) sleep(d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-c.ctx.Done():
	case <-timer.C:
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func resultReason(code uint32) string {
	switch code {
	case 2001:
		return "diameter success"
	case 2002:
		return "diameter limited success"
	case 5001:
		return "user unknown"
	case 0:
		return "missing result code"
	default:
		return fmt.Sprintf("diameter result code %d", code)
	}
}

func eapResponseIdentity(identifier byte, identity string) ([]byte, error) {
	if identity == "" {
		return nil, fmt.Errorf("EAP identity is required")
	}
	length := 5 + len(identity)
	if length > 0xffff {
		return nil, fmt.Errorf("EAP identity too long")
	}
	payload := make([]byte, length)
	payload[0] = 2
	payload[1] = identifier
	payload[2] = byte(length >> 8)
	payload[3] = byte(length)
	payload[4] = 1
	copy(payload[5:], identity)
	return payload, nil
}

type eapState string

const (
	eapStateUnknown eapState = "unknown"
	eapStateRequest eapState = "request"
	eapStateSuccess eapState = "success"
	eapStateFailure eapState = "failure"
	eapStateInvalid eapState = "invalid"
)

type eapResult struct {
	State       eapState
	Description string
	Identifier  byte
}

func parseEAPResult(payload []byte) eapResult {
	if len(payload) < 4 {
		return eapResult{State: eapStateInvalid, Description: "short header"}
	}
	code := payload[0]
	identifier := payload[1]
	length := int(payload[2])<<8 | int(payload[3])
	if length < 4 || length > len(payload) {
		return eapResult{State: eapStateInvalid, Identifier: identifier, Description: "invalid length"}
	}
	switch code {
	case 1:
		if length < 5 {
			return eapResult{State: eapStateInvalid, Identifier: identifier, Description: "request missing type"}
		}
		return eapResult{State: eapStateRequest, Identifier: identifier, Description: eapRequestDescription(payload[4:length])}
	case 3:
		return eapResult{State: eapStateSuccess, Identifier: identifier, Description: "success"}
	case 4:
		return eapResult{State: eapStateFailure, Identifier: identifier, Description: "failure"}
	default:
		return eapResult{State: eapStateUnknown, Identifier: identifier, Description: fmt.Sprintf("code %d", code)}
	}
}

func eapRequestDescription(data []byte) string {
	if len(data) == 0 {
		return "request"
	}
	switch data[0] {
	case 1:
		return "identity request"
	case 23:
		if len(data) >= 2 {
			return "eap-aka " + eapAKASubtype(data[1])
		}
		return "eap-aka request"
	case 50:
		if len(data) >= 2 {
			return "eap-aka-prime " + eapAKASubtype(data[1])
		}
		return "eap-aka-prime request"
	default:
		return fmt.Sprintf("request type %d", data[0])
	}
}

func eapAKASubtype(subtype byte) string {
	switch subtype {
	case 1:
		return "challenge"
	case 2:
		return "authentication rejection"
	case 4:
		return "synchronization failure"
	case 5:
		return "identity"
	case 12:
		return "client error"
	default:
		return fmt.Sprintf("subtype %d", subtype)
	}
}

type StubSTaClient struct {
	cfg config.STaConfig
	log *slog.Logger

	mu     sync.RWMutex
	status STaStatus
}

func NewStubSTaClient(cfg config.STaConfig, log *slog.Logger) *StubSTaClient {
	return &StubSTaClient{
		cfg: cfg,
		log: log,
		status: STaStatus{
			PeerAddr: cfg.PeerAddr,
			State:    "initialized",
		},
	}
}

func (c *StubSTaClient) Start(_ context.Context) error {
	c.mu.Lock()
	c.status.State = "stub_ready"
	c.status.LastError = ""
	c.mu.Unlock()
	c.log.Info("Diameter STa client initialized", "peer_addr", c.cfg.PeerAddr)
	c.log.Info("Diameter STa stub ready", "peer_addr", c.cfg.PeerAddr)
	return nil
}

func (c *StubSTaClient) Stop() error {
	c.mu.Lock()
	c.status.State = "stopped"
	c.mu.Unlock()
	c.log.Info("Diameter STa client stopped", "peer_addr", c.cfg.PeerAddr)
	return nil
}

func (c *StubSTaClient) Authenticate(_ context.Context, req STaAuthRequest) (*STaAuthResult, error) {
	if req.IMSI == "" && req.Username == "" {
		return nil, fmt.Errorf("sta auth requires imsi or username")
	}
	c.mu.Lock()
	c.status.ResultCode = 2001
	c.mu.Unlock()
	c.log.Info("STa authentication request sent", "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "reason", "", "command", "DER")
	c.log.Info("STa authentication answer received", "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "diameter_result_code", 2001, "allowed", true, "reason", "diameter success", "command", "DEA")
	return &STaAuthResult{
		ResultCode: 2001,
		Allowed:    true,
		IMSI:       req.IMSI,
		MSISDN:     req.MSISDN,
		APN:        req.APN,
		Reason:     "stub accepted",
	}, nil
}

func (c *StubSTaClient) ExchangeEAP(_ context.Context, req STaEAPRequest) (*STaEAPResult, error) {
	if req.IMSI == "" && req.Username == "" {
		return nil, fmt.Errorf("sta eap exchange requires imsi or username")
	}
	if len(req.EAPPayload) == 0 {
		return nil, fmt.Errorf("sta eap exchange requires eap payload")
	}
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("%s;%d", c.cfg.OriginHost, time.Now().UnixNano())
	}
	c.mu.Lock()
	c.status.ResultCode = 2001
	c.mu.Unlock()
	c.log.Info("STa EAP request sent", "session_id", sessionID, "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "reason", "", "command", "DER")
	c.log.Info("STa EAP answer received", "session_id", sessionID, "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "diameter_result_code", 2001, "eap_state", STaEAPStateSuccess, "allowed", true, "reason", "stub accepted", "command", "DEA")
	return &STaEAPResult{
		SessionID:  sessionID,
		ResultCode: 2001,
		State:      STaEAPStateSuccess,
		Allowed:    true,
		IMSI:       req.IMSI,
		MSISDN:     req.MSISDN,
		APN:        req.APN,
		Reason:     "stub accepted",
	}, nil
}

func (c *StubSTaClient) Status() STaStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}
