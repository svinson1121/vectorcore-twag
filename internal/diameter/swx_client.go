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

type SWxClient interface {
	Start(ctx context.Context) error
	Stop() error
	Authenticate(ctx context.Context, req SWxAuthRequest) (*SWxAuthResult, error)
	Status() SWxStatus
}

type SWxAuthRequest struct {
	IMSI     string
	MSISDN   string
	Username string
	Realm    string
	APN      string
}

type SWxAuthResult struct {
	ResultCode uint32
	Allowed    bool
	IMSI       string
	MSISDN     string
	APN        string
	Reason     string
}

type SWxStatus struct {
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

type SWxDiameterClient struct {
	cfg config.SWxConfig
	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.RWMutex
	conn     net.Conn
	status   SWxStatus
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

func NewSWxClient(cfg config.SWxConfig, log *slog.Logger) *SWxDiameterClient {
	c := &SWxDiameterClient{
		cfg:              cfg,
		log:              log,
		pending:          make(map[uint32]chan diameterResponse),
		openedCh:         make(chan struct{}),
		watchdogInterval: defaultWatchdogInterval,
		watchdogTimeout:  defaultWatchdogTimeout,
		status: SWxStatus{
			PeerAddr: cfg.PeerAddr,
			State:    "initialized",
		},
	}
	c.nextHop.Store(uint32(time.Now().UnixNano()))
	c.nextEnd.Store(uint32(time.Now().Unix()))
	return c
}

func (c *SWxDiameterClient) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.cancel != nil {
		c.mu.Unlock()
		return c.waitOpen(ctx)
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.status.State = "starting"
	c.mu.Unlock()

	c.log.Info("Diameter SWx client initialized", "peer_addr", c.cfg.PeerAddr)
	go c.connectLoop()
	return c.waitOpen(ctx)
}

func (c *SWxDiameterClient) Stop() error {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.status.State = "stopped"
	c.failPendingLocked(errors.New("swx client stopped"))
	c.mu.Unlock()
	c.log.Info("Diameter SWx client stopped", "peer_addr", c.cfg.PeerAddr)
	return nil
}

func (c *SWxDiameterClient) Authenticate(ctx context.Context, req SWxAuthRequest) (*SWxAuthResult, error) {
	if req.IMSI == "" && req.Username == "" {
		return nil, fmt.Errorf("swx auth requires imsi or username")
	}
	if err := c.waitOpen(ctx); err != nil {
		return nil, err
	}
	sessionID := fmt.Sprintf("%s;%d", c.cfg.OriginHost, time.Now().UnixNano())
	userName := req.IMSI
	if userName == "" {
		userName = req.Username
	}
	msg := c.newRequest(commandSAR, c.cfg.AuthApplicationID, true, []avp{
		utf8AVP(avpSessionID, 0, sessionID),
		groupedAVP(avpVendorSpecificApplicationID, 0,
			uint32AVP(avpVendorID, 0, c.cfg.VendorID),
			uint32AVP(avpAuthApplicationID, 0, c.cfg.AuthApplicationID),
		),
		utf8AVP(avpOriginHost, 0, c.cfg.OriginHost),
		utf8AVP(avpOriginRealm, 0, c.cfg.OriginRealm),
		utf8AVP(avpDestinationRealm, 0, c.cfg.DestinationRealm),
		utf8AVP(avpUserName, 0, userName),
		uint32AVP(avpAuthSessionState, 0, 1),
		uint32AVP(avpServerAssignmentType, vendor3GPP, 1),
		utf8AVP(avpServiceSelection, vendor3GPP, req.APN),
	})
	if c.cfg.DestinationHost != "" {
		msg.AVPs = append(msg.AVPs, utf8AVP(avpDestinationHost, 0, c.cfg.DestinationHost))
	}
	c.log.Info("SWx server assignment request sent", "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "reason", "", "command", "SAR")
	answer, err := c.sendRequest(ctx, msg)
	if err != nil {
		return nil, err
	}
	resultCode, ok := avpUint32(answer.AVPs, avpResultCode, 0)
	if !ok {
		resultCode, ok = experimentalResultCode(answer.AVPs)
	}
	if !ok {
		resultCode = 0
	}
	allowed := resultCode == 2001 || resultCode == 2002
	c.mu.Lock()
	c.status.ResultCode = resultCode
	c.mu.Unlock()
	c.log.Info("SWx server assignment answer received", "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "diameter_result_code", resultCode, "allowed", allowed, "reason", resultReason(resultCode), "command", "SAA")
	return &SWxAuthResult{
		ResultCode: resultCode,
		Allowed:    allowed,
		IMSI:       req.IMSI,
		MSISDN:     req.MSISDN,
		APN:        req.APN,
		Reason:     resultReason(resultCode),
	}, nil
}

func (c *SWxDiameterClient) Status() SWxStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *SWxDiameterClient) connectLoop() {
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
		c.log.Info("connecting to HSS Diameter peer", "peer_addr", c.cfg.PeerAddr)
		dialer := net.Dialer{Timeout: 5 * time.Second}
		conn, err := dialer.DialContext(c.ctx, "tcp", c.cfg.PeerAddr)
		if err != nil {
			c.setStatus("disconnected", err.Error(), false)
			c.log.Warn("Diameter SWx peer connect failed", "peer_addr", c.cfg.PeerAddr, "error", err)
			c.sleep(backoff)
			backoff = minDuration(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if err := c.handshake(conn); err != nil {
			_ = conn.Close()
			c.setStatus("disconnected", err.Error(), false)
			c.log.Warn("Diameter SWx handshake failed", "peer_addr", c.cfg.PeerAddr, "error", err)
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

func (c *SWxDiameterClient) handshake(conn net.Conn) error {
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
		"swx_application_id", c.cfg.AuthApplicationID,
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

func (c *SWxDiameterClient) readLoop(conn net.Conn, errCh chan<- error) {
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

func (c *SWxDiameterClient) handleRequest(conn net.Conn, req message) {
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
	case commandPPR, commandRTR:
		c.log.Warn("SWx inbound request not implemented", "command_code", req.CommandCode, "user_name", avpString(req.AVPs, avpUserName, 0))
	default:
		c.log.Warn("Diameter inbound request ignored", "command_code", req.CommandCode)
	}
}

func (c *SWxDiameterClient) watchdogLoop(conn net.Conn) {
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

func (c *SWxDiameterClient) sendRequest(ctx context.Context, req message) (message, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return message{}, fmt.Errorf("Diameter peer is not open")
	}
	return c.sendRequestOnConn(ctx, conn, req)
}

func (c *SWxDiameterClient) sendRequestOnConn(ctx context.Context, conn net.Conn, req message) (message, error) {
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

func (c *SWxDiameterClient) newRequest(command, appID uint32, proxiable bool, avps []avp) message {
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

func (c *SWxDiameterClient) newAnswer(req message, avps []avp) message {
	return message{
		Flags:       req.Flags &^ flagRequest,
		CommandCode: req.CommandCode,
		AppID:       req.AppID,
		HopByHop:    req.HopByHop,
		EndToEnd:    req.EndToEnd,
		AVPs:        avps,
	}
}

func (c *SWxDiameterClient) waitOpen(ctx context.Context) error {
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

func (c *SWxDiameterClient) setStatus(state, lastErr string, cerComplete bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.State = state
	c.status.LastError = lastErr
	c.status.CERComplete = cerComplete
}

func (c *SWxDiameterClient) failPendingLocked(err error) {
	for hop, ch := range c.pending {
		delete(c.pending, hop)
		ch <- diameterResponse{err: err}
	}
}

func (c *SWxDiameterClient) sleep(d time.Duration) {
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

type StubSWxClient struct {
	cfg config.SWxConfig
	log *slog.Logger

	mu     sync.RWMutex
	status SWxStatus
}

func NewStubSWxClient(cfg config.SWxConfig, log *slog.Logger) *StubSWxClient {
	return &StubSWxClient{
		cfg: cfg,
		log: log,
		status: SWxStatus{
			PeerAddr: cfg.PeerAddr,
			State:    "initialized",
		},
	}
}

func (c *StubSWxClient) Start(_ context.Context) error {
	c.mu.Lock()
	c.status.State = "stub_ready"
	c.status.LastError = ""
	c.mu.Unlock()
	c.log.Info("Diameter SWx client initialized", "peer_addr", c.cfg.PeerAddr)
	c.log.Info("Diameter SWx stub ready", "peer_addr", c.cfg.PeerAddr)
	return nil
}

func (c *StubSWxClient) Stop() error {
	c.mu.Lock()
	c.status.State = "stopped"
	c.mu.Unlock()
	c.log.Info("Diameter SWx client stopped", "peer_addr", c.cfg.PeerAddr)
	return nil
}

func (c *StubSWxClient) Authenticate(_ context.Context, req SWxAuthRequest) (*SWxAuthResult, error) {
	if req.IMSI == "" && req.Username == "" {
		return nil, fmt.Errorf("swx auth requires imsi or username")
	}
	c.mu.Lock()
	c.status.ResultCode = 2001
	c.mu.Unlock()
	c.log.Info("SWx server assignment request sent", "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "reason", "", "command", "SAR")
	c.log.Info("SWx server assignment answer received", "imsi", req.IMSI, "msisdn", req.MSISDN, "apn", req.APN, "diameter_result_code", 2001, "allowed", true, "reason", "diameter success", "command", "SAA")
	return &SWxAuthResult{
		ResultCode: 2001,
		Allowed:    true,
		IMSI:       req.IMSI,
		MSISDN:     req.MSISDN,
		APN:        req.APN,
		Reason:     "stub accepted",
	}, nil
}

func (c *StubSWxClient) Status() SWxStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}
