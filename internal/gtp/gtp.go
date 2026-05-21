package gtp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

const gtpControlPort = 2123

type PeerHealth string

const (
	PeerHealthUnknown   PeerHealth = "unknown"
	PeerHealthHealthy   PeerHealth = "healthy"
	PeerHealthUnhealthy PeerHealth = "unhealthy"
)

type GTPClient struct {
	cfg      config.PGWConfig
	echoCfg  config.GTPEchoConfig
	log      *slog.Logger
	local    *net.UDPAddr
	remote   *net.UDPAddr
	conn     *net.UDPConn
	writeMu  sync.Mutex
	seq      *gtpv2SequenceAllocator
	nextTEID atomic.Uint32

	txMu      sync.Mutex
	pending   map[uint32]*gtpcTransaction
	closeCh   chan struct{}
	closeOnce sync.Once
	readWG    sync.WaitGroup
	echoWG    sync.WaitGroup

	healthMu                sync.RWMutex
	peerHealth              PeerHealth
	consecutiveEchoFailures int
	lastEchoSuccess         time.Time
	lastEchoFailure         time.Time
	lastEchoLatency         time.Duration
	echoWatchdogStarted     atomic.Bool
	networkDeleteHandler    func(context.Context, uint32)
}

type CreateSessionResult struct {
	SubscriberIP   net.IP
	GatewayIP      net.IP
	PGWControlIP   net.IP
	PGWUserIP      net.IP
	GTPCTEID       uint32
	LocalGTPUTEID  uint32
	RemoteGTPUTEID uint32
}

type PeerHealthStatus struct {
	Health              PeerHealth
	ConsecutiveFailures int
	LastSuccess         time.Time
	LastFailure         time.Time
	LastLatency         time.Duration
}

type gtpcTransaction struct {
	sequence     uint32
	requestType  uint8
	expectedType uint8
	responseCh   chan gtpv2Message
	errCh        chan error
	description  string
}

func NewGTP(cfg config.PGWConfig, echoCfg config.GTPEchoConfig, log *slog.Logger) (*GTPClient, error) {
	echoCfg = normalizeEchoConfig(echoCfg, log)
	localIP := net.ParseIP(cfg.LocalGTPCIP)
	if localIP == nil {
		return nil, fmt.Errorf("pgw.local_gtpc_ip is invalid")
	}
	remoteIP := net.ParseIP(cfg.RemotePGWGTPCIP)
	if remoteIP == nil {
		return nil, fmt.Errorf("pgw.remote_pgw_gtpc_ip is invalid")
	}
	if _, err := chargingCharacteristicsValue(cfg.ChargingCharacteristics); err != nil {
		return nil, fmt.Errorf("pgw.charging_characteristics is invalid: %w", err)
	}
	local := &net.UDPAddr{IP: localIP, Port: gtpControlPort}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, fmt.Errorf("bind local GTP-C socket %s: %w", local.String(), err)
	}
	c := &GTPClient{
		cfg:        cfg,
		echoCfg:    echoCfg,
		log:        log,
		local:      conn.LocalAddr().(*net.UDPAddr),
		remote:     &net.UDPAddr{IP: remoteIP, Port: gtpControlPort},
		conn:       conn,
		seq:        newGTPv2SequenceAllocator(),
		pending:    make(map[uint32]*gtpcTransaction),
		closeCh:    make(chan struct{}),
		peerHealth: PeerHealthUnknown,
	}
	c.nextTEID.Store(uint32(time.Now().UnixNano()))
	log.Info("GTP-C PGW client initialized",
		"local_gtpc_ip", cfg.LocalGTPCIP,
		"local_gtpc_port", c.local.Port,
		"remote_pgw_gtpc_ip", cfg.RemotePGWGTPCIP,
		"remote_pgw_gtpc_port", gtpControlPort,
		"apn", cfg.APN,
	)
	c.readWG.Add(1)
	go func() {
		defer c.readWG.Done()
		c.readLoop()
	}()
	return c, nil
}

func (c *GTPClient) CreateSession(ctx context.Context, sess *session.Session) (*CreateSessionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, fmt.Errorf("session is required")
	}
	health := c.PeerHealth()
	if health.Health == PeerHealthUnhealthy {
		c.log.Warn("GTP-C Create Session attempted while peer unhealthy",
			"session_id", sess.ID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
			"consecutive_failures", health.ConsecutiveFailures,
		)
	}
	localGTPC := c.nextTEIDValue()
	localGTPU := c.nextTEIDValue()
	msg := gtpv2Message{
		Type:    gtpv2CreateSessionReq,
		HasTEID: true,
		TEID:    0,
		Payload: c.createSessionPayload(sess, localGTPC, localGTPU),
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
	resp, err := c.doTransaction(ctx, msg, gtpv2CreateSessionResp, "Create Session")
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

func normalizeEchoConfig(cfg config.GTPEchoConfig, log *slog.Logger) config.GTPEchoConfig {
	if cfg.IntervalSeconds == 0 {
		cfg.IntervalSeconds = config.MinGTPEchoIntervalSeconds
	} else if cfg.IntervalSeconds > 0 && cfg.IntervalSeconds < config.MinGTPEchoIntervalSeconds {
		if log != nil {
			log.Warn("GTP-C echo interval below minimum; clamping",
				"configured_interval_seconds", cfg.IntervalSeconds,
				"effective_interval_seconds", config.MinGTPEchoIntervalSeconds,
			)
		}
		cfg.IntervalSeconds = config.MinGTPEchoIntervalSeconds
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 5
	}
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 3
	}
	return cfg
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
		Type:    gtpv2DeleteSessionReq,
		HasTEID: true,
		TEID:    sess.GTPCTEID,
		Payload: uint8IE(ieEBI, 5).encode(),
	}
	c.log.Info("GTP-C Delete Session Request sent", "session_id", sess.ID, "imsi", sess.IMSI, "gtpc_teid", sess.GTPCTEID)
	resp, err := c.doTransaction(ctx, msg, gtpv2DeleteSessionResp, "Delete Session")
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
		return &GTPError{Operation: "GTP-C Delete Session", Cause: cause}
	}
	c.log.Info("GTP-C Delete Session Response received", "session_id", sess.ID, "imsi", sess.IMSI, "gtp_cause", cause)
	return nil
}

func (c *GTPClient) Type() string { return "gtp" }

func (c *GTPClient) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closeCh)
		if c.conn != nil {
			err = c.conn.Close()
		}
		c.failPending(fmt.Errorf("GTP-C client closed"))
		c.readWG.Wait()
		c.echoWG.Wait()
		c.log.Info("GTP-C client stopped",
			"local_gtpc_ip", c.local.IP.String(),
			"local_gtpc_port", c.local.Port,
			"remote_pgw_gtpc_ip", c.remote.IP.String(),
			"remote_pgw_gtpc_port", c.remote.Port,
		)
	})
	return err
}

func (c *GTPClient) Probe(ctx context.Context) error {
	c.log.Info("GTP-C echo request sent",
		"local_gtpc_ip", c.cfg.LocalGTPCIP,
		"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
		"remote_pgw_gtpc_port", c.remote.Port,
	)
	seq, latency, err := c.echo(ctx)
	if err != nil {
		c.recordEchoFailure(err)
		c.log.Warn("GTP-C echo failed",
			"local_gtpc_ip", c.cfg.LocalGTPCIP,
			"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
			"remote_pgw_gtpc_port", c.remote.Port,
			"error", err,
		)
		return err
	}
	c.recordEchoSuccess(seq, latency)
	c.log.Info("GTP-C echo response received",
		"local_gtpc_ip", c.cfg.LocalGTPCIP,
		"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
		"remote_pgw_gtpc_port", c.remote.Port,
	)
	return nil
}

func (c *GTPClient) Echo(ctx context.Context) error {
	seq, latency, err := c.echo(ctx)
	if err != nil {
		return err
	}
	c.recordEchoSuccess(seq, latency)
	return nil
}

func (c *GTPClient) StartEchoWatchdog(ctx context.Context) {
	if !c.echoCfg.Enabled {
		return
	}
	if !c.echoWatchdogStarted.CompareAndSwap(false, true) {
		return
	}
	c.echoWG.Add(1)
	go func() {
		defer c.echoWG.Done()
		c.runEchoWatchdog(ctx)
	}()
}

func (c *GTPClient) SetNetworkDeleteHandler(handler func(context.Context, uint32)) {
	c.networkDeleteHandler = handler
}

func (c *GTPClient) PeerHealth() PeerHealthStatus {
	c.healthMu.RLock()
	defer c.healthMu.RUnlock()
	return PeerHealthStatus{
		Health:              c.peerHealth,
		ConsecutiveFailures: c.consecutiveEchoFailures,
		LastSuccess:         c.lastEchoSuccess,
		LastFailure:         c.lastEchoFailure,
		LastLatency:         c.lastEchoLatency,
	}
}

func (c *GTPClient) runEchoWatchdog(ctx context.Context) {
	interval := time.Duration(c.echoCfg.IntervalSeconds) * time.Second
	timeout := time.Duration(c.echoCfg.TimeoutSeconds) * time.Second
	c.log.Info("GTP-C echo watchdog started",
		"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
		"remote_pgw_gtpc_port", c.remote.Port,
		"interval_seconds", c.echoCfg.IntervalSeconds,
		"timeout_seconds", c.echoCfg.TimeoutSeconds,
		"max_failures", c.echoCfg.MaxFailures,
	)
	defer func() {
		c.echoWatchdogStarted.Store(false)
		c.log.Info("GTP-C echo watchdog stopped",
			"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
			"remote_pgw_gtpc_port", c.remote.Port,
		)
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closeCh:
			return
		case <-ticker.C:
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			c.runEchoProbe(probeCtx)
			cancel()
		}
	}
}

func (c *GTPClient) runEchoProbe(ctx context.Context) {
	seq, latency, err := c.echo(ctx)
	if err != nil {
		failures, unhealthy := c.recordEchoFailure(err)
		c.log.Warn("GTP-C echo failed",
			"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
			"remote_pgw_gtpc_port", c.remote.Port,
			"error", err,
			"consecutive_failures", failures,
			"max_failures", c.echoCfg.MaxFailures,
		)
		if unhealthy {
			c.log.Warn("GTP-C peer marked unhealthy",
				"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
				"remote_pgw_gtpc_port", c.remote.Port,
				"consecutive_failures", failures,
			)
		}
		return
	}
	_, recovered := c.recordEchoSuccess(seq, latency)
	attrs := []any{
		"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
		"remote_pgw_gtpc_port", c.remote.Port,
		"sequence", seq,
		"latency_ms", latency.Milliseconds(),
		"consecutive_failures", 0,
	}
	if recovered {
		c.log.Info("GTP-C peer recovered", append(attrs, "previous_health", PeerHealthUnhealthy)...)
		return
	}
	c.log.Debug("GTP-C echo response received", attrs...)
}

func (c *GTPClient) echo(ctx context.Context) (uint32, time.Duration, error) {
	start := time.Now()
	resp, err := c.doTransaction(ctx, gtpv2Message{
		Type:    gtpv2EchoRequest,
		Payload: recoveryIE(0).encode(),
	}, gtpv2EchoResponse, "Echo")
	if err != nil {
		return 0, 0, err
	}
	if resp.Type != gtpv2EchoResponse {
		return resp.Sequence, 0, fmt.Errorf("expected GTPv2 Echo Response, got message type %d", resp.Type)
	}
	c.log.Debug("GTP-C echo response decoded", "remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP, "sequence", resp.Sequence)
	return resp.Sequence, time.Since(start), nil
}

func (c *GTPClient) recordEchoSuccess(seq uint32, latency time.Duration) (PeerHealth, bool) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	previous := c.peerHealth
	c.peerHealth = PeerHealthHealthy
	c.consecutiveEchoFailures = 0
	c.lastEchoSuccess = time.Now()
	c.lastEchoLatency = latency
	if previous == PeerHealthUnknown {
		c.log.Info("GTP-C peer marked healthy",
			"remote_pgw_gtpc_ip", c.cfg.RemotePGWGTPCIP,
			"remote_pgw_gtpc_port", c.remote.Port,
			"sequence", seq,
			"latency_ms", latency.Milliseconds(),
		)
	}
	return previous, previous == PeerHealthUnhealthy
}

func (c *GTPClient) recordEchoFailure(err error) (int, bool) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.consecutiveEchoFailures++
	c.lastEchoFailure = time.Now()
	if c.consecutiveEchoFailures >= c.echoCfg.MaxFailures && c.peerHealth != PeerHealthUnhealthy {
		c.peerHealth = PeerHealthUnhealthy
		return c.consecutiveEchoFailures, true
	}
	return c.consecutiveEchoFailures, false
}

func (c *GTPClient) doTransaction(ctx context.Context, req gtpv2Message, expectedType uint8, description string) (gtpv2Message, error) {
	if err := ctx.Err(); err != nil {
		return gtpv2Message{}, err
	}
	req.Sequence = c.nextSequence()
	tx := &gtpcTransaction{
		sequence:     req.Sequence,
		requestType:  req.Type,
		expectedType: expectedType,
		responseCh:   make(chan gtpv2Message, 1),
		errCh:        make(chan error, 1),
		description:  description,
	}
	if err := c.registerTransaction(tx); err != nil {
		return gtpv2Message{}, err
	}
	defer c.unregisterTransaction(req.Sequence)

	encoded, err := req.encode()
	if err != nil {
		return gtpv2Message{}, err
	}
	c.logGTPv2Tx(req, encoded)
	c.writeMu.Lock()
	if _, err := c.conn.WriteToUDP(encoded, c.remote); err != nil {
		c.writeMu.Unlock()
		return gtpv2Message{}, fmt.Errorf("send GTP-C message: %w", err)
	}
	c.writeMu.Unlock()

	select {
	case resp := <-tx.responseCh:
		return resp, nil
	case err := <-tx.errCh:
		return gtpv2Message{}, err
	case <-ctx.Done():
		err := c.transactionContextError(ctx, tx)
		c.log.Warn("GTP-C transaction timeout",
			"operation", tx.description,
			"expected_message_type", tx.expectedType,
			"sequence_number_hex", fmt.Sprintf("0x%06x", tx.sequence),
			"sequence_number_decimal", tx.sequence,
			"error", err,
		)
		return gtpv2Message{}, err
	}
}

func (c *GTPClient) nextSequence() uint32 {
	return c.seq.next()
}

func (c *GTPClient) registerTransaction(tx *gtpcTransaction) error {
	c.txMu.Lock()
	defer c.txMu.Unlock()
	select {
	case <-c.closeCh:
		return fmt.Errorf("GTP-C client closed")
	default:
	}
	if _, exists := c.pending[tx.sequence]; exists {
		return fmt.Errorf("duplicate GTP-C sequence %d", tx.sequence)
	}
	c.pending[tx.sequence] = tx
	return nil
}

func (c *GTPClient) unregisterTransaction(sequence uint32) {
	c.txMu.Lock()
	delete(c.pending, sequence)
	c.txMu.Unlock()
}

func (c *GTPClient) failPending(err error) {
	c.txMu.Lock()
	defer c.txMu.Unlock()
	for sequence, tx := range c.pending {
		select {
		case tx.errCh <- err:
		default:
		}
		delete(c.pending, sequence)
	}
}

func (c *GTPClient) transactionContextError(ctx context.Context, tx *gtpcTransaction) error {
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s timeout waiting for response sequence %d", tx.description, tx.sequence)
	}
	return fmt.Errorf("%s canceled waiting for response sequence %d: %w", tx.description, tx.sequence, ctx.Err())
}

func (c *GTPClient) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, peer, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.closeCh:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Warn("GTP-C receive failed", "error", err)
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		c.handleIncomingGTPv2(packet, peer)
	}
}

func (c *GTPClient) handleIncomingGTPv2(packet []byte, peer *net.UDPAddr) {
	if !peer.IP.Equal(c.remote.IP) || peer.Port != c.remote.Port {
		c.log.Warn("GTP-C packet from unexpected peer ignored", "peer", peer.String(), "expected_peer", c.remote.String())
		return
	}
	msg, err := decodeGTPv2Message(packet)
	if err != nil {
		c.log.Warn("GTP-C decode failed", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "error", err)
		return
	}
	if msg.Type == gtpv2EchoRequest {
		c.handleInboundEchoRequest(msg, peer)
		return
	}
	if msg.Type == gtpv2DeleteSessionReq {
		c.handleInboundDeleteSessionRequest(msg, peer)
		return
	}

	tx, pendingCount, pendingSeq, pendingOp := c.lookupTransaction(msg.Sequence)
	if tx == nil {
		c.logGTPv2Rx(msg, peer, "")
		attrs := []any{
			"message_type", msg.Type,
			"sequence_number_hex", fmt.Sprintf("0x%06x", msg.Sequence),
			"sequence_number_decimal", msg.Sequence,
			"teid_flag", msg.HasTEID,
			"teid_value", fmt.Sprintf("0x%08x", msg.TEID),
			"pending_transactions", pendingCount,
		}
		if pendingSeq != 0 {
			attrs = append(attrs, "pending_sequence", pendingSeq, "pending_operation", pendingOp)
		}
		c.log.Debug("GTP-C unmatched response ignored", attrs...)
		return
	}
	c.logGTPv2Rx(msg, peer, tx.description)
	if msg.Type != tx.expectedType {
		err := fmt.Errorf("%s response type mismatch for sequence %d: got %d want %d", tx.description, msg.Sequence, msg.Type, tx.expectedType)
		c.log.Warn("GTP-C response type mismatch",
			"operation", tx.description,
			"sequence_number_hex", fmt.Sprintf("0x%06x", msg.Sequence),
			"sequence_number_decimal", msg.Sequence,
			"got_type", msg.Type,
			"expected_type", tx.expectedType,
		)
		select {
		case tx.errCh <- err:
		default:
		}
		return
	}
	select {
	case tx.responseCh <- msg:
	default:
		c.log.Warn("GTP-C transaction response channel full",
			"operation", tx.description,
			"sequence_number_decimal", msg.Sequence,
			"message_type", msg.Type,
		)
	}
}

func (c *GTPClient) handleInboundEchoRequest(msg gtpv2Message, peer *net.UDPAddr) {
	c.log.Info("GTP-C echo request received",
		"remote_ip", peer.IP.String(),
		"remote_port", peer.Port,
		"sequence", msg.Sequence,
	)
	resp := gtpv2Message{
		Type:     gtpv2EchoResponse,
		Sequence: msg.Sequence,
		Payload:  recoveryIE(0).encode(),
	}
	encoded, err := resp.encode()
	if err != nil {
		c.log.Warn("GTP-C echo response encode failed", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence, "error", err)
		return
	}
	c.writeMu.Lock()
	_, err = c.conn.WriteToUDP(encoded, peer)
	c.writeMu.Unlock()
	if err != nil {
		c.log.Warn("GTP-C echo response send failed", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence, "error", err)
		return
	}
	c.log.Info("GTP-C echo response sent",
		"remote_ip", peer.IP.String(),
		"remote_port", peer.Port,
		"sequence", msg.Sequence,
	)
}

func (c *GTPClient) handleInboundDeleteSessionRequest(msg gtpv2Message, peer *net.UDPAddr) {
	c.log.Warn("PGW-initiated bearer/session deletion received",
		"remote_ip", peer.IP.String(),
		"remote_port", peer.Port,
		"gtpc_teid", msg.TEID,
		"action", "cleanup_and_radius_disconnect",
	)
	resp := gtpv2Message{
		Type:     gtpv2DeleteSessionResp,
		HasTEID:  true,
		TEID:     msg.TEID,
		Sequence: msg.Sequence,
		Payload:  gtpv2IE{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}}.encode(),
	}
	encoded, err := resp.encode()
	if err != nil {
		c.log.Warn("GTP-C Delete Session Response encode failed", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence, "error", err)
		return
	}
	if _, err := c.conn.WriteToUDP(encoded, peer); err != nil {
		c.log.Warn("GTP-C Delete Session Response send failed", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence, "error", err)
		return
	}
	if c.networkDeleteHandler != nil {
		go c.networkDeleteHandler(context.Background(), msg.TEID)
	}
}

func (c *GTPClient) lookupTransaction(sequence uint32) (*gtpcTransaction, int, uint32, string) {
	c.txMu.Lock()
	defer c.txMu.Unlock()
	tx := c.pending[sequence]
	pendingCount := len(c.pending)
	var pendingSeq uint32
	var pendingOp string
	for seq, pending := range c.pending {
		pendingSeq = seq
		pendingOp = pending.description
		break
	}
	return tx, pendingCount, pendingSeq, pendingOp
}

func (c *GTPClient) logGTPv2Tx(req gtpv2Message, encoded []byte) {
	headerLen := 8
	if req.HasTEID {
		headerLen = 12
	}
	headerSample := encoded
	if len(headerSample) > 16 {
		headerSample = headerSample[:16]
	}
	c.log.Debug("GTPv2-C message transmit",
		"local_ip", c.local.IP.String(),
		"local_port", c.local.Port,
		"remote_ip", c.remote.IP.String(),
		"remote_port", c.remote.Port,
		"message_type", req.Type,
		"teid_flag", req.HasTEID,
		"teid_value", fmt.Sprintf("0x%08x", req.TEID),
		"sequence_number_hex", fmt.Sprintf("0x%06x", req.Sequence),
		"sequence_number_decimal", req.Sequence,
		"packet_length", len(encoded),
		"header_length", headerLen,
		"length_field", int(binary.BigEndian.Uint16(encoded[2:4])),
		"first_16_bytes_hex", fmt.Sprintf("%x", headerSample),
	)
}

func (c *GTPClient) logGTPv2Rx(msg gtpv2Message, peer *net.UDPAddr, operation string) {
	headerLen := 8
	if msg.HasTEID {
		headerLen = 12
	}
	attrs := []any{
		"local_ip", c.local.IP.String(),
		"local_port", c.local.Port,
		"remote_ip", peer.IP.String(),
		"remote_port", peer.Port,
		"message_type", msg.Type,
		"teid_flag", msg.HasTEID,
		"teid_value", fmt.Sprintf("0x%08x", msg.TEID),
		"sequence_number_hex", fmt.Sprintf("0x%06x", msg.Sequence),
		"sequence_number_decimal", msg.Sequence,
		"packet_length", headerLen + len(msg.Payload),
		"header_length", headerLen,
	}
	if operation != "" {
		attrs = append(attrs, "matched_operation", operation)
	}
	c.log.Debug("GTPv2-C message received", attrs...)
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
	chargingChars, err := chargingCharacteristicsValue(c.cfg.ChargingCharacteristics)
	if err != nil {
		chargingChars = defaultChargingCharacteristics
	}
	ies := []gtpv2IE{
		bcdIE(ieIMSI, sess.IMSI),
		recoveryIE(0),
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
		paaIE(net.IPv4zero),
		uint8IE(ieAPNRestriction, 0),
		ambrIE(0, 0),
		chargingCharacteristicsIE(0, chargingChars),
		gtpv2IE{Type: ieBearerContext, Payload: encodeIEs(
			uint8IE(ieEBI, 5),
			fteidIE(6, ifaceS2aTWANGTPU, localGTPU, localGTPUIP),
			bearerQoSIE(9),
		)},
	)
	if sess.MSISDN != "" {
		ies = append(ies, bcdIE(ieMSISDN, sess.MSISDN))
	}
	return encodeIEs(ies...)
}

func chargingCharacteristicsValue(value string) (uint16, error) {
	if value == "" {
		return defaultChargingCharacteristics, nil
	}
	return parseChargingCharacteristicsHex(value)
}

func (c *GTPClient) parseCreateSessionResponse(resp gtpv2Message, localGTPU uint32) (*CreateSessionResult, uint8, error) {
	ies, err := decodeIEs(resp.Payload)
	if err != nil {
		return nil, 0, err
	}
	cause := parseCauseInfo(ies)
	if cause.Cause != causeRequestAccepted {
		if cause.OffendingIEType != 0 {
			return nil, cause.Cause, &GTPError{
				Operation: "GTP-C Create Session",
				Cause:     cause.Cause,
				Message:   fmt.Sprintf("offending_ie_type=%d offending_ie_instance=%d offending_ie_length=%d", cause.OffendingIEType, cause.OffendingIEInstance, cause.OffendingIELength),
			}
		}
		return nil, cause.Cause, &GTPError{Operation: "GTP-C Create Session", Cause: cause.Cause}
	}
	result := &CreateSessionResult{
		SubscriberIP:  parsePAA(ies),
		PGWControlIP:  net.ParseIP(c.cfg.RemotePGWGTPCIP),
		PGWUserIP:     net.ParseIP(c.cfg.RemotePGWGTPUIP),
		LocalGTPUTEID: localGTPU,
	}
	if iface, teid, ip, ok := findFTEIDByInterface(ies, ifaceS2aPGWGTPC, 1, 0); ok {
		if iface != ifaceS2aPGWGTPC {
			c.log.Debug("GTP-C Create Session Response control F-TEID interface type", "interface_type", iface)
		}
		result.GTPCTEID = teid
		if ip != nil {
			result.PGWControlIP = ip
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
		if iface, teid, ip, ok := findFTEIDByInterface(children, ifaceS2aPGWGTPU, 5, 2); ok {
			if iface != ifaceS2aPGWGTPU {
				c.log.Debug("GTP-C Create Session Response bearer F-TEID interface type", "interface_type", iface)
			}
			result.RemoteGTPUTEID = teid
			if ip != nil {
				result.PGWUserIP = ip
			}
		}
	}
	return result, cause.Cause, nil
}

func findFTEIDByInterface(ies []gtpv2IE, wantIface uint8, fallbackInstances ...uint8) (uint8, uint32, net.IP, bool) {
	for _, ie := range ies {
		if ie.Type != ieFTEID {
			continue
		}
		iface, teid, ip, ok := parseFTEID(ie)
		if ok && iface == wantIface {
			return iface, teid, ip, true
		}
	}
	for _, instance := range fallbackInstances {
		ie, ok := findIE(ies, ieFTEID, instance)
		if !ok {
			continue
		}
		iface, teid, ip, parsed := parseFTEID(ie)
		if parsed {
			return iface, teid, ip, true
		}
	}
	return 0, 0, nil, false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
