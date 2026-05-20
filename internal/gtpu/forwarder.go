package gtpu

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

const (
	portGTPU                  = 2152
	msgTypeEchoRequest        = 1
	msgTypeEchoResponse       = 2
	msgTypeErrorIndication    = 26
	msgTypeGTPU               = 255
	ieRecovery                = 14
	ieTunnelEndpointIDDataI   = 16
	headerLenGTPU             = 8
	headerLenGTPUWithSequence = 12
	maxUDPPacket              = 65535
	readWaitPeriod            = 500 * time.Millisecond
)

type Forwarder struct {
	log    *slog.Logger
	local  *net.UDPAddr
	remote *net.UDPAddr
	conn   *net.UDPConn

	mu          sync.RWMutex
	bySessionID map[string]*session.Session
	byLocalTEID map[uint32]*session.Session
	byIP        map[string]*session.Session

	errorHandler ErrorIndicationHandler
	stopOnce     sync.Once
}

type ErrorIndication struct {
	RemoteAddr    *net.UDPAddr
	OffendingTEID uint32
	RawPayload    []byte
}

type ErrorIndicationHandler func(context.Context, ErrorIndication)

type DecapsulatedPacket struct {
	Session *session.Session
	Payload []byte
	Peer    *net.UDPAddr
}

func (f *Forwarder) SetErrorIndicationHandler(handler ErrorIndicationHandler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errorHandler = handler
}

func NewForwarder(cfg config.PGWConfig, log *slog.Logger) (*Forwarder, error) {
	return newForwarder(cfg.LocalGTPUIP, cfg.RemotePGWGTPUIP, portGTPU, portGTPU, log)
}

func newForwarder(localIP, remoteIP string, localPort, remotePort int, log *slog.Logger) (*Forwarder, error) {
	localAddrIP := net.ParseIP(localIP)
	if localAddrIP == nil {
		return nil, fmt.Errorf("pgw.local_gtpu_ip is invalid")
	}
	remoteAddrIP := net.ParseIP(remoteIP)
	if remoteAddrIP == nil {
		return nil, fmt.Errorf("pgw.remote_pgw_gtpu_ip is invalid")
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localAddrIP, Port: localPort})
	if err != nil {
		return nil, fmt.Errorf("bind local GTP-U socket %s:%d: %w", localAddrIP.String(), localPort, err)
	}
	f := &Forwarder{
		log:         log,
		local:       conn.LocalAddr().(*net.UDPAddr),
		remote:      &net.UDPAddr{IP: remoteAddrIP, Port: remotePort},
		conn:        conn,
		bySessionID: make(map[string]*session.Session),
		byLocalTEID: make(map[uint32]*session.Session),
		byIP:        make(map[string]*session.Session),
	}
	log.Info("GTP-U forwarder initialized",
		"local_gtpu_ip", f.local.IP.String(),
		"local_gtpu_port", f.local.Port,
		"remote_pgw_gtpu_ip", f.remote.IP.String(),
		"remote_pgw_gtpu_port", f.remote.Port,
	)
	return f, nil
}

func (f *Forwarder) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	go f.readLoop(ctx)
	return nil
}

func (f *Forwarder) Stop() error {
	var err error
	f.stopOnce.Do(func() {
		err = f.conn.Close()
	})
	return err
}

func (f *Forwarder) AddSession(sess *session.Session) error {
	if sess == nil {
		return fmt.Errorf("session is required")
	}
	if sess.ID == "" {
		return fmt.Errorf("session id is required")
	}
	if sess.LocalGTPUTEID == 0 {
		return fmt.Errorf("session %s has no local GTP-U TEID", sess.ID)
	}
	if sess.RemoteGTPUTEID == 0 {
		return fmt.Errorf("session %s has no remote GTP-U TEID", sess.ID)
	}
	if sess.SubscriberIP == nil {
		return fmt.Errorf("session %s has no subscriber IP", sess.ID)
	}
	cp := cloneSession(sess)
	f.mu.Lock()
	defer f.mu.Unlock()
	if old := f.bySessionID[cp.ID]; old != nil {
		delete(f.byLocalTEID, old.LocalGTPUTEID)
		if old.SubscriberIP != nil {
			delete(f.byIP, old.SubscriberIP.String())
		}
	}
	f.bySessionID[cp.ID] = cp
	f.byLocalTEID[cp.LocalGTPUTEID] = cp
	f.byIP[cp.SubscriberIP.String()] = cp
	f.log.Info("GTP-U session bound",
		"session_id", cp.ID,
		"imsi", cp.IMSI,
		"subscriber_ip", cp.SubscriberIP.String(),
		"local_gtpu_teid", cp.LocalGTPUTEID,
		"remote_gtpu_teid", cp.RemoteGTPUTEID,
		"pgw_user_ip", ipString(cp.PGWUserIP),
	)
	return nil
}

func (f *Forwarder) RemoveSession(sessionID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sess := f.bySessionID[sessionID]
	if sess == nil {
		return
	}
	delete(f.bySessionID, sessionID)
	delete(f.byLocalTEID, sess.LocalGTPUTEID)
	if sess.SubscriberIP != nil {
		delete(f.byIP, sess.SubscriberIP.String())
	}
	f.log.Info("GTP-U session unbound", "session_id", sess.ID, "imsi", sess.IMSI, "subscriber_ip", ipString(sess.SubscriberIP))
}

func (f *Forwarder) SendUplinkPacket(ctx context.Context, sess *session.Session, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sess == nil {
		return fmt.Errorf("session is required")
	}
	if sess.RemoteGTPUTEID == 0 {
		return fmt.Errorf("session %s has no remote GTP-U TEID", sess.ID)
	}
	packet, err := EncodePacket(sess.RemoteGTPUTEID, payload)
	if err != nil {
		return err
	}
	remote := f.remoteForSession(sess)
	if deadline, ok := ctx.Deadline(); ok {
		_ = f.conn.SetWriteDeadline(deadline)
	} else {
		_ = f.conn.SetWriteDeadline(time.Time{})
	}
	if _, err := f.conn.WriteToUDP(packet, remote); err != nil {
		return fmt.Errorf("send GTP-U packet: %w", err)
	}
	f.log.Debug("GTP-U uplink packet sent",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"subscriber_ip", ipString(sess.SubscriberIP),
		"remote_gtpu_teid", sess.RemoteGTPUTEID,
		"payload_length", len(payload),
	)
	return nil
}

func (f *Forwarder) readLoop(ctx context.Context) {
	buf := make([]byte, maxUDPPacket)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		_ = f.conn.SetReadDeadline(time.Now().Add(readWaitPeriod))
		n, peer, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			f.log.Warn("GTP-U receive failed", "error", err)
			return
		}
		if f.handleControlPacket(ctx, buf[:n], peer) {
			continue
		}
		packet, err := f.Decapsulate(buf[:n], peer)
		if err != nil {
			f.log.Warn("GTP-U packet dropped", "peer", peer.String(), "reason", err.Error())
			continue
		}
		f.log.Debug("GTP-U downlink packet received",
			"session_id", packet.Session.ID,
			"imsi", packet.Session.IMSI,
			"subscriber_ip", ipString(packet.Session.SubscriberIP),
			"local_gtpu_teid", packet.Session.LocalGTPUTEID,
			"payload_length", len(packet.Payload),
		)
	}
}

func (f *Forwarder) handleControlPacket(ctx context.Context, packet []byte, peer *net.UDPAddr) bool {
	msg, err := DecodeControlPacket(packet)
	if err != nil {
		return false
	}
	if peer != nil && !peer.IP.Equal(f.remote.IP) {
		f.log.Warn("GTP-U control packet from unexpected peer ignored", "peer", peer.String(), "expected_peer", f.remote.String(), "message_type", msg.Type)
		return true
	}
	switch msg.Type {
	case msgTypeEchoRequest:
		f.log.Info("GTP-U echo request received", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence)
		resp, err := EncodeEchoResponse(msg.Sequence)
		if err != nil {
			f.log.Warn("GTP-U echo response encode failed", "sequence", msg.Sequence, "error", err)
			return true
		}
		if _, err := f.conn.WriteToUDP(resp, peer); err != nil {
			f.log.Warn("GTP-U echo response send failed", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence, "error", err)
			return true
		}
		f.log.Info("GTP-U echo response sent", "remote_ip", peer.IP.String(), "remote_port", peer.Port, "sequence", msg.Sequence)
		return true
	case msgTypeErrorIndication:
		ind := ErrorIndication{RemoteAddr: peer, OffendingTEID: msg.OffendingTEID, RawPayload: append([]byte(nil), msg.Payload...)}
		f.log.Warn("GTP-U Error Indication received",
			"remote_ip", peer.IP.String(),
			"remote_port", peer.Port,
			"offending_teid", fmt.Sprintf("0x%08x", ind.OffendingTEID),
			"raw_length", len(msg.Payload),
		)
		f.mu.RLock()
		handler := f.errorHandler
		f.mu.RUnlock()
		if handler != nil {
			go handler(ctx, ind)
		}
		return true
	default:
		return false
	}
}

func (f *Forwarder) Decapsulate(packet []byte, peer *net.UDPAddr) (*DecapsulatedPacket, error) {
	teid, payload, err := DecodePacket(packet)
	if err != nil {
		return nil, err
	}
	if peer != nil && !peer.IP.Equal(f.remote.IP) {
		return nil, fmt.Errorf("unexpected GTP-U peer %s want %s", peer.IP.String(), f.remote.IP.String())
	}
	f.mu.RLock()
	sess := cloneSession(f.byLocalTEID[teid])
	f.mu.RUnlock()
	if sess == nil {
		return nil, fmt.Errorf("unknown local GTP-U TEID %d", teid)
	}
	return &DecapsulatedPacket{Session: sess, Payload: payload, Peer: peer}, nil
}

type ControlMessage struct {
	Type          uint8
	TEID          uint32
	Sequence      uint16
	Payload       []byte
	OffendingTEID uint32
}

func DecodeControlPacket(packet []byte) (ControlMessage, error) {
	if len(packet) < headerLenGTPU {
		return ControlMessage{}, fmt.Errorf("GTP-U control packet truncated")
	}
	if packet[0]>>5 != 1 {
		return ControlMessage{}, fmt.Errorf("unsupported GTP-U version %d", packet[0]>>5)
	}
	msgType := packet[1]
	if msgType != msgTypeEchoRequest && msgType != msgTypeEchoResponse && msgType != msgTypeErrorIndication {
		return ControlMessage{}, fmt.Errorf("not a GTP-U control message type %d", msgType)
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if len(packet)-headerLenGTPU < length {
		return ControlMessage{}, fmt.Errorf("GTP-U control length %d exceeds remaining payload %d", length, len(packet)-headerLenGTPU)
	}
	msg := ControlMessage{
		Type: msgType,
		TEID: binary.BigEndian.Uint32(packet[4:8]),
	}
	payloadOffset := headerLenGTPU
	payloadEnd := headerLenGTPU + length
	if packet[0]&0x02 != 0 {
		if len(packet) < headerLenGTPUWithSequence || length < 4 {
			return ControlMessage{}, fmt.Errorf("GTP-U control packet sequence extension truncated")
		}
		msg.Sequence = binary.BigEndian.Uint16(packet[8:10])
		payloadOffset = headerLenGTPUWithSequence
	}
	if payloadOffset > payloadEnd {
		return ControlMessage{}, fmt.Errorf("GTP-U control payload offset exceeds length")
	}
	msg.Payload = append([]byte(nil), packet[payloadOffset:payloadEnd]...)
	msg.OffendingTEID = parseOffendingTEID(msg.Payload)
	return msg, nil
}

func EncodeEchoResponse(sequence uint16) ([]byte, error) {
	payload := []byte{ieRecovery, 1, 0}
	out := make([]byte, headerLenGTPUWithSequence+len(payload))
	out[0] = 0x32
	out[1] = msgTypeEchoResponse
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(payload)))
	binary.BigEndian.PutUint32(out[4:8], 0)
	binary.BigEndian.PutUint16(out[8:10], sequence)
	out[10] = 0
	out[11] = 0
	copy(out[12:], payload)
	return out, nil
}

func parseOffendingTEID(payload []byte) uint32 {
	for i := 0; i+2 <= len(payload); {
		typ := payload[i]
		switch typ {
		case ieTunnelEndpointIDDataI:
			if i+5 <= len(payload) {
				return binary.BigEndian.Uint32(payload[i+1 : i+5])
			}
			return 0
		case ieRecovery:
			i += 2
		default:
			if i+2 > len(payload) {
				return 0
			}
			// Many GTPv1 IEs used here are TV encoded; advance one byte when unknown
			// so a later TEID Data I IE can still be found in vendor variants.
			i++
		}
	}
	return 0
}

func EncodePacket(teid uint32, payload []byte) ([]byte, error) {
	if teid == 0 {
		return nil, fmt.Errorf("GTP-U TEID is required")
	}
	if len(payload) > maxUDPPacket-headerLenGTPU {
		return nil, fmt.Errorf("GTP-U payload too large: %d", len(payload))
	}
	out := make([]byte, headerLenGTPU+len(payload))
	out[0] = 0x30
	out[1] = msgTypeGTPU
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint32(out[4:8], teid)
	copy(out[8:], payload)
	return out, nil
}

func DecodePacket(packet []byte) (uint32, []byte, error) {
	if len(packet) < headerLenGTPU {
		return 0, nil, fmt.Errorf("GTP-U packet truncated")
	}
	if packet[0]>>5 != 1 {
		return 0, nil, fmt.Errorf("unsupported GTP-U version %d", packet[0]>>5)
	}
	if packet[1] != msgTypeGTPU {
		return 0, nil, fmt.Errorf("unsupported GTP-U message type %d", packet[1])
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if len(packet)-headerLenGTPU < length {
		return 0, nil, fmt.Errorf("GTP-U length %d exceeds remaining payload %d", length, len(packet)-headerLenGTPU)
	}
	teid := binary.BigEndian.Uint32(packet[4:8])
	if teid == 0 {
		return 0, nil, fmt.Errorf("GTP-U TEID is required")
	}
	payload := append([]byte(nil), packet[8:8+length]...)
	return teid, payload, nil
}

func (f *Forwarder) remoteForSession(sess *session.Session) *net.UDPAddr {
	if sess.PGWUserIP != nil {
		return &net.UDPAddr{IP: sess.PGWUserIP, Port: f.remote.Port}
	}
	return f.remote
}

func cloneSession(sess *session.Session) *session.Session {
	if sess == nil {
		return nil
	}
	cp := *sess
	cp.SubscriberIP = cloneIP(sess.SubscriberIP)
	cp.GatewayIP = cloneIP(sess.GatewayIP)
	cp.PGWControlIP = cloneIP(sess.PGWControlIP)
	cp.PGWUserIP = cloneIP(sess.PGWUserIP)
	return &cp
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
