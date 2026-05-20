package accessside

import (
	"encoding/binary"
	"log/slog"
	"net"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

type ARPProxy struct {
	cfg      config.ARPProxyConfig
	sessions *session.Manager
	log      *slog.Logger
	ifaceMAC net.HardwareAddr
	conn     packetConn
	done     chan struct{}
}

func NewARPProxy(cfg config.ARPProxyConfig, sessions *session.Manager, log *slog.Logger) *ARPProxy {
	return &ARPProxy{cfg: cfg, sessions: sessions, log: log}
}

func (p *ARPProxy) Start() error {
	if !p.cfg.Enabled {
		return nil
	}
	conn, ifi, err := openPacketSocket(p.cfg.Interface, etherTypeARP)
	if err != nil {
		return err
	}
	p.conn = conn
	p.ifaceMAC = append(net.HardwareAddr(nil), ifi.HardwareAddr...)
	p.done = make(chan struct{})
	go runReader(p.done, p.conn, func(frame []byte) {
		if reply := p.HandleFrame(frame); len(reply) > 0 {
			_ = p.conn.WriteFrame(reply, ethernetSrc(frame))
		}
	})
	p.log.Info("ARP proxy started", "interface", p.cfg.Interface, "gateway_ip", p.cfg.GatewayIP)
	return nil
}

func (p *ARPProxy) Stop() error {
	if p.done != nil {
		close(p.done)
	}
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

func (p *ARPProxy) HandleFrame(frame []byte) []byte {
	req, ok := parseARPRequest(frame)
	if !ok {
		return nil
	}
	gateway := net.ParseIP(p.cfg.GatewayIP).To4()
	if gateway == nil || !req.TargetIP.Equal(gateway) {
		return nil
	}
	sess, authorized := p.authorizedSession(req.SenderMAC, req.SenderIP)
	attrs := []any{"mac", req.SenderMAC.String(), "sender_ip", req.SenderIP.String(), "target_ip", req.TargetIP.String(), "authorized", authorized}
	if sess != nil {
		attrs = append(attrs, "session_id", sess.ID)
	}
	p.log.Info("ARP request received", attrs...)
	if !authorized {
		if tombstone, ok := p.sessions.LookupRecoveryByMACAddr(req.SenderMAC); ok {
			p.log.Info("stale ARP during session recovery",
				"mac", req.SenderMAC.String(),
				"sender_ip", req.SenderIP.String(),
				"target_ip", req.TargetIP.String(),
				"old_session_id", tombstone.OldSessionID,
				"action", "no_reply",
			)
		}
		return nil
	}
	reply := buildARPReply(req, p.ifaceMAC, gateway)
	p.log.Info("ARP proxy reply sent", "gateway_ip", gateway.String(), "mac", req.SenderMAC.String(), "subscriber_ip", req.SenderIP.String(), "interface", p.cfg.Interface)
	return reply
}

func (p *ARPProxy) authorizedSession(mac net.HardwareAddr, senderIP net.IP) (*session.Session, bool) {
	if !p.cfg.RequireAuthorizedSession {
		return &session.Session{}, true
	}
	sess, ok := p.sessions.LookupByMACAddr(mac)
	if !ok || sess.State != session.Active || sess.SubscriberIP == nil {
		return sess, false
	}
	if senderIP != nil && !senderIP.Equal(net.IPv4zero) && !senderIP.Equal(sess.SubscriberIP) {
		return sess, false
	}
	return sess, true
}

type arpRequest struct {
	SenderMAC net.HardwareAddr
	SenderIP  net.IP
	TargetIP  net.IP
}

func parseARPRequest(frame []byte) (arpRequest, bool) {
	var req arpRequest
	if len(frame) < 42 || binary.BigEndian.Uint16(frame[12:14]) != etherTypeARP {
		return req, false
	}
	arp := frame[14:42]
	if binary.BigEndian.Uint16(arp[0:2]) != 1 || binary.BigEndian.Uint16(arp[2:4]) != etherTypeIPv4 || arp[4] != 6 || arp[5] != 4 || binary.BigEndian.Uint16(arp[6:8]) != 1 {
		return req, false
	}
	req.SenderMAC = append(net.HardwareAddr(nil), arp[8:14]...)
	req.SenderIP = cloneIP(net.IP(arp[14:18]))
	req.TargetIP = cloneIP(net.IP(arp[24:28]))
	return req, true
}

func buildARPReply(req arpRequest, srcMAC net.HardwareAddr, gateway net.IP) []byte {
	frame := make([]byte, 42)
	copy(frame[0:6], req.SenderMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)
	arp := frame[14:42]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], etherTypeIPv4)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 2)
	copy(arp[8:14], srcMAC)
	copy(arp[14:18], gateway.To4())
	copy(arp[18:24], req.SenderMAC)
	copy(arp[24:28], req.SenderIP.To4())
	return frame
}
