package accessside

import (
	"encoding/binary"
	"log/slog"
	"net"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

const (
	bootRequest  = 1
	bootReply    = 2
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpNak      = 6

	optSubnetMask       = 1
	optRouter           = 3
	optDNSServer        = 6
	optRequestedIP      = 50
	optLeaseTime        = 51
	optMessageType      = 53
	optServerIdentifier = 54
	optRenewalTime      = 58
	optRebindingTime    = 59
	optEnd              = 255
)

type DHCPServer struct {
	cfg      config.DHCPConfig
	sessions *session.Manager
	log      *slog.Logger
	ifaceMAC net.HardwareAddr
	conn     packetConn
	done     chan struct{}
	leases   map[string]Lease
}

type Lease struct {
	SessionID    string
	IMSI         string
	SubscriberIP net.IP
	ExpiresAt    time.Time
}

func NewDHCPServer(cfg config.DHCPConfig, sessions *session.Manager, log *slog.Logger) *DHCPServer {
	return &DHCPServer{cfg: cfg, sessions: sessions, log: log, leases: make(map[string]Lease)}
}

func (s *DHCPServer) Start() error {
	if !s.cfg.Enabled {
		return nil
	}
	conn, ifi, err := openPacketSocket(s.cfg.Interface, etherTypeIPv4)
	if err != nil {
		return err
	}
	s.conn = conn
	s.ifaceMAC = append(net.HardwareAddr(nil), ifi.HardwareAddr...)
	s.done = make(chan struct{})
	go runReader(s.done, s.conn, func(frame []byte) {
		if reply := s.HandleFrame(frame); len(reply) > 0 {
			_ = s.conn.WriteFrame(reply, ethernetSrc(frame))
		}
	})
	s.log.Info("DHCP access server started", "interface", s.cfg.Interface, "mode", s.cfg.Mode)
	return nil
}

func (s *DHCPServer) Stop() error {
	if s.done != nil {
		close(s.done)
	}
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *DHCPServer) RemoveSession(sess *session.Session) {
	if sess == nil || sess.MACAddress == "" {
		return
	}
	delete(s.leases, sess.MACAddress)
}

func (s *DHCPServer) HandleFrame(frame []byte) []byte {
	p, ok := parseDHCPFrame(frame)
	if !ok {
		return nil
	}
	sess, authorized := s.authorizedSession(p.ClientMAC)
	attrs := []any{"interface", s.cfg.Interface, "mac", p.ClientMAC.String(), "xid", p.XID, "authorized", authorized}
	if sess != nil {
		attrs = append(attrs, "session_id", sess.ID, "subscriber_ip", ipString(sess.SubscriberIP))
	}
	switch p.MessageType {
	case dhcpDiscover:
		s.log.Info("DHCP Discover received", attrs...)
		if !authorized {
			if tombstone, ok := s.sessions.LookupRecoveryByMACAddr(p.ClientMAC); ok {
				s.log.Info("DHCP discover from recovery client without active PGW session",
					"mac", p.ClientMAC.String(),
					"old_ip", ipString(tombstone.OldSubscriberIP),
					"old_session_id", tombstone.OldSessionID,
					"recovery_state", tombstone.State,
					"action", "wait_for_radius_reattach",
				)
				return nil
			}
			s.log.Info("DHCP ignored unauthorized client", "mac", p.ClientMAC.String())
			return nil
		}
		reply := s.buildReply(p, sess, dhcpOffer)
		s.log.Info("DHCP Offer sent", "mac", p.ClientMAC.String(), "offered_ip", sess.SubscriberIP.String(), "router", s.cfg.Router, "dns", s.cfg.DNS, "lease_time", s.cfg.LeaseTimeSeconds)
		return reply
	case dhcpRequest:
		attrs = append(attrs, "requested_ip", ipString(p.RequestedIP), "server_identifier", ipString(p.ServerIdentifier))
		s.log.Info("DHCP Request received", attrs...)
		if !authorized {
			requested := firstIP(p.RequestedIP, p.ClientIP)
			if tombstone, ok := s.sessions.LookupRecoveryByMACAddr(p.ClientMAC); ok {
				action := s.cfg.StaleRequestAction
				if action == "" {
					action = "ignore"
				}
				s.log.Info("stale DHCP request during session recovery",
					"mac", p.ClientMAC.String(),
					"old_ip", ipString(tombstone.OldSubscriberIP),
					"requested_ip", ipString(requested),
					"old_session_id", tombstone.OldSessionID,
					"recovery_state", tombstone.State,
					"action", action,
				)
				if action == "nak" {
					return s.buildNAK(p)
				}
				return nil
			}
			s.log.Info("DHCP ignored unauthorized client", "mac", p.ClientMAC.String())
			return nil
		}
		requested := firstIP(p.RequestedIP, p.ClientIP)
		if requested != nil && !requested.Equal(sess.SubscriberIP) {
			return s.buildNAK(p)
		}
		reply := s.buildReply(p, sess, dhcpAck)
		s.leases[p.ClientMAC.String()] = Lease{
			SessionID:    sess.ID,
			IMSI:         sess.IMSI,
			SubscriberIP: cloneIP(sess.SubscriberIP),
			ExpiresAt:    time.Now().UTC().Add(time.Duration(s.cfg.LeaseTimeSeconds) * time.Second),
		}
		s.log.Info("DHCP Ack sent", "mac", p.ClientMAC.String(), "assigned_ip", sess.SubscriberIP.String(), "session_id", sess.ID)
		return reply
	default:
		return nil
	}
}

func (s *DHCPServer) authorizedSession(mac net.HardwareAddr) (*session.Session, bool) {
	if !s.cfg.RequireAuthorizedSession {
		return &session.Session{SubscriberIP: net.ParseIP("0.0.0.0")}, true
	}
	sess, ok := s.sessions.LookupByMACAddr(mac)
	if !ok || sess.State != session.Active || sess.SubscriberIP == nil {
		return sess, false
	}
	return sess, true
}

func (s *DHCPServer) buildReply(req dhcpPacket, sess *session.Session, msgType byte) []byte {
	opts := []dhcpOption{
		{optMessageType, []byte{msgType}},
		{optSubnetMask, net.ParseIP(s.cfg.Netmask).To4()},
		{optRouter, net.ParseIP(s.cfg.Router).To4()},
		{optDNSServer, ipListBytes(s.cfg.DNS)},
		{optLeaseTime, u32(s.cfg.LeaseTimeSeconds)},
		{optServerIdentifier, net.ParseIP(s.cfg.ServerIdentifier).To4()},
		{optRenewalTime, u32(s.cfg.RenewalTimeSeconds)},
		{optRebindingTime, u32(s.cfg.RebindingTimeSeconds)},
	}
	return buildDHCPFrame(req, s.ifaceMAC, net.ParseIP(s.cfg.ServerIdentifier), sess.SubscriberIP.To4(), net.IPv4bcast, opts)
}

func (s *DHCPServer) buildNAK(req dhcpPacket) []byte {
	opts := []dhcpOption{
		{optMessageType, []byte{dhcpNak}},
		{optServerIdentifier, net.ParseIP(s.cfg.ServerIdentifier).To4()},
	}
	return buildDHCPFrame(req, s.ifaceMAC, net.ParseIP(s.cfg.ServerIdentifier), net.IPv4zero, net.IPv4bcast, opts)
}

type dhcpPacket struct {
	XID              uint32
	ClientMAC        net.HardwareAddr
	ClientIP         net.IP
	RequestedIP      net.IP
	ServerIdentifier net.IP
	MessageType      byte
}

type dhcpOption struct {
	code byte
	data []byte
}

func parseDHCPFrame(frame []byte) (dhcpPacket, bool) {
	var p dhcpPacket
	if len(frame) < 14+20+8+240 || binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv4 {
		return p, false
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl+8+240 || ip[9] != 17 {
		return p, false
	}
	udp := ip[ihl:]
	if binary.BigEndian.Uint16(udp[2:4]) != 67 {
		return p, false
	}
	d := udp[8:]
	if len(d) < 240 || d[0] != bootRequest || d[1] != 1 || d[2] != 6 {
		return p, false
	}
	p.XID = binary.BigEndian.Uint32(d[4:8])
	p.ClientIP = cloneIP(net.IP(d[12:16]))
	p.ClientMAC = append(net.HardwareAddr(nil), d[28:34]...)
	if binary.BigEndian.Uint32(d[236:240]) != 0x63825363 {
		return p, false
	}
	opts := parseOptions(d[240:])
	if mt := opts[optMessageType]; len(mt) == 1 {
		p.MessageType = mt[0]
	}
	if rip := opts[optRequestedIP]; len(rip) == 4 {
		p.RequestedIP = cloneIP(net.IP(rip))
	}
	if sid := opts[optServerIdentifier]; len(sid) == 4 {
		p.ServerIdentifier = cloneIP(net.IP(sid))
	}
	return p, p.MessageType != 0
}

func buildDHCPFrame(req dhcpPacket, srcMAC net.HardwareAddr, srcIP, yiaddr, dstIP net.IP, opts []dhcpOption) []byte {
	if len(srcMAC) != 6 {
		srcMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	}
	if srcIP == nil || srcIP.To4() == nil {
		srcIP = net.IPv4zero
	}
	payload := make([]byte, 240)
	payload[0] = bootReply
	payload[1] = 1
	payload[2] = 6
	binary.BigEndian.PutUint32(payload[4:8], req.XID)
	copy(payload[16:20], yiaddr.To4())
	copy(payload[28:34], req.ClientMAC)
	binary.BigEndian.PutUint32(payload[236:240], 0x63825363)
	for _, opt := range opts {
		if len(opt.data) == 0 {
			continue
		}
		payload = append(payload, opt.code, byte(len(opt.data)))
		payload = append(payload, opt.data...)
	}
	payload = append(payload, optEnd)
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen
	frame := make([]byte, 14+ipLen)
	copy(frame[0:6], req.ClientMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 67)
	binary.BigEndian.PutUint16(udp[2:4], 68)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(frame[42:], payload)
	return frame
}

func parseOptions(b []byte) map[byte][]byte {
	opts := make(map[byte][]byte)
	for i := 0; i < len(b); {
		code := b[i]
		i++
		if code == optEnd {
			break
		}
		if code == 0 {
			continue
		}
		if i >= len(b) {
			break
		}
		l := int(b[i])
		i++
		if i+l > len(b) {
			break
		}
		opts[code] = append([]byte(nil), b[i:i+l]...)
		i += l
	}
	return opts
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func ipListBytes(values []string) []byte {
	out := make([]byte, 0, len(values)*4)
	for _, value := range values {
		if ip := net.ParseIP(value).To4(); ip != nil {
			out = append(out, ip...)
		}
	}
	return out
}
