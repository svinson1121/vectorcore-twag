package accessside

import (
	"encoding/binary"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

func TestDHCPIgnoresUnauthorizedMAC(t *testing.T) {
	srv := testDHCPServer(session.NewManager(slog.New(slog.DiscardHandler)))
	frame := testDHCPClientFrame(t, dhcpDiscover, 0x1001, "f0:5c:77:e8:72:9e", nil)
	if got := srv.HandleFrame(frame); got != nil {
		t.Fatalf("unauthorized discover produced %d-byte reply", len(got))
	}
}

func TestDHCPOffersPGWAssignedIP(t *testing.T) {
	mgr := session.NewManager(slog.New(slog.DiscardHandler))
	addActiveSession(t, mgr, "f0:5c:77:e8:72:9e", "100.64.0.204")
	srv := testDHCPServer(mgr)
	reply := srv.HandleFrame(testDHCPClientFrame(t, dhcpDiscover, 0x1002, "f0:5c:77:e8:72:9e", nil))
	if len(reply) == 0 {
		t.Fatal("expected DHCP offer")
	}
	assertDHCPReply(t, reply, dhcpOffer, "100.64.0.204")
	opts := replyOptions(t, reply)
	if got := net.IP(opts[optRouter]).String(); got != "100.64.0.1" {
		t.Fatalf("router option = %s", got)
	}
	if got := binary.BigEndian.Uint32(opts[optLeaseTime]); got != 600 {
		t.Fatalf("lease time = %d", got)
	}
	if got := net.IP(opts[optServerIdentifier]).String(); got != "100.64.0.1" {
		t.Fatalf("server identifier = %s", got)
	}
	if got := len(opts[optDNSServer]); got != 8 {
		t.Fatalf("dns option len = %d", got)
	}
}

func TestDHCPRequestACK(t *testing.T) {
	mgr := session.NewManager(slog.New(slog.DiscardHandler))
	addActiveSession(t, mgr, "f0:5c:77:e8:72:9e", "100.64.0.204")
	srv := testDHCPServer(mgr)
	reply := srv.HandleFrame(testDHCPClientFrame(t, dhcpRequest, 0x1003, "f0:5c:77:e8:72:9e", net.ParseIP("100.64.0.204")))
	if len(reply) == 0 {
		t.Fatal("expected DHCP ack")
	}
	assertDHCPReply(t, reply, dhcpAck, "100.64.0.204")
	if lease, ok := srv.leases["f0:5c:77:e8:72:9e"]; !ok || lease.SubscriberIP.String() != "100.64.0.204" {
		t.Fatalf("lease = %#v, ok=%v", lease, ok)
	}
}

func TestDHCPRequestWrongIPNAK(t *testing.T) {
	mgr := session.NewManager(slog.New(slog.DiscardHandler))
	addActiveSession(t, mgr, "f0:5c:77:e8:72:9e", "100.64.0.204")
	srv := testDHCPServer(mgr)
	reply := srv.HandleFrame(testDHCPClientFrame(t, dhcpRequest, 0x1004, "f0:5c:77:e8:72:9e", net.ParseIP("100.64.0.99")))
	if len(reply) == 0 {
		t.Fatal("expected DHCP nak")
	}
	assertDHCPReply(t, reply, dhcpNak, "0.0.0.0")
}

func TestDHCPRequestOldIPDuringRecoveryNAKWhenConfigured(t *testing.T) {
	mgr := session.NewManager(slog.New(slog.DiscardHandler))
	old := addActiveSession(t, mgr, "f0:5c:77:e8:72:9e", "100.64.0.204")
	if _, ok := mgr.AddRecoveryTombstone(old, "test recovery", time.Minute); !ok {
		t.Fatal("expected recovery tombstone")
	}
	terminating, err := mgr.MarkTerminating(old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mgr.Delete(terminating.ID); !ok {
		t.Fatal("expected old session delete")
	}
	srv := testDHCPServer(mgr)
	srv.cfg.StaleRequestAction = "nak"
	reply := srv.HandleFrame(testDHCPClientFrame(t, dhcpRequest, 0x1005, "f0:5c:77:e8:72:9e", net.ParseIP("100.64.0.204")))
	if len(reply) == 0 {
		t.Fatal("expected DHCP nak")
	}
	assertDHCPReply(t, reply, dhcpNak, "0.0.0.0")
}

func TestDHCPDiscoverDuringRecoveryDoesNotOffer(t *testing.T) {
	mgr := session.NewManager(slog.New(slog.DiscardHandler))
	old := addActiveSession(t, mgr, "f0:5c:77:e8:72:9e", "100.64.0.204")
	if _, ok := mgr.AddRecoveryTombstone(old, "test recovery", time.Minute); !ok {
		t.Fatal("expected recovery tombstone")
	}
	terminating, err := mgr.MarkTerminating(old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mgr.Delete(terminating.ID); !ok {
		t.Fatal("expected old session delete")
	}
	srv := testDHCPServer(mgr)
	reply := srv.HandleFrame(testDHCPClientFrame(t, dhcpDiscover, 0x1006, "f0:5c:77:e8:72:9e", nil))
	if len(reply) != 0 {
		t.Fatalf("recovery discover produced %d-byte reply", len(reply))
	}
}

func testDHCPServer(mgr *session.Manager) *DHCPServer {
	srv := NewDHCPServer(config.DHCPConfig{
		Enabled:                  true,
		Interface:                "eth1",
		Mode:                     "proxy",
		RequireAuthorizedSession: true,
		LeaseTimeSeconds:         600,
		RenewalTimeSeconds:       300,
		RebindingTimeSeconds:     525,
		Netmask:                  "255.255.255.0",
		Router:                   "100.64.0.1",
		ServerIdentifier:         "100.64.0.1",
		DNS:                      []string{"8.8.8.8", "1.1.1.1"},
	}, mgr, slog.New(slog.DiscardHandler))
	srv.ifaceMAC = mustMAC("02:00:00:00:00:01")
	return srv
}

func addActiveSession(t *testing.T, mgr *session.Manager, mac, ip string) *session.Session {
	t.Helper()
	s := mgr.Create(session.CreateInput{IMSI: "311435000070571", MACAddress: mac, APN: "internet", AccessInterface: "eth1"})
	if _, err := mgr.MarkAuthPending(s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.ApplyAuthResult(s.ID, s.IMSI, "", s.APN, "accepted"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.MarkPGWPending(s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.UpdateSubscriberIP(s.ID, net.ParseIP(ip)); err != nil {
		t.Fatal(err)
	}
	active, err := mgr.MarkActive(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	return active
}

func testDHCPClientFrame(t *testing.T, msgType byte, xid uint32, mac string, requestedIP net.IP) []byte {
	t.Helper()
	hw := mustMAC(mac)
	payload := make([]byte, 240)
	payload[0] = bootRequest
	payload[1] = 1
	payload[2] = 6
	binary.BigEndian.PutUint32(payload[4:8], xid)
	copy(payload[28:34], hw)
	binary.BigEndian.PutUint32(payload[236:240], 0x63825363)
	payload = append(payload, optMessageType, 1, msgType)
	if requestedIP != nil {
		payload = append(payload, optRequestedIP, 4)
		payload = append(payload, requestedIP.To4()...)
	}
	payload = append(payload, optEnd)
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen
	frame := make([]byte, 14+ipLen)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], hw)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], net.IPv4zero.To4())
	copy(ip[16:20], net.IPv4bcast.To4())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 68)
	binary.BigEndian.PutUint16(udp[2:4], 67)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(frame[42:], payload)
	return frame
}

func assertDHCPReply(t *testing.T, frame []byte, wantType byte, wantIP string) {
	t.Helper()
	opts := replyOptions(t, frame)
	if got := opts[optMessageType]; len(got) != 1 || got[0] != wantType {
		t.Fatalf("message type = %v, want %d", got, wantType)
	}
	yiaddr := net.IP(frame[42+16 : 42+20]).String()
	if yiaddr != wantIP {
		t.Fatalf("yiaddr = %s, want %s", yiaddr, wantIP)
	}
}

func replyOptions(t *testing.T, frame []byte) map[byte][]byte {
	t.Helper()
	if len(frame) < 42+240 {
		t.Fatalf("short DHCP reply: %d", len(frame))
	}
	return parseOptions(frame[42+240:])
}

func mustMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}
