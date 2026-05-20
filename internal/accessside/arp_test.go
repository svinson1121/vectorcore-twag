package accessside

import (
	"encoding/binary"
	"log/slog"
	"net"
	"testing"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
)

func TestARPProxyAuthorized(t *testing.T) {
	mgr := session.NewManager(slog.New(slog.DiscardHandler))
	addActiveSession(t, mgr, "f0:5c:77:e8:72:9e", "100.64.0.204")
	proxy := testARPProxy(mgr)
	reply := proxy.HandleFrame(testARPRequest("f0:5c:77:e8:72:9e", "100.64.0.204", "100.64.0.1"))
	if len(reply) == 0 {
		t.Fatal("expected ARP reply")
	}
	if got := net.HardwareAddr(reply[6:12]).String(); got != "02:00:00:00:00:01" {
		t.Fatalf("reply source mac = %s", got)
	}
	if got := net.IP(reply[14+14 : 14+18]).String(); got != "100.64.0.1" {
		t.Fatalf("sender protocol ip = %s", got)
	}
	if op := binary.BigEndian.Uint16(reply[20:22]); op != 2 {
		t.Fatalf("arp op = %d, want 2", op)
	}
}

func TestARPProxyUnauthorized(t *testing.T) {
	proxy := testARPProxy(session.NewManager(slog.New(slog.DiscardHandler)))
	reply := proxy.HandleFrame(testARPRequest("f0:5c:77:e8:72:9e", "100.64.0.204", "100.64.0.1"))
	if len(reply) != 0 {
		t.Fatalf("unauthorized ARP produced %d-byte reply", len(reply))
	}
}

func testARPProxy(mgr *session.Manager) *ARPProxy {
	proxy := NewARPProxy(config.ARPProxyConfig{
		Enabled:                  true,
		Interface:                "eth1",
		GatewayIP:                "100.64.0.1",
		RequireAuthorizedSession: true,
	}, mgr, slog.New(slog.DiscardHandler))
	proxy.ifaceMAC = mustMAC("02:00:00:00:00:01")
	return proxy
}

func testARPRequest(mac, senderIP, targetIP string) []byte {
	hw := mustMAC(mac)
	frame := make([]byte, 42)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], hw)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)
	arp := frame[14:42]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], etherTypeIPv4)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], hw)
	copy(arp[14:18], net.ParseIP(senderIP).To4())
	copy(arp[24:28], net.ParseIP(targetIP).To4())
	return frame
}
