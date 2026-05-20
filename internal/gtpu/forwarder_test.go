package gtpu

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/vectorcore/twag/internal/session"
)

func TestEncodeDecodePacket(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x14}
	packet, err := EncodePacket(0x01020304, payload)
	if err != nil {
		t.Fatalf("EncodePacket() error = %v", err)
	}
	wantHeader := []byte{0x30, 0xff, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(packet[:8], wantHeader) {
		t.Fatalf("header = % x, want % x", packet[:8], wantHeader)
	}
	teid, decoded, err := DecodePacket(packet)
	if err != nil {
		t.Fatalf("DecodePacket() error = %v", err)
	}
	if teid != 0x01020304 {
		t.Fatalf("teid = %#x, want 0x01020304", teid)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("payload = % x, want % x", decoded, payload)
	}
}

func TestForwarderSendUplinkPacket(t *testing.T) {
	remote, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen remote: %v", err)
	}
	defer remote.Close() //nolint:errcheck
	f, err := newForwarder("127.0.0.1", "127.0.0.1", 0, remote.LocalAddr().(*net.UDPAddr).Port, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newForwarder() error = %v", err)
	}
	defer f.Stop() //nolint:errcheck
	sess := &session.Session{
		ID:             "sess-1",
		IMSI:           "001010000000001",
		SubscriberIP:   net.ParseIP("100.64.0.10"),
		PGWUserIP:      net.ParseIP("127.0.0.1"),
		LocalGTPUTEID:  0x11111111,
		RemoteGTPUTEID: 0x22222222,
	}
	payload := []byte{0x45, 0x00, 0x00, 0x14}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.SendUplinkPacket(ctx, sess, payload); err != nil {
		t.Fatalf("SendUplinkPacket() error = %v", err)
	}
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1500)
	n, _, err := remote.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read remote: %v", err)
	}
	teid, decoded, err := DecodePacket(buf[:n])
	if err != nil {
		t.Fatalf("DecodePacket(sent) error = %v", err)
	}
	if teid != sess.RemoteGTPUTEID {
		t.Fatalf("sent teid = %#x, want %#x", teid, sess.RemoteGTPUTEID)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("sent payload = % x, want % x", decoded, payload)
	}
}

func TestForwarderDecapsulateByLocalTEID(t *testing.T) {
	f, err := newForwarder("127.0.0.1", "127.0.0.1", 0, 2152, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newForwarder() error = %v", err)
	}
	defer f.Stop() //nolint:errcheck
	sess := &session.Session{
		ID:             "sess-1",
		IMSI:           "001010000000001",
		SubscriberIP:   net.ParseIP("100.64.0.10"),
		LocalGTPUTEID:  0x11111111,
		RemoteGTPUTEID: 0x22222222,
	}
	if err := f.AddSession(sess); err != nil {
		t.Fatalf("AddSession() error = %v", err)
	}
	payload := []byte{0x45, 0x00, 0x00, 0x14}
	packet, err := EncodePacket(sess.LocalGTPUTEID, payload)
	if err != nil {
		t.Fatalf("EncodePacket() error = %v", err)
	}
	decoded, err := f.Decapsulate(packet, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2152})
	if err != nil {
		t.Fatalf("Decapsulate() error = %v", err)
	}
	if decoded.Session.ID != sess.ID {
		t.Fatalf("session id = %q, want %q", decoded.Session.ID, sess.ID)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("payload = % x, want % x", decoded.Payload, payload)
	}
}

func TestEncodeDecodeEchoResponse(t *testing.T) {
	packet, err := EncodeEchoResponse(0x1234)
	if err != nil {
		t.Fatalf("EncodeEchoResponse() error = %v", err)
	}
	msg, err := DecodeControlPacket(packet)
	if err != nil {
		t.Fatalf("DecodeControlPacket() error = %v", err)
	}
	if msg.Type != msgTypeEchoResponse || msg.Sequence != 0x1234 || msg.TEID != 0 {
		t.Fatalf("unexpected echo response %#v", msg)
	}
}

func TestEncodeDecodeEchoRequest(t *testing.T) {
	packet, err := EncodeEchoRequest(0x4321)
	if err != nil {
		t.Fatalf("EncodeEchoRequest() error = %v", err)
	}
	msg, err := DecodeControlPacket(packet)
	if err != nil {
		t.Fatalf("DecodeControlPacket() error = %v", err)
	}
	if msg.Type != msgTypeEchoRequest || msg.Sequence != 0x4321 || msg.TEID != 0 {
		t.Fatalf("unexpected echo request %#v", msg)
	}
	if len(msg.Payload) != 0 {
		t.Fatalf("echo request payload length = %d, want 0", len(msg.Payload))
	}
}

func TestDecodeErrorIndicationOffendingTEID(t *testing.T) {
	packet := make([]byte, headerLenGTPUWithSequence+5)
	packet[0] = 0x32
	packet[1] = msgTypeErrorIndication
	binary.BigEndian.PutUint16(packet[2:4], 9)
	binary.BigEndian.PutUint32(packet[4:8], 0)
	binary.BigEndian.PutUint16(packet[8:10], 1)
	packet[12] = ieTunnelEndpointIDDataI
	binary.BigEndian.PutUint32(packet[13:17], 0x8011e007)
	msg, err := DecodeControlPacket(packet)
	if err != nil {
		t.Fatalf("DecodeControlPacket() error = %v", err)
	}
	if msg.Type != msgTypeErrorIndication {
		t.Fatalf("message type = %d, want %d", msg.Type, msgTypeErrorIndication)
	}
	if msg.OffendingTEID != 0x8011e007 {
		t.Fatalf("offending TEID = %#x, want 0x8011e007", msg.OffendingTEID)
	}
}
