package pgw

import (
	"encoding/binary"
	"fmt"
)

const (
	gtpv2VersionFlag       byte  = 0x40
	gtpv2TEIDFlag          byte  = 0x08
	gtpv2EchoRequest       uint8 = 1
	gtpv2EchoResponse      uint8 = 2
	gtpv2CreateSessionReq  uint8 = 32
	gtpv2CreateSessionResp uint8 = 33
	gtpv2DeleteSessionReq  uint8 = 36
	gtpv2DeleteSessionResp uint8 = 37
)

type gtpv2Message struct {
	Type     uint8
	TEID     uint32
	HasTEID  bool
	Sequence uint32
	Payload  []byte
}

func (m gtpv2Message) encode() ([]byte, error) {
	if m.Sequence > 0x00ffffff {
		return nil, fmt.Errorf("gtpv2 sequence %d exceeds 24 bits", m.Sequence)
	}
	headerLen := 8
	flags := gtpv2VersionFlag
	if m.HasTEID {
		flags |= gtpv2TEIDFlag
		headerLen = 12
	}
	length := headerLen - 4 + len(m.Payload)
	if length > 0xffff {
		return nil, fmt.Errorf("gtpv2 message too large: %d", length)
	}
	out := make([]byte, headerLen+len(m.Payload))
	out[0] = flags
	out[1] = m.Type
	binary.BigEndian.PutUint16(out[2:4], uint16(length))
	offset := 4
	if m.HasTEID {
		binary.BigEndian.PutUint32(out[offset:offset+4], m.TEID)
		offset += 4
	}
	put24(out[offset:offset+3], m.Sequence)
	offset += 4
	copy(out[offset:], m.Payload)
	return out, nil
}

func decodeGTPv2Message(b []byte) (gtpv2Message, error) {
	if len(b) < 8 {
		return gtpv2Message{}, fmt.Errorf("gtpv2 message too short: %d", len(b))
	}
	if b[0]&0xe0 != gtpv2VersionFlag {
		return gtpv2Message{}, fmt.Errorf("unsupported gtp version flags 0x%02x", b[0])
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length != len(b)-4 {
		return gtpv2Message{}, fmt.Errorf("gtpv2 length %d does not match packet length %d", length, len(b)-4)
	}
	msg := gtpv2Message{
		Type:    b[1],
		HasTEID: b[0]&gtpv2TEIDFlag != 0,
	}
	offset := 4
	if msg.HasTEID {
		if len(b) < 12 {
			return gtpv2Message{}, fmt.Errorf("gtpv2 teid message too short: %d", len(b))
		}
		msg.TEID = binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
	}
	msg.Sequence = read24(b[offset : offset+3])
	offset += 4
	msg.Payload = append([]byte(nil), b[offset:]...)
	return msg, nil
}

func put24(dst []byte, v uint32) {
	dst[0] = byte(v >> 16)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v)
}

func read24(src []byte) uint32 {
	return uint32(src[0])<<16 | uint32(src[1])<<8 | uint32(src[2])
}
