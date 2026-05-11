package diameter

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	flagRequest   byte   = 0x80
	flagProxiable byte   = 0x40
	flagVendorAVP byte   = 0x80
	flagMandatory byte   = 0x40
	diameterVer   byte   = 1
	headerLen            = 20
	commandCER    uint32 = 257
	commandDWR    uint32 = 280
	commandDPR    uint32 = 282
	commandSAR    uint32 = 301
	commandRTR    uint32 = 304
	commandPPR    uint32 = 305
)

const (
	avpUserName                    uint32 = 1
	avpHostIPAddress               uint32 = 257
	avpAuthApplicationID           uint32 = 258
	avpVendorSpecificApplicationID uint32 = 260
	avpSessionID                   uint32 = 263
	avpOriginHost                  uint32 = 264
	avpSupportedVendorID           uint32 = 265
	avpVendorID                    uint32 = 266
	avpFirmwareRevision            uint32 = 267
	avpResultCode                  uint32 = 268
	avpProductName                 uint32 = 269
	avpAuthSessionState            uint32 = 277
	avpOriginStateID               uint32 = 278
	avpDestinationRealm            uint32 = 283
	avpDestinationHost             uint32 = 293
	avpOriginRealm                 uint32 = 296
	avpExperimentalResult          uint32 = 297
	avpExperimentalResultCode      uint32 = 298
	avpInbandSecurityID            uint32 = 299
	avpServiceSelection            uint32 = 493
	avpServerAssignmentType        uint32 = 614
)

const (
	vendor3GPP     uint32 = 10415
	inbandNoSec    uint32 = 0
	firmwareRevOne uint32 = 1
)

type message struct {
	Flags       byte
	CommandCode uint32
	AppID       uint32
	HopByHop    uint32
	EndToEnd    uint32
	AVPs        []avp
}

type avp struct {
	Code     uint32
	VendorID uint32
	Flags    byte
	Data     []byte
}

func (m message) isRequest() bool {
	return m.Flags&flagRequest != 0
}

func (m message) encode() []byte {
	var payload []byte
	for _, a := range m.AVPs {
		payload = append(payload, a.encode()...)
	}
	totalLen := headerLen + len(payload)
	out := make([]byte, totalLen)
	out[0] = diameterVer
	put24(out[1:4], uint32(totalLen))
	out[4] = m.Flags
	put24(out[5:8], m.CommandCode)
	binary.BigEndian.PutUint32(out[8:12], m.AppID)
	binary.BigEndian.PutUint32(out[12:16], m.HopByHop)
	binary.BigEndian.PutUint32(out[16:20], m.EndToEnd)
	copy(out[headerLen:], payload)
	return out
}

func decodeMessage(r io.Reader) (message, error) {
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return message{}, err
	}
	if prefix[0] != diameterVer {
		return message{}, fmt.Errorf("unsupported Diameter version %d", prefix[0])
	}
	length := int(read24(prefix[1:4]))
	if length < headerLen {
		return message{}, fmt.Errorf("Diameter message length %d too short", length)
	}
	rest := make([]byte, length-4)
	if _, err := io.ReadFull(r, rest); err != nil {
		return message{}, err
	}
	full := append(prefix, rest...)
	msg := message{
		Flags:       full[4],
		CommandCode: read24(full[5:8]),
		AppID:       binary.BigEndian.Uint32(full[8:12]),
		HopByHop:    binary.BigEndian.Uint32(full[12:16]),
		EndToEnd:    binary.BigEndian.Uint32(full[16:20]),
	}
	avps, err := decodeAVPs(full[headerLen:])
	if err != nil {
		return message{}, err
	}
	msg.AVPs = avps
	return msg, nil
}

func (a avp) encode() []byte {
	flags := a.Flags
	headerSize := 8
	if a.VendorID != 0 {
		flags |= flagVendorAVP
		headerSize = 12
	}
	length := headerSize + len(a.Data)
	padded := pad4(length)
	out := make([]byte, padded)
	binary.BigEndian.PutUint32(out[0:4], a.Code)
	out[4] = flags
	put24(out[5:8], uint32(length))
	offset := 8
	if a.VendorID != 0 {
		binary.BigEndian.PutUint32(out[8:12], a.VendorID)
		offset = 12
	}
	copy(out[offset:], a.Data)
	return out
}

func decodeAVPs(data []byte) ([]avp, error) {
	var out []avp
	for len(data) > 0 {
		if len(data) < 8 {
			return nil, fmt.Errorf("AVP header truncated")
		}
		code := binary.BigEndian.Uint32(data[0:4])
		flags := data[4]
		length := int(read24(data[5:8]))
		headerSize := 8
		var vendorID uint32
		if flags&flagVendorAVP != 0 {
			headerSize = 12
			if len(data) < headerSize {
				return nil, fmt.Errorf("vendor AVP header truncated")
			}
			vendorID = binary.BigEndian.Uint32(data[8:12])
		}
		if length < headerSize || len(data) < length {
			return nil, fmt.Errorf("AVP length invalid")
		}
		payload := append([]byte(nil), data[headerSize:length]...)
		out = append(out, avp{Code: code, VendorID: vendorID, Flags: flags, Data: payload})
		step := pad4(length)
		if len(data) < step {
			return nil, fmt.Errorf("AVP padding truncated")
		}
		data = data[step:]
	}
	return out, nil
}

func utf8AVP(code, vendor uint32, value string) avp {
	return utf8AVPFlags(code, vendor, flagMandatory, value)
}

func utf8AVPFlags(code, vendor uint32, flags byte, value string) avp {
	return avp{Code: code, VendorID: vendor, Flags: flags, Data: []byte(value)}
}

func uint32AVP(code, vendor, value uint32) avp {
	return uint32AVPFlags(code, vendor, flagMandatory, value)
}

func uint32AVPFlags(code, vendor uint32, flags byte, value uint32) avp {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return avp{Code: code, VendorID: vendor, Flags: flags, Data: data}
}

func groupedAVP(code, vendor uint32, children ...avp) avp {
	var data []byte
	for _, child := range children {
		data = append(data, child.encode()...)
	}
	return avp{Code: code, VendorID: vendor, Flags: flagMandatory, Data: data}
}

func addressAVP(code uint32, ip4 [4]byte) avp {
	data := []byte{0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3]}
	return avp{Code: code, Flags: flagMandatory, Data: data}
}

func findAVP(avps []avp, code, vendor uint32) (avp, bool) {
	for _, a := range avps {
		if a.Code == code && a.VendorID == vendor {
			return a, true
		}
	}
	return avp{}, false
}

func avpString(avps []avp, code, vendor uint32) string {
	if a, ok := findAVP(avps, code, vendor); ok {
		return string(a.Data)
	}
	return ""
}

func avpUint32(avps []avp, code, vendor uint32) (uint32, bool) {
	a, ok := findAVP(avps, code, vendor)
	if !ok || len(a.Data) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(a.Data[:4]), true
}

func experimentalResultCode(avps []avp) (uint32, bool) {
	a, ok := findAVP(avps, avpExperimentalResult, 0)
	if !ok {
		return 0, false
	}
	children, err := decodeAVPs(a.Data)
	if err != nil {
		return 0, false
	}
	return avpUint32(children, avpExperimentalResultCode, 0)
}

func put24(dst []byte, value uint32) {
	dst[0] = byte(value >> 16)
	dst[1] = byte(value >> 8)
	dst[2] = byte(value)
}

func read24(src []byte) uint32 {
	return uint32(src[0])<<16 | uint32(src[1])<<8 | uint32(src[2])
}

func pad4(n int) int {
	if rem := n % 4; rem != 0 {
		return n + 4 - rem
	}
	return n
}
