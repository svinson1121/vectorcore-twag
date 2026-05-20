package gtp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	ieIMSI           uint8 = 1
	ieCause          uint8 = 2
	ieRecovery       uint8 = 3
	ieAPN            uint8 = 71
	ieAMBR           uint8 = 72
	ieEBI            uint8 = 73
	ieMSISDN         uint8 = 76
	iePAA            uint8 = 79
	ieBearerQoS      uint8 = 80
	ieRATType        uint8 = 82
	ieServingNetwork uint8 = 83
	ieFTEID          uint8 = 87
	ieBearerContext  uint8 = 93
	ieChargingChars  uint8 = 95
	iePDNType        uint8 = 99
	ieAPNRestriction uint8 = 127
	ieSelectionMode  uint8 = 128
)

const (
	causeRequestAccepted uint8 = 16
	ratTypeWLAN          uint8 = 3
	pdnTypeIPv4          uint8 = 1
	ifaceS2aTWANGTPU     uint8 = 34
	ifaceS2aTWANGTPC     uint8 = 35
	ifaceS2aPGWGTPC      uint8 = 36
	ifaceS2aPGWGTPU      uint8 = 37

	defaultChargingCharacteristics uint16 = 0x0800
)

type gtpv2IE struct {
	Type     uint8
	Instance uint8
	Payload  []byte
}

type causeInfo struct {
	Cause               uint8
	OffendingIEType     uint8
	OffendingIELength   uint16
	OffendingIEInstance uint8
}

func (ie gtpv2IE) encode() []byte {
	out := make([]byte, 4+len(ie.Payload))
	out[0] = ie.Type
	binary.BigEndian.PutUint16(out[1:3], uint16(len(ie.Payload)))
	out[3] = ie.Instance & 0x0f
	copy(out[4:], ie.Payload)
	return out
}

func encodeIEs(ies ...gtpv2IE) []byte {
	var out []byte
	for _, ie := range ies {
		out = append(out, ie.encode()...)
	}
	return out
}

func decodeIEs(payload []byte) ([]gtpv2IE, error) {
	var ies []gtpv2IE
	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, fmt.Errorf("gtpv2 IE header truncated")
		}
		l := int(binary.BigEndian.Uint16(payload[1:3]))
		if len(payload) < 4+l {
			return nil, fmt.Errorf("gtpv2 IE %d length %d exceeds remaining %d", payload[0], l, len(payload)-4)
		}
		ies = append(ies, gtpv2IE{
			Type:     payload[0],
			Instance: payload[3] & 0x0f,
			Payload:  append([]byte(nil), payload[4:4+l]...),
		})
		payload = payload[4+l:]
	}
	return ies, nil
}

func findIE(ies []gtpv2IE, typ uint8, instance uint8) (gtpv2IE, bool) {
	for _, ie := range ies {
		if ie.Type == typ && ie.Instance == instance {
			return ie, true
		}
	}
	return gtpv2IE{}, false
}

func bcdIE(typ uint8, value string) gtpv2IE {
	return gtpv2IE{Type: typ, Payload: encodeTBCD(value)}
}

func apnIE(apn string) gtpv2IE {
	labels := strings.Split(apn, ".")
	var payload []byte
	for _, label := range labels {
		if label == "" {
			continue
		}
		payload = append(payload, byte(len(label)))
		payload = append(payload, []byte(label)...)
	}
	return gtpv2IE{Type: ieAPN, Payload: payload}
}

func uint8IE(typ uint8, v uint8) gtpv2IE {
	return gtpv2IE{Type: typ, Payload: []byte{v}}
}

func recoveryIE(restartCounter uint8) gtpv2IE {
	return uint8IE(ieRecovery, restartCounter)
}

func chargingCharacteristicsIE(instance uint8, value uint16) gtpv2IE {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, value)
	return gtpv2IE{Type: ieChargingChars, Instance: instance, Payload: payload}
}

func parseChargingCharacteristicsHex(s string) (uint16, error) {
	if len(s) != 4 {
		return 0, fmt.Errorf("charging characteristics must be exactly 4 hex characters")
	}
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("charging characteristics must be exactly 4 hex characters: %w", err)
	}
	return uint16(v), nil
}

func servingNetworkIE(realm string) (gtpv2IE, bool) {
	mcc, mnc, ok := plmnFromRealm(realm)
	if !ok {
		return gtpv2IE{}, false
	}
	return gtpv2IE{Type: ieServingNetwork, Payload: encodePLMN(mcc, mnc)}, true
}

func uint8IEInstance(typ uint8, instance uint8, v uint8) gtpv2IE {
	return gtpv2IE{Type: typ, Instance: instance, Payload: []byte{v}}
}

func ambrIE(uplink, downlink uint32) gtpv2IE {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], uplink)
	binary.BigEndian.PutUint32(payload[4:8], downlink)
	return gtpv2IE{Type: ieAMBR, Payload: payload}
}

func bearerQoSIE(qci uint8) gtpv2IE {
	payload := make([]byte, 22)
	payload[1] = qci
	return gtpv2IE{Type: ieBearerQoS, Payload: payload}
}

func fteidIE(instance uint8, iface uint8, teid uint32, ip net.IP) gtpv2IE {
	if iface > 0x3f {
		return gtpv2IE{Type: ieFTEID, Instance: instance}
	}
	ip4 := ip.To4()
	payload := make([]byte, 5, 9)
	payload[0] = 0x80 | iface
	binary.BigEndian.PutUint32(payload[1:5], teid)
	if ip4 != nil {
		payload = append(payload, ip4...)
	}
	return gtpv2IE{Type: ieFTEID, Instance: instance, Payload: payload}
}

func paaIE(ip net.IP) gtpv2IE {
	ip4 := ip.To4()
	payload := []byte{pdnTypeIPv4}
	if ip4 != nil {
		payload = append(payload, ip4...)
	}
	return gtpv2IE{Type: iePAA, Payload: payload}
}

func parseCause(ies []gtpv2IE) uint8 {
	return parseCauseInfo(ies).Cause
}

func parseCauseInfo(ies []gtpv2IE) causeInfo {
	ie, ok := findIE(ies, ieCause, 0)
	if !ok || len(ie.Payload) == 0 {
		return causeInfo{}
	}
	info := causeInfo{Cause: ie.Payload[0]}
	if len(ie.Payload) >= 6 {
		info.OffendingIEType = ie.Payload[2]
		info.OffendingIELength = binary.BigEndian.Uint16(ie.Payload[3:5])
		info.OffendingIEInstance = ie.Payload[5] & 0x0f
	}
	return info
}

func parsePAA(ies []gtpv2IE) net.IP {
	ie, ok := findIE(ies, iePAA, 0)
	if !ok || len(ie.Payload) < 5 {
		return nil
	}
	if ie.Payload[0]&0x07 != pdnTypeIPv4 {
		return nil
	}
	return net.IPv4(ie.Payload[1], ie.Payload[2], ie.Payload[3], ie.Payload[4])
}

func parseFTEID(ie gtpv2IE) (uint8, uint32, net.IP, bool) {
	if len(ie.Payload) < 5 {
		return 0, 0, nil, false
	}
	iface := ie.Payload[0] & 0x3f
	teid := binary.BigEndian.Uint32(ie.Payload[1:5])
	if ie.Payload[0]&0x80 == 0 || len(ie.Payload) < 9 {
		return iface, teid, nil, true
	}
	return iface, teid, net.IPv4(ie.Payload[5], ie.Payload[6], ie.Payload[7], ie.Payload[8]), true
}

func encodeTBCD(value string) []byte {
	digits := make([]byte, 0, len(value))
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits = append(digits, byte(r-'0'))
		}
	}
	out := make([]byte, (len(digits)+1)/2)
	for i := 0; i < len(out); i++ {
		lo := digits[i*2]
		hi := byte(0x0f)
		if i*2+1 < len(digits) {
			hi = digits[i*2+1]
		}
		out[i] = lo | hi<<4
	}
	return out
}

func plmnFromRealm(realm string) (string, string, bool) {
	parts := strings.Split(realm, ".")
	var mcc, mnc string
	for _, part := range parts {
		if strings.HasPrefix(part, "mcc") && len(part) == 6 {
			mcc = part[3:]
		}
		if strings.HasPrefix(part, "mnc") && (len(part) == 5 || len(part) == 6) {
			mnc = part[3:]
		}
	}
	if len(mcc) != 3 || (len(mnc) != 2 && len(mnc) != 3) {
		return "", "", false
	}
	return mcc, mnc, true
}

func encodePLMN(mcc, mnc string) []byte {
	mnc3 := byte(0x0f)
	if len(mnc) == 3 {
		mnc3 = digitNibble(mnc[2])
	}
	return []byte{
		digitNibble(mcc[0]) | digitNibble(mcc[1])<<4,
		digitNibble(mcc[2]) | mnc3<<4,
		digitNibble(mnc[0]) | digitNibble(mnc[1])<<4,
	}
}

func digitNibble(b byte) byte {
	if b >= '0' && b <= '9' {
		return b - '0'
	}
	return 0x0f
}
