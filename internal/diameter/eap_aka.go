package diameter

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	eapCodeRequest  byte = 1
	eapCodeResponse byte = 2
	eapCodeSuccess  byte = 3
	eapCodeFailure  byte = 4

	eapTypeIdentity byte = 1
	eapTypeAKA      byte = 23
	eapTypeAKAPrime byte = 50

	eapAKASubtypeChallenge byte = 1

	eapAKAAttrRAND byte = 1
	eapAKAAttrAUTN byte = 2
	eapAKAAttrRES  byte = 3
	eapAKAAttrMAC  byte = 11
)

type akaChallenge struct {
	Identifier byte
	RAND       [16]byte
	AUTN       [16]byte
}

type akaKeys struct {
	RES []byte
	CK  [16]byte
	IK  [16]byte
}

func buildEAPAKAChallengeResponse(identity string, challengePayload []byte, kiHex, opcHex string) ([]byte, error) {
	challenge, err := parseAKAChallenge(challengePayload)
	if err != nil {
		return nil, err
	}
	keys, err := milenageAKA(kiHex, opcHex, challenge.RAND, challenge.AUTN)
	if err != nil {
		return nil, err
	}
	_, kAut := deriveEAPAKAKeys([]byte(identity), keys.IK, keys.CK)
	return eapAKAChallengeResponse(challenge.Identifier, keys.RES, kAut), nil
}

func parseAKAChallenge(payload []byte) (akaChallenge, error) {
	if len(payload) < 8 {
		return akaChallenge{}, fmt.Errorf("EAP-AKA challenge too short")
	}
	if payload[0] != eapCodeRequest || payload[4] != eapTypeAKA || payload[5] != eapAKASubtypeChallenge {
		return akaChallenge{}, fmt.Errorf("not an EAP-AKA challenge")
	}
	length := int(payload[2])<<8 | int(payload[3])
	if length < 8 || length > len(payload) {
		return akaChallenge{}, fmt.Errorf("invalid EAP-AKA challenge length")
	}
	var out akaChallenge
	out.Identifier = payload[1]
	attrs := payload[8:length]
	for len(attrs) > 0 {
		if len(attrs) < 4 {
			return akaChallenge{}, fmt.Errorf("truncated EAP-AKA attribute")
		}
		attrType := attrs[0]
		attrLen := int(attrs[1]) * 4
		if attrLen < 4 || attrLen > len(attrs) {
			return akaChallenge{}, fmt.Errorf("invalid EAP-AKA attribute length")
		}
		value := attrs[4:attrLen]
		switch attrType {
		case eapAKAAttrRAND:
			if len(value) < 16 {
				return akaChallenge{}, fmt.Errorf("AT_RAND too short")
			}
			copy(out.RAND[:], value[:16])
		case eapAKAAttrAUTN:
			if len(value) < 16 {
				return akaChallenge{}, fmt.Errorf("AT_AUTN too short")
			}
			copy(out.AUTN[:], value[:16])
		}
		attrs = attrs[attrLen:]
	}
	if out.RAND == [16]byte{} {
		return akaChallenge{}, fmt.Errorf("EAP-AKA challenge missing AT_RAND")
	}
	if out.AUTN == [16]byte{} {
		return akaChallenge{}, fmt.Errorf("EAP-AKA challenge missing AT_AUTN")
	}
	return out, nil
}

func eapAKAChallengeResponse(identifier byte, res []byte, kAut []byte) []byte {
	resAttr := eapAKAAttrRESValue(res)
	macAttr := append([]byte{eapAKAAttrMAC, 5, 0, 0}, make([]byte, 16)...)
	length := 8 + len(resAttr) + len(macAttr)
	out := make([]byte, 0, length)
	out = append(out, eapCodeResponse, identifier, byte(length>>8), byte(length), eapTypeAKA, eapAKASubtypeChallenge, 0, 0)
	out = append(out, resAttr...)
	out = append(out, macAttr...)
	mac := hmac.New(sha1.New, kAut)
	mac.Write(out)
	sum := mac.Sum(nil)
	copy(out[len(out)-16:], sum[:16])
	return out
}

func osmoAAAAuthCompletePayload(identifier byte) []byte {
	atom := func(name string) []byte {
		out := []byte{119, byte(len(name))}
		return append(out, name...)
	}
	out := []byte{
		131,        // ETF version
		116,        // MAP_EXT
		0, 0, 0, 2, // arity
	}
	out = append(out, atom("sta_auth_complete")...)
	out = append(out, atom("true")...)
	out = append(out, atom("eap_identifier")...)
	out = append(out, 97, identifier) // SMALL_INTEGER_EXT
	return out
}

func eapAKAAttrRESValue(res []byte) []byte {
	valueLen := 2 + len(res)
	paddedValueLen := pad4(valueLen)
	attrLen := 4 + paddedValueLen
	out := make([]byte, attrLen)
	out[0] = eapAKAAttrRES
	out[1] = byte(attrLen / 4)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(res)*8))
	copy(out[4:], res)
	return out
}

func milenageAKA(kiHex, opcHex string, randB, autn [16]byte) (akaKeys, error) {
	ki, err := decode16Hex(kiHex, "Ki")
	if err != nil {
		return akaKeys{}, err
	}
	opc, err := decode16Hex(opcHex, "OPc")
	if err != nil {
		return akaKeys{}, err
	}
	temp, err := aesEncryptBlock(ki, xor16(randB, opc))
	if err != nil {
		return akaKeys{}, err
	}
	xres, ck, ik, ak, err := milenageF2345(ki, opc, temp)
	if err != nil {
		return akaKeys{}, err
	}
	var sqn [6]byte
	for i := range sqn {
		sqn[i] = autn[i] ^ ak[i]
	}
	amf := [2]byte{autn[6], autn[7]}
	macA, err := milenageF1(ki, opc, temp, sqn, amf)
	if err != nil {
		return akaKeys{}, err
	}
	if !hmac.Equal(macA[:], autn[8:16]) {
		return akaKeys{}, fmt.Errorf("AUTN MAC verification failed")
	}
	return akaKeys{RES: append([]byte(nil), xres[:]...), CK: ck, IK: ik}, nil
}

func decode16Hex(value, name string) ([16]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return [16]byte{}, fmt.Errorf("decode %s: %w", name, err)
	}
	if len(raw) != 16 {
		return [16]byte{}, fmt.Errorf("%s must be 16 bytes / 32 hex characters", name)
	}
	var out [16]byte
	copy(out[:], raw)
	return out, nil
}

func milenageF2345(ki, opc, temp [16]byte) (res [8]byte, ck, ik [16]byte, ak [6]byte, err error) {
	out2, err := milenageFN(ki, opc, temp, milenageC(2), 0)
	if err != nil {
		return
	}
	copy(ak[:], out2[0:6])
	copy(res[:], out2[8:16])
	ck, err = milenageFN(ki, opc, temp, milenageC(3), 4)
	if err != nil {
		return
	}
	ik, err = milenageFN(ki, opc, temp, milenageC(4), 8)
	return
}

func milenageF1(ki, opc, temp [16]byte, sqn [6]byte, amf [2]byte) ([8]byte, error) {
	var in1 [16]byte
	copy(in1[0:6], sqn[:])
	copy(in1[6:8], amf[:])
	copy(in1[8:14], sqn[:])
	copy(in1[14:16], amf[:])
	out, err := aesEncryptBlock(ki, xor16(temp, rotateLeft128(xor16(in1, opc), 8)))
	if err != nil {
		return [8]byte{}, err
	}
	out = xor16(out, opc)
	var macA [8]byte
	copy(macA[:], out[0:8])
	return macA, nil
}

func milenageFN(ki, opc, temp, c [16]byte, rotateBytes int) ([16]byte, error) {
	in := xor16(rotateLeft128(xor16(temp, opc), rotateBytes), c)
	out, err := aesEncryptBlock(ki, in)
	if err != nil {
		return [16]byte{}, err
	}
	return xor16(out, opc), nil
}

func milenageC(index int) [16]byte {
	var c [16]byte
	if index > 1 {
		c[15] = byte(1 << (index - 2))
	}
	return c
}

func xor16(a, b [16]byte) [16]byte {
	var out [16]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func rotateLeft128(in [16]byte, n int) [16]byte {
	if n == 0 {
		return in
	}
	var out [16]byte
	for i := range out {
		out[i] = in[(i+n)%16]
	}
	return out
}

func aesEncryptBlock(key, plaintext [16]byte) ([16]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return [16]byte{}, err
	}
	var out [16]byte
	block.Encrypt(out[:], plaintext[:])
	return out, nil
}

func deriveEAPAKAKeys(identity []byte, ik, ck [16]byte) (kEncr, kAut []byte) {
	h := sha1.New()
	h.Write(identity)
	h.Write(ik[:])
	h.Write(ck[:])
	mk := h.Sum(nil)
	keymat := eapAKAPRF(mk, 160)
	return keymat[:16], keymat[16:32]
}

func eapAKAPRF(mk []byte, length int) []byte {
	result := make([]byte, 0, length)
	xval := append([]byte(nil), mk...)
	modulus := new(big.Int).Lsh(big.NewInt(1), 160)
	for len(result) < length {
		w0 := sha1DSS(xval)
		result = append(result, w0...)
		xval = eapAKANextXVAL(xval, w0, modulus)
		w1 := sha1DSS(xval)
		result = append(result, w1...)
		xval = eapAKANextXVAL(xval, w1, modulus)
	}
	return result[:length]
}

func eapAKANextXVAL(xval, w []byte, modulus *big.Int) []byte {
	x := new(big.Int).SetBytes(xval)
	x.Add(x, new(big.Int).SetBytes(w))
	x.Add(x, big.NewInt(1))
	x.Mod(x, modulus)
	out := x.Bytes()
	if len(out) >= 20 {
		return out[len(out)-20:]
	}
	return append(bytes.Repeat([]byte{0}, 20-len(out)), out...)
}

func sha1DSS(data []byte) []byte {
	padded := append(append([]byte(nil), data...), bytes.Repeat([]byte{0}, 44)...)
	var h0 uint32 = 0x67452301
	var h1 uint32 = 0xEFCDAB89
	var h2 uint32 = 0x98BADCFE
	var h3 uint32 = 0x10325476
	var h4 uint32 = 0xC3D2E1F0
	for len(padded) > 0 {
		block := padded[:64]
		padded = padded[64:]
		var w [80]uint32
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
		}
		for i := 16; i < 80; i++ {
			w[i] = bitsRotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
		}
		a, b, c, d, e := h0, h1, h2, h3, h4
		for i := 0; i < 80; i++ {
			var f, k uint32
			switch {
			case i < 20:
				f = (b & c) | (^b & d)
				k = 0x5A827999
			case i < 40:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			case i < 60:
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			default:
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}
			a, b, c, d, e = bitsRotateLeft32(a, 5)+f+e+k+w[i], a, bitsRotateLeft32(b, 30), c, d
		}
		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
	}
	out := make([]byte, 20)
	binary.BigEndian.PutUint32(out[0:4], h0)
	binary.BigEndian.PutUint32(out[4:8], h1)
	binary.BigEndian.PutUint32(out[8:12], h2)
	binary.BigEndian.PutUint32(out[12:16], h3)
	binary.BigEndian.PutUint32(out[16:20], h4)
	return out
}

func bitsRotateLeft32(x uint32, k int) uint32 {
	return x<<k | x>>(32-k)
}
