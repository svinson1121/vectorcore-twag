package radius

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"

	radiustransport "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	microsoftVendorID uint32 = 311
	msMPPESendKey     byte   = 16
	msMPPERecvKey     byte   = 17
)

func addMPPEKeys(packet *radiustransport.Packet, msk []byte) error {
	if len(msk) != 64 {
		return fmt.Errorf("eap msk length = %d, want 64", len(msk))
	}
	recvKey := msk[:32]
	sendKey := msk[32:64]

	recvSalt, err := newMPPESalt()
	if err != nil {
		return err
	}
	sendSalt, err := newMPPESalt()
	if err != nil {
		return err
	}
	for recvSalt == sendSalt {
		sendSalt, err = newMPPESalt()
		if err != nil {
			return err
		}
	}

	recvAttr, err := encryptMPPEKey(packet.Secret, packet.Authenticator, recvSalt, recvKey)
	if err != nil {
		return err
	}
	if err := addMicrosoftVSA(packet, msMPPERecvKey, recvAttr); err != nil {
		return err
	}

	sendAttr, err := encryptMPPEKey(packet.Secret, packet.Authenticator, sendSalt, sendKey)
	if err != nil {
		return err
	}
	return addMicrosoftVSA(packet, msMPPESendKey, sendAttr)
}

func newMPPESalt() ([2]byte, error) {
	var salt [2]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return salt, err
	}
	salt[0] |= 0x80
	return salt, nil
}

func encryptMPPEKey(secret []byte, requestAuthenticator [16]byte, salt [2]byte, key []byte) ([]byte, error) {
	if len(key) > 255 {
		return nil, errors.New("mppe key too long")
	}
	if len(secret) == 0 {
		return nil, errors.New("empty radius secret")
	}
	if salt[0]&0x80 == 0 {
		return nil, errors.New("mppe salt high bit is not set")
	}

	plainLen := 1 + len(key)
	paddedLen := ((plainLen + md5.Size - 1) / md5.Size) * md5.Size
	if paddedLen == 0 {
		paddedLen = md5.Size
	}
	plain := make([]byte, paddedLen)
	plain[0] = byte(len(key))
	copy(plain[1:], key)

	out := make([]byte, 2+len(plain))
	copy(out[:2], salt[:])

	hash := md5.New()
	prev := requestAuthenticator[:]
	for offset := 0; offset < len(plain); offset += md5.Size {
		hash.Reset()
		_, _ = hash.Write(secret)
		if offset == 0 {
			_, _ = hash.Write(prev)
			_, _ = hash.Write(salt[:])
		} else {
			_, _ = hash.Write(out[2+offset-md5.Size : 2+offset])
		}
		mask := hash.Sum(nil)
		for i := 0; i < md5.Size; i++ {
			out[2+offset+i] = plain[offset+i] ^ mask[i]
		}
	}
	return out, nil
}

func addMicrosoftVSA(packet *radiustransport.Packet, vendorType byte, value []byte) error {
	if len(value) > 253 {
		return errors.New("microsoft vsa value too long")
	}
	vendorValue := make(radiustransport.Attribute, 2+len(value))
	vendorValue[0] = vendorType
	vendorValue[1] = byte(len(vendorValue))
	copy(vendorValue[2:], value)
	vsa, err := radiustransport.NewVendorSpecific(microsoftVendorID, vendorValue)
	if err != nil {
		return err
	}
	packet.Add(rfc2865.VendorSpecific_Type, vsa)
	return nil
}
