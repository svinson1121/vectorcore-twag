package radius

import (
	"encoding/hex"
	"testing"
)

func TestEncryptMPPEKeyDeterministic(t *testing.T) {
	secret := []byte("shared-secret")
	requestAuthenticator := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	salt := [2]byte{0x80, 0x01}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	got, err := encryptMPPEKey(secret, requestAuthenticator, salt, key)
	if err != nil {
		t.Fatalf("encryptMPPEKey() error = %v", err)
	}
	want := "8001d1f1a45f853201bc7d1ed550dc1ce0a308a49647aeec43f01b96906ed17b4d138916eeef32314ec7c5c12ac884709709"
	if hex.EncodeToString(got) != want {
		t.Fatalf("encrypted MPPE key = %x, want %s", got, want)
	}
}
