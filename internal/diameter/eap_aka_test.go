package diameter

import (
	"encoding/hex"
	"testing"
)

func TestMilenageAKATestSet1(t *testing.T) {
	randB := must16Hex(t, "23553cbe9637a89d218ae64dae47bf35")
	autn := must16Hex(t, "55f328b43577b9b94a9ffac354dfafb3")

	keys, err := milenageAKA(
		"465b5ce8b199b49faa5f0a2ee238a6bc",
		"cd63cb71954a9f4e48a5994e37a02baf",
		randB,
		autn,
	)
	if err != nil {
		t.Fatalf("milenageAKA() error = %v", err)
	}
	if got := hex.EncodeToString(keys.RES); got != "a54211d5e3ba50bf" {
		t.Fatalf("RES = %s", got)
	}
	if got := hex.EncodeToString(keys.CK[:]); got != "b40ba9a3c58b2a05bbf0d987b21bf8cb" {
		t.Fatalf("CK = %s", got)
	}
	if got := hex.EncodeToString(keys.IK[:]); got != "f769bcd751044604127672711c6d3441" {
		t.Fatalf("IK = %s", got)
	}
}

func must16Hex(t *testing.T, s string) [16]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("hex length = %d", len(raw))
	}
	var out [16]byte
	copy(out[:], raw)
	return out
}
