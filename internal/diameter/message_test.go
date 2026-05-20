package diameter

import (
	"bytes"
	"testing"
)

func TestMessageEncodeDecode(t *testing.T) {
	original := message{
		Flags:       flagRequest | flagProxiable,
		CommandCode: commandDER,
		AppID:       16777250,
		HopByHop:    10,
		EndToEnd:    20,
		AVPs: []avp{
			utf8AVP(avpSessionID, 0, "twag.example;1"),
			uint32AVP(avpAuthSessionState, 0, 1),
			groupedAVP(avpVendorSpecificApplicationID, 0,
				uint32AVP(avpVendorID, 0, vendor3GPP),
				uint32AVP(avpAuthApplicationID, 0, 16777250),
			),
		},
	}
	decoded, err := decodeMessage(bytes.NewReader(original.encode()))
	if err != nil {
		t.Fatalf("decodeMessage() error = %v", err)
	}
	if decoded.CommandCode != original.CommandCode || decoded.AppID != original.AppID {
		t.Fatalf("unexpected header %#v", decoded)
	}
	if got := avpString(decoded.AVPs, avpSessionID, 0); got != "twag.example;1" {
		t.Fatalf("session id = %q", got)
	}
	if got, ok := avpUint32(decoded.AVPs, avpAuthSessionState, 0); !ok || got != 1 {
		t.Fatalf("auth session state = %d ok=%v", got, ok)
	}
}

func TestExperimentalResultCode(t *testing.T) {
	msg := message{
		AVPs: []avp{
			groupedAVP(avpExperimentalResult, 0,
				uint32AVP(avpVendorID, 0, vendor3GPP),
				uint32AVP(avpExperimentalResultCode, 0, 5001),
			),
		},
	}
	got, ok := experimentalResultCode(msg.AVPs)
	if !ok || got != 5001 {
		t.Fatalf("experimental result = %d ok=%v", got, ok)
	}
}
