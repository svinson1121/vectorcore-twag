package gtp

import "testing"

func TestGTPErrorContextNotFound(t *testing.T) {
	if !IsContextNotFound(&GTPError{Operation: "Delete Session", Cause: GTPv2CauseContextNotFound}) {
		t.Fatal("cause 64 should be context not found")
	}
	if IsContextNotFound(&GTPError{Operation: "Delete Session", Cause: 65}) {
		t.Fatal("cause 65 should not be context not found")
	}
}
