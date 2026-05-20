package gtp

import (
	"errors"
	"fmt"
)

const GTPv2CauseContextNotFound uint8 = 64

type GTPError struct {
	Operation string
	Cause     uint8
	Message   string
}

func (e *GTPError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s rejected with cause %d: %s", e.Operation, e.Cause, e.Message)
	}
	return fmt.Sprintf("%s rejected with cause %d", e.Operation, e.Cause)
}

func IsContextNotFound(err error) bool {
	var gtpErr *GTPError
	return errors.As(err, &gtpErr) && gtpErr.Cause == GTPv2CauseContextNotFound
}
