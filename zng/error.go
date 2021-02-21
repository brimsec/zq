package zng

import (
	"errors"
	"fmt"

	"github.com/brimsec/zq/zcode"
)

// ErrMissing is returned by entities that fail because a referenced field
// was missing or because an argument to the entity had a missing value.
// This is used at sites in the code where it is unknown whether the outcome
// should result in a runtime exit or in continued execution with a
// Missing value embedded in the Z results.
var ErrMissing = errors.New(missing)

const missing = "missing"

// Missing is value that represents the error condition that a field
// referenced was not present.  The Missing value can be propagated through
// functions and expressions and each operator must clearly defined its
// semantics with respect to the Missing value.  For example, "true AND MISSING"
// is MISSING.
var Missing = NewError(ErrMissing)

type TypeOfError struct{}

func NewErrorf(format string, args ...interface{}) Value {
	msg := fmt.Sprintf(format, args...)
	return Value{TypeError, zcode.Bytes(msg)}
}

func NewError(err error) Value {
	return Value{TypeError, zcode.Bytes(err.Error())}
}

func EncodeError(err error) zcode.Bytes {
	return zcode.Bytes(err.Error())
}

func DecodeError(zv zcode.Bytes) (error, error) {
	if zv == nil {
		return nil, nil
	}
	return errors.New(string(zv)), nil
}

func (t *TypeOfError) Parse(in []byte) (zcode.Bytes, error) {
	return zcode.Bytes(in), nil
}

func (t *TypeOfError) ID() int {
	return IdError
}

func (t *TypeOfError) String() string {
	return "error"
}

func (t *TypeOfError) StringOf(zv zcode.Bytes, fmt OutFmt, inContainer bool) string {
	return string(zv)
}

func (t *TypeOfError) Marshal(zv zcode.Bytes) (interface{}, error) {
	return t.StringOf(zv, OutFormatUnescaped, false), nil
}

func (t *TypeOfError) ZSON() string {
	return "error"
}

func (t *TypeOfError) ZSONOf(zv zcode.Bytes) string {
	return QuotedString(zv, false)
}
