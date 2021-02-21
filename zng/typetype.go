package zng

import (
	"fmt"

	"github.com/brimsec/zq/zcode"
)

type TypeOfType struct{}

func NewTypeType(t Type) Value {
	return Value{TypeType, zcode.Bytes(t.ZSON())}
}

func (t *TypeOfType) ID() int {
	return IdType
}

func (t *TypeOfType) Parse(in []byte) (zcode.Bytes, error) {
	// There's nothing to parse.  The zcode value is the ZSON value.
	// The caller should validate the canonical form.
	// This means we can't type check the parsed value here.
	// A caller should type check the resulting type value with a
	// type-context lookup.
	return zcode.Bytes(in), nil
}

func (t *TypeOfType) String() string {
	return "type"
}

func (t *TypeOfType) StringOf(zv zcode.Bytes, fmt OutFmt, inContainer bool) string {
	return TypeString.StringOf(zv, fmt, inContainer)
}

func (t *TypeOfType) Marshal(zv zcode.Bytes) (interface{}, error) {
	return t.StringOf(zv, OutFormatUnescaped, false), nil
}

func (t *TypeOfType) ZSON() string {
	return "type"
}

func (t *TypeOfType) ZSONOf(zv zcode.Bytes) string {
	return fmt.Sprintf("(%s)", string(zv))
}
