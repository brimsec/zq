package zng

import (
	"github.com/brimsec/zq/pkg/byteconv"
	"github.com/brimsec/zq/zcode"
)

type TypeOfBool struct{}

var False = Value{TypeBool, []byte{0}}
var True = Value{TypeBool, []byte{1}}

func IsTrue(zv zcode.Bytes) bool {
	return zv[0] != 0
}

func NewBool(b bool) Value {
	return Value{TypeBool, EncodeBool(b)}
}

func AppendBool(zb zcode.Bytes, b bool) zcode.Bytes {
	if b {
		return append(zb, 1)
	}
	return append(zb, 0)
}

func EncodeBool(b bool) zcode.Bytes {
	return AppendBool(nil, b)
}

func DecodeBool(zv zcode.Bytes) (bool, error) {
	if zv == nil {
		return false, nil
	}
	if zv[0] != 0 {
		return true, nil
	}
	return false, nil
}

func (t *TypeOfBool) Parse(in []byte) (zcode.Bytes, error) {
	b, err := byteconv.ParseBool(in)
	if err != nil {
		return nil, err
	}
	return EncodeBool(b), nil
}

func (t *TypeOfBool) ID() int {
	return IdBool
}

func (t *TypeOfBool) String() string {
	return "bool"
}

func (t *TypeOfBool) StringOf(zv zcode.Bytes, _ OutFmt, _ bool) string {
	b, err := DecodeBool(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	if b {
		return "T"
	}
	return "F"
}

func (t *TypeOfBool) Marshal(zv zcode.Bytes) (interface{}, error) {
	return DecodeBool(zv)
}

func (t *TypeOfBool) ZSON() string {
	return "bool"
}

func (t *TypeOfBool) ZSONOf(zv zcode.Bytes) string {
	b, err := DecodeBool(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	if b {
		return "true"
	}
	return "false"
}
