package zng

import (
	"fmt"
	"strconv"

	"github.com/brimsec/zq/zcode"
)

type TypeOfString struct{}

func NewString(s string) Value {
	return Value{TypeString, EncodeString(s)}
}

func EncodeString(s string) zcode.Bytes {
	return zcode.Bytes(s)
}

func DecodeString(zv zcode.Bytes) (string, error) {
	return string(zv), nil
}

func (t *TypeOfString) ID() int {
	return IdString
}

func (t *TypeOfString) String() string {
	return "string"
}

func uescape(r rune) []byte {
	code := strconv.FormatInt(int64(r), 16)
	var s string
	if len(code) == 4 {
		s = fmt.Sprintf("\\u%s", code)
	} else {
		s = fmt.Sprintf("\\u{%s}", code)
	}
	return []byte(s)
}

func (t *TypeOfString) Marshal(zv zcode.Bytes) (interface{}, error) {
	//return t.StringOf(zv, OutFormatUnescaped, false), nil
	return nil, nil
}

func (t *TypeOfString) ZSON() string {
	return "string"
}

func (t *TypeOfString) ZSONOf(zv zcode.Bytes) string {
	return QuotedString(zv, false)
}
