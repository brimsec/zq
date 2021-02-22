package zng

import (
	"github.com/brimsec/zq/zcode"
)

type TypeOfBstring struct{}

func NewBstring(s string) Value {
	return Value{TypeBstring, EncodeString(s)}
}

func (t *TypeOfBstring) ID() int {
	return IdBstring
}

func (t *TypeOfBstring) String() string {
	return "bstring"
}

func (t *TypeOfBstring) Marshal(zv zcode.Bytes) (interface{}, error) {
	//return t.StringOf(zv, OutFormatUnescaped, false), nil
	//XXX
	return nil, nil
}

func (t *TypeOfBstring) ZSON() string {
	return "bstring"
}

// Values of type bstring may contain a mix of valid UTF-8 and arbitrary
// binary data.  These are represented in output using the same formatting
// with "\x.." escapes as Zeek.
// In general, valid UTF-8 code points are passed through unmodified,
// though for the ZEEK_ASCII output format, all non-ascii bytes are
// escaped for compatibility with older versions of Zeek.
func (t *TypeOfBstring) ZSONOf(data zcode.Bytes) string {
	return QuotedString(data, true)
}
