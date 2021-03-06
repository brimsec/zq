package zng

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/brimsec/zq/pkg/byteconv"
	"github.com/brimsec/zq/zcode"
)

type TypeOfFloat64 struct{}

func NewFloat64(f float64) Value {
	return Value{TypeFloat64, EncodeFloat64(f)}
}

func AppendFloat64(zb zcode.Bytes, d float64) zcode.Bytes {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, math.Float64bits(d))
	return append(zb, buf...)
}

func EncodeFloat64(d float64) zcode.Bytes {
	return AppendFloat64(nil, d)
}

func DecodeFloat64(zv zcode.Bytes) (float64, error) {
	if len(zv) != 8 {
		return 0, errors.New("byte encoding of double not 8 bytes")
	}
	bits := binary.LittleEndian.Uint64(zv)
	return math.Float64frombits(bits), nil
}

func (t *TypeOfFloat64) Parse(in []byte) (zcode.Bytes, error) {
	d, err := byteconv.ParseFloat64(in)
	if err != nil {
		return nil, err
	}
	return EncodeFloat64(d), nil
}

func (t *TypeOfFloat64) ID() int {
	return IdFloat64
}

func (t *TypeOfFloat64) String() string {
	return "float64"
}

func (t *TypeOfFloat64) StringOf(zv zcode.Bytes, _ OutFmt, _ bool) string {
	d, err := DecodeFloat64(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	return strconv.FormatFloat(d, 'f', -1, 64)
}

func (t *TypeOfFloat64) Marshal(zv zcode.Bytes) (interface{}, error) {
	return DecodeFloat64(zv)
}

func (t *TypeOfFloat64) ZSON() string {
	return "float64"
}

func (t *TypeOfFloat64) ZSONOf(zv zcode.Bytes) string {
	d, err := DecodeFloat64(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	if d == float64(int64(d)) {
		return fmt.Sprintf("%d.", int64(d))
	}
	return strconv.FormatFloat(d, 'e', -1, 64)
}
