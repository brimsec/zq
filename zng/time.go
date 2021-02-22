package zng

import (
	"time"

	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/zcode"
)

type TypeOfTime struct{}

func NewTime(ts nano.Ts) Value {
	return Value{TypeTime, EncodeTime(ts)}
}

func EncodeTime(t nano.Ts) zcode.Bytes {
	var b [8]byte
	n := zcode.EncodeCountedVarint(b[:], int64(t))
	return b[:n]
}

func AppendTime(bytes zcode.Bytes, t nano.Ts) zcode.Bytes {
	return AppendInt(bytes, int64(t))
}

func DecodeTime(zv zcode.Bytes) (nano.Ts, error) {
	if zv == nil {
		return 0, nil
	}
	return nano.Ts(zcode.DecodeCountedVarint(zv)), nil
}

func (t *TypeOfTime) Parse(in []byte) (zcode.Bytes, error) {
	ts, err := nano.Parse(in)
	if err != nil {
		return nil, err
	}
	return EncodeTime(ts), nil
}

func (t *TypeOfTime) ID() int {
	return IdTime
}

func (t *TypeOfTime) String() string {
	return "time"
}

func (t *TypeOfTime) Marshal(zv zcode.Bytes) (interface{}, error) {
	ts, err := DecodeTime(zv)
	if err != nil {
		return nil, err
	}
	return ts.Time().UTC().Format(time.RFC3339Nano), nil
}

func (t *TypeOfTime) ZSON() string {
	return "time"
}

func (t *TypeOfTime) ZSONOf(zv zcode.Bytes) string {
	ts, err := DecodeTime(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	b := ts.Time().Format(time.RFC3339Nano)
	return string(b)
}
