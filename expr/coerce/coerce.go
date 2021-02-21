package coerce

import (
	"bytes"
	"errors"
	"math"
	"strconv"

	"github.com/brimsec/zq/expr/result"
	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
)

var ErrOverflow = errors.New("integer overflow: uint64 value too large for int64")
var ErrIncompatibleTypes = errors.New("incompatible types")

// XXX aliases should probably be preserved according to the rank
// of the underlying number type.

// Pair provides a buffer to decode values into while doing comparisons
// so the same buffers can be reused on each call without zcode.Bytes buffers
// escaping to GC.  This method uses the zng.AppendInt(), zng.AppendUint(),
// etc to encode zcode.Bytes as an in-place slice instead of allocating
// new slice buffers for every value created.
type Pair struct {
	// a and b point to inputs that can't change
	A zcode.Bytes
	B zcode.Bytes
	// Buffer is a scratch buffer that stays around between calls and is the
	// landing place for either the a or b value if one of them needs to
	// be coerced (you never need to coerce both).  Then we point a or b
	// at buf and let go of the other input pointer.
	result.Buffer
}

func (c *Pair) Equal() bool {
	// bytes.Equal() returns true for nil compared to an empty-slice,
	// which doesn't work for Z null comparisons, so we explicitly check
	// for the nil condition here.
	if c.A == nil {
		return c.B == nil
	}
	if c.B == nil {
		return c.A == nil
	}
	return bytes.Equal(c.A, c.B)
}

func (c *Pair) Coerce(a, b zng.Value) (int, error) {
	c.A = a.Bytes
	c.B = b.Bytes
	aid := a.Type.ID()
	bid := b.Type.ID()
	if aid == bid {
		return aid, nil
	}
	if zng.IsNumber(aid) {
		if !zng.IsNumber(bid) {
			return 0, ErrIncompatibleTypes
		}
		return c.coerceNumbers(aid, bid)
	}
	if zng.IsStringy(aid) && zng.IsStringy(bid) {
		// Promote to bstring if they are different
		id := aid
		if id != bid {
			id = zng.IdBstring
		}
		return id, nil
	}
	if aid == zng.IdNull {
		return bid, nil
	}
	if bid == zng.IdNull {
		return aid, nil
	}
	return 0, ErrIncompatibleTypes
}

func (c *Pair) compare(lhs, rhs zng.Value) (bool, error) {
	if _, err := c.Coerce(lhs, rhs); err != nil {
		return false, err
	}
	return c.Equal(), nil
}

func intToFloat(id int, b zcode.Bytes) float64 {
	if zng.IsSigned(id) {
		v, _ := zng.DecodeInt(b)
		return float64(v)
	}
	v, _ := zng.DecodeUint(b)
	return float64(v)
}

func (c *Pair) promoteToSigned(in zcode.Bytes) (zcode.Bytes, error) {
	v, _ := zng.DecodeUint(in)
	if v > math.MaxInt64 {
		return nil, ErrOverflow
	}
	return c.Int(int64(v)), nil
}

func (c *Pair) promoteToUnsigned(in zcode.Bytes) (zcode.Bytes, error) {
	v, _ := zng.DecodeInt(in)
	if v < 0 {
		return nil, ErrOverflow
	}
	return c.Uint(uint64(v)), nil
}

func (c *Pair) coerceNumbers(aid, bid int) (int, error) {
	if zng.IsFloat(aid) {
		c.B = c.Float64(intToFloat(bid, c.B))
		return aid, nil
	}
	if zng.IsFloat(bid) {
		c.A = c.Float64(intToFloat(aid, c.A))
		return bid, nil
	}
	aIsSigned := zng.IsSigned(aid)
	if aIsSigned == zng.IsSigned(bid) {
		// They have the same signed-ness.  Promote to the wider
		// type by rank and leave the zcode.Bytes as is since
		// the varint encoding is the same for all the widths.
		// Width increasese with type ID.
		id := aid
		if bid > id {
			id = bid
		}
		return id, nil
	}
	id := zng.PromoteInt(aid, bid)

	// Otherwise, we'll promote mixed signed-ness to signed unless
	// the unsigned value is greater than signed maxint, in which
	// case, we report an overflow error.
	var err error
	if aIsSigned {
		c.B, err = c.promoteToSigned(c.B)
	} else {
		c.A, err = c.promoteToSigned(c.A)
	}
	if err == ErrOverflow {
		// We got overflow trying to turn the unsigned to signed,
		// so try turning the signed into unsigned.
		if aIsSigned {
			c.A, err = c.promoteToUnsigned(c.A)
		} else {
			c.B, err = c.promoteToUnsigned(c.B)
		}
		id = zng.IdUint64
	}
	return id, err
}

func ToFloat(zv zng.Value) (float64, bool) {
	id := zv.Type.ID()
	if zng.IsFloat(id) {
		f, _ := zng.DecodeFloat64(zv.Bytes)
		return f, true
	}
	if zng.IsInteger(id) {
		if zng.IsSigned(id) {
			v, _ := zng.DecodeInt(zv.Bytes)
			return float64(v), true
		} else {
			v, _ := zng.DecodeUint(zv.Bytes)
			return float64(v), true
		}
	}
	if id == zng.IdDuration {
		v, _ := zng.DecodeInt(zv.Bytes)
		return 1e-9 * float64(v), true
	}
	if zng.IsStringy(id) {
		v, err := strconv.ParseFloat(string(zv.Bytes), 64)
		return v, err == nil
	}
	return 0, false
}

func ToUint(zv zng.Value) (uint64, bool) {
	id := zv.Type.ID()
	if zng.IsFloat(id) {
		f, _ := zng.DecodeFloat64(zv.Bytes)
		return uint64(f), true
	}
	if zng.IsInteger(id) {
		if zng.IsSigned(id) {
			v, _ := zng.DecodeInt(zv.Bytes)
			if v < 0 {
				return 0, false
			}
			return uint64(v), true
		} else {
			v, _ := zng.DecodeUint(zv.Bytes)
			return uint64(v), true
		}
	}
	if id == zng.IdDuration {
		v, _ := zng.DecodeInt(zv.Bytes)
		return uint64(v / 1_000_000_000), true
	}
	if zng.IsStringy(id) {
		v, err := strconv.ParseUint(string(zv.Bytes), 10, 64)
		return v, err == nil
	}
	return 0, false
}

func ToInt(zv zng.Value) (int64, bool) {
	id := zv.Type.ID()
	if zng.IsFloat(id) {
		f, _ := zng.DecodeFloat64(zv.Bytes)
		return int64(f), true
	}
	if zng.IsInteger(id) {
		if zng.IsSigned(id) {
			v, _ := zng.DecodeInt(zv.Bytes)
			// XXX check if negative? should -1:uint64 be maxint64 or an error?
			return int64(v), true
		} else {
			v, _ := zng.DecodeUint(zv.Bytes)
			return int64(v), true
		}
	}
	if id == zng.IdDuration {
		v, _ := zng.DecodeInt(zv.Bytes)
		return int64(v / 1_000_000_000), true
	}
	if zng.IsStringy(id) {
		v, err := strconv.ParseInt(string(zv.Bytes), 10, 64)
		return v, err == nil
	}
	return 0, false
}

func ToTime(zv zng.Value) (nano.Ts, bool) {
	id := zv.Type.ID()
	if id == zng.IdTime {
		ts, _ := zng.DecodeTime(zv.Bytes)
		return ts, true
	}
	if zng.IsSigned(id) {
		v, _ := zng.DecodeInt(zv.Bytes)
		return nano.Ts(v) * 1_000_000_000, true
	}
	if zng.IsInteger(id) {
		v, _ := zng.DecodeUint(zv.Bytes)
		// check for overflow
		if v > math.MaxInt64 {
			return 0, false
		}
		return nano.Ts(v), true
	}
	if zng.IsFloat(id) {
		v, _ := zng.DecodeFloat64(zv.Bytes)
		return nano.Ts(v * 1e9), true
	}
	return 0, false
}

// ToDuration attempts to convert a value to a duration.  Int
// and Double are converted as seconds. The resulting coerced value is
// written to out, and true is returned. If the value cannot be
// coerced, then false is returned.
func ToDuration(in zng.Value) (int64, bool) {
	var out int64
	var err error
	switch in.Type.ID() {
	case zng.IdDuration:
		out, err = zng.DecodeDuration(in.Bytes)
	case zng.IdUint16, zng.IdUint32, zng.IdUint64:
		var v uint64
		v, err = zng.DecodeUint(in.Bytes)
		// check for overflow
		if v > math.MaxInt64 {
			return 0, false
		}
		out = 1_000_000_000 * int64(v)
	case zng.IdInt16, zng.IdInt32, zng.IdInt64:
		out, err = zng.DecodeInt(in.Bytes)
		//XXX check for overflow here
		out *= 1_000_000_000
	case zng.IdFloat64:
		var v float64
		v, err = zng.DecodeFloat64(in.Bytes)
		v *= 1e9
		out = int64(v)
	default:
		return 0, false
	}
	if err != nil {
		return 0, false
	}
	return out, true
}
