package zeek

import (
	"encoding/json"
	"errors"

	"github.com/mccanne/zq/pkg/nano"
)

type TypeOfTime struct{}

func (t *TypeOfTime) String() string {
	return "time"
}

func (t *TypeOfTime) Parse(value []byte) (nano.Ts, error) {
	if value == nil {
		return 0, ErrUnset
	}
	return nano.Parse(value)
}

func (t *TypeOfTime) Format(value []byte) (interface{}, error) {
	return t.Parse(value)
}

func (t *TypeOfTime) New(value []byte) (Value, error) {
	if value == nil {
		return &Unset{}, nil
	}
	v, err := nano.Parse(value)
	if err != nil {
		return nil, err
	}
	return &Time{Native: v}, nil
}

type Time struct {
	Native nano.Ts
}

func (t *Time) String() string {
	// This format of a fractional second is used by zeek in logs.
	// It uses enough precision to fully represent the 64-bit ns
	// accuracy of a nano.Ts.  Such values cannot be representd by
	// float64's without loss of the least significant digits of ns,
	return t.Native.StringFloat()
}

func (t *Time) Encoding() []byte {
	return []byte(t.String())
}

func (t *Time) Type() Type {
	return TypeTime
}

func (t *Time) Comparison(op string) (Predicate, error) {
	// XXX we need to add time literals to zql before this matters
	return nil, errors.New("time comparisons not yet implemented")
}

func (t *Time) Coerce(typ Type) Value {
	_, ok := typ.(*TypeOfTime)
	if ok {
		return t
	}
	return nil
}

// CoerceToTime attempts to convert a value to a time and
// returns a new time value if the conversion is possible.  Int,
// is converted as nanoseconds and Double is converted as seconds. If
// the value cannot be coerced, then nil is returned.
func CoerceToTime(in Value) *Time {
	switch v := in.(type) {
	case *Time:
		return v
	case *Int:
		return &Time{nano.Ts(v.Native)}
	case *Double:
		s := v.Native * 1000 * 1000 * 1000
		return &Time{nano.Ts(s)}
	}
	return nil
}

func (t *Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Native)
}

func (t *Time) Elements() ([]Value, bool) { return nil, false }
