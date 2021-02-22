package zng

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/brimsec/zq/zcode"
)

var (
	ErrNotNumber  = errors.New("not a number")
	ErrTypeSyntax = errors.New("syntax error parsing type string")
)

type Value struct {
	Type  Type
	Bytes zcode.Bytes
}

func (v Value) IsContainer() bool {
	return IsContainerType(v.Type)
}

func (v Value) MarshalJSON() ([]byte, error) {
	if v.Bytes == nil {
		return json.Marshal(nil)
	}
	object, err := v.Type.Marshal(v.Bytes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(object)
}

func badZng(err error, t Type, zv zcode.Bytes) string {
	return fmt.Sprintf("<ZNG-ERR type %s [%s]: %s>", t, zv, err)
}

// String implements fmt.Stringer.String.  It should only be used for logs,
// debugging, etc.  Any caller that requires a specific output format should use
// FormatAs() instead.
func (v Value) String() string {
	return fmt.Sprintf("%s: %s", v.Type.ZSON(), v.Encode(nil))
}

// Encode appends the ZNG representation of this value to the passed in
// argument and returns the resulting zcode.Bytes (which may or may not
// be the same underlying buffer, as with append(), depending on its capacity)
func (v Value) Encode(dst zcode.Bytes) zcode.Bytes {
	if IsContainerType(v.Type) {
		return zcode.AppendContainer(dst, v.Bytes)
	}
	return zcode.AppendPrimitive(dst, v.Bytes)
}

func (v Value) Iter() zcode.Iter {
	return v.Bytes.Iter()
}

// If the passed-in element is an array, attempt to get the idx'th
// element, and return its type and raw representation.  Returns an
// error if the passed-in element is not an array or if idx is
// outside the array bounds.
func (v Value) ArrayIndex(idx int64) (Value, error) {
	vec, ok := v.Type.(*TypeArray)
	if !ok {
		return Value{}, ErrNotArray
	}
	if idx < 0 {
		return Value{}, ErrIndex
	}
	for i, it := 0, v.Iter(); !it.Done(); i++ {
		zv, _, err := it.Next()
		if err != nil {
			return Value{}, err
		}
		if i == int(idx) {
			return Value{vec.Type, zv}, nil
		}
	}
	return Value{}, ErrIndex
}

// Elements returns an array of Values for the given container type.
// Returns an error if the element is not an array or set.
func (v Value) Elements() ([]Value, error) {
	innerType := InnerType(v.Type)
	if innerType == nil {
		return nil, ErrNotContainer
	}
	var elements []Value
	for it := v.Iter(); !it.Done(); {
		zv, _, err := it.Next()
		if err != nil {
			return nil, err
		}
		elements = append(elements, Value{innerType, zv})
	}
	return elements, nil
}

func (v Value) ContainerLength() (int, error) {
	switch v.Type.(type) {
	case *TypeSet, *TypeArray:
		if v.Bytes == nil {
			return -1, ErrLenUnset
		}
		var n int
		for it := v.Iter(); !it.Done(); {
			if _, _, err := it.Next(); err != nil {
				return -1, err
			}
			n++
		}
		return n, nil
	default:
		return -1, ErrNotContainer
	}
}

func (v Value) IsNil() bool {
	return v.Bytes == nil && v.Type == nil
}

// IsUnset returns true iff v is an unset value.  Unset values are represented
// with a zero-valued Value.  A zero-valued value that is not unset is represented
// by a non-nil slice for Bytes of zero length.
func (v Value) IsUnset() bool {
	return v.Bytes == nil && v.Type != nil
}

func (v Value) IsUnsetOrNil() bool {
	return v.Bytes == nil
}

func (v Value) Copy() Value {
	var b zcode.Bytes
	if v.Bytes != nil {
		b = make(zcode.Bytes, len(v.Bytes))
		copy(b, v.Bytes)
	}
	return Value{v.Type, b}
}

func (v Value) IsStringy() bool {
	return IsStringy(v.Type.ID())
}

func (v Value) IsError() bool {
	return v.Type == TypeError
}

var missingAsBytes = []byte(missing)

func (v Value) IsMissing() bool {
	return v.Type == TypeError && bytes.Equal(v.Bytes, missingAsBytes)
}

func (v Value) Equal(p Value) bool {
	return v.Type == p.Type && bytes.Equal(v.Bytes, p.Bytes)
}
