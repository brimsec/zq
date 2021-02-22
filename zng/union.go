package zng

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/brimsec/zq/zcode"
)

type TypeUnion struct {
	id    int
	Types []Type
}

func NewTypeUnion(id int, types []Type) *TypeUnion {
	return &TypeUnion{id, types}
}

func (t *TypeUnion) ID() int {
	return t.id
}

func (t *TypeUnion) SetID(id int) {
	t.id = id
}

func (t *TypeUnion) TypeIndex(index int) (Type, error) {
	if index < 0 || index >= len(t.Types) {
		return nil, ErrUnionIndex
	}
	return t.Types[index], nil
}

// SplitZng takes a zng encoding of a value of the receiver's union type and
// returns the concrete type of the value, its index into the union
// type, and the value encoding.
func (t *TypeUnion) SplitZng(zv zcode.Bytes) (Type, int64, zcode.Bytes, error) {
	it := zv.Iter()
	v, container, err := it.Next()
	if err != nil {
		return nil, -1, nil, err
	}
	if container {
		return nil, -1, nil, ErrBadValue
	}
	index, err := DecodeInt(v)
	if err != nil {
		return nil, -1, nil, err
	}
	inner, err := t.TypeIndex(int(index))
	if err != nil {
		return nil, -1, nil, err
	}
	v, _, err = it.Next()
	if err != nil {
		return nil, -1, nil, err
	}
	if !it.Done() {
		return nil, -1, nil, ErrBadValue
	}
	return inner, int64(index), v, nil
}

// SplitTzng takes a tzng encoding of a value of the receiver's type and returns the
// concrete type of the value, its index into the union type, and the value
// encoding.
func (t *TypeUnion) SplitTzng(in []byte) (Type, int, []byte, error) {
	c := bytes.Index(in, []byte{':'})
	if c < 0 {
		return nil, -1, nil, ErrBadValue
	}
	index, err := strconv.Atoi(string(in[0:c]))
	if err != nil {
		return nil, -1, nil, err
	}
	typ, err := t.TypeIndex(index)
	if err != nil {
		return nil, -1, nil, err
	}
	return typ, index, in[c+1:], nil
}

func (t *TypeUnion) Marshal(zv zcode.Bytes) (interface{}, error) {
	inner, _, zv, err := t.SplitZng(zv)
	if err != nil {
		return nil, err
	}
	return Value{inner, zv}, nil
}

func (t *TypeUnion) ZSON() string {
	var ss []string
	for _, typ := range t.Types {
		ss = append(ss, typ.ZSON())
	}
	return fmt.Sprintf("(%s)", strings.Join(ss, ","))
}

func (t *TypeUnion) ZSONOf(zv zcode.Bytes) string {
	typ, _, iv, err := t.SplitZng(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	return fmt.Sprintf("%s (%s) %s", typ.ZSONOf(iv), typ.ZSON(), t.ZSON())
}
