package zng

import (
	"errors"
	"strings"

	"github.com/brimsec/zq/zcode"
)

type TypeEnum struct {
	id       int
	Type     Type
	Elements []Element
}

type Element struct {
	Name  string
	Value zcode.Bytes
}

func NewTypeEnum(id int, typ Type, elements []Element) *TypeEnum {
	return &TypeEnum{id, typ, elements}
}

func (t *TypeEnum) ID() int {
	return t.id
}

func (t *TypeEnum) SetID(id int) {
	t.id = id
}

func (t *TypeEnum) Element(index int) (*Element, error) {
	if index < 0 || index >= len(t.Elements) {
		return nil, ErrEnumIndex
	}
	return &t.Elements[index], nil
}

func (t *TypeEnum) Parse(in []byte) (zcode.Bytes, error) {
	return TypeUint64.Parse(in)
}

func (t *TypeEnum) Marshal(zv zcode.Bytes) (interface{}, error) {
	return TypeUint64.Marshal(zv)
}

func (t *TypeEnum) ZSON() string {
	var b strings.Builder
	typ := t.Type
	b.WriteByte('<')
	sep := ""
	for _, e := range t.Elements {
		b.WriteString(sep)
		b.WriteString(QuotedName(e.Name))
		b.WriteByte(':')
		b.WriteString(typ.ZSONOf(e.Value))
		sep = ","
	}
	b.WriteByte('>')
	return b.String()
}

func (t *TypeEnum) ZSONOf(zv zcode.Bytes) string {
	id, err := DecodeUint(zv)
	if id >= uint64(len(t.Elements)) || err != nil {
		if err == nil {
			err = errors.New("enum index out of range")
		}
		return badZng(err, t, zv)
	}
	return t.Elements[id].Name
}
