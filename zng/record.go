package zng

import (
	"fmt"
	"strings"

	"github.com/brimsec/zq/zcode"
)

type TypeRecord struct {
	id      int
	Columns []Column
	LUT     map[string]int
}

func NewTypeRecord(id int, columns []Column) *TypeRecord {
	if columns == nil {
		columns = []Column{}
	}
	r := &TypeRecord{
		id:      id,
		Columns: columns,
	}
	r.createLUT()
	return r
}

func (t *TypeRecord) ID() int {
	return t.id
}

func (t *TypeRecord) SetID(id int) {
	t.id = id
}

//XXX we shouldn't need this... tests are using it
func (t *TypeRecord) Decode(zv zcode.Bytes) ([]Value, error) {
	if zv == nil {
		return nil, nil
	}
	var vals []Value
	for i, it := 0, zv.Iter(); !it.Done(); i++ {
		val, _, err := it.Next()
		if err != nil {
			return nil, err
		}
		if i >= len(t.Columns) {
			return nil, fmt.Errorf("too many values for record element %s", val)
		}
		v := Value{t.Columns[i].Type, val}
		vals = append(vals, v)
	}
	return vals, nil
}

func (t *TypeRecord) Marshal(zv zcode.Bytes) (interface{}, error) {
	m := make(map[string]Value)
	it := zv.Iter()
	for _, col := range t.Columns {
		zv, _, err := it.Next()
		if err != nil {
			return nil, err
		}
		m[col.Name] = Value{col.Type, zv}
	}
	return m, nil
}

func (t *TypeRecord) ColumnOfField(field string) (int, bool) {
	v, ok := t.LUT[field]
	return v, ok
}

func (t *TypeRecord) TypeOfField(field string) (Type, bool) {
	n, ok := t.LUT[field]
	if !ok {
		return nil, false
	}
	return t.Columns[n].Type, true
}

func (t *TypeRecord) HasField(field string) bool {
	_, ok := t.LUT[field]
	return ok
}

func (t *TypeRecord) createLUT() {
	t.LUT = make(map[string]int)
	for k, col := range t.Columns {
		t.LUT[string(col.Name)] = k
	}
}

func (t *TypeRecord) ZSON() string {
	var b strings.Builder
	b.WriteString("{")
	sep := ""
	for _, c := range t.Columns {
		b.WriteString(sep)
		b.WriteString(QuotedName(c.Name))
		b.WriteByte(':')
		b.WriteString(c.Type.ZSON())
		sep = ","
	}
	b.WriteString("}")
	return b.String()
}

func (t *TypeRecord) ZSONOf(zv zcode.Bytes) string {
	var b strings.Builder
	b.WriteString("{")
	sep := ""
	it := zv.Iter()
	for _, c := range t.Columns {
		val, _, err := it.Next()
		if err != nil {
			return badZng(err, t, zv)
		}
		b.WriteString(sep)
		b.WriteString(QuotedName(c.Name))
		b.WriteByte(':')
		if val == nil {
			b.WriteString("null")
		} else {
			b.WriteString(c.Type.ZSONOf(val))
		}
		sep = ","
	}
	b.WriteString("}")
	return b.String()
}
