package zng

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/brimsec/zq/zcode"
)

type TypeSet struct {
	id   int
	Type Type
}

func NewTypeSet(id int, typ Type) *TypeSet {
	return &TypeSet{id, typ}
}

func (t *TypeSet) ID() int {
	return t.id
}

func (t *TypeSet) String() string {
	return fmt.Sprintf("set[%s]", t.Type)
}

func (t *TypeSet) Decode(zv zcode.Bytes) ([]Value, error) {
	if zv == nil {
		return nil, nil
	}
	return parseContainer(t, t.Type, zv)
}

func (t *TypeSet) Parse(in []byte) (zcode.Bytes, error) {
	return ParseContainer(t, in)
}

func (t *TypeSet) StringOf(zv zcode.Bytes, fmt OutFmt, _ bool) string {
	if len(zv) == 0 && (fmt == OutFormatZeek || fmt == OutFormatZeekAscii) {
		return "(empty)"
	}

	var b strings.Builder
	separator := byte(',')
	if fmt == OutFormatZNG {
		b.WriteByte('[')
		separator = ';'
	}

	first := true
	it := zv.Iter()
	for !it.Done() {
		val, _, err := it.Next()
		if err != nil {
			//XXX
			b.WriteString("ERR")
			break
		}
		if first {
			first = false
		} else {
			b.WriteByte(separator)
		}
		b.WriteString(t.Type.StringOf(val, fmt, true))
	}

	if fmt == OutFormatZNG {
		if !first {
			b.WriteByte(';')
		}
		b.WriteByte(']')
	}
	return b.String()
}

func (t *TypeSet) Marshal(zv zcode.Bytes) (interface{}, error) {
	// start out with zero-length container so we get "[]" instead of nil
	vals := []Value{}
	it := zv.Iter()
	for !it.Done() {
		val, _, err := it.Next()
		if err != nil {
			return nil, err
		}
		vals = append(vals, Value{t.Type, val})
	}
	return vals, nil
}

func (t *TypeSet) ZSON() string {
	return fmt.Sprintf("|[%s]|", t.Type.ZSON())
}

func (t *TypeSet) ZSONOf(zv zcode.Bytes) string {
	var b strings.Builder
	b.WriteString("|[")
	sep := ""
	it := zv.Iter()
	for !it.Done() {
		val, _, err := it.Next()
		if err != nil {
			return badZng(err, t, zv)
		}
		b.WriteString(sep)
		if val == nil {
			b.WriteString("null")
		} else {
			b.WriteString(t.Type.ZSONOf(val))
		}
		sep = ","
	}
	b.WriteString("]|")
	return b.String()
}

// NormalizeSet interprets zv as a set body and returns an equivalent set body
// that is normalized according to the ZNG specification (i.e., each element's
// tag-counted value is lexicographically greater than that of the preceding
// element).
func NormalizeSet(zv zcode.Bytes) zcode.Bytes {
	elements := make([]zcode.Bytes, 0, 8)
	for it := zv.Iter(); !it.Done(); {
		elem, _, err := it.NextTagAndBody()
		if err != nil {
			panic(err)
		}
		elements = append(elements, elem)
	}
	if len(elements) < 2 {
		return zv
	}
	sort.Slice(elements, func(i, j int) bool {
		return bytes.Compare(elements[i], elements[j]) == -1
	})
	norm := make(zcode.Bytes, 0, len(zv))
	norm = append(norm, elements[0]...)
	for i := 1; i < len(elements); i++ {
		// Skip duplicates.
		if !bytes.Equal(elements[i], elements[i-1]) {
			norm = append(norm, elements[i]...)
		}
	}
	return norm
}
