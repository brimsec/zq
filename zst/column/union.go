package column

import (
	"errors"
	"fmt"
	"io"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

type UnionWriter struct {
	typ      *zng.TypeUnion
	values   []Writer
	selector *IntWriter
}

func NewUnionWriter(typ *zng.TypeUnion, spiller *Spiller) *UnionWriter {
	var values []Writer
	for _, typ := range typ.Types {
		values = append(values, NewWriter(typ, spiller))
	}
	return &UnionWriter{
		typ:      typ,
		values:   values,
		selector: NewIntWriter(spiller),
	}
}

func (u *UnionWriter) Write(body zcode.Bytes) error {
	_, selector, zv, err := u.typ.SplitZng(body)
	if err != nil {
		return err
	}
	if int(selector) >= len(u.values) || selector < 0 {
		return fmt.Errorf("bad selector in column.UnionWriter: %d", selector)
	}
	if err := u.selector.Write(int32(selector)); err != nil {
		return err
	}
	return u.values[selector].Write(zv)
}

func (u *UnionWriter) Flush(eof bool) error {
	if err := u.selector.Flush(eof); err != nil {
		return err
	}
	for _, value := range u.values {
		if err := value.Flush(eof); err != nil {
			return err
		}
	}
	return nil
}

func (u *UnionWriter) MarshalZNG(zctx *resolver.Context, b *zcode.Builder) (zng.Type, error) {
	var cols []zng.Column
	b.BeginContainer()
	for k, value := range u.values {
		typ, err := value.MarshalZNG(zctx, b)
		if err != nil {
			return nil, err
		}
		// Field name is based on integer position in the column.
		name := fmt.Sprintf("c%d", k)
		cols = append(cols, zng.Column{name, typ})
	}
	typ, err := u.selector.MarshalZNG(zctx, b)
	if err != nil {
		return nil, err
	}
	cols = append(cols, zng.Column{"selector", typ})
	b.EndContainer()
	return zctx.LookupTypeRecord(cols)
}

type Union struct {
	values   []Interface
	selector *Int
}

func (u *Union) UnmarshalZNG(typ *zng.TypeUnion, in zng.Value, r io.ReaderAt) error {
	rtype, ok := in.Type.(*zng.TypeRecord)
	if !ok {
		return errors.New("zst object union_column not a record")
	}
	rec := zng.NewRecord(rtype, in.Bytes)
	for k := 0; k < len(typ.Types); k++ {
		zv, err := rec.Access(fmt.Sprintf("c%d", k))
		if err != nil {
			return err
		}
		valueCol, err := Unmarshal(typ.Types[k], zv, r)
		if err != nil {
			return err
		}
		u.values = append(u.values, valueCol)
	}
	zv, err := rec.Access("selector")
	if err != nil {
		return err
	}
	u.selector = &Int{}
	return u.selector.UnmarshalZNG(zv, r)
}

func (u *Union) Read(b *zcode.Builder) error {
	selector, err := u.selector.Read()
	if err != nil {
		return err
	}
	if selector < 0 || int(selector) >= len(u.values) {
		return errors.New("bad selector in zst union reader") //XXX
	}
	b.BeginContainer()
	b.AppendPrimitive(zng.EncodeInt(int64(selector)))
	if err := u.values[selector].Read(b); err != nil {
		return err
	}
	b.EndContainer()
	return nil
}
