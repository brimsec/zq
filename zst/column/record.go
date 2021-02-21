package column

import (
	"errors"
	"io"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

var ErrColumnMismatch = errors.New("zng record value doesn't match column writer")

type RecordWriter []*FieldWriter

func NewRecordWriter(typ *zng.TypeRecord, spiller *Spiller) RecordWriter {
	var r RecordWriter
	for _, col := range typ.Columns {
		fw := &FieldWriter{
			name:     col.Name,
			column:   NewWriter(col.Type, spiller),
			presence: NewPresenceWriter(spiller),
		}
		r = append(r, fw)
	}
	return r
}

func (r RecordWriter) Write(body zcode.Bytes) error {
	it := body.Iter()
	for _, f := range r {
		if it.Done() {
			return ErrColumnMismatch
		}
		body, _, err := it.Next()
		if err != nil {
			return err
		}
		if err := f.write(body); err != nil {
			return err
		}
	}
	if !it.Done() {
		return ErrColumnMismatch
	}
	return nil
}

func (r RecordWriter) Flush(eof bool) error {
	// XXX we might want to arrange these flushes differently for locality
	for _, f := range r {
		if err := f.Flush(eof); err != nil {
			return err
		}
	}
	return nil
}

func (r RecordWriter) MarshalZNG(zctx *resolver.Context, b *zcode.Builder) (zng.Type, error) {
	var columns []zng.Column
	b.BeginContainer()
	for _, f := range r {
		fieldType, err := f.MarshalZNG(zctx, b)
		if err != nil {
			return nil, err
		}
		columns = append(columns, zng.Column{f.name, fieldType})
	}
	b.EndContainer()
	return zctx.LookupTypeRecord(columns)
}

type Record []*Field

func (r *Record) UnmarshalZNG(typ *zng.TypeRecord, in zng.Value, reader io.ReaderAt) error {
	rtype, ok := in.Type.(*zng.TypeRecord)
	if !ok {
		return errors.New("corrupt zst object: record_column is not a record")
	}
	k := 0
	for it := in.Bytes.Iter(); !it.Done(); k++ {
		zv, _, err := it.Next()
		if err != nil {
			return err
		}
		if k >= len(typ.Columns) {
			return errors.New("mismatch between record type and record_column") //XXX
		}
		fieldType := typ.Columns[k].Type
		f := &Field{}
		if err = f.UnmarshalZNG(fieldType, zng.Value{rtype.Columns[k].Type, zv}, reader); err != nil {
			return err
		}
		*r = append(*r, f)
	}
	return nil
}

func (r Record) Read(b *zcode.Builder) error {
	b.BeginContainer()
	for _, f := range r {
		if err := f.Read(b); err != nil {
			return err
		}
	}
	b.EndContainer()
	return nil
}

var ErrNonRecordAccess = errors.New("attempting to access a field in a non-record value")

func (r Record) Lookup(typ *zng.TypeRecord, fields []string) (zng.Type, Interface, error) {
	if len(fields) == 0 {
		panic("column.Record.Lookup cannot be called with an empty fields argument")
	}
	k, ok := typ.ColumnOfField(fields[0])
	if !ok {
		return nil, nil, zng.ErrMissing
	}
	t := typ.Columns[k].Type
	if len(fields) == 1 {
		return t, r[k], nil
	}
	typ, ok = t.(*zng.TypeRecord)
	if !ok {
		// This condition can happen when you are cutting id.foo and there
		// is a field "id" that isn't a record so cut should ignore it.
		return nil, nil, ErrNonRecordAccess
	}
	return r[k].column.(*Record).Lookup(typ, fields[1:])
}
