package zst

import (
	"context"
	"errors"
	"io"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zst/column"
)

func NewCutter(object *Object, fields []string) (*Reader, error) {
	assembler, err := NewCutAssembler(object.zctx, fields, object)
	if err != nil {
		return nil, err
	}
	return &Reader{
		Object: object,
		Reader: assembler,
	}, nil

}

func NewCutterFromPath(ctx context.Context, zctx *resolver.Context, path string, fields []string) (*Reader, error) {
	object, err := NewObjectFromPath(ctx, zctx, path)
	if err != nil {
		return nil, err
	}
	reader, err := NewCutter(object, fields)
	if err != nil {
		object.Close()
		return nil, err
	}
	return reader, nil
}

type CutAssembler struct {
	zctx    *resolver.Context
	root    *column.Int
	schemas []*zng.TypeRecord
	columns []column.Interface
	types   []*zng.TypeRecord
	nwrap   []int
	builder zcode.Builder
	leaf    string
}

func NewCutAssembler(zctx *resolver.Context, fields []string, object *Object) (*CutAssembler, error) {
	a := object.assembly
	n := len(a.columns)
	ca := &CutAssembler{
		zctx:    zctx,
		root:    &column.Int{},
		schemas: a.schemas,
		columns: make([]column.Interface, n),
		types:   make([]*zng.TypeRecord, n),
		nwrap:   make([]int, n),
		leaf:    fields[len(fields)-1],
	}
	if err := ca.root.UnmarshalZNG(a.root, object.seeker); err != nil {
		return nil, err
	}
	cnt := 0
	for k, schema := range a.schemas {
		var err error
		rec := a.columns[k]
		zv := zng.Value{rec.Type, rec.Raw}
		topcol := &column.Record{}
		if err := topcol.UnmarshalZNG(a.schemas[k], zv, object.seeker); err != nil {
			return nil, err
		}
		_, ca.columns[k], err = topcol.Lookup(schema, fields)
		if err == zng.ErrMissing || err == column.ErrNonRecordAccess {
			continue
		}
		if err != nil {
			return nil, err
		}
		ca.types[k], ca.nwrap[k], err = cutType(zctx, schema, fields)
		if err != nil {
			return nil, err
		}
		cnt++
	}
	if cnt == 0 {
		return nil, zng.ErrMissing
	}
	return ca, nil
}

func cutType(zctx *resolver.Context, typ *zng.TypeRecord, fields []string) (*zng.TypeRecord, int, error) {
	if len(fields) == 0 {
		panic("zst.cutType cannot be called with an empty fields argument")
	}
	k, ok := typ.ColumnOfField(fields[0])
	if !ok {
		return nil, 0, zng.ErrMissing
	}
	if len(fields) == 1 {
		col := []zng.Column{typ.Columns[k]}
		recType, err := zctx.LookupTypeRecord(col)
		return recType, 0, err
	}
	fieldName := typ.Columns[k].Name
	typ, ok = typ.Columns[k].Type.(*zng.TypeRecord)
	if !ok {
		return nil, 0, column.ErrNonRecordAccess
	}
	typ, nwrap, err := cutType(zctx, typ, fields[1:])
	if err != nil {
		return nil, 0, err
	}
	col := []zng.Column{{fieldName, typ}}
	wrapType, err := zctx.LookupTypeRecord(col)
	return wrapType, nwrap + 1, err
}

func (a *CutAssembler) Read() (*zng.Record, error) {
	a.builder.Reset()
	for {
		schemaID, err := a.root.Read()
		if err == io.EOF {
			return nil, nil
		}
		if schemaID < 0 || int(schemaID) >= len(a.columns) {
			return nil, errors.New("bad schema id in root reassembly column")
		}
		col := a.columns[schemaID]
		if col == nil {
			// Skip records that don't have the field we're cutting.
			continue
		}
		nwrap := a.nwrap[schemaID]
		for n := nwrap; n > 0; n-- {
			a.builder.BeginContainer()
		}
		err = col.Read(&a.builder)
		if err != nil {
			return nil, err
		}
		for n := nwrap; n > 0; n-- {
			a.builder.EndContainer()
		}
		recType := a.types[schemaID]
		rec := zng.NewRecord(recType, a.builder.Bytes())
		//XXX if we had a buffer pool where records could be built back to
		// back in batches, then we could get rid of this extra allocation
		// and copy on every record
		rec.Keep()
		return rec, nil
	}
}
