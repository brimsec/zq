package index

import (
	"fmt"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/proc"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
)

// A FieldCutter is a custom proc that, given an input record and a
// field name, outputs one record per input record containing the
// field, with the field as only column.  It is used for field-based
// indexing. Unlike the zql cut proc, which has support for different
// types in a same-named field, this proc doesn't support different
// types, and errors if more than one type is seen.
type FieldCutter struct {
	pctx     *proc.Context
	parent   proc.Interface
	builder  *zng.Builder
	accessor expr.Evaluator
	field    field.Static
	out      field.Static
	typ      zng.Type
}

// NewFieldCutter creates a FieldCutter for field fieldName, where the
// output records' single column is named out.
func NewFieldCutter(pctx *proc.Context, parent proc.Interface, fieldName, out field.Static) (proc.Interface, error) {
	accessor := expr.NewDotExpr(fieldName)
	if accessor == nil {
		return nil, fmt.Errorf("bad field syntax: %s", fieldName)
	}

	return &FieldCutter{
		pctx:     pctx,
		parent:   parent,
		field:    fieldName,
		out:      out,
		accessor: accessor,
	}, nil
}

func (f *FieldCutter) checkType(typ zng.Type) error {
	if f.typ == nil {
		f.typ = typ
	}
	if f.typ == typ {
		return nil
	}
	return fmt.Errorf("type of %s field changed from %s to %s", f.field, f.typ, typ)
}

func (f *FieldCutter) Pull() (zbuf.Batch, error) {
	for {
		batch, err := f.parent.Pull()
		if proc.EOS(batch, err) {
			return nil, err
		}
		recs := make([]*zng.Record, 0, batch.Length())
		for _, rec := range batch.Records() {
			val, err := f.accessor.Eval(rec)
			if err != nil || val.Bytes == nil {
				continue
			}
			if err := f.checkType(val.Type); err != nil {
				return nil, err
			}
			if f.builder == nil {
				cols := []zng.Column{{f.out.Leaf(), val.Type}}
				rectyp := f.pctx.TypeContext.MustLookupTypeRecord(cols)
				f.builder = zng.NewBuilder(rectyp)
			}
			recs = append(recs, f.builder.Build(val.Bytes).Keep())
		}
		batch.Unref()
		if len(recs) > 0 {
			return zbuf.Array(recs), nil
		}
	}
}

func (f *FieldCutter) Done() {
	f.parent.Done()
}

type fieldCutterNode struct {
	field field.Static
	out   field.Static
}

func (t *fieldCutterNode) ProcNode() {}

// A TypeSplitter is a custom proc that, given an input record and a
// zng type T, outputs one record for each field of the input record of
// type T. It is used for type-based indexing.
type TypeSplitter struct {
	parent  proc.Interface
	builder zng.Builder
	typ     zng.Type
}

// NewTypeSplitter creates a TypeSplitter for type typ, where the
// output records' single column is named colName.
func NewTypeSplitter(pctx *proc.Context, parent proc.Interface, typ zng.Type, colName string) (proc.Interface, error) {
	cols := []zng.Column{{colName, typ}}
	rectyp := pctx.TypeContext.MustLookupTypeRecord(cols)
	builder := zng.NewBuilder(rectyp)

	return &TypeSplitter{
		parent:  parent,
		builder: *builder,
		typ:     typ,
	}, nil
}

func (t *TypeSplitter) Pull() (zbuf.Batch, error) {
	for {
		batch, err := t.parent.Pull()
		if proc.EOS(batch, err) {
			return nil, err
		}
		recs := make([]*zng.Record, 0, batch.Length())
		for _, rec := range batch.Records() {
			rec.Walk(func(typ zng.Type, body zcode.Bytes) error {
				if typ == t.typ && body != nil {
					recs = append(recs, t.builder.Build(body).Keep())
					return zng.SkipContainer
				}
				return nil
			})
		}
		batch.Unref()
		if len(recs) > 0 {
			return zbuf.Array(recs), nil
		}
	}
}

func (t *TypeSplitter) Done() {
	t.parent.Done()
}

type typeSplitterNode struct {
	key      field.Static
	typeName string
}

func (t *typeSplitterNode) ProcNode() {}

func compile(node ast.Proc, pctx *proc.Context, parent proc.Interface) (proc.Interface, error) {
	switch v := node.(type) {
	case *fieldCutterNode:
		return NewFieldCutter(pctx, parent, v.field, v.out)
	case *typeSplitterNode:
		typ, err := pctx.TypeContext.LookupByName(v.typeName)
		if err != nil {
			return nil, err
		}
		return NewTypeSplitter(pctx, parent, typ, v.key.String())
	}
	return nil, nil
}
