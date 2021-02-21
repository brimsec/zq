package expr

import (
	"errors"
	"fmt"
	"strings"

	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/builder"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zng/typevector"
)

type Cutter struct {
	zctx        *resolver.Context
	builder     *builder.ColumnBuilder
	fieldRefs   []field.Static
	fieldExprs  []Evaluator
	typeCache   []zng.Type
	outTypes    *typevector.Table
	recordTypes map[int]*zng.TypeRecord

	droppers     []*Dropper
	dropperCache []*Dropper
	dirty        bool
}

// NewCutter returns a Cutter for fieldnames. If complement is true,
// the Cutter copies fields that are not in fieldnames. If complement
// is false, the Cutter copies any fields in fieldnames, where targets
// specifies the copied field names.
func NewCutter(zctx *resolver.Context, fieldRefs []field.Static, fieldExprs []Evaluator) (*Cutter, error) {
	if len(fieldRefs) > 1 {
		for _, f := range fieldRefs {
			if f.IsRoot() {
				return nil, errors.New("cannot assign to . when cutting multiple values")
			}
		}
	}
	var b *builder.ColumnBuilder
	if len(fieldRefs) == 0 || !fieldRefs[0].IsRoot() {
		// A root field will cause NewColumnBuilder to panic.
		var err error
		b, err = builder.NewColumnBuilder(zctx, fieldRefs)
		if err != nil {
			return nil, err
		}
	}
	return &Cutter{
		zctx:        zctx,
		builder:     b,
		fieldRefs:   fieldRefs,
		fieldExprs:  fieldExprs,
		typeCache:   make([]zng.Type, len(fieldRefs)),
		outTypes:    typevector.NewTable(),
		recordTypes: make(map[int]*zng.TypeRecord),
	}, nil
}

func (c *Cutter) AllowPartialCuts() {
	n := len(c.fieldRefs)
	c.droppers = make([]*Dropper, n)
	c.dropperCache = make([]*Dropper, n)
}

func (c *Cutter) FoundCut() bool {
	return c.dirty
}

// Apply returns a new record comprising fields copied from in according to the
// receiver's configuration.  If the resulting record would be empty, Apply
// returns nil.
func (c *Cutter) Apply(in *zng.Record) (*zng.Record, error) {
	if len(c.fieldRefs) == 1 && c.fieldRefs[0].IsRoot() {
		zv, err := c.fieldExprs[0].Eval(in)
		if err != nil {
			if err == zng.ErrMissing {
				return nil, nil
			}
			return nil, err
		}
		recType, ok := zng.AliasedType(zv.Type).(*zng.TypeRecord)
		if !ok {
			return nil, errors.New("cannot cut a non-record to .")
		}
		c.dirty = true
		return zng.NewRecord(recType, append(zcode.Bytes{}, zv.Bytes...)), nil
	}
	types := c.typeCache
	b := c.builder
	b.Reset()
	droppers := c.dropperCache[:0]
	for k, e := range c.fieldExprs {
		zv, err := e.Eval(in)
		if err != nil {
			if err == zng.ErrMissing {
				if c.droppers != nil {
					if c.droppers[k] == nil {
						c.droppers[k] = NewDropper(c.zctx, c.fieldRefs[k:k+1])
					}
					droppers = append(droppers, c.droppers[k])
					// ignore this record
					b.Append(zv.Bytes, false)
					types[k] = zng.TypeNull
					continue
				}
				err = nil
			}
			return nil, err
		}
		b.Append(zv.Bytes, zv.IsContainer())
		types[k] = zv.Type
	}
	typ, err := c.lookupTypeRecord(types)
	if err != nil {
		return nil, err
	}
	zv, err := b.Encode()
	if err != nil {
		return nil, err
	}
	rec := zng.NewRecord(typ, zv)
	for _, d := range droppers {
		r, err := d.Apply(rec)
		if err != nil {
			return nil, err
		}
		rec = r
	}
	if rec != nil {
		c.dirty = true
	}
	return rec, nil
}

func (c *Cutter) lookupTypeRecord(types []zng.Type) (*zng.TypeRecord, error) {
	id := c.outTypes.Lookup(types)
	typ, ok := c.recordTypes[id]
	if !ok {
		cols := c.builder.TypedColumns(types)
		var err error
		typ, err = c.zctx.LookupTypeRecord(cols)
		if err != nil {
			return nil, err
		}
		c.recordTypes[id] = typ
	}
	return typ, nil
}

func fieldList(fields []Evaluator) string {
	var each []string
	for _, fieldExpr := range fields {
		s := "<not a field>"
		if f, err := DotExprToField(fieldExpr); err == nil {
			s = f.String()
		}
		each = append(each, s)
	}
	return strings.Join(each, ",")
}

func (c *Cutter) Warning() string {
	if c.FoundCut() {
		return ""
	}
	return fmt.Sprintf("no record found with columns %s", fieldList(c.fieldExprs))
}

func (c *Cutter) Eval(rec *zng.Record) (zng.Value, error) {
	out, err := c.Apply(rec)
	if err != nil {
		return zng.Value{}, err
	}
	if out == nil {
		return zng.Value{}, zng.ErrMissing
	}
	return zng.Value{out.Type, out.Raw}, nil
}
