package expr

import (
	"github.com/brimsec/zq/expr/agg"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

type Generator interface {
	Init(*zng.Record)
	Next() (zng.Value, error)
}

type MapMethod struct {
	src    Generator
	dollar zng.Value
	expr   Evaluator
	rec    *zng.Record
}

func NewMapMethod(src Generator) *MapMethod {
	return &MapMethod{src: src}
}

func (m *MapMethod) Ref() *zng.Value {
	return &m.dollar
}

func (m *MapMethod) Set(e Evaluator) {
	m.expr = e
}

func (m *MapMethod) Init(rec *zng.Record) {
	m.rec = rec
	m.src.Init(rec)
}

func (m *MapMethod) Next() (zng.Value, error) {
	zv, err := m.src.Next()
	if err != nil || zv.Type == nil {
		return zv, err
	}
	m.dollar = zv
	return m.expr.Eval(m.rec)
}

type FilterMethod struct {
	src    Generator
	dollar zng.Value
	expr   Evaluator
	rec    *zng.Record
}

func NewFilterMethod(src Generator) *FilterMethod {
	return &FilterMethod{src: src}
}

func (f *FilterMethod) Ref() *zng.Value {
	return &f.dollar
}

func (f *FilterMethod) Set(e Evaluator) {
	f.expr = e
}

func (f *FilterMethod) Init(rec *zng.Record) {
	f.rec = rec
	f.src.Init(rec)
}

func (f *FilterMethod) Next() (zng.Value, error) {
	for {
		zv, err := f.src.Next()
		if err != nil || zv.Type == nil {
			return zv, err
		}
		f.dollar = zv
		b, err := f.expr.Eval(f.rec)
		if err != nil {
			return zng.Value{}, err
		}
		if zng.AliasedType(b.Type) != zng.TypeBool {
			return zng.NewErrorf("not a boolean"), nil
		}
		if zng.IsTrue(b.Bytes) {
			return zv, nil
		}
	}
}

type AggExpr struct {
	zctx   *resolver.Context
	newAgg agg.Pattern
	src    Generator
}

func NewAggExpr(zctx *resolver.Context, pattern agg.Pattern, src Generator) *AggExpr {
	return &AggExpr{
		zctx:   zctx,
		newAgg: pattern,
		src:    src,
	}
}

func (a *AggExpr) Eval(rec *zng.Record) (zng.Value, error) {
	// XXX This is currently really inefficient while we prototype
	// this machinery.  We used to have a Reset() method on aggregators
	// and we should probably reintroduce that for use here so we
	// don't create a new aggregator for every record. See Issue #2068.
	f := a.newAgg()
	a.src.Init(rec)
	for {
		zv, err := a.src.Next()
		if err != nil {
			return zng.Value{}, nil
		}
		if zv.Type == nil {
			return f.Result(a.zctx)
		}
		if err := f.Consume(zv); err != nil {
			return zng.Value{}, err
		}
	}
}
