package expr

import (
	"errors"

	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/zng"
)

type RootRecord struct{}

func (r *RootRecord) Eval(rec *zng.Record) (zng.Value, error) {
	return zng.Value{rec.Alias, rec.Raw}, nil
}

type DotExpr struct {
	record Evaluator
	field  string
}

func NewDotAccess(record Evaluator, field string) *DotExpr {
	return &DotExpr{record, field}
}

func NewDotExpr(f field.Static) Evaluator {
	ret := Evaluator(&RootRecord{})
	for _, name := range f {
		ret = &DotExpr{ret, name}
	}
	return ret
}

func accessField(record zng.Value, field string) (zng.Value, error) {
	recType, ok := zng.AliasedType(record.Type).(*zng.TypeRecord)
	if !ok {
		return zng.Value{}, zng.ErrMissing
	}
	idx, ok := recType.ColumnOfField(field)
	if !ok {
		return zng.Value{}, zng.ErrMissing
	}
	typ := recType.Columns[idx].Type
	if record.Bytes == nil {
		// Value was unset.  Return unset value of the indicated type.
		return zng.Value{typ, nil}, nil
	}
	//XXX see PR #1071 to improve this (though we need this for Index anyway)
	zv, err := getNthFromContainer(record.Bytes, uint(idx))
	if err != nil {
		return zng.Value{}, err
	}
	return zng.Value{recType.Columns[idx].Type, zv}, nil
}

func (f *DotExpr) Eval(rec *zng.Record) (zng.Value, error) {
	lval, err := f.record.Eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	return accessField(lval, f.field)
}

// DotExprToString returns ZQL for the Evaluator assuming its a field expr.
func DotExprToString(e Evaluator) (string, error) {
	f, err := DotExprToField(e)
	if err != nil {
		return "", err
	}
	return f.String(), nil
}

func DotExprToField(e Evaluator) (field.Static, error) {
	switch e := e.(type) {
	case *RootRecord:
		return field.NewRoot(), nil
	case *DotExpr:
		lhs, err := DotExprToField(e.record)
		if err != nil {
			return nil, err
		}
		return append(lhs, e.field), nil
	case *Literal:
		return field.New(e.zv.String()), nil
	case *Index:
		lhs, err := DotExprToField(e.container)
		if err != nil {
			return nil, err
		}
		rhs, err := DotExprToField(e.index)
		if err != nil {
			return nil, err
		}
		return append(lhs, rhs...), nil
	}
	return nil, errors.New("not a field")
}
