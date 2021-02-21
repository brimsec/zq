package expr

import (
	"github.com/brimsec/zq/zng"
)

type Var struct {
	ref *zng.Value
}

func NewVar(ref *zng.Value) *Var {
	return &Var{ref}
}

func (v *Var) Eval(*zng.Record) (zng.Value, error) {
	zv := *v.ref
	if zv.Type == nil {
		return zng.Value{}, zng.ErrMissing
	}
	return zv, nil
}
