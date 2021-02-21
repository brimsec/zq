package expr

import (
	"errors"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
)

type Selector struct {
	selectors []Evaluator
	cursor    []Evaluator
	iter      zcode.Iter
	iterCols  []zng.Column
	rec       *zng.Record
}

func NewSelector(selectors []Evaluator) *Selector {
	return &Selector{selectors: selectors}
}

func (s *Selector) Init(rec *zng.Record) {
	s.rec = rec
	s.cursor = s.selectors
}

func (s *Selector) Next() (zng.Value, error) {
again:
	if s.iter != nil && !s.iter.Done() {
		b, _, err := s.iter.Next()
		if err != nil {
			return zng.Value{}, err
		}
		if len(s.iterCols) == 0 {
			return zng.Value{}, errors.New("selector encountered bad record value")
		}
		typ := s.iterCols[0].Type
		s.iterCols = s.iterCols[1:]
		x := zng.Value{typ, b}
		return x, nil
	}
	if len(s.cursor) == 0 {
		return zng.Value{}, nil
	}
	zv, err := s.cursor[0].Eval(s.rec)
	if err != nil {
		return zng.Value{}, err
	}
	s.cursor = s.cursor[1:]
	if typ, ok := zv.Type.(*zng.TypeRecord); ok {
		s.iter = zv.Iter()
		s.iterCols = typ.Columns
		goto again
	}
	return zv, nil
}
