package put

import (
	"fmt"

	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/proc"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
)

// Put is a proc that modifies the record stream with computed values.
// Each new value is called a clause and consists of a field name and
// an expression. Each put clause either replaces an existing value in
// the column specified or appends a value as a new column.  Appended
// values appear as new columns in the order that the clause appears
// in the put expression.
type Proc struct {
	pctx    *proc.Context
	parent  proc.Interface
	builder zcode.Builder
	clauses []expr.Assignment
	// vals is a fixed array to avoid re-allocating for every record
	vals   []zng.Value
	rules  map[int]putRule
	warned map[string]struct{}
}

// A putRule describes how a given record type is modified by describing
// which input columns should be replaced with which clause expression and
// which clauses should be appended.  The type of each clause expression
// is recorded since a new rule must be created if any of the types change.
// Such changes aren't typically expected but are possible in the expression
// language.
type putRule struct {
	typ         *zng.TypeRecord
	clauseTypes []zng.Type
	step        step
}

func New(pctx *proc.Context, parent proc.Interface, clauses []expr.Assignment) (proc.Interface, error) {
	for i, p := range clauses {
		for j, c := range clauses {
			if i == j {
				continue
			}
			if p.LHS.Equal(c.LHS) {
				return nil, fmt.Errorf("put: multiple assignments to %s", p.LHS)
			}
			if c.LHS.HasStrictPrefix(p.LHS) {
				return nil, fmt.Errorf("put: conflicting nested assignments to %s and %s", p.LHS, c.LHS)
			}
		}
	}

	return &Proc{
		pctx:    pctx,
		parent:  parent,
		clauses: clauses,
		vals:    make([]zng.Value, len(clauses)),
		rules:   make(map[int]putRule),
		warned:  make(map[string]struct{}),
	}, nil
}

func (p *Proc) maybeWarn(err error) {
	s := err.Error()
	_, alreadyWarned := p.warned[s]
	if !alreadyWarned {
		if err == zng.ErrMissing {
			s = "put: a referenced field is missing"
		}
		p.pctx.Warnings <- s
		p.warned[s] = struct{}{}
	}
}

func (p *Proc) eval(in *zng.Record) ([]zng.Value, error) {
	vals := p.vals
	for k, cl := range p.clauses {
		var err error
		vals[k], err = cl.RHS.Eval(in)
		if err != nil {
			return nil, err
		}
	}
	return vals, nil
}

// A step is a recursive data structure encoding a series of steps to be
// carried out to construct an output record from an input record and
// a slice of evaluated clauses.
type step struct {
	op        op
	index     int
	container bool
	record    []step // for op == record
}

func (s *step) append(step step) {
	s.record = append(s.record, step)
}

type op int

const (
	fromInput  op = iota // copy field from input record
	fromClause           // copy field from put assignment
	root                 // values are being copied to the root record (put .=)
	record               // recurse into record below us
)

func (s step) build(in zcode.Bytes, b *zcode.Builder, vals []zng.Value) (zcode.Bytes, error) {
	switch s.op {
	case root:
		bytes := make(zcode.Bytes, len(vals[s.index].Bytes))
		copy(bytes, vals[s.index].Bytes)
		return bytes, nil
	case record:
		b.Reset()
		if err := s.buildRecord(in, b, vals); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	default:
		// top-level op should be root or record
		panic(fmt.Sprintf("put: unexpected step %v", s.op))
	}
}

func (s step) buildRecord(in zcode.Bytes, b *zcode.Builder, vals []zng.Value) error {
	ig := newGetter(in)

	for _, step := range s.record {
		switch step.op {
		case fromInput:
			bytes, err := ig.nth(step.index)
			if err != nil {
				return err
			}
			if step.container {
				b.AppendContainer(bytes)
			} else {
				b.AppendPrimitive(bytes)
			}
		case fromClause:
			if step.container {
				b.AppendContainer(vals[step.index].Bytes)
			} else {
				b.AppendPrimitive(vals[step.index].Bytes)
			}
		case record:
			b.BeginContainer()
			bytes, err := in, error(nil)
			if step.index >= 0 {
				bytes, err = ig.nth(step.index)
				if err != nil {
					return err
				}
			}
			if err := step.buildRecord(bytes, b, vals); err != nil {
				return err
			}
			b.EndContainer()
		}
	}
	return nil
}

// A getter provides random access to values in a zcode container
// using zcode.Iter. It uses a cursor to avoid quadratic re-seeks for
// the common case where values are fetched sequentially.
type getter struct {
	cursor    int
	container zcode.Bytes
	iter      zcode.Iter
}

func newGetter(cont zcode.Bytes) getter {
	return getter{
		cursor:    -1,
		container: cont,
		iter:      cont.Iter(),
	}
}
func (ig *getter) nth(n int) (zcode.Bytes, error) {
	if n < ig.cursor {
		ig.iter = ig.container.Iter()
	}
	for !ig.iter.Done() {
		zv, _, err := ig.iter.Next()
		if err != nil {
			return nil, err
		}
		ig.cursor++
		if ig.cursor == n {
			return zv, nil
		}
	}
	return nil, fmt.Errorf("getter.nth: array index %d out of bounds", n)
}

func findOverwriteClause(path field.Static, clauses []expr.Assignment) (int, field.Static, bool) {
	for i, cand := range clauses {
		if path.Equal(cand.LHS) || cand.LHS.HasStrictPrefix(path) {
			return i, cand.LHS, true
		}
	}
	return -1, nil, false
}

func (p *Proc) deriveSteps(inType *zng.TypeRecord, vals []zng.Value) (step, *zng.TypeRecord, error) {
	// special case: assign to root (put .=x)
	if p.clauses[0].LHS.IsRoot() {
		recVal, ok := vals[0].Type.(*zng.TypeRecord)
		if !ok {
			return step{}, nil, fmt.Errorf("put .=x: cannot put a non-record to .")
		}
		typ, err := p.pctx.TypeContext.LookupTypeRecord(recVal.Columns)
		return step{op: root, index: 0}, typ, err
	}
	return p.deriveRecordSteps(field.NewRoot(), inType.Columns, vals)
}

func (p *Proc) deriveRecordSteps(parentPath field.Static, inCols []zng.Column, vals []zng.Value) (step, *zng.TypeRecord, error) {
	s := step{op: record}
	cols := make([]zng.Column, 0)

	// First look at all input columns to see which should
	// be copied over and which should be overwritten by
	// assignments.
	for i, inCol := range inCols {
		path := append(parentPath, inCol.Name)
		matchIndex, matchPath, found := findOverwriteClause(path, p.clauses)
		switch {
		// input not overwritten by assignment: copy input value.
		case !found:
			s.append(step{
				op:        fromInput,
				container: zng.IsContainerType(inCol.Type),
				index:     i,
			})
			cols = append(cols, inCol)
		// input field overwritten by non-nested assignment: copy assignment value.
		case len(path) == len(matchPath):
			s.append(step{
				op:        fromClause,
				container: zng.IsContainerType(vals[matchIndex].Type),
				index:     matchIndex,
			})
			cols = append(cols, zng.Column{inCol.Name, vals[matchIndex].Type})
		// input record field overwritten by nested assignment: recurse.
		case len(path) < len(matchPath) && zng.IsRecordType(inCol.Type):
			nestedStep, typ, err := p.deriveRecordSteps(path, inCol.Type.(*zng.TypeRecord).Columns, vals)
			if err != nil {
				return step{}, nil, err
			}
			nestedStep.index = i
			s.append(nestedStep)
			cols = append(cols, zng.Column{inCol.Name, typ})
		// input non-record field overwritten by nested assignment(s): recurse.
		case len(path) < len(matchPath) && !zng.IsRecordType(inCol.Type):
			nestedStep, typ, err := p.deriveRecordSteps(path, []zng.Column{}, vals)
			if err != nil {
				return step{}, nil, err
			}
			nestedStep.index = i
			s.append(nestedStep)
			cols = append(cols, zng.Column{inCol.Name, typ})
		default:
			panic("faulty logic")
		}
	}

	appendClause := func(cl expr.Assignment) bool {
		if !cl.LHS.HasPrefix(parentPath) {
			return false
		}
		return !hasField(cl.LHS[len(parentPath)], cols)
	}
	// Then, look at put assignments to see if there are any new fields to append.
	for i, cl := range p.clauses {
		if appendClause(cl) {
			switch {
			// Append value at this level
			case len(cl.LHS) == len(parentPath)+1:
				s.append(step{
					op:        fromClause,
					container: zng.IsContainerType(vals[i].Type),
					index:     i,
				})
				cols = append(cols, zng.Column{cl.LHS[len(parentPath)], vals[i].Type})
			// Appended and nest. For example, this would happen with "put b.c=1" applied to a record {"a": 1}.
			case len(cl.LHS) > len(parentPath)+1:
				path := append(parentPath, cl.LHS[len(parentPath)])
				nestedStep, typ, err := p.deriveRecordSteps(path, []zng.Column{}, vals)
				if err != nil {
					return step{}, nil, err
				}
				nestedStep.index = -1
				cols = append(cols, zng.Column{cl.LHS[len(parentPath)], typ})
				s.append(nestedStep)
			}
		}
	}

	typ, err := p.pctx.TypeContext.LookupTypeRecord(cols)
	return s, typ, err
}

func hasField(name string, cols []zng.Column) bool {
	for _, col := range cols {
		if col.Name == name {
			return true
		}
	}
	return false
}

func sameTypes(types []zng.Type, vals []zng.Value) bool {
	for k, typ := range types {
		if vals[k].Type != typ {
			return false
		}
	}
	return true
}

func (p *Proc) lookupRule(inType *zng.TypeRecord, vals []zng.Value) (putRule, error) {
	rule, ok := p.rules[inType.ID()]
	if ok && sameTypes(rule.clauseTypes, vals) {
		return rule, nil
	}
	step, typ, err := p.deriveSteps(inType, vals)
	var clauseTypes []zng.Type
	for _, val := range vals {
		clauseTypes = append(clauseTypes, val.Type)
	}
	rule = putRule{typ, clauseTypes, step}
	p.rules[inType.ID()] = rule
	return rule, err
}

func (p *Proc) put(in *zng.Record) (*zng.Record, error) {
	vals, err := p.eval(in)
	if err != nil {
		p.maybeWarn(err)
		return in, nil
	}
	rule, err := p.lookupRule(in.Type, vals)
	if err != nil {
		return nil, err
	}

	bytes, err := rule.step.build(in.Raw, &p.builder, vals)
	if err != nil {
		return nil, err
	}
	return zng.NewRecord(rule.typ, bytes), nil
}
func (p *Proc) Pull() (zbuf.Batch, error) {
	batch, err := p.parent.Pull()
	if proc.EOS(batch, err) {
		return nil, err
	}
	recs := make([]*zng.Record, 0, batch.Length())
	for k := 0; k < batch.Length(); k++ {
		in := batch.Index(k)
		rec, err := p.put(in)
		if err != nil {
			return nil, err
		}
		// Keep is necessary because put can return its argument.
		recs = append(recs, rec.Keep())
	}
	batch.Unref()
	return zbuf.Array(recs), nil
}

func (p *Proc) Done() {
	p.parent.Done()
}
