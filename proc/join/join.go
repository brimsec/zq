package join

import (
	"context"
	"fmt"
	"sync"

	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/proc"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng"
)

type Proc struct {
	pctx        *proc.Context
	ctx         context.Context
	cancel      context.CancelFunc
	once        sync.Once
	left        *puller
	right       *zbuf.Peeker
	getLeftKey  expr.Evaluator
	getRightKey expr.Evaluator
	compare     expr.ValueCompareFn
	cutter      *expr.Cutter
	joinKey     zng.Value
	joinSet     []*zng.Record
	types       map[int]map[int]*zng.TypeRecord
}

func New(pctx *proc.Context, left, right proc.Interface, leftKey, rightKey expr.Evaluator, lhs []field.Static, rhs []expr.Evaluator) (*Proc, error) {
	cutter, err := expr.NewCutter(pctx.TypeContext, lhs, rhs)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(pctx.Context)
	return &Proc{
		pctx:        pctx,
		ctx:         ctx,
		cancel:      cancel,
		getLeftKey:  leftKey,
		getRightKey: rightKey,
		left:        newPuller(left, ctx),
		right:       zbuf.NewPeeker(newPuller(right, ctx)),
		// XXX need to make sure nullsmax agrees with inbound merge
		compare: expr.NewValueCompareFn(false),
		cutter:  cutter,
		types:   make(map[int]map[int]*zng.TypeRecord),
	}, nil
}

// Pull implements the merge logic for returning data from the upstreams.
func (p *Proc) Pull() (zbuf.Batch, error) {
	p.once.Do(func() {
		go p.left.run()
		go p.right.Reader.(*puller).run()
	})
	var out []*zng.Record
	for {
		leftRec, err := p.left.Read()
		if err != nil {
			return nil, err
		}
		if leftRec == nil {
			if len(out) == 0 {
				return nil, nil
			}
			return zbuf.Array(out), nil
		}
		key, err := p.getLeftKey.Eval(leftRec)
		if err != nil {
			// If the left key isn't present (which is not a thing
			// in a sql join), then drop the record and return only
			// left records that can eval the key expression.
			if err == zng.ErrMissing {
				continue
			}
			return nil, err
		}
		rightRecs, err := p.getJoinSet(key)
		if err != nil {
			return nil, err
		}
		if rightRecs == nil {
			// Nothing to add to the left join.
			// Accumulate this record for an outer join.
			out = append(out, leftRec.Keep())
			continue
		}
		// For every record on the right with a key matching
		// this left record, generate a joined record.
		// XXX This loop could be more efficient if we had CutAppend
		// and built the record in a re-usable buffer, then allocated
		// a right-sized output buffer for the record body and copied
		// the two inputs into the output buffer.  Even better, these
		// output buffers could come from a large buffer that implements
		// Batch and lives in a pool so the downstream user can
		// release the batch with and bypass GC.
		for _, rightRec := range rightRecs {
			cutRec, err := p.cutter.Apply(rightRec)
			if err != nil {
				return nil, err
			}
			rec, err := p.splice(leftRec, cutRec)
			if err != nil {
				return nil, err
			}
			out = append(out, rec)
		}
	}
}

func (p *Proc) Done() {
	p.cancel()
}

func (p *Proc) setJoinKey(key zng.Value) {
	// Copy the joinkey value into the joinKeBytes buffer since
	// we want to stash it and the zcode.Bytes points to a record
	// that otherwise could be freed.
	p.joinKey.Type = key.Type
	p.joinKey.Bytes = append(p.joinKey.Bytes[:0], key.Bytes...)
}

func (p *Proc) getJoinSet(leftKey zng.Value) ([]*zng.Record, error) {
	if leftKey.Equal(p.joinKey) {
		return p.joinSet, nil
	}
	for {
		rec, err := p.right.Peek()
		if err != nil || rec == nil {
			return nil, err
		}
		rightKey, err := p.getRightKey.Eval(rec)
		if err != nil {
			if err == zng.ErrMissing {
				p.right.Read()
				continue
			}
			return nil, err
		}
		if leftKey.Equal(rightKey) {
			p.setJoinKey(leftKey)
			p.joinSet, err = p.readJoinSet(p.joinKey)
			return p.joinSet, err
		}
		if p.compare(leftKey, rightKey) < 0 {
			// If the left key is smaller than the next eligible
			// join key, then there is nothing to join for this
			// record.
			return nil, nil
		}
		// Discard the peeked-at record and keep looking for
		// a righthand key that either matches or exceeds the
		// lefthand key.
		p.right.Read()
	}
}

// fillJoinSet is called when a join key has been found that matches
// the current lefthand key.  It returns the all the subsequent records
// from the righthand stream that match this key.
func (p *Proc) readJoinSet(joinKey zng.Value) ([]*zng.Record, error) {
	var recs []*zng.Record
	for {
		rec, err := p.right.Peek()
		if err != nil {
			return nil, err
		}
		if rec == nil {
			return recs, nil
		}
		key, err := p.getRightKey.Eval(rec)
		if err != nil {
			if err == zng.ErrMissing {
				p.right.Read()
				continue
			}
			return nil, err
		}
		if !key.Equal(joinKey) {
			return recs, nil
		}
		recs = append(recs, rec.Keep())
		p.right.Read()
	}
}

func (p *Proc) lookupType(left, right *zng.TypeRecord) *zng.TypeRecord {
	if table, ok := p.types[left.ID()]; ok {
		return table[right.ID()]
	}
	return nil
}

func (p *Proc) enterType(combined, left, right *zng.TypeRecord) {
	id := left.ID()
	table := p.types[id]
	if table == nil {
		table = make(map[int]*zng.TypeRecord)
		p.types[id] = table
	}
	table[right.ID()] = combined
}

func (p *Proc) buildType(left, right *zng.TypeRecord) (*zng.TypeRecord, error) {
	cols := make([]zng.Column, 0, len(left.Columns)+len(right.Columns))
	for _, c := range left.Columns {
		cols = append(cols, c)
	}
	for _, c := range right.Columns {
		name := c.Name
		for k := 2; left.HasField(name); k++ {
			name = fmt.Sprintf("%s_%d", c.Name, k)
		}
		cols = append(cols, zng.Column{name, c.Type})
	}
	return p.pctx.TypeContext.LookupTypeRecord(cols)
}

func (p *Proc) combinedType(left, right *zng.TypeRecord) (*zng.TypeRecord, error) {
	if typ := p.lookupType(left, right); typ != nil {
		return typ, nil
	}
	typ, err := p.buildType(left, right)
	if err != nil {
		return nil, err
	}
	p.enterType(typ, left, right)
	return typ, nil
}

func (p *Proc) splice(left, right *zng.Record) (*zng.Record, error) {
	if right == nil {
		// This happens on a simple join, i.e., "join key",
		// where there are no cut expressions.  For left joins,
		// this does nothing, but for inner joins, it will
		// filter the lefthand stream by what's in the righthand
		// stream.
		return left, nil
	}
	typ, err := p.combinedType(left.Type, right.Type)
	if err != nil {
		return nil, err
	}
	n := len(left.Raw)
	bytes := make([]byte, n+len(right.Raw))
	copy(bytes, left.Raw)
	copy(bytes[n:], right.Raw)
	return zng.NewRecord(typ, bytes), nil
}
