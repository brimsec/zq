package proc

import (
	"fmt"
	"sort"
	"time"

	"github.com/mccanne/zq/ast"
	"github.com/mccanne/zq/expr"
	"github.com/mccanne/zq/pkg/nano"
	"github.com/mccanne/zq/pkg/zeek"
	"github.com/mccanne/zq/pkg/zson"
	"github.com/mccanne/zq/pkg/zson/resolver"
	"github.com/mccanne/zq/pkg/zval"
	"github.com/mccanne/zq/reducer"
	"github.com/mccanne/zq/reducer/compile"
	"go.uber.org/zap"
)

type GroupByKey struct {
	name     string
	resolver expr.FieldExprResolver
}

type GroupByParams struct {
	duration        ast.Duration
	update_interval ast.Duration
	limit           int
	keys            []GroupByKey
	reducers        []compile.CompiledReducer
}

type errTooBig int

func (e errTooBig) Error() string {
	return fmt.Sprintf("groupby aggregation exceeded configured cardinality limit (%d)", e)
}

func IsErrTooBig(err error) bool {
	_, ok := err.(errTooBig)
	return ok
}

const defaultGroupByLimit = 1000000

func CompileGroupBy(node *ast.GroupByProc) (*GroupByParams, error) {
	keys := make([]GroupByKey, 0)
	for _, key := range(node.Keys) {
		resolver, err := expr.CompileFieldExpr(key)
		if err != nil {
			return nil, err
		}
		keys = append(keys, GroupByKey{
			name:     groupKey(key),
			resolver: resolver,
		})
	}
	reducers := make([]compile.CompiledReducer, 0)
	for _, reducer := range(node.Reducers) {
		compiled, err := compile.Compile(reducer)
		if err != nil {
			return nil, err
		}
		reducers = append(reducers, compiled)
	}
	return &GroupByParams{
		duration:        node.Duration,
		update_interval: node.UpdateInterval,
		limit:           node.Limit,
		keys:            keys,
		reducers:        reducers,
	}, nil
}

// GroupBy computes aggregations using a GroupByAggregator.
type GroupBy struct {
	Base
	timeBinned bool
	interval   time.Duration
	agg        *GroupByAggregator
}

// GroupByAggregator performs the core aggregation computation for a
// list of reducer generators. It handles both regular and time-binned
// ("every") group-by operations.  Records are generated in a
// deterministic but undefined total order. Records and spans generated
// by time-binning are partially ordered by timestamp coincident with
// search direction.
type GroupByAggregator struct {
	keyCols        []zeek.Column
	staticCols     []zeek.Column
	consumeCutDest []zval.Encoding // Reduces memory allocations in Consume.
	consumeKeyBuf  []byte          // Reduces memory allocations in Consume.
	dt             *resolver.Table
	keys           []GroupByKey
	reducerDefs    []compile.CompiledReducer
	// For a regular group-by, tables has one entry with key 0.  For a
	// time-binned group-by, tables has one entry per bin and is keyed by
	// bin timestamp (so that a bin with span [ts, ts+timeBinDuration) has
	// key ts).
	tables          map[nano.Ts]map[string]*GroupByRow
	TimeBinDuration int64 // Zero means regular group-by (no time binning).
	reverse         bool
	logger          *zap.Logger
	limit           int
}

type GroupByRow struct {
	keyVals []zeek.Value
	ts      nano.Ts
	columns compile.Row
}

func NewGroupByAggregator(c *Context, params GroupByParams) *GroupByAggregator {
	//XXX we should change this AST format... left over from Looky
	// convert second to nano second
	dur := int64(params.duration.Seconds) * 1000000000
	if dur < 0 {
		panic("dur cannot be negative")
	}
	limit := params.limit
	if limit == 0 {
		limit = defaultGroupByLimit
	}
	return &GroupByAggregator{
		keys:            params.keys,
		dt:              c.Resolver,
		reducerDefs:     params.reducers,
		tables:          make(map[nano.Ts]map[string]*GroupByRow),
		TimeBinDuration: dur,
		reverse:         c.Reverse,
		logger:          c.Logger,
		limit:           limit,
	}
}

func NewGroupBy(c *Context, parent Proc, params GroupByParams) *GroupBy {
	// XXX in a subsequent PR we will isolate ast params and pass in
	// ast.GroupByParams
	agg := NewGroupByAggregator(c, params)
	timeBinned := params.duration.Seconds > 0
	interval := time.Duration(params.update_interval.Seconds) * time.Second
	return &GroupBy{
		Base:       Base{Context: c, Parent: parent},
		timeBinned: timeBinned,
		interval:   interval,
		agg:        agg,
	}
}

func (g *GroupBy) Pull() (zson.Batch, error) {
	start := time.Now()
	for {
		batch, err := g.Get()
		if err != nil {
			return nil, err
		}
		if batch == nil {
			return g.agg.Results(true, g.MinTs, g.MaxTs), nil
		}
		for k := 0; k < batch.Length(); k++ {
			err := g.agg.Consume(batch.Index(k))
			if err != nil {
				batch.Unref()
				return nil, err
			}
		}
		batch.Unref()
		if g.timeBinned {
			if f := g.agg.Results(false, g.MinTs, g.MaxTs); f != nil {
				return f, nil
			}
		} else if g.interval > 0 && time.Since(start) >= g.interval {
			return g.agg.Results(false, g.MinTs, g.MaxTs), nil
		}
	}
}

func (g *GroupByAggregator) createRow(ts nano.Ts, columns []zeek.Column, zvals []zval.Encoding) *GroupByRow {
	// Make a deep copy so the caller can reuse the underlying arrays.
	vals := make([]zeek.Value, len(zvals))
	for k, v := range zvals {
		if v != nil {
			//XXX check for err
			vals[k], _ = columns[k].Type.New(zvals[k])
		}
	}
	return &GroupByRow{
		keyVals: vals,
		ts:      ts,
		columns: compile.Row{Defs: g.reducerDefs},
	}
}

func (g *GroupByAggregator) key(key []byte, columns []zeek.Column, vals []zval.Encoding) ([]byte, error) {
	if len(vals) > 0 {
		s, err := zson.Splat(columns[0].Type, vals[0])
		if err != nil {
			return nil, err
		}
		key = append(key, s...)
		for i, v := range vals[1:] {
			s, err := zson.Splat(columns[i+1].Type, v)
			if err != nil {
				return nil, err
			}
			key = append(key, ':')
			key = append(key, s...)
		}
	}
	return key, nil
}

// Consume takes a record and adds it to the aggregation. Records
// successively passed to Consume are expected to have timestamps in
// monotonically increasing or decreasing order determined by g.reverse.
func (g *GroupByAggregator) Consume(r *zson.Record) error {
	// Extract the list of groupby expressions.  Re-use the array
	// stored in consumeCutDest to avoid re-allocating on every record.
	var vals [][]byte
	if g.consumeCutDest != nil {
		vals = g.consumeCutDest[:0]
	}
	for _, key := range(g.keys) {
		_, v := key.resolver(r)
		if v != nil {
			vals = append(vals, v)
		}
	}
	g.consumeCutDest = vals

	if len(vals) != len(g.keys) {
		// This record does not have all the group-by fields, so ignore
		// it.  XXX Maybe we should include it with missing vals = nil.
		return nil
	}
	if g.staticCols == nil {
		g.initStaticCols(r)
	}

	// See if we've encountered this combo before.
	// If so, update the state of each probe attached to the row.
	// Otherwise, create a new row and create new probe state.
	key, err := g.key(g.consumeKeyBuf[:0], g.keyCols, vals)
	if err != nil {
		return err
	}
	g.consumeKeyBuf = key

	var ts nano.Ts
	if g.TimeBinDuration > 0 {
		ts = r.Ts.Trunc(g.TimeBinDuration)
	}
	table, ok := g.tables[ts]
	if !ok {
		table = make(map[string]*GroupByRow)
		g.tables[ts] = table
	}
	//XXX use unsafe here to avoid sending all the string keys to GC
	row, ok := table[string(key)]
	if !ok {
		if len(table) >= g.limit {
			return errTooBig(g.limit)
		}
		row = g.createRow(ts, g.keyCols, vals)
		table[string(key)] = row
	}
	row.columns.Consume(r)
	return nil
}

// Results returns a batch of aggregation result records.
// If this is a time-binned aggregation, this can be called multiple
// times; all completed time bins at the time of the invocation are
// returned. A final call with eof=true should be made to get the
// final (possibly incomplete) time bin.
// If this is not a time-binned aggregation, a single call (with
// eof=true) should be made after all records have been Consumed()'d.
func (g *GroupByAggregator) Results(eof bool, minTs nano.Ts, maxTs nano.Ts) zson.Batch {
	var bins []nano.Ts
	for b := range g.tables {
		bins = append(bins, b)
	}
	if g.reverse {
		sort.Slice(bins, func(i, j int) bool { return bins[i] > bins[j] })
	} else {
		sort.Slice(bins, func(i, j int) bool { return bins[i] < bins[j] })
	}
	var recs []*zson.Record
	for _, b := range bins {
		if g.TimeBinDuration > 0 && !eof {
			// We're not yet at EOF, so for a reverse search, we haven't
			// seen all of g.minTs's bin and should skip it.
			// Similarly, for a forward search, we haven't seen all
			// of g.maxTs's bin and should skip it.
			if g.reverse && b == minTs.Trunc(g.TimeBinDuration) ||
				!g.reverse && b == maxTs.Trunc(g.TimeBinDuration) {
				continue
			}
		}
		recs = append(recs, g.recordsForTable(g.tables[b])...)
		delete(g.tables, b)
	}
	if len(recs) == 0 {
		// Don't propagate empty batches.
		return nil
	}
	first, last := recs[0], recs[len(recs)-1]
	if g.reverse {
		first, last = last, first
	}
	span := nano.NewSpanTs(first.Ts, last.Ts.Add(g.TimeBinDuration))
	return zson.NewArray(recs, span)
}

// recordsForTable returns a slice of records with one record per table entry in a
// deterministic but undefined order.
func (g *GroupByAggregator) recordsForTable(table map[string]*GroupByRow) []*zson.Record {
	var keys []string
	for k := range table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var recs []*zson.Record
	for _, k := range keys {
		row := table[k]
		var zv zval.Encoding
		if g.TimeBinDuration > 0 {
			zv = zval.AppendValue(zv, []byte(row.ts.StringFloat()))
		}
		for _, v := range row.keyVals {
			// XXX this is super hokey
			_, ok := v.Elements()
			if ok {
				// append the container body
				zv = append(zv, v.TextZval()...)
			} else {
				// wrap the value and append
				zv = zval.AppendValue(zv, v.TextZval())
			}
		}
		for _, red := range row.columns.Reducers {
			zv = zval.AppendValue(zv, reducer.Result(red).TextZval())
		}
		d := g.lookupDescriptor(&row.columns)
		r := zson.NewRecord(d, row.ts, zv)
		recs = append(recs, r)
	}
	return recs
}

func (g *GroupByAggregator) lookupDescriptor(columns *compile.Row) *zson.Descriptor {
	keyCols := make([]zeek.Column, len(columns.Reducers))
	for k, red := range columns.Reducers {
		z := reducer.Result(red)
		keyCols[k] = zeek.Column{
			Name: columns.Defs[k].Target(),
			Type: z.Type(),
		}
	}
	outcols := append(g.staticCols, keyCols...)
	return g.dt.GetByColumns(outcols)
}

// initialize the static columns, namely the td, ts (if time-binned), and key columns.
func (g *GroupByAggregator) initStaticCols(r *zson.Record) {
	// This is a little ugly.  We infer the types of the group-by keys by
	// looking at the types if the keys of the first record we see.  XXX We
	// might want to check subseuent records to make sure the types don't
	// change and drop them if they do?  If so, we should have a new method
	// that combines Cut/CutTypes.
	ncols := len(g.keys)
	if g.TimeBinDuration > 0 {
		ncols++
	}
	cols := make([]zeek.Column, ncols)
	if g.TimeBinDuration > 0 {
		cols[0] = zeek.Column{Name: "ts", Type: zeek.TypeTime}
	}
	keycols := cols[len(cols)-len(g.keys):]
	for i, key := range g.keys {
		typ, _ := key.resolver(r)
		keycols[i] = zeek.Column{Name: key.name, Type: typ}
	}
	g.keyCols = keycols
	g.staticCols = cols
}
