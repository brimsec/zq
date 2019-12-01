package proc

import (
	"context"
	"fmt"

	"github.com/mccanne/zq/ast"
	"github.com/mccanne/zq/expr"
	"github.com/mccanne/zq/filter"
	"github.com/mccanne/zq/pkg/nano"
	"github.com/mccanne/zq/pkg/zson"
	"github.com/mccanne/zq/pkg/zson/resolver"
	"github.com/mccanne/zq/reducer/compile"
	"go.uber.org/zap"
)

// Proc is the interface to objects that operate on Batches of zson.Records
// and are arranged into a flowgraph to perform pattern matching and analytics.
// A proc is generally single-threaded unless lengths are taken to implement
// concurrency within a Proc.  The model is reciever-driven, stream-oriented
// data processing.  Downstream Procs Pull() batches of data from upstream procs.
// Normally, a Proc pulls data until end of stream (nil batch and nil error)
// or error (nil batch and non-nil error).  If a Proc wants to end before
// end of stream, it calls the Done() method on its parent.  A Proc implementation
// may assume calls to Pull() and Done() are single threaded so any arrangement
// of calls to Pull() and Done() cannot be done concurrently.  In short, never
// call Done() concurrently to another goroutine calling Pull()
type Proc interface {
	Pull() (zson.Batch, error)
	Done()
	Parents() []Proc
}

// Result is a convenient way to bundle the result of Proc.Pull() to
// send over channels.
type Result struct {
	Batch zson.Batch
	Err   error
}

// Context provides states used by all procs to provide the outside context
// in which they are running.
type Context struct {
	context.Context
	Resolver *resolver.Table
	Logger   *zap.Logger
	Reverse  bool
	Warnings chan string
}

type Base struct {
	*Context
	Parent Proc
	MinTs  nano.Ts // Smallest Span.Ts seen by Get.
	MaxTs  nano.Ts // Largest Span.End() seen by Get.
}

func EOS(batch zson.Batch, err error) bool {
	return batch == nil || err != nil
}

func (b *Base) Done() {
	if b.Parent != nil {
		b.Parent.Done()
	}
}

func (b *Base) Parents() []Proc {
	if b.Parent == nil {
		return []Proc{}
	}
	return []Proc{b.Parent}
}

func (b *Base) Get() (zson.Batch, error) {
	batch, err := b.Parent.Pull()
	if err != nil {
		return nil, err
	}
	if batch != nil {
		// XXX
		if batch.Span().Ts < b.MinTs || b.MinTs == 0 {
			b.MinTs = batch.Span().Ts
		}
		if batch.Span().End() > b.MaxTs {
			b.MaxTs = batch.Span().End()
		}
	}
	return batch, err
}

type Compiler interface {
	Compile(ast.Proc, *Context, Proc) (Proc, error)
}

// Choose the name to use for a groupby key
func groupKey(node ast.FieldExpr) string {
	switch n := node.(type) {
	case *ast.FieldRead:
		return n.Field
	case *ast.FieldCall:
		if n.Fn == "RecordFieldRead" {
			return n.Param
		}
		return groupKey(n.Field)
	default:
		panic("unknown FieldExpr type")
	}
}

// CompileProc compiles an AST into a graph of Procs, and returns
// the leaves.  A custom proc compiler can be included and it will be tried first
// for each node encountered during the compilation.
func CompileProc(custom Compiler, node ast.Proc, c *Context, parent Proc) ([]Proc, error) {
	if custom != nil {
		p, err := custom.Compile(node, c, parent)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return []Proc{p}, err
		}
	}
	switch v := node.(type) {
	case *ast.ReducerProc:
		reducers := make([]compile.CompiledReducer, 0)
		for _, reducer := range v.Reducers {
			compiled, err := compile.Compile(reducer)
			if err != nil {
				return nil, err
			}
			reducers = append(reducers, compiled)
		}
		params := ReducerParams{
			interval: v.UpdateInterval,
			reducers: reducers,
		}
		return []Proc{NewReducer(c, parent, params)}, nil

	case *ast.GroupByProc:
		params, err := CompileGroupBy(v)
		if err != nil {
			return nil, err
		}
		return []Proc{NewGroupBy(c, parent, *params)}, nil

	case *ast.CutProc:
		return []Proc{NewCut(c, parent, v.Fields)}, nil

	case *ast.SortProc:
		var fields []expr.FieldExprResolver
		if v.Fields != nil {
			fields = make([]expr.FieldExprResolver, 0, len(v.Fields))
			for _, exp := range v.Fields {
				res, err := expr.CompileFieldExpr(exp)
				if err != nil {
					return nil, err
				}
				fields = append(fields, res)
			}
		}
		return []Proc{NewSort(c, parent, v.Limit, fields, v.SortDir)}, nil

	case *ast.HeadProc:
		limit := v.Count
		if limit == 0 {
			limit = 1
		}
		return []Proc{NewHead(c, parent, limit)}, nil

	case *ast.TailProc:
		limit := v.Count
		if limit == 0 {
			limit = 1
		}
		return []Proc{NewTail(c, parent, limit)}, nil

	case *ast.UniqProc:
		return []Proc{NewUniq(c, parent, v.Cflag)}, nil

	case *ast.PassProc:
		return []Proc{NewPass(c, parent)}, nil

	case *ast.FilterProc:
		f, err := filter.Compile(v.Filter)
		if err != nil {
			return nil, err
		}
		return []Proc{NewFilter(c, parent, f)}, nil

	case *ast.TopProc:
		var fields []expr.FieldExprResolver
		if v.Fields != nil {
			fields = make([]expr.FieldExprResolver, 0, len(v.Fields))
			for _, exp := range v.Fields {
				res, err := expr.CompileFieldExpr(exp)
				if err != nil {
					return nil, err
				}
				fields = append(fields, res)
			}
		}
		return []Proc{NewTop(c, parent, v.Limit, fields, v.Flush)}, nil

	case *ast.SequentialProc:
		var parents []Proc
		var err error
		n := len(v.Procs)
		for k := 0; k < n; k++ {
			parents, err = CompileProc(custom, v.Procs[k], c, parent)
			if err != nil {
				return nil, err
			}
			// merge unless we're at the end of the chain,
			// in which case the output layer will mux
			// into channels.
			if len(parents) > 1 && k < n-1 {
				parent = NewMerge(c, parents)
			} else {
				parent = parents[0]
			}
		}
		return parents, nil

	case *ast.ParallelProc:
		splitter := NewSplit(c, parent)
		n := len(v.Procs)
		var procs []Proc
		for k := 0; k < n; k++ {
			//
			// for each downstream proc chain, create a new SplitChannel,
			// attach the SplitChannel to the SplitProc, then generate the
			// proc chain with the SplitChannel as the new parent
			//
			sc := NewSplitChannel(splitter)
			proc, err := CompileProc(custom, v.Procs[k], c, sc)
			if err != nil {
				return nil, err
			}
			procs = append(procs, proc...)
		}
		return procs, nil

	default:
		return nil, fmt.Errorf("unknown AST type: %v", v)
	}
}

// Compile the proc AST and return a Executor ready to go
// "scanner" is embedded into the source node during compilation... XXX fix
func Compile(node ast.Proc, c *Context, custom Compiler) ([]Proc, error) {
	return CompileProc(nil, node, c, nil)
}
