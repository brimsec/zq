package semantic

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/compiler/kernel"
	"github.com/brimsec/zq/expr/agg"
	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/zng/resolver"
)

var passProc = &ast.PassProc{Op: "PassProc"}

//XXX
func zbufDirInt(reversed bool) int {
	if reversed {
		return -1
	}
	return 1
}

func Optimize(zctx *resolver.Context, program ast.Proc, sortKey field.Static, sortReversed bool) (*kernel.Filter, ast.Proc) {
	if program == nil {
		return nil, passProc
	}
	Transform(program)
	if sortKey != nil {
		SetGroupByProcInputSortDir(program, sortKey, zbufDirInt(sortReversed))
	}
	fe, p := liftFilter(program)
	if fe == nil {
		return nil, p
	}
	return kernel.NewFilter(zctx, fe), p
}

func ensureSequentialProc(p ast.Proc) *ast.SequentialProc {
	if p, ok := p.(*ast.SequentialProc); ok {
		return p
	}
	return &ast.SequentialProc{
		Procs: []ast.Proc{p},
	}
}

func countConsts(procs []ast.Proc) int {
	for k, p := range procs {
		switch p.(type) {
		case *ast.ConstProc, *ast.TypeProc:
			continue
		default:
			return k
		}
	}
	return 0
}

// liftFilter removes the filter at the head of the flowgraph AST, if
// one is present, and returns its ast.Expression and the modified
// flowgraph AST. If the flowgraph does not start with a filter, it
// returns nil and the unmodified flowgraph.
func liftFilter(p ast.Proc) (ast.Expression, ast.Proc) {
	if fp, ok := p.(*ast.FilterProc); ok {
		return fp.Filter, passProc
	}
	seq, ok := p.(*ast.SequentialProc)
	if ok && len(seq.Procs) > 0 {
		nc := countConsts(seq.Procs)
		if nc == len(seq.Procs) {
			return nil, p
		}
		if fp, ok := seq.Procs[nc].(*ast.FilterProc); ok {
			rest := ast.Proc(passProc)
			if len(seq.Procs) > nc+1 {
				var procs []ast.Proc
				procs = append(procs, seq.Procs[0:nc]...)
				procs = append(procs, seq.Procs[nc+1:]...)
				rest = &ast.SequentialProc{
					Op:    "SequentialProc",
					Procs: procs,
				}
			}
			return fp.Filter, rest
		}
	}
	return nil, p
}

// Transform does a semantic analysis on a flowgraph to an
// intermediate representation that can be compiled into the runtime
// object.  Currently, it only replaces the group-by duration with
// a truncation call on the ts and replaces FunctionCall's in proc context
// with either a group-by or filter-proc based on the function's name.
// XXX In a subsequent PR, instead of modifed the AST in place we will
// translate the AST into a flow DSL.
func Transform(p ast.Proc) (ast.Proc, error) {
	switch p := p.(type) {
	case *ast.GroupByProc:
		if duration := p.Duration.Seconds; duration != 0 {
			durationKey := ast.Assignment{
				LHS: ast.NewDotExpr(field.New("ts")),
				RHS: &ast.FunctionCall{
					Op:       "FunctionCall",
					Function: "trunc",
					Args: []ast.Expression{
						ast.NewDotExpr(field.New("ts")),
						&ast.Literal{
							Op:    "Literal",
							Type:  "int64",
							Value: strconv.Itoa(duration),
						}},
				},
			}
			p.Keys = append([]ast.Assignment{durationKey}, p.Keys...)
		}
	case *ast.ParallelProc:
		for k := range p.Procs {
			var err error
			p.Procs[k], err = Transform(p.Procs[k])
			if err != nil {
				return nil, err
			}
		}
	case *ast.SequentialProc:
		for k := range p.Procs {
			var err error
			p.Procs[k], err = Transform(p.Procs[k])
			if err != nil {
				return nil, err
			}
		}
	case *ast.SwitchProc:
		for k := range p.Cases {
			var err error
			tr, err := Transform(p.Cases[k].Proc)
			if err != nil {
				return nil, err
			}
			p.Cases[k] = ast.SwitchCase{Filter: p.Cases[k].Filter, Proc: tr}
		}
	case *ast.FunctionCall:
		converted, err := convertFunctionProc(p)
		if err != nil {
			return nil, err
		}
		// The conversion may be a group-by so we recursively
		// invoke the transformation here...
		return Transform(converted)
	}
	return p, nil
}

// convertFunctionProc converts a FunctionCall ast node at proc level
// to a group-by or a filter-proc based on the name of the function.
// This way, Z of the form `... | exists(...) | ...` can be distinguished
// from `count()` by the name lookup here at compile time.
func convertFunctionProc(call *ast.FunctionCall) (ast.Proc, error) {
	if _, err := agg.NewPattern(call.Function); err != nil {
		// Assume it's a valid function and convert.  If not,
		// the compiler will report an unknown function error.
		return ast.FilterToProc(call), nil
	}
	var e ast.Expression
	if len(call.Args) > 1 {
		return nil, fmt.Errorf("%s: wrong number of arguments", call.Function)
	}
	if len(call.Args) == 1 {
		e = call.Args[0]
	}
	reducer := &ast.Reducer{
		Op:       "Reducer",
		Operator: call.Function,
		Expr:     e,
	}
	return &ast.GroupByProc{
		Op:       "GroupByProc",
		Reducers: []ast.Assignment{{RHS: reducer}},
	}, nil
}

func eq(e ast.Expression, b field.Static) bool {
	a, ok := ast.DotExprToField(e)
	if !ok {
		return false
	}
	return a.Equal(b)
}

// SetGroupByProcInputSortDir examines p under the assumption that its input is
// sorted according to inputSortField and inputSortDir.  If p is an
// ast.GroupByProc and SetGroupByProcInputSortDir can determine that its first
// grouping key is inputSortField or an order-preserving function of
// inputSortField, SetGroupByProcInputSortDir sets ast.GroupByProc.InputSortDir
// to inputSortDir.  SetGroupByProcInputSortDir returns true if it determines
// that p's output will remain sorted according to inputSortField and
// inputSortDir; otherwise, it returns false.
func SetGroupByProcInputSortDir(p ast.Proc, inputSortField field.Static, inputSortDir int) bool {
	switch p := p.(type) {
	case *ast.CutProc:
		// Return true if the output record contains inputSortField.
		for _, f := range p.Fields {
			if eq(f.RHS, inputSortField) {
				return true
			}
		}
		return false
	case *ast.PickProc:
		// Return true if the output record contains inputSortField.
		for _, f := range p.Fields {
			if eq(f.RHS, inputSortField) {
				return true
			}
		}
		return false
	case *ast.DropProc:
		// Return true if the output record contains inputSortField.
		for _, e := range p.Fields {
			if eq(e, inputSortField) {
				return false
			}
		}
		return true
	case *ast.GroupByProc:
		// Set p.InputSortDir and return true if the first grouping key
		// is inputSortField or an order-preserving function of it.
		if len(p.Keys) > 0 && eq(p.Keys[0].LHS, inputSortField) {
			rhs, ok := ast.DotExprToField(p.Keys[0].RHS)
			if ok && rhs.Equal(inputSortField) {
				p.InputSortDir = inputSortDir
				return true
			}
			if expr, ok := p.Keys[0].RHS.(*ast.FunctionCall); ok {
				switch expr.Function {
				case "ceil", "floor", "round", "trunc":
					if len(expr.Args) == 0 {
						return false
					}
					arg0, ok := ast.DotExprToField(expr.Args[0])
					if ok && arg0.Equal(inputSortField) {
						p.InputSortDir = inputSortDir
						return true
					}
				}
			}
		}
		return false
	case *ast.PutProc:
		for _, c := range p.Clauses {
			lhs, ok := ast.DotExprToField(c.LHS)
			if ok && lhs.Equal(inputSortField) {
				return false
			}
		}
		return true
	case *ast.SequentialProc:
		for _, pp := range p.Procs {
			if !SetGroupByProcInputSortDir(pp, inputSortField, inputSortDir) {
				return false
			}
		}
		return true
	case *ast.FilterProc, *ast.HeadProc, *ast.PassProc, *ast.UniqProc, *ast.TailProc, *ast.FuseProc, *ast.ConstProc, *ast.TypeProc:
		return true
	default:
		return false
	}
}

func copyProcs(ps []ast.Proc) []ast.Proc {
	var copies []ast.Proc
	for _, p := range ps {
		copies = append(copies, copyProc(p))
	}
	return copies
}

func copyProc(p ast.Proc) ast.Proc {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	copy, err := ast.UnpackJSON(nil, b)
	if err != nil {
		panic(err)
	}
	return copy
}

func buildSplitFlowgraph(branch, tail []ast.Proc, mergeField field.Static, reverse bool, N int) (*ast.SequentialProc, bool) {
	if len(branch) == 0 {
		return &ast.SequentialProc{
			Op:    "SequentialProc",
			Procs: tail,
		}, false
	}
	if len(tail) == 0 && mergeField != nil {
		// Insert a pass tail in order to force a merge of the
		// parallel branches when compiling. (Trailing parallel branches are wired to
		// a mux output).
		tail = []ast.Proc{&ast.PassProc{Op: "PassProc"}}
	}
	pp := &ast.ParallelProc{
		Op:                "ParallelProc",
		Procs:             []ast.Proc{},
		MergeOrderField:   mergeField,
		MergeOrderReverse: reverse,
	}
	for i := 0; i < N; i++ {
		pp.Procs = append(pp.Procs, &ast.SequentialProc{
			Op:    "SequentialProc",
			Procs: copyProcs(branch),
		})
	}
	return &ast.SequentialProc{
		Op:    "SequentialProc",
		Procs: append([]ast.Proc{pp}, tail...),
	}, true
}

// IsParallelizable reports whether Parallelize can parallelize p when called
// with the same arguments.
func IsParallelizable(p ast.Proc, inputSortField field.Static, inputSortReversed bool) bool {
	_, ok := Parallelize(copyProc(p), 0, inputSortField, inputSortReversed)
	return ok
}

// Parallelize takes a sequential proc AST and tries to
// parallelize it by splitting as much as possible of the sequence
// into N parallel branches. The boolean return argument indicates
// whether the flowgraph could be parallelized.
func Parallelize(p ast.Proc, N int, inputSortField field.Static, inputSortReversed bool) (*ast.SequentialProc, bool) {
	seq := ensureSequentialProc(p)
	orderSensitiveTail := true
	for i := range seq.Procs {
		switch seq.Procs[i].(type) {
		case *ast.SortProc, *ast.GroupByProc:
			orderSensitiveTail = false
			break
		default:
			continue
		}
	}
	for i := range seq.Procs {
		switch p := seq.Procs[i].(type) {
		case *ast.FilterProc, *ast.PassProc, *ast.ConstProc, *ast.TypeProc:
			// Stateless procs: continue until we reach one of the procs below at
			// which point we'll either split the flowgraph or see we can't and return it as-is.
			continue
		case *ast.CutProc, *ast.PickProc:
			if inputSortField == nil || !orderSensitiveTail {
				continue
			}
			var fields []ast.Assignment
			if cut, ok := p.(*ast.CutProc); ok {
				fields = cut.Fields
			} else {
				fields = p.(*ast.PickProc).Fields
			}
			var found bool
			for _, f := range fields {
				fieldName, okField := ast.DotExprToField(f.RHS)
				lhs, okLHS := ast.DotExprToField(f.LHS)
				if okField && !fieldName.Equal(inputSortField) && okLHS && lhs.Equal(inputSortField) {
					return buildSplitFlowgraph(seq.Procs[0:i], seq.Procs[i:], inputSortField, inputSortReversed, N)
				}
				if okField && fieldName.Equal(inputSortField) && lhs == nil {
					found = true
				}
			}
			if !found {
				return buildSplitFlowgraph(seq.Procs[0:i], seq.Procs[i:], inputSortField, inputSortReversed, N)
			}
		case *ast.DropProc:
			if inputSortField == nil || !orderSensitiveTail {
				continue
			}
			for _, e := range p.Fields {
				if eq(e, inputSortField) {
					return buildSplitFlowgraph(seq.Procs[0:i], seq.Procs[i:], inputSortField, inputSortReversed, N)
				}
			}
			continue
		case *ast.PutProc:
			if inputSortField == nil || !orderSensitiveTail {
				continue
			}
			for _, c := range p.Clauses {
				if eq(c.LHS, inputSortField) {
					return buildSplitFlowgraph(seq.Procs[0:i], seq.Procs[i:], inputSortField, inputSortReversed, N)
				}
			}
			continue
		case *ast.RenameProc:
			if inputSortField == nil || !orderSensitiveTail {
				continue
			}
			for _, f := range p.Fields {
				if eq(f.LHS, inputSortField) {
					return buildSplitFlowgraph(seq.Procs[0:i], seq.Procs[i:], inputSortField, inputSortReversed, N)
				}
			}
		case *ast.GroupByProc:
			// To decompose the groupby, we split the flowgraph into branches that run up to and including a groupby,
			// followed by a post-merge groupby that composes the results.
			var mergeField field.Static
			if p.Duration.Seconds != 0 {
				// Group by time requires a time-ordered merge, irrespective of any upstream ordering.
				mergeField = field.New("ts")
			}
			branch := copyProcs(seq.Procs[0 : i+1])
			branch[len(branch)-1].(*ast.GroupByProc).EmitPart = true

			composerGroupBy := copyProcs([]ast.Proc{p})[0].(*ast.GroupByProc)
			composerGroupBy.ConsumePart = true

			return buildSplitFlowgraph(branch, append([]ast.Proc{composerGroupBy}, seq.Procs[i+1:]...), mergeField, inputSortReversed, N)
		case *ast.SortProc:
			dir := map[int]bool{-1: true, 1: false}[p.SortDir]
			if len(p.Fields) == 1 {
				// Single sort field: we can sort in each parallel branch, and then do an ordered merge.
				mergeField, ok := ast.DotExprToField(p.Fields[0])
				if !ok {
					return seq, false
				}
				return buildSplitFlowgraph(seq.Procs[0:i+1], seq.Procs[i+1:], mergeField, dir, N)
			} else {
				// Unknown or multiple sort fields: we sort after the merge point, which can be unordered.
				return buildSplitFlowgraph(seq.Procs[0:i], seq.Procs[i:], nil, dir, N)
			}
		case *ast.ParallelProc:
			return seq, false
		case *ast.HeadProc, *ast.TailProc:
			if inputSortField == nil {
				// Unknown order: we can't parallelize because we can't maintain this unknown order at the merge point.
				return seq, false
			}
			// put one head/tail on each parallel branch and one after the merge.
			return buildSplitFlowgraph(seq.Procs[0:i+1], seq.Procs[i:], inputSortField, inputSortReversed, N)
		case *ast.UniqProc, *ast.FuseProc:
			if inputSortField == nil {
				// Unknown order: we can't parallelize because we can't maintain this unknown order at the merge point.
				return seq, false
			}
			// Split all the upstream procs into parallel branches, then merge and continue with this and any remaining procs.
			return buildSplitFlowgraph(seq.Procs[0:i], seq.Procs[i:], inputSortField, inputSortReversed, N)
		case *ast.SequentialProc:
			return seq, false
			// XXX Joins can be parallelized but we need to write
			// the code to parallelize the flow graph, which is a bit
			// different from how group-bys are parallelized.
		case *ast.JoinProc:
			return seq, false
		default:
			panic("proc type not handled")
		}
	}
	// If we're here, we reached the end of the flowgraph without
	// coming across a merge-forcing proc. If inputs are sorted,
	// we can parallelize the entire chain and do an ordered
	// merge. Otherwise, no parallelization.
	if inputSortField == nil {
		return seq, false
	}
	return buildSplitFlowgraph(seq.Procs, nil, inputSortField, inputSortReversed, N)
}
