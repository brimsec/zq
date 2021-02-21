package kernel

import (
	"errors"
	"fmt"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/proc"
	"github.com/brimsec/zq/proc/combine"
	"github.com/brimsec/zq/proc/filter"
	"github.com/brimsec/zq/proc/fuse"
	"github.com/brimsec/zq/proc/head"
	"github.com/brimsec/zq/proc/join"
	"github.com/brimsec/zq/proc/merge"
	"github.com/brimsec/zq/proc/pass"
	"github.com/brimsec/zq/proc/put"
	"github.com/brimsec/zq/proc/rename"
	"github.com/brimsec/zq/proc/sort"
	"github.com/brimsec/zq/proc/split"
	"github.com/brimsec/zq/proc/switcher"
	"github.com/brimsec/zq/proc/tail"
	"github.com/brimsec/zq/proc/top"
	"github.com/brimsec/zq/proc/uniq"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zson"
)

var ErrJoinParents = errors.New("join requires two upstream parallel query paths")

type Hook func(ast.Proc, *proc.Context, proc.Interface) (proc.Interface, error)

func isContainerProc(node ast.Proc) bool {
	if _, ok := node.(*ast.SequentialProc); ok {
		return true
	}
	if _, ok := node.(*ast.ParallelProc); ok {
		return true
	}
	return false
}

func compileProc(custom Hook, node ast.Proc, pctx *proc.Context, scope *Scope, parent proc.Interface) (proc.Interface, error) {
	if custom != nil {
		// XXX custom should take scope
		p, err := custom(node, pctx, parent)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, err
		}
	}
	switch v := node.(type) {
	case *ast.GroupByProc:
		return compileGroupBy(pctx, scope, parent, v)

	case *ast.CutProc:
		assignments, err := compileAssignments(v.Fields, pctx.TypeContext, scope)
		if err != nil {
			return nil, err
		}
		lhs, rhs := splitAssignments(assignments)
		cutter, err := expr.NewCutter(pctx.TypeContext, lhs, rhs)
		if err != nil {
			return nil, err
		}
		cutter.AllowPartialCuts()
		return proc.FromFunction(pctx, parent, cutter, "cut"), nil

	case *ast.PickProc:
		assignments, err := compileAssignments(v.Fields, pctx.TypeContext, scope)
		if err != nil {
			return nil, err
		}
		lhs, rhs := splitAssignments(assignments)
		cutter, err := expr.NewCutter(pctx.TypeContext, lhs, rhs)
		if err != nil {
			return nil, err
		}
		return proc.FromFunction(pctx, parent, cutter, "pick"), nil

	case *ast.DropProc:
		if len(v.Fields) == 0 {
			return nil, errors.New("drop: no fields given")
		}
		fields := make([]field.Static, 0, len(v.Fields))
		for _, e := range v.Fields {
			field, ok := ast.DotExprToField(e)
			if !ok {
				return nil, errors.New("drop: arg not a field")
			}
			fields = append(fields, field)
		}
		dropper := expr.NewDropper(pctx.TypeContext, fields)
		return proc.FromFunction(pctx, parent, dropper, "drop"), nil

	case *ast.SortProc:
		fields, err := CompileExprs(pctx.TypeContext, scope, v.Fields)
		if err != nil {
			return nil, err
		}
		sort, err := sort.New(pctx, parent, fields, v.SortDir, v.NullsFirst)
		if err != nil {
			return nil, fmt.Errorf("compiling sort: %w", err)
		}
		return sort, nil

	case *ast.HeadProc:
		limit := v.Count
		if limit == 0 {
			limit = 1
		}
		return head.New(parent, limit), nil

	case *ast.TailProc:
		limit := v.Count
		if limit == 0 {
			limit = 1
		}
		return tail.New(parent, limit), nil

	case *ast.UniqProc:
		return uniq.New(pctx, parent, v.Cflag), nil

	case *ast.PassProc:
		return pass.New(parent), nil

	case *ast.FilterProc:
		f, err := compileFilter(pctx.TypeContext, scope, v.Filter)
		if err != nil {
			return nil, fmt.Errorf("compiling filter: %w", err)
		}
		return filter.New(parent, f), nil

	case *ast.TopProc:
		fields, err := CompileExprs(pctx.TypeContext, scope, v.Fields)
		if err != nil {
			return nil, fmt.Errorf("compiling top: %w", err)
		}
		return top.New(parent, v.Limit, fields, v.Flush), nil

	case *ast.PutProc:
		clauses, err := compileAssignments(v.Clauses, pctx.TypeContext, scope)
		if err != nil {
			return nil, err
		}
		put, err := put.New(pctx, parent, clauses)
		if err != nil {
			return nil, err
		}
		return put, nil

	case *ast.RenameProc:
		var srcs, dsts []field.Static
		for _, fa := range v.Fields {
			dst, err := CompileLval(fa.LHS)
			if err != nil {
				return nil, err
			}
			// We call CompileLval on the RHS because renames are
			// restricted to dotted field name expressions.
			src, err := CompileLval(fa.RHS)
			if err != nil {
				return nil, err
			}
			if len(dst) != len(src) {
				return nil, fmt.Errorf("cannot rename %s to %s", src, dst)
			}
			// Check that the prefixes match and, if not, report first place
			// that they don't.
			for i := 0; i <= len(src)-2; i++ {
				if src[i] != dst[i] {
					return nil, fmt.Errorf("cannot rename %s to %s (differ in %s vs %s)", src, dst, src[i], dst[i])
				}
			}
			dsts = append(dsts, dst)
			srcs = append(srcs, src)
		}
		renamer := rename.NewFunction(pctx.TypeContext, srcs, dsts)
		return proc.FromFunction(pctx, parent, renamer, "rename"), nil

	case *ast.FuseProc:
		return fuse.New(pctx, parent)

	case *ast.FunctionCall:
		return nil, errors.New("internal error: semantic analyzer should have converted function in proc context to filter or group-by")

	case *ast.JoinProc:
		return nil, ErrJoinParents

	default:
		return nil, fmt.Errorf("unknown AST type: %v", v)

	}
}

func compileAssignments(assignments []ast.Assignment, zctx *resolver.Context, scope *Scope) ([]expr.Assignment, error) {
	keys := make([]expr.Assignment, 0, len(assignments))
	for _, assignment := range assignments {
		a, err := CompileAssignment(zctx, scope, &assignment)
		if err != nil {
			return nil, err
		}
		keys = append(keys, a)
	}
	return keys, nil
}

func splitAssignments(assignments []expr.Assignment) ([]field.Static, []expr.Evaluator) {
	n := len(assignments)
	lhs := make([]field.Static, 0, n)
	rhs := make([]expr.Evaluator, 0, n)
	for _, a := range assignments {
		lhs = append(lhs, a.LHS)
		rhs = append(rhs, a.RHS)
	}
	return lhs, rhs
}

func enteringJoin(nodes []ast.Proc) bool {
	var ok bool
	if len(nodes) > 0 {
		_, ok = nodes[0].(*ast.JoinProc)
	}
	return ok
}

func mergeInfo(p ast.Proc) (field.Static, bool) {
	if par, ok := p.(*ast.ParallelProc); ok {
		return par.MergeOrderField, par.MergeOrderReverse
	}
	swi := p.(*ast.SwitchProc)
	return swi.MergeOrderField, swi.MergeOrderReverse
}

func compileSequential(custom Hook, nodes []ast.Proc, pctx *proc.Context, scope *Scope, parents []proc.Interface) ([]proc.Interface, error) {
	node := nodes[0]
	parents, err := Compile(custom, node, pctx, scope, parents)
	if err != nil {
		return nil, err
	}
	// merge unless we're at the end of the chain,
	// in which case the output layer will mux
	// into channels.
	if len(nodes) == 1 {
		return parents, nil
	}
	if len(parents) > 1 && !enteringJoin(nodes[1:]) {
		var parent proc.Interface
		orderField, orderReverse := mergeInfo(node)
		if orderField != nil {
			cmp := zbuf.NewCompareFn(orderField, orderReverse)
			parent = merge.New(pctx, parents, cmp)
		} else {
			parent = combine.New(pctx, parents)
		}
		parents = []proc.Interface{parent}
	}
	return compileSequential(custom, nodes[1:], pctx, scope, parents)
}

func compileParallel(custom Hook, pp *ast.ParallelProc, c *proc.Context, scope *Scope, parents []proc.Interface) ([]proc.Interface, error) {
	n := len(pp.Procs)
	if len(parents) == 1 {
		// Single parent: insert a splitter and wire to each branch.
		splitter := split.New(parents[0])
		parents = []proc.Interface{}
		for k := 0; k < n; k++ {
			sc := splitter.NewProc()
			parents = append(parents, sc)
		}
	}
	if len(parents) != n {
		return nil, fmt.Errorf("proc.CompileProc: %d parents for parallel proc with %d branches", len(parents), len(pp.Procs))
	}
	var procs []proc.Interface
	for k := 0; k < n; k++ {
		proc, err := Compile(custom, pp.Procs[k], c, scope, []proc.Interface{parents[k]})
		if err != nil {
			return nil, err
		}
		procs = append(procs, proc...)
	}
	return procs, nil
}

func compileSwitch(custom Hook, pp *ast.SwitchProc, pctx *proc.Context, scope *Scope, parents []proc.Interface) ([]proc.Interface, error) {
	n := len(pp.Cases)
	if len(parents) == 1 {
		// Single parent: insert a switcher and wire to each branch.
		switcher := switcher.New(parents[0])
		parents = []proc.Interface{}
		for _, c := range pp.Cases {
			f, err := compileFilter(pctx.TypeContext, scope, c.Filter)
			if err != nil {
				return nil, fmt.Errorf("compiling switch case filter: %w", err)
			}
			sc := switcher.NewProc(f)
			parents = append(parents, sc)
		}
	}
	if len(parents) != n {
		return nil, fmt.Errorf("proc.compileSwitch: %d parents for switch proc with %d branches", len(parents), len(pp.Cases))
	}
	var procs []proc.Interface
	for k := 0; k < n; k++ {
		proc, err := Compile(custom, pp.Cases[k].Proc, pctx, scope, []proc.Interface{parents[k]})
		if err != nil {
			return nil, err
		}
		procs = append(procs, proc...)
	}
	return procs, nil
}

// Compile compiles an AST into a graph of Procs, and returns
// the leaves.  A custom compiler hook can be included and it will be tried first
// for each node encountered during the compilation.
func Compile(custom Hook, node ast.Proc, pctx *proc.Context, scope *Scope, parents []proc.Interface) ([]proc.Interface, error) {
	if len(parents) == 0 {
		return nil, errors.New("no parents")
	}
	if scope == nil {
		// Outermost caller should pass in global scope object.  If nil,
		// we assume no global context and allocate a fresh, empty scope.
		scope = newScope()
		scope.Enter()
	}
	switch node := node.(type) {
	case *ast.SequentialProc:
		if len(node.Procs) == 0 {
			return nil, errors.New("sequential proc without procs")
		}
		procs, err := compileConsts(pctx.TypeContext, scope, node.Procs)
		if err != nil {
			return nil, err
		}
		return compileSequential(custom, procs, pctx, scope, parents)

	case *ast.ParallelProc:
		return compileParallel(custom, node, pctx, scope, parents)

	case *ast.SwitchProc:
		return compileSwitch(custom, node, pctx, scope, parents)

	case *ast.JoinProc:
		if len(parents) != 2 {
			return nil, ErrJoinParents
		}
		assignments, err := compileAssignments(node.Clauses, pctx.TypeContext, scope)
		if err != nil {
			return nil, err
		}
		lhs, rhs := splitAssignments(assignments)
		leftKey, err := compileExpr(pctx.TypeContext, scope, node.LeftKey)
		if err != nil {
			return nil, err
		}
		rightKey, err := compileExpr(pctx.TypeContext, scope, node.RightKey)
		if err != nil {
			return nil, err
		}
		join, err := join.New(pctx, parents[0], parents[1], leftKey, rightKey, lhs, rhs)
		if err != nil {
			return nil, err
		}
		return []proc.Interface{join}, nil

	default:
		if len(parents) > 1 {
			return nil, fmt.Errorf("ast type %v cannot have multiple parents", node)
		}
		p, err := compileProc(custom, node, pctx, scope, parents[0])
		return []proc.Interface{p}, err
	}
}

func compileConsts(zctx *resolver.Context, scope *Scope, procs []ast.Proc) ([]ast.Proc, error) {
	for k, p := range procs {
		switch p := p.(type) {
		case *ast.ConstProc:
			e, err := compileExpr(zctx, scope, p.Expr)
			if err != nil {
				return nil, err
			}
			typ, err := zctx.LookupTypeRecord([]zng.Column{})
			if err != nil {
				return nil, err
			}
			rec := zng.NewRecord(typ, nil)
			zv, err := e.Eval(rec)
			if err != nil {
				if err == zng.ErrMissing {
					err = fmt.Errorf("cannot resolve const '%s' at compile time", p.Name)
				}
				return nil, err
			}
			scope.Bind(p.Name, &zv)

		case *ast.TypeProc:
			name := p.Name
			typ, err := zson.TranslateType(zctx, p.Type)
			if err != nil {
				return nil, err
			}
			alias, err := zctx.LookupTypeAlias(name, typ)
			if err != nil {
				return nil, err
			}
			zv := zng.NewTypeType(alias)
			scope.Bind(name, &zv)

		default:
			return procs[k:], nil
		}
	}
	return nil, nil
}
