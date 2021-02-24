package semantic

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/field"
)

// semProc does a semantic analysis on a flowgraph to an
// intermediate representation that can be compiled into the runtime
// object.  Currently, it only replaces the group-by duration with
// a truncation call on the ts and replaces FunctionCall's in proc context
// with either a group-by or filter-proc based on the function's name.
func semProc(scope *Scope, p ast.Proc) (ast.Proc, error) {
	switch p := p.(type) {
	case *ast.GroupByProc:
		keys := p.Keys
		if duration := p.Duration.Seconds; duration != 0 {
			durationKey := ast.Assignment{
				Op:  "Assignment",
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
			keys = append([]ast.Assignment{durationKey}, keys...)
		}
		var err error
		keys, err = semAssignments(scope, keys)
		if err != nil {
			return nil, err
		}
		reducers, err := semAssignments(scope, p.Reducers)
		if err != nil {
			return nil, err
		}
		// Note: InputSortDir is copied in here but it's not meaningful
		// coming from a parser AST, only from a worker using the kernel DSL,
		// which is another reason why we need separate parser and kernel ASTs.
		// Said another way, we don't want to do semantic analysis on a worker AST
		// as we presume that work had already been done and we just need
		// to execute it.  For now, the worker only uses a filter expression
		// so this code path isn't hit yet, but it uses this same entry point
		// and it will soon do other stuff so we need to put in place the
		// separation... see issue #2163.  Also, we copy Duration even though
		// above we changed duration to the a trunc(ts) group-by key as the
		// Duration field is used later by the parallelization operator.
		return &ast.GroupByProc{
			Op:           "GroupByProc",
			Duration:     p.Duration,
			InputSortDir: p.InputSortDir,
			Limit:        p.Limit,
			Keys:         keys,
			Reducers:     reducers,
			ConsumePart:  p.ConsumePart,
			EmitPart:     p.EmitPart,
		}, nil
	case *ast.ParallelProc:
		var procs []ast.Proc
		for _, p := range p.Procs {
			if isConst(p) {
				continue
			}
			converted, err := semProc(scope, p)
			if err != nil {
				return nil, err
			}
			procs = append(procs, converted)
		}
		return &ast.ParallelProc{
			Op:                "ParallelProc",
			MergeOrderField:   p.MergeOrderField,
			MergeOrderReverse: p.MergeOrderReverse,
			Procs:             procs,
		}, nil
	case *ast.SequentialProc:
		var procs []ast.Proc
		for _, p := range p.Procs {
			if isConst(p) {
				continue
			}
			converted, err := semProc(scope, p)
			if err != nil {
				return nil, err
			}
			procs = append(procs, converted)
		}
		return &ast.SequentialProc{
			Op:    "SequentialProc",
			Procs: procs,
		}, nil
	case *ast.SwitchProc:
		var cases []ast.SwitchCase
		for k := range p.Cases {
			var err error
			tr, err := semProc(scope, p.Cases[k].Proc)
			if err != nil {
				return nil, err
			}
			f, err := semExpr(scope, p.Cases[k].Filter)
			if err != nil {
				return nil, err
			}
			cases = append(cases, ast.SwitchCase{Filter: f, Proc: tr})
		}
		return &ast.SwitchProc{
			Op:                "SwitchProc",
			Cases:             cases,
			MergeOrderField:   p.MergeOrderField,
			MergeOrderReverse: p.MergeOrderReverse,
		}, nil
	case *ast.FunctionCall:
		converted, err := convertFunctionProc(p)
		if err != nil {
			return nil, err
		}
		return semProc(scope, converted)
	case *ast.CutProc:
		assignments, err := semAssignments(scope, p.Fields)
		if err != nil {
			return nil, err
		}
		return &ast.CutProc{
			Op:     "CutProc",
			Fields: assignments,
		}, nil
	case *ast.PickProc:
		assignments, err := semAssignments(scope, p.Fields)
		if err != nil {
			return nil, err
		}
		return &ast.PickProc{
			Op:     "PickProc",
			Fields: assignments,
		}, nil
	case *ast.DropProc:
		fields, err := semFields(scope, p.Fields)
		if err != nil {
			return nil, fmt.Errorf("drop: %w", err)
		}
		if len(fields) == 0 {
			return nil, errors.New("drop: no fields given")
		}
		return &ast.DropProc{
			Op:     "DropProc",
			Fields: fields,
		}, nil
	case *ast.SortProc:
		fields, err := semExprs(scope, p.Fields)
		if err != nil {
			return nil, fmt.Errorf("sort: %w", err)
		}
		return &ast.SortProc{
			Op:         "SortProc",
			Fields:     fields,
			SortDir:    p.SortDir,
			NullsFirst: p.NullsFirst,
		}, nil
	case *ast.HeadProc:
		limit := p.Count
		if limit == 0 {
			limit = 1
		}
		return &ast.HeadProc{
			Op:    "HeadProc",
			Count: limit,
		}, nil
	case *ast.TailProc:
		limit := p.Count
		if limit == 0 {
			limit = 1
		}
		return &ast.TailProc{
			Op:    "TailProc",
			Count: limit,
		}, nil
	case *ast.UniqProc:
		return &ast.UniqProc{
			Op:    "UniqProc",
			Cflag: p.Cflag,
		}, nil
	case *ast.PassProc:
		return p, nil
	case *ast.FilterProc:
		f, err := semExpr(scope, p.Filter)
		if err != nil {
			return nil, err
		}
		return &ast.FilterProc{
			Op:     "FilterProc",
			Filter: f,
		}, nil
	case *ast.TopProc:
		fields, err := semFields(scope, p.Fields)
		if err != nil {
			return nil, fmt.Errorf("top: %w", err)
		}
		if len(fields) == 0 {
			return nil, errors.New("top: no fields given")
		}
		return &ast.TopProc{
			Fields: fields,
			Flush:  p.Flush,
			Limit:  p.Limit,
		}, nil
	case *ast.PutProc:
		assignments, err := semAssignments(scope, p.Clauses)
		if err != nil {
			return nil, err
		}
		return &ast.PutProc{
			Op:      "PutProc",
			Clauses: assignments,
		}, nil
	case *ast.RenameProc:
		var assignments []ast.Assignment
		for _, fa := range p.Fields {
			dst, err := semField(scope, fa.LHS)
			if err != nil {
				return nil, err
			}
			src, err := semField(scope, fa.RHS)
			if err != nil {
				return nil, err
			}
			dstField, ok := dst.(*ast.FieldPath)
			if !ok {
				return nil, errors.New("'rename' requires explicit field references")
			}
			srcField, ok := src.(*ast.FieldPath)
			if !ok {
				return nil, errors.New("'rename' requires explicit field references")
			}
			if len(dstField.Name) != len(srcField.Name) {
				return nil, fmt.Errorf("cannot rename %s to %s", src, dst)
			}
			// Check that the prefixes match and, if not, report first place
			// that they don't.
			for i := 0; i <= len(srcField.Name)-2; i++ {
				if srcField.Name[i] != dstField.Name[i] {
					return nil, fmt.Errorf("cannot rename %s to %s (differ in %s vs %s)", srcField, dstField, srcField.Name[i], dstField.Name[i])
				}
			}
			assignments = append(assignments, ast.Assignment{"Assignment", dst, src})
		}
		return &ast.RenameProc{
			Op:     "RenameProc",
			Fields: assignments,
		}, nil
	case *ast.FuseProc:
		return p, nil
	case *ast.JoinProc:
		leftKey, err := semExpr(scope, p.LeftKey)
		if err != nil {
			return nil, err
		}
		rightKey, err := semExpr(scope, p.RightKey)
		if err != nil {
			return nil, err
		}
		assignments, err := semAssignments(scope, p.Clauses)
		if err != nil {
			return nil, err
		}
		return &ast.JoinProc{
			Op:       "JoinProc",
			Kind:     p.Kind,
			LeftKey:  leftKey,
			RightKey: rightKey,
			Clauses:  assignments,
		}, nil
	case *ast.SqlExpression:
		converted, err := convertSQLProc(scope, p)
		if err != nil {
			return nil, err
		}
		// The conversion may be a group-by so we recursively
		// invoke the transformation here...
		if converted == nil {
			return nil, errors.New("unable to covert SQL expression to Z")
		}
		return semProc(scope, converted)

	case *ast.FieldCutter, *ast.TypeSplitter:
		return p, nil
	}
	return nil, fmt.Errorf("semantic transform: unknown AST type: %v", p)
}

func semConsts(consts []ast.Proc, scope *Scope, p ast.Proc) ([]ast.Proc, error) {
	switch p := p.(type) {
	case *ast.SequentialProc:
		for _, p := range p.Procs {
			var err error
			consts, err = semConsts(consts, scope, p)
			if err != nil {
				return nil, err
			}
		}
	case *ast.ParallelProc:
		for _, p := range p.Procs {
			var err error
			consts, err = semConsts(consts, scope, p)
			if err != nil {
				return nil, err
			}
		}
	case *ast.TypeProc:
		typ, err := semType(scope, p.Type)
		if err != nil {
			return nil, err
		}
		converted := &ast.TypeProc{
			Op:   "TypeProc",
			Name: p.Name,
			Type: typ,
		}
		scope.Bind(p.Name, converted)
		return append(consts, converted), nil
	case *ast.ConstProc:
		e, err := semExpr(scope, p.Expr)
		if err != nil {
			return nil, err
		}
		converted := &ast.ConstProc{
			Op:   "ConstProc",
			Name: p.Name,
			Expr: e,
		}
		scope.Bind(p.Name, converted)
		return append(consts, converted), nil
	}
	return consts, nil
}

func isConst(p ast.Proc) bool {
	switch p.(type) {
	case *ast.ConstProc, *ast.TypeProc:
		return true
	}
	return false
}
