package semantic

import (
	"errors"
	"fmt"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/expr/agg"
)

func semExpr(scope *Scope, e ast.Expression) (ast.Expression, error) {
	switch e := e.(type) {
	case nil:
		return nil, errors.New("semantic analysis: illegal null value encountered in AST")
	case *ast.Literal:
		if e.Type == "regexp" {
			if _, err := expr.CheckRegexp(e.Value); err != nil {
				return nil, err
			}
		}
		return e, nil
	case *ast.Identifier:
		// We use static scoping here to see if an identifier is
		// a "var" reference to the name or a field access
		// and transform the ast node appropriately.  The semantic AST
		// should have no Identifiers in it as they should all be
		// resolved one way or another.
		if ref := scope.Lookup(e.Name); ref != nil {
			// For now, this could only be a literal but
			// it may refer to other data types down the
			// road so we call it a "ref" for now.
			return &ast.Ref{"Ref", e.Name}, nil
		}
		if e.Name == "$" {
			return &ast.Ref{"Ref", "$"}, nil
		}
		return semField(scope, e)
	case *ast.RootRecord:
		return semField(scope, e)
	case *ast.Search:
		return e, nil
	case *ast.UnaryExpression:
		expr, err := semExpr(scope, e.Operand)
		if err != nil {
			return nil, err
		}
		return &ast.UnaryExpression{
			Op:       "UnaryExpr",
			Operator: e.Operator,
			Operand:  expr,
		}, nil
	case *ast.SelectExpression:
		return nil, errors.New("select expression found outside of generator context")
	case *ast.BinaryExpression:
		return semBinary(scope, e)
	case *ast.ConditionalExpression:
		cond, err := semExpr(scope, e.Condition)
		if err != nil {
			return nil, err
		}
		thenExpr, err := semExpr(scope, e.Then)
		if err != nil {
			return nil, err
		}
		elseExpr, err := semExpr(scope, e.Else)
		if err != nil {
			return nil, err
		}
		return &ast.ConditionalExpression{
			Op:        "ConditionalExpr",
			Condition: cond,
			Then:      thenExpr,
			Else:      elseExpr,
		}, nil
	case *ast.FunctionCall:
		return semCall(scope, e)
	case *ast.CastExpression:
		expr, err := semExpr(scope, e.Expr)
		if err != nil {
			return nil, err
		}
		return &ast.CastExpression{
			Op:   "CastExpr",
			Expr: expr,
			Type: e.Type, //XXX
		}, nil
	case *ast.TypeValue:
		tv, err := semType(scope, e.Value)
		if err != nil {
			return nil, err
		}
		return &ast.TypeValue{
			Op:    "TypeValue",
			Value: tv,
		}, nil
	case *ast.Reducer:
		expr, err := semExprNullable(scope, e.Expr)
		if err != nil {
			return nil, err
		}
		if expr == nil && e.Operator != "count" {
			return nil, fmt.Errorf("aggregator '%s' requires argument", e.Operator)
		}
		where, err := semExprNullable(scope, e.Where)
		if err != nil {
			return nil, err
		}
		return &ast.Reducer{
			Op:       "Reducer",
			Operator: e.Operator,
			Expr:     expr,
			Where:    where,
		}, nil
	}
	return nil, fmt.Errorf("invalid expression type %T", e)
}

func semBinary(scope *Scope, e *ast.BinaryExpression) (ast.Expression, error) {
	op := e.Operator
	if op == "." {
		return semField(scope, e)
	}
	if slice, ok := e.RHS.(*ast.BinaryExpression); ok && slice.Operator == ":" {
		if op != "[" {
			return nil, errors.New("slice outside of index operator")
		}
		ref, err := semExpr(scope, e.LHS)
		if err != nil {
			return nil, err
		}
		slice, err := semSlice(scope, slice)
		if err != nil {
			return nil, err
		}
		return &ast.BinaryExpression{
			Op:       "BinaryExpr",
			Operator: "[",
			LHS:      ref,
			RHS:      slice,
		}, nil
	}
	lhs, err := semExpr(scope, e.LHS)
	if err != nil {
		return nil, err
	}
	rhs, err := semExpr(scope, e.RHS)
	if err != nil {
		return nil, err
	}
	return &ast.BinaryExpression{
		Op:       "BinaryExpr",
		Operator: e.Operator,
		LHS:      lhs,
		RHS:      rhs,
	}, nil
}

func semSlice(scope *Scope, slice *ast.BinaryExpression) (*ast.BinaryExpression, error) {
	sliceFrom, err := semExprNullable(scope, slice.LHS)
	if err != nil {
		return nil, err
	}
	sliceTo, err := semExprNullable(scope, slice.RHS)
	if err != nil {
		return nil, err
	}
	return &ast.BinaryExpression{
		Op:       "BinaryExpr",
		Operator: ":",
		LHS:      sliceFrom,
		RHS:      sliceTo,
	}, nil
}

func semExprNullable(scope *Scope, e ast.Expression) (ast.Expression, error) {
	if e == nil {
		return nil, nil
	}
	return semExpr(scope, e)
}

func semCall(scope *Scope, call *ast.FunctionCall) (ast.Expression, error) {
	if e, err := semSequence(scope, call); e != nil || err != nil {
		return e, err
	}
	exprs, err := semExprs(scope, call.Args)
	if err != nil {
		return nil, fmt.Errorf("%s: bad argument: %w", call.Function, err)
	}
	return &ast.FunctionCall{
		Op:       "FunctionCall",
		Function: call.Function,
		Args:     exprs,
	}, nil
}

func semSequence(scope *Scope, call *ast.FunctionCall) (*ast.SeqExpr, error) {
	if len(call.Args) != 1 {
		return nil, nil
	}
	sel, ok := call.Args[0].(*ast.SelectExpression)
	if !ok {
		return nil, nil
	}
	_, err := agg.NewPattern(call.Function)
	if err != nil {
		return nil, nil
	}
	selectors, err := semExprs(scope, sel.Selectors)
	if err != nil {
		return nil, nil
	}
	var methods []ast.Method
	for _, call := range sel.Methods {
		m, err := semMethod(scope, call)
		if err != nil {
			return nil, err
		}
		methods = append(methods, *m)
	}
	return &ast.SeqExpr{
		Op:        "SeqExpr",
		Name:      call.Function,
		Selectors: selectors,
		Methods:   methods,
	}, nil
}

func semMethod(scope *Scope, call ast.FunctionCall) (*ast.Method, error) {
	switch call.Function {
	case "map":
		if len(call.Args) != 1 {
			return nil, errors.New("map() method requires one argument")
		}
		scope.Enter()
		defer scope.Exit()
		e, err := semExpr(scope, call.Args[0])
		scope.Bind("$", nil)
		if err != nil {
			return nil, err
		}
		return &ast.Method{Name: "map", Args: []ast.Expression{e}}, nil
	case "filter":
		if len(call.Args) != 1 {
			return nil, errors.New("filter() method requires one argument")
		}
		scope.Enter()
		defer scope.Exit()
		scope.Bind("$", nil)
		e, err := semExpr(scope, call.Args[0])
		if err != nil {
			return nil, err
		}
		return &ast.Method{Name: "filter", Args: []ast.Expression{e}}, nil
	default:
		return nil, fmt.Errorf("uknown method: %s", call.Function)
	}
}

func semExprs(scope *Scope, in []ast.Expression) ([]ast.Expression, error) {
	exprs := make([]ast.Expression, 0, len(in))
	for _, e := range in {
		expr, err := semExpr(scope, e)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, expr)
	}
	return exprs, nil
}

func semAssignments(scope *Scope, assignments []ast.Assignment) ([]ast.Assignment, error) {
	out := make([]ast.Assignment, 0, len(assignments))
	for _, e := range assignments {
		a, err := semAssignment(scope, e)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func semAssignment(scope *Scope, a ast.Assignment) (ast.Assignment, error) {
	rhs, err := semExpr(scope, a.RHS)
	if err != nil {
		return ast.Assignment{}, fmt.Errorf("rhs of assigment expression: %w", err)
	}
	var lhs ast.Expression
	if a.LHS != nil {
		// XXX currently only support explicit field lvals
		// (i.e., no assignments to array elements etc... instead
		// you create a new array with modified contends)
		lhs, err = semField(scope, a.LHS)
		if err != nil {
			return ast.Assignment{}, fmt.Errorf("lhs of assigment expression: %w", err)
		}
	} else if call, ok := a.RHS.(*ast.FunctionCall); ok {
		lhs = &ast.FieldPath{"FieldPath", []string{call.Function}}
	} else if r, ok := a.RHS.(*ast.Reducer); ok {
		lhs = &ast.FieldPath{"FieldPath", []string{r.Operator}}
	} else if _, ok := a.RHS.(*ast.RootRecord); ok {
		lhs = &ast.FieldPath{"FieldPath", []string{"."}}
	} else {
		lhs, err = semField(scope, a.RHS)
		if err != nil {
			return ast.Assignment{}, errors.New("assignment name could not be inferred from rhs expression")
		}
	}
	return ast.Assignment{"Assignment", lhs, rhs}, nil
}

func semFields(scope *Scope, exprs []ast.Expression) ([]ast.Expression, error) {
	fields := make([]ast.Expression, 0, len(exprs))
	for _, e := range exprs {
		f, err := semField(scope, e)
		if err != nil {
			return nil, err
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// semField checks that an expression is a field refernce and converts it
// to a field path if possible.  It will convert any references to Refs.
func semField(scope *Scope, e ast.Expression) (ast.Expression, error) {
	switch e := e.(type) {
	case *ast.BinaryExpression:
		if e.Operator == "." {
			lhs, err := semField(scope, e.LHS)
			if err != nil {
				return nil, err
			}
			id, ok := e.RHS.(*ast.Identifier)
			if !ok {
				return nil, errors.New("RHS of dot operator is not an identifier")
			}
			if lhs, ok := lhs.(*ast.FieldPath); ok {
				lhs.Name = append(lhs.Name, id.Name)
				return lhs, nil
			}
			return &ast.BinaryExpression{
				Op:       "BinaryExpr",
				Operator: ".",
				LHS:      lhs,
				RHS:      id,
			}, nil
		}
		if e.Operator == "[" {
			lhs, err := semField(scope, e.LHS)
			if err != nil {
				return nil, err
			}
			rhs, err := semExpr(scope, e.RHS)
			if err != nil {
				return nil, err
			}
			return &ast.BinaryExpression{
				Op:       "BinaryExpr",
				Operator: "[",
				LHS:      lhs,
				RHS:      rhs,
			}, nil
		}
	case *ast.Identifier:
		if scope.Lookup(e.Name) != nil {
			// For now, this could only be a literal but
			// it may refer to other data types down the
			// road so we call it a "ref" for now.
			return &ast.Ref{"Ref", e.Name}, nil
		}
		if e.Name == "$" {
			return &ast.Ref{"Ref", "$"}, nil
		}
		return &ast.FieldPath{Op: "FieldPath", Name: []string{e.Name}}, nil
	case *ast.RootRecord:
		return &ast.FieldPath{Op: "FieldPath", Name: []string{}}, nil
	}
	// This includes a null Expr, which can happen if the AST is missing
	// a field or sets it to null.
	return nil, errors.New("expression is not a field reference.")
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
		Op: "GroupByProc",
		Reducers: []ast.Assignment{
			{
				Op:  "Assignment",
				RHS: reducer,
			},
		},
	}, nil
}
