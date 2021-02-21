package kernel

import (
	"fmt"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

var _ zbuf.Filter = (*Filter)(nil)

// Filter wraps an ast.BooleanExpr and implements the zbuf.Filter interface
// so that scanners can generate filters and buffer filters from an AST without
// importing compiler (and causing an import loop).
type Filter struct {
	zctx *resolver.Context
	ast  ast.Expression
}

func NewFilter(zctx *resolver.Context, ast ast.Expression) *Filter {
	return &Filter{zctx, ast}
}

func (f *Filter) AsFilter() (expr.Filter, error) {
	if f == nil {
		return nil, nil
	}
	// XXX nil scope... when we implement global scope, the filters
	// will need access to it.
	return compileFilter(f.zctx, nil, f.ast)
}

func (f *Filter) AsBufferFilter() (*expr.BufferFilter, error) {
	if f == nil {
		return nil, nil
	}
	return compileBufferFilter(f.ast)
}

func (f *Filter) AST() ast.Expression {
	return f.ast
}

func (f *Filter) AsProc() ast.Proc {
	return ast.FilterToProc(f.ast)
}

func compileCompareField(zctx *resolver.Context, scope *Scope, e *ast.BinaryExpression) (expr.Filter, error) {
	if e.Operator == "in" {
		literal, ok := e.LHS.(*ast.Literal)
		if !ok {
			return nil, nil
		}
		// Check if RHS is a legit lval/field.
		if _, err := CompileLval(e.RHS); err != nil {
			return nil, nil
		}
		resolver, err := compileExpr(zctx, scope, e.RHS)
		if err != nil {
			return nil, err
		}
		eql, _ := expr.Comparison("=", *literal)
		comparison := expr.Contains(eql)
		return expr.Combine(resolver, comparison), nil
	}
	literal, ok := e.RHS.(*ast.Literal)
	if !ok {
		return nil, nil
	}
	comparison, err := expr.Comparison(e.Operator, *literal)
	if err != nil {
		// If this fails, return no match instead of the error and
		// let later-on code detect the error as this could be a
		// non-error situation that isn't a simple comparison.
		return nil, nil
	}
	// Check if LHS is a legit lval/field before compiling the expr.
	if _, err := CompileLval(e.LHS); err != nil {
		return nil, nil
	}
	resolver, err := compileExpr(zctx, scope, e.LHS)
	if err != nil {
		return nil, err
	}
	return expr.Combine(resolver, comparison), nil
}

func compileSearch(node *ast.Search) (expr.Filter, error) {
	if node.Value.Type == "regexp" || node.Value.Type == "net" {
		match, err := expr.Comparison("=", node.Value)
		if err != nil {
			return nil, err
		}
		contains := expr.Contains(match)
		pred := func(zv zng.Value) bool {
			return match(zv) || contains(zv)
		}

		return expr.EvalAny(pred, true), nil
	}

	if node.Value.Type == "string" {
		term, err := zng.TypeBstring.Parse([]byte(node.Value.Value))
		if err != nil {
			return nil, err
		}
		return expr.SearchRecordString(string(term)), nil
	}

	return expr.SearchRecordOther(node.Text, node.Value)
}

func compileFilter(zctx *resolver.Context, scope *Scope, node ast.Expression) (expr.Filter, error) {
	switch v := node.(type) {
	case *ast.UnaryExpression:
		if v.Operator != "!" {
			return nil, fmt.Errorf("unknown unary operator: %s", v.Operator)
		}
		e, err := compileFilter(zctx, scope, v.Operand)
		if err != nil {
			return nil, err
		}
		return expr.LogicalNot(e), nil

	case *ast.Literal:
		// This literal translation should happen elsewhere will
		// be fixed when we add ZSON literals to Z, e.g.,
		// ast.Literal.AsBool() etc methods.
		if v.Type != "bool" {
			return nil, fmt.Errorf("bad literal type in filter compiler: %s", v.Type)
		}
		var b bool
		switch v.Value {
		case "true":
			b = true
		case "false":
		default:
			return nil, fmt.Errorf("bad boolean value in ast.Literal: %s", v.Value)
		}
		return func(*zng.Record) bool { return b }, nil

	case *ast.Search:
		return compileSearch(v)

	case *ast.BinaryExpression:
		if v.Operator == "and" {
			left, err := compileFilter(zctx, scope, v.LHS)
			if err != nil {
				return nil, err
			}
			right, err := compileFilter(zctx, scope, v.RHS)
			if err != nil {
				return nil, err
			}
			return expr.LogicalAnd(left, right), nil
		}
		if v.Operator == "or" {
			left, err := compileFilter(zctx, scope, v.LHS)
			if err != nil {
				return nil, err
			}
			right, err := compileFilter(zctx, scope, v.RHS)
			if err != nil {
				return nil, err
			}
			return expr.LogicalOr(left, right), nil
		}
		if f, err := compileCompareField(zctx, scope, v); f != nil || err != nil {
			return f, err
		}
		return compilExprPredicate(zctx, scope, v)

	case *ast.FunctionCall:
		if f, err := compileCompareAny(v); f != nil || err != nil {
			return f, err
		}
		return compilExprPredicate(zctx, scope, v)

	default:
		return nil, fmt.Errorf("Filter AST unknown type: %v", v)
	}
}

func compilExprPredicate(zctx *resolver.Context, scope *Scope, e ast.Expression) (expr.Filter, error) {
	predicate, err := compileExpr(zctx, scope, e)
	if err != nil {
		return nil, err
	}
	return func(rec *zng.Record) bool {
		zv, err := predicate.Eval(rec)
		if err != nil {
			return false
		}
		if zv.Type == zng.TypeBool && zng.IsTrue(zv.Bytes) {
			return true
		}
		return false
	}, nil
}

func compileCompareAny(e *ast.FunctionCall) (expr.Filter, error) {
	literal, op, ok := isCompareAny(e)
	if !ok {
		return nil, nil
	}
	var pred expr.Boolean
	var err error
	if op == "in" {
		comparison, err := expr.Comparison("=", *literal)
		if err != nil {
			return nil, err
		}
		pred = expr.Contains(comparison)
	} else {
		pred, err = expr.Comparison(op, *literal)
		if err != nil {
			return nil, err
		}
	}
	return expr.EvalAny(pred, false), nil
}
