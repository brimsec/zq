package kernel

import (
	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/zng"
)

// compileBufferFilter tries to return a BufferFilter for e such that the
// BufferFilter's Eval method returns true for any byte slice containing the ZNG
// encoding of a record matching e. (It may also return true for some byte
// slices that do not match.) compileBufferFilter returns a nil pointer and nil
// error if it cannot construct a useful filter.
func compileBufferFilter(e ast.Expression) (*expr.BufferFilter, error) {
	switch e := e.(type) {
	case *ast.FunctionCall:
		if literal, op, ok := isCompareAny(e); ok && (op == "=" || op == "in") {
			return newBufferFilterForLiteral(*literal)
		}
		return nil, nil
	case *ast.BinaryExpression:
		if literal, _ := isFieldEqualOrIn(e); literal != nil {
			return newBufferFilterForLiteral(*literal)
		}
		if e.Operator == "and" {
			left, err := compileBufferFilter(e.LHS)
			if err != nil {
				return nil, err
			}
			right, err := compileBufferFilter(e.RHS)
			if err != nil {
				return nil, err
			}
			if left == nil {
				return right, nil
			}
			if right == nil {
				return left, nil
			}
			return expr.NewAndBufferFilter(left, right), nil
		}
		if e.Operator == "or" {
			left, err := compileBufferFilter(e.LHS)
			if err != nil {
				return nil, err
			}
			right, err := compileBufferFilter(e.RHS)
			if left == nil || right == nil || err != nil {
				return nil, err
			}
			return expr.NewOrBufferFilter(left, right), nil
		}
		return nil, nil
	case *ast.Search:
		if e.Value.Type == "net" || e.Value.Type == "regexp" {
			return nil, nil
		}
		if e.Value.Type == "string" {
			pattern, err := zng.TypeBstring.Parse([]byte(e.Value.Value))
			if err != nil {
				return nil, err
			}
			left := expr.NewBufferFilterForStringCase(string(pattern))
			if left == nil {
				return nil, nil
			}
			right := expr.NewFieldNameFinder(string(pattern))
			return expr.NewOrBufferFilter(left, right), nil
		}
		left := expr.NewBufferFilterForStringCase(e.Text)
		right, err := newBufferFilterForLiteral(e.Value)
		if left == nil || right == nil || err != nil {
			return nil, err
		}
		return expr.NewOrBufferFilter(left, right), nil
	default:
		return nil, nil
	}
}

func isIdOrRoot(e ast.Expression) bool {
	if _, ok := e.(*ast.Identifier); ok {
		return true
	}
	_, ok := e.(*ast.RootRecord)
	return ok
}

func isRootField(e ast.Expression) bool {
	if isIdOrRoot(e) {
		return true
	}
	b, ok := e.(*ast.BinaryExpression)
	if !ok || b.Operator != "." {
		return false
	}
	if _, ok := b.LHS.(*ast.RootRecord); !ok {
		return false
	}
	_, ok = b.RHS.(*ast.Identifier)
	return ok
}

func isFieldEqualOrIn(e *ast.BinaryExpression) (*ast.Literal, string) {
	if isRootField(e.LHS) && e.Operator == "=" {
		if literal, ok := e.RHS.(*ast.Literal); ok {
			return literal, "="
		}
	} else if isRootField(e.RHS) && e.Operator == "in" {
		if literal, ok := e.LHS.(*ast.Literal); ok && literal.Type != "net" {
			return literal, "in"
		}
	}
	return nil, ""
}

func isCompareAny(call *ast.FunctionCall) (*ast.Literal, string, bool) {
	if call.Function != "or" || len(call.Args) != 1 {
		return nil, "", false
	}
	e, ok := call.Args[0].(*ast.BinaryExpression)
	if !ok || e.Operator != "@" || !isSelectAll(e.LHS) {
		return nil, "", false
	}
	// expression must be a comparison or an in operator
	apply, ok := e.RHS.(*ast.FunctionCall)
	if !ok || len(apply.Args) != 1 {
		return nil, "", false
	}
	pred, ok := apply.Args[0].(*ast.BinaryExpression)
	if !ok {
		return nil, "", false
	}
	if pred.Operator == "=" {
		if !isDollar(pred.LHS) {
			return nil, "", false
		}
		if rhs, ok := pred.RHS.(*ast.Literal); ok && rhs.Type != "net" {
			return rhs, pred.Operator, true
		}
	} else if pred.Operator == "in" {
		if !isDollar(pred.RHS) {
			return nil, "", false
		}
		if lhs, ok := pred.LHS.(*ast.Literal); ok && lhs.Type != "net" {
			return lhs, pred.Operator, true
		}
	}
	return nil, "", false
}

func isSelectAll(e ast.Expression) bool {
	s, ok := e.(*ast.SelectExpression)
	if !ok || len(s.Selectors) != 1 {
		return false
	}
	_, ok = s.Selectors[0].(*ast.RootRecord)
	return ok
}

func isDollar(e ast.Expression) bool {
	id, ok := e.(*ast.Identifier)
	if !ok {
		return false
	}
	return id.Name == "$"
}

func newBufferFilterForLiteral(l ast.Literal) (*expr.BufferFilter, error) {
	switch l.Type {
	case "bool", "byte", "int16", "uint16", "int32", "uint32", "int64", "uint64", "float64", "time", "duration":
		// These are all comparable, so they can require up to three
		// patterns: float, varint, and uvarint.
		return nil, nil
	case "null":
		return nil, nil
	case "regexp":
		// Could try to extract a pattern (e.g., "efg" from "(ab|cd)(efg)+[hi]").
		return nil, nil
	case "string":
		// Match the behavior of zng.ParseLiteral.
		l.Type = "bstring"
	}
	v, err := zng.Parse(l)
	if err != nil {
		return nil, err
	}
	// We're looking for a complete ZNG value, so we can lengthen the
	// pattern by calling Encode to add a tag.
	pattern := string(v.Encode(nil))
	return expr.NewBufferFilterForString(pattern), nil
}
