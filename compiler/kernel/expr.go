package kernel

import (
	"errors"
	"fmt"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/expr/agg"
	"github.com/brimsec/zq/expr/function"
	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zson"
)

// TestCompileExpr provides an exported entry point for unit tests
// to compile expressions (e.g., as is used by expr/expr_test.go).
func TestCompileExpr(zctx *resolver.Context, node ast.Expression) (expr.Evaluator, error) {
	return compileExpr(zctx, nil, node)
}

// compileExpr compiles the given Expression into an object
// that evaluates the expression against a provided Record.  It returns an
// error if compilation fails for any reason.
//
// This is the "intepreted slow path" of the analytics engine.  Because it
// handles dynamic typing at runtime, overheads are incurred due to
// various type checks and coercions that determine different computational
// outcomes based on type.  There is nothing here that optimizes analytics
// for native machine types; these optimizations (will) happen in the pushdown
// predicate processing engine in the zst columnar scanner.
//
// Eventually, we will optimize this zst "fast path" by dynamically
// generating byte codes (which can in turn be JIT assembled into machine code)
// for each zng TypeRecord encountered.  Once you know the TypeRecord,
// you can generate code using strong typing just as an OLAP system does
// due to its schemas defined up-front in its relational tables.  Here,
// each record type is like a schema and as we encounter them, we can compile
// optimized code for the now-static types within that record type.
//
// The Evaluator return by CompileExpr produces zng.Values that are stored
// in temporary buffers and may be modified on subsequent calls to Eval.
// This is intended to minimize the garbage collection needs of the inner loop
// by not allocating memory on a per-Eval basis.  For uses like filtering and
// aggregations, where the results are immediately used, this is desirable and
// efficient but for use cases like storing the results as groupby keys, the
// resulting zng.Value should be copied (e.g., via zng.Value.Copy()).
//
// TBD: string values and net.IP address do not need to be copied because they
// are allocated by go libraries and temporary buffers are not used.  This will
// change down the road when we implement no-allocation string and IP conversion.
func compileExpr(zctx *resolver.Context, scope *Scope, node ast.Expression) (expr.Evaluator, error) {
	if scope == nil {
		// XXX The compiler should be a struct with all of these functions
		// becoming recievers.  Then, zctx and scope can be member variables
		// of the compiler.  As compiler becomes more sophisticated, we will
		// build on this structure.  See issue #2067.
		scope = &Scope{}
	}
	switch n := node.(type) {
	case *ast.Empty:
		return nil, errors.New("empty expression outside of slice")
	case *ast.Literal:
		return expr.NewLiteral(*n)
	case *ast.Identifier:
		// If the identifier refers to a named variable in scope (like "$"),
		// then return a Var expression referring to the pointer to the value.
		// Note that constants may be accessed this way too by entering their
		// names into the global (outermost) scope in the Scope entity.
		if ref := scope.Lookup(n.Name); ref != nil {
			return expr.NewVar(ref), nil
		}
		return compileExpr(zctx, scope, rootField(n.Name))
	case *ast.RootRecord:
		return &expr.RootRecord{}, nil
	case *ast.UnaryExpression:
		return compileUnary(zctx, scope, *n)
	case *ast.SelectExpression:
		return nil, errors.New("select expression found outside of generator context")
	case *ast.BinaryExpression:
		return compileBinary(zctx, scope, n.Operator, n.LHS, n.RHS)
	case *ast.ConditionalExpression:
		return compileConditional(zctx, scope, *n)
	case *ast.FunctionCall:
		return compileCall(zctx, scope, *n)
	case *ast.CastExpression:
		return compileCast(zctx, scope, *n)
	case *ast.TypeExpr:
		return compileTypeExpr(zctx, scope, *n)
	default:
		return nil, fmt.Errorf("invalid expression type %T", node)
	}
}

func compileExprWithEmpty(zctx *resolver.Context, scope *Scope, node ast.Expression) (expr.Evaluator, error) {
	if _, ok := node.(*ast.Empty); ok {
		return nil, nil
	}
	return compileExpr(zctx, scope, node)
}

func rootField(name string) *ast.BinaryExpression {
	return &ast.BinaryExpression{
		Op:       "BinaryExpr",
		Operator: ".",
		LHS:      &ast.RootRecord{"RootRecord"},
		RHS:      &ast.Identifier{Name: name},
	}
}

func CompileExprs(zctx *resolver.Context, scope *Scope, nodes []ast.Expression) ([]expr.Evaluator, error) {
	var exprs []expr.Evaluator
	for k := range nodes {
		e, err := compileExpr(zctx, scope, nodes[k])
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, e)
	}
	return exprs, nil
}

func compileBinary(zctx *resolver.Context, scope *Scope, op string, LHS, RHS ast.Expression) (expr.Evaluator, error) {
	if op == "." {
		return compileDotExpr(zctx, scope, LHS, RHS)
	}
	if op == "@" {
		return nil, errors.New("generator expression encountered outside of aggregator")
	}
	if slice, ok := RHS.(*ast.BinaryExpression); ok && slice.Operator == ":" {
		return compileSlice(zctx, scope, LHS, slice)
	}
	lhs, err := compileExpr(zctx, scope, LHS)
	if err != nil {
		return nil, err
	}
	rhs, err := compileExpr(zctx, scope, RHS)
	if err != nil {
		return nil, err
	}
	switch op {
	case "and", "or":
		return compileLogical(lhs, rhs, op)
	case "in":
		return expr.NewIn(lhs, rhs), nil
	case "=", "!=":
		return expr.NewCompareEquality(lhs, rhs, op)
	case "=~", "!~":
		return expr.NewPatternMatch(lhs, rhs, op)
	case "<", "<=", ">", ">=":
		return expr.NewCompareRelative(lhs, rhs, op)
	case "+", "-", "*", "/":
		return expr.NewArithmetic(lhs, rhs, op)
	case "[":
		return expr.NewIndexExpr(zctx, lhs, rhs)
	default:
		return nil, fmt.Errorf("invalid binary operator %s", op)
	}
}

func compileSlice(zctx *resolver.Context, scope *Scope, container ast.Expression, slice *ast.BinaryExpression) (expr.Evaluator, error) {
	from, err := compileExprWithEmpty(zctx, scope, slice.LHS)
	if err != nil {
		return nil, err
	}
	to, err := compileExprWithEmpty(zctx, scope, slice.RHS)
	if err != nil {
		return nil, err
	}
	e, err := compileExpr(zctx, scope, container)
	if err != nil {
		return nil, err
	}
	return expr.NewSlice(e, from, to), nil
}

func compileGenerator(zctx *resolver.Context, scope *Scope, e ast.Expression) (expr.Generator, error) {
	switch e := e.(type) {
	case *ast.BinaryExpression:
		if e.Operator != "@" {
			return nil, fmt.Errorf("bad expression in generator: %s", e.Operator)
		}
		src, err := compileGenerator(zctx, scope, e.LHS)
		if err != nil {
			return nil, err
		}
		return compileMethod(zctx, scope, src, e.RHS)
	case *ast.SelectExpression:
		exprs, err := compileExprs(zctx, scope, e.Selectors)
		if err != nil {
			return nil, err
		}
		return expr.NewSelector(exprs), nil
	}
	return nil, fmt.Errorf("bad generator expression: %T", e)
}

func compileMethod(zctx *resolver.Context, scope *Scope, src expr.Generator, e ast.Expression) (expr.Generator, error) {
	method, ok := e.(*ast.FunctionCall)
	if !ok {
		return nil, fmt.Errorf("bad method expression: %T", e)
	}
	switch method.Function {
	case "map":
		if len(method.Args) != 1 {
			return nil, errors.New("map() method requires one argument")
		}
		mapMethod := expr.NewMapMethod(src)
		scope.Enter()
		defer scope.Exit()
		scope.Bind("$", mapMethod.Ref())
		mapExpr, err := compileExpr(zctx, scope, method.Args[0])
		if err != nil {
			return nil, err
		}
		mapMethod.Set(mapExpr)
		return mapMethod, nil
	case "filter":
		if len(method.Args) != 1 {
			return nil, errors.New("filter() method requires one argument")
		}
		filterMethod := expr.NewFilterMethod(src)
		scope.Enter()
		defer scope.Exit()
		scope.Bind("$", filterMethod.Ref())
		filterExpr, err := compileExpr(zctx, scope, method.Args[0])
		if err != nil {
			fmt.Println("ERR", err)
			return nil, err
		}
		filterMethod.Set(filterExpr)
		return filterMethod, nil
	default:
		return nil, fmt.Errorf("uknown method: %s", method.Function)
	}
}

// compileMethodChain tries to compile the given function call as an aggregation
// function operating on a generator.  If this fails with an error or (nil,nil),
// then it doesn't have the required shape and the caller can try compiling
// this AST node a different way.
func compileMethodChain(zctx *resolver.Context, scope *Scope, call ast.FunctionCall) (expr.Evaluator, error) {
	if len(call.Args) != 1 {
		return nil, nil
	}
	pattern, err := agg.NewPattern(call.Function)
	if err != nil {
		return nil, nil
	}
	gen, err := compileGenerator(zctx, scope, call.Args[0])
	if gen == nil || err != nil {
		return nil, nil
	}
	return expr.NewAggExpr(zctx, pattern, gen), nil
}

func compileUnary(zctx *resolver.Context, scope *Scope, node ast.UnaryExpression) (expr.Evaluator, error) {
	if node.Operator != "!" {
		return nil, fmt.Errorf("unknown unary operator %s\n", node.Operator)
	}
	e, err := compileExpr(zctx, scope, node.Operand)
	if err != nil {
		return nil, err
	}
	return expr.NewLogicalNot(e), nil
}

func compileLogical(lhs, rhs expr.Evaluator, operator string) (expr.Evaluator, error) {
	switch operator {
	case "and":
		return expr.NewLogicalAnd(lhs, rhs), nil
	case "or":
		return expr.NewLogicalOr(lhs, rhs), nil
	default:
		return nil, fmt.Errorf("unknown logical operator: %s", operator)
	}
}

func compileConditional(zctx *resolver.Context, scope *Scope, node ast.ConditionalExpression) (expr.Evaluator, error) {
	predicate, err := compileExpr(zctx, scope, node.Condition)
	if err != nil {
		return nil, err
	}
	thenExpr, err := compileExpr(zctx, scope, node.Then)
	if err != nil {
		return nil, err
	}
	elseExpr, err := compileExpr(zctx, scope, node.Else)
	if err != nil {
		return nil, err
	}
	return expr.NewConditional(predicate, thenExpr, elseExpr), nil
}

func compileDotExpr(zctx *resolver.Context, scope *Scope, lhs, rhs ast.Expression) (expr.Evaluator, error) {
	id, ok := rhs.(*ast.Identifier)
	if !ok {
		return nil, errors.New("rhs of dot expression is not an identifier")
	}
	record, err := compileExpr(zctx, scope, lhs)
	if err != nil {
		return nil, err
	}
	return expr.NewDotAccess(record, id.Name), nil
}

func compileCast(zctx *resolver.Context, scope *Scope, node ast.CastExpression) (expr.Evaluator, error) {
	e, err := compileExpr(zctx, scope, node.Expr)
	if err != nil {
		return nil, err
	}
	//XXX we should handle runtime resolution of typedef names
	typ, err := zson.TranslateType(zctx, node.Type)
	if err != nil {
		return nil, err
	}
	return expr.NewCast(e, typ)
}

func CompileLval(node ast.Expression) (field.Static, error) {
	switch node := node.(type) {
	case *ast.RootRecord:
		return field.NewRoot(), nil
	// XXX We need to allow index operators at some point, but for now
	// we have been assuming only dotted field lvalues.  See Issue #1462.
	case *ast.BinaryExpression:
		if node.Operator != "." {
			break
		}
		id, ok := node.RHS.(*ast.Identifier)
		if !ok {
			return nil, errors.New("rhs of dot operator is not an identifier")
		}
		lhs, err := CompileLval(node.LHS)
		if err != nil {
			return nil, err
		}
		return append(lhs, id.Name), nil
	case *ast.Identifier:
		return CompileLval(rootField(node.Name))
	}
	return nil, errors.New("invalid expression on lhs of assignment")
}

var ErrInference = errors.New("assignment name could not be inferred from rhs expression")

func CompileAssignment(zctx *resolver.Context, scope *Scope, node *ast.Assignment) (expr.Assignment, error) {
	rhs, err := compileExpr(zctx, scope, node.RHS)
	if err != nil {
		return expr.Assignment{}, fmt.Errorf("rhs of assigment expression: %w", err)
	}
	var lhs field.Static
	if node.LHS != nil {
		lhs, err = CompileLval(node.LHS)
		if err != nil {
			return expr.Assignment{}, fmt.Errorf("lhs of assigment expression: %w", err)
		}
	} else {
		switch rhs := node.RHS.(type) {
		case *ast.RootRecord:
			lhs = field.New(".")
		case *ast.Identifier:
			lhs = field.New(rhs.Name)
		case *ast.FunctionCall:
			lhs = field.New(rhs.Function)
		case *ast.BinaryExpression:
			// This can be a dotted record or some other expression.
			// In the latter case, it might be nice to infer a name,
			// e.g., forr "count() by a+b" we could infer "sum" for
			// the name, i,e., "count() by sum=a+b".  But for now,
			// we'll just catch this as an error.
			lhs, err = CompileLval(rhs)
			if err != nil {
				err = ErrInference
			}
		default:
			err = ErrInference
		}
	}
	return expr.Assignment{lhs, rhs}, err
}

func CompileAssignments(dsts []field.Static, srcs []field.Static) ([]field.Static, []expr.Evaluator) {
	if len(srcs) != len(dsts) {
		panic("CompileAssignments: argument mismatch")
	}
	var resolvers []expr.Evaluator
	var fields []field.Static
	for k, dst := range dsts {
		fields = append(fields, dst)
		resolvers = append(resolvers, expr.NewDotExpr(srcs[k]))
	}
	return fields, resolvers
}

func compileCutter(zctx *resolver.Context, scope *Scope, node ast.FunctionCall) (*expr.Cutter, error) {
	var lhs []field.Static
	var rhs []expr.Evaluator
	for _, expr := range node.Args {
		// This is a bit of a hack and could be cleaed up by re-factoring
		// CompileAssigment, but for now, we create an assigment expression
		// where the LHS and RHS are the same, so that cut(id.orig_h,_path)
		// gives a value of type {id:{orig_h:ip},{_path:string}}
		// with field names that are the same as the cut names.
		// We should allow field assignments as function arguments.
		// See issue #1772.
		assignment := &ast.Assignment{LHS: expr, RHS: expr}
		compiled, err := CompileAssignment(zctx, scope, assignment)
		if err != nil {
			return nil, err
		}
		lhs = append(lhs, compiled.LHS)
		rhs = append(rhs, compiled.RHS)
	}
	return expr.NewCutter(zctx, lhs, rhs)
}

func shaperOps(name string) expr.ShaperTransform {
	switch name {
	case "cast":
		return expr.Cast
	case "crop":
		return expr.Crop
	case "fill":
		return expr.Fill
	case "fit":
		return expr.Crop | expr.Fill
	case "order":
		return expr.Order
	case "shape":
		return expr.Cast | expr.Crop | expr.Fill | expr.Order
	default:
		return 0
	}

}

func isShaperFunc(name string) bool {
	return shaperOps(name) != 0
}

func compileShaper(zctx *resolver.Context, scope *Scope, node ast.FunctionCall) (*expr.Shaper, error) {
	if len(node.Args) < 2 {
		return nil, function.ErrTooFewArgs
	}
	if len(node.Args) > 2 {
		return nil, function.ErrTooManyArgs
	}
	field, err := compileExpr(zctx, scope, node.Args[0])
	if err != nil {
		return nil, err
	}
	ev, err := compileExpr(zctx, scope, node.Args[1])
	if err != nil {
		return nil, err
	}
	return expr.NewShaper(zctx, field, ev, shaperOps(node.Function))
}

func compileCall(zctx *resolver.Context, scope *Scope, node ast.FunctionCall) (expr.Evaluator, error) {

	// For now, we special case cut and pick here.  We shuold generalize this
	// as we will add many more stateful functions and also resolve this
	// the changes to create running aggegation functions from reducers.
	// XXX See issue #1259.
	if node.Function == "cut" {
		cut, err := compileCutter(zctx, scope, node)
		if err != nil {
			return nil, err
		}
		cut.AllowPartialCuts()
		return cut, nil
	}
	if node.Function == "pick" {
		return compileCutter(zctx, scope, node)
	}
	if isShaperFunc(node.Function) {
		return compileShaper(zctx, scope, node)
	}
	if e, err := compileMethodChain(zctx, scope, node); e != nil || err != nil {
		return e, err
	}
	if node.Function == "exists" {
		exprs, err := compileExprs(zctx, scope, node.Args)
		if err != nil {
			return nil, fmt.Errorf("exists: bad argument: %w", err)
		}
		return expr.NewExists(zctx, exprs), nil
	}
	nargs := len(node.Args)
	fn, root, err := function.New(zctx, node.Function, nargs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", node.Function, err)
	}
	args := node.Args
	if root {
		args = append([]ast.Expression{&ast.RootRecord{}}, args...)
	}
	exprs, err := compileExprs(zctx, scope, args)
	if err != nil {
		return nil, fmt.Errorf("%s: bad argument: %w", node.Function, err)
	}
	return expr.NewCall(zctx, fn, exprs), nil
}

func compileExprs(zctx *resolver.Context, scope *Scope, in []ast.Expression) ([]expr.Evaluator, error) {
	out := make([]expr.Evaluator, 0, len(in))
	for _, e := range in {
		ev, err := compileExpr(zctx, scope, e)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func compileTypeExpr(zctx *resolver.Context, scope *Scope, t ast.TypeExpr) (expr.Evaluator, error) {
	if typ, ok := t.Type.(*ast.TypeName); ok {
		// We currently support dynamic type names only for
		// top-level type names.  By dynamic, we mean typedefs that
		// come from the data instead of the Z.  For dynamic type
		// names that are embedded lower down in a complex type,
		// we need to implement some type of tracker objec that
		// can resolve the type when all the dependent types are found.
		// See issue #2182.
		return expr.NewTypeFunc(zctx, typ.Name), nil
	}
	typ, err := zson.TranslateType(zctx, t.Type)
	if err != nil {
		return nil, err
	}
	return expr.NewLiteralVal(zng.NewTypeType(typ)), nil
}
