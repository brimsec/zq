package zfmt

import (
	"time"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/zng"
)

func Canonical(p ast.Proc) string {
	c := &canon{formatter: formatter{tab: 2}, head: true, first: true}
	c.proc(p)
	c.flush()
	return c.String()
}

type canon struct {
	formatter
	head  bool
	first bool
}

func (c *canon) open(args ...interface{}) {
	c.formatter.open(args...)
}

func (c *canon) close() {
	c.formatter.close()
}

func (c *canon) assignments(assignments []ast.Assignment) {
	for k, a := range assignments {
		if k > 0 {
			c.write(",")
		}
		if a.LHS != nil {
			c.expr(a.LHS, false)
			c.write("=")
		}
		c.expr(a.RHS, false)
	}
}

func (c *canon) exprs(exprs []ast.Expression) {
	for k, e := range exprs {
		if k > 0 {
			c.write(", ")
		}
		c.expr(e, false)
	}
}

func (c *canon) expr(e ast.Expression, paren bool) {
	switch e := e.(type) {
	case nil:
		c.write("null")
	case *ast.Reducer:
		c.write("%s(", e.Operator)
		if e.Expr != nil {
			c.expr(e.Expr, false)
		}
		c.write(")")
		if e.Where != nil {
			c.write(" where ")
			c.expr(e.Where, false)
		}
	case *ast.Literal:
		c.literal(*e)
	case *ast.Identifier:
		// If the identifier refers to a named variable in scope (like "$"),
		// then return a Var expression referring to the pointer to the value.
		// Note that constants may be accessed this way too by entering their
		// names into the global (outermost) scope in the Scope entity.
		c.write(e.Name)
	case *ast.RootRecord:
		c.write(".")
	case *ast.UnaryExpression:
		c.space()
		c.write(e.Operator)
		c.expr(e.Operand, true)
	case *ast.SelectExpression:
		c.write("TBD:select")
	case *ast.BinaryExpression:
		c.binary(e)
	case *ast.ConditionalExpression:
		c.write("(")
		c.expr(e.Condition, true)
		c.write(") ? ")
		c.expr(e.Then, false)
		c.write(" : ")
		c.expr(e.Else, false)
	case *ast.FunctionCall:
		c.write("%s(", e.Function)
		c.exprs(e.Args)
		c.write(")")
	case *ast.CastExpression:
		c.expr(e.Expr, false)
		c.open(":%s", e.Type)
	case *ast.Search:
		c.write("match(")
		c.literal(e.Value)
		c.write(")")
	case *ast.FieldPath:
		c.fieldpath(e.Name)
	case *ast.Ref:
		c.write("%s", e.Name)
	case *ast.TypeValue:
		c.write("type(")
		c.typ(e.Value)
		c.write(")")
	default:
		c.open("(unknown expr %T)", e)
		c.close()
		c.ret()
	}
}

func (c *canon) binary(e *ast.BinaryExpression) {
	switch e.Operator {
	case ".":
		if !isRoot(e.LHS) {
			c.expr(e.LHS, false)
			c.write(".")
		}
		c.expr(e.RHS, false)
	case "[":
		if isRoot(e.LHS) {
			c.write(".")
		} else {
			c.expr(e.LHS, false)
		}
		c.write("[")
		c.expr(e.RHS, false)
		c.write("]")
	case "in", "and":
		c.expr(e.LHS, false)
		c.write(" %s ", e.Operator)
		c.expr(e.RHS, false)
	case "or":
		c.expr(e.LHS, true)
		c.write(" %s ", e.Operator)
		c.expr(e.RHS, true)
	default:
		// do need parens calc
		c.expr(e.LHS, true)
		c.write("%s", e.Operator)
		c.expr(e.RHS, true)
	}
}

func isRoot(e ast.Expression) bool {
	if _, ok := e.(*ast.RootRecord); ok {
		return true
	}
	if f, ok := e.(*ast.FieldPath); ok {
		if f.Name != nil && len(f.Name) == 0 {
			return true
		}
	}
	return false
}

func (c *canon) next() {
	if c.first {
		c.first = false
	} else {
		c.write("\n")
	}
	c.needRet = false
	c.writeTab()
	if c.head {
		c.head = false
	} else {
		c.write("| ")
	}
}

func (c *canon) proc(p ast.Proc) {
	switch p := p.(type) {
	case *ast.SequentialProc:
		for _, p := range p.Procs {
			c.proc(p)
		}
	case *ast.ParallelProc:
		c.next()
		c.open("split (")
		for _, p := range p.Procs {
			c.ret()
			c.write("=>")
			c.open()
			c.head = true
			c.proc(p)
			c.close()
		}
		c.close()
		c.ret()
		c.flush()
		c.write(")")
		if p.MergeOrderField != nil {
			c.write(" merge-by ")
			c.fieldpath(p.MergeOrderField)
		}
		if p.MergeOrderReverse {
			c.write(" rev")
		}
	case *ast.ConstProc:
		c.write("const %s=", p.Name)
		c.expr(p.Expr, false)
		c.ret()
		c.flush()
	case *ast.TypeProc:
		c.write("type %s=", p.Name)
		c.typ(p.Type)
		c.ret()
		c.flush()
	case *ast.GroupByProc:
		c.next()
		c.open("summarize")
		if secs := p.Duration.Seconds; secs != 0 {
			c.write(" every %s", time.Duration(1_000_000_000*secs))
		}
		if p.ConsumePart {
			c.write(" partials-in")
		}
		if p.EmitPart {
			c.write(" partials-out")
		}
		if p.InputSortDir != 0 {
			c.write(" sort-dir %d", p.InputSortDir)
		}
		c.ret()
		c.open()
		c.assignments(p.Reducers)
		if len(p.Keys) != 0 {
			c.write(" by ")
			c.assignments(p.Keys)
		}
		if p.Limit != 0 {
			c.write(" -with limit %d", p.Limit)
		}
		c.close()
		c.close()
	case *ast.CutProc:
		c.next()
		c.write("cut ")
		c.assignments(p.Fields)
	case *ast.PickProc:
		c.next()
		c.open("pick ")
		c.assignments(p.Fields)
	case *ast.DropProc:
		c.next()
		c.write("drop ")
		c.exprs(p.Fields)
	case *ast.SortProc:
		c.next()
		c.write("sort")
		if p.SortDir < 0 {
			c.write(" -r")
		}
		if p.NullsFirst {
			c.write(" -nulls first")
		}
		if len(p.Fields) > 0 {
			c.space()
			c.exprs(p.Fields)
		}
	case *ast.HeadProc:
		c.next()
		c.write("head %d", p.Count)
	case *ast.TailProc:
		c.next()
		c.write("tail %d", p.Count)
	case *ast.UniqProc:
		c.next()
		c.write("uniq")
		if p.Cflag {
			c.write(" -c")
		}
	case *ast.PassProc:
		c.next()
		c.write("pass")
	case *ast.FilterProc:
		c.next()
		c.open("filter ")
		if isTrue(p.Filter) {
			c.write("*")
		} else {
			c.expr(p.Filter, false)
		}
		c.close()
	case *ast.TopProc:
		c.next()
		c.write("top limit=%d flush=%t ", p.Limit, p.Flush)
		c.exprs(p.Fields)
	case *ast.PutProc:
		c.next()
		c.write("put ")
		c.assignments(p.Clauses)
	case *ast.RenameProc:
		c.next()
		c.write("rename ")
		c.assignments(p.Fields)
	case *ast.FuseProc:
		c.next()
		c.write("fuse")
	case *ast.FunctionCall:
		c.next()
		c.write("%s(", p.Function)
		c.exprs(p.Args)
		c.write(")")
	case *ast.JoinProc:
		c.next()
		c.open("join on ")
		c.expr(p.LeftKey, false)
		c.write("=")
		c.expr(p.RightKey, false)
		c.ret()
		c.open("join-cut ")
		c.assignments(p.Clauses)
		c.close()
		c.close()
	//case *ast.SqlExpression:
	//	//XXX TBD
	//	c.open("sql")
	//	c.close()
	default:
		c.open("unknown proc: %T", p)
		c.close()
	}
}

func isTrue(e ast.Expression) bool {
	if lit, ok := e.(*ast.Literal); ok {
		return lit.Type == "bool" && lit.Value == "true"
	}
	return false
}

//XXX this needs to change when we use the zson values from the ast
func (c *canon) literal(e ast.Literal) {
	switch e.Type {
	case "string", "bstring", "error":
		c.write("\"%s\"", e.Value)
	case "regexp":
		c.write("/%s/", e.Value)
	default:
		//XXX need decorators for non-implied
		c.write("%s", e.Value)

	}
}

func (c *canon) fieldpath(path []string) {
	for k, s := range path {
		if k != 0 {
			c.write(".")
		}
		c.write(s)
	}
}

func (c *canon) typ(t ast.Type) {
	switch t := t.(type) {
	case *ast.TypePrimitive:
		c.write(t.Name)
	case *ast.TypeRecord:
		c.write("{")
		c.typeFields(t.Fields)
		c.write("}")
	case *ast.TypeArray:
		c.write("[")
		c.typ(t.Type)
		c.write("]")
	case *ast.TypeSet:
		c.write("|[")
		c.typ(t.Type)
		c.write("]|")
	case *ast.TypeUnion:
		c.write("(")
		c.types(t.Types)
		c.write(")")
	case *ast.TypeEnum:
		//XXX need to figure out Z syntax for enum literal which may
		// be different than zson, requiring some ast adjustments.
		c.write("TBD:ENUM")
	case *ast.TypeMap:
		c.write("|{")
		c.typ(t.KeyType)
		c.write(",")
		c.typ(t.ValType)
		c.write("}|")
	case *ast.TypeNull:
		c.write("null")
	case *ast.TypeDef:
		c.write("%s=(", t.Name)
		c.typ(t.Type)
		c.write(")")
	case *ast.TypeName:
		c.write(t.Name)
	}
}

func (c *canon) typeFields(fields []ast.TypeField) {
	for k, f := range fields {
		if k != 0 {
			c.write(",")
		}
		c.write("%s:", zng.QuotedName(f.Name))
		c.typ(f.Type)
	}
}

func (c *canon) types(types []ast.Type) {
	for k, t := range types {
		if k != 0 {
			c.write(",")
		}
		c.typ(t)
	}
}
