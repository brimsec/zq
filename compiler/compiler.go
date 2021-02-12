package compiler

import (
	"github.com/brimsec/zq/ast"
	"github.com/brimsec/zq/pkg/joe"
	"github.com/brimsec/zq/proc"
	"github.com/brimsec/zq/zql"
	"github.com/mitchellh/mapstructure"
)

type Compiler struct {
	pctx     *proc.Context
	scope    *Scope
	custom   ProcHook
	ast      ast.Proc
	semantic ast.Proc
	parallel ast.Proc
}

func NewCompiler(pctx *proc.Context, p ast.Proc) *Compiler {
	return &Compiler{
		pctx:  pctx,
		scope: newScope(),
	}
}

func NewCustomCompiler(pctx *proc.Context, custom ProcHook, p ast.Proc) *Compiler {
	c := NewCompiler(pctx, p)
	c.custom = custom
	return c
}

// ParseProc() is an entry point for use from external go code,
// mostly just a wrapper around Parse() that casts the return value.
func ParseProc(query string, opts ...zql.Option) (ast.Proc, error) {
	parsed, err := zql.Parse("", []byte(query), opts...)
	if err != nil {
		return nil, err
	}
	return ast.UnpackMap(nil, parsed)
}

func ParseExpression(expr string) (ast.Expression, error) {
	m, err := zql.Parse("", []byte(expr), zql.Entrypoint("Expr"))
	if err != nil {
		return nil, err
	}
	node := joe.Convert(m)
	ex, err := ast.UnpackExpression(node)
	if err != nil {
		return nil, err
	}
	c := &mapstructure.DecoderConfig{
		TagName: "json",
		Result:  ex,
		Squash:  true,
	}
	dec, err := mapstructure.NewDecoder(c)
	if err != nil {
		return nil, err
	}
	return ex, dec.Decode(m)
}

// MustParseProc is functionally the same as ParseProc but panics if an error
// is encountered.
func MustParseProc(query string) ast.Proc {
	proc, err := ParseProc(query)
	if err != nil {
		panic(err)
	}
	return proc
}
