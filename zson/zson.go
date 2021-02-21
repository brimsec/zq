// Package zson provides fundamental interfaces to the ZSON data format comprising
// Reader, Writer, Parser, and so forth.  The ZSON format includes a type system
// that requries a semantic analysis to parse an input to its structured data
// representation.  To do so, Parser translats a ZSON input to an AST, Analyzer
// performs semantic type analysis to turn the AST into a Value, and Builder
// constructs a zng.Value from a Value.
package zson

import (
	"strings"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

// Implied returns true for primitive types whose type can be inferred
// syntactically from its value and thus never needs a decorator.
func Implied(typ zng.Type) bool {
	switch typ := typ.(type) {
	case *zng.TypeOfInt64, *zng.TypeOfDuration, *zng.TypeOfTime, *zng.TypeOfFloat64, *zng.TypeOfBool, *zng.TypeOfBytes, *zng.TypeOfString, *zng.TypeOfIP, *zng.TypeOfNet, *zng.TypeOfType:
		return true
	case *zng.TypeRecord:
		for _, c := range typ.Columns {
			if !Implied(c.Type) {
				return false
			}
		}
		return true
	case *zng.TypeArray:
		return Implied(typ.Type)
	case *zng.TypeSet:
		return Implied(typ.Type)
	case *zng.TypeMap:
		return Implied(typ.KeyType) && Implied(typ.ValType)
	}
	return false
}

// SelfDescribing returns true for types whose type name can be entirely derived
// from its typed value, e.g., a record type can be derived from a record value
// because all of the field names and type names are present in the value, but
// an enum type cannot be derived from an enum value because not all the enumerated
// names are present in the value.  In the former case, a decorated typedef can
// use the abbreviated form "(= <name>)", while the letter case, a type def must use
// the longer form "<value> (<name> = (<type>))".
func SelfDescribing(typ zng.Type) bool {
	if Implied(typ) {
		return true
	}
	switch typ := typ.(type) {
	case *zng.TypeRecord, *zng.TypeArray, *zng.TypeSet, *zng.TypeMap:
		return true
	case *zng.TypeAlias:
		return SelfDescribing(typ.Type)
	}
	return false
}

func LookupType(zctx *resolver.Context, zson string) (zng.Type, error) {
	zp, err := NewParser(strings.NewReader(zson))
	if err != nil {
		return nil, err
	}
	ast, err := zp.parseType()
	if ast == nil || noEOF(err) != nil {
		return nil, err
	}
	return NewAnalyzer().convertType(zctx, ast)
}

func TranslateType(zctx *resolver.Context, astType ast.Type) (zng.Type, error) {
	return NewAnalyzer().convertType(zctx, astType)
}
