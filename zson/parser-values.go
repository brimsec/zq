package zson

import (
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/brimsec/zq/compiler/ast"
)

func (p *Parser) ParseValue() (ast.Value, error) {
	v, err := p.matchValue()
	if err == io.EOF {
		err = nil
	}
	if v == nil && err == nil {
		if err := p.lexer.check(1); (err != nil && err != io.EOF) || len(p.lexer.cursor) > 0 {
			return nil, errors.New("zson syntax error")
		}
	}
	return v, err
}

func noEOF(err error) error {
	if err == io.EOF {
		err = nil
	}
	return err
}

func (p *Parser) matchValue() (ast.Value, error) {
	if val, err := p.matchRecord(); val != nil || err != nil {
		return p.decorate(val, err)
	}
	if val, err := p.matchArray(); val != nil || err != nil {
		return p.decorate(val, err)
	}
	if val, err := p.matchSetOrMap(); val != nil || err != nil {
		return p.decorate(val, err)
	}
	if val, err := p.matchTypeValue(); val != nil || err != nil {
		return p.decorate(val, err)
	}
	// Primitive comes last as the other matchers short-circuit more
	// efficiently on sentinel characters.
	if val, err := p.matchPrimitive(); val != nil || err != nil {
		return p.decorate(val, err)
	}
	// But enum really goes last becase we don't want it to pick up
	// true, false, or null.
	if val, err := p.matchEnum(); val != nil || err != nil {
		return p.decorate(val, err)
	}
	return nil, nil
}

func anyAsValue(any ast.Any) *ast.ImpliedValue {
	return &ast.ImpliedValue{
		Op: ast.ImpliedValueOp,
		Of: any,
	}
}

func (p *Parser) decorate(any ast.Any, err error) (ast.Value, error) {
	if err != nil {
		return nil, err
	}
	// First see if there's a short-form typedef decorator.
	// If there isn't, matchShortForm() returns the AnyValue wrapped
	// in an ast.ImpliedValue (as ast.Value)  Otherwise, it returns an
	//  ast.DefVal (as ast.Vaue).
	val, ok, err := p.matchDecorator(any, nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		// No decorator.  Just return the input value.
		return anyAsValue(any), nil
	}
	// Now see if there are additional decorators to apply as casts and
	// return value chain, wrapped if at all, as an ast.Value.
	for {
		outer, ok, err := p.matchDecorator(nil, val)
		if err != nil {
			return nil, err
		}
		if !ok {
			return val, nil
		}
		val = outer
	}
}

// We pass both any and val in here to avoid having to backtrack.
// If we had proper backtracking, this would look a little more sensible.
func (p *Parser) matchDecorator(any ast.Any, val ast.Value) (ast.Value, bool, error) {
	l := p.lexer
	ok, err := l.match('(')
	if err != nil || !ok {
		return nil, false, noEOF(err)
	}
	val, err = p.parseDecorator(any, val)
	if err != nil {
		return nil, false, err
	}
	ok, err = l.match(')')
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, p.error("mismatched parentheses while parsing type decorator")
	}
	return val, true, nil
}

func (p *Parser) parseDecorator(any ast.Any, val ast.Value) (ast.Value, error) {
	l := p.lexer
	// We can have either:
	//   Case 1: =<name>
	//   Case 2: <type>
	// For case 2, there can be embedded typedefs created from the
	// descent into parseType.
	ok, err := l.match('=')
	if err != nil {
		return nil, err
	}
	if ok {
		name, err := l.scanTypeName()
		if name == "" || err != nil {
			return nil, p.error("bad short-form type definition")
		}
		return &ast.DefValue{
			Op:       ast.DefValueOp,
			Of:       any,
			TypeName: name,
		}, nil
	}
	typ, err := p.parseType()
	if err != nil {
		return nil, err
	}
	if any != nil {
		return &ast.CastValue{
			Op:   ast.CastValueOp,
			Of:   anyAsValue(any),
			Type: typ,
		}, nil
	}
	return &ast.CastValue{
		Op:   ast.CastValueOp,
		Of:   val,
		Type: typ,
	}, nil
}

// A bug in Go's time.ParseDuration() function causes an error for
// duration value math.MinInt64.  We work around this by explicitly
// checking for the string that represents this duration (which is
// correctly returned by time.Duration.String()).
const minDuration = "-2562047h47m16.854775808s"

func (p *Parser) matchPrimitive() (*ast.Primitive, error) {
	if val, err := p.matchStringPrimitive(); val != nil || err != nil {
		return val, noEOF(err)
	}
	if val, err := p.matchBacktickString(); val != nil || err != nil {
		return val, noEOF(err)
	}
	l := p.lexer
	if err := l.skipSpace(); err != nil {
		return nil, noEOF(err)
	}
	s, err := l.peekPrimitive()
	if err != nil {
		return nil, noEOF(err)
	}
	if s == "" {
		return nil, nil
	}
	// Try to parse the string different ways.  This is not intended
	// to be performant.  ZNG provides performance for the ZSON data model.
	var typ string
	if s == "true" || s == "false" {
		typ = "bool"
	} else if s == "null" {
		typ = "null"
	} else if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		typ = "int64"
	} else if _, err := strconv.ParseUint(s, 10, 64); err == nil {
		typ = "uint64"
	} else if _, err := strconv.ParseFloat(s, 64); err == nil {
		typ = "float64"
	} else if _, err := time.Parse(time.RFC3339Nano, s); err == nil {
		typ = "time"
	} else if _, err := time.ParseDuration(s); err == nil || s == minDuration {
		typ = "duration"
	} else if _, _, err := net.ParseCIDR(s); err == nil {
		typ = "net"
	} else if ip := net.ParseIP(s); ip != nil {
		typ = "ip"
	} else if len(s) >= 2 && s[0:2] == "0x" {
		if len(s) == 2 {
			typ = "bytes"
		} else if _, err := hex.DecodeString(s[2:]); err == nil {
			typ = "bytes"
		} else {
			return nil, err
		}
	} else {
		// no match
		return nil, nil
	}
	l.skip(len(s))
	return &ast.Primitive{
		Op:   "Primitive",
		Type: typ,
		Text: s,
	}, nil
}

func (p *Parser) matchStringPrimitive() (*ast.Primitive, error) {
	s, ok, err := p.matchString()
	if err != nil || !ok {
		return nil, noEOF(err)
	}
	return &ast.Primitive{
		Op:   "Primitive",
		Type: "string",
		Text: s,
	}, nil
}

func (p *Parser) matchString() (string, bool, error) {
	l := p.lexer
	ok, err := l.match('"')
	if err != nil || !ok {
		return "", false, noEOF(err)
	}
	s, err := l.scanString()
	if err != nil {
		return "", false, p.error("parsing string literal")
	}
	ok, err = l.match('"')
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, p.error("mismatched string quotes")
	}
	return s, true, nil
}

var arrow = []byte("=>")

func (p *Parser) matchBacktickString() (*ast.Primitive, error) {
	l := p.lexer
	keepIndentation := false
	ok, err := l.matchBytes(arrow)
	if err != nil {
		return nil, noEOF(err)
	}
	if ok {
		keepIndentation = true
	}
	ok, err = l.match('`')
	if err != nil || !ok {
		if err == nil && keepIndentation {
			err = errors.New("no backtick found following '=>'")
		}
		return nil, err
	}
	s, err := l.scanBacktickString(keepIndentation)
	if err != nil {
		return nil, p.error("parsing backtick string literal")
	}
	ok, err = l.match('`')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.error("mismatched string backticks")
	}
	return &ast.Primitive{
		Op:   "Primitive",
		Type: "string",
		Text: s,
	}, nil
}

func (p *Parser) matchRecord() (*ast.Record, error) {
	l := p.lexer
	if ok, err := l.match('{'); !ok || err != nil {
		return nil, noEOF(err)
	}
	fields, err := p.matchFields()
	if err != nil {
		return nil, err
	}
	ok, err := l.match('}')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.error("mismatched braces while parsing record type")
	}
	return &ast.Record{
		Op:     "Record",
		Fields: fields,
	}, nil
}

func (p *Parser) matchFields() ([]ast.Field, error) {
	l := p.lexer
	var fields []ast.Field
	for {
		field, err := p.matchField()
		if err != nil {
			return nil, err
		}
		if field == nil {
			break
		}
		fields = append(fields, *field)
		ok, err := l.match(',')
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
	}
	return fields, nil
}

func (p *Parser) matchField() (*ast.Field, error) {
	l := p.lexer
	name, ok, err := p.matchSymbol()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	ok, err = l.match(':')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.errorf("no type name found for field %q", name)
	}
	val, err := p.ParseValue()
	if err != nil {
		return nil, err
	}
	return &ast.Field{
		Name:  name,
		Value: val,
	}, nil
}

func (p *Parser) matchSymbol() (string, bool, error) {
	s, ok, err := p.matchString()
	if err != nil {
		return "", false, noEOF(err)
	}
	if ok {
		return s, true, nil
	}
	s, err = p.matchIdentifier()
	if err != nil || s == "" {
		return "", false, err
	}
	return s, true, nil
}

func (p *Parser) matchArray() (*ast.Array, error) {
	l := p.lexer
	if ok, err := l.match('['); !ok || err != nil {
		return nil, noEOF(err)
	}
	vals, err := p.matchValueList()
	if err != nil {
		return nil, err
	}
	ok, err := l.match(']')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.error("mismatched brackets while parsing array type")
	}
	return &ast.Array{
		Op:       "Array",
		Elements: vals,
	}, nil
}

func (p *Parser) matchValueList() ([]ast.Value, error) {
	l := p.lexer
	var vals []ast.Value
	for {
		val, err := p.matchValue()
		if err != nil {
			return nil, err
		}
		if val == nil {
			break
		}
		vals = append(vals, val)
		ok, err := l.match(',')
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
	}
	return vals, nil
}

func (p *Parser) matchSetOrMap() (ast.Any, error) {
	l := p.lexer
	if ok, err := l.match('|'); !ok || err != nil {
		return nil, noEOF(err)
	}
	isSet, err := l.matchTight('[')
	if err != nil {
		return nil, err
	}
	var val ast.Any
	var which string
	if isSet {
		which = "set"
		vals, err := p.matchValueList()
		if err != nil {
			return nil, err
		}
		ok, err := l.match(']')
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, p.error("mismatched set value brackets")
		}
		val = &ast.Set{
			Op:       "Set",
			Elements: vals,
		}
	} else {
		ok, err := l.matchTight('{')
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, p.error("no '|[' or '|{' type bracket at '|' character")
		}
		which = "map"
		entries, err := p.matchMapEntries()
		if err != nil {
			return nil, err
		}
		ok, err = l.match('}')
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, p.error("mismatched map value brackets")
		}
		val = &ast.Map{
			Op:      "Map",
			Entries: entries,
		}
	}
	ok, err := l.matchTight('|')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.errorf("mismatched closing bracket while parsing %s value", which)
	}
	return val, nil

}

func (p *Parser) matchMapEntries() ([]ast.Entry, error) {
	l := p.lexer
	var entries []ast.Entry
	for {
		ok, err := l.match('{')
		if err != nil {
			return nil, err
		}
		if !ok {
			return entries, nil
		}
		entry, err := p.parseEntry()
		if err != nil {
			return nil, err
		}
		ok, err = l.match('}')
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, p.error("mismatched braces while parsing map value entries")
		}
		entries = append(entries, *entry)
		ok, err = p.lexer.match(',')
		if err != nil {
			return nil, err
		}
		if !ok {
			return entries, nil
		}
	}
}

func (p *Parser) parseEntry() (*ast.Entry, error) {
	key, err := p.matchValue()
	if err != nil {
		return nil, err
	}
	if key == nil {
		// no match
		return nil, errors.New("map key not found after '{' while parsing entries")
	}
	ok, err := p.lexer.match(',')
	if err != nil {

		return nil, err
	}
	if !ok {
		return nil, p.error("no comma found after key vaoue while parsing map entry")
	}
	val, err := p.ParseValue()
	if err != nil {
		return nil, err
	}
	return &ast.Entry{
		Key:   key,
		Value: val,
	}, nil
}

func (p *Parser) matchEnum() (*ast.Enum, error) {
	// We only detect identifier-style enum values even though they can
	// also be strings but we don't know that until the semantic check.
	name, err := p.matchIdentifier()
	if err != nil || name == "" {
		return nil, noEOF(err)
	}
	return &ast.Enum{
		Op:   "Enum",
		Name: name,
	}, nil
}

func (p *Parser) matchTypeValue() (*ast.TypeValue, error) {
	l := p.lexer
	if ok, err := l.match('('); !ok || err != nil {
		return nil, noEOF(err)
	}
	typ, err := p.parseType()
	if err != nil {
		return nil, err
	}
	ok, err := l.match(')')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.error("mismatched parentheses while parsing type value")
	}
	return &ast.TypeValue{
		Op:    "TypeValue",
		Value: typ,
	}, nil
}
