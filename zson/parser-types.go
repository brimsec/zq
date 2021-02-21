package zson

import (
	"unicode"

	// XXX should move ZSON ast into zq/zson/ast... it's a bit different
	// than Z literals so it deserves its own home.
	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/zng"
)

func (p *Parser) parseType() (ast.Type, error) {
	typ, err := p.matchType()
	if typ == nil && err == nil {
		err = p.error("couldn't parse type")
	}
	return typ, err
}

func (p *Parser) matchType() (ast.Type, error) {
	if typ, err := p.matchTypeName(); typ != nil || err != nil {
		return typ, err
	}
	if typ, err := p.matchTypeRecord(); typ != nil || err != nil {
		return typ, err
	}
	if typ, err := p.matchTypeArray(); typ != nil || err != nil {
		return typ, err
	}
	if typ, err := p.matchTypeSetOrMap(); typ != nil || err != nil {
		return typ, err
	}
	if typ, err := p.matchTypeUnion(); typ != nil || err != nil {
		return typ, err
	}
	if typ, err := p.matchTypeEnum(); typ != nil || err != nil {
		return typ, err
	}
	// no match
	return nil, nil
}

func (p *Parser) matchIdentifier() (string, error) {
	l := p.lexer
	if err := l.skipSpace(); err != nil {
		return "", err
	}
	r, _, err := l.peekRune()
	if err != nil || !zng.IdChar(r) {
		return "", err
	}
	return l.scanIdentifier()
}

func (p *Parser) matchTypeName() (ast.Type, error) {
	l := p.lexer
	if err := l.skipSpace(); err != nil {
		return nil, err
	}
	r, _, err := l.peekRune()
	if err != nil {
		return nil, err
	}
	if !(zng.IdChar(r) || unicode.IsDigit(r)) {
		return nil, nil
	}
	name, err := l.scanTypeName()
	if err != nil {
		return nil, err
	}
	if t := zng.LookupPrimitive(name); t != nil {
		return &ast.TypePrimitive{"TypePrimitive", name}, nil
	}
	// Wherever we have a type name, we can have a type def defining the
	// type name.
	if ok, err := l.match('='); !ok || err != nil {
		return &ast.TypeName{"TypeName", name}, nil
	}
	tv, err := p.matchTypeValue()
	if err != nil {
		return nil, err
	}
	if tv == nil {
		return nil, p.errorf("bad type sytax in typedef '%s=...'", name)
	}
	return &ast.TypeDef{
		Op:   "TypeDef",
		Name: name,
		Type: tv.Value,
	}, nil
}

func (p *Parser) matchTypeRecord() (*ast.TypeRecord, error) {
	l := p.lexer
	if ok, err := l.match('{'); !ok || err != nil {
		return nil, err
	}
	var fields []ast.TypeField
	for {
		field, err := p.matchTypeField()
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
	ok, err := l.match('}')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.error("mismatched braces while parsing record type")
	}
	return &ast.TypeRecord{
		Op:     "TypeRecord",
		Fields: fields,
	}, nil
}

func (p *Parser) matchTypeField() (*ast.TypeField, error) {
	l := p.lexer
	symbol, ok, err := p.matchSymbol()
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
		return nil, p.errorf("no type name found for field %q", symbol)
	}
	typ, err := p.parseType()
	if err != nil {
		return nil, err
	}
	return &ast.TypeField{
		Name: symbol,
		Type: typ,
	}, nil
}

func (p *Parser) matchTypeArray() (*ast.TypeArray, error) {
	l := p.lexer
	if ok, err := l.match('['); !ok || err != nil {
		return nil, err
	}
	typ, err := p.parseType()
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
	return &ast.TypeArray{
		Op:   "TypeArray",
		Type: typ,
	}, nil
}

func (p *Parser) matchTypeSetOrMap() (ast.Type, error) {
	l := p.lexer
	if ok, err := l.match('|'); !ok || err != nil {
		return nil, err
	}
	isSet, err := l.matchTight('[')
	if err != nil {
		return nil, err
	}
	var typ ast.Type
	var which string
	if isSet {
		which = "set"
		inner, err := p.parseType()
		if err != nil {
			return nil, err
		}
		ok, err := l.match(']')
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, p.error("mismatched set-brackets while parsing set type")
		}
		typ = &ast.TypeSet{
			Op:   "TypeSet",
			Type: inner,
		}
	} else {
		ok, err := l.matchTight('{')
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, p.error("no '|[' or '|{' type token at '|' character")
		}
		which = "map"
		typ, err = p.parseTypeMap()
		if err != nil {
			return nil, err
		}
		ok, err = l.match('}')
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, p.error("mismatched set-brackets while parsing map type")
		}
	}
	ok, err := l.matchTight('|')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.errorf("mismatched closing bracket while parsing type %q", which)
	}
	return typ, nil

}

func (p *Parser) parseTypeMap() (*ast.TypeMap, error) {
	keyType, err := p.parseType()
	if err != nil {
		return nil, err
	}
	ok, err := p.lexer.match(',')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.error("value type missing while parsing map type")
	}
	valType, err := p.parseType()
	if err != nil {
		return nil, err
	}
	return &ast.TypeMap{
		Op:      "TypeMap",
		KeyType: keyType,
		ValType: valType,
	}, nil
}

func (p *Parser) matchTypeUnion() (*ast.TypeUnion, error) {
	l := p.lexer
	if ok, err := l.match('('); !ok || err != nil {
		return nil, err
	}
	var types []ast.Type
	for {
		typ, err := p.matchType()
		if err != nil {
			return nil, err
		}
		if typ == nil {
			break
		}
		types = append(types, typ)
		ok, err := l.match(',')
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
	}
	if len(types) < 2 {
		return nil, p.error("type list not found parsing union type at '('")
	}
	ok, err := l.match(')')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.error("mismatched parentheses while parsing union type")
	}
	return &ast.TypeUnion{
		Op:    "TypeUnion",
		Types: types,
	}, nil
}

func (p *Parser) matchTypeEnum() (*ast.TypeEnum, error) {
	l := p.lexer
	if ok, err := l.match('<'); !ok || err != nil {
		return nil, err
	}
	fields, err := p.matchEnumFields()
	if err != nil {
		return nil, err
	}
	ok, err := l.match('>')
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, p.error("mismatched brackets while parsing enum type")
	}
	return &ast.TypeEnum{
		Op:       "TypeEnum",
		Elements: fields,
	}, nil
}

func (p *Parser) matchEnumFields() ([]ast.Field, error) {
	l := p.lexer
	var fields []ast.Field
	for {
		field, err := p.matchEnumField()
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

func (p *Parser) matchEnumField() (*ast.Field, error) {
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
	var val ast.Value
	if ok {
		v, err := p.ParseValue()
		if err != nil {
			return nil, err
		}
		val = v
	}
	return &ast.Field{
		Name:  name,
		Value: val,
	}, nil
}
