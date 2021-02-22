package zng

import (
	"errors"

	"github.com/brimsec/zq/zcode"
)

var (
	ErrUnterminated = errors.New("tzng syntax error: unterminated container")
	ErrSyntax       = errors.New("tzng syntax error")
)

type Parser struct {
	zcode.Builder
}

func NewParser() *Parser {
	return &Parser{*zcode.NewBuilder()}
}

// Parse decodes a zng value in text format using the type information
// in the descriptor.  Once parsed, the resulting zcode.Bytes has
// the nested data structure encoded independently of the data type.
func (p *Parser) Parse(typ *TypeRecord, zng []byte) (zcode.Bytes, error) {
	p.Reset()
	if zng[0] != leftbracket {
		return nil, ErrSyntax
	}
	rest, err := p.ParseContainer(typ, zng)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, ErrSyntax
	}
	return p.Bytes().ContainerBody()
}

const (
	semicolon    = byte(';')
	leftbracket  = byte('[')
	rightbracket = byte(']')
	backslash    = byte('\\')
)

// ParseContainer parses the given byte array representing a container
// in the zng format.
func (p *Parser) ParseContainer(typ Type, b []byte) ([]byte, error) {
	realType := AliasedType(typ)
	// This is hokey.
	var keyType, valType Type
	if typ, ok := realType.(*TypeMap); ok {
		keyType = typ.KeyType
		valType = typ.ValType
	}
	p.BeginContainer()
	// skip leftbracket
	b = b[1:]
	childType, columns := ContainedType(realType)
	if childType == nil && columns == nil && keyType == nil {
		return nil, ErrNotPrimitive
	}

	k := 0
	for {
		if len(b) == 0 {
			return nil, ErrUnterminated
		}
		if b[0] == rightbracket {
			if _, ok := realType.(*TypeSet); ok {
				p.TransformContainer(NormalizeSet)
			}
			if _, ok := realType.(*TypeMap); ok {
				p.TransformContainer(NormalizeMap)
			}
			p.EndContainer()
			return b[1:], nil
		}
		if columns != nil {
			if k >= len(columns) {
				return nil, &RecordTypeError{Name: "<record>", Type: typ.String(), Err: ErrExtraField}
			}
			childType = columns[k].Type
			k++
		}
		if keyType != nil {
			if (k & 1) == 0 {
				childType = keyType
			} else {
				childType = valType
			}
			k++
		}
		rest, err := p.ParseField(childType, b)
		if err != nil {
			return nil, err
		}
		b = rest
	}
}

// ParseField parses the given byte array representing any value
// in the zng format.
func (p *Parser) ParseField(typ Type, b []byte) ([]byte, error) {
	realType := AliasedType(typ)
	var err error
	var index int
	if len(b) >= 2 && b[0] == '-' && b[1] == ';' {
		if IsContainerType(realType) {
			p.AppendContainer(nil)
		} else {
			p.AppendPrimitive(nil)
		}
		return b[2:], nil
	}
	if utyp, ok := realType.(*TypeUnion); ok {
		var childType Type
		childType, index, b, err = utyp.SplitTzng(b)
		if err != nil {
			return nil, err
		}
		p.BeginContainer()
		defer p.EndContainer()
		p.AppendPrimitive(EncodeInt(int64(index)))
		return p.ParseField(childType, b)
	}
	if b[0] == leftbracket {
		return p.ParseContainer(typ, b)
	}
	if IsContainerType(realType) {
		return nil, ErrNotContainer
	}

	// We don't actually need to handle escapes here, type.Parse()
	// will take care of that.  The important thing is just figuring
	// out the proper boundary between individual records (skipping
	// over an escaped semicolon without being tricked by something
	// like \\; which could be an escaped backslash followed by a
	// real semicolon)
	i := 0
	for ; i < len(b); i++ {
		if b[i] == semicolon {
			break
		}
		if b[i] == backslash {
			i++
		}
	}
	if i == len(b) {
		return nil, ErrUnterminated
	}

	zv, err := realType.Parse(b[:i])
	if err != nil {
		return nil, err
	}
	p.AppendPrimitive(zv)
	return b[i+1:], nil
}

func ParseContainer(typ Type, in []byte) (zcode.Bytes, error) {
	p := NewParser()
	_, err := p.ParseContainer(typ, in)
	if err != nil {
		return nil, err
	}
	return p.Bytes().ContainerBody()
}
