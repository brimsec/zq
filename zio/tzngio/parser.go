package tzngio

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

//XXX
func (t *TypeMap) Parse(in []byte) (zcode.Bytes, error) {
	return ParseContainer(t, in)
}

func (t *TypeRecord) Parse(in []byte) (zcode.Bytes, error) {
	return ParseContainer(t, in)
}

func (t *TypeSet) Parse(in []byte) (zcode.Bytes, error) {
	return ParseContainer(t, in)
}

func (t *TypeUnion) Parse(in []byte) (zcode.Bytes, error) {
	return ParseContainer(t, in)
}

//XXX this literal stuff is going away replace with ast.Value

// Parse translates an ast.Literal into a Value.
// This currently supports only primitive literals.
func Parse(v ast.Literal) (Value, error) {
	t := LookupPrimitive(v.Type)
	if t == nil {
		return Value{}, fmt.Errorf("unsupported type %s in ast.Literal", v.Type)
	}
	zv, err := t.Parse([]byte(v.Value))
	if err != nil {
		return Value{}, err
	}
	return Value{t, zv}, nil
}

func parseContainer(containerType Type, elementType Type, b zcode.Bytes) ([]Value, error) {
	// We start out with a pointer instead of nil so that empty sets and arrays
	// are properly encoded etc., e.g., by json.Marshal.
	vals := []Value{}
	for it := b.Iter(); !it.Done(); {
		zv, _, err := it.Next()
		if err != nil {
			return nil, fmt.Errorf("parsing %s element %q: %w", containerType.String(), zv, err)
		}
		vals = append(vals, Value{elementType, zv})
	}
	return vals, nil
}

func (t *TypeArray) Decode(zv zcode.Bytes) ([]Value, error) {
	if zv == nil {
		return nil, nil
	}
	return parseContainer(t, t.Type, zv)
}

func (t *TypeSet) Decode(zv zcode.Bytes) ([]Value, error) {
	if zv == nil {
		return nil, nil
	}
	return parseContainer(t, t.Type, zv)
}

func (t *TypeOfBstring) Parse(in []byte) (zcode.Bytes, error) {
	normalized := norm.NFC.Bytes(UnescapeBstring(in))
	return normalized, nil
}

func (t *TypeOfString) Parse(in []byte) (zcode.Bytes, error) {
	normalized := norm.NFC.Bytes(UnescapeString(in))
	return normalized, nil
}
