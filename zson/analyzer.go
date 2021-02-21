package zson

import (
	"errors"
	"fmt"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

type Value interface {
	TypeOf() zng.Type
	SetType(zng.Type)
}

// Note that all of the types include a generic zng.Type as their type since
// anything can have a named typed which is a zng.TypeAlias along with their
// normal type.
type (
	Primitive struct {
		Type zng.Type
		Text string
	}
	Record struct {
		Type   zng.Type
		Fields []Value
	}
	Array struct {
		Type     zng.Type
		Elements []Value
	}
	Set struct {
		Type     zng.Type
		Elements []Value
	}
	Union struct {
		Type     zng.Type
		Selector int
		Value    Value
	}
	Enum struct {
		Type     zng.Type
		Selector int
		Name     string
	}
	Map struct {
		Type    zng.Type
		Entries []Entry
	}
	Entry struct {
		Key   Value
		Value Value
	}
	Null struct {
		Type zng.Type
	}
	TypeValue struct {
		Type  zng.Type
		Value zng.Type
	}
)

func (p *Primitive) TypeOf() zng.Type { return p.Type }
func (r *Record) TypeOf() zng.Type    { return r.Type }
func (a *Array) TypeOf() zng.Type     { return a.Type }
func (s *Set) TypeOf() zng.Type       { return s.Type }
func (u *Union) TypeOf() zng.Type     { return u.Type }
func (e *Enum) TypeOf() zng.Type      { return e.Type }
func (m *Map) TypeOf() zng.Type       { return m.Type }
func (n *Null) TypeOf() zng.Type      { return n.Type }
func (t *TypeValue) TypeOf() zng.Type { return t.Type }

func (p *Primitive) SetType(t zng.Type) { p.Type = t }
func (r *Record) SetType(t zng.Type)    { r.Type = t }
func (a *Array) SetType(t zng.Type)     { a.Type = t }
func (s *Set) SetType(t zng.Type)       { s.Type = t }
func (u *Union) SetType(t zng.Type)     { u.Type = t }
func (e *Enum) SetType(t zng.Type)      { e.Type = t }
func (m *Map) SetType(t zng.Type)       { m.Type = t }
func (n *Null) SetType(t zng.Type)      { n.Type = t }
func (t *TypeValue) SetType(T zng.Type) { t.Type = T }

// An Analyzer transforms an ast.Value (which has decentralized type decorators)
// to a typed Value, where every component of a nested Value is explicitly typed.
// This is done via a semantic analysis where type state flows both down a the
// nested value hierarchy (via type decorators) and back up via fully typed value
// whose types are then usable as typedefs.  The Analyzer tracks the ZSON typedef
// semantics by updating its table of name-to-type bindings in accordance with the
// left-to-right, depth-first semantics of ZSON typedefs.
type Analyzer map[string]zng.Type

func NewAnalyzer() Analyzer {
	return Analyzer(make(map[string]zng.Type))
}

func (a Analyzer) ConvertValue(zctx *resolver.Context, val ast.Value) (Value, error) {
	return a.convertValue(zctx, val, nil)
}

func (a Analyzer) convertValue(zctx *resolver.Context, val ast.Value, parent zng.Type) (Value, error) {
	switch val := val.(type) {
	case *ast.ImpliedValue:
		return a.convertAny(zctx, val.Of, parent)
	case *ast.DefValue:
		v, err := a.convertAny(zctx, val.Of, parent)
		if err != nil {
			return nil, err
		}
		alias, err := a.enterTypeDef(zctx, val.TypeName, v.TypeOf())
		if err != nil {
			return nil, err
		}
		if alias != nil {
			v.SetType(alias)
		}
		return v, nil
	case *ast.CastValue:
		cast, err := a.convertType(zctx, val.Type)
		if err != nil {
			return nil, err
		}
		if err := a.typeCheck(cast, parent); err != nil {
			return nil, err
		}
		v, err := a.convertValue(zctx, val.Of, cast)
		if err != nil {
			return nil, err
		}
		if union, ok := zng.AliasedType(parent).(*zng.TypeUnion); ok {
			v, err = a.convertUnion(zctx, v, union, parent)
		}
		return v, err
	}
	return nil, fmt.Errorf("unknown value ast type: %T", val)
}

func (a Analyzer) typeCheck(cast, parent zng.Type) error {
	if parent == nil || cast == parent {
		return nil
	}
	if _, ok := zng.AliasedType(parent).(*zng.TypeUnion); ok {
		// We let unions through this type check with no further checking
		// as any union incompability will be caught in convertAnyValue().
		return nil
	}
	return fmt.Errorf("decorator conflict enclosing context %q and decorator cast %q", parent.ZSON(), cast.ZSON())
}

func (a Analyzer) enterTypeDef(zctx *resolver.Context, name string, typ zng.Type) (*zng.TypeAlias, error) {
	var alias *zng.TypeAlias
	if zng.IsTypeName(name) {
		var err error
		if alias, err = zctx.LookupTypeAlias(name, typ); err != nil {
			return nil, err
		}
		if existing, ok := a[name]; ok && existing != alias {
			return nil, fmt.Errorf("type %q redefined from %q to %q", name, existing.ZSON(), typ.ZSON())
		}
		typ = alias
	}
	a[name] = typ
	return alias, nil
}

func (a Analyzer) convertAny(zctx *resolver.Context, val ast.Any, cast zng.Type) (Value, error) {
	// If we're casting something to a union, then the thing inside needs to
	// describe itself and we can convert the inner value to a union value when
	// we know its type (so we can code the selector).
	if union, ok := zng.AliasedType(cast).(*zng.TypeUnion); ok {
		v, err := a.convertAny(zctx, val, nil)
		if err != nil {
			return nil, err
		}
		return a.convertUnion(zctx, v, union, cast)
	}
	switch val := val.(type) {
	case *ast.Primitive:
		return a.convertPrimitive(zctx, val, cast)
	case *ast.Record:
		return a.convertRecord(zctx, val, cast)
	case *ast.Array:
		return a.convertArray(zctx, val, cast)
	case *ast.Set:
		return a.convertSet(zctx, val, cast)
	case *ast.Enum:
		return a.convertEnum(zctx, val, cast)
	case *ast.Map:
		return a.convertMap(zctx, val, cast)
	case *ast.TypeValue:
		return a.convertTypeValue(zctx, val, cast)
	}
	return nil, fmt.Errorf("internal error: unknown ast type in Analyzer.convertAny(): %T", val)
}

func (a Analyzer) convertPrimitive(zctx *resolver.Context, val *ast.Primitive, cast zng.Type) (Value, error) {
	typ := zng.LookupPrimitive(val.Type)
	if typ == nil {
		return nil, fmt.Errorf("no such primitive type: %q", val.Type)
	}
	isNull := typ == zng.TypeNull
	if cast != nil {
		// The parser emits Enum values for identifiers but not for
		// string enum names.  Check if the cast type is an enum,
		// and if so, convert the string to its enum counterpart.
		if v := stringToEnum(val, cast); v != nil {
			return v, nil
		}
		var err error
		typ, err = castType(typ, cast)
		if err != nil {
			return nil, err
		}
	}
	if isNull {
		return &Null{Type: typ}, nil
	}
	return &Primitive{Type: typ, Text: val.Text}, nil
}

func stringToEnum(val *ast.Primitive, cast zng.Type) Value {
	if enum, ok := cast.(*zng.TypeEnum); ok {
		if val.Type == "string" {
			return &Enum{
				Type: enum,
				Name: val.Text,
			}
		}
	}
	return nil
}

func castType(typ, cast zng.Type) (zng.Type, error) {
	if typ == cast || typ == zng.TypeNull {
		return cast, nil
	}
	if zng.IsStringy(typ.ID()) {
		if zng.IsStringy(cast.ID()) {
			return cast, nil
		}
	} else if zng.IsInteger(typ.ID()) {
		if zng.IsInteger(cast.ID()) {
			return cast, nil
		}
	} else if zng.IsFloat(typ.ID()) {
		if zng.IsFloat(cast.ID()) {
			return cast, nil
		}
	}
	return nil, fmt.Errorf("type mismatch: %q cannot be used as %q", typ.ZSON(), cast.ZSON())
}

func (a Analyzer) convertRecord(zctx *resolver.Context, val *ast.Record, cast zng.Type) (Value, error) {
	var fields []Value
	var err error
	if cast != nil {
		recType, ok := zng.AliasedType(cast).(*zng.TypeRecord)
		if !ok {
			return nil, fmt.Errorf("record decorator not of type record: %T", cast)
		}
		if len(recType.Columns) != len(val.Fields) {
			return nil, fmt.Errorf("record decorator columns (%d) mismatched with value columns (%d)", len(recType.Columns), len(val.Fields))
		}
		fields, err = a.convertFields(zctx, val.Fields, recType.Columns)
	} else {
		fields, err = a.convertFields(zctx, val.Fields, nil)
		if err != nil {
			return nil, err
		}
		cast, err = lookupRecordType(zctx, val.Fields, fields)
	}
	if err != nil {
		return nil, err
	}
	return &Record{
		Type:   cast,
		Fields: fields,
	}, nil
}

func (a Analyzer) convertFields(zctx *resolver.Context, in []ast.Field, cols []zng.Column) ([]Value, error) {
	fields := make([]Value, 0, len(in))
	for k, f := range in {
		var cast zng.Type
		if cols != nil {
			cast = cols[k].Type
		}
		v, err := a.convertValue(zctx, f.Value, cast)
		if err != nil {
			return nil, err
		}
		fields = append(fields, v)
	}
	return fields, nil
}

func lookupRecordType(zctx *resolver.Context, fields []ast.Field, vals []Value) (*zng.TypeRecord, error) {
	columns := make([]zng.Column, 0, len(fields))
	for k, f := range fields {
		columns = append(columns, zng.Column{f.Name, vals[k].TypeOf()})
	}
	return zctx.LookupTypeRecord(columns)
}

// Figure out what the cast should be for the elements and for the union conversion if any.
func arrayElemCast(cast zng.Type) (zng.Type, error) {
	if cast == nil {
		return nil, nil
	}
	if arrayType, ok := zng.AliasedType(cast).(*zng.TypeArray); ok {
		return arrayType.Type, nil
	}
	return nil, errors.New("array decorator not of type array")
}

func (a Analyzer) convertArray(zctx *resolver.Context, array *ast.Array, cast zng.Type) (Value, error) {
	vals := make([]Value, 0, len(array.Elements))
	typ, err := arrayElemCast(cast)
	if err != nil {
		return nil, err
	}
	for _, elem := range array.Elements {
		v, err := a.convertValue(zctx, elem, typ)
		if err != nil {
			return nil, err
		}
		vals = append(vals, v)
	}
	if cast != nil || len(vals) == 0 {
		// We had a cast so we know any type mistmatches we have been
		// caught below...
		if cast == nil {
			cast = zctx.LookupTypeArray(zng.TypeNull)
		}
		return &Array{
			Type:     cast,
			Elements: vals,
		}, nil
	}
	// No cast, we need to look up the TypeArray.
	elemType := sameType(vals)
	if elemType != nil {
		// The elements were of uniform type.
		arrayType := zctx.LookupTypeArray(elemType)
		return &Array{arrayType, vals}, nil
	}
	types := differentTypes(vals)
	// See if this array has a mix of a single type and null type and
	// if so return a regular array.
	if array := a.mixedNullArray(zctx, types, vals); array != nil {
		return array, nil
	}
	// The elements are of mixed type so create wrap each value in a union
	// and create the TypeUnion.
	unionType := zctx.LookupTypeUnion(types)
	var unions []Value
	for _, v := range vals {
		union, err := a.convertUnion(zctx, v, unionType, unionType)
		if err != nil {
			return nil, err
		}
		unions = append(unions, union)
	}
	return &Array{
		Type:     zctx.LookupTypeArray(unionType),
		Elements: unions,
	}, nil
}

func (a Analyzer) mixedNullArray(zctx *resolver.Context, types []zng.Type, vals []Value) *Array {
	if len(types) != 2 {
		return nil
	}
	var typ zng.Type
	if types[0] == zng.TypeNull {
		typ = types[1]
	} else if types[1] == zng.TypeNull {
		typ = types[0]
	} else {
		return nil
	}
	// There are two types but one of them is null.  We can use the
	// non-nil type for the array and go back and change the null
	// types to use this same type...
	vals[0].SetType(typ)
	vals[1].SetType(typ)
	arrayType := zctx.LookupTypeArray(typ)
	return &Array{
		Type:     arrayType,
		Elements: vals,
	}
}

func sameType(vals []Value) zng.Type {
	typ := vals[0].TypeOf()
	for _, v := range vals[1:] {
		if typ != v.TypeOf() {
			return nil
		}
	}
	return typ
}

func addUniq(types []zng.Type, typ zng.Type) []zng.Type {
	for _, t := range types {
		if t == typ {
			return types
		}
	}
	return append(types, typ)
}

func differentTypes(vals []Value) []zng.Type {
	out := make([]zng.Type, 0, len(vals))
	for _, v := range vals {
		out = addUniq(out, v.TypeOf())
	}
	return out
}

func (a Analyzer) convertSet(zctx *resolver.Context, set *ast.Set, cast zng.Type) (Value, error) {
	var elemType zng.Type
	if cast != nil {
		setType, ok := zng.AliasedType(cast).(*zng.TypeSet)
		if !ok {
			return nil, fmt.Errorf("set decorator not of type set: %T", cast)
		}
		elemType = setType.Type
	}
	vals := make([]Value, 0, len(set.Elements))
	for _, elem := range set.Elements {
		v, err := a.convertValue(zctx, elem, elemType)
		if err != nil {
			return nil, err
		}
		vals = append(vals, v)
	}
	if cast == nil {
		if elemType == nil {
			if len(vals) == 0 {
				// empty set with no decorator
				elemType = zng.TypeNull
			} else {
				elemType = vals[0].TypeOf()
			}
		}
		cast = zctx.LookupTypeSet(elemType)
	}
	return &Set{
		Type:     cast,
		Elements: vals,
	}, nil
}

func (a Analyzer) convertUnion(zctx *resolver.Context, v Value, union *zng.TypeUnion, cast zng.Type) (Value, error) {
	valType := v.TypeOf()
	if valType == zng.TypeNull {
		// Set selector to -1 to signal to the builder to encode a null.
		return &Union{
			Type:     cast,
			Selector: -1,
			Value:    v,
		}, nil
	}
	for k, typ := range union.Types {
		if valType == typ {
			return &Union{
				Type:     cast,
				Selector: k,
				Value:    v,
			}, nil
		}
	}
	return nil, fmt.Errorf("type %q is not in union type %q", valType.ZSON(), union.ZSON())
}

func (a Analyzer) convertEnum(zctx *resolver.Context, val *ast.Enum, cast zng.Type) (Value, error) {
	if cast == nil {
		return nil, fmt.Errorf("identifier %q must be enum and requires decorator", val.Name)
	}
	enum, ok := zng.AliasedType(cast).(*zng.TypeEnum)
	if !ok {
		return nil, fmt.Errorf("identifier %q is enum and incompatible with type %q", val.Name, cast.ZSON())
	}
	for k, elem := range enum.Elements {
		if elem.Name == val.Name {
			return &Enum{
				Name:     elem.Name,
				Selector: k,
				Type:     cast,
			}, nil
		}
	}
	return nil, fmt.Errorf("identifier %q not a member of enum type %q", val.Name, enum.ZSON())
}

func (a Analyzer) convertMap(zctx *resolver.Context, m *ast.Map, cast zng.Type) (Value, error) {
	var keyType, valType zng.Type
	if cast != nil {
		typ, ok := zng.AliasedType(cast).(*zng.TypeMap)
		if !ok {
			return nil, errors.New("map decorator not of type map")
		}
		keyType = typ.KeyType
		valType = typ.ValType
	}
	entries := make([]Entry, 0, len(m.Entries))
	for _, e := range m.Entries {
		key, err := a.convertValue(zctx, e.Key, keyType)
		if err != nil {
			return nil, err
		}
		val, err := a.convertValue(zctx, e.Value, valType)
		if err != nil {
			return nil, err
		}
		entries = append(entries, Entry{key, val})
	}
	if cast == nil {
		// If there was no decorator, pull the types out of the first
		// entry we just analyed.
		if len(entries) == 0 {
			// empty set with no decorator
			keyType = zng.TypeNull
			valType = zng.TypeNull
		} else {
			keyType = entries[0].Key.TypeOf()
			valType = entries[0].Value.TypeOf()
		}
		cast = zctx.LookupTypeMap(keyType, valType)
	}
	return &Map{
		Type:    cast,
		Entries: entries,
	}, nil
}

func (a Analyzer) convertTypeValue(zctx *resolver.Context, tv *ast.TypeValue, cast zng.Type) (Value, error) {
	if cast != nil {
		if _, ok := zng.AliasedType(cast).(*zng.TypeOfType); !ok {
			return nil, fmt.Errorf("cannot apply decorator (%q) to a type value", cast.ZSON())
		}
	}
	typ, err := a.convertType(zctx, tv.Value)
	if err != nil {
		return nil, err
	}
	if cast == nil {
		cast = typ
	}
	return &TypeValue{
		Type:  cast,
		Value: typ,
	}, nil
}

func (a Analyzer) convertType(zctx *resolver.Context, typ ast.Type) (zng.Type, error) {
	switch t := typ.(type) {
	case *ast.TypePrimitive:
		name := t.Name
		typ := zng.LookupPrimitive(name)
		if typ == nil {
			return nil, fmt.Errorf("no such primitive type: %q", name)
		}
		return typ, nil
	case *ast.TypeDef:
		typ, err := a.convertType(zctx, t.Type)
		if err != nil {
			return nil, err
		}
		alias, err := a.enterTypeDef(zctx, t.Name, typ)
		if err != nil {
			return nil, err
		}
		if alias != nil {
			typ = alias
		}
		return typ, nil
	case *ast.TypeRecord:
		return a.convertTypeRecord(zctx, t)
	case *ast.TypeArray:
		typ, err := a.convertType(zctx, t.Type)
		if err != nil {
			return nil, err
		}
		return zctx.LookupTypeArray(typ), nil
	case *ast.TypeSet:
		typ, err := a.convertType(zctx, t.Type)
		if err != nil {
			return nil, err
		}
		return zctx.LookupTypeSet(typ), nil
	case *ast.TypeMap:
		return a.convertTypeMap(zctx, t)
	case *ast.TypeUnion:
		return a.convertTypeUnion(zctx, t)
	case *ast.TypeEnum:
		return a.convertTypeEnum(zctx, t)
	case *ast.TypeName:
		typ, ok := a[t.Name]
		if !ok {
			return nil, fmt.Errorf("no such type name: %q", t.Name)
		}
		return typ, nil
	}
	return nil, fmt.Errorf("unknown type in Analyzer.convertType: %T", typ)
}

func (a Analyzer) convertTypeRecord(zctx *resolver.Context, typ *ast.TypeRecord) (*zng.TypeRecord, error) {
	fields := typ.Fields
	columns := make([]zng.Column, 0, len(fields))
	for _, f := range fields {
		typ, err := a.convertType(zctx, f.Type)
		if err != nil {
			return nil, err
		}
		columns = append(columns, zng.Column{f.Name, typ})
	}
	return zctx.LookupTypeRecord(columns)
}

func (a Analyzer) convertTypeMap(zctx *resolver.Context, tmap *ast.TypeMap) (*zng.TypeMap, error) {
	keyType, err := a.convertType(zctx, tmap.KeyType)
	if err != nil {
		return nil, err
	}
	valType, err := a.convertType(zctx, tmap.ValType)
	if err != nil {
		return nil, err
	}
	return zctx.LookupTypeMap(keyType, valType), nil
}

func (a Analyzer) convertTypeUnion(zctx *resolver.Context, union *ast.TypeUnion) (*zng.TypeUnion, error) {
	var types []zng.Type
	for _, typ := range union.Types {
		typ, err := a.convertType(zctx, typ)
		if err != nil {
			return nil, err
		}
		types = append(types, typ)
	}
	return zctx.LookupTypeUnion(types), nil
}

func (a Analyzer) convertTypeEnum(zctx *resolver.Context, enum *ast.TypeEnum) (*zng.TypeEnum, error) {
	n := len(enum.Elements)
	if n == 0 {
		return nil, errors.New("enum body is empty")
	}
	var typ zng.Type
	elements := make([]zng.Element, 0, n)
	b := NewBuilder()
	for _, f := range enum.Elements {
		b.Reset()
		v, err := a.convertValue(zctx, f.Value, typ)
		if err != nil {
			return nil, err
		}
		other := v.TypeOf()
		if typ == nil {
			typ = other
		} else if typ != other {
			return nil, fmt.Errorf("mixed type enum values: %q and %q", typ.ZSON(), other.ZSON())
		} else {
			v.SetType(typ)
		}
		zv, err := b.Build(v)
		if err != nil {
			return nil, err
		}
		if zv.Type != typ {
			return nil, fmt.Errorf("internal error built type (%q) does not match semantic type (%q)", zv.Type.ZSON(), typ.ZSON())
		}
		e := zng.Element{
			Name:  f.Name,
			Value: zv.Bytes,
		}
		elements = append(elements, e)
	}
	return zctx.LookupTypeEnum(typ, elements), nil
}
