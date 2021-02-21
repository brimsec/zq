package resolver

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
)

var (
	ErrEmptyTypeList = errors.New("empty type list in set or union")
	ErrAliasExists   = errors.New("alias exists with different type")
)

// A Context manages the mapping between small-integer descriptor identifiers
// and zng descriptor objects, which hold the binding between an identifier
// and a zng.Type.
type Context struct {
	mu       sync.RWMutex
	table    []zng.Type
	lut      map[string]int
	typedefs map[string]*zng.TypeAlias
}

func NewContext() *Context {
	return &Context{
		//XXX hack... leave blanks for primitive types... will fix this later
		table:    make([]zng.Type, zng.IdTypeDef),
		lut:      make(map[string]int),
		typedefs: make(map[string]*zng.TypeAlias),
	}
}

func (c *Context) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Reset the table that maps type ID numbers to zng.Types and reset
	// the lookup table that maps type strings to these locally scoped
	// type ID number.
	c.table = c.table[:zng.IdTypeDef]
	c.lut = make(map[string]int)
}

func (c *Context) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.table)
}

func (c *Context) Serialize() ([]byte, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := serializeTypes(nil, c.table[zng.IdTypeDef:])
	return b, len(c.table)
}

func (c *Context) LookupType(id int) (zng.Type, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lookupTypeWithLock(id)
}

func (c *Context) lookupTypeWithLock(id int) (zng.Type, error) {
	if id < 0 || id >= len(c.table) {
		return nil, fmt.Errorf("id %d out of range for table of size %d", id, len(c.table))
	}
	if id < zng.IdTypeDef {
		typ := zng.LookupPrimitiveById(id)
		if typ != nil {
			return typ, nil
		}
	} else if typ := c.table[id]; typ != nil {
		return typ, nil
	}
	return nil, fmt.Errorf("no type found for id %d", id)
}

func (c *Context) Lookup(td int) *zng.TypeRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if td >= len(c.table) {
		return nil
	}
	typ := c.table[td]
	if typ != nil {
		if typ, ok := typ.(*zng.TypeRecord); ok {
			return typ
		}
	}
	return nil
}

func setKey(inner zng.Type) string {
	return fmt.Sprintf("s%d", inner.ID())
}

func mapKey(keyType, valType zng.Type) string {
	return fmt.Sprintf("m%d:%d", keyType.ID(), valType.ID())
}

func arrayKey(inner zng.Type) string {
	return fmt.Sprintf("a%d", inner.ID())
}

func typeTypeKey(typ zng.Type) string {
	return fmt.Sprintf("t%d", typ.ID())
}

func aliasKey(name string) string {
	return fmt.Sprintf("x%s", name)
}

func enumKey(typ zng.Type, elements []zng.Element) string {
	key := fmt.Sprintf("e:%d:", typ.ID())
	for _, e := range elements {
		key += fmt.Sprintf("%s:[%s];", e.Name, typ.StringOf(e.Value, zng.OutFormatZNG, false))
	}
	return key
}

func recordKey(columns []zng.Column) string {
	key := "r"
	for _, col := range columns {
		id := col.Type.ID()
		if alias, ok := col.Type.(*zng.TypeAlias); ok {
			// XXX why is this here?  The id should just be the aliast ID, no need for its name
			key += fmt.Sprintf("%s:%s/%d;", col.Name, alias.Name, alias.ID())
			continue
		}
		key += fmt.Sprintf("%s:%d;", col.Name, id)
	}
	return key
}

func unionKey(types []zng.Type) string {
	key := "u"
	key += fmt.Sprintf("%d", types[0].ID())
	for _, t := range types[1:] {
		key += fmt.Sprintf(",%d", t.ID())
	}
	return key
}

func typeKey(typ zng.Type) string {
	switch typ := typ.(type) {
	case *zng.TypeAlias:
		return aliasKey(typ.Name)
	case *zng.TypeRecord:
		return recordKey(typ.Columns)
	case *zng.TypeArray:
		return arrayKey(typ.Type)
	case *zng.TypeSet:
		return setKey(typ.Type)
	case *zng.TypeUnion:
		return unionKey(typ.Types)
	case *zng.TypeEnum:
		//XXX why not use this for everything?
		// See Issue #1418
		return "e:" + typ.String()
	case *zng.TypeMap:
		//XXX why not use this for everything?
		// See Issue #1418
		return "m:" + typ.String()
	default:
		panic("unsupported type in typeKey")
	}
}

func (c *Context) addTypeWithLock(key string, typ zng.Type) {
	id := len(c.table)
	c.lut[key] = id
	c.table = append(c.table, typ)
	switch typ := typ.(type) {
	case *zng.TypeAlias:
		typ.SetID(id)
	case *zng.TypeRecord:
		typ.SetID(id)
	case *zng.TypeArray:
		typ.SetID(id)
	case *zng.TypeSet:
		typ.SetID(id)
	case *zng.TypeUnion:
		typ.SetID(id)
	case *zng.TypeEnum:
		typ.SetID(id)
	case *zng.TypeMap:
		typ.SetID(id)
	default:
		panic("unsupported type in addTypeWithLock: " + typ.String())
	}
}

// AddType adds a new type from a path that could race with another
// path creating the same type.  So we take the lock then check if the
// type already exists and if not add it while locked.
func (c *Context) AddType(t zng.Type) zng.Type {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := typeKey(t)
	id, ok := c.lut[key]
	if ok {
		t = c.table[id]
	} else {
		c.addTypeWithLock(key, t)
	}
	return t
}

// LookupTypeRecord returns a zng.TypeRecord within this context that binds with the
// indicated columns.  Subsequent calls with the same columns will return the
// same record pointer.  If the type doesn't exist, it's created, stored,
// and returned.  The closure of types within the columns must all be from
// this type context.  If you want to use columns from a different type context,
// use TranslateTypeRecord.
func (c *Context) LookupTypeRecord(columns []zng.Column) (*zng.TypeRecord, error) {
	// First check for duplicate columns
	names := make(map[string]struct{})
	var val struct{}
	for _, col := range columns {
		_, ok := names[col.Name]
		if ok {
			return nil, fmt.Errorf("duplicate field %s", col.Name)
		}
		names[col.Name] = val
	}

	key := recordKey(columns)
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.lut[key]
	if ok {
		return c.table[id].(*zng.TypeRecord), nil
	}
	dup := make([]zng.Column, 0, len(columns))
	typ := zng.NewTypeRecord(-1, append(dup, columns...))
	c.addTypeWithLock(key, typ)
	return typ, nil
}

func (c *Context) MustLookupTypeRecord(columns []zng.Column) *zng.TypeRecord {
	r, err := c.LookupTypeRecord(columns)
	if err != nil {
		panic(err)
	}
	return r
}

func (c *Context) LookupTypeSet(inner zng.Type) *zng.TypeSet {
	key := setKey(inner)
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.lut[key]
	if ok {
		return c.table[id].(*zng.TypeSet)
	}
	typ := zng.NewTypeSet(-1, inner)
	c.addTypeWithLock(key, typ)
	return typ
}

func (c *Context) LookupTypeMap(keyType, valType zng.Type) *zng.TypeMap {
	key := mapKey(keyType, valType)
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.lut[key]
	if ok {
		return c.table[id].(*zng.TypeMap)
	}
	typ := zng.NewTypeMap(-1, keyType, valType)
	c.addTypeWithLock(key, typ)
	return typ
}

func (c *Context) LookupTypeArray(inner zng.Type) *zng.TypeArray {
	key := arrayKey(inner)
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.lut[key]
	if ok {
		return c.table[id].(*zng.TypeArray)
	}
	typ := zng.NewTypeArray(-1, inner)
	c.addTypeWithLock(key, typ)
	return typ
}

func (c *Context) LookupTypeUnion(types []zng.Type) *zng.TypeUnion {
	key := unionKey(types)
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.lut[key]
	if ok {
		return c.table[id].(*zng.TypeUnion)
	}
	typ := zng.NewTypeUnion(-1, types)
	c.addTypeWithLock(key, typ)
	return typ
}

func (c *Context) LookupTypeEnum(typ zng.Type, elements []zng.Element) *zng.TypeEnum {
	key := enumKey(typ, elements)
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.lut[key]
	if ok {
		return c.table[id].(*zng.TypeEnum)
	}
	enumType := zng.NewTypeEnum(-1, typ, elements)
	c.addTypeWithLock(key, enumType)
	return enumType
}

func (c *Context) LookupTypeDef(name string) *zng.TypeAlias {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.typedefs[name]
}

func (c *Context) LookupTypeAlias(name string, target zng.Type) (*zng.TypeAlias, error) {
	key := aliasKey(name)
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.lut[key]
	if ok {
		alias := c.table[id].(*zng.TypeAlias)
		if zng.SameType(alias.Type, target) {
			return alias, nil
		} else {
			return nil, ErrAliasExists
		}
	}
	typ := zng.NewTypeAlias(-1, name, target)
	c.typedefs[name] = typ
	c.addTypeWithLock(key, typ)
	return typ, nil
}

// AddColumns returns a new zbuf.Record with columns equal to the given
// record along with new rightmost columns as indicated with the given values.
// If any of the newly provided columns already exists in the specified value,
// an error is returned.
func (c *Context) AddColumns(r *zng.Record, newCols []zng.Column, vals []zng.Value) (*zng.Record, error) {
	oldCols := r.Type.Columns
	outCols := make([]zng.Column, len(oldCols), len(oldCols)+len(newCols))
	copy(outCols, oldCols)
	for _, col := range newCols {
		if r.HasField(string(col.Name)) {
			return nil, fmt.Errorf("field already exists: %s", col.Name)
		}
		outCols = append(outCols, col)
	}
	zv := make(zcode.Bytes, len(r.Raw))
	copy(zv, r.Raw)
	for _, val := range vals {
		zv = val.Encode(zv)
	}
	typ, err := c.LookupTypeRecord(outCols)
	if err != nil {
		return nil, err
	}
	return zng.NewRecord(typ, zv), nil
}

func isIdChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.'
}

func parseWord(in string) (string, string) {
	in = strings.TrimSpace(in)
	var off int
	for ; off < len(in); off++ {
		if !isIdChar(in[off]) {
			break
		}
	}
	if off == 0 {
		return "", ""
	}
	return in[off:], in[:off]
}

// LookupByName returns the Type indicated by the zng type string.  The type string
// may be a simple type like int, double, time, etc or it may be a set
// or an array, which are recusively composed of other types.  The set and array
// type definitions are encoded in the same fashion as zeek stores them as type field
// in a zeek file header.  Each unique compound type object is created once and
// interned so that pointer comparison can be used to determine type equality.
func (c *Context) LookupByName(in string) (zng.Type, error) {
	rest, typ, err := c.parseType(in)
	// check if there is still text at the end of the type string...
	if err == nil && rest != "" {
		err = zng.ErrTypeSyntax
	}
	return typ, err
}

// Localize takes a type from another context and creates and returns that
// type in this context.
func (c *Context) Localize(foreign zng.Type) zng.Type {
	// there can't be an error here since the type string
	// is generated internally
	typ, _ := c.LookupByName(foreign.String())
	return typ
}

func (c *Context) parseType(in string) (string, zng.Type, error) {
	in = strings.TrimSpace(in)
	c.mu.RLock()
	id, ok := c.lut[in]
	if ok {
		typ := c.table[id]
		c.mu.RUnlock()
		return "", typ, nil
	}
	c.mu.RUnlock()
	rest, word := parseWord(in)
	if word == "" {
		return "", nil, fmt.Errorf("unknown type: %s", in)
	}
	typ := zng.LookupPrimitive(word)
	if typ != nil {
		return rest, typ, nil
	}
	c.mu.RLock()
	id, ok = c.lut[word]
	if ok {
		typ := c.table[id]
		c.mu.RUnlock()
		return rest, typ, nil
	}
	c.mu.RUnlock()
	switch word {
	case "set":
		rest, t, err := c.parseSetTypeBody(rest)
		if err != nil {
			return "", nil, err
		}
		return rest, t, nil
	case "array":
		rest, t, err := c.parseArrayTypeBody(rest)
		if err != nil {
			return "", nil, err
		}
		return rest, t, nil
	case "record":
		rest, t, err := c.parseRecordTypeBody(rest)
		if err != nil {
			return "", nil, err
		}
		return rest, t, nil
	case "union":
		rest, t, err := c.parseUnionTypeBody(rest)
		if err != nil {
			return "", nil, err
		}
		return rest, t, nil
	case "enum":
		rest, t, err := c.parseEnumTypeBody(rest)
		if err != nil {
			return "", nil, err
		}
		return rest, t, nil
	case "map":
		rest, t, err := c.parseMapTypeBody(rest)
		if err != nil {
			return "", nil, err
		}
		return rest, t, nil
	}
	c.mu.RLock()
	// check alias
	id, ok = c.lut[aliasKey(word)]
	if ok {
		typ := c.table[id]
		c.mu.RUnlock()
		return rest, typ, nil
	}
	c.mu.RUnlock()
	return "", nil, fmt.Errorf("unknown type: %s", word)
}

func match(in, pattern string) (string, bool) {
	in = strings.TrimSpace(in)
	if strings.HasPrefix(in, pattern) {
		return in[len(pattern):], true
	}
	return in, false
}

// parseRecordTypeBody parses a list of record columns of the form "[field:type,...]".
func (c *Context) parseRecordTypeBody(in string) (string, zng.Type, error) {
	in, ok := match(in, "[")
	if !ok {
		return "", nil, zng.ErrTypeSyntax
	}
	in, ok = match(in, "]")
	if ok {
		typ, err := c.LookupTypeRecord([]zng.Column{})
		if err != nil {
			return "", nil, err
		}
		return in, typ, nil
	}
	var columns []zng.Column
	for {
		// at top of loop, we have to have a field def either because
		// this is the first def or we found a comma and are expecting
		// another one.
		rest, col, err := c.parseColumn(in)
		if err != nil {
			return "", nil, err
		}
		columns = append(columns, col)
		rest, ok = match(rest, ",")
		if ok {
			in = rest
			continue
		}
		rest, ok = match(rest, "]")
		if !ok {
			return "", nil, zng.ErrTypeSyntax
		}
		typ, err := c.LookupTypeRecord(columns)
		if err != nil {
			return "", nil, err
		}
		return rest, typ, nil
	}
}

func (c *Context) parseColumn(in string) (string, zng.Column, error) {
	in = strings.TrimSpace(in)
	rest, name, err := c.parseName(in)
	if err != nil {
		return "", zng.Column{}, err
	}
	var typ zng.Type
	rest, typ, err = c.parseType(rest)
	if err != nil {
		return "", zng.Column{}, err
	}
	if typ == nil {
		return "", zng.Column{}, zng.ErrTypeSyntax
	}
	return rest, zng.NewColumn(name, typ), nil
}

// parseTypeList parses a type list of the form "[type1,type2,type3]".
func (c *Context) parseTypeList(in string) (string, []zng.Type, error) {
	rest, ok := match(in, "[")
	if !ok {
		return "", nil, zng.ErrTypeSyntax
	}
	if rest[0] == ']' {
		return "", nil, ErrEmptyTypeList
	}
	in = rest
	var types []zng.Type
	for {
		// at top of loop, we have to have a field def either because
		// this is the first def or we found a comma and are expecting
		// another one.
		rest, typ, err := c.parseType(in)
		if err != nil {
			return "", nil, err
		}
		types = append(types, typ)
		rest, ok = match(rest, ",")
		if ok {
			in = rest
			continue
		}
		rest, ok = match(rest, "]")
		if !ok {
			return "", nil, zng.ErrTypeSyntax
		}
		return rest, types, nil
	}
}

// parseSetTypeBody parses a set type body of the form "[type]" presuming the set
// keyword is already matched.
func (c *Context) parseSetTypeBody(in string) (string, zng.Type, error) {
	rest, types, err := c.parseTypeList(in)
	if err != nil {
		return "", nil, err
	}
	if len(types) > 1 {
		return "", nil, fmt.Errorf("sets with multiple type parameters")
	}
	return rest, c.LookupTypeSet(types[0]), nil
}

// parseMapTypeBody parses a maap type body of the form "[type,type]" presuming
// the map keyword is already matched.
// The syntax is "map[keyType,valType]".
func (c *Context) parseMapTypeBody(in string) (string, zng.Type, error) {
	rest, types, err := c.parseTypeList(in)
	if err != nil {
		return "", nil, err
	}
	if len(types) != 2 {
		return "", nil, fmt.Errorf("map type must have exactly two type parameters")
	}
	return rest, c.LookupTypeMap(types[0], types[1]), nil
}

// parseUnionTypeBody parses a set type body of the form
// "[type1,type2,...]" presuming the union keyword is already matched.
func (c *Context) parseUnionTypeBody(in string) (string, zng.Type, error) {
	rest, types, err := c.parseTypeList(in)
	if err != nil {
		return "", nil, err
	}
	return rest, c.LookupTypeUnion(types), nil
}

// parse an array body type of the form "[type]"
func (c *Context) parseArrayTypeBody(in string) (string, *zng.TypeArray, error) {
	rest, ok := match(in, "[")
	if !ok {
		return "", nil, zng.ErrTypeSyntax
	}
	var inner zng.Type
	var err error
	rest, inner, err = c.parseType(rest)
	if err != nil {
		return "", nil, err
	}
	rest, ok = match(rest, "]")
	if !ok {
		return "", nil, zng.ErrTypeSyntax
	}
	return rest, c.LookupTypeArray(inner), nil
}

// parse an array body type of the form "[type]"
func (c *Context) parseEnumTypeBody(in string) (string, *zng.TypeEnum, error) {
	rest, ok := match(in, "[")
	if !ok {
		return "", nil, zng.ErrTypeSyntax
	}
	var typ zng.Type
	var err error
	rest, typ, err = c.parseType(rest)
	if err != nil {
		return "", nil, err
	}
	rest, ok = match(rest, ",")
	if !ok {
		return "", nil, zng.ErrTypeSyntax
	}
	var elements []zng.Element
	rest, elements, err = c.parseElements(typ, rest)
	if err != nil {
		return "", nil, err
	}
	return rest, c.LookupTypeEnum(typ, elements), nil
}

// Parses a name up to the colon of the form "<id>:" or "[<tzng-strinig>]:"
func (c *Context) parseName(in string) (string, string, error) {
	in = strings.TrimSpace(in)
	if in, ok := match(in, "["); ok {
		rbracket := strings.IndexByte(in, byte(']'))
		if rbracket < 0 {
			return "", "", zng.ErrTypeSyntax
		}
		name := strings.TrimSpace(in[:rbracket])
		rest := in[rbracket+1:]
		rest, ok := match(rest, ":")
		if !ok {
			return "", "", zng.ErrTypeSyntax
		}
		return rest, name, nil
	}
	colon := strings.IndexByte(in, byte(':'))
	if colon < 0 {
		return "", "", zng.ErrTypeSyntax
	}
	name := strings.TrimSpace(in[:colon])
	if !zng.IsIdentifier(name) {
		return "", "", zng.ErrTypeSyntax
	}
	return in[colon+1:], name, nil
}

func (c *Context) parseElements(typ zng.Type, in string) (string, []zng.Element, error) {
	var elems []zng.Element
	for {
		// at top of loop, we have to have a element def either because
		// this is the first def or we found a comma and are expecting
		// another one.
		rest, elem, err := c.parseElement(typ, in)
		if err != nil {
			return "", nil, err
		}
		elems = append(elems, elem)
		var ok bool
		rest, ok = match(rest, ",")
		if ok {
			in = rest
			continue
		}
		rest, ok = match(rest, "]")
		if !ok {
			return "", nil, zng.ErrTypeSyntax
		}
		return rest, elems, nil
	}
}

func (c *Context) parseElement(typ zng.Type, in string) (string, zng.Element, error) {
	rest, name, err := c.parseName(in)
	if err != nil {
		return "", zng.Element{}, err
	}
	rest, ok := match(rest, "[")
	if !ok {
		return "", zng.Element{}, err
	}
	rbracket := strings.IndexByte(rest, byte(']'))
	if rbracket < 0 {
		return "", zng.Element{}, zng.ErrTypeSyntax
	}
	val := rest[:rbracket]
	zv, err := typ.Parse([]byte(val))
	if err != nil {
		return "", zng.Element{}, zng.ErrTypeSyntax
	}
	rest = rest[rbracket+1:]
	return rest, zng.Element{name, zv}, nil
}

func (c *Context) TranslateType(ext zng.Type) (zng.Type, error) {
	switch ext := ext.(type) {
	case *zng.TypeRecord:
		return c.TranslateTypeRecord(ext)
	case *zng.TypeSet:
		inner, err := c.TranslateType(ext.Type)
		if err != nil {
			return nil, err
		}
		return c.LookupTypeSet(inner), nil
	case *zng.TypeArray:
		inner, err := c.TranslateType(ext.Type)
		if err != nil {
			return nil, err
		}
		return c.LookupTypeArray(inner), nil
	case *zng.TypeUnion:
		return c.TranslateTypeUnion(ext)
	case *zng.TypeEnum:
		return c.TranslateTypeEnum(ext)
	case *zng.TypeMap:
		return c.TranslateTypeMap(ext)
	case *zng.TypeAlias:
		local, err := c.TranslateType(ext.Type)
		if err != nil {
			return nil, err
		}
		return c.LookupTypeAlias(ext.Name, local)
	default:
		// primitive type
		return ext, nil
	}
}

func (c *Context) TranslateTypeRecord(ext *zng.TypeRecord) (*zng.TypeRecord, error) {
	var columns []zng.Column
	for _, col := range ext.Columns {
		child, err := c.TranslateType(col.Type)
		if err != nil {
			return nil, err
		}
		columns = append(columns, zng.NewColumn(col.Name, child))
	}
	return c.MustLookupTypeRecord(columns), nil
}

func (c *Context) TranslateTypeUnion(ext *zng.TypeUnion) (*zng.TypeUnion, error) {
	var types []zng.Type
	for _, t := range ext.Types {
		translated, err := c.TranslateType(t)
		if err != nil {
			return nil, err
		}
		types = append(types, translated)
	}
	return c.LookupTypeUnion(types), nil
}

//XXX this translate methods call be done with tzng type name and all go away,
// especially since the LookupType* does a LUT lookup by (modified) name anyway
func (c *Context) TranslateTypeEnum(ext *zng.TypeEnum) (*zng.TypeEnum, error) {
	translated, err := c.TranslateType(ext.Type)
	if err != nil {
		return nil, err
	}
	return c.LookupTypeEnum(translated, ext.Elements), nil
}

func (c *Context) TranslateTypeMap(ext *zng.TypeMap) (*zng.TypeMap, error) {
	keyType, err := c.TranslateType(ext.KeyType)
	if err != nil {
		return nil, err
	}
	valType, err := c.TranslateType(ext.ValType)
	if err != nil {
		return nil, err
	}
	return c.LookupTypeMap(keyType, valType), nil
}
