package resolver

import (
	"errors"
	"fmt"
	"sync"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
)

var (
	ErrEmptyTypeList = errors.New("empty type list in set or union")
	ErrAliasExists   = errors.New("alias exists with different type")
)

type TypeResolver interface {
	Lookup(string) (zng.Type, error)
}

// A Context manages the mapping between small-integer descriptor identifiers
// and zng descriptor objects, which hold the binding between an identifier
// and a zng.Type.
type Context struct {
	mu       sync.RWMutex
	table    []zng.Type
	lut      map[string]int
	typedefs map[string]*zng.TypeAlias
	resolver TypeResolver
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
		panic("unsupported type in addTypeWithLock: " + typ.ZSON())
	}
}

// AddType adds a new type from a path that could race with another
// path creating the same type.  So we take the lock then check if the
// type already exists and if not add it while locked.
func (c *Context) AddType(t zng.Type) zng.Type {
	key := t.ZSON()
	c.mu.Lock()
	defer c.mu.Unlock()
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
	tmp := &zng.TypeRecord{Columns: columns}
	key := tmp.ZSON()
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
	tmp := &zng.TypeSet{Type: inner}
	key := tmp.ZSON()
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
	tmp := &zng.TypeMap{KeyType: keyType, ValType: valType}
	key := tmp.ZSON()
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
	tmp := &zng.TypeArray{Type: inner}
	key := tmp.ZSON()
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
	tmp := zng.TypeUnion{Types: types}
	key := tmp.ZSON()
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
	tmp := zng.TypeEnum{Type: typ, Elements: elements}
	key := tmp.ZSON()
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
	tmp := zng.TypeAlias{Name: name, Type: target}
	key := tmp.ZSON()
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

// LookupByName returns the Type indicated by the zng type string.  The type string
// may be a simple type like int, double, time, etc or it may be a set
// or an array, which are recusively composed of other types.  The set and array
// type definitions are encoded in the same fashion as zeek stores them as type field
// in a zeek file header.  Each unique compound type object is created once and
// interned so that pointer comparison can be used to determine type equality.

//XXX package zson should do this now...?

func (c *Context) LookupByName(zson string) (zng.Type, error) {
	if c.resolver == nil {
		return nil, errors.New("LookupByName cannot be called without resolver")
	}
	return c.resolver.Lookup(zson)
}

// Localize takes a type from another context and creates and returns that
// type in this context.
func (c *Context) Localize(foreign zng.Type) zng.Type {
	// there can't be an error here since the type string
	// is generated internally
	typ, _ := c.LookupByName(foreign.ZSON())
	return typ
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
