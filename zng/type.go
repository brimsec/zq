// Package zng implements a data typing system based on the zeek type system.
// All zeek types are defined here and implement the Type interface while instances
// of values implement the Value interface.  All values conform to exactly one type.
// The package provides a fast-path for comparing a value to a byte slice
// without having to create a zeek value from the byte slice.  To exploit this,
// all values include a Comparison method that returns a Predicate function that
// takes a byte slice and a Type and returns a boolean indicating whether the
// the byte slice with the indicated Type matches the value.  The package also
// provides mechanism for coercing values in well-defined and natural ways.
package zng

import (
	"errors"
	"strings"

	"github.com/brimsec/zq/zcode"
)

var (
	ErrLenUnset   = errors.New("len(unset) is undefined")
	ErrNotArray   = errors.New("cannot index a non-array")
	ErrIndex      = errors.New("array index out of bounds")
	ErrUnionIndex = errors.New("union index out of bounds")
	ErrEnumIndex  = errors.New("enum index out of bounds")
)

// The fmt paramter passed to Type.StringOf() must be one of the following
// values, these are used to inform the formatter how containers should be
// encoded and what sort of escaping should be applied to string types.
type OutFmt int

const (
	OutFormatUnescaped = OutFmt(iota)
	OutFormatZNG
	OutFormatZeek
	OutFormatZeekAscii
)

// A Type is an interface presented by a zeek type.
// Types can be used to infer type compatibility and create new values
// of the underlying type.
type Type interface {
	// String returns the name of the type as defined in the ZNG spec.
	String() string
	// StringOf formats an arbitrary value of this type encoded as zcode.
	// The fmt parameter controls output formatting.  The inContainer
	// parameter indicates if this value is inside a set or vector
	// (which is needed to correctly implement  zeek log escaping rules).
	StringOf(zv zcode.Bytes, fmt OutFmt, inContainer bool) string
	// Marshal is used from Value.MarshalJSON(), it should turn an
	// arbitrary value of this type encoded as zcode into something
	// suitable for passing to json.Marshal()
	Marshal(zcode.Bytes) (interface{}, error)
	// Parse transforms a string representation of the type to its zval
	// encoding.  The string input is provided as a byte slice for
	// efficiency given the common use cases in the system.
	Parse([]byte) (zcode.Bytes, error)
	// ID returns a unique (per resolver.Context) identifier that
	// represents this type.  For an aliased type, this identifier
	// represents the actual underlying type and not the alias itself.
	// Callers that care about the underlying type of a zng.Value for
	// example should prefer to use this instead of using the go
	// .(type) operator on a zng.Type instance.
	ID() int

	// XXX temporary methods until we deprecate tzng then we will
	// move this logic into String()/StringOf()
	ZSON() string
	ZSONOf(zv zcode.Bytes) string
}

var (
	TypeUint8    = &TypeOfUint8{}
	TypeUint16   = &TypeOfUint16{}
	TypeUint32   = &TypeOfUint32{}
	TypeUint64   = &TypeOfUint64{}
	TypeInt8     = &TypeOfInt8{}
	TypeInt16    = &TypeOfInt16{}
	TypeInt32    = &TypeOfInt32{}
	TypeInt64    = &TypeOfInt64{}
	TypeDuration = &TypeOfDuration{}
	TypeTime     = &TypeOfTime{}
	// XXX add TypeFloat16
	// XXX add TypeFloat32
	TypeFloat64 = &TypeOfFloat64{}
	// XXX add TypeDecimal
	TypeBool    = &TypeOfBool{}
	TypeBytes   = &TypeOfBytes{}
	TypeString  = &TypeOfString{}
	TypeBstring = &TypeOfBstring{}
	TypeIP      = &TypeOfIP{}
	TypeNet     = &TypeOfNet{}
	TypeType    = &TypeOfType{}
	TypeError   = &TypeOfError{}
	TypeNull    = &TypeOfNull{}
)

const (
	IdUint8    = 0
	IdUint16   = 1
	IdUint32   = 2
	IdUint64   = 3
	IdInt8     = 4
	IdInt16    = 5
	IdInt32    = 6
	IdInt64    = 7
	IdDuration = 8
	IdTime     = 9
	IdFloat16  = 10
	IdFloat32  = 11
	IdFloat64  = 12
	IdDecimal  = 13
	IdBool     = 14
	IdBytes    = 15
	IdString   = 16
	IdBstring  = 17
	IdIP       = 18
	IdNet      = 19
	IdType     = 20
	IdError    = 21
	IdNull     = 22

	IdTypeDef = 23
)

var promote = []int{
	IdInt8,    // IdUint8    = 0
	IdInt16,   // IdUint16   = 1
	IdInt32,   // IdUint32   = 2
	IdInt64,   // IdUint64   = 3
	IdInt8,    // IdInt8     = 4
	IdInt16,   // IdInt16    = 5
	IdInt32,   // IdInt32    = 6
	IdInt64,   // IdInt64    = 7
	IdInt64,   // IdDuration = 8
	IdInt64,   // IdTime     = 9
	IdFloat16, // IdFloat32  = 10
	IdFloat32, // IdFloat32  = 11
	IdFloat64, // IdFloat64  = 12
	IdDecimal, // IdDecimal  = 13
}

// Promote type to the largest signed type where the IDs must both
// satisfy IsNumber.
func PromoteInt(aid, bid int) int {
	id := promote[aid]
	if bid := promote[bid]; bid > id {
		id = bid
	}
	return id
}

// True iff the type id is encoded as a zng signed or unsigened integer zcode.Bytes.
func IsInteger(id int) bool {
	return id <= IdInt64
}

// True iff the type id is encoded as a zng signed or unsigned integer zcode.Bytes,
// float32 zcode.Bytes, or float64 zcode.Bytes.
func IsNumber(id int) bool {
	return id <= IdDecimal
}

// True iff the type id is encoded as a float encoding.
// XXX add IdDecimal here when we implement coercible math with it.
func IsFloat(id int) bool {
	return id >= IdFloat16 && id <= IdFloat64
}

// True iff the type id is encoded as a number encoding and is signed.
func IsSigned(id int) bool {
	return id >= IdInt8 && id <= IdTime
}

// True iff the type id is encoded as a string zcode.Bytes.
func IsStringy(id int) bool {
	return id == IdString || id == IdBstring || id == IdError || id == IdType
}

const (
	CtrlValueEscape   = 0xf5
	TypeDefRecord     = 0xf6
	TypeDefArray      = 0xf7
	TypeDefSet        = 0xf8
	TypeDefUnion      = 0xf9
	TypeDefEnum       = 0xfa
	TypeDefMap        = 0xfb
	TypeDefAlias      = 0xfc
	CtrlCompressed    = 0xfd
	CtrlAppMessage    = 0xfe
	CtrlEOS           = 0xff
	AppEncodingZNG    = 0
	AppEncodingJSON   = 1
	AppEncodingZSON   = 2
	AppEncodingString = 3
	AppEncodingBinary = 4
)

type CompressionFormat int

const CompressionFormatLZ4 CompressionFormat = 0x00

func LookupPrimitive(name string) Type {
	switch name {
	case "uint8":
		return TypeUint8
	case "uint16":
		return TypeUint16
	case "uint32":
		return TypeUint32
	case "uint64":
		return TypeUint64
	case "int8":
		return TypeInt8
	case "int16":
		return TypeInt16
	case "int32":
		return TypeInt32
	case "int64":
		return TypeInt64
	case "duration":
		return TypeDuration
	case "time":
		return TypeTime
	case "float64":
		return TypeFloat64
	case "bool":
		return TypeBool
	case "bytes":
		return TypeBytes
	case "string":
		return TypeString
	case "bstring":
		return TypeBstring
	case "ip":
		return TypeIP
	case "net":
		return TypeNet
	case "type":
		return TypeType
	case "error":
		return TypeError
	case "null":
		return TypeNull
	}
	return nil
}

func LookupPrimitiveById(id int) Type {
	switch id {
	case IdBool:
		return TypeBool
	case IdInt8:
		return TypeInt8
	case IdUint8:
		return TypeUint8
	case IdInt16:
		return TypeInt16
	case IdUint16:
		return TypeUint16
	case IdInt32:
		return TypeInt32
	case IdUint32:
		return TypeUint32
	case IdInt64:
		return TypeInt64
	case IdUint64:
		return TypeUint64
	case IdFloat64:
		return TypeFloat64
	case IdString:
		return TypeString
	case IdBstring:
		return TypeBstring
	case IdIP:
		return TypeIP
	case IdNet:
		return TypeNet
	case IdTime:
		return TypeTime
	case IdDuration:
		return TypeDuration
	case IdType:
		return TypeType
	case IdError:
		return TypeError
	case IdNull:
		return TypeNull
	}
	return nil
}

// SameType returns true if the two types are equal in that each interface
// points to the same underlying type object.  Because the zeek library
// creates each unique type only once, this pointer comparison works.  If types
// are created outside of the zeek package, then SameType will not work in general
// for them.
func SameType(t1, t2 Type) bool {
	return t1 == t2
}

// Utilities shared by complex types (ie, set and array)

// InnerType returns the element type for set and array types
// or nil if the type is not a set or array.
func InnerType(typ Type) Type {
	switch typ := typ.(type) {
	case *TypeSet:
		return typ.Type
	case *TypeArray:
		return typ.Type
	default:
		return nil
	}
}

// ContainedType returns the inner type for set and array types in the first
// return value and the columns of its of type for record types in the second
// return value.  ContainedType returns nil for both return values if the
// type is not a set, array, or record.
func ContainedType(typ Type) (Type, []Column) {
	switch typ := typ.(type) {
	case *TypeSet:
		return typ.Type, nil
	case *TypeArray:
		return typ.Type, nil
	case *TypeRecord:
		return nil, typ.Columns
		// XXX enum?
	default:
		return nil, nil
	}
}

func IsUnionType(typ Type) bool {
	_, ok := typ.(*TypeUnion)
	return ok
}

func IsRecordType(typ Type) bool {
	_, ok := AliasedType(typ).(*TypeRecord)
	return ok
}

func IsContainerType(typ Type) bool {
	switch typ := typ.(type) {
	case *TypeAlias:
		return IsContainerType(typ.Type)
	case *TypeSet, *TypeArray, *TypeRecord, *TypeUnion, *TypeMap:
		return true
	default:
		return false
	}
}

func IsPrimitiveType(typ Type) bool {
	return !IsContainerType(typ)
}

func AliasTypes(typ Type) []*TypeAlias {
	var aliases []*TypeAlias
	switch typ := typ.(type) {
	case *TypeSet:
		aliases = AliasTypes(typ.Type)
	case *TypeArray:
		aliases = AliasTypes(typ.Type)
	case *TypeRecord:
		for _, col := range typ.Columns {
			aliases = append(aliases, AliasTypes(col.Type)...)
		}
	case *TypeUnion:
		for _, typ := range typ.Types {
			aliases = append(aliases, AliasTypes(typ)...)
		}
	case *TypeEnum:
		aliases = AliasTypes(typ.Type)
	case *TypeMap:
		keyAliases := AliasTypes(typ.KeyType)
		valAliases := AliasTypes(typ.KeyType)
		aliases = append(keyAliases, valAliases...)
	case *TypeAlias:
		aliases = append(aliases, AliasTypes(typ.Type)...)
		aliases = append(aliases, typ)
	}
	return aliases
}

func trimInnerTypes(typ string, raw string) string {
	// XXX handle white space, "set [..."... ?
	innerTypes := strings.TrimPrefix(raw, typ+"[")
	innerTypes = strings.TrimSuffix(innerTypes, "]")
	return innerTypes
}

// ReferencedID returns the underlying type from the given referential type.
// e.g., aliases and enums both refer to other underlying types and the
// Value's Bytes field is encoded according to the underlying type.
// XXX we initially had this as a method on Type but it was removed in favor
// of TypeAlias.ID() returning the underlying type where code that cared
// has to check if the type is an alias and use TypeAlias.AliasID().  Now that
// we have enums we need to implement a similar workaround.  It seems like we
// should add back the Type method that we took out.
func ReferencedID(typ Type) int {
	if typ, ok := typ.(*TypeEnum); ok {
		return typ.Type.ID()
	}
	return typ.ID()
}
