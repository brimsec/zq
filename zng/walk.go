package zng

import (
	"errors"

	"github.com/brimsec/zq/zcode"
)

// A Visitor is called for each value in a record encountered by
// Walk. If the visitor returns an error, the walk stops and that
// error will be returned to the caller of Walk(). The sole exception
// is when the visitor returns the special value SkipContainer.
type Visitor func(typ Type, body zcode.Bytes) error

// SkipContainer is used as a return value from Visitors to indicate
// that the container passed in the call should not be visited. It is
// not returned as an error by any function.
var SkipContainer = errors.New("skip this container")

func Walk(typ Type, body zcode.Bytes, visit Visitor) error {
	if err := visit(typ, body); err != nil {
		if err == SkipContainer {
			return nil
		}
		return err
	}
	switch typ := typ.(type) {
	case *TypeAlias:
		return Walk(typ.Type, body, visit)
	case *TypeRecord:
		return walkRecord(typ, body, visit)
	case *TypeArray:
		return walkArray(typ, body, visit)
	case *TypeSet:
		return walkSet(typ, body, visit)
	case *TypeUnion:
		return walkUnion(typ, body, visit)
	case *TypeMap:
		return walkMap(typ, body, visit)
	}
	return nil
}

func checkKind(name string, typ Type, body zcode.Bytes, container bool) error {
	if body == nil {
		return nil
	}
	isContainer := IsContainerType(typ)
	if isContainer == container {
		return nil
	}
	var err error
	if isContainer {
		err = ErrNotContainer
	} else {
		err = ErrNotPrimitive
	}
	return &RecordTypeError{Name: name, Type: typ.ZSON(), Err: err}
}

func walkRecord(typ *TypeRecord, body zcode.Bytes, visit Visitor) error {
	if body == nil {
		return nil
	}
	it := body.Iter()
	for _, col := range typ.Columns {
		if it.Done() {
			return &RecordTypeError{Name: string(col.Name), Type: col.Type.ZSON(), Err: ErrMissingField}
		}
		body, container, err := it.Next()
		if err != nil {
			return err
		}
		if err := checkKind(col.Name, col.Type, body, container); err != nil {
			return err
		}
		if err := Walk(col.Type, body, visit); err != nil {
			return err
		}
	}
	return nil
}

func walkArray(typ *TypeArray, body zcode.Bytes, visit Visitor) error {
	if body == nil {
		return nil
	}
	inner := InnerType(AliasedType(typ))
	it := body.Iter()
	for !it.Done() {
		body, container, err := it.Next()
		if err != nil {
			return err
		}
		if err := checkKind("<array element>", inner, body, container); err != nil {
			return err
		}
		if err := Walk(inner, body, visit); err != nil {
			return err
		}
	}
	return nil
}

func walkUnion(typ *TypeUnion, body zcode.Bytes, visit Visitor) error {
	if body == nil {
		return nil
	}
	if len(body) == 0 {
		err := errors.New("union as empty body")
		return &RecordTypeError{Name: "<union type>", Type: typ.ZSON(), Err: err}
	}
	it := body.Iter()
	v, container, err := it.Next()
	if err != nil {
		return err
	}
	if container {
		return ErrBadValue
	}
	index, err := DecodeInt(v)
	if err != nil {
		return err
	}
	inner, err := typ.TypeIndex(int(index))
	if err != nil {
		return err
	}
	body, container, err = it.Next()
	if err != nil {
		return err
	}
	if !it.Done() {
		err := errors.New("union value container has more than two items")
		return &RecordTypeError{Name: "<union>", Type: typ.ZSON(), Err: err}
	}
	if err := checkKind("<union body>", inner, body, container); err != nil {
		return err
	}
	return Walk(inner, body, visit)
}

func walkSet(typ *TypeSet, body zcode.Bytes, visit Visitor) error {
	if body == nil {
		return nil
	}
	inner := AliasedType(InnerType(typ))
	it := body.Iter()
	for !it.Done() {
		body, container, err := it.Next()
		if err != nil {
			return err
		}
		if err := checkKind("<set element>", inner, body, container); err != nil {
			return err
		}
		if err := Walk(inner, body, visit); err != nil {
			return err
		}
	}
	return nil
}

func walkMap(typ *TypeMap, body zcode.Bytes, visit Visitor) error {
	if body == nil {
		return nil
	}
	keyType := AliasedType(typ.KeyType)
	valType := AliasedType(typ.ValType)
	it := body.Iter()
	for !it.Done() {
		body, container, err := it.Next()
		if err != nil {
			return err
		}
		if err := checkKind("<map key>", keyType, body, container); err != nil {
			return err
		}
		if err := Walk(keyType, body, visit); err != nil {
			return err
		}
		body, container, err = it.Next()
		if err != nil {
			return err
		}
		if err := checkKind("<map value>", valType, body, container); err != nil {
			return err
		}
		if err := Walk(valType, body, visit); err != nil {
			return err
		}
	}
	return nil
}
