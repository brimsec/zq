package function

import (
	"errors"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zson"
)

type fields struct {
	types *zson.TypeTable
	typ   zng.Type
	bytes zcode.Bytes
}

func fieldNames(typ *zng.TypeRecord) []string {
	var out []string
	for _, c := range typ.Columns {
		if typ, ok := zng.AliasedType(c.Type).(*zng.TypeRecord); ok {
			for _, subfield := range fieldNames(typ) {
				out = append(out, c.Name+"."+subfield)
			}
		} else {
			out = append(out, c.Name)
		}
	}
	return out
}

func (f *fields) Call(args []zng.Value) (zng.Value, error) {
	zvSubject := args[0]
	typ := isRecordType(zvSubject, f.types)
	if typ == nil {
		//XXX create a zng.Missing which is ErrMissing as zng.Value
		// To do this, need to move ErrNoSuchField=>ErrMissing to zng.
		// See issue #2130.
		return zng.NewError(errors.New("missing value")), nil
	}
	bytes := f.bytes[:0]
	for _, field := range fieldNames(typ) {
		bytes = zcode.AppendPrimitive(bytes, zcode.Bytes(field))
	}
	f.bytes = bytes
	return zng.Value{f.typ, bytes}, nil
}

type has struct {
	types *zson.TypeTable
}

func isRecordType(zv zng.Value, types *zson.TypeTable) *zng.TypeRecord {
	if typ, ok := zng.AliasedType(zv.Type).(*zng.TypeRecord); ok {
		return typ
	}
	if zv.Type == zng.TypeType {
		s, err := zng.DecodeString(zv.Bytes)
		if err != nil {
			return nil
		}
		typ, err := types.LookupType(s)
		if err != nil {
			return nil
		}
		if typ, ok := zng.AliasedType(typ).(*zng.TypeRecord); ok {
			return typ
		}
	}
	return nil
}

func (h *has) Call(args []zng.Value) (zng.Value, error) {
	zvSubject := args[0]
	zvField := args[1]
	if len(args) == 3 {
		zvSubject = args[1]
		zvField = args[2]
	}
	if !zvField.IsStringy() {
		return zng.NewErrorf("field name in has() is not a string"), nil
	}
	field, err := zng.DecodeString(zvField.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	if typ := isRecordType(zvSubject, h.types); typ.HasField(field) {
		return zng.True, nil
	}
	return zng.False, nil
}
