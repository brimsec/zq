package function

import (
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
		return zng.Missing, nil
	}
	bytes := f.bytes[:0]
	for _, field := range fieldNames(typ) {
		bytes = zcode.AppendPrimitive(bytes, zcode.Bytes(field))
	}
	f.bytes = bytes
	return zng.Value{f.typ, bytes}, nil
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
