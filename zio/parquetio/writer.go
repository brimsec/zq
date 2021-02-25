package parquetio

import (
	"errors"
	"io"
	"math"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zio/csvio"
	"github.com/brimsec/zq/zng"
	goparquet "github.com/fraugster/parquet-go"
	"github.com/fraugster/parquet-go/parquet"
	"github.com/fraugster/parquet-go/parquetschema"
)

type Writer struct {
	w io.WriteCloser

	fw  *goparquet.FileWriter
	typ *zng.TypeRecord
}

type WriterOpts struct {
}

func NewWriter(w io.WriteCloser) *Writer {
	return &Writer{w: w}
}

func (w *Writer) Close() error {
	err := w.fw.Close()
	if err2 := w.w.Close(); err == nil {
		err = err2
	}
	return err
}

func (w *Writer) Write(rec *zng.Record) error {
	if w.typ == nil {
		w.typ = rec.Type
		sd, err := NewSchemaDefinition(rec.Type)
		if err != nil {
			return err
		}
		w.fw = goparquet.NewFileWriter(w.w, goparquet.WithSchemaDefinition(sd))
	} else if w.typ != rec.Type {
		return csvio.ErrNotDataFrame
	}
	data, err := newRecordInterface(rec.Type, rec.Raw)
	if err != nil {
		return err
	}
	return w.fw.AddData(data)
}

func newData(rec *zng.Record) (map[string]interface{}, error) {
	m := make(map[string]interface{})

	return m, nil
}

func newInterface(typ zng.Type, zb zcode.Bytes) (interface{}, error) {
	if zb == nil {
		return nil, nil
	}
	switch typ := zng.AliasedType(typ).(type) {
	case *zng.TypeOfUint8:
		v, err := zng.DecodeUint(zb)
		return uint32(v), err
	case *zng.TypeOfUint16:
		v, err := zng.DecodeUint(zb)
		return uint32(v), err
	case *zng.TypeOfUint32:
		v, err := zng.DecodeUint(zb)
		return uint32(v), err
	case *zng.TypeOfUint64:
		return zng.DecodeUint(zb)
	case *zng.TypeOfInt8:
		v, err := zng.DecodeInt(zb)
		return int32(v), err
	case *zng.TypeOfInt16:
		v, err := zng.DecodeInt(zb)
		return int32(v), err
	case *zng.TypeOfInt32:
		v, err := zng.DecodeInt(zb)
		return int32(v), err
	case *zng.TypeOfInt64, *zng.TypeOfDuration, *zng.TypeOfTime:
		return zng.DecodeInt(zb)
	// XXX add TypeFloat16
	// XXX add TypeFloat32
	case *zng.TypeOfFloat64:
		return zng.DecodeFloat64(zb)
	// XXX add TypeDecimal
	case *zng.TypeOfBool:
		return zng.DecodeBool(zb)
	case *zng.TypeOfBytes, *zng.TypeOfBstring, *zng.TypeOfString:
		return zng.DecodeBytes(zb)
	case *zng.TypeOfIP:
		v, err := zng.DecodeIP(zb)
		return []byte(v.String()), err
	case *zng.TypeOfNet:
		v, err := zng.DecodeNet(zb)
		return []byte(v.String()), err
	case *zng.TypeOfType, *zng.TypeOfError:
		return zng.DecodeBytes(zb)
	case *zng.TypeOfNull:
		return nil, errors.New("null type unsupported") // xxx use parquet.NullType
	case *zng.TypeRecord:
		return newRecordInterface(typ, zb)
	case *zng.TypeArray:
		return newListInterace(typ.Type, zb)
	case *zng.TypeSet:
		return newListInterace(typ.Type, zb)
	case *zng.TypeUnion:
		return nil, errors.New("union type unsupported")
	case *zng.TypeEnum:
		return zng.DecodeBytes(zb)
	case *zng.TypeMap:
		return newMapInterface(typ.KeyType, typ.ValType, zb)
	default:
		panic(typ)
	}
}

func newListInterace(typ zng.Type, zb zcode.Bytes) ([]interface{}, error) {
	var vs []interface{}
	for it := zb.Iter(); !it.Done(); {
		zb2, _, err := it.Next()
		if err != nil {
			return nil, err
		}
		v, err := newInterface(typ, zb2)
		if err != nil {
			return nil, err
		}
		vs = append(vs, v)
	}
	return vs, nil
}

func newMapInterface(keyType, valType zng.Type, zb zcode.Bytes) (map[interface{}]interface{}, error) {
	m := make(map[interface{}]interface{})
	for i, it := 0, zb.Iter(); !it.Done(); i++ {
		keyBytes, _, err := it.Next()
		if err != nil {
			return nil, err
		}
		k, err := newInterface(keyType, keyBytes)
		if err != nil {
			return nil, err
		}

		valBytes, _, err := it.Next()
		if err != nil {
			return nil, err
		}
		v, err := newInterface(valType, valBytes)
		if err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, nil
}

func newRecordInterface(typ *zng.TypeRecord, zb zcode.Bytes) (map[string]interface{}, error) {
	m := make(map[string]interface{}, len(typ.Columns))
	for i, it := 0, zb.Iter(); !it.Done(); i++ {
		zb2, _, err := it.Next()
		if err != nil {
			return nil, err
		}
		v, err := newInterface(typ.Columns[i].Type, zb2)
		if err != nil {
			return nil, err
		}
		m[typ.Columns[i].Name] = v
	}
	return m, nil
}

func NewSchemaDefinition(typ *zng.TypeRecord) (*parquetschema.SchemaDefinition, error) {
	c, err := newColumnDefinition("", typ)
	if err != nil {
		return nil, err
	}
	s := &parquetschema.SchemaDefinition{
		RootColumn: &parquetschema.ColumnDefinition{
			Children: c.Children,
			SchemaElement: &parquet.SchemaElement{
				Name: "zq",
			},
		},
	}
	return s, s.ValidateStrict()
}

func newColumnDefinition(name string, typ zng.Type) (*parquetschema.ColumnDefinition, error) {
	switch typ := zng.AliasedType(typ).(type) {
	case *zng.TypeOfUint8:
		return newIntColumnDefinition(name, parquet.Type_INT32, parquet.ConvertedType_UINT_8, 8, false)
	case *zng.TypeOfUint16:
		return newIntColumnDefinition(name, parquet.Type_INT32, parquet.ConvertedType_UINT_16, 16, false)
	case *zng.TypeOfUint32:
		return newIntColumnDefinition(name, parquet.Type_INT32, parquet.ConvertedType_UINT_32, 32, false)
	case *zng.TypeOfUint64:
		return newIntColumnDefinition(name, parquet.Type_INT64, parquet.ConvertedType_UINT_64, 64, false)
	case *zng.TypeOfInt8:
		return newIntColumnDefinition(name, parquet.Type_INT32, parquet.ConvertedType_INT_8, 8, true)
	case *zng.TypeOfInt16:
		return newIntColumnDefinition(name, parquet.Type_INT32, parquet.ConvertedType_INT_16, 16, true)
	case *zng.TypeOfInt32:
		return newIntColumnDefinition(name, parquet.Type_INT32, parquet.ConvertedType_INT_32, 32, true)
	case *zng.TypeOfInt64:
		return newIntColumnDefinition(name, parquet.Type_INT64, parquet.ConvertedType_INT_64, 64, true)
	case *zng.TypeOfDuration:
		return newIntColumnDefinition(name, parquet.Type_INT64, parquet.ConvertedType_INT_64, 64, true)
	case *zng.TypeOfTime:
		return newLeafColumnDefinition(name, parquet.Type_INT64, nil, &parquet.LogicalType{
			TIMESTAMP: &parquet.TimestampType{
				Unit: &parquet.TimeUnit{
					NANOS: parquet.NewNanoSeconds(),
				},
			},
		})
	// XXX add TypeFloat16
	// XXX add TypeFloat32
	case *zng.TypeOfFloat64:
		return newLeafColumnDefinition(name, parquet.Type_DOUBLE, nil, nil)
	// XXX add TypeDecimal
	case *zng.TypeOfBool:
		return newLeafColumnDefinition(name, parquet.Type_BOOLEAN, nil, nil)
	case *zng.TypeOfBytes, *zng.TypeOfBstring:
		return newLeafColumnDefinition(name, parquet.Type_BYTE_ARRAY, nil, nil)
	case *zng.TypeOfString, *zng.TypeOfIP, *zng.TypeOfNet, *zng.TypeOfType, *zng.TypeOfError:
		c := parquet.ConvertedTypePtr(parquet.ConvertedType_UTF8)
		return newLeafColumnDefinition(name, parquet.Type_BYTE_ARRAY, c, &parquet.LogicalType{
			STRING: parquet.NewStringType(),
		})
	case *zng.TypeOfNull:
		return nil, errors.New("null type unsupported") // xxx use parquet.NullType
	case *zng.TypeRecord:
		return newRecordColumnDefinition(name, typ)
	case *zng.TypeArray:
		return newListColumnDefinition(name, typ.Type)
	case *zng.TypeSet:
		return newListColumnDefinition(name, typ.Type)
	case *zng.TypeUnion:
		return nil, errors.New("union type unsupported")
	case *zng.TypeEnum:
		c := parquet.ConvertedTypePtr(parquet.ConvertedType_ENUM)
		return newLeafColumnDefinition(name, parquet.Type_BYTE_ARRAY, c, &parquet.LogicalType{
			ENUM: parquet.NewEnumType(),
		})
	case *zng.TypeMap:
		return newMapColumnDefinition(name, typ.KeyType, typ.ValType)
	default:
		panic(typ)
	}
}

func newIntColumnDefinition(name string, t parquet.Type, c parquet.ConvertedType, bitWidth int8, isSigned bool) (*parquetschema.ColumnDefinition, error) {
	return newLeafColumnDefinition(name, t, parquet.ConvertedTypePtr(c), &parquet.LogicalType{
		INTEGER: &parquet.IntType{
			BitWidth: bitWidth,
			IsSigned: isSigned,
		},
	})
}

func newLeafColumnDefinition(name string, t parquet.Type, c *parquet.ConvertedType, l *parquet.LogicalType) (*parquetschema.ColumnDefinition, error) {
	return &parquetschema.ColumnDefinition{
		SchemaElement: &parquet.SchemaElement{
			Type:           parquet.TypePtr(t),
			RepetitionType: parquet.FieldRepetitionTypePtr(parquet.FieldRepetitionType_OPTIONAL),
			Name:           name,
			ConvertedType:  c,
			LogicalType:    l,
		},
	}, nil
}

func newListColumnDefinition(name string, typ zng.Type) (*parquetschema.ColumnDefinition, error) {
	element, err := newColumnDefinition("element", typ)
	if err != nil {
		return nil, err
	}
	return &parquetschema.ColumnDefinition{
		Children: []*parquetschema.ColumnDefinition{
			{
				Children: []*parquetschema.ColumnDefinition{element},
				SchemaElement: &parquet.SchemaElement{
					RepetitionType: parquet.FieldRepetitionTypePtr(
						parquet.FieldRepetitionType_REPEATED),
					Name:        "list",
					NumChildren: int32Ptr(1),
				},
			},
		},
		SchemaElement: &parquet.SchemaElement{
			RepetitionType: parquet.FieldRepetitionTypePtr(parquet.FieldRepetitionType_OPTIONAL),
			Name:           name,
			NumChildren:    int32Ptr(1),
			ConvertedType:  parquet.ConvertedTypePtr(parquet.ConvertedType_LIST),
		},
	}, nil
}

func newMapColumnDefinition(name string, keyType, valueType zng.Type) (*parquetschema.ColumnDefinition, error) {
	key, err := newColumnDefinition("key", keyType)
	if err != nil {
		return nil, err
	}
	value, err := newColumnDefinition("value", valueType)
	if err != nil {
		return nil, err
	}
	// xxx maybe set key.RepetitionType and value.RepetitionType to repeated
	return &parquetschema.ColumnDefinition{
		Children: []*parquetschema.ColumnDefinition{
			{
				Children: []*parquetschema.ColumnDefinition{key, value},
				SchemaElement: &parquet.SchemaElement{
					RepetitionType: parquet.FieldRepetitionTypePtr(
						parquet.FieldRepetitionType_REPEATED),
					Name:          "key_value",
					NumChildren:   int32Ptr(2),
					ConvertedType: parquet.ConvertedTypePtr(parquet.ConvertedType_MAP_KEY_VALUE),
				},
			},
		},
		SchemaElement: &parquet.SchemaElement{
			RepetitionType: parquet.FieldRepetitionTypePtr(parquet.FieldRepetitionType_OPTIONAL),
			Name:           name,
			NumChildren:    int32Ptr(1),
			ConvertedType:  parquet.ConvertedTypePtr(parquet.ConvertedType_MAP),
		},
	}, nil
}

func newRecordColumnDefinition(name string, typ *zng.TypeRecord) (*parquetschema.ColumnDefinition, error) {
	var children []*parquetschema.ColumnDefinition
	for _, c := range typ.Columns {
		c, err := newColumnDefinition(c.Name, c.Type)
		if err != nil {
			return nil, err
		}
		children = append(children, c)
	}
	return &parquetschema.ColumnDefinition{
		Children: children,
		SchemaElement: &parquet.SchemaElement{
			RepetitionType: parquet.FieldRepetitionTypePtr(parquet.FieldRepetitionType_OPTIONAL),
			Name:           name,
			NumChildren:    int32Ptr(len(children)),
		},
	}, nil
}

func int32Ptr(i int) *int32 {
	if i > math.MaxInt32 || i < math.MinInt32 {
		panic(i)
	}
	i32 := int32(i)
	return &i32
}
