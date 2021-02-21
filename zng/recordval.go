package zng

import (
	"bytes"
	"errors"
	"math"
	"net"

	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/zcode"
)

var (
	ErrMissingField   = errors.New("record missing a field")
	ErrExtraField     = errors.New("record with extra field")
	ErrNotContainer   = errors.New("expected container type, got primitive")
	ErrNotPrimitive   = errors.New("expected primitive type, got container")
	ErrTypeIDExists   = errors.New("zng type ID exists")
	ErrTypeIDInvalid  = errors.New("zng type ID out of range")
	ErrBadValue       = errors.New("malformed zng value")
	ErrBadFormat      = errors.New("malformed zng record")
	ErrTypeMismatch   = errors.New("type/value mismatch")
	ErrColumnMismatch = errors.New("zng record mismatch between columns in type and columns in value")
	ErrCorruptColumns = errors.New("wrong number of columns in zng record value")
)

type RecordTypeError struct {
	Name string
	Type string
	Err  error
}

func (r *RecordTypeError) Error() string { return r.Name + " (" + r.Type + "): " + r.Err.Error() }
func (r *RecordTypeError) Unwrap() error { return r.Err }

// XXX A Record wraps a zng.Record and can simultaneously represent its raw
// serialized zng form or its parsed zng.Record form.  This duality lets us
// parse raw logs and perform fast-path operations directly on the zng data
// without having to parse the entire record.  Thus, the same code that performs
// operations on zeek data can work with either serialized data or native
// zng.Records by accessing data via the Record methods.
type Record struct {
	Type        *TypeRecord
	Alias       Type
	nonvolatile bool
	// Raw is the serialization format for records.  A raw value comprises a
	// sequence of zvals, one per descriptor column.  The descriptor is stored
	// outside of the raw serialization but is needed to interpret the raw values.
	Raw     zcode.Bytes
	ts      nano.Ts
	tsValid bool
}

func NewRecord(typ *TypeRecord, raw zcode.Bytes) *Record {
	return &Record{
		Type:        typ,
		Alias:       typ,
		nonvolatile: true,
		Raw:         raw,
	}
}

func NewRecordFromType(typ Type, raw zcode.Bytes) *Record {
	return &Record{
		Type:        AliasedType(typ).(*TypeRecord),
		Alias:       typ,
		nonvolatile: true,
		Raw:         raw,
	}
}

func NewRecordCheck(typ *TypeRecord, raw zcode.Bytes) (*Record, error) {
	r := NewRecord(typ, raw)
	if err := r.TypeCheck(); err != nil {
		return nil, err
	}
	return r, nil
}

func NewRecordCheckFromType(typ Type, raw zcode.Bytes) (*Record, error) {
	r := &Record{
		Type:        AliasedType(typ).(*TypeRecord),
		Alias:       typ,
		nonvolatile: true,
		Raw:         raw,
	}
	if err := r.TypeCheck(); err != nil {
		return nil, err
	}
	return r, nil
}

// NewVolatileRecord creates a record from a raw value and marks
// it volatile so that Keep() must be called to make it safe.
// This is useful for readers that allocate records whose raw body points
// into a reusable buffer allowing the scanner to filter these records
// without having their body copied to safe memory, i.e., when the scanner
// matches a record, it will call Keep() to make a safe copy.
func NewVolatileRecord(typ *TypeRecord, raw zcode.Bytes) *Record {
	return &Record{
		Type:  typ,
		Alias: typ,
		Raw:   raw,
	}
}

func NewVolatileRecordFromType(typ Type, raw zcode.Bytes) *Record {
	return &Record{
		Type:  AliasedType(typ).(*TypeRecord),
		Alias: typ,
		Raw:   raw,
	}
}

// ZvalIter returns a zcode.Iter iterator over the receiver's values.
func (r *Record) ZvalIter() zcode.Iter {
	return r.Raw.Iter()
}

// FieldIter returns a fieldIter iterator over the receiver's values.
func (r *Record) FieldIter() fieldIter {
	return fieldIter{
		stack: []iterInfo{iterInfo{
			iter: r.ZvalIter(),
			typ:  r.Type,
		}},
	}
}

func (r *Record) Keep() *Record {
	if r.nonvolatile {
		return r
	}
	raw := make(zcode.Bytes, len(r.Raw))
	copy(raw, r.Raw)
	return &Record{
		Type:        r.Type,
		Alias:       r.Alias,
		nonvolatile: true,
		Raw:         raw,
		ts:          r.ts,
		tsValid:     r.tsValid,
	}
}

func (r *Record) CopyBody() {
	if r.nonvolatile {
		return
	}
	body := make(zcode.Bytes, len(r.Raw))
	copy(body, r.Raw)
	r.Raw = body
	r.nonvolatile = true
}

func (r *Record) HasField(field string) bool {
	return r.Type.HasField(field)
}

func (r *Record) Bytes() []byte {
	if r.Raw == nil {
		panic("this shouldn't happen")
	}
	return r.Raw
}

// Walk traverses a record in depth-first order, calling a
// RecordVisitor on the way.
func (r *Record) Walk(rv Visitor) error {
	return walkRecord(r.Type, r.Raw, rv)
}

// TypeCheck checks that the value coding in Raw is structurally consistent
// with this value's descriptor.  It does not check that the actual leaf
// values when parsed are type compatible with the leaf types.
func (r *Record) TypeCheck() error {
	return r.Walk(func(typ Type, body zcode.Bytes) error {
		if typset, ok := typ.(*TypeSet); ok {
			if err := checkSet(typset, body); err != nil {
				return err
			}
			return SkipContainer
		}
		if typ, ok := typ.(*TypeEnum); ok {
			if err := checkEnum(typ, body); err != nil {
				return err
			}
			return SkipContainer
		}
		return nil
	})
}

func checkSet(typ *TypeSet, body zcode.Bytes) error {
	if body == nil {
		return nil
	}
	it := body.Iter()
	var prev zcode.Bytes
	for !it.Done() {
		tagAndBody, _, err := it.NextTagAndBody()
		if err != nil {
			return err
		}
		if prev != nil {
			switch bytes.Compare(prev, tagAndBody) {
			case 0:
				err := errors.New("duplicate element")
				return &RecordTypeError{Name: "<set element>", Type: typ.String(), Err: err}
			case 1:
				err := errors.New("elements not sorted")
				return &RecordTypeError{Name: "<set element>", Type: typ.String(), Err: err}
			}
		}
		prev = tagAndBody
	}
	return nil
}

func checkEnum(typ *TypeEnum, body zcode.Bytes) error {
	if body == nil {
		return nil
	}
	selector, err := DecodeUint(body)
	if err != nil {
		return err
	}
	if int(selector) >= len(typ.Elements) {
		return errors.New("enum selector out of range")
	}
	return nil
}

// Slice returns the encoded zcode.Bytes corresponding to the indicated
// column or an error if a problem was encountered.  If the encoded bytes
// result is nil without error, then that columnn is unset in this record value.
func (r *Record) Slice(column int) (zcode.Bytes, error) {
	var zv zcode.Bytes
	for i, it := 0, r.Raw.Iter(); i <= column; i++ {
		if it.Done() {
			return nil, ErrMissing
		}
		var err error
		zv, _, err = it.Next()
		if err != nil {
			return nil, err
		}
	}
	return zv, nil
}

// Value returns the indicated column as a Value.  If the column doesn't
// exist or another error occurs, the nil Value is returned.
func (r *Record) Value(col int) Value {
	zv, err := r.Slice(col)
	if err != nil {
		return Value{}
	}
	return Value{r.Type.Columns[col].Type, zv}
}

func (r *Record) ValueByField(field string) (Value, error) {
	col, ok := r.ColumnOfField(field)
	if !ok {
		return Value{}, ErrMissing
	}
	return r.Value(col), nil
}

func (r *Record) ColumnOfField(field string) (int, bool) {
	return r.Type.ColumnOfField(field)
}

func (r *Record) TypeOfColumn(col int) Type {
	return r.Type.Columns[col].Type
}

func (r *Record) Access(field string) (Value, error) {
	col, ok := r.ColumnOfField(field)
	if !ok {
		return Value{}, ErrMissing
	}
	return r.Value(col), nil
}

func (r *Record) AccessString(field string) (string, error) {
	v, err := r.Access(field)
	if err != nil {
		return "", err
	}
	switch AliasedType(v.Type).(type) {
	case *TypeOfString, *TypeOfBstring:
		return DecodeString(v.Bytes)
	default:
		return "", ErrTypeMismatch
	}
}

func (r *Record) AccessBool(field string) (bool, error) {
	v, err := r.Access(field)
	if err != nil {
		return false, err
	}
	if _, ok := AliasedType(v.Type).(*TypeOfBool); !ok {
		return false, ErrTypeMismatch
	}
	return DecodeBool(v.Bytes)
}

func (r *Record) AccessInt(field string) (int64, error) {
	v, err := r.Access(field)
	if err != nil {
		return 0, err
	}
	switch AliasedType(v.Type).(type) {
	case *TypeOfUint8:
		b, err := DecodeUint(v.Bytes)
		return int64(b), err
	case *TypeOfInt16, *TypeOfInt32, *TypeOfInt64:
		return DecodeInt(v.Bytes)
	case *TypeOfUint16, *TypeOfUint32:
		v, err := DecodeUint(v.Bytes)
		return int64(v), err
	case *TypeOfUint64:
		v, err := DecodeUint(v.Bytes)
		if v > math.MaxInt64 {
			return 0, errors.New("conversion from uint64 to signed int results in overflow")
		}
		return int64(v), err
	}
	return 0, ErrTypeMismatch
}

func (r *Record) AccessIP(field string) (net.IP, error) {
	v, err := r.Access(field)
	if err != nil {
		return nil, err
	}
	if _, ok := AliasedType(v.Type).(*TypeOfIP); !ok {
		return nil, ErrTypeMismatch
	}
	return DecodeIP(v.Bytes)
}

func (r *Record) AccessTime(field string) (nano.Ts, error) {
	v, err := r.Access(field)
	if err != nil {
		return 0, err
	}
	if _, ok := AliasedType(v.Type).(*TypeOfTime); !ok {
		return 0, ErrTypeMismatch
	}
	return DecodeTime(v.Bytes)
}

func (r *Record) AccessTimeByColumn(colno int) (nano.Ts, error) {
	zv, err := r.Slice(colno)
	if err != nil {
		return 0, err
	}
	return DecodeTime(zv)
}

// Ts returns the value of the receiver's "ts" field.  If the field is absent,
// is null, or has a type other than TypeOfTime, Ts returns nano.MinTs.
func (r *Record) Ts() nano.Ts {
	if !r.tsValid {
		r.ts, _ = r.AccessTime("ts")
		r.tsValid = true
	}
	return r.ts
}

func (r *Record) String() string {
	return Value{r.Type, r.Raw}.String()
}

// MarshalJSON implements json.Marshaler.
func (r *Record) MarshalJSON() ([]byte, error) {
	return Value{r.Alias, r.Raw}.MarshalJSON()
}
