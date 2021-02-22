package expr

import (
	"bytes"
	"sort"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
)

type CompareFn func(a *zng.Record, b *zng.Record) int
type ValueCompareFn func(a zng.Value, b zng.Value) int
type KeyCompareFn func(*zng.Record) int

// Internal function that compares two values of compatible types.
type comparefn func(a, b zcode.Bytes) int

func isNull(val zng.Value) bool {
	return val.Type == nil || val.Bytes == nil
}

// NewCompareFn creates a function that compares a pair of Records
// based on the provided ordered list of fields.
// The returned function uses the same return conventions as standard
// routines such as bytes.Compare() and strings.Compare(), so it may
// be used with packages such as heap and sort.
// The handling of records in which a comparison field is unset or not
// present (collectively refered to as fields in which the value is "null")
// is governed by the nullsMax parameter.  If this parameter is true,
// a record with a null value is considered larger than a record with any
// other value, and vice versa.
func NewCompareFn(nullsMax bool, fields ...Evaluator) CompareFn {
	comparefns := make(map[zng.Type]comparefn)
	return func(ra *zng.Record, rb *zng.Record) int {
		for _, resolver := range fields {
			// XXX return errors?
			a, _ := resolver.Eval(ra)
			b, _ := resolver.Eval(rb)
			v := compareValues(a, b, comparefns, nullsMax)
			// If the events don't match, then return the sort
			// info.  Otherwise, they match and we continue on
			// on in the loop to the secondary key, etc.
			if v != 0 {
				return v
			}
		}
		// All the keys matched with equality.
		return 0
	}
}

func NewValueCompareFn(nullsMax bool) ValueCompareFn {
	comparefns := make(map[zng.Type]comparefn)
	return func(a, b zng.Value) int {
		return compareValues(a, b, comparefns, nullsMax)
	}
}

func compareValues(a, b zng.Value, comparefns map[zng.Type]comparefn, nullsMax bool) int {
	// Handle nulls according to nullsMax
	nullA := isNull(a)
	nullB := isNull(b)
	if nullA && nullB {
		return 0
	}
	if nullA {
		if nullsMax {
			return 1
		} else {
			return -1
		}
	}
	if nullB {
		if nullsMax {
			return -1
		} else {
			return 1
		}
	}

	// If values are of different types, just compare
	// the native representation of the type
	if a.Type.ID() != b.Type.ID() {
		return bytes.Compare([]byte(a.Type.ZSON()), []byte(b.Type.ZSON()))
	}

	cfn, ok := comparefns[a.Type]
	if !ok {
		cfn = LookupCompare(a.Type)
		comparefns[a.Type] = cfn
	}

	return cfn(a.Bytes, b.Bytes)
}

func NewKeyCompareFn(key *zng.Record) (KeyCompareFn, error) {
	comparefns := make(map[zng.Type]comparefn)
	var accessors []Evaluator
	var keyval []zng.Value
	for it := key.FieldIter(); !it.Done(); {
		name, val, err := it.Next()
		if err != nil {
			return nil, err
		}
		// We got an unset value, so all remaining values in the key
		// must be unset.
		if isNull(val) {
			break
		}
		keyval = append(keyval, val)
		accessors = append(accessors, NewDotExpr(name))
	}
	return func(rec *zng.Record) int {
		for k, access := range accessors {
			// XXX error
			a, _ := access.Eval(rec)
			if isNull(a) {
				// we know the key value is not null
				return -1
			}
			b := keyval[k]
			// If the type of a field in the comparison record does
			// not match the type of the key, behavior is undefined.
			if a.Type.ID() != b.Type.ID() {
				return -1
			}
			//XXX comparefns should be a slice indexed by ID
			cfn, ok := comparefns[a.Type]
			if !ok {
				cfn = LookupCompare(a.Type)
				comparefns[a.Type] = cfn
			}
			v := cfn(a.Bytes, b.Bytes)
			// If the fields don't match, then return the sense of
			// the mismatch.  Otherwise, we continue on
			// in the loop to the secondary key, etc.
			if v != 0 {
				return v
			}
		}
		// All the keys matched with equality.
		return 0
	}, nil
}

// SortStable performs a stable sort on the provided records.
func SortStable(records []*zng.Record, compare CompareFn) {
	slice := &RecordSlice{records, compare}
	sort.Stable(slice)
}

type RecordSlice struct {
	records []*zng.Record
	compare CompareFn
}

func NewRecordSlice(compare CompareFn) *RecordSlice {
	return &RecordSlice{compare: compare}
}

// Swap implements sort.Interface for *Record slices.
func (r *RecordSlice) Len() int { return len(r.records) }

// Swap implements sort.Interface for *Record slices.
func (r *RecordSlice) Swap(i, j int) { r.records[i], r.records[j] = r.records[j], r.records[i] }

// Less implements sort.Interface for *Record slices.
func (r *RecordSlice) Less(i, j int) bool {
	return r.compare(r.records[i], r.records[j]) < 0
}

// Push adds x as element Len(). Implements heap.Interface.
func (r *RecordSlice) Push(rec interface{}) {
	r.records = append(r.records, rec.(*zng.Record))
}

// Pop removes the first element in the array. Implements heap.Interface.
func (r *RecordSlice) Pop() interface{} {
	rec := r.records[len(r.records)-1]
	r.records = r.records[:len(r.records)-1]
	return rec
}

// Index returns the ith record.
func (r *RecordSlice) Index(i int) *zng.Record {
	return r.records[i]
}

func LookupCompare(typ zng.Type) comparefn {
	// XXX record support easy to add here if we moved the creation of the
	// field resolvers into this package.
	if innerType := zng.InnerType(typ); innerType != nil {
		return func(a, b zcode.Bytes) int {
			compare := LookupCompare(innerType)
			ia := a.Iter()
			ib := b.Iter()
			for {
				if ia.Done() {
					if ib.Done() {
						return 0
					}
					return -1
				}
				if ib.Done() {
					return 1
				}
				va, container, err := ia.Next()
				if container || err != nil {
					return -1
				}

				vb, container, err := ib.Next()
				if container || err != nil {
					return 1
				}
				if v := compare(va, vb); v != 0 {
					return v
				}
			}
		}
	}
	switch typ.ID() {
	case zng.IdBool:
		return func(a, b zcode.Bytes) int {
			va, err := zng.DecodeBool(a)
			if err != nil {
				return -1
			}
			vb, err := zng.DecodeBool(b)
			if err != nil {
				return 1
			}
			if va == vb {
				return 0
			}
			if va {
				return 1
			}
			return -1
		}

	case zng.IdString:
		return func(a, b zcode.Bytes) int {
			return bytes.Compare(a, b)
		}

	case zng.IdInt16, zng.IdInt32, zng.IdInt64:
		return func(a, b zcode.Bytes) int {
			va, err := zng.DecodeInt(a)
			if err != nil {
				return -1
			}
			vb, err := zng.DecodeInt(b)
			if err != nil {
				return 1
			}
			if va < vb {
				return -1
			} else if va > vb {
				return 1
			}
			return 0
		}

	case zng.IdUint16, zng.IdUint32, zng.IdUint64:
		return func(a, b zcode.Bytes) int {
			va, err := zng.DecodeUint(a)
			if err != nil {
				return -1
			}
			vb, err := zng.DecodeUint(b)
			if err != nil {
				return 1
			}
			if va < vb {
				return -1
			} else if va > vb {
				return 1
			}
			return 0
		}

	case zng.IdFloat64:
		return func(a, b zcode.Bytes) int {
			va, err := zng.DecodeFloat64(a)
			if err != nil {
				return -1
			}
			vb, err := zng.DecodeFloat64(b)
			if err != nil {
				return 1
			}
			if va < vb {
				return -1
			} else if va > vb {
				return 1
			}
			return 0
		}

	case zng.IdTime:
		return func(a, b zcode.Bytes) int {
			va, err := zng.DecodeTime(a)
			if err != nil {
				return -1
			}
			vb, err := zng.DecodeTime(b)
			if err != nil {
				return 1
			}
			if va < vb {
				return -1
			} else if va > vb {
				return 1
			}
			return 0
		}

	case zng.IdDuration:
		return func(a, b zcode.Bytes) int {
			va, err := zng.DecodeDuration(a)
			if err != nil {
				return -1
			}
			vb, err := zng.DecodeDuration(b)
			if err != nil {
				return 1
			}
			if va < vb {
				return -1
			} else if va > vb {
				return 1
			}
			return 0
		}

	case zng.IdIP:
		return func(a, b zcode.Bytes) int {
			va, err := zng.DecodeIP(a)
			if err != nil {
				return -1
			}
			vb, err := zng.DecodeIP(b)
			if err != nil {
				return 1
			}
			return bytes.Compare(va.To16(), vb.To16())
		}

	default:
		return func(a, b zcode.Bytes) int {
			return bytes.Compare(a, b)
		}
	}
}
