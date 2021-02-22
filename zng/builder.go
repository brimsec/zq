package zng

import (
	"errors"

	"github.com/brimsec/zq/zcode"
)

var ErrIncomplete = errors.New("not enough values supplied to complete record")

// Builder provides a way of easily and efficiently building records
// of the same type.
type Builder struct {
	zcode.Builder
	Type *TypeRecord
	rec  Record
}

func NewBuilder(typ *TypeRecord) *Builder {
	return &Builder{Type: typ}
}

// Build encodes the top-level zcode.Bytes values as the Raw field
// of a record and sets that field and the Type field of the passed-in record.
// XXX This currently only works for zvals that are properly formatted for
// the top-level scan of the record, e.g., if a field is record[id:[record:[orig_h:ip]]
// then the zval passed in here for that field must have the proper encoding...
// this works fine when values are extracted and inserted from the proper level
// but when leaf values are inserted we should have another method to handle this,
// e.g., by encoding the dfs traversal of the record type with info about
// primitive vs container insertions.  This could be the start of a whole package
// that provides different ways to build zng.Records via, e.g., a marshal API,
// auto-generated stubs, etc.
func (b *Builder) Build(zvs ...zcode.Bytes) *Record {
	b.Reset()
	cols := b.Type.Columns
	for k, zv := range zvs {
		if IsContainerType(cols[k].Type) {
			b.AppendContainer(zv)
		} else {
			b.AppendPrimitive(zv)
		}
	}
	// Note that t.rec.nonvolatile is false so anything downstream
	// will have to copy the record and we can re-use the record value
	// between subsequent calls.
	b.rec.Type = b.Type
	b.rec.Alias = b.Type
	b.rec.Raw = b.Bytes()
	return &b.rec
}

/*

// Parse creates a record from the a text representation of each leaf value
// in the DFS traversal of the record type.  If there aren't enough inputs values
// to occupy every leaf value, then those values are left unset, in which case
// a valid record is returned along with ErrIncomplete.
// XXX We do not yet have a complete specification of the literal syntax of
// zng values (e.g., as defined in zql) but once we have clarity, we will
// update this routine with proper recursive-descent parsing of the syntax,
// or we will use the peg parser to generate an AST for the literal and
// take that AST as input here.
func (b *Builder) Parse(vals ...string) (*Record, error) {
	b.Reset()
	out, err := b.parseRecord(b.Type, vals)
	if err != nil && err != ErrIncomplete {
		return nil, err
	}
	if len(out) != 0 {
		return nil, fmt.Errorf("too many values (%d) supplied for type: %s", len(vals), b.Type)
	}
	// Note that t.rec.nonvolatile is false so anything downstream
	// will have to copy the record and we can re-use the record value
	// between subsequent calls.
	b.rec.Type = b.Type
	b.rec.Raw = b.Bytes()
	// We do a final type check to make sure everything is good.  In particular,
	// there are no checks below to ensure that set vals comply with the
	// ordering constraint.  XXX we could order them automatically if they
	// are not sorted, but we don't do this yet.
	if typErr := b.rec.TypeCheck(); typErr != nil {
		// type error overrides ErrIncomplete
		err = typErr
	}
	return &b.rec, err
}

func (b *Builder) parseRecord(typ *TypeRecord, in []string) ([]string, error) {
	var err error
	for _, col := range typ.Columns {
		if len(in) == 0 {
			err = ErrIncomplete
			b.appendUnset(col.Type)
			continue
		}

		switch v := AliasedType(col.Type).(type) {
		case *TypeRecord:
			b.BeginContainer()
			in, err = b.parseRecord(v, in)
			if err != nil && err != ErrIncomplete {
				return nil, err
			}
			b.EndContainer()
		case *TypeArray:
			b.BeginContainer()
			if err := b.parseArray(v, in[0]); err != nil {
				return nil, err
			}
			b.EndContainer()
			in = in[1:]
		case *TypeSet:
			b.BeginContainer()
			if err := b.parseSet(v, in[0]); err != nil {
				return nil, err
			}
			b.EndContainer()
			in = in[1:]
		case *TypeUnion:
			// XXX need a value syntax that indicates which type to use
			return nil, errors.New("union values not yet supported")
		default:
			if err := b.parsePrimitive(v, in[0]); err != nil {
				return nil, err
			}
			in = in[1:]
		}
	}
	return in, err
}

func (b *Builder) parseArray(typ *TypeArray, in string) error {
	inner := InnerType(AliasedType(typ))
	if len(in) == 0 {
		return nil
	}
	if in[0] != '[' || in[len(in)-1] != ']' {
		return ErrBadFormat
	}
	in = in[1 : len(in)-1]
	if len(in) == 0 {
		// empty array
		b.appendUnset(inner)
		return nil
	}
	//XXX for now just use simple comma rule, which means comman
	// cannot be embedded in a set value here.  we need a recursive
	// descent parser like the type parser to d this correctly or
	// change all this to built from an AST literal object parsed
	// by the zql parser.
	for _, val := range strings.Split(in, ",") {
		switch v := inner.(type) {
		case *TypeRecord:
			// XXX need a syntax for this, and recursive descent
			return errors.New("array of records value not yet supported")
		case *TypeArray:
			// XXX need a syntax for this, and recursive descent
			return errors.New("array of arrays value not yet supported")
		case *TypeSet:
			// XXX need a syntax for this, and recursive descent
			return errors.New("array of sets value not yet supported")
		case *TypeUnion:
			// XXX need a syntax for this, and recursive descent
			return errors.New("array of unions value not yet supported")
		default:
			b.parsePrimitive(v, val)
		}
	}
	return nil
}

func (b *Builder) parseSet(typ *TypeSet, in string) error {
	inner := InnerType(AliasedType(typ))
	if len(in) == 0 {
		return nil
	}
	if in[0] != '[' || in[len(in)-1] != ']' {
		return ErrBadFormat
	}
	in = in[1 : len(in)-1]
	if len(in) == 0 {
		// empty set
		b.appendUnset(inner)
		return nil
	}
	//XXX for now just use simple comma rule, which means comman
	// cannot be embedded in a set value here.  we need a recursive
	// descent parser like the type parser to d this correctly
	for _, val := range strings.Split(in, ",") {
		// we a don't enforce ordering here but rely on top-level
		// here doing a recordCheck
		if err := b.parsePrimitive(inner, val); err != nil {
			return err
		}
	}
	return nil
}
*/

func (b *Builder) appendUnset(typ Type) {
	if IsContainerType(typ) {
		b.AppendContainer(nil)
	} else {
		b.AppendPrimitive(nil)
	}
}

/*
func (b *Builder) parsePrimitive(typ Type, val string) error {
	body, err := typ.Parse([]byte(val))
	if err != nil {
		return err
	}
	b.AppendPrimitive(body)
	return nil
}
*/
