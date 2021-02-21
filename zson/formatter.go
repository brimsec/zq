package zson

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
)

type Formatter struct {
	typedefs    typemap
	tab         int
	newline     string
	whitespace  string
	typeTab     int
	typeNewline string
	nid         int
	types       *TypeTable
	builder     strings.Builder
	stack       []strings.Builder
	implied     map[zng.Type]bool
}

func NewFormatter(pretty int) *Formatter {
	var newline string
	if pretty > 0 {
		newline = "\n"
	}
	return &Formatter{
		typedefs:   make(typemap),
		tab:        pretty,
		newline:    newline,
		whitespace: strings.Repeat(" ", 80),
		implied:    make(map[zng.Type]bool),
	}
}

func (f *Formatter) push() {
	f.stack = append(f.stack, f.builder)
	f.builder = strings.Builder{}
}

func (f *Formatter) pop() {
	n := len(f.stack)
	f.builder = f.stack[n-1]
	f.stack = f.stack[:n-1]
}

func (f *Formatter) FormatRecord(rec *zng.Record) (string, error) {
	f.builder.Reset()
	if err := f.formatValueAndDecorate(rec.Alias, rec.Raw); err != nil {
		return "", err
	}
	return f.builder.String(), nil
}

func (f *Formatter) Format(zv zng.Value) (string, error) {
	f.builder.Reset()
	if err := f.formatValueAndDecorate(zv.Type, zv.Bytes); err != nil {
		return "", err
	}
	return f.builder.String(), nil
}

func (f *Formatter) formatValueAndDecorate(typ zng.Type, bytes zcode.Bytes) error {
	known := f.typedefs.exists(typ)
	implied := f.isImplied(typ)
	if err := f.formatValue(0, typ, bytes, known, implied, false); err != nil {
		return err
	}
	f.decorate(typ, false, bytes == nil)
	return nil
}

func (f *Formatter) formatValue(indent int, typ zng.Type, bytes zcode.Bytes, parentKnown, parentImplied, decorate bool) error {
	known := parentKnown || f.typedefs.exists(typ)
	if bytes == nil {
		f.build("null")
		if parentImplied {
			parentKnown = false
		}
		f.decorate(typ, parentKnown, true)
		return nil
	}
	var err error
	var null bool
	switch t := typ.(type) {
	default:
		f.build(typ.ZSONOf(bytes))
	case *zng.TypeAlias:
		err = f.formatValue(indent, t.Type, bytes, known, parentImplied, false)
	case *zng.TypeRecord:
		err = f.formatRecord(indent, t, bytes, known, parentImplied)
	case *zng.TypeArray:
		null, err = f.formatVector(indent, "[", "]", t.Type, zng.Value{t, bytes}, known, parentImplied)
	case *zng.TypeSet:
		null, err = f.formatVector(indent, "|[", "]|", t.Type, zng.Value{t, bytes}, known, parentImplied)
	case *zng.TypeUnion:
		err = f.formatUnion(indent, t, bytes)
	case *zng.TypeMap:
		null, err = f.formatMap(indent, t, bytes, known, parentImplied)
	case *zng.TypeEnum:
		f.build(t.ZSONOf(bytes))
	case *zng.TypeOfType:
		f.buildf("(%s)", string(bytes))
	}
	if err == nil && decorate {
		f.decorate(typ, parentKnown, null)
	}
	return err
}

func (f *Formatter) nextInternalType() string {
	name := strconv.Itoa(f.nid)
	f.nid++
	return name
}

func (f *Formatter) decorate(typ zng.Type, known, null bool) {
	if known || (!null && f.isImplied(typ)) {
		return
	}
	if name, ok := f.typedefs[typ]; ok {
		f.buildf(" (%s)", name)
		return
	}
	if SelfDescribing(typ) && !null {
		var name string
		if typ, ok := typ.(*zng.TypeAlias); ok {
			name = typ.Name
		} else {
			name = f.nextInternalType()
		}
		f.typedefs[typ] = name
		f.buildf(" (=%s)", name)
		return
	}
	f.build(" (")
	f.formatType(typ)
	f.build(")")
}

func (f *Formatter) formatRecord(indent int, typ *zng.TypeRecord, bytes zcode.Bytes, known, parentImplied bool) error {
	f.build("{")
	if len(typ.Columns) == 0 {
		f.build("}")
		return nil
	}
	indent += f.tab
	sep := f.newline
	it := bytes.Iter()
	for _, field := range typ.Columns {
		if it.Done() {
			return &zng.RecordTypeError{Name: string(field.Name), Type: field.Type.String(), Err: zng.ErrMissingField}
		}
		bytes, _, err := it.Next()
		if err != nil {
			return err
		}
		f.build(sep)
		f.indent(indent, zng.QuotedName(field.Name))
		f.build(":")
		if f.tab > 0 {
			f.build(" ")
		}
		if err := f.formatValue(indent, field.Type, bytes, known, parentImplied, true); err != nil {
			return err
		}
		sep = "," + f.newline
	}
	f.build(f.newline)
	f.indent(indent-f.tab, "}")
	return nil
}

func (f *Formatter) formatVector(indent int, open, close string, inner zng.Type, zv zng.Value, known, parentImplied bool) (bool, error) {
	f.build(open)
	len, err := zv.ContainerLength()
	if err != nil {
		return true, err
	}
	if len == 0 {
		f.build(close)
		return true, nil
	}
	indent += f.tab
	sep := f.newline
	it := zv.Iter()
	for !it.Done() {
		bytes, _, err := it.Next()
		if err != nil {
			return true, err
		}
		f.build(sep)
		f.indent(indent, "")
		if err := f.formatValue(indent, inner, bytes, known, parentImplied, true); err != nil {
			return true, err
		}
		sep = "," + f.newline
	}
	f.build(f.newline)
	f.indent(indent-f.tab, close)
	return false, nil
}

func (f *Formatter) formatUnion(indent int, union *zng.TypeUnion, bytes zcode.Bytes) error {
	typ, _, bytes, err := union.SplitZng(bytes)
	if err != nil {
		return err
	}
	// XXX For now, we always decorate a union value so that
	// we can determine the selector from the value's explicit type.
	// We can later optimize this so we only print the decorator if its
	// ambigous with another type (e.g., int8 and int16 vs a union of int8 and string).
	// Let's do this after we have the parser working and capable of this
	// disambiguation.  See issue #1764.
	// In other words, just because we known the union's type doesn't mean
	// we know the type of a particular value of that union.
	const known = false
	const parentImplied = true
	return f.formatValue(indent, typ, bytes, known, parentImplied, true)
}

func (f *Formatter) formatMap(indent int, typ *zng.TypeMap, bytes zcode.Bytes, known, parentImplied bool) (bool, error) {
	empty := true
	f.build("|{")
	indent += f.tab
	sep := f.newline
	for it := bytes.Iter(); !it.Done(); {
		keyBytes, _, err := it.Next()
		if err != nil {
			return empty, err
		}
		if it.Done() {
			return empty, errors.New("truncated map value")
		}
		empty = false
		valBytes, _, err := it.Next()
		if err != nil {
			return empty, err
		}
		f.build(sep)
		f.indent(indent, "{")
		if err := f.formatValue(indent+f.tab, typ.KeyType, keyBytes, known, parentImplied, true); err != nil {
			return empty, err
		}
		f.build(",")
		if err := f.formatValue(indent+f.tab, typ.ValType, valBytes, known, parentImplied, true); err != nil {
			return empty, err
		}
		f.build("}")
		sep = "," + f.newline
	}
	f.build(f.newline)
	f.indent(indent-f.tab, "}|")
	return empty, nil
}

func (f *Formatter) indent(tab int, s string) {
	for k := 0; k < tab; k++ {
		f.builder.WriteByte(' ')
	}
	f.build(s)
}

func (f *Formatter) build(s string) {
	f.builder.WriteString(s)
}

func (f *Formatter) buildf(s string, args ...interface{}) {
	f.builder.WriteString(fmt.Sprintf(s, args...))
}

// formatType builds typ as a type string with any
// needed typedefs for aliases that have not been previously defined.
// These typedefs use the embedded syntax (name=(type-string)).
// Typedefs handled by decorators are handled in decorate().
// The routine re-enters the type formatter with a fresh builder by
// invoking push()/pop().
func (f *Formatter) formatType(typ zng.Type) {
	if name, ok := f.typedefs[typ]; ok {
		f.build(name)
		return
	}
	if alias, ok := typ.(*zng.TypeAlias); ok {
		// We don't check here for typedefs that illegally change
		// the type of a type name as we build this output from
		// the internal type system which should not let this happen.
		name := alias.Name
		f.typedefs[typ] = name
		f.build(name)
		f.build("=(")
		f.formatType(alias.Type)
		f.build(")")
		return
	}
	if typ.ID() < zng.IdTypeDef {
		name := typ.String()
		f.typedefs[typ] = name
		f.build(name)
		return
	}
	name := f.nextInternalType()
	f.build(name)
	f.build("=(")
	f.push()
	f.formatTypeBody(typ)
	s := f.builder.String()
	f.pop()
	f.build(s)
	f.build(")")
	f.typedefs[typ] = name
}

func (f *Formatter) formatTypeBody(typ zng.Type) error {
	if name, ok := f.typedefs[typ]; ok {
		f.build(name)
		return nil
	}
	switch typ := typ.(type) {
	case *zng.TypeAlias:
		// Aliases are handled differently above to determine the
		// plain form vs embedded typedef.
		panic("alias shouldn't be formatted")
	case *zng.TypeRecord:
		f.formatTypeRecord(typ)
	case *zng.TypeArray:
		f.build("[")
		f.formatType(typ.Type)
		f.build("]")
	case *zng.TypeSet:
		f.build("|[")
		f.formatType(typ.Type)
		f.build("]|")
	case *zng.TypeMap:
		f.build("|{")
		f.formatType(typ.KeyType)
		f.formatType(typ.ValType)
		f.build("}|")
	case *zng.TypeUnion:
		f.formatTypeUnion(typ)
	case *zng.TypeEnum:
		return f.formatTypeEnum(typ)
	case *zng.TypeOfType:
		f.build(typ.ZSON())
	default:
		panic("unknown case in formatTypeBody(): " + typ.String())
	}
	return nil
}

func (f *Formatter) formatTypeRecord(typ *zng.TypeRecord) {
	var sep string
	f.build("{")
	for _, col := range typ.Columns {
		f.build(sep)
		f.build(zng.QuotedName(col.Name))
		f.build(":")
		f.formatType(col.Type)
		sep = ","
	}
	f.build("}")
}

func (f *Formatter) formatTypeUnion(typ *zng.TypeUnion) {
	var sep string
	f.build("(")
	for _, typ := range typ.Types {
		f.build(sep)
		f.formatType(typ)
		sep = ","
	}
	f.build(")")
}

func (f *Formatter) formatTypeEnum(typ *zng.TypeEnum) error {
	var sep string
	f.build("<")
	inner := typ.Type
	for k, elem := range typ.Elements {
		f.build(sep)
		f.buildf("%s:", zng.QuotedName(elem.Name))
		known := k != 0
		const parentImplied = true
		if err := f.formatValue(0, inner, elem.Value, known, parentImplied, true); err != nil {
			return err
		}
		sep = ","
	}
	f.build(">")
	return nil
}

func (f *Formatter) isImplied(typ zng.Type) bool {
	implied, ok := f.implied[typ]
	if !ok {
		implied = Implied(typ)
		f.implied[typ] = implied
	}
	return implied
}

type typemap map[zng.Type]string

func (t typemap) exists(typ zng.Type) bool {
	_, ok := t[typ]
	return ok
}

func (t typemap) known(typ zng.Type) bool {
	if _, ok := t[typ]; ok {
		return true
	}
	if _, ok := typ.(*zng.TypeOfType); ok {
		return true
	}
	if _, ok := typ.(*zng.TypeAlias); ok {
		return false
	}
	return typ.ID() < zng.IdTypeDef
}
