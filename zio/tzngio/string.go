package tzngio

import (
	"fmt"
	"strings"
)

func (c *Column) String() string {
	return FormatName(c.Name) + ":" + c.Type.String()
}

func ColumnString(prefix string, columns []Column, suffix string) string {
	var s strings.Builder
	s.WriteString(prefix)
	var comma bool
	for _, c := range columns {
		if comma {
			s.WriteByte(byte(','))
		}
		s.WriteString(c.String())
		comma = true
	}
	s.WriteString(suffix)
	return s.String()
}

func (t *TypeAlias) String() string {
	return t.Name
}

func (t *TypeEnum) String() string {
	typ := t.Type
	var out []string
	for _, e := range t.Elements {
		name := FormatName(e.Name)
		val := typ.StringOf(e.Value, OutFormatZNG, false)
		out = append(out, fmt.Sprintf("%s:[%s]", name, val))
	}
	return fmt.Sprintf("enum[%s,%s]", typ, strings.Join(out, ","))
}


func FormatName(name string) string {
	if IsIdentifier(name) {
		return name
	}
	var b strings.Builder
	b.WriteRune('[')
	b.WriteString(TypeString.StringOf(EncodeString(name), OutFormatZNG, false))
	b.WriteRune(']')
	return b.String()
}

func TypeRecordString(columns []Column) string {
	return ColumnString("record[", columns, "]")
}

func (t *TypeRecord) String() string {
	return TypeRecordString(t.Columns)
}

func (t *TypeUnion) String() string {
	var ss []string
	for _, typ := range t.Types {
		ss = append(ss, typ.String())
	}
	return fmt.Sprintf("union[%s]", strings.Join(ss, ","))
}

func badZng(err error, t Type, zv zcode.Bytes) string {
	return fmt.Sprintf("<ZNG-ERR type %s [%s]: %s>", t, zv, err)
}

func FormatValue(v zng.Value, fmt OutFmt) string {
	if v.Bytes == nil {
		return "-"
	}
	return v.Type.StringOf(v.Bytes, fmt, false)
}
