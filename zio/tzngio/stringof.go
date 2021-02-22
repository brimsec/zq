package tzngio

import (
	"strings"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
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

func StringOf(zv zng.Value, out OutFmt, b bool) string {
	switch t := zv.Type.(type) {
	case *zng.TypeArray:
		return StringOfArray(t, zv.Bytes, out, b)
	case *zng.TypeAlias:
		return StringOf(t.Type, zv.Bytes, out, b)
	case *TypeOfBool:
		b, err := zng.DecodeBool(zv.Bytes)
		if err != nil {
			return badZng(err, t, zv.Bytes)
		}
		if b {
			return "T"
		}
		return "F"
	case *TypeOfBstring:
		return StringOfBstring(t, zv.Bytes, out, b)
        case *TypeOfBytes:
                return base64.StdEncoding.EncodeToString(zv.Bytes)
	case *TypeOfDuration:
                return zng.StringOfDuration(t, zv.Bytes, out, b)
        case *TypeEnum:
                return TypeUint64.StringOf(zv.Bytes, fmt, false)
        case *TypeOfError:
                return string(zv.Bytes)
        case *TypeOfFloat64:
                d, err := zng.DecodeFloat64(zv.Bytes)
                if err != nil {
                        return badZng(err, t, zv)
                }
                return strconv.FormatFloat(d, 'f', -1, 64)
        case: *TypeOfInt8, *TypeOfInt16, *TypeOfInt32, *TypeOfInt64:
                b, err := zng.DecodeInt(zv.Bytes)
                if err != nil {
                        return badZng(err, t, zv, zv.Bytes)
                }
                return strconv.FormatInt(int64(b), 10)
        case *TypeOfUint8, *TypeOfUint16, *TypeOfUint32, *TypeOfUint64:
                b, err := zng.DecodeUint(zv.Bytes)
                if err != nil {
                        return badZng(err, t, zv.Bytes)
                }
                return strconv.FormatUint(uint64(b), 10)
        case *TypeOfIP:
                ip, err := zng.DecodeIP(zv)
                if err != nil {
                        return badZng(err, t, zv)
                }
                return ip.String()
	case *TypeOfMap:
                return zng.StringOfMap(t, zv.Bytes, out, b)
	case *TypeOfNet:
                return zng.StringOfRecord(t, zv.Bytes, out, b)
        case *TypeOfNull:
                return "-"
	case *TypeOfRecord:
                return zng.StringOfRecord(t, zv.Bytes, out, b)
	case *TypeOfSet:
                return zng.StringOfSet(t, zv.Bytes, out, b)
	case *TypeOfString:
                return zng.StringOfString(t, zv.Bytes, out, b)
	case *TypeOfTime:
                return zng.StringOfTime(t, zv.Bytes, out, b)
        case *TypeOfType:
                return StringOfString(zv, fmt, inContainer)
        case *TypeOfUnion:
                return StringOfUnion(t, zv, fmt, inContainer)
        }

	return "XXX"
}

func (t *TypeArray) StringOfArray(t *zng.TypeArray, zv zcode.Bytes, fmt OutFmt, _ bool) string {
	if len(zv) == 0 && (fmt == OutFormatZeek || fmt == OutFormatZeekAscii) {
		return "(empty)"
	}

	var b strings.Builder
	separator := byte(',')
	if fmt == OutFormatZNG {
		b.WriteByte('[')
		separator = ';'
	}

	first := true
	it := zv.Iter()
	for !it.Done() {
		val, _, err := it.Next()
		if err != nil {
			//XXX
			b.WriteString("ERR")
			break
		}
		if first {
			first = false
		} else {
			b.WriteByte(separator)
		}
		if val == nil {
			b.WriteByte('-')
		} else {
			b.WriteString(t.Type.StringOf(val, fmt, true))
		}
	}

	if fmt == OutFormatZNG {
		if !first {
			b.WriteByte(';')
		}
		b.WriteByte(']')
	}
	return b.String()
}

const hexdigits = "0123456789abcdef"


// Values of type bstring may contain a mix of valid UTF-8 and arbitrary
// binary data.  These are represented in output using the same formatting
// with "\x.." escapes as Zeek.
// In general, valid UTF-8 code points are passed through unmodified,
// though for the ZEEK_ASCII output format, all non-ascii bytes are
// escaped for compatibility with older versions of Zeek.
func StringOfBstring(t *TypeOfBstring, data zcode.Bytes, fmt OutFmt, inContainer bool) string {
	if bytes.Equal(data, []byte{'-'}) {
		return "\\x2d"
	}

	var out []byte
	var start int
	for i := 0; i < len(data); {
		r, l := utf8.DecodeRune(data[i:])
		if fmt != OutFormatUnescaped && r == '\\' {
			out = append(out, data[start:i]...)
			out = append(out, '\\', '\\')
			i++
			start = i
			continue
		}
		needEscape := r == utf8.RuneError || !unicode.IsPrint(r)
		if !needEscape {
			needEscape = ShouldEscape(r, fmt, i, inContainer)
		}
		if needEscape {
			out = append(out, data[start:i]...)
			// XXX format l chars
			c := data[i]
			out = append(out, '\\', 'x', hexdigits[c>>4], hexdigits[c&0xf])
			i++
			start = i
		} else {
			i += l
		}
	}
	return string(append(out, data[start:len(data)]...))
}

func StringOfDuration(t *TypeOfDuration, zv zcode.Bytes, _ OutFmt, _ bool) string {
	i, err := DecodeDuration(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	// This format of a fractional second is used by zeek in logs.
	// It uses enough precision to fully represent the 64-bit ns
	// accuracy of a nano Duration. Such values cannot be represented by
	// float64's without loss of the least significant digits of ns,
	return nano.DurationString(i)
}

func StringOfMap( t *zng.TypeMap, zv zcode.Bytes, fmt OutFmt, _ bool) string {
	var b strings.Builder
	it := zv.Iter()
	b.WriteByte('[')
	for !it.Done() {
		val, container, err := it.Next()
		if err != nil {
			//XXX
			b.WriteString("ERR")
			break
		}
		b.WriteString(Stringof(t.KeyType, val, fmt, true))
		if !container {
			b.WriteByte(';')
		}
		val, container, err = it.Next()
		if err != nil {
			//XXX
			b.WriteString("ERR")
			break
		}
		b.WriteString(StringOf(t.ValType, val, fmt, true))
		if !container {
			b.WriteByte(';')
		}
	}
	b.WriteByte(']')
	return b.String()
}

func StringOfNet(t *TypeOfNet, zv zcode.Bytes, _ OutFmt, _ bool) string {
	s, err := zng.DecodeNet(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	ipnet := net.IPNet(*s)
	return ipnet.String()
}

func StringOfRecord(t *TypeRecord, zv zcode.Bytes, fmt OutFmt, _ bool) string {
	var b strings.Builder
	separator := byte(',')
	if fmt == OutFormatZNG {
		b.WriteByte('[')
		separator = ';'
	}

	first := true
	it := zv.Iter()
	for _, col := range t.Columns {
		val, _, err := it.Next()
		if err != nil {
			//XXX
			b.WriteString("ERR")
			break
		}
		if first {
			first = false
		} else {
			b.WriteByte(separator)
		}
		if val == nil {
			b.WriteByte('-')
		} else {
			b.WriteString(col.Type.StringOf(val, fmt, false))
		}
	}

	if fmt == OutFormatZNG {
		if !first {
			b.WriteByte(';')
		}
		b.WriteByte(']')
	}
	return b.String()
}


func StringOfSet(t *TypeSet, zv zcode.Bytes, fmt OutFmt, _ bool) string {
	if len(zv) == 0 && (fmt == OutFormatZeek || fmt == OutFormatZeekAscii) {
		return "(empty)"
	}

	var b strings.Builder
	separator := byte(',')
	if fmt == OutFormatZNG {
		b.WriteByte('[')
		separator = ';'
	}

	first := true
	it := zv.Iter()
	for !it.Done() {
		val, _, err := it.Next()
		if err != nil {
			//XXX
			b.WriteString("ERR")
			break
		}
		if first {
			first = false
		} else {
			b.WriteByte(separator)
		}
		b.WriteString(t.Type.StringOf(val, fmt, true))
	}

	if fmt == OutFormatZNG {
		if !first {
			b.WriteByte(';')
		}
		b.WriteByte(']')
	}
	return b.String()
}

func  StringOfString(t *TypeOfString, zv zcode.Bytes, fmt OutFmt, inContainer bool) string {
	if fmt != OutFormatUnescaped && bytes.Equal(zv, []byte{'-'}) {
		return "\\u002d"
	}

	var out []byte
	var start int
	for i := 0; i < len(zv); {
		r, l := utf8.DecodeRune(zv[i:])
		if fmt != OutFormatUnescaped && r == '\\' {
			out = append(out, zv[start:i]...)
			out = append(out, '\\', '\\')
			i++
			start = i
			continue
		}
		if !unicode.IsPrint(r) || ShouldEscape(r, fmt, i, inContainer) {
			out = append(out, zv[start:i]...)
			out = append(out, uescape(r)...)
			i += l
			start = i
		} else {
			i += l
		}
	}
	return string(append(out, zv[start:len(zv)]...))
}

func  StringOfTime(t *TypeOfTime, zv zcode.Bytes, _ OutFmt, _ bool) string {
	ts, err := DecodeTime(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	// This format of a fractional second is used by zeek in logs.
	// It uses enough precision to fully represent the 64-bit ns
	// accuracy of a nano.Ts.  Such values cannot be representd by
	// float64's without loss of the least significant digits of ns,
	return ts.StringFloat()
}

func StringOfUnion(t *TypeUnion, zv zcode.Bytes, ofmt OutFmt, _ bool) string {
	typ, index, iv, err := t.SplitZng(zv)
	if err != nil {
		// this follows set and record StringOfs. Like there, XXX.
		return "ERR"
	}

	s := strconv.FormatInt(index, 10) + ":"
	return s + typ.StringOf(iv, ofmt, false)
}
