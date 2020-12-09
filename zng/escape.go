package zng

import (
	"bytes"
	"regexp"
	"unicode"
	"unicode/utf8"
)

func QuotedName(name string) string {
	if !NameIsId(name) {
		name = QuotedString([]byte(name), false)
	}
	return name
}

func QuotedString(data []byte, bstr bool) string {
	var out []byte
	var start int
	out = append(out, '"')
	for i := 0; i < len(data); {
		r, l := utf8.DecodeRune(data[i:])
		if c := StringEscape(r); c != 0 {
			out = append(out, data[start:i]...)
			out = append(out, '\\', c)
			i++
			start = i
			continue
		}
		if (r == utf8.RuneError && bstr) || !unicode.IsPrint(r) {
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
	out = append(out, data[start:len(data)]...)
	out = append(out, '"')
	return string(out)
}

// ShouldEscape determines if the given code point at the given position
// in a value should be escaped for the given output format.  This function
// does not account for unprintable characters, its main purpose is to
// centralize the logic about which characters are syntatically significant
// in each output format and hence must be escaped.  The inContainer parameter
// specifies whether this values is inside a set or vector (which is needed
// to correctly implement  zeek log escaping rules).
func ShouldEscape(r rune, fmt OutFmt, pos int, inContainer bool) bool {
	if fmt != OutFormatUnescaped && r == '\\' {
		return true
	}

	if fmt == OutFormatZNG && (r == ';' || (pos == 0 && (r == '[' || r == ']'))) {
		return true
	}

	if (fmt == OutFormatZeek || fmt == OutFormatZeekAscii) && (r == '\t' || (r == ',' && inContainer)) {
		return true
	}

	if fmt == OutFormatZeekAscii && r > 0x7f {
		return true
	}
	return false
}

func StringEscape(r rune) byte {
	switch r {
	case '\\':
		return '\\'
	case '"':
		return '"'
	case '\b':
		return 'b'
	case '\f':
		return 'f'
	case '\n':
		return 'n'
	case '\r':
		return 'r'
	case '\t':
		return 't'
	}
	return 0
}

// UnescapeBstring replaces all the escaped characters defined in the
// for the zng spec for the bstring type with their unescaped equivalents.
func UnescapeBstring(data []byte) []byte {
	if bytes.IndexByte(data, '\\') < 0 {
		return data
	}
	var buf []byte
	i := 0
	for i < len(data) {
		c := data[i]
		if c == '\\' && len(data[i:]) >= 2 {
			var n int
			c, n = parseBstringEscape(data[i:])
			i += n
		} else {
			i++
		}
		buf = append(buf, c)
	}
	return buf
}

func parseBstringEscape(data []byte) (byte, int) {
	if len(data) >= 4 && data[1] == 'x' {
		v1 := unhex(data[2])
		v2 := unhex(data[3])
		if v1 <= 0xf || v2 <= 0xf {
			return v1<<4 | v2, 4
		}
	} else if len(data) >= 2 && data[1] == '\\' {
		return data[1], 2
	}

	// Not a valid escape sequence, just leave it alone.
	return data[0], 1
}

func unhex(b byte) byte {
	switch {
	case '0' <= b && b <= '9':
		return b - '0'
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10
	case 'A' <= b && b <= 'F':
		return b - 'A' + 10
	}
	return 255
}

func replaceStringEscape(in []byte) []byte {
	var r rune
	i := 2
	if in[i] == '{' {
		i++
	}
	for ; i < len(in) && in[i] != '}'; i++ {
		r <<= 4
		r |= rune(unhex(in[i]))
	}
	return []byte(string(r))
}

var pattern = regexp.MustCompile(`\\u([0-9A-Fa-f]{4}|\{[0-9A-Fa-f]{1,6}\})`)

// UnescapeString replaces all the escaped characters defined in the
// for the zng spec for the string type with their unescaped equivalents.
func UnescapeString(data []byte) []byte {
	r := pattern.ReplaceAllFunc(data, replaceStringEscape)
	// ReplaceAllFunc() returns nil when data is an empty string but the
	// difference is meaningful inside zng...
	if r == nil {
		return data
	}
	return r
}
