package zng

import (
	"unicode"
	"unicode/utf8"
)

func QuotedName(name string) string {
	if !IsIdentifier(name) {
		name = QuotedString([]byte(name), false)
	}
	return name
}

const hexdigits = "0123456789abcdef"

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
