package tzngio

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnescapeBstring(t *testing.T) {
	cases := []struct {
		unescaped string
		escaped   string
	}{
		{`\`, `\\`},
		{`\\`, `\\\\`},
		{`ascii`, `ascii`},
		{"\a\b\f\n\r\t\v", `\x07\x08\x0c\x0a\x0d\x09\x0b`},
		{"\x00\x19\x20\\\x7e\x7f\xff", "\\x00\\x19\x20\\\\\x7e\\x7f\\xff"},
		{"\x00😁", `\x00\xf0\x9f\x98\x81`},
	}
	for _, c := range cases {
		in, expected := c.escaped, c.unescaped

		actual := UnescapeBstring([]byte(in))
		require.Exactly(t, []byte(expected), actual, "case: %#v", c)

		actual = UnescapeBstring([]byte("prefix" + in + "suffix"))
		expected = "prefix" + expected + "suffix"
		require.Exactly(t, []byte(expected), actual, "case: %#v", c)
	}
}

func TestUnescapeString(t *testing.T) {
	cases := []struct {
		unescaped string
		escaped   string
	}{
		// A few valid escapes:
		{`🍺`, `\u{1f37a}`},
		{`⛰`, `\u{26f0}`},
		{`⛰`, `\u26f0`},

		// Things that are not interpreted in string type:
		{`\x0a`, `\x0a`},
		{`\\`, `\\`},

		// Invalid escape sequences are ignored:
		{`\u{}`, `\u{}`},
		{`\u{xyz}`, `\u{xyz}`},
		{`\u{12345678}`, `\u{12345678}`},
		{`\uabcz`, `\uabcz`},
		{`\u`, `\u`},
	}
	for _, c := range cases {
		in, expected := c.escaped, c.unescaped

		actual := UnescapeString([]byte(in))
		require.Exactly(t, []byte(expected), actual, "case: %#v", c)

		actual = UnescapeString([]byte("prefix" + in + "suffix"))
		expected = "prefix" + expected + "suffix"
		require.Exactly(t, []byte(expected), actual, "case: %#v", c)
	}
}
