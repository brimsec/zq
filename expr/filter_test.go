package expr_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/brimsec/zq/compiler"
	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zio/tzngio"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testcase struct {
	filter   string
	expected bool
}

func runCases(t *testing.T, tzng string, cases []testcase) {
	t.Helper()
	runCasesHelper(t, tzng, cases, false)
}

func runCasesExpectBufferFilterFalsePositives(t *testing.T, tzng string, cases []testcase) {
	t.Helper()
	runCasesHelper(t, tzng, cases, true)
}

func runCasesHelper(t *testing.T, tzng string, cases []testcase, expectBufferFilterFalsePositives bool) {
	t.Helper()

	zctx := resolver.NewContext()
	batch, err := zbuf.NewPuller(tzngio.NewReader(strings.NewReader(tzng), zctx), 2).Pull()
	require.NoError(t, err, "tzng: %q", tzng)
	require.Exactly(t, 1, batch.Length(), "tzng: %q", tzng)
	rec := batch.Index(0)

	for _, c := range cases {
		t.Run(c.filter, func(t *testing.T) {
			t.Helper()

			proc, err := compiler.ParseProc(c.filter)
			require.NoError(t, err, "filter: %q", c.filter)
			fproc := filterProc(proc)
			require.NotNil(t, fproc)
			filterExpr := fproc.Filter

			filterAST := compiler.NewFilter(zctx, filterExpr)
			f, err := filterAST.AsFilter()
			assert.NoError(t, err, "filter: %q", c.filter)
			if f != nil {
				assert.Equal(t, c.expected, f(rec),
					"filter: %q\nrecord:\n%s", c.filter, hex.Dump(rec.Raw))
			}

			bf, err := filterAST.AsBufferFilter()
			assert.NoError(t, err, "filter: %q", c.filter)
			if bf != nil {
				expected := c.expected
				if expectBufferFilterFalsePositives {
					expected = true
				}
				// For fieldNameFinder.find coverage, we need to
				// hand BufferFilter.Eval a buffer containing a
				// ZNG value message for rec, assembled here.
				require.Less(t, rec.Type.ID(), 0x40)
				buf := []byte{byte(rec.Type.ID())}
				buf = zcode.AppendUvarint(buf, uint64(len(rec.Raw)))
				buf = append(buf, rec.Raw...)
				assert.Equal(t, expected, bf.Eval(zctx, buf),
					"filter: %q\nbuffer:\n%s", c.filter, hex.Dump(buf))
			}
		})
	}
}

func TestFilters(t *testing.T) {
	t.Parallel()

	// Test set membership with "in"
	tzng := `
#0:record[stringset:set[bstring]]
0:[[abc;xyz;]]`
	runCases(t, tzng, []testcase{
		{"'abc' in stringset", true},
		{"'xyz' in stringset", true},
		{"'ab'in stringset", false},
		{"'abcd' in stringset", false},
	})

	// Test escaped bstrings inside a set
	tzng = `
#0:record[stringset:set[bstring]]
0:[[a\x3bb;xyz;]]`
	runCases(t, tzng, []testcase{
		{"\"a;b\" in stringset", true},
		{"'a' in stringset", false},
		{"'b' in stringset", false},
		{"'xyz' in stringset", true},
	})

	// Test array membership with "in"
	tzng = `
#0:record[stringvec:array[bstring]]
0:[[abc;xyz;]]`
	runCases(t, tzng, []testcase{
		{"'abc' in stringvec", true},
		{"'xyz' in stringvec", true},
		{"'ab' in stringvec", false},
		{"'abcd' in stringvec", false},
	})

	// Test escaped bstrings inside an array
	tzng = `
#0:record[stringvec:array[bstring]]
0:[[a\x3bb;xyz;]]`
	runCases(t, tzng, []testcase{
		{"\"a;b\" in stringvec", true},
		{"'a' in stringvec", false},
		{"'b' in stringvec", false},
		{"'xyz' in stringvec", true},
	})

	// Test membership in set of integers
	tzng = `
#0:record[intset:set[int32]]
0:[[1;2;3;]]`
	runCases(t, tzng, []testcase{
		{"2 in intset", true},
		{"4 in intset", false},
		{"'abc' in intset", false},
	})

	// Test membership in array of integers
	tzng = `
#0:record[intvec:array[int32]]
0:[[1;2;3;]]`
	runCases(t, tzng, []testcase{
		{"2 in intvec", true},
		{"4 in intvec", false},
		{"'abc' in intvec", false},
	})

	// Test membership in set of ip addresses
	tzng = `
#0:record[addrset:set[ip]]
0:[[1.1.1.1;2.2.2.2;]]`
	runCases(t, tzng, []testcase{
		{"1.1.1.1 in addrset", true},
		{"3.3.3.3 in addrset", false},
	})

	// Test membership and len() on array of ip addresses
	tzng = `
#0:record[addrvec:array[ip]]
0:[[1.1.1.1;2.2.2.2;]]`
	runCases(t, tzng, []testcase{
		{"1.1.1.1 in addrvec", true},
		{"3.3.3.3 in addrvec", false},
		{"len(addrvec) = 2", true},
		{"len(addrvec) = 3", false},
		{"len(addrvec) > 1", true},
		{"len(addrvec) >= 2", true},
		{"len(addrvec) < 5", true},
		{"len(addrvec) <= 2", true},
	})

	// Test comparing fields in nested records
	tzng = `
#0:record[nested:record[field:string]]
0:[[test;]]`
	// We expect false positives from BufferFilter here because it looks for
	// values without regard to field name, returning true as long as some
	// field matches the literal to the right of the equal sign.
	runCasesExpectBufferFilterFalsePositives(t, tzng, []testcase{
		{"nested.field = test", true},
		{"bogus.field = test", false},
		{"nested.bogus = test", false},
		{"* = test", false},
	})

	// Test array of records
	tzng = `
#0:record[nested:array[record[field:int32]]]
0:[[[1;][2;]]]`
	runCases(t, tzng, []testcase{
		{"nested[0].field = 1", true},
		{"nested[1].field = 2", true},
		{"nested[0].field = 2", false},
		{"nested[2].field = 2", false},
		{"nested.field = 2", false},
	})

	// Test array inside a record
	tzng = `
#0:record[nested:record[vec:array[int32]]]
0:[[[1;2;3;]]]`
	runCases(t, tzng, []testcase{
		{"1 in nested.vec", true},
		{"2 in nested.vec", true},
		{"4 in nested.vec", false},
		{"nested.vec[0] = 1", true},
		{"nested.vec[1] = 1", false},
		{"1 in nested", false},
		{"1", true},
	})

	// Test escaped chars in a bstring
	tzng = `
#0:record[s:bstring]
0:[begin\x01\x02\xffend;]`
	runCases(t, tzng, []testcase{
		{"begin", true},
		{"s=begin", false},
		{"begin\\x01\\x02\\xffend", true},
		{"s=begin\\x01\\x02\\xffend", true},
		{"s=*\\x01\\x02*", true},
	})

	// Test unicode string comparison.  The following two records
	// both have the string "Buenos días señor" but one uses
	// combining characters (e.g., plain n plus combining
	// tilde) and the other uses composed characters.  Test both
	// strings against queries written with both formats.
	tzng = `
#0:record[s:bstring]
0:[Buenos di\xcc\x81as sen\xcc\x83or;]`
	runCases(t, tzng, []testcase{
		{`s = "Buenos di\u{0301}as sen\u{0303}or"`, true},
		{`s = "Buenos d\u{ed}as se\u{f1}or"`, true},
	})
	tzng = `
#0:record[s:bstring]
0:[Buenos d\xc3\xadas se\xc3\xb1or;]`
	runCases(t, tzng, []testcase{
		{`s = "Buenos di\u{0301}as sen\u{0303}or"`, true},
		{`s = "Buenos d\u{ed}as se\u{f1}or"`, true},
	})

	// There are two Unicode code points with a multibyte UTF-8 encoding
	// equivalent under Unicode simple case folding to code points with
	// single-byte UTF-8 encodings: U+017F LATIN SMALL LETTER LONG S is
	// equivalent to S and s, and U+212A KELVIN SIGN is equivalent to K and
	// k. The next two records ensure they're handled correctly.

	// Test U+017F LATIN SMALL LETTER LONG S.
	tzng = `
#0:record[a:string]
0:[\u017F;]`
	runCases(t, tzng, []testcase{
		{`a = \u017F`, true},
		{`a = S`, false},
		{`a = s`, false},
		{`\u017F`, true},
		{`S`, false}, // Should be true; see https://github.com/brimsec/zq/issues/1207.
		{`s`, false}, // Should be true; see https://github.com/brimsec/zq/issues/1207.
	})

	// Test U+212A KELVIN SIGN.
	tzng = `
#0:record[a:string]
0:[\u212A;]`
	runCases(t, tzng, []testcase{
		{`a = '\u212A'`, true},
		{`a = K`, true}, // True because Unicode NFC replaces U+212A with U+004B.
		{`a = k`, false},
		{`\u212A`, true},
		{`K`, true},
		{`k`, true},
	})

	// Test searching both fields and containers,
	// also test case-insensitive search.
	tzng = `
#0:record[s:string,srec:record[svec:array[string]]]
0:[hello;[[world;worldz;1.1.1.1;]]]`
	runCases(t, tzng, []testcase{
		{"hello", true},
		{"worldz", true},
		{"HELLO", true},
		{"WoRlDZ", true},
		{"1.1.1.1", true},
		{"wor*", true},
	})

	// Test searching a record inside an array, record, set, and union.
	for _, c := range []struct {
		name string
		tzng string
	}{
		{"array", `
#0:record[a:array[record[i:int64,s1:string,s2:string]]]
0:[[[123;456;hello;]]]`},
		{"record", `
#0:record[r:record[r2:record[i:int64,s1:string,s2:string]]]
0:[[[123;456;hello;]]]`},
		{"set", `
#0:record[s:set[record[i:int64,s1:string,s2:string]]]
0:[[[123;456;hello;]]]`},
		{"union", `
#0:record[u:union[int64,record[i:int64,s1:string,s2:string]]]
0:[1:[123;456;hello, world;]]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			runCases(t, c.tzng, []testcase{
				{"123", true},
				{`"123"`, false},
				{"12", false},
				{"456", true},
				{`"456"`, true},
				{"45", true},
				{"hello", true},
			})
		})
	}

	// Test searching with subnet syntax
	tzng = `
#0:record[addr:ip]
0:[192.168.1.50;]`
	runCases(t, tzng, []testcase{
		{"192.168.0.0/16", true},
		{"192.168.1.0/24", true},
		{"10.0.0.0/8", false},
	})

	// Test time coercion
	tzng = `
#0:record[ts:time,ts2:time,ts3:time]
0:[1.001;1578411532;1578411533.01;]`
	runCases(t, tzng, []testcase{
		{"ts<2", true},
		{"ts=1.001", true},
		{"ts<1.002", true},
		{"ts<2.0", true},
		{"ts2=1578411532", true},
		{"ts3=1578411533", false},
	})

	// Test that string search doesn't match non-string types:
	// The ASCII value of 'T' (0x54) is present inside the binary
	// encoding of 1.001.  But naked string search should not match.
	tzng = `
#0:record[f:float64]
0:[1.001;]`
	runCases(t, tzng, []testcase{
		{"T", false},
	})

	// Test integer conditions.  These are really testing 2 things:
	// 1. that the full range of values are correctly parsed
	// 2. that coercion to int64 works properly (in all the filters
	//    with integers on the RHS)
	// 3. that coercion to float64 works properly (in the filters
	//    with floats on the RHS)
	tzng = `
#0:record[b:uint8,i16:int16,u16:uint16,i32:int32,u32:uint32,i64:int64,u64:uint64]
0:[0;-32768;0;-2147483648;0;-9223372036854775808;0;]`
	runCases(t, tzng, []testcase{
		{"b > -1", true},
		{"b = 0", true},
		{"b < 1", true},
		{"b > 1", false},
		{"b = 0.0", true},
		{"b < 0.5", true},

		{"i16 = -32768", true},
		{"i16 < 0", true},
		{"i16 > 0", false},
		{"i16 = -32768.0", true},
		{"i16 < 0.0", true},

		{"u16 > -1", true},
		{"u16 = 0", true},
		{"u16 < 1", true},
		{"u16 > 1", false},
		{"u16 = 0.0", true},
		{"u16 < 0.5", true},

		{"i32 = -2147483648", true},
		{"i32 < 0", true},
		{"i32 > 0", false},
		{"i32 = -2147483648.0", true},
		{"i32 < 0.5", true},

		{"u32 > -1", true},
		{"u32 = 0", true},
		{"u32 < 1", true},
		{"u32 > 1", false},
		{"u32 = 0.0", true},
		{"u32 < 0.5", true},

		{"i64 = -9223372036854775808", true},
		{"i64 < 0", true},
		{"i64 > 0", false},
		{"i64 < 0.0", true},
		// MinInt64 can't be represented precisely as a float64

		{"u64 > -1", true},
		{"u64 = 0", true},
		{"u64 < 1", true},
		{"u64 > 1", false},
		{"u64 = 0.0", true},
		{"u64 < 0.5", true},
	})

	tzng = `
#0:record[b:uint8,i16:int16,u16:uint16,i32:int32,u32:uint32,i64:int64,u64:uint64]
0:[255;32767;65535;2147483647;4294967295;9223372036854775807;18446744073709551615;]`
	runCases(t, tzng, []testcase{
		{"b = 255", true},
		{"i16 = 32767", true},
		{"u16 = 65535", true},
		{"i32 = 2147483647", true},
		{"u32 = 4294967295", true},
		{"i64 = 9223372036854775807", true},
		// can't represent large unsigned 64 bit values in zql...
		// {"u64 = 18446744073709551615", true},
	})

	// Test comparisons with field of type port (can compare with
	// a port literal or an integer literal)
	tzng = `
#port=uint16
#0:record[p:port]
0:[443;]`
	runCases(t, tzng, []testcase{
		{"p = 443", true},
		{"p = 80", false},
	})

	// Test coercion from string to bstring
	tzng = `
#0:record[s:bstring]
0:[hello;]`
	runCases(t, tzng, []testcase{
		{"s = hello", true},
		{"s != hello", false},

		// Also smoke test that globs work...
		{"s = hell*", true},
		{"s = ell*", false},
		{"s != hell*", false},
		{"s != ell*", true},
	})

	// Test ip comparisons
	tzng = `
#0:record[a:ip]
0:[192.168.1.50;]`
	runCases(t, tzng, []testcase{
		{"a = 192.168.1.50", true},
		{"a = 50.1.168.192", false},
		{"a != 50.1.168.192", true},
		{"a in 192.168.0.0/16", true},
		{"a = 10.0.0.0/16", false},
		{"a != 192.168.0.0/16", false},
		{"a != 10.0.0.0/16", true},
	})

	// Test comparisons with an aliased type
	tzng = `
#myint=int32
#0:record[i:myint]
0:[100;]`
	runCases(t, tzng, []testcase{
		{"i = 100", true},
		{"i > 0", true},
		{"i < 50", false},
	})

	// Test searching for a field name
	tzng = `
#0:record[foo:string,rec:record[SUB:string]]
0:[bleah;[meh;]]`
	runCases(t, tzng, []testcase{
		{"foo", true},
		{"FOO", true},
		{"foo.", false},
		{"sub", true},
		{"sub.", false},
		{"rec.sub", true},
		{"c.s", true},
	})

	// Test searching for a field name of an unset record
	tzng = `
#0:record[rec:record[str:string]]
0:[-;]`
	runCases(t, tzng, []testcase{
		{"rec.str", true},
	})

	// Test searching an empty top-level record
	tzng = `
#0:record[]
0:[]`
	runCases(t, tzng, []testcase{
		{"empty", false},
	})

	// Test searching an empty nested record
	tzng = `
#0:record[empty:record[]]
0:[[]]`
	runCases(t, tzng, []testcase{
		{"empty", true},
	})

}

func filterProc(p ast.Proc) *ast.FilterProc {
	if seq, ok := p.(*ast.SequentialProc); ok {
		p = seq.Procs[0]
	}
	if f, ok := p.(*ast.FilterProc); ok {
		return f
	}
	return nil
}

func TestBadFilter(t *testing.T) {
	t.Parallel()
	proc, err := compiler.ParseProc(`s = \xa8*`)
	require.NoError(t, err)
	fproc := filterProc(proc)
	require.NotNil(t, fproc)
	f := compiler.NewFilter(resolver.NewContext(), fproc.Filter)
	_, err = f.AsFilter()
	assert.Error(t, err, "Received error for bad glob")
}
