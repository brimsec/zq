package function

import (
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/brimsec/zq/expr/result"
	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

// XXX these string format functions should be handlded by :string cast

type stringFormatFloat struct{}

func (s *stringFormatFloat) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	if zv.Type.ID() != zng.IdFloat64 {
		return badarg("string.floatToString")
	}
	if zv.Bytes == nil {
		return zng.Value{zng.TypeString, nil}, nil
	}
	f, _ := zng.DecodeFloat64(zv.Bytes)
	// XXX GC
	v := strconv.FormatFloat(f, 'g', -1, 64)
	return zng.Value{zng.TypeString, zng.EncodeString(v)}, nil
}

type stringFormatInt struct{}

func (s *stringFormatInt) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	id := zv.Type.ID()
	var out string
	if !zng.IsInteger(id) {
		return badarg("string.intToString")
	}
	if zv.Bytes == nil {
		return zng.Value{zng.TypeString, nil}, nil
	}
	if zng.IsSigned(id) {
		v, _ := zng.DecodeInt(zv.Bytes)
		// XXX GC
		out = strconv.FormatInt(v, 10)
	} else {
		v, _ := zng.DecodeUint(zv.Bytes)
		// XXX GC
		out = strconv.FormatUint(v, 10)
	}
	return zng.Value{zng.TypeString, zng.EncodeString(out)}, nil
}

type stringFormatIp struct{}

func (s *stringFormatIp) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	if zv.Type.ID() != zng.IdIP {
		return badarg("string.ipToString")
	}
	if zv.Bytes == nil {
		return zng.Value{zng.TypeString, nil}, nil
	}
	// XXX GC
	ip, _ := zng.DecodeIP(zv.Bytes)
	return zng.Value{zng.TypeString, zng.EncodeString(ip.String())}, nil
}

type stringParseInt struct {
	result.Buffer
}

func (s *stringParseInt) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	if !zv.IsStringy() {
		return badarg("String.parseInt")
	}
	if zv.Bytes == nil {
		return zng.Value{zng.TypeInt64, nil}, nil
	}
	v, e := zng.DecodeString(zv.Bytes)
	if e != nil {
		return zng.Value{}, e
	}
	i, perr := strconv.ParseInt(v, 10, 64)
	if perr != nil {
		// Get rid of the strconv wrapping gunk to get the
		// actual error message
		e := perr.(*strconv.NumError)
		return zverr("String.parseInt", e.Err)
	}
	return zng.Value{zng.TypeInt64, s.Int(i)}, nil
}

type stringParseFloat struct {
	result.Buffer
}

func (s *stringParseFloat) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	if !zv.IsStringy() {
		return badarg("String.parseFloat")
	}
	if zv.Bytes == nil {
		return zng.Value{zng.TypeFloat64, nil}, nil
	}
	v, perr := zng.DecodeString(zv.Bytes)
	if perr != nil {
		return zng.Value{}, perr
	}
	f, perr := strconv.ParseFloat(v, 64)
	if perr != nil {
		// Get rid of the strconv wrapping gunk to get the
		// actual error message
		e := perr.(*strconv.NumError)
		return zverr("String.parseFloat", e.Err)
	}
	return zng.Value{zng.TypeFloat64, s.Float64(f)}, nil
}

type stringParseIp struct{}

func (s *stringParseIp) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	if !zv.IsStringy() {
		return badarg("String.parseIp")
	}
	if zv.Bytes == nil {
		return zng.Value{zng.TypeIP, nil}, nil
	}
	v, err := zng.DecodeString(zv.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	// XXX GC
	a := net.ParseIP(v)
	if a == nil {
		return badarg("String.parseIp")
	}
	// XXX GC
	return zng.Value{zng.TypeIP, zng.EncodeIP(a)}, nil
}

type replace struct{}

func (*replace) Call(args []zng.Value) (zng.Value, error) {
	zvs := args[0]
	zvold := args[1]
	zvnew := args[2]
	if !zvs.IsStringy() || !zvold.IsStringy() || !zvnew.IsStringy() {
		return badarg("replace")
	}
	if zvs.Bytes == nil {
		return zvs, nil
	}
	if zvold.Bytes == nil || zvnew.Bytes == nil {
		return badarg("replace")
	}
	s, err := zng.DecodeString(zvs.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	old, err := zng.DecodeString(zvold.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	new, err := zng.DecodeString(zvnew.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	result := strings.ReplaceAll(s, old, new)
	return zng.Value{zng.TypeString, zng.EncodeString(result)}, nil
}

type runeLen struct {
	result.Buffer
}

func (s *runeLen) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	if !zv.IsStringy() {
		return badarg("rune_len")
	}
	if zv.Bytes == nil {
		return zng.Value{zng.TypeInt64, s.Int(0)}, nil
	}
	in, err := zng.DecodeString(zv.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	v := utf8.RuneCountInString(in)
	return zng.Value{zng.TypeInt64, s.Int(int64(v))}, nil
}

type toLower struct{}

func (*toLower) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	if !zv.IsStringy() {
		return badarg("to_lower")
	}
	if zv.Bytes == nil {
		return zv, nil
	}
	s, err := zng.DecodeString(zv.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	// XXX GC
	s = strings.ToLower(s)
	return zng.Value{zng.TypeString, zng.EncodeString(s)}, nil
}

type toUpper struct{}

func (*toUpper) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	if !zv.IsStringy() {
		return badarg("to_upper")
	}
	if zv.Bytes == nil {
		return zv, nil
	}
	s, err := zng.DecodeString(zv.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	// XXX GC
	s = strings.ToUpper(s)
	return zng.Value{zng.TypeString, zng.EncodeString(s)}, nil
}

type trim struct{}

func (*trim) Call(args []zng.Value) (zng.Value, error) {
	zv := args[0]
	if !zv.IsStringy() {
		return badarg("trim")
	}
	if zv.Bytes == nil {
		return zv, nil
	}
	// XXX GC
	s := strings.TrimSpace(string(zv.Bytes))
	return zng.Value{zng.TypeString, zng.EncodeString(s)}, nil
}

type split struct {
	zctx  *resolver.Context
	typ   zng.Type
	bytes zcode.Bytes
}

func newSplit(zctx *resolver.Context) *split {
	return &split{
		typ: zctx.LookupTypeArray(zng.TypeString),
	}
}

func (s *split) Call(args []zng.Value) (zng.Value, error) {
	zs := args[0]
	zsep := args[1]
	if !zs.IsStringy() || !zsep.IsStringy() {
		return badarg("split")
	}
	if zs.Bytes == nil || zsep.Bytes == nil {
		return zng.Value{Type: s.typ}, nil
	}
	str, err := zng.DecodeString(zs.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	sep, err := zng.DecodeString(zsep.Bytes)
	if err != nil {
		return zng.Value{}, err
	}
	splits := strings.Split(str, sep)
	b := s.bytes[:0]
	for _, substr := range splits {
		b = zcode.AppendPrimitive(b, zng.EncodeString(substr))
	}
	s.bytes = b
	return zng.Value{s.typ, b}, nil
}

type join struct {
	bytes   zcode.Bytes
	builder strings.Builder
}

func (j *join) Call(args []zng.Value) (zng.Value, error) {
	zsplits := args[0]
	typ, ok := zng.AliasedType(zsplits.Type).(*zng.TypeArray)
	if !ok {
		return zng.NewErrorf("argument to join() is not an array"), nil
	}
	if !zng.IsStringy(typ.Type.ID()) {
		return zng.NewErrorf("argument to join() is not a string array"), nil
	}
	var separator string
	if len(args) == 2 {
		zsep := args[1]
		if !zsep.IsStringy() {
			return zng.NewErrorf("separator argument to join() is not a string"), nil
		}
		var err error
		separator, err = zng.DecodeString(zsep.Bytes)
		if err != nil {
			return zng.Value{}, err
		}
	}
	b := j.builder
	b.Reset()
	it := zsplits.Bytes.Iter()
	var sep string
	for !it.Done() {
		bytes, _, err := it.Next()
		if err != nil {
			return zng.Value{}, err
		}
		s, err := zng.DecodeString(bytes)
		if err != nil {
			return zng.Value{}, err
		}
		b.WriteString(sep)
		b.WriteString(s)
		sep = separator
	}
	return zng.Value{zng.TypeString, zng.EncodeString(b.String())}, nil
}
