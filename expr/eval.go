package expr

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"

	"github.com/brimsec/zq/expr/coerce"
	"github.com/brimsec/zq/expr/function"
	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/reglob"
	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

var ErrIncompatibleTypes = coerce.ErrIncompatibleTypes
var ErrIndexOutOfBounds = errors.New("array index out of bounds")
var ErrNotContainer = errors.New("cannot apply in to a non-container")
var ErrBadCast = errors.New("bad cast")

type Evaluator interface {
	Eval(*zng.Record) (zng.Value, error)
}

type Not struct {
	expr Evaluator
}

func NewLogicalNot(e Evaluator) *Not {
	return &Not{e}
}

func (n *Not) Eval(rec *zng.Record) (zng.Value, error) {
	zv, err := evalBool(n.expr, rec)
	if err != nil {
		return zv, err
	}
	if zng.IsTrue(zv.Bytes) {
		return zng.False, nil
	}
	return zng.True, nil
}

type And struct {
	lhs Evaluator
	rhs Evaluator
}

func NewLogicalAnd(lhs, rhs Evaluator) *And {
	return &And{lhs, rhs}
}

type Or struct {
	lhs Evaluator
	rhs Evaluator
}

func NewLogicalOr(lhs, rhs Evaluator) *Or {
	return &Or{lhs, rhs}
}

func evalBool(e Evaluator, rec *zng.Record) (zng.Value, error) {
	zv, err := e.Eval(rec)
	if err != nil {
		return zv, err
	}
	if zv.Type != zng.TypeBool {
		err = ErrIncompatibleTypes
	}
	return zv, err
}

func (a *And) Eval(rec *zng.Record) (zng.Value, error) {
	lhs, err := evalBool(a.lhs, rec)
	if err != nil {
		return lhs, err
	}
	if !zng.IsTrue(lhs.Bytes) {
		return zng.False, nil
	}
	rhs, err := evalBool(a.rhs, rec)
	if err != nil {
		return lhs, err
	}
	if !zng.IsTrue(rhs.Bytes) {
		return zng.False, nil
	}
	return zng.True, nil
}

func (o *Or) Eval(rec *zng.Record) (zng.Value, error) {
	lhs, err := evalBool(o.lhs, rec)
	if err != nil {
		return lhs, err
	}
	if zng.IsTrue(lhs.Bytes) {
		return zng.True, nil
	}
	rhs, err := evalBool(o.rhs, rec)
	if err != nil {
		return lhs, err
	}
	if zng.IsTrue(rhs.Bytes) {
		return zng.True, nil
	}
	return zng.False, nil
}

type In struct {
	elem      Evaluator
	container Evaluator
	vals      coerce.Pair
}

func NewIn(elem, container Evaluator) *In {
	return &In{
		elem:      elem,
		container: container,
	}
}

func (i *In) Eval(rec *zng.Record) (zng.Value, error) {
	elem, err := i.elem.Eval(rec)
	if err != nil {
		return elem, err
	}
	container, err := i.container.Eval(rec)
	if err != nil {
		return container, err
	}
	if typ := zng.AliasedType(container.Type); typ == zng.TypeNet {
		n, err := zng.DecodeNet(container.Bytes)
		if err != nil {
			return zng.Value{}, err
		}
		if typ := zng.AliasedType(elem.Type); typ != zng.TypeIP {
			return zng.Value{}, ErrIncompatibleTypes
		}
		a, err := zng.DecodeIP(elem.Bytes)
		if err != nil {
			return zng.Value{}, err
		}
		if n.IP.Equal(a.Mask(n.Mask)) {
			return zng.True, nil
		}
		return zng.False, nil
	}
	typ := zng.InnerType(container.Type)
	if typ == nil {
		return zng.Value{}, ErrNotContainer
	}
	iter := container.Bytes.Iter()
	for {
		if iter.Done() {
			return zng.False, nil
		}
		zv, _, err := iter.Next()
		if err != nil {
			return zng.Value{}, err
		}
		_, err = i.vals.Coerce(elem, zng.Value{typ, zv})
		if err != nil {
			return zng.Value{}, err
		}
		if i.vals.Equal() {
			return zng.True, nil
		}
	}
}

type Equal struct {
	numeric
	equality bool
}

func NewCompareEquality(lhs, rhs Evaluator, operator string) (*Equal, error) {
	e := &Equal{numeric: newNumeric(lhs, rhs)} //XXX
	switch operator {
	case "=":
		e.equality = true
	case "!=":
	default:
		return nil, fmt.Errorf("unknown equality operator: %s", operator)
	}
	return e, nil
}

func (e *Equal) Eval(rec *zng.Record) (zng.Value, error) {
	_, err := e.numeric.eval(rec)
	if err != nil {
		if err == coerce.ErrOverflow {
			// If there was overflow converting one to the other,
			// we know they can't be equal.
			if e.equality {
				return zng.False, nil
			}
			return zng.True, nil
		}
		return zng.Value{}, err
	}
	result := e.vals.Equal()
	if !e.equality {
		result = !result
	}
	if result {
		return zng.True, nil
	}
	return zng.False, nil
}

type Match struct {
	equality bool
	lhs      Evaluator
	rhs      Evaluator
}

func NewPatternMatch(lhs, rhs Evaluator, op string) (*Match, error) {
	equality := true
	if op == "!~" {
		equality = false
	}
	return &Match{
		equality: equality,
		lhs:      lhs,
		rhs:      rhs,
	}, nil
}

func (m *Match) Eval(rec *zng.Record) (zng.Value, error) {
	lhs, err := m.lhs.Eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	rhs, err := m.rhs.Eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	var result bool
	rid := rhs.Type.ID()
	lid := lhs.Type.ID()
	if zng.IsStringy(rid) {
		if !zng.IsStringy(lid) {
			return zng.Value{}, ErrIncompatibleTypes
		}
		pattern := reglob.Reglob(string(rhs.Bytes))
		result, err = regexp.MatchString(pattern, string(lhs.Bytes))
		if err != nil {
			return zng.Value{}, fmt.Errorf("error comparing pattern: %w", err)
		}
	} else if rid == zng.IdNet && lid == zng.IdIP {
		addr, _ := zng.DecodeIP(lhs.Bytes)
		net, _ := zng.DecodeNet(rhs.Bytes)
		result = net.IP.Equal(addr.Mask(net.Mask))
	} else {
		return zng.Value{}, ErrIncompatibleTypes
	}
	if !m.equality {
		result = !result
	}
	if result {
		return zng.True, nil
	}
	return zng.False, nil
}

type numeric struct {
	zctx *resolver.Context
	lhs  Evaluator
	rhs  Evaluator
	vals coerce.Pair
}

func newNumeric(lhs, rhs Evaluator) numeric {
	return numeric{
		lhs: lhs,
		rhs: rhs,
	}
}

func enumify(v zng.Value) (zng.Value, error) {
	// automatically convert an enum to its value when coercing
	if typ, ok := v.Type.(*zng.TypeEnum); ok {
		selector, err := zng.DecodeUint(v.Bytes)
		if err != nil {
			return zng.Value{}, err
		}
		elem, err := typ.Element(int(selector))
		if err != nil {
			return zng.Value{}, err
		}
		return zng.Value{typ.Type, elem.Value}, nil
	}
	return v, nil
}

func (n *numeric) eval(rec *zng.Record) (int, error) {
	lhs, err := n.lhs.Eval(rec)
	if err != nil {
		return 0, err
	}
	lhs, err = enumify(lhs)
	if err != nil {
		return 0, err
	}
	rhs, err := n.rhs.Eval(rec)
	if err != nil {
		return 0, err
	}
	rhs, err = enumify(rhs)
	if err != nil {
		return 0, err
	}
	return n.vals.Coerce(lhs, rhs)
}

type Compare struct {
	numeric
	convert func(int) bool
}

func NewCompareRelative(lhs, rhs Evaluator, operator string) (*Compare, error) {
	c := &Compare{numeric: newNumeric(lhs, rhs)}
	switch operator {
	case "<":
		c.convert = func(v int) bool { return v < 0 }
	case "<=":
		c.convert = func(v int) bool { return v <= 0 }
	case ">":
		c.convert = func(v int) bool { return v > 0 }
	case ">=":
		c.convert = func(v int) bool { return v >= 0 }
	default:
		return nil, fmt.Errorf("unknown comparison operator: %s", operator)
	}
	return c, nil
}

func (c *Compare) result(result int) zng.Value {
	if c.convert(result) {
		return zng.True
	}
	return zng.False
}

func (c *Compare) Eval(rec *zng.Record) (zng.Value, error) {
	lhs, err := c.lhs.Eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	rhs, err := c.rhs.Eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	id, err := c.vals.Coerce(lhs, rhs)
	if err != nil {
		// If coercion fails due to overflow, then we know there is a
		// mixed signed and unsigned situation and either the unsigned
		// value couldn't be converted to an int64 because it was too big,
		// or the signed value couldn't be converted to a uint64 because
		// it was negative.  In either case, the unsigned value is bigger
		// than the signed value.
		if err == coerce.ErrOverflow {
			result := 1
			if zng.IsSigned(lhs.Type.ID()) {
				result = -1
			}
			return c.result(result), nil
		}
		return zng.False, err
	}
	var result int
	if !c.vals.Equal() {
		switch {
		case zng.IsFloat(id):
			v1, _ := zng.DecodeFloat64(c.vals.A)
			v2, _ := zng.DecodeFloat64(c.vals.B)
			if v1 < v2 {
				result = -1
			} else {
				result = 1
			}
		case zng.IsSigned(id):
			v1, _ := zng.DecodeInt(c.vals.A)
			v2, _ := zng.DecodeInt(c.vals.B)
			if v1 < v2 {
				result = -1
			} else {
				result = 1
			}
		case zng.IsNumber(id):
			v1, _ := zng.DecodeUint(c.vals.A)
			v2, _ := zng.DecodeUint(c.vals.B)
			if v1 < v2 {
				result = -1
			} else {
				result = 1
			}
		case zng.IsStringy(id):
			v1, _ := zng.DecodeString(c.vals.A)
			v2, _ := zng.DecodeString(c.vals.B)
			if v1 < v2 {
				result = -1
			} else {
				result = 1
			}
		default:
			return zng.Value{}, fmt.Errorf("bad comparison type ID: %d", id)
		}
	}
	if c.convert(result) {
		return zng.True, nil
	}
	return zng.False, nil
}

type Add struct {
	numeric
}

type Subtract struct {
	numeric
}

type Multiply struct {
	numeric
}

type Divide struct {
	numeric
}

// NewArithmetic compiles an expression of the form "expr1 op expr2"
// for the arithmetic operators +, -, *, /
func NewArithmetic(lhs, rhs Evaluator, op string) (Evaluator, error) {
	n := newNumeric(lhs, rhs)
	switch op {
	case "+":
		return &Add{n}, nil
	case "-":
		return &Subtract{n}, nil
	case "*":
		return &Multiply{n}, nil
	case "/":
		return &Divide{n}, nil
	}
	return nil, fmt.Errorf("unknown arithmetic operator: %s", op)
}

func (a *Add) Eval(rec *zng.Record) (zng.Value, error) {
	id, err := a.eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	typ := zng.LookupPrimitiveById(id)
	switch {
	case zng.IsFloat(id):
		v1, _ := zng.DecodeFloat64(a.vals.A)
		v2, _ := zng.DecodeFloat64(a.vals.B)
		return zng.Value{typ, a.vals.Float64(v1 + v2)}, nil
	case zng.IsSigned(id):
		v1, _ := zng.DecodeInt(a.vals.A)
		v2, _ := zng.DecodeInt(a.vals.B)
		return zng.Value{typ, a.vals.Int(v1 + v2)}, nil
	case zng.IsNumber(id):
		v1, _ := zng.DecodeUint(a.vals.A)
		v2, _ := zng.DecodeUint(a.vals.B)
		return zng.Value{typ, a.vals.Uint(v1 + v2)}, nil
	case zng.IsStringy(id):
		v1, _ := zng.DecodeString(a.vals.A)
		v2, _ := zng.DecodeString(a.vals.B)
		// XXX GC
		return zng.Value{typ, zng.EncodeString(v1 + v2)}, nil
	}
	return zng.Value{}, ErrIncompatibleTypes
}

func (s *Subtract) Eval(rec *zng.Record) (zng.Value, error) {
	id, err := s.eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	typ := zng.LookupPrimitiveById(id)
	switch {
	case zng.IsFloat(id):
		v1, _ := zng.DecodeFloat64(s.vals.A)
		v2, _ := zng.DecodeFloat64(s.vals.B)
		return zng.Value{typ, s.vals.Float64(v1 - v2)}, nil
	case zng.IsSigned(id):
		v1, _ := zng.DecodeInt(s.vals.A)
		v2, _ := zng.DecodeInt(s.vals.B)
		return zng.Value{typ, s.vals.Int(v1 - v2)}, nil
	case zng.IsNumber(id):
		v1, _ := zng.DecodeUint(s.vals.A)
		v2, _ := zng.DecodeUint(s.vals.B)
		return zng.Value{typ, s.vals.Uint(v1 - v2)}, nil
	}
	return zng.Value{}, ErrIncompatibleTypes
}

func (m *Multiply) Eval(rec *zng.Record) (zng.Value, error) {
	id, err := m.eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	typ := zng.LookupPrimitiveById(id)
	switch {
	case zng.IsFloat(id):
		v1, _ := zng.DecodeFloat64(m.vals.A)
		v2, _ := zng.DecodeFloat64(m.vals.B)
		return zng.Value{typ, m.vals.Float64(v1 * v2)}, nil
	case zng.IsSigned(id):
		v1, _ := zng.DecodeInt(m.vals.A)
		v2, _ := zng.DecodeInt(m.vals.B)
		return zng.Value{typ, m.vals.Int(v1 * v2)}, nil
	case zng.IsNumber(id):
		v1, _ := zng.DecodeUint(m.vals.A)
		v2, _ := zng.DecodeUint(m.vals.B)
		return zng.Value{typ, m.vals.Uint(v1 * v2)}, nil
	}
	return zng.Value{}, ErrIncompatibleTypes
}

func (d *Divide) Eval(rec *zng.Record) (zng.Value, error) {
	id, err := d.eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	typ := zng.LookupPrimitiveById(id)
	switch {
	case zng.IsFloat(id):
		v1, _ := zng.DecodeFloat64(d.vals.A)
		v2, _ := zng.DecodeFloat64(d.vals.B)
		if v2 == 0 {
			return zng.NewErrorf("floating point divide by 0"), nil
		}
		return zng.Value{typ, d.vals.Float64(v1 / v2)}, nil
	case zng.IsSigned(id):
		v1, _ := zng.DecodeInt(d.vals.A)
		v2, _ := zng.DecodeInt(d.vals.B)
		if v2 == 0 {
			return zng.NewErrorf("signed integer divide by 0"), nil
		}
		return zng.Value{typ, d.vals.Int(v1 / v2)}, nil
	case zng.IsNumber(id):
		v1, _ := zng.DecodeUint(d.vals.A)
		v2, _ := zng.DecodeUint(d.vals.B)
		if v2 == 0 {
			return zng.NewErrorf("unsigned integer divide by 0"), nil
		}
		return zng.Value{typ, d.vals.Uint(v1 / v2)}, nil
	}
	return zng.Value{}, ErrIncompatibleTypes
}

func getNthFromContainer(container zcode.Bytes, idx uint) (zcode.Bytes, error) {
	iter := container.Iter()
	var i uint = 0
	for ; !iter.Done(); i++ {
		zv, _, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if i == idx {
			return zv, nil
		}
	}
	return nil, ErrIndexOutOfBounds
}

func lookupKey(mapBytes, target zcode.Bytes) (zcode.Bytes, bool) {
	iter := mapBytes.Iter()
	for !iter.Done() {
		key, _, err := iter.Next()
		if err != nil {
			return nil, false
		}
		val, _, err := iter.Next()
		if err != nil {
			return nil, false
		}
		if bytes.Compare(key, target) == 0 {
			return val, true
		}
	}
	return nil, false
}

// Index represents an index operator "container[index]" where container is
// either an array (with index type integer) or a record (with index type string).
type Index struct {
	zctx      *resolver.Context
	container Evaluator
	index     Evaluator
}

func NewIndexExpr(zctx *resolver.Context, container, index Evaluator) (Evaluator, error) {
	return &Index{zctx, container, index}, nil
}

func (i *Index) Eval(rec *zng.Record) (zng.Value, error) {
	container, err := i.container.Eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	index, err := i.index.Eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	switch typ := container.Type.(type) {
	case *zng.TypeArray:
		return indexArray(typ, container.Bytes, index)
	case *zng.TypeRecord:
		return indexRecord(typ, container.Bytes, index)
	case *zng.TypeMap:
		return indexMap(typ, container.Bytes, index)
	default:
		return zng.Value{}, fmt.Errorf("cannot index type \"%s\" with key \"%s\"", typ, index)
	}
}

func indexArray(typ *zng.TypeArray, array zcode.Bytes, index zng.Value) (zng.Value, error) {
	id := index.Type.ID()
	if !zng.IsInteger(id) {
		return zng.NewErrorf("array index is not an integer"), nil
	}
	var idx uint
	if zng.IsSigned(id) {
		v, _ := zng.DecodeInt(index.Bytes)
		if idx < 0 {
			return zng.NewErrorf("array index out of bounds"), nil
		}
		idx = uint(v)
	} else {
		v, _ := zng.DecodeUint(index.Bytes)
		idx = uint(v)
	}
	zv, err := getNthFromContainer(array, idx)
	if err != nil {
		return zng.Value{}, err
	}
	return zng.Value{typ.Type, zv}, nil
}

func indexRecord(typ *zng.TypeRecord, record zcode.Bytes, index zng.Value) (zng.Value, error) {
	id := index.Type.ID()
	if !zng.IsStringy(id) {
		return zng.NewErrorf("record index is not a string"), nil
	}
	field, _ := zng.DecodeString(index.Bytes)
	result, err := zng.NewRecord(typ, record).ValueByField(string(field))
	if err != nil {
		return zng.NewError(err), nil
	}
	return result, nil
}

func indexMap(typ *zng.TypeMap, mapBytes zcode.Bytes, key zng.Value) (zng.Value, error) {
	if key.Type != typ.KeyType {
		//XXX should try coercing?
		return zng.NewErrorf("map key type does not match index type"), nil
	}
	if valBytes, ok := lookupKey(mapBytes, key.Bytes); ok {
		return zng.Value{typ.ValType, valBytes}, nil
	}
	return zng.NewErrorf("key not found in map: %s", key), nil
}

type Conditional struct {
	predicate Evaluator
	thenExpr  Evaluator
	elseExpr  Evaluator
}

func NewConditional(predicate, thenExpr, elseExpr Evaluator) *Conditional {
	return &Conditional{
		predicate: predicate,
		thenExpr:  thenExpr,
		elseExpr:  elseExpr,
	}
}

func (c *Conditional) Eval(rec *zng.Record) (zng.Value, error) {
	val, err := c.predicate.Eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	if val.Type.ID() != zng.IdBool {
		return zng.Value{}, ErrIncompatibleTypes
	}
	if zng.IsTrue(val.Bytes) {
		return c.thenExpr.Eval(rec)
	}
	return c.elseExpr.Eval(rec)
}

type Call struct {
	zctx    *resolver.Context
	fn      function.Interface
	exprs   []Evaluator
	args    []zng.Value
	AddRoot bool
}

func NewCall(zctx *resolver.Context, fn function.Interface, exprs []Evaluator) *Call {
	return &Call{
		zctx:  zctx,
		fn:    fn,
		exprs: exprs,
		args:  make([]zng.Value, len(exprs)),
	}
}

func (c *Call) Eval(rec *zng.Record) (zng.Value, error) {
	for k, e := range c.exprs {
		val, err := e.Eval(rec)
		if err != nil {
			return zng.Value{}, err
		}
		c.args[k] = val
	}
	return c.fn.Call(c.args)
}

// A TyepFunc returns a type value of the named type (where the name is
// a Z typedef).  It returns MISSING if the name doesn't exist.
type TypeFunc struct {
	name string
	zctx *resolver.Context
	zv   zng.Value
}

func NewTypeFunc(zctx *resolver.Context, name string) *TypeFunc {
	return &TypeFunc{
		name: name,
		zctx: zctx,
	}
}

func (t *TypeFunc) Eval(rec *zng.Record) (zng.Value, error) {
	if t.zv.Bytes == nil {
		typ := t.zctx.LookupTypeDef(t.name)
		if typ == nil {
			return zng.Missing, nil
		}
		t.zv = zng.NewTypeType(typ)
	}
	return t.zv, nil
}

type Exists struct {
	zctx  *resolver.Context
	exprs []Evaluator
}

func NewExists(zctx *resolver.Context, exprs []Evaluator) *Exists {
	return &Exists{
		zctx:  zctx,
		exprs: exprs,
	}
}

func (e *Exists) Eval(rec *zng.Record) (zng.Value, error) {
	for _, expr := range e.exprs {
		zv, err := expr.Eval(rec)
		if err != nil || zv.Type == zng.TypeError {
			return zng.False, nil
		}
	}
	return zng.True, nil
}

func NewCast(expr Evaluator, typ zng.Type) (Evaluator, error) {
	// XXX should handle alias casts... need type context.
	// compile is going to need a local type context to create literals
	// of complex types?
	c := LookupPrimitiveCaster(typ)
	if c == nil {
		// XXX See issue #1572.   To implement aliascast here.
		return nil, fmt.Errorf("cast to '%s' not implemented", typ.ZSON())
	}
	return &evalCast{expr, c, typ}, nil
}

type evalCast struct {
	expr   Evaluator
	caster PrimitiveCaster
	typ    zng.Type
}

func (c *evalCast) Eval(rec *zng.Record) (zng.Value, error) {
	zv, err := c.expr.Eval(rec)
	if err != nil {
		return zng.Value{}, err
	}
	if zv.Bytes == nil {
		// Take care of null here so the casters don't have to
		// worry about it.  Any value can be null after all.
		return zng.Value{c.typ, nil}, nil
	}
	return c.caster(zv)
}

func NewRootField(name string) Evaluator {
	return NewDotExpr(field.New(name))
}

type Assignment struct {
	LHS field.Static
	RHS Evaluator
}
