package kernel

import "github.com/brimsec/zq/zng"

// A Scope is a stack of bindings that map identifiers to literals,
// generator variables, functions etc.  Currently, we only handle iterators
// but this will change soone as we add support for richer Z script semantics.
type Scope struct {
	stack []Binder
}

func newScope() *Scope {
	return &Scope{}
}

func (s *Scope) tos() Binder {
	return s.stack[len(s.stack)-1]
}

func (s *Scope) Enter() {
	s.stack = append(s.stack, NewBinder())
}

func (s *Scope) Exit() {
	s.stack = s.stack[:len(s.stack)-1]
}

func (s *Scope) Bind(name string, ref *zng.Value) {
	s.tos().Define(name, ref)
}

func (s *Scope) Lookup(name string) *zng.Value {
	for k := len(s.stack) - 1; k >= 0; k-- {
		if ref, ok := s.stack[k][name]; ok {
			return ref
		}
	}
	return nil
}

//XXX for now, Binder is just a map of identifiers to a specific zng.Value
// reference that the name refers to.  This will be generalized later to handle
// all possible types of identifier bindings.
type Binder map[string]*zng.Value

func NewBinder() Binder {
	return make(map[string]*zng.Value)
}

func (b Binder) Define(name string, ref *zng.Value) {
	b[name] = ref
}
