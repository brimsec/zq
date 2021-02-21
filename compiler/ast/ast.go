// Package ast declares the types used to represent syntax trees for zql
// queries.
package ast

// This module is derived from the GO ast design pattern
// https://golang.org/pkg/go/ast/
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import (
	"encoding/json"

	"github.com/brimsec/zq/field"
)

// Proc is the interface implemented by all AST processor nodes.
type Proc interface {
	ProcNode()
}

// Identifier refers to a syntax element analogous to a programming language
// identifier.  It is currently used exclusively as the RHS of a BinaryExpr "."
// expression though it may have future uses (e.g., enum names or externally
// referred to data e.g, maps to do external joins).
type Identifier struct {
	Op   string `json:"op"`
	Name string `json:"name"`
}

// RootRecord refers to the outer record being operated upon.  Field accesses
// typically begin with the LHS of a "." expression set to a RootRecord.
type RootRecord struct {
	Op string `json:"op"`
}

type Empty struct {
	Op string `json:"op"`
}

type Expression interface {
	exprNode()
}

// Literal is a string representation of a literal value where the
// type field indicates the underlying data type (of the set of all supported
// zng data types, derived from the zng type system and not to be confused with
// the native Go types) and value is a string representation of that value that
// must conform to the provided type.
type Literal struct {
	Op    string `json:"op"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Search struct {
	Op    string  `json:"op"`
	Text  string  `json:"text"`
	Value Literal `json:"value"`
}

type UnaryExpression struct {
	Op       string     `json:"op"`
	Operator string     `json:"operator"`
	Operand  Expression `json:"operand"`
}

// A BinaryExpression is any expression of the form "operand operator operand"
// including arithmetic (+, -, *, /), logical operators (and, or),
// comparisons (=, !=, <, <=, >, >=), index operatons (on arrays, sets, and records)
// with operator "[" and a dot expression (".") (on records).
type BinaryExpression struct {
	Op       string     `json:"op"`
	Operator string     `json:"operator"`
	LHS      Expression `json:"lhs"`
	RHS      Expression `json:"rhs"`
}

type SelectExpression struct {
	Op        string       `json:"op"`
	Selectors []Expression `json:"selectors"`
}

type ConditionalExpression struct {
	Op        string     `json:"op"`
	Condition Expression `json:"condition"`
	Then      Expression `json:"then"`
	Else      Expression `json:"else"`
}

// A FunctionCall represents different things dependending on its context.
// As a proc, it is either a group-by with no group-by keys and no duration,
// or a filter with a function that is boolean valued.  This is determined
// by the compiler rather than the syntax tree based on the specific functions
// and aggregators that are defined at compile time.  In expression context,
// a function call has the standard semantics where it takes one or more arguments
// and returns a result.
type FunctionCall struct {
	Op       string       `json:"op"`
	Function string       `json:"function"`
	Args     []Expression `json:"args"`
}

type CastExpression struct {
	Op   string     `json:"op"`
	Expr Expression `json:"expr"`
	Type Type       `json:"type"`
}

type TypeExpr struct {
	Op   string `json:"op"`
	Type Type   `json:"type"`
}

func (*UnaryExpression) exprNode()       {}
func (*BinaryExpression) exprNode()      {}
func (*SelectExpression) exprNode()      {}
func (*ConditionalExpression) exprNode() {}
func (*Search) exprNode()                {}
func (*FunctionCall) exprNode()          {}
func (*CastExpression) exprNode()        {}
func (*TypeExpr) exprNode()              {}
func (*Literal) exprNode()               {}
func (*Identifier) exprNode()            {}
func (*RootRecord) exprNode()            {}
func (*Empty) exprNode()                 {}
func (*Assignment) exprNode()            {}
func (*Reducer) exprNode()               {}

// ----------------------------------------------------------------------------
// Procs

// A proc is a node in the flowgraph that takes records in, processes them,
// and produces records as output.
//
type (
	// A SequentialProc node represents a set of procs that receive
	// a stream of records from their parent into the first proc
	// and each subsequent proc processes the output records from the
	// previous proc.
	SequentialProc struct {
		Op    string `json:"op"`
		Procs []Proc `json:"procs"`
	}
	// A ParallelProc node represents a set of procs that each get
	// a stream of records from their parent.
	ParallelProc struct {
		Op string `json:"op"`
		// If non-zero, MergeOrderField contains the field name on
		// which the branches of this parallel proc should be
		// merged in the order indicated by MergeOrderReverse.
		MergeOrderField   field.Static `json:"merge_order_field,omitempty"`
		MergeOrderReverse bool         `json:"merge_order_reverse,omitempty"`
		Procs             []Proc       `json:"procs"`
	}
	// A SwitchProc node represents a set of procs that each get
	// a stream of records from their parent.
	SwitchProc struct {
		Op    string       `json:"op"`
		Cases []SwitchCase `json:"cases"`
		// If non-zero, MergeOrderField contains the field name on
		// which the branches of this parallel proc should be
		// merged in the order indicated by MergeOrderReverse.
		MergeOrderField   field.Static `json:"merge_order_field,omitempty"`
		MergeOrderReverse bool         `json:"merge_order_reverse,omitempty"`
	}
	// A SortProc node represents a proc that sorts records.
	SortProc struct {
		Op         string       `json:"op"`
		Fields     []Expression `json:"fields"`
		SortDir    int          `json:"sortdir"`
		NullsFirst bool         `json:"nullsfirst"`
	}
	// A CutProc node represents a proc that removes fields from each
	// input record where each removed field matches one of the named fields
	// sending each such modified record to its output in the order received.
	CutProc struct {
		Op     string       `json:"op"`
		Fields []Assignment `json:"fields"`
	}
	// A PickProc is like a CutProc but skips records that do not
	// match all of the field expressions.
	PickProc struct {
		Op     string       `json:"op"`
		Fields []Assignment `json:"fields"`
	}
	// A DropProc node represents a proc that removes fields from each
	// input record.
	DropProc struct {
		Op     string       `json:"op"`
		Fields []Expression `json:"fields"`
	}
	// A HeadProc node represents a proc that forwards the indicated number
	// of records then terminates.
	HeadProc struct {
		Op    string `json:"op"`
		Count int    `json:"count"`
	}
	// A TailProc node represents a proc that reads all its records from its
	// input transmits the final number of records indicated by the count.
	TailProc struct {
		Op    string `json:"op"`
		Count int    `json:"count"`
	}
	// A FilterProc node represents a proc that discards all records that do
	// not match the indicfated filter and forwards all that match to its output.
	FilterProc struct {
		Op     string     `json:"op"`
		Filter Expression `json:"filter"`
	}
	// A PassProc node represents a passthrough proc that mirrors
	// incoming Pull()s on its parent and returns the result.
	PassProc struct {
		Op string `json:"op"`
	}
	// A UniqProc node represents a proc that discards any record that matches
	// the previous record transmitted.  The Cflag causes the output records
	// to contain a new field called count that contains the number of matched
	// records in that set, similar to the unix shell command uniq.
	UniqProc struct {
		Op    string `json:"op"`
		Cflag bool   `json:"cflag"`
	}
	// A GroupByProc node represents a proc that consumes all the records
	// in its input, partitions the records into groups based on the values
	// of the fields specified in the keys field (where the first key is the
	// primary grouping key), and applies reducers (if any) to each group. If the
	// Duration field is non-zero, then the groups are further partioned by time
	// into bins of the duration.  In this case, the primary grouping key is ts.
	// The InputSortDir field indicates that input is sorted (with
	// direction indicated by the sign of the field) in the primary
	// grouping key. In this case, the proc outputs the reducer
	// results from each key as they complete so that large inputs
	// are processed and streamed efficiently.
	// The Limit field specifies the number of different groups that can be
	// aggregated over. When absent, the runtime defaults to an
	// appropriate value.
	// If EmitPart is true, the proc will produce decomposed
	// output results, using the reducer.ResultPart()
	// method. Likewise, if ConsumePart is true, the proc will
	// expect decomposed inputs, using the reducer.ResultPart()
	// method. It is an error for either of these flags to be true
	// if any reducer in Reducers is non-decomposable.
	GroupByProc struct {
		Op           string       `json:"op"`
		Duration     Duration     `json:"duration"`
		InputSortDir int          `json:"input_sort_dir,omitempty"`
		Limit        int          `json:"limit"`
		Keys         []Assignment `json:"keys"`
		Reducers     []Assignment `json:"reducers"`
		ConsumePart  bool         `json:"consume_part,omitempty"`
		EmitPart     bool         `json:"emit_part,omitempty"`
	}
	// TopProc is similar to proc.SortProc with a few key differences:
	// - It only sorts in descending order.
	// - It utilizes a MaxHeap, immediately discarding records that are not in
	// the top N of the sort.
	// - It has a hidden option (FlushEvery) to sort and emit on every batch.
	TopProc struct {
		Op     string       `json:"op"`
		Limit  int          `json:"limit"`
		Fields []Expression `json:"fields"`
		Flush  bool         `json:"flush"`
	}

	PutProc struct {
		Op      string       `json:"op"`
		Clauses []Assignment `json:"clauses"`
	}

	// A RenameProc node represents a proc that renames fields.
	RenameProc struct {
		Op     string       `json:"op"`
		Fields []Assignment `json:"fields"`
	}

	// A FuseProc node represents a proc that turns a zng stream into a dataframe.
	FuseProc struct {
		Op string `json:"op"`
	}

	// A JoinProc node represents a proc that joins two zng streams.
	JoinProc struct {
		Op       string       `json:"op"`
		LeftKey  Expression   `json:"left_key"`
		RightKey Expression   `json:"right_key"`
		Clauses  []Assignment `json:"clauses"`
	}

	// XXX This is a quick and dirty way to get constants into Z.  They are
	// smuggled in as fake procs.  When we refactor this AST into a parser AST
	// proper and a separate kernel DSL, we will clean this up.
	ConstProc struct {
		Op   string     `json:"op"`
		Name string     `json:"name"`
		Expr Expression `json:"expr"`
	}

	TypeProc struct {
		Op   string `json:"op"`
		Name string `json:"name"`
		Type Type   `json:"type"`
	}
)

type SwitchCase struct {
	Filter Expression `json:"filter"`
	Proc   Proc       `json:"proc"`
}

type Assignment struct {
	Op  string     `json:"op"`
	LHS Expression `json:"lhs"`
	RHS Expression `json:"rhs"`
}

//XXX TBD: chance to nano.Duration
type Duration struct {
	Seconds int `json:"seconds"`
}

type DurationNode struct {
	Type    string `json:"type"`
	Seconds int    `json:"seconds"`
}

func (d *Duration) MarshalJSON() ([]byte, error) {
	if d.Seconds == 0 {
		return json.Marshal(nil)
	}
	v := DurationNode{"Duration", d.Seconds}
	return json.Marshal(&v)
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v DurationNode
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	d.Seconds = v.Seconds
	return nil
}

func (*SequentialProc) ProcNode() {}
func (*ParallelProc) ProcNode()   {}
func (*SwitchProc) ProcNode()     {}
func (*SortProc) ProcNode()       {}
func (*CutProc) ProcNode()        {}
func (*PickProc) ProcNode()       {}
func (*DropProc) ProcNode()       {}
func (*HeadProc) ProcNode()       {}
func (*TailProc) ProcNode()       {}
func (*PassProc) ProcNode()       {}
func (*FilterProc) ProcNode()     {}
func (*UniqProc) ProcNode()       {}
func (*GroupByProc) ProcNode()    {}
func (*TopProc) ProcNode()        {}
func (*PutProc) ProcNode()        {}
func (*RenameProc) ProcNode()     {}
func (*FuseProc) ProcNode()       {}
func (*JoinProc) ProcNode()       {}
func (*ConstProc) ProcNode()      {}
func (*TypeProc) ProcNode()       {}
func (*FunctionCall) ProcNode()   {}

// A Reducer is an AST node that represents a reducer function.  The Operator
// field indicates the aggregation method while the Expr field indicates
// an expression applied to the incoming records that is operated upon by them
// reducer function.  If Expr isn't present, then the reducer doesn't act upon
// a function of the record, e.g., count() counts up records without looking
// into them.
type Reducer struct {
	Op       string     `json:"op"`
	Operator string     `json:"operator"`
	Expr     Expression `json:"expr"`
	Where    Expression `json:"where"`
}

func DotExprToField(n Expression) (field.Static, bool) {
	switch n := n.(type) {
	case nil:
		return nil, true
	case *BinaryExpression:
		if n.Operator == "." || n.Operator == "[" {
			lhs, ok := DotExprToField(n.LHS)
			if !ok {
				return nil, false
			}
			rhs, ok := DotExprToField(n.RHS)
			if !ok {
				return nil, false
			}
			return append(lhs, rhs...), true
		}
	case *Identifier:
		return field.Static{n.Name}, true
	case *RootRecord, *Empty:
		return nil, true
	}
	return nil, false
}

func FieldsOf(e Expression) []field.Static {
	switch e := e.(type) {
	default:
		f, _ := DotExprToField(e)
		if f == nil {
			return nil
		}
		return []field.Static{f}
	case *BinaryExpression:
		if e.Operator == "." || e.Operator == "[" {
			lhs, _ := DotExprToField(e.LHS)
			rhs, _ := DotExprToField(e.RHS)
			var fields []field.Static
			if lhs != nil {
				fields = append(fields, lhs)
			}
			if rhs != nil {
				fields = append(fields, rhs)
			}
			return fields
		}
		return append(FieldsOf(e.LHS), FieldsOf(e.RHS)...)
	case *Assignment:
		return append(FieldsOf(e.LHS), FieldsOf(e.RHS)...)
	case *SelectExpression:
		var fields []field.Static
		for _, selector := range e.Selectors {
			fields = append(fields, FieldsOf(selector)...)
		}
		return fields
	}
}

func NewDotExpr(f field.Static) Expression {
	lhs := Expression(&RootRecord{Op: "RootRecord"})
	for _, name := range f {
		rhs := &Identifier{
			Op:   "Identifier",
			Name: name,
		}
		lhs = &BinaryExpression{
			Op:       "BinaryExpr",
			Operator: ".",
			LHS:      lhs,
			RHS:      rhs,
		}
	}
	return lhs
}

func NewReducerAssignment(op string, lval field.Static, arg field.Static) Assignment {
	reducer := &Reducer{Op: "Reducer", Operator: op}
	if arg != nil {
		reducer.Expr = NewDotExpr(arg)
	}
	lhs := lval
	if lhs == nil {
		lhs = field.New(op)
	}
	return Assignment{LHS: NewDotExpr(lhs), RHS: reducer}
}

func FanIn(p Proc) int {
	first := p
	if seq, ok := first.(*SequentialProc); ok {
		first = seq.Procs[0]
	}
	if p, ok := first.(*ParallelProc); ok {
		return len(p.Procs)
	}
	if _, ok := first.(*JoinProc); ok {
		return 2
	}
	return 1
}

func FilterToProc(e Expression) *FilterProc {
	return &FilterProc{
		Op:     "FilterProc",
		Filter: e,
	}
}
