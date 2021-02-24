package ast

import (
	"errors"

	"github.com/brimsec/zq/pkg/unpack"
)

var unpacker = unpack.New(
	Array{},
	Assignment{},
	BinaryExpression{},
	CastExpression{},
	CastValue{},
	ConditionalExpression{},
	ConstProc{},
	CutProc{},
	DefValue{},
	DropProc{},
	Enum{},
	FieldPath{},
	FilterProc{},
	FunctionCall{},
	FuseProc{},
	GroupByProc{},
	HeadProc{},
	Identifier{},
	ImpliedValue{},
	JoinProc{},
	Literal{},
	Map{},
	ParallelProc{},
	PassProc{},
	PickProc{},
	Primitive{},
	PutProc{},
	Record{},
	Reducer{},
	Ref{},
	RenameProc{},
	RootRecord{},
	Search{},
	SelectExpression{},
	SeqExpr{},
	SequentialProc{},
	Set{},
	SqlExpression{},
	SqlOrderBy{},
	SortProc{},
	SwitchProc{},
	TailProc{},
	TopProc{},
	TypeArray{},
	TypeDef{},
	TypeEnum{},
	TypeMap{},
	TypeName{},
	TypeNull{},
	TypePrimitive{},
	TypeProc{},
	TypeRecord{},
	TypeSet{},
	TypeUnion{},
	TypeValue{},
	UnaryExpression{},
	UniqProc{},
)

func UnpackJSON(buf []byte) (interface{}, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	return unpacker.UnpackBytes(buf)
}

// UnpackJSONAsProc transforms a JSON representation of a proc into an ast.Proc.
func UnpackJSONAsProc(buf []byte) (Proc, error) {
	result, err := UnpackJSON(buf)
	if result == nil || err != nil {
		return nil, err
	}
	proc, ok := result.(Proc)
	if !ok {
		return nil, errors.New("JSON object is not a proc")
	}
	return proc, nil
}

func UnpackMapAsProc(m interface{}) (Proc, error) {
	object, err := unpacker.UnpackMap(m)
	if object == nil || err != nil {
		return nil, err
	}
	proc, ok := object.(Proc)
	if !ok {
		return nil, errors.New("ast.UnpackMapAsProc: not a proc")
	}
	return proc, nil
}

func UnpackMapAsExpr(m interface{}) (Expression, error) {
	object, err := unpacker.UnpackMap(m)
	if object == nil || err != nil {
		return nil, err
	}
	e, ok := object.(Expression)
	if !ok {
		return nil, errors.New("ast.UnpackMapAsExpr: not an expression")
	}
	return e, nil
}
