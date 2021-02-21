package ast

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/brimsec/zq/pkg/joe"
	"github.com/mitchellh/mapstructure"
)

type Unpacker interface {
	Unpack(string, joe.Interface) (Proc, error)
}

func unpackProcs(custom Unpacker, node joe.Interface) ([]Proc, error) {
	if node == nil {
		return nil, errors.New("ast.unpackProcs: procs field is missing")
	}
	procList, err := node.Get("procs")
	if err != nil {
		return nil, fmt.Errorf("ast.unpackProcs: procs field is missing")
	}
	a, ok := procList.(joe.Array)
	if !ok {
		return nil, fmt.Errorf("ast.unpackProcs: procs field is not an array")
	}
	procs := make([]Proc, 0, len(a))
	for _, item := range a {
		proc, err := unpackProc(custom, item)
		if err != nil {
			return nil, err
		}
		procs = append(procs, proc)
	}
	return procs, nil
}

func unpackCases(custom Unpacker, node joe.Interface) ([]SwitchCase, error) {
	if node == nil {
		return nil, errors.New("ast.unpackCases: cases field is missing")
	}
	caseList, err := node.Get("cases")
	if err != nil {
		return nil, fmt.Errorf("ast.unpackCases: cases field is missing")
	}
	a, ok := caseList.(joe.Array)
	if !ok {
		return nil, fmt.Errorf("ast.unpackCases: cases field is not an array")
	}
	cases := make([]SwitchCase, 0, len(a))
	for _, item := range a {
		procJ, err := item.Get("proc")
		if err != nil {
			return nil, fmt.Errorf("ast.unpackCases: proc field is missing")
		}
		proc, err := unpackProc(custom, procJ)
		if err != nil {
			return nil, err
		}
		filtJ, err := item.Get("filter")
		if err != nil {
			return nil, fmt.Errorf("ast.unpackCases: filter field is missing")
		}
		filt, err := UnpackExpression(filtJ)
		if err != nil {
			return nil, err
		}
		cases = append(cases, SwitchCase{Filter: filt, Proc: proc})
	}
	return cases, nil
}

func getString(node joe.Interface, field string) (string, error) {
	item, err := node.Get(field)
	if err != nil {
		return "", fmt.Errorf("AST is missing %s field: %s", node, field)
	}
	s, err := item.String()
	if err != nil {
		return "", fmt.Errorf("AST field %s of %s is not a string", field, node)
	}
	return s, nil
}

func unpackProc(custom Unpacker, node joe.Interface) (Proc, error) {
	if node == nil {
		return nil, errors.New("bad AST: missing proc field")
	}
	op, err := getString(node, "op")
	if err != nil {
		return nil, err
	}
	if custom != nil {
		p, err := custom.Unpack(op, node)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
	}

	switch op {
	case "SequentialProc":
		procs, err := unpackProcs(custom, node)
		if err != nil {
			return nil, err
		}
		return &SequentialProc{Procs: procs}, nil
	case "ParallelProc":
		procs, err := unpackProcs(custom, node)
		if err != nil {
			return nil, err
		}
		return &ParallelProc{Procs: procs}, nil
	case "SwitchProc":
		cases, err := unpackCases(custom, node)
		if err != nil {
			return nil, err
		}
		return &SwitchProc{Cases: cases}, nil
	case "SortProc":
		a, _ := node.Get("fields")
		fields, err := unpackExprs(a)
		if err != nil {
			return nil, err
		}
		return &SortProc{Fields: fields}, nil
	case "CutProc":
		a, _ := node.Get("fields")
		fas, err := unpackAssignments(a)
		if err != nil {
			return nil, err
		}
		return &CutProc{Fields: fas}, nil
	case "PickProc":
		a, _ := node.Get("fields")
		fas, err := unpackAssignments(a)
		if err != nil {
			return nil, err
		}
		return &PickProc{Fields: fas}, nil
	case "DropProc":
		a, _ := node.Get("fields")
		fields, err := unpackExprs(a)
		if err != nil {
			return nil, err
		}
		return &DropProc{Fields: fields}, nil
	case "HeadProc":
		return &HeadProc{}, nil
	case "TailProc":
		return &TailProc{}, nil
	case "FilterProc":
		f, err := node.Get("filter")
		if err != nil {
			return nil, errors.New("ast filter proc: missing filter field")
		}
		filter, err := UnpackExpression(f)
		if err != nil {
			return nil, err
		}
		return &FilterProc{Filter: filter}, nil
	case "FunctionCall":
		// A FuncionCall can appear in proc context too.
		args, err := unpackArgs(node)
		if err != nil {
			return nil, err
		}
		return &FunctionCall{Args: args}, nil
	case "PutProc":
		a, _ := node.Get("clauses")
		clauses, err := unpackAssignments(a)
		if err != nil {
			return nil, err
		}
		return &PutProc{Clauses: clauses}, nil
	case "RenameProc":
		a, _ := node.Get("fields")
		fas, err := unpackAssignments(a)
		if err != nil {
			return nil, err
		}
		return &RenameProc{Fields: fas}, nil
	case "FuseProc":
		return &FuseProc{}, nil
	case "UniqProc":
		return &UniqProc{}, nil
	case "GroupByProc":
		a, _ := node.Get("keys")
		keys, err := unpackAssignments(a)
		if err != nil {
			return nil, err
		}
		a, _ = node.Get("reducers")
		reducers, err := unpackAssignments(a)
		if err != nil {
			return nil, err
		}
		return &GroupByProc{Reducers: reducers, Keys: keys}, nil
	case "TopProc":
		a, _ := node.Get("fields")
		fields, err := unpackExprs(a)
		if err != nil {
			return nil, err
		}
		return &TopProc{Fields: fields}, nil
	case "PassProc":
		return &PassProc{}, nil
	case "JoinProc":
		n, _ := node.Get("clauses")
		clauses, err := unpackAssignments(n)
		if err != nil {
			return nil, err
		}
		n, err = node.Get("left_key")
		if err != nil {
			return nil, errors.New("ast join proc: missing left_key field")
		}
		leftKey, err := UnpackExpression(n)
		if err != nil {
			return nil, err
		}
		n, err = node.Get("right_key")
		if err != nil {
			return nil, errors.New("ast join proc: missing right_key field")
		}
		rightKey, err := UnpackExpression(n)
		if err != nil {
			return nil, err
		}
		return &JoinProc{LeftKey: leftKey, RightKey: rightKey, Clauses: clauses}, nil
	case "ConstProc":
		exprField, err := node.Get("expr")
		if err != nil {
			return nil, errors.New("expr field is missing from ast.ConstProc")
		}
		e, err := UnpackExpression(exprField)
		if err != nil {
			return nil, err
		}
		return &ConstProc{Expr: e}, nil
	case "TypeProc":
		t, err := node.Get("type")
		if err != nil {
			return nil, errors.New("type field is missing from ast.TypeProc")
		}
		typ, err := unpackType(t)
		if err != nil {
			return nil, err
		}
		return &TypeProc{Type: typ}, nil
	default:
		return nil, fmt.Errorf("ast.unpackProc: unknown proc op: %s", op)
	}
}

func unpackExprs(node joe.Interface) ([]Expression, error) {
	if node == nil {
		return nil, nil
	}
	a, ok := node.(joe.Array)
	if !ok {
		return nil, errors.New("ast.unpackExprs: fields property should be an array")
	}
	exprs := make([]Expression, 0, len(a))
	for _, item := range a {
		e, err := UnpackExpression(item)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, e)
	}
	return exprs, nil
}

func unpackAssignment(node joe.Interface) (Assignment, error) {
	if node == nil {
		return Assignment{}, errors.New("ast.unpackAssignment: missing assignment field")
	}
	var lhs Expression
	lhsNode, err := node.Get("lhs")
	// LHS is optional as compiler will infer a field name from the LHS.
	if err == nil && lhsNode != nil {
		lhs, err = UnpackExpression(lhsNode)
		if err != nil {
			return Assignment{}, err
		}
	}
	rhsNode, err := node.Get("rhs")
	if err != nil {
		return Assignment{}, errors.New("ast.unpackAssignment: missing rhs field")
	}
	rhs, err := UnpackExpression(rhsNode)
	if err != nil {
		return Assignment{}, err
	}
	return Assignment{LHS: lhs, RHS: rhs}, nil
}

func unpackAssignments(node joe.Interface) ([]Assignment, error) {
	if node == nil {
		return nil, nil
	}
	a, ok := node.(joe.Array)
	if !ok {
		return nil, errors.New("ast.unpackAssignments: not an array")
	}
	fas := make([]Assignment, 0, len(a))
	for _, item := range a {
		fa, err := unpackAssignment(item)
		if err != nil {
			return nil, err
		}
		fas = append(fas, fa)
	}
	return fas, nil
}

func UnpackExpression(node joe.Interface) (Expression, error) {
	if node == nil {
		return nil, errors.New("ast.UnpackExpression: no expression provided")
	}
	op, err := getString(node, "op")
	if err != nil {
		return nil, err
	}
	switch op {
	case "UnaryExpr":
		return unpackUnaryExpr(node)
	case "BinaryExpr":
		return unpackBinaryExpr(node)
	case "SelectExpr":
		return unpackSelectExpr(node)
	case "Search":
		return &Search{}, nil
	case "ConditionalExpr":
		conditionNode, err := node.Get("condition")
		if err != nil {
			return nil, errors.New("ConditionalExpr missing condition")
		}
		condition, err := UnpackExpression(conditionNode)
		if err != nil {
			return nil, err
		}

		thenNode, err := node.Get("then")
		if err != nil {
			return nil, errors.New("ConditionalExpr missing then")
		}
		thenClause, err := UnpackExpression(thenNode)
		if err != nil {
			return nil, err
		}

		elseNode, err := node.Get("else")
		if err != nil {
			return nil, errors.New("ConditionalExpr missing else")
		}
		elseClause, err := UnpackExpression(elseNode)
		if err != nil {
			return nil, err
		}
		return &ConditionalExpression{
			Condition: condition,
			Then:      thenClause,
			Else:      elseClause,
		}, nil
	case "FunctionCall":
		args, err := unpackArgs(node)
		if err != nil {
			return nil, err
		}
		return &FunctionCall{Args: args}, nil
	case "CastExpr":
		exprNode, err := node.Get("expr")
		if err != nil {
			return nil, errors.New("CastExpr missing expr")
		}
		expr, err := UnpackExpression(exprNode)
		if err != nil {
			return nil, err
		}
		castType, err := node.Get("type")
		if err != nil {
			return nil, errors.New("ast.CastExpression has no field 'type'")
		}
		typ, err := unpackType(castType)
		if err != nil {
			return nil, err
		}
		return &CastExpression{Expr: expr, Type: typ}, nil
	case "Reducer":
		exprNode, _ := node.Get("expr")
		var expr Expression
		if exprNode != nil {
			expr, _ = UnpackExpression(exprNode)
		}
		whereNode, _ := node.Get("where")
		var where Expression
		if whereNode != nil {
			where, _ = UnpackExpression(whereNode)
		}
		return &Reducer{Expr: expr, Where: where}, nil
	case "Literal":
		return &Literal{}, nil
	case "Identifier":
		return &Identifier{}, nil
	case "RootRecord":
		return &RootRecord{}, nil
	case "TypeExpr":
		t, err := node.Get("type")
		if err != nil {
			return nil, errors.New("ast.TypeExpr: no type field")
		}
		typ, err := unpackType(t)
		if err != nil {
			return nil, err
		}
		return &TypeExpr{Type: typ}, nil
	case "Empty":
		return &Empty{}, nil
	default:
		return nil, fmt.Errorf("ast.UnpackExpression: unknown op %s", op)
	}
}

func unpackArgs(node joe.Interface) ([]Expression, error) {
	argsNode, err := node.Get("args")
	if err != nil {
		return nil, errors.New("ast node missing function args field")
	}
	a, ok := argsNode.(joe.Array)
	if !ok {
		return nil, errors.New("function args property must be an array")
	}
	args := make([]Expression, len(a))
	for i := range args {
		var err error
		args[i], err = UnpackExpression(a[i])
		if err != nil {
			return nil, err
		}
	}
	return args, nil
}

func unpackBinaryExpr(node joe.Interface) (*BinaryExpression, error) {
	lhsNode, err := node.Get("lhs")
	if err != nil {
		return nil, errors.New("BinaryExpression missing lhs")
	}
	lhs, err := UnpackExpression(lhsNode)
	if err != nil {
		return nil, err
	}
	rhsNode, err := node.Get("rhs")
	if err != nil {
		return nil, errors.New("BinaryExpression missing rhs")
	}
	rhs, err := UnpackExpression(rhsNode)
	if err != nil {
		return nil, err
	}
	return &BinaryExpression{LHS: lhs, RHS: rhs}, nil
}

func unpackSelectExpr(node joe.Interface) (*SelectExpression, error) {
	selectorsNode, err := node.Get("selectors")
	if err != nil {
		return nil, errors.New("SelectExpression missing selectors field")
	}
	selectors, err := unpackExprs(selectorsNode)
	if err != nil {
		return nil, err
	}
	return &SelectExpression{Selectors: selectors}, nil
}

func unpackUnaryExpr(node joe.Interface) (*UnaryExpression, error) {
	operandNode, err := node.Get("operand")
	if err != nil {
		return nil, errors.New("UnaryExpr missing operand")
	}
	operand, err := UnpackExpression(operandNode)
	if err != nil {
		return nil, err
	}
	return &UnaryExpression{Operand: operand}, nil
}

func unpackType(node joe.Interface) (Type, error) {
	op, err := getString(node, "op")
	if err != nil {
		return nil, err
	}
	switch op {
	case "TypeNull":
		return &TypeNull{}, nil
	case "TypeName":
		return &TypeName{}, nil
	case "TypeDef":
		typeField, err := node.Get("type")
		if err != nil {
			return nil, errors.New("ast.unpackType: TypeDef has no type field")
		}
		typ, err := unpackType(typeField)
		if err != nil {
			return nil, err
		}
		return &TypeDef{Type: typ}, nil
	case "TypePrimitive":
		return &TypePrimitive{}, nil
	case "TypeRecord":
		a, _ := node.Get("fields")
		fields, err := unpackTypeFields(a)
		if err != nil {
			return nil, err
		}
		return &TypeRecord{Fields: fields}, nil
	case "TypeUnion":
		a, _ := node.Get("types")
		types, err := unpackTypes(a)
		if err != nil {
			return nil, err
		}
		return &TypeUnion{Types: types}, nil
	case "TypeArray":
		arrayType, err := node.Get("type")
		if err != nil {
			return nil, errors.New("ast.unpackType: TypeArray has no type field")
		}
		typ, err := unpackType(arrayType)
		if err != nil {
			return nil, err
		}
		return &TypeArray{Type: typ}, nil
	case "TypeSet":
		setType, err := node.Get("type")
		if err != nil {
			return nil, errors.New("ast.unpackType: TypeSet has no type field")
		}
		typ, err := unpackType(setType)
		if err != nil {
			return nil, err
		}
		return &TypeSet{Type: typ}, nil
	case "TypeMap":
		keyTypeField, err := node.Get("key_type")
		if err != nil {
			return nil, errors.New("ast.unpackType: TypeMap has no key_type field")
		}
		keyType, err := unpackType(keyTypeField)
		valTypeField, err := node.Get("val_type")
		if err != nil {
			return nil, errors.New("ast.unpackType: TypeMap has no val_type field")
		}
		valType, err := unpackType(valTypeField)
		if err != nil {
			return nil, err
		}
		return &TypeMap{KeyType: keyType, ValType: valType}, nil
	}
	return nil, fmt.Errorf("ast.unpacketType: unknown op: %s", op)
}

func unpackTypes(node joe.Interface) ([]Type, error) {
	if node == nil {
		return nil, nil
	}
	a, ok := node.(joe.Array)
	if !ok {
		return nil, errors.New("ast.unpackTypes: types property should be an array")
	}
	types := make([]Type, 0, len(a))
	for _, item := range a {
		typ, err := unpackType(item)
		if err != nil {
			return nil, err
		}
		types = append(types, typ)
	}
	return types, nil
}

func unpackTypeFields(node joe.Interface) ([]TypeField, error) {
	if node == nil {
		return nil, nil
	}
	a, ok := node.(joe.Array)
	if !ok {
		return nil, errors.New("ast.unpackTypeFields: fields property should be an array")
	}
	types := make([]TypeField, 0, len(a))
	for _, item := range a {
		fieldType, err := item.Get("type")
		if err != nil {
			return nil, errors.New("ast.unpackTypeFields: no type field")
		}
		typ, err := unpackType(fieldType)
		if err != nil {
			return nil, err
		}
		types = append(types, TypeField{Type: typ})
	}
	return types, nil
}

func UnpackMap(custom Unpacker, m interface{}) (Proc, error) {
	obj := joe.Convert(m)
	proc, err := unpackProc(custom, obj)
	if err != nil {
		return nil, err
	}
	c := &mapstructure.DecoderConfig{
		TagName: "json",
		Result:  proc,
		Squash:  true,
	}
	dec, err := mapstructure.NewDecoder(c)
	if err != nil {
		return nil, err
	}
	return proc, dec.Decode(m)
}

// UnpackJSON transforms a JSON representation of a proc into an ast.Proc.
func UnpackJSON(custom Unpacker, buf []byte) (Proc, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	obj, err := joe.Unmarshal(buf)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, nil
	}
	proc, err := unpackProc(custom, obj)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(buf, proc); err != nil {
		return nil, err
	}
	return proc, nil
}
