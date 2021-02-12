package compiler

import (
	"errors"
	"fmt"

	"github.com/brimsec/zq/ast"
	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/proc"
	"github.com/brimsec/zq/proc/groupby"
)

func (c *Compiler) compileGroupBy(parent proc.Interface, node *ast.GroupByProc) (*groupby.Proc, error) {
	keys, err := c.compileAssignments(node.Keys)
	if err != nil {
		return nil, err
	}
	names, reducers, err := c.compileAggs(node.Reducers)
	if err != nil {
		return nil, err
	}
	return groupby.New(c.pctx, parent, keys, names, reducers, node.Limit, node.InputSortDir, node.ConsumePart, node.EmitPart)
}

func (c *Compiler) compileAggs(assignments []ast.Assignment) ([]field.Static, []*expr.Aggregator, error) {
	names := make([]field.Static, 0, len(assignments))
	aggs := make([]*expr.Aggregator, 0, len(assignments))
	for _, assignment := range assignments {
		name, agg, err := c.compileAgg(assignment)
		if err != nil {
			return nil, nil, err
		}
		aggs = append(aggs, agg)
		names = append(names, name)
	}
	return names, aggs, nil
}

func (c *Compiler) compileAgg(assignment ast.Assignment) (field.Static, *expr.Aggregator, error) {
	aggAST, ok := assignment.RHS.(*ast.Reducer)
	if !ok {
		return nil, nil, errors.New("aggregator is not an aggregation expression")
	}
	aggOp := aggAST.Operator
	var err error
	var arg expr.Evaluator
	if aggAST.Expr != nil {
		arg, err = c.compileExpr(aggAST.Expr)
		if err != nil {
			return nil, nil, err
		}
	}
	// If there is a reducer assignment, the LHS is non-nil and we
	// compile.  Otherwise, we infer an LHS top-level field name from
	// the name of reducer function.
	var lhs field.Static
	if assignment.LHS == nil {
		lhs = field.New(aggOp)
	} else {
		lhs, err = CompileLval(assignment.LHS)
		if err != nil {
			return nil, nil, fmt.Errorf("lhs of aggregation: %w", err)
		}
	}
	var where expr.Filter
	if aggAST.Where != nil {
		where, err = c.compileFilter(aggAST.Where)
		if err != nil {
			return nil, nil, err
		}
	}
	m, err := expr.NewAggregator(aggOp, arg, where)
	return lhs, m, err
}
