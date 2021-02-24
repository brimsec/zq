package semantic

import (
	"errors"
	"fmt"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/expr/agg"
	"github.com/brimsec/zq/field"
)

// XXX NOTE: kernel.CompileLval should have name changed... and be used
// exclusively here in semantic?

func convertSQLProc(scope *Scope, sql *ast.SqlExpression) (ast.Proc, error) {
	selection, err := newSQLSelection(scope, sql.Select)
	if err != err {
		return nil, err
	}
	var procs []ast.Proc
	if sql.From != nil {
		tableFilter, err := convertSQLTableRef(sql.From.Table)
		if err != nil {
			return nil, err
		}
		procs = append(procs, tableFilter)
		if sql.From.Alias != nil {
			// If there's an alias, we do a 'cut alias=.'
			alias, err := convertSQLAlias(scope, sql.From.Alias)
			if err != nil {
				return nil, err
			}
			procs = append(procs, alias)
		}
	}
	if sql.Joins != nil {
		if len(procs) == 0 {
			//XXX allow self join where we create a null path
			return nil, errors.New("cannot JOIN without a FROM")
		}
		procs, err = convertSQLJoins(scope, procs, sql.Joins)
		if err != nil {
			return nil, err
		}
	}
	if sql.Where != nil {
		filter := &ast.FilterProc{
			Op:     "FilterProc",
			Filter: sql.Where,
		}
		procs = append(procs, filter)
	}
	if sql.GroupBy != nil {
		groupby, err := convertSQLGroupBy(scope, sql.GroupBy, selection)
		if err != nil {
			return nil, err
		}
		procs = append(procs, groupby)
		if sql.Having != nil {
			having, err := semExpr(scope, sql.Having)
			if err != nil {
				return nil, err
			}
			filter := &ast.FilterProc{
				Op:     "FilterProc",
				Filter: having,
			}
			procs = append(procs, filter)
		}
	} else if sql.Select != nil {
		if sql.Having != nil {
			return nil, errors.New("HAVING clause used without GROUP BY")
		}
		// GroupBy will do the cutting but if there's no GroupBy,
		// then we need a cut for the select expressions.
		// For SELECT *, cutter is nil.
		selector, err := convertSQLSelect(selection)
		if err != nil {
			return nil, err
		}
		if selector != nil {
			procs = append(procs, selector)
		}
	}
	if sql.OrderBy != nil {
		direction := 1
		if sql.OrderBy.Direction == "desc" {
			direction = -1
		}
		procs = append(procs, sortByMulti(sql.OrderBy.Keys, direction))
	}
	if sql.Limit != 0 {
		p := &ast.HeadProc{
			Op:    "HeadProc",
			Count: sql.Limit,
		}
		procs = append(procs, p)
	}
	if len(procs) == 0 {
		procs = []ast.Proc{passProc}
	}
	return wrap(procs), nil
}

func convertSQLTableRef(in ast.Expression) (ast.Proc, error) {
	// For now, we special case a string that parses as a ZSON type.
	// If not, we try to compiler this as a filter expression.
	switch e := in.(type) {
	case *ast.Literal:
		if e.Type == "string" {
			in = &ast.BinaryExpression{
				Op:       "BinaryExpr",
				Operator: "=",
				LHS: &ast.FunctionCall{
					Op:       "FunctionCall",
					Function: "typeof",
					Args: []ast.Expression{
						&ast.RootRecord{},
					},
				},
				RHS: e,
			}
		}
	case *ast.Identifier:
		in = &ast.FunctionCall{
			Op:       "FunctionCall",
			Function: "is",
			Args: []ast.Expression{
				&ast.TypeValue{
					Op: "TypeValue",
					Value: &ast.TypeName{
						Op:   "TypeName",
						Name: e.Name,
					},
				},
			},
		}
	}
	return &ast.FilterProc{
		Op:     "FilterProc",
		Filter: in,
	}, nil
}

func convertSQLAlias(scope *Scope, e ast.Expression) (*ast.CutProc, error) {
	if _, err := semField(scope, e); err != nil {
		return nil, fmt.Errorf("illegal alias: %w", err)
	}
	cut := ast.Assignment{
		Op:  "Assignment",
		LHS: e,
		RHS: &ast.RootRecord{},
	}
	return &ast.CutProc{
		Op:     "CutProc",
		Fields: []ast.Assignment{cut},
	}, nil
}

func wrap(procs []ast.Proc) ast.Proc {
	if len(procs) == 0 {
		return nil
	}
	if len(procs) == 1 {
		return procs[0]
	}
	return &ast.SequentialProc{
		Op:    "SequentialProc",
		Procs: procs,
	}
}

func convertSQLJoins(scope *Scope, fromPath []ast.Proc, joins []ast.SqlJoin) ([]ast.Proc, error) {
	left := fromPath
	for _, right := range joins {
		var err error
		left, err = convertSQLJoin(scope, left, right)
		if err != nil {
			return nil, err
		}
	}
	return left, nil
}

// For now, each joining table is on the right...
// We don't have logic to not care about the side of the JOIN ON keys...
func convertSQLJoin(scope *Scope, leftPath []ast.Proc, sqlJoin ast.SqlJoin) ([]ast.Proc, error) {
	if sqlJoin.Alias == nil {
		return nil, errors.New("JOIN currently requires alias, e.g., JOIN <type> <alias> (will be fixed soon)")
	}
	leftPath = append(leftPath, sortBy(sqlJoin.LeftKey))

	joinFilter, err := convertSQLTableRef(sqlJoin.Table)
	if err != nil {
		return nil, err
	}
	rightPath := []ast.Proc{joinFilter}
	cut, err := convertSQLAlias(scope, sqlJoin.Alias)
	if err != nil {
		return nil, errors.New("JOIN alias must be a name")
	}
	rightPath = append(rightPath, cut)
	rightPath = append(rightPath, sortBy(sqlJoin.RightKey))

	fork := &ast.ParallelProc{
		Op:    "ParallelProc",
		Procs: []ast.Proc{wrap(leftPath), wrap(rightPath)},
	}
	alias := ast.Assignment{
		Op:  "Assignment",
		RHS: sqlJoin.Alias,
	}
	join := &ast.JoinProc{
		Op:       "JoinProc",
		Kind:     sqlJoin.Kind,
		LeftKey:  sqlJoin.LeftKey,
		RightKey: sqlJoin.RightKey,
		Clauses:  []ast.Assignment{alias},
	}
	return []ast.Proc{fork, join}, nil
}

func sortBy(e ast.Expression) *ast.SortProc {
	return sortByMulti([]ast.Expression{e}, 1)
}

func sortByMulti(keys []ast.Expression, direction int) *ast.SortProc {
	return &ast.SortProc{
		Op:      "SortProc",
		Fields:  keys,
		SortDir: direction,
	}
}

func convertSQLSelect(selection sqlSelection) (ast.Proc, error) {
	// This is a straight select without a group-by.
	// If all the expressions are aggregators, then we build a group-by.
	// If it's mixed, we return an error.  Otherwise, we do a simple cut.
	var nagg int
	for _, p := range selection {
		if p.agg != nil {
			nagg++
		}
	}
	if nagg == 0 {
		return selection.Cut(), nil
	}
	if nagg != len(selection) {
		return nil, errors.New("cannot mix aggregations and non-aggregations without a group-by")
	}
	// Note here that we reconstruct the group-by aggregators instead of
	// using the assignments in ast.SqlExpression.Select since the SQL peg
	// parser does not know whether they are aggregators or function calls,
	// but the sqlPick elements have this determined.  So we take the LHS
	// from the original expression and mix it with the agg that was put
	// in sqlPick.
	var assignments []ast.Assignment
	for _, p := range selection {
		a := ast.Assignment{
			Op:  "Assignment",
			LHS: p.assignment.LHS,
			RHS: p.agg,
		}
		assignments = append(assignments, a)
	}
	return &ast.GroupByProc{
		Op:       "GroupByProc",
		Reducers: assignments,
	}, nil
}

func convertSQLGroupBy(scope *Scope, groupByKeys []ast.Expression, selection sqlSelection) (ast.Proc, error) {
	var keys []field.Static
	for _, key := range groupByKeys {
		name, err := sqlField(scope, key)
		if err != nil {
			return nil, fmt.Errorf("bad group-by key: %w", err)
		}
		keys = append(keys, name)
	}
	// Make sure all group-by keys are in the selection.
	all := selection.Fields()
	for _, key := range keys {
		//XXX fix this for select *?
		if !key.In(all) {
			if key.HasPrefixIn(all) {
				return nil, fmt.Errorf("'%s': group-by key cannot be a sub-field of the selected value", key)
			}
			return nil, fmt.Errorf("'%s': group-by key not in selection", key)
		}
	}
	// Make sure all scalars are in the group-by keys.
	scalars := selection.Scalars()
	for _, f := range scalars.Fields() {
		if !f.In(keys) {
			return nil, fmt.Errorf("'%s': selected expression is missing from group-by clause (and is not an aggregation)", f)
		}
	}
	// Now that the selection and keys have been checked, build the
	// key expressions from the scalars of the select and build the
	// aggregators (aka reducers) from the aggregation functions present
	// in the select clause.
	var keyExprs []ast.Assignment
	for _, p := range scalars {
		keyExprs = append(keyExprs, p.assignment)
	}
	var aggExprs []ast.Assignment
	for _, p := range selection.Aggs() {
		aggExprs = append(aggExprs, ast.Assignment{
			LHS: p.assignment.LHS,
			RHS: p.agg,
		})
	}
	// XXX how to override limit for spills?
	return &ast.GroupByProc{
		Op:       "GroupByProc",
		Keys:     keyExprs,
		Reducers: aggExprs,
	}, nil
}

// A sqlPick is one column of a select statement.  We bookkeep here whether
// a column is a scalar expression or an aggregation by looking up the function
// name and seeing if it's an aggregator or not.  We also infer the column
// names so we can do SQL error checking relating the selections to the group-by
// keys, something that is not needed in Z.
type sqlPick struct {
	name       field.Static
	agg        *ast.Reducer
	assignment ast.Assignment
}

type sqlSelection []sqlPick

func newSQLSelection(scope *Scope, assignments []ast.Assignment) (sqlSelection, error) {
	// Make a cut from a SQL select.  This should just work
	// without having to track identifier names of columns because
	// the transformations will all relable data from stage to stage
	// and Select names refer to the names at the last stage of
	// the table.
	var s sqlSelection
	for _, a := range assignments {
		name, err := deriveAs(scope, a)
		if err != nil {
			return nil, err
		}
		agg, err := isAgg(a.RHS)
		if err != nil {
			return nil, err
		}
		s = append(s, sqlPick{name, agg, a})
	}
	return s, nil
}

func (s sqlSelection) Fields() []field.Static {
	var fields []field.Static
	for _, p := range s {
		fields = append(fields, p.name)
	}
	return fields
}

func (s sqlSelection) Aggs() sqlSelection {
	var aggs sqlSelection
	for _, p := range s {
		if p.agg != nil {
			aggs = append(aggs, p)
		}
	}
	return aggs
}

func (s sqlSelection) Scalars() sqlSelection {
	var scalars sqlSelection
	for _, p := range s {
		if p.agg == nil {
			scalars = append(scalars, p)
		}
	}
	return scalars
}

func (s sqlSelection) Cut() *ast.CutProc {
	if len(s) == 0 {
		return nil
	}
	var a []ast.Assignment
	for _, p := range s {
		a = append(a, p.assignment)
	}
	return &ast.CutProc{
		Op:     "CutProc",
		Fields: a,
	}
}

func isAgg(e ast.Expression) (*ast.Reducer, error) {
	call, ok := e.(*ast.FunctionCall)
	if !ok {
		return nil, nil
	}
	if _, err := agg.NewPattern(call.Function); err != nil {
		return nil, nil
	}
	var arg ast.Expression
	if len(call.Args) > 1 {
		return nil, fmt.Errorf("%s: wrong number of arguments", call.Function)
	}
	if len(call.Args) == 1 {
		arg = call.Args[0]
	}
	return &ast.Reducer{
		Op:       "Reducer",
		Operator: call.Function,
		Expr:     arg,
	}, nil
}

func deriveAs(scope *Scope, a ast.Assignment) (field.Static, error) {
	sa, err := semAssignment(scope, a)
	if err != nil {
		return nil, fmt.Errorf("AS clause of select: %w", err)
	}
	f, ok := sa.LHS.(*ast.FieldPath)
	if !ok {
		return nil, fmt.Errorf("AS clause not a field: %w", err)
	}
	return f.Name, nil
}

func sqlField(scope *Scope, e ast.Expression) (field.Static, error) {
	name, err := semField(scope, e)
	if err != nil {
		return nil, err
	}
	if f, ok := name.(*ast.FieldPath); ok {
		return f.Name, nil
	}
	return nil, errors.New("expression is not a field reference")
}
