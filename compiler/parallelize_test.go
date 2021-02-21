package compiler

import (
	"testing"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/compiler/semantic"
	"github.com/brimsec/zq/field"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fields(flds ...string) []ast.Expression {
	var out []ast.Expression
	for _, f := range flds {
		e := ast.NewDotExpr(field.New(f))
		out = append(out, e)
	}
	return out
}

func sf(f string) field.Static {
	if f == "" {
		return nil
	}
	return field.Dotted(f)
}

func TestParallelizeFlowgraph(t *testing.T) {
	tests := []struct {
		zql                     string
		orderField              string
		expected                string
		expectedMergeOrderField string
	}{
		{
			"* | uniq",
			"ts",
			"split (=>filter * =>filter *) | uniq",
			"ts",
		},
		{
			"* | cut ts, foo=x | uniq",
			"ts",
			"split (=>filter * | cut ts, foo=x =>filter * | cut ts, foo=x) | uniq",
			"ts",
		},
		{
			"* | drop x | uniq",
			"ts",
			"split (=> filter * | drop x =>filter * | drop x) | uniq",
			"ts",
		},
		{
			"* | put ts=foo | rename foo=boo",
			"ts",
			"split (=>filter * =>filter *) | put ts=foo | rename foo=boo",
			"ts",
		},
		{
			"* | put ts=foo | rename foo=boo | count()",
			"ts",
			"split (=>filter * | put ts=foo | rename foo=boo | count() =>filter * | put ts=foo | rename foo=boo | count()) | count()",
			"",
		},
		{
			"* | put ts=foo | rename foo=boo | sort",
			"ts",
			"split (=>filter * | put ts=foo | rename foo=boo =>filter * | put ts=foo | rename foo=boo) | sort",
			"",
		},
		{
			"* | put x=foo | rename foo=boo | uniq",
			"ts",
			"split (=>filter * | put x=foo | rename foo=boo =>filter * | put x=foo | rename foo=boo) | uniq",
			"ts",
		},
		{
			"* | sort x | uniq",
			"ts",
			"split (=>filter * | sort x =>filter * | sort x) | uniq",
			"x",
		},
		{
			"* | sort | uniq",
			"ts",
			"split (=>filter * =>filter *) | sort | uniq",
			"",
		},
		{
			"* | put x=y | countdistinct(x) by y | uniq",
			"ts",
			"split (=>filter * | put x=y | countdistinct(x) by y  =>filter * | put x=y | countdistinct(x) by y) | countdistinct(x) by y | uniq",
			"",
		},
		{
			"* | count() by y",
			"ts",
			"split (=>filter * | count() by y =>filter * | count() by y) | count() by y",
			"",
		},
		{
			"* | every 1h count() by y",
			"",
			"split (=>filter * | every 1h count() by y =>filter * | every 1h count() by y) | every 1h count() by y",
			"ts",
		},
		{
			"* | put a=1 | tail",
			"ts",
			"split (=>filter * | put a=1 | tail =>filter * | put a=1 | tail) | tail",
			"ts",
		},
	}
	for _, tc := range tests {
		t.Run(tc.zql, func(t *testing.T) {
			query, err := ParseProc(tc.zql)
			require.NoError(t, err)

			ok := semantic.IsParallelizable(query.(*ast.SequentialProc), sf(tc.orderField), false)
			require.Equal(t, ok, tc.zql != tc.expected)

			seq, err := semantic.Transform(query.(*ast.SequentialProc))
			require.NoError(t, err)
			parallelized, ok := semantic.Parallelize(seq, 2, sf(tc.orderField), false)
			require.Equal(t, ok, tc.zql != tc.expected)

			expectedProc, err := ParseProc(tc.expected)
			require.NoError(t, err)
			expected, err := semantic.Transform(expectedProc)
			require.NoError(t, err)

			// If the parallelized flowgraph includes a groupby, then adjust the expected AST by setting
			// the EmitPart flag on the parallelized groupbys and the ConsumePart flag on the post-merge groupby.
			branch := expected.(*ast.SequentialProc).Procs[0].(*ast.ParallelProc).Procs[0].(*ast.SequentialProc)
			if _, ok := branch.Procs[len(branch.Procs)-1].(*ast.GroupByProc); ok {
				for _, b := range expected.(*ast.SequentialProc).Procs[0].(*ast.ParallelProc).Procs {
					seq := b.(*ast.SequentialProc)
					seq.Procs[len(seq.Procs)-1].(*ast.GroupByProc).EmitPart = true
				}
				g := expected.(*ast.SequentialProc).Procs[1].(*ast.GroupByProc)
				g.ConsumePart = true
			}
			if tc.zql != tc.expected {
				expected.(*ast.SequentialProc).Procs[0].(*ast.ParallelProc).MergeOrderField = sf(tc.expectedMergeOrderField)
			}
			assert.Equal(t, expected.(*ast.SequentialProc), parallelized)
		})
	}
	// This needs a standalone test due to the presence of a pass
	// proc in the transformed AST.
	t.Run("* | cut ts, y, z | put x=y | rename y=z", func(t *testing.T) {
		orderField := "ts"
		query := "* | cut ts, y, z | put x=y | rename y=z"
		dquery := "split (=>filter * | cut ts, y, z | put x=y | rename y=z =>filter * | cut ts, y, z | put x=y | rename y=z)"
		program, err := ParseProc(query)
		require.NoError(t, err)
		parallelized, ok := semantic.Parallelize(program.(*ast.SequentialProc), 2, sf(orderField), false)
		require.True(t, ok)

		expected, err := ParseProc(dquery)
		require.NoError(t, err)

		// We can't express a pass proc in zql, so add it to the AST this way.
		// (It's added by the parallelized flowgraph in order to force a merge rather than having trailing leaves connected to a mux output).
		expected.(*ast.SequentialProc).Procs = append(expected.(*ast.SequentialProc).Procs, &ast.PassProc{Op: "PassProc"})
		expected.(*ast.SequentialProc).Procs[0].(*ast.ParallelProc).MergeOrderField = sf(orderField)

		assert.Equal(t, expected.(*ast.SequentialProc), parallelized)
	})
}

func TestSetGroupByProcInputSortDir(t *testing.T) {
	tests := []struct {
		zql            string
		inputSortField string
		groupbySortDir int
		outputSorted   bool
	}{
		{
			"* | every 1h count()",
			"ts",
			1,
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.zql, func(t *testing.T) {
			query, err := ParseProc(tc.zql)
			require.NoError(t, err)
			semantic.Transform(query)
			outputSorted := semantic.SetGroupByProcInputSortDir(query, sf(tc.inputSortField), 1)
			require.Equal(t, tc.outputSorted, outputSorted)

			var found bool
			for _, b := range query.(*ast.SequentialProc).Procs {
				if gbp, ok := b.(*ast.GroupByProc); ok {
					require.Equal(t, tc.groupbySortDir, gbp.InputSortDir)
					found = true
					break
				}
			}
			require.True(t, found)
		})
	}
}
