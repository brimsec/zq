package proc_test

import (
	"testing"

	"github.com/mccanne/zq/pkg/nano"
	"github.com/mccanne/zq/pkg/zeek"
	"github.com/mccanne/zq/pkg/zson"
	"github.com/mccanne/zq/pkg/zson/resolver"
	"github.com/mccanne/zq/proc"
	"github.com/stretchr/testify/require"
)

func TestTop(t *testing.T) {
	resolver := resolver.NewTable()

	fooDesc := resolver.GetByColumns([]zeek.Column{{"foo", zeek.TypeCount}})
	r0, _ := zson.NewTestRecord(fooDesc, "-")
	r1, _ := zson.NewTestRecord(fooDesc, "1")
	r2, _ := zson.NewTestRecord(fooDesc, "2")
	r3, _ := zson.NewTestRecord(fooDesc, "3")
	r4, _ := zson.NewTestRecord(fooDesc, "4")
	r5, _ := zson.NewTestRecord(fooDesc, "5")
	fooBatch := zson.NewArray([]*zson.Record{r0, r1, r2, r3, r4, r5}, nano.MaxSpan)

	test, err := proc.NewProcTestFromSource("top -limit 3 foo", resolver, []zson.Batch{fooBatch})
	require.NoError(t, err)

	res, err := test.Pull()
	require.NoError(t, err)
	require.NoError(t, test.ExpectEOS())
	require.NoError(t, test.Finish())
	require.Equal(t, 3, res.Length())
	var ints []int64
	for i := 0; i < 3; i++ {
		foo, err := res.Index(i).AccessInt("foo")
		require.NoError(t, err)
		ints = append(ints, foo)
	}
	require.Equal(t, []int64{5, 4, 3}, ints)
}
