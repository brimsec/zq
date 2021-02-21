package groupby_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/compiler"
	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/compiler/semantic"
	"github.com/brimsec/zq/driver"
	"github.com/brimsec/zq/pkg/test"
	"github.com/brimsec/zq/proc/groupby"
	"github.com/brimsec/zq/proc/proctest"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/detector"
	"github.com/brimsec/zq/zio/tzngio"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Data sets for tests:
const in = `
#0:record[key1:string,key2:string,n:int32]
0:[a;x;1;]
0:[a;y;2;]
0:[b;z;1;]
`

const groupSingleOut = `
#0:record[key1:string,count:uint64]
0:[a;2;]
0:[b;1;]
`

const groupMultiOut = `
#0:record[key1:string,key2:string,count:uint64]
0:[a;x;1;]
0:[a;y;1;]
0:[b;z;1;]
`

const unsetKeyIn = `
#1:record[key1:string,key2:string,n:int32]
1:[-;-;3;]
1:[-;-;4;]
`

const groupSingleOut_unsetOut = `
#0:record[key1:string,count:uint64]
0:[a;2;]
0:[b;1;]
0:[-;2;]
`

const missingField = `
#1:record[key3:string,n:int32]
1:[a;1;]
1:[b;2;]
`

const differentTypeIn = `
#1:record[key1:ip,n:int32]
1:[10.0.0.1;1;]
1:[10.0.0.2;1;]
1:[10.0.0.1;1;]
`

const differentTypeOut = `
#0:record[key1:ip,count:uint64]
0:[10.0.0.1;2;]
0:[10.0.0.2;1;]
#1:record[key1:string,count:uint64]
1:[a;2;]
1:[b;1;]
`

const reducersOut = `
#0:record[key1:string,any:int32,sum:int64,avg:float64,min:int64,max:int64]
0:[a;1;3;1.5;1;2;]
0:[b;1;1;1;1;1;]
`

const arrayKeyIn = `
#0:record[arr:array[int32],val:int32]
0:[-;2;]
0:[[1;2;]2;]
0:[[1;2;]3;]
`

const arrayKeyOut = `
#0:record[arr:array[int32],count:uint64]
0:[-;1;]
0:[[1;2;]2;]
`

const nestedKeyIn = `
#0:record[rec:record[i:int32,s:string],val:int64]
0:[[1;bleah;]1;]
0:[[1;bleah;]2;]
0:[[2;bleah;]3;]
`

const nestedKeyOut = `
#0:record[rec:record[i:int32],count:uint64]
0:[[1;]2;]
0:[[2;]1;]
`
const nestedKeyAssignedOut = `
#0:record[newkey:int32,count:uint64]
0:[1;2;]
0:[2;1;]
`

const unsetIn = `
#0:record[key:string,val:int64]
0:[key1;5;]
0:[key2;-;]
`

const unsetOut = `
#0:record[key:string,sum:int64]
0:[key1;5;]
0:[key2;-;]
`

const notPresentIn = `
#0:record[key:string]
0:[key1;]
`

const notPresentOut = `
#0:record[key:string,max:null]
0:[key1;-;]
`

const mixedIn = `
#0:record[key:string,f:int32]
0:[k;5;]
#1:record[key:string,f:string]
1:[k;bleah;]
`

const mixedOut = `
#0:record[key:string,first:int32,last:string]
0:[k;5;bleah;]
`

const aliasIn = `
#ipaddr=ip
#0:record[host:ipaddr]
0:[127.0.0.1;]
#1:record[host:ip]
1:[127.0.0.2;]
`

const aliasOut = `
#ipaddr=ip
#0:record[host:ipaddr,count:uint64]
0:[127.0.0.1;1;]
#1:record[host:ip,count:uint64]
1:[127.0.0.2;1;]
`

const computedKeyIn = `
#0:record[s:string,i:uint64,j:uint64]
0:[foo;2;2;]
0:[FOO;2;2;]
`
const computedKeyOut = `
#0:record[s:string,ij:uint64,count:uint64]
0:[foo;4;2;]
`

//XXX this should go in a shared package
type suite []test.Internal

func (s suite) runSystem(t *testing.T) {
	for _, d := range s {
		t.Run(d.Name, func(t *testing.T) {
			results, err := d.Run()
			require.NoError(t, err)
			assert.Exactly(t, d.Expected, results, "Wrong query results...\nQuery: %s\nInput: %s\n", d.Query, d.Input)
		})
	}
}

func (s *suite) add(t test.Internal) {
	*s = append(*s, t)
}

func New(name, input, output, cmd string) test.Internal {
	output = strings.ReplaceAll(output, "\n\n", "\n")
	return test.Internal{
		Name:         name,
		Query:        "* | " + cmd,
		Input:        input,
		OutputFormat: "tzng",
		Expected:     test.Trim(output),
	}
}

func tests() suite {
	s := suite{}

	// Test a simple groupby
	s.add(New("simple", in, groupSingleOut, "count() by key1 | sort key1"))
	s.add(New("simple-assign", in, groupSingleOut, "count() by key1=key1 | sort key1"))

	// Test that unset key values work correctly
	s.add(New("unset-keys", in+unsetKeyIn, groupSingleOut_unsetOut, "count() by key1 | sort key1"))
	s.add(New("unset-keys-at-start", unsetKeyIn+in, groupSingleOut_unsetOut, "count() by key1 | sort key1"))

	// Test grouping by multiple fields
	s.add(New("multiple-fields", in, groupMultiOut, "count() by key1,key2 | sort key1, key2"))

	// Test that records missing groupby fields are ignored
	s.add(New("missing-fields", in+missingField, groupSingleOut, "count() by key1 | sort key1"))

	// Test that input with different key types works correctly
	s.add(New("different-key-types", in+differentTypeIn, differentTypeOut, "count() by key1 | sort key1"))

	// Test various reducers
	s.add(New("reducers", in, reducersOut, "any(n), sum(n), avg(n), min(n), max(n) by key1 | sort key1"))

	// Check out of bounds array indexes
	s.add(New("array-out-of-bounds", arrayKeyIn, arrayKeyOut, "count() by arr | sort"))

	// Check groupby key inside a record
	s.add(New("key-in-record", nestedKeyIn, nestedKeyOut, "count() by rec.i | sort rec.i"))

	// Test reducers with unset inputs
	s.add(New("unset-inputs", unsetIn, unsetOut, "sum(val) by key | sort"))

	// Test reducers with missing operands
	s.add(New("not-present", notPresentIn, notPresentOut, "max(val) by key | sort"))

	s.add(New("aliases", aliasIn, aliasOut, "count() by host | sort host"))

	// Tests with assignments and computed keys
	s.add(New("unset-keys-computed", in+unsetKeyIn, groupSingleOut_unsetOut, "count() by key1=to_lower(to_upper(key1)) | sort key1"))
	s.add(New("unset-keys-assign", in+unsetKeyIn, strings.ReplaceAll(groupSingleOut_unsetOut, "key1", "newkey"), "count() by newkey=key1 | sort newkey"))
	s.add(New("unset-keys-at-start-assign", unsetKeyIn+in, strings.ReplaceAll(groupSingleOut_unsetOut, "key1", "newkey"), "count() by newkey=key1 | sort newkey"))
	s.add(New("multiple-fields-assign", in, strings.ReplaceAll(groupMultiOut, "key2", "newkey"), "count() by key1,newkey=key2 | sort key1, newkey"))
	s.add(New("key-in-record-assign", nestedKeyIn, nestedKeyAssignedOut, "count() by newkey=rec.i | sort newkey"))
	s.add(New("computed-key", computedKeyIn, computedKeyOut, "count() by s=to_lower(s), ij=i+j | sort"))
	return s
}

func TestGroupbySystem(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		tests().runSystem(t)
	})
	t.Run("spill", func(t *testing.T) {
		saved := groupby.DefaultLimit
		groupby.DefaultLimit = 1
		defer func() {
			groupby.DefaultLimit = saved
		}()
		tests().runSystem(t)
	})
}

func compileGroupBy(code string) (*ast.GroupByProc, error) {
	parsed, err := compiler.ParseProc(code)
	if err != nil {
		return nil, err
	}
	sp := parsed.(*ast.SequentialProc)
	return sp.Procs[0].(*ast.GroupByProc), nil
}

func TestGroupbyUnit(t *testing.T) {
	inBatches := []string{`
#0:record[ts:time]
0:[1;]
`, `
#0:record[ts:time]
0:[1;]
0:[2;]
`, `
#0:record[ts:time]
0:[3;]
`}
	outBatches := []string{
		`
#0:record[ts:time,count:uint64]
0:[1;2;]
`, `
#0:record[ts:time,count:uint64]
0:[2;1;]
`, `
#0:record[ts:time,count:uint64]
0:[3;1;]
`}

	inBatchesWithUnset := append(inBatches, `
#0:record[ts:time]
0:[-;]
`)

	outBatchesWithUnset := append(outBatches, `
#0:record[ts:time,count:uint64]
0:[-;1;]
`)

	inBatchesRecordKey := []string{`
#0:record[foo:record[a:string]]
0:[[aaa;]]
`, `
#0:record[foo:record[a:string]]
0:[[baa;]]
`}
	inBatchesRecordKeyWithUnsetRecord := append(inBatchesRecordKey, `
#0:record[foo:record[a:string]]
0:[-;]
`)

	outBatchesRecordKey := []string{
		`
#0:record[foo:record[a:string],count:uint64]
0:[[aaa;]1;]
`, `
#0:record[foo:record[a:string],count:uint64]
0:[[baa;]1;]
`}
	outBatchesRecordKeyWithUnsetRecord := append(outBatchesRecordKey, `
#0:record[foo:record[a:string],count:uint64]
0:[-;1;]
`)
	outBatchesRecordKeyWithUnsetKey := append(outBatchesRecordKey, `
#0:record[foo:record[a:string],count:uint64]
0:[[-;]1;]
`)

	inBatchesRev := []string{
		`#0:record[ts:time]
0:[-;]
0:[10;]
0:[8;]
0:[7;]
0:[6;]
0:[2;]`,
		`#0:record[ts:time]
0:[1;]`}

	outBatchesRev := []string{`
#0:record[ts:time,count:uint64]
0:[-;1;]
0:[10;1;]
0:[8;1;]
0:[7;1;]
0:[6;1;]`,
		`#0:record[ts:time,count:uint64]
0:[2;1;]`,
		`#0:record[ts:time,count:uint64]
0:[1;1;]`}

	runner := func(zql string, dir int, in, out []string) func(t *testing.T) {
		return func(t *testing.T) {
			resolver := resolver.NewContext()
			var inBatches []zbuf.Batch
			for _, s := range in {
				b, err := proctest.ParseTestTzng(resolver, s)
				require.NoError(t, err, s)
				inBatches = append(inBatches, b)
			}

			astProc, err := compileGroupBy(zql)
			assert.NoError(t, err)
			semantic.Transform(astProc)
			astProc.InputSortDir = dir
			tctx := proctest.NewTestContext(resolver)
			src := proctest.NewTestSource(inBatches)
			gproc, err := proctest.CompileTestProcAST(astProc, tctx, src)
			assert.NoError(t, err)
			procTest := proctest.NewProcTest(gproc, tctx)

			for _, s := range out {
				b, err := proctest.ParseTestTzng(resolver, s)
				require.NoError(t, err, s)
				err = procTest.Expect(b)
				assert.NoError(t, err)
			}
			err = procTest.ExpectEOS()
			assert.NoError(t, err)
		}
	}

	t.Run("forward-sorted", runner("count() by ts", 1, inBatches, outBatches))
	t.Run("forward-sorted-with-unset", runner("count() by ts", 1, inBatchesWithUnset, outBatchesWithUnset))
	t.Run("forward-sorted-every", runner("every 1s count()", 1, inBatches, outBatches))
	t.Run("forward-sorted-record-key", runner("count() by foo", 1, inBatchesRecordKey, outBatchesRecordKey))
	t.Run("forward-sorted-nested-key", runner("count() by foo.a", 1, inBatchesRecordKey, outBatchesRecordKey))
	t.Run("forward-sorted-record-key-unset", runner("count() by foo", 1, inBatchesRecordKeyWithUnsetRecord, outBatchesRecordKeyWithUnsetRecord))
	t.Run("forward-sorted-nested-key-unset", runner("count() by foo.a", 1, inBatchesRecordKeyWithUnsetRecord, outBatchesRecordKeyWithUnsetKey))
	t.Run("reverse-sorted", runner("count() by ts", -1, inBatchesRev, outBatchesRev))
}

type countReader struct {
	mu sync.Mutex
	n  int
	r  zbuf.Reader
}

func (cr *countReader) records() int {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.n
}

func (cr *countReader) Read() (*zng.Record, error) {
	rec, err := cr.r.Read()
	if rec != nil {
		cr.mu.Lock()
		cr.n++
		cr.mu.Unlock()
	}
	return rec, err
}

type testGroupByDriver struct {
	n      int
	writer zbuf.Writer
	cb     func(n int)
}

func (d *testGroupByDriver) Write(cid int, batch zbuf.Batch) error {
	for _, r := range batch.Records() {
		d.n++
		if err := d.writer.Write(r); err != nil {
			return err
		}
	}
	d.cb(d.n)
	return nil
}

func (d *testGroupByDriver) Warn(msg string) error {
	panic("shouldn't warn")
}

func (d *testGroupByDriver) ChannelEnd(int) error         { return nil }
func (d *testGroupByDriver) Stats(api.ScannerStats) error { return nil }

func TestGroupbyStreamingSpill(t *testing.T) {

	// This test verifies that with sorted input, spillable groupby streams results as input arrives.
	//
	// The sorted input key is ts. The input and config parameters are carefully chosen such that:
	// - spills are not aligned with ts changes (at least some
	//   transitions from ts=n to ts=n+1 happen mid-spill)
	// - secondary keys repeat in a ts bin
	//
	// Together these conditions test that the read barrier (using
	// GroupByAggregator.maxSpillKey) does not read a key from a
	// spill before that all records for that key have been
	// written to the spill.
	//
	savedBatchSize := zbuf.ScannerBatchSize
	zbuf.ScannerBatchSize = 1
	savedBatchSizeGroupByLimit := groupby.DefaultLimit
	groupby.DefaultLimit = 2
	defer func() {
		zbuf.ScannerBatchSize = savedBatchSize
		groupby.DefaultLimit = savedBatchSizeGroupByLimit
	}()

	const totRecs = 200
	const recsPerTs = 9
	const uniqueIpsPerTs = 3

	data := []string{"#0:record[ts:time,ip:ip]"}
	for i := 0; i < totRecs; i++ {
		t := i / recsPerTs
		data = append(data, fmt.Sprintf("0:[%d;1.1.1.%d;]", t, i%uniqueIpsPerTs))
	}

	runOne := func(inputSortKey string) []string {
		proc, err := compiler.ParseProc("every 1s count() by ip")
		assert.NoError(t, err)

		zctx := resolver.NewContext()
		zr := tzngio.NewReader(strings.NewReader(strings.Join(data, "\n")), zctx)
		cr := &countReader{r: zr}
		var outbuf bytes.Buffer
		zw, _ := detector.LookupWriter(&nopCloser{&outbuf}, zctx, zio.WriterOpts{})
		d := &testGroupByDriver{
			writer: zw,
			cb: func(n int) {
				if inputSortKey != "" {
					if n == uniqueIpsPerTs {
						require.Less(t, cr.records(), totRecs)
					}
				}
			},
		}
		err = driver.Run(context.Background(), d, proc, zctx, cr, driver.Config{
			ReaderSortKey: inputSortKey,
		})
		require.NoError(t, err)
		outData := strings.Split(outbuf.String(), "\n")
		sort.Strings(outData)
		return outData
	}

	res := runOne("") // run once in non-streaming mode to have reference results to compare with.
	resStreaming := runOne("ts")
	require.Equal(t, res, resStreaming)
}

type nopCloser struct{ io.Writer }

func (*nopCloser) Close() error { return nil }
