package zson_test

import (
	"encoding/json"
	"testing"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/pkg/fs"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parse(path string) (ast.Value, error) {
	file, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	parser, err := zson.NewParser(file)
	if err != nil {
		return nil, err
	}
	return parser.ParseValue()
}

const testFile = "test.zson"

func TestZsonParser(t *testing.T) {
	val, err := parse(testFile)
	require.NoError(t, err)
	s, err := json.MarshalIndent(val, "", "    ")
	require.NoError(t, err)
	assert.NotEqual(t, s, "")
}

func analyze(zctx *resolver.Context, path string) (zson.Value, error) {
	val, err := parse(path)
	if err != nil {
		return nil, err
	}
	analyzer := zson.NewAnalyzer()
	return analyzer.ConvertValue(zctx, val)
}

func TestZsonAnalyzer(t *testing.T) {
	zctx := resolver.NewContext()
	val, err := analyze(zctx, testFile)
	require.NoError(t, err)
	assert.NotNil(t, val)
}

func TestZsonBuilder(t *testing.T) {
	zctx := resolver.NewContext()
	val, err := analyze(zctx, testFile)
	require.NoError(t, err)
	b := zson.NewBuilder()
	zv, err := b.Build(val)
	require.NoError(t, err)
	rec := zng.NewRecord(zv.Type.(*zng.TypeRecord), zv.Bytes)
	zv, err = rec.Access("a")
	require.NoError(t, err)
	assert.Equal(t, "array[string]: [(31)(32)(33)]", zv.String())
}
