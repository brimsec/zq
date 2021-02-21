package zqd_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/api/client"
	"github.com/brimsec/zq/compiler"
	"github.com/brimsec/zq/driver"
	"github.com/brimsec/zq/pkg/fs"
	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/pkg/promtest"
	"github.com/brimsec/zq/pkg/test"
	"github.com/brimsec/zq/ppl/lake/immcache"
	"github.com/brimsec/zq/ppl/zqd"
	"github.com/brimsec/zq/ppl/zqd/pcapanalyzer"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/detector"
	"github.com/brimsec/zq/zio/ndjsonio"
	"github.com/brimsec/zq/zio/tzngio"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

const (
	babble       = "../../ztests/suite/data/babble.tzng"
	babbleSorted = "../../ztests/suite/data/babble-sorted.tzng"
)

func TestASTPost(t *testing.T) {
	_, conn := newCore(t)
	resp, err := conn.Do(context.Background(), http.MethodPost, "/ast", &api.ASTRequest{ZQL: "*"})
	require.NoError(t, err)
	require.Equal(t, string(resp.Body()), "{\"op\":\"SequentialProc\",\"procs\":[{\"op\":\"FilterProc\",\"filter\":{\"op\":\"Literal\",\"type\":\"bool\",\"value\":\"true\"}}]}\n")
}

func TestSearch(t *testing.T) {
	const src = `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;1521911723.205187;CBrzd94qfowOqJwCHa;]
0:[conn;1521911721.255387;C8Tful1TvM3Zf5x8fl;]
`
	_, conn := newCore(t)
	ctx := context.Background()
	_, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	id, err := conn.SpaceLookup(ctx, "test")
	require.NoError(t, err)

	_, err = conn.LogPostReaders(context.Background(), id, nil, strings.NewReader(src))
	require.NoError(t, err)

	res := searchTzng(t, conn, id, "*")
	require.Equal(t, test.Trim(src), res)
}

func TestSearchNoCtrl(t *testing.T) {
	src := `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;1521911723.205187;CBrzd94qfowOqJwCHa;]
0:[conn;1521911721.255387;C8Tful1TvM3Zf5x8fl;]
`
	_, conn := newCore(t)
	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	_, err = conn.LogPostReaders(context.Background(), sp.ID, nil, strings.NewReader(src))
	require.NoError(t, err)

	parsed, err := compiler.ParseProc("*")
	require.NoError(t, err)
	proc, err := json.Marshal(parsed)
	require.NoError(t, err)
	req := api.SearchRequest{
		Space: sp.ID,
		Proc:  proc,
		Span:  nano.MaxSpan,
		Dir:   -1,
	}
	body, err := conn.SearchRaw(context.Background(), req, map[string]string{"noctrl": "true"})
	require.NoError(t, err)
	var msgs []interface{}
	r := client.NewZngSearch(body)
	r.SetOnCtrl(func(i interface{}) {
		msgs = append(msgs, i)
	})
	buf := bytes.NewBuffer(nil)
	w := tzngio.NewWriter(zio.NopCloser(buf))
	require.NoError(t, zbuf.Copy(w, r))
	require.Equal(t, test.Trim(src), buf.String())
	require.Equal(t, 0, len(msgs))
}

func TestSearchStats(t *testing.T) {
	src := `
#0:record[_path:string,ts:time]
0:[a;1;]
0:[b;1;]
`
	_, conn := newCore(t)
	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	_, err = conn.LogPostReaders(context.Background(), sp.ID, nil, strings.NewReader(src))
	require.NoError(t, err)
	_, msgs := search(t, conn, sp.ID, "_path != b")
	var stats *api.SearchStats
	for i := len(msgs) - 1; i >= 0; i-- {
		if s, ok := msgs[i].(*api.SearchStats); ok {
			stats = s
			break
		}
	}
	require.NotNil(t, stats)
	assert.Equal(t, stats.Type, "SearchStats")
	assert.Equal(t, stats.ScannerStats, api.ScannerStats{
		BytesRead:      14,
		BytesMatched:   7,
		RecordsRead:    2,
		RecordsMatched: 1,
	})
}

func TestGroupByReverse(t *testing.T) {
	src := `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;1;CBrzd94qfowOqJwCHa;]
0:[conn;1;C8Tful1TvM3Zf5x8fl;]
0:[conn;2;C8Tful1TvM3Zf5x8fl;]
`
	counts := `
#0:record[ts:time,count:uint64]
0:[2;1;]
0:[1;2;]
`
	_, conn := newCore(t)
	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	_, err = conn.LogPostReaders(context.Background(), sp.ID, nil, strings.NewReader(src))
	require.NoError(t, err)
	res := searchTzng(t, conn, sp.ID, "every 1s count()")
	require.Equal(t, test.Trim(counts), res)
}

func TestSearchEmptySpace(t *testing.T) {
	ctx := context.Background()
	_, conn := newCore(t)
	sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	res := searchTzng(t, conn, sp.ID, "*")
	require.Equal(t, "", res)
}

func TestSearchError(t *testing.T) {
	src := `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;1521911723.205187;CBrzd94qfowOqJwCHa;]
0:[conn;1521911721.255387;C8Tful1TvM3Zf5x8fl;]
`
	_, conn := newCore(t)
	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	_, err = conn.LogPostReaders(context.Background(), sp.ID, nil, strings.NewReader(src))
	require.NoError(t, err)

	parsed, err := compiler.ParseProc("*")
	require.NoError(t, err)
	proc, err := json.Marshal(parsed)
	require.NoError(t, err)
	t.Run("InvalidDir", func(t *testing.T) {
		req := api.SearchRequest{
			Space: sp.ID,
			Proc:  proc,
			Span:  nano.MaxSpan,
			Dir:   2,
		}
		_, err = conn.SearchRaw(context.Background(), req, nil)
		require.Error(t, err)
		errResp := err.(*client.ErrorResponse)
		assert.Equal(t, http.StatusBadRequest, errResp.StatusCode())
		assert.IsType(t, &api.Error{}, errResp.Err)
	})
	t.Run("ForwardSearchUnsupported", func(t *testing.T) {
		req := api.SearchRequest{
			Space: sp.ID,
			Proc:  proc,
			Span:  nano.MaxSpan,
			Dir:   1,
		}
		_, err = conn.SearchRaw(context.Background(), req, nil)
		require.Error(t, err)
		errResp := err.(*client.ErrorResponse)
		assert.Equal(t, http.StatusBadRequest, errResp.StatusCode())
		assert.IsType(t, &api.Error{}, errResp.Err)
	})
}

func TestSpaceList(t *testing.T) {
	names := []string{"sp1", "sp2", "sp3", "sp4"}
	var expected []api.Space

	ctx := context.Background()
	c, conn := newCore(t)
	for _, n := range names {
		sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: n})
		require.NoError(t, err)
		expected = append(expected, api.Space{
			ID:          sp.ID,
			Name:        n,
			DataPath:    c.Root().AppendPath(string(sp.ID)),
			StorageKind: api.DefaultStorageKind(),
		})
	}

	list, err := conn.SpaceList(ctx)
	require.NoError(t, err)
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	require.Equal(t, expected, list)
}

func TestSpaceInfo(t *testing.T) {
	src := `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;1;CBrzd94qfowOqJwCHa;]
0:[conn;2;C8Tful1TvM3Zf5x8fl;]`
	ctx := context.Background()
	_, conn := newCore(t)
	sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	_, err = conn.LogPostReaders(context.Background(), sp.ID, nil, strings.NewReader(src))
	require.NoError(t, err)

	span := nano.Span{Ts: 1e9, Dur: 1e9 + 1}
	expected := &api.SpaceInfo{
		Space: api.Space{
			ID:          sp.ID,
			Name:        sp.Name,
			DataPath:    sp.DataPath,
			StorageKind: api.DefaultStorageKind(),
		},
		Span:        &span,
		Size:        81,
		PcapSupport: false,
	}
	info, err := conn.SpaceInfo(ctx, sp.ID)
	require.NoError(t, err)
	require.Equal(t, expected, info)
}

func TestSpaceInfoNoData(t *testing.T) {
	ctx := context.Background()
	_, conn := newCore(t)
	sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	info, err := conn.SpaceInfo(ctx, sp.ID)
	require.NoError(t, err)
	expected := &api.SpaceInfo{
		Space: api.Space{
			ID:          sp.ID,
			Name:        sp.Name,
			DataPath:    sp.DataPath,
			StorageKind: api.DefaultStorageKind(),
		},
		Size:        0,
		PcapSupport: false,
	}
	require.Equal(t, expected, info)
}

func TestSpacePostNameOnly(t *testing.T) {
	ctx := context.Background()
	c, conn := newCore(t)
	sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	assert.Equal(t, "test", sp.Name)
	assert.Equal(t, c.Root().AppendPath(string(sp.ID)), sp.DataPath)
	assert.Regexp(t, "^sp", sp.ID)
}

func TestSpacePostDuplicateName(t *testing.T) {
	ctx := context.Background()
	_, conn := newCore(t)
	_, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	_, err = conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.Equal(t, client.ErrSpaceExists, err)
}

func TestSpaceInvalidName(t *testing.T) {
	ctx := context.Background()
	_, conn := newCore(t)
	t.Run("Post", func(t *testing.T) {
		_, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "𝚭𝚴𝚪 is.good"})
		require.NoError(t, err)
		_, err = conn.SpacePost(ctx, api.SpacePostRequest{Name: "𝚭𝚴𝚪/bad"})
		require.EqualError(t, err, "status code 400: name may not contain '/' or non-printable characters")
	})
	t.Run("Put", func(t *testing.T) {
		sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "𝚭𝚴𝚪1"})
		require.NoError(t, err)
		err = conn.SpacePut(ctx, sp.ID, api.SpacePutRequest{Name: "𝚭𝚴𝚪/2"})
		require.EqualError(t, err, "status code 400: name may not contain '/' or non-printable characters")
	})
}

func TestSpacePutDuplicateName(t *testing.T) {
	ctx := context.Background()
	_, conn := newCore(t)
	_, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test1"})
	require.NoError(t, err)
	err = conn.SpacePut(ctx, sp.ID, api.SpacePutRequest{Name: "test"})
	assert.EqualError(t, err, "status code 409: space with name 'test' already exists")
}

func TestSpacePostDataPath(t *testing.T) {
	ctx := context.Background()
	tmp := createTempDir(t)
	datapath := filepath.Join(tmp, "mypcap.brim")
	_, conn := newCoreAtDir(t, filepath.Join(tmp, "spaces"))
	sp, err := conn.SpacePost(ctx, api.SpacePostRequest{DataPath: datapath})
	require.NoError(t, err)
	assert.Equal(t, "mypcap.brim", sp.Name)
	assert.Equal(t, datapath, sp.DataPath.Filepath())
}

func TestSpacePut(t *testing.T) {
	ctx := context.Background()
	_, conn := newCore(t)
	sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	err = conn.SpacePut(ctx, sp.ID, api.SpacePutRequest{Name: "new_name"})
	require.NoError(t, err)
	info, err := conn.SpaceInfo(ctx, sp.ID)
	require.NoError(t, err)
	assert.Equal(t, "new_name", info.Name)
}

func TestSpaceDelete(t *testing.T) {
	ctx := context.Background()
	c, conn := newCore(t)
	sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	err = conn.SpaceDelete(ctx, sp.ID)
	require.NoError(t, err)
	list, err := conn.SpaceList(ctx)
	require.NoError(t, err)
	require.Len(t, list, 0)

	require.Equal(t, 1.0, promCounterValue(c.Registry(), "spaces_created_total"))
	require.Equal(t, 1.0, promCounterValue(c.Registry(), "spaces_deleted_total"))
}

func TestSpaceDeleteDataDir(t *testing.T) {
	ctx := context.Background()
	tmp := createTempDir(t)
	_, conn := newCoreAtDir(t, filepath.Join(tmp, "spaces"))
	datadir := filepath.Join(tmp, "mypcap.brim")
	sp, err := conn.SpacePost(ctx, api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)
	err = conn.SpaceDelete(ctx, sp.ID)
	require.NoError(t, err)
	list, err := conn.SpaceList(ctx)
	require.NoError(t, err)
	require.Len(t, list, 0)
	// ensure data dir has also been deleted
	_, err = os.Stat(datadir)
	require.Error(t, err)
	require.Truef(t, os.IsNotExist(err), "expected error to be os.IsNotExist, got %v", err)
}

func TestNoEndSlashSupport(t *testing.T) {
	_, conn := newCore(t)
	_, err := conn.Do(context.Background(), "GET", "/space/", nil)
	require.Error(t, err)
	require.Equal(t, 404, err.(*client.ErrorResponse).StatusCode())
}

func TestRequestID(t *testing.T) {
	ctx := context.Background()
	t.Run("GeneratesUniqueID", func(t *testing.T) {
		_, conn := newCore(t)
		res1, err := conn.Do(ctx, "GET", "/space", nil)
		require.NoError(t, err)
		res2, err := conn.Do(ctx, "GET", "/space", nil)
		require.NoError(t, err)
		assert.NotEqual(t, "", res1.Header().Get("X-Request-ID"))
		assert.NotEqual(t, "", res2.Header().Get("X-Request-ID"))
	})
	t.Run("PropagatesID", func(t *testing.T) {
		_, conn := newCore(t)
		requestID := "random-request-ID"
		req := conn.Request(context.Background())
		req.SetHeader("X-Request-ID", requestID)
		res, err := req.Execute("GET", "/space")
		require.NoError(t, err)
		require.Equal(t, requestID, res.Header().Get("X-Request-ID"))
	})
}

func TestPostZngLogs(t *testing.T) {
	const src1 = `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;1;CBrzd94qfowOqJwCHa;]`
	const src2 = `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;2;CBrzd94qfowOqJwCHa;]`
	const expected = `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;2;CBrzd94qfowOqJwCHa;]
0:[conn;1;CBrzd94qfowOqJwCHa;]`

	_, conn := newCore(t)
	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)

	pres, err := conn.LogPostReaders(context.Background(), sp.ID, nil,
		strings.NewReader(src1),
		strings.NewReader(src2),
	)
	require.NoError(t, err)
	assert.Equal(t, api.LogPostResponse{Type: "LogPostResponse", BytesRead: 150}, pres)

	res := searchTzng(t, conn, sp.ID, "*")
	require.EqualValues(t, test.Trim(expected), res)

	info, err := conn.SpaceInfo(context.Background(), sp.ID)
	require.NoError(t, err)
	assert.Equal(t, &api.SpaceInfo{
		Space: api.Space{
			ID:          sp.ID,
			Name:        sp.Name,
			DataPath:    sp.DataPath,
			StorageKind: api.DefaultStorageKind(),
		},
		Span:        &nano.Span{Ts: nano.Ts(time.Second), Dur: int64(time.Second) + 1},
		Size:        79,
		PcapSupport: false,
	}, info)
}

func TestPostZngLogWarning(t *testing.T) {
	const src1 = `undetectableformat`
	const src2 = `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;1;CBrzd94qfowOqJwCHa;]
detectablebutbadline`

	_, conn := newCore(t)
	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)

	res, err := conn.LogPostReaders(context.Background(), sp.ID, nil,
		strings.NewReader(src1),
		strings.NewReader(src2),
	)
	require.NoError(t, err)
	assert.Regexp(t, ": format detection error.*", res.Warnings[0])
	assert.Regexp(t, ": line 4: bad format$", res.Warnings[1])
}

func TestPostNDJSONLogs(t *testing.T) {
	const src = `{"ts":"1000","uid":"CXY9a54W2dLZwzPXf1","_path":"http"}
{"ts":"2000","uid":"CXY9a54W2dLZwzPXf1","_path":"http"}`
	const expected = "#0:record[_path:string,ts:time,uid:bstring]\n0:[http;2;CXY9a54W2dLZwzPXf1;]\n0:[http;1;CXY9a54W2dLZwzPXf1;]"
	tc := ndjsonio.TypeConfig{
		Descriptors: map[string][]interface{}{
			"http_log": []interface{}{
				map[string]interface{}{
					"name": "_path",
					"type": "string",
				},
				map[string]interface{}{
					"name": "ts",
					"type": "time",
				},
				map[string]interface{}{
					"name": "uid",
					"type": "bstring",
				},
			},
		},
		Rules: []ndjsonio.Rule{
			ndjsonio.Rule{"_path", "http", "http_log"},
		},
	}

	test := func(input string) {
		_, conn := newCore(t)

		sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{Name: "test"})
		require.NoError(t, err)

		opts := &client.LogPostOpts{JSON: &tc}
		_, err = conn.LogPostReaders(context.Background(), sp.ID, opts, strings.NewReader(src))
		require.NoError(t, err)

		res := searchTzng(t, conn, sp.ID, "*")
		require.Equal(t, expected, strings.TrimSpace(res))

		span := nano.Span{Ts: 1e9, Dur: 1e9 + 1}
		info, err := conn.SpaceInfo(context.Background(), sp.ID)
		require.NoError(t, err)
		require.Equal(t, &api.SpaceInfo{
			Space: api.Space{
				ID:          sp.ID,
				Name:        sp.Name,
				DataPath:    sp.DataPath,
				StorageKind: api.DefaultStorageKind(),
			},
			Span:        &span,
			Size:        79,
			PcapSupport: false,
		}, info)
	}
	t.Run("plain", func(t *testing.T) {
		test(src)
	})
	t.Run("gzipped", func(t *testing.T) {
		var b strings.Builder
		w := gzip.NewWriter(&b)
		_, err := w.Write([]byte(src))
		require.NoError(t, err)
		require.NoError(t, w.Close())
		test(b.String())
	})
}

func TestPostNDJSONLogWarning(t *testing.T) {
	src1 := strings.NewReader(`{"ts":"1000","_path":"http"}
{"ts":"2000","_path":"nosuchpath"}`)
	src2 := strings.NewReader(`{"ts":"1000","_path":"http"}
{"ts":"1000","_path":"http","extra":"foo"}`)
	tc := ndjsonio.TypeConfig{
		Descriptors: map[string][]interface{}{
			"http_log": []interface{}{
				map[string]interface{}{
					"name": "_path",
					"type": "string",
				},
				map[string]interface{}{
					"name": "ts",
					"type": "time",
				},
			},
		},
		Rules: []ndjsonio.Rule{
			ndjsonio.Rule{"_path", "http", "http_log"},
		},
	}
	_, conn := newCore(t)
	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)

	opts := &client.LogPostOpts{JSON: &tc}
	res, err := conn.LogPostReaders(context.Background(), sp.ID, opts, src1, src2)
	require.NoError(t, err)
	require.Len(t, res.Warnings, 2)
	assert.Regexp(t, ": line 2: descriptor not found", res.Warnings[0])
	assert.Regexp(t, ": line 2: incomplete descriptor", res.Warnings[1])
	assert.EqualValues(t, 134, res.BytesRead)
}

func TestPostLogStopErr(t *testing.T) {
	const src = `
#0:record[_path:string,ts:time,uid:bstring
0:[conn;1;CBrzd94qfowOqJwCHa;]`

	_, conn := newCore(t)
	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{Name: "test"})
	require.NoError(t, err)

	opts := &client.LogPostOpts{StopError: true}
	_, err = conn.LogPostReaders(context.Background(), sp.ID, opts, strings.NewReader(src))
	require.Error(t, err)
	assert.Regexp(t, ": format detection error.*", err.Error())
}

func TestSpaceDataDir(t *testing.T) {
	src := `
#0:record[_path:string,ts:time,uid:bstring]
0:[conn;1521911723.205187;CBrzd94qfowOqJwCHa;]
0:[conn;1521911721.255387;C8Tful1TvM3Zf5x8fl;]
`

	root := createTempDir(t)
	datapath := createTempDir(t)

	_, conn1 := newCoreAtDir(t, root)

	// Verify space creation request uses datapath.
	sp, err := conn1.SpacePost(context.Background(), api.SpacePostRequest{
		Name:     "test",
		DataPath: datapath,
	})
	require.NoError(t, err)
	_, err = conn1.LogPostReaders(context.Background(), sp.ID, nil, strings.NewReader(src))
	require.NoError(t, err)
	res := searchTzng(t, conn1, sp.ID, "*")
	require.Equal(t, test.Trim(src), res)

	// Verify storage metadata file created in expected location.
	mdfile := "zar.json"
	if sp.StorageKind == api.FileStore {
		mdfile = "all.zng"
	}
	_, err = os.Stat(filepath.Join(datapath, mdfile))
	require.NoError(t, err)

	// Verify space load on startup uses datapath.
	_, conn2 := newCoreAtDir(t, root)

	res = searchTzng(t, conn2, sp.ID, "*")
	require.Equal(t, test.Trim(src), res)
}

func TestCreateArchiveSpace(t *testing.T) {
	thresh := int64(1000)
	_, conn := newCore(t)

	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{
		Name: "arktest",
		Storage: &api.StorageConfig{
			Kind: api.ArchiveStore,
			Archive: &api.ArchiveConfig{
				CreateOptions: &api.ArchiveCreateOptions{
					LogSizeThreshold: &thresh,
				},
			},
		},
	})
	require.NoError(t, err)
	_, err = conn.LogPost(context.Background(), sp.ID, nil, babbleSorted)
	require.NoError(t, err)

	span := nano.Span{Ts: 1587508830068523240, Dur: 9789993714061}
	expsi := &api.SpaceInfo{
		Space: api.Space{
			ID:          sp.ID,
			Name:        sp.Name,
			DataPath:    sp.DataPath,
			StorageKind: api.ArchiveStore,
		},
		Span: &span,
		Size: 35118,
	}
	si, err := conn.SpaceInfo(context.Background(), sp.ID)
	require.NoError(t, err)
	require.Equal(t, expsi, si)

	exptzng := `
#0:record[ts:time,s:string,v:int64]
0:[1587508881.0613914;harefoot-raucous;137;]
`
	res := searchTzng(t, conn, sp.ID, "s=harefoot\\-raucous")
	require.Equal(t, test.Trim(exptzng), res)
}

func TestArchiveInProcessCache(t *testing.T) {
	const expcount = `
#0:record[count:uint64]
0:[1000;]`

	core, conn := newCoreWithConfig(t, zqd.Config{
		ImmutableCache: immcache.Config{
			Kind:           immcache.KindLocal,
			LocalCacheSize: 128,
		},
	})

	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{
		Name:    "arktest",
		Storage: &api.StorageConfig{Kind: api.ArchiveStore},
	})
	require.NoError(t, err)

	_, err = conn.LogPost(context.Background(), sp.ID, nil, babbleSorted)
	require.NoError(t, err)

	for i := 0; i < 4; i++ {
		res, _ := search(t, conn, sp.ID, "count()")
		assert.Equal(t, test.Trim(expcount), res)
	}

	kind := prometheus.Labels{"kind": "metadata"}
	misses := promtest.CounterValue(t, core.Registry(), "archive_cache_misses_total", kind)
	hits := promtest.CounterValue(t, core.Registry(), "archive_cache_hits_total", kind)

	assert.EqualValues(t, 2, misses)
	assert.EqualValues(t, 8, hits)
}

func TestBlankNameSpace(t *testing.T) {
	// Verify that spaces created before the zq#721 work have names.

	oldconfig := `{"data_path":"."}`
	testdirname := "testdirname"
	root := createTempDir(t)

	err := os.MkdirAll(filepath.Join(root, testdirname), 0700)
	require.NoError(t, err)
	err = ioutil.WriteFile(filepath.Join(root, testdirname, "config.json"), []byte(oldconfig), 0600)
	require.NoError(t, err)

	_, conn := newCoreAtDir(t, root)

	si, err := conn.SpaceInfo(context.Background(), api.SpaceID(testdirname))
	require.NoError(t, err)
	assert.Equal(t, testdirname, si.Name)
}

func TestIndexSearch(t *testing.T) {
	thresh := int64(1000)
	root := createTempDir(t)

	_, conn := newCoreAtDir(t, root)

	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{
		Name: "TestIndexSearch",
		Storage: &api.StorageConfig{
			Kind: api.ArchiveStore,
			Archive: &api.ArchiveConfig{
				CreateOptions: &api.ArchiveCreateOptions{
					LogSizeThreshold: &thresh,
				},
			},
		},
	})
	require.NoError(t, err)
	// babbleSorted must be used because regular babble isn't fully sorted and
	// generates an overlap which on compaction deletes certain indices. We
	// should be able to remove this once #1656 is completed and we have some
	// api way of determining if compactions are complete.
	_, err = conn.LogPost(context.Background(), sp.ID, nil, babbleSorted)
	require.NoError(t, err)
	err = conn.IndexPost(context.Background(), sp.ID, api.IndexPostRequest{
		Patterns: []string{"v"},
	})
	require.NoError(t, err)

	exp := `
#0:record[key:int64,count:uint64,first:time,last:time]
0:[257;1;1587518582.06699522;1587518014.06491752;]
0:[257;1;1587516748.0632538;1587516200.06892251;]
0:[257;1;1587512245.0693411;1587511709.06845389;]
0:[257;1;1587511703.06774599;1587511182.064686;]
0:[257;1;1587510666.06396109;1587510062.069881;]
0:[257;1;1587509477.06450528;1587508830.06852324;]
`
	res, _ := indexSearch(t, conn, sp.ID, "", []string{"v=257"})
	assert.Equal(t, test.Trim(exp), tzngCopy(t, "drop _log", res, "tzng"))
}

func TestArchiveStat(t *testing.T) {
	thresh := int64(20 * 1024)
	root := createTempDir(t)
	_, conn := newCoreAtDir(t, root)

	sp, err := conn.SpacePost(context.Background(), api.SpacePostRequest{
		Name: "TestArchiveStat",
		Storage: &api.StorageConfig{
			Kind: api.ArchiveStore,
			Archive: &api.ArchiveConfig{
				CreateOptions: &api.ArchiveCreateOptions{
					LogSizeThreshold: &thresh,
				},
			},
		},
	})
	require.NoError(t, err)
	_, err = conn.LogPost(context.Background(), sp.ID, nil, babble)
	require.NoError(t, err)
	err = conn.IndexPost(context.Background(), sp.ID, api.IndexPostRequest{
		Patterns: []string{"v"},
	})
	require.NoError(t, err)

	exp := `
#0:record[type:string,first:time,last:time,size:uint64,record_count:uint64]
0:[chunk;1587518620.0622373;1587513611.06391469;16995;496;]
#1:record[type:string,first:time,last:time,definition:record[description:string],size:uint64,record_count:uint64,keys:array[record[name:string,type:string]]]
1:[index;1587518620.0622373;1587513611.06391469;[field-v;]2281;0;[[key;int64;]]]
0:[chunk;1587513592.0625444;1587508830.06852324;17206;504;]
1:[index;1587513592.0625444;1587508830.06852324;[field-v;]2267;0;[[key;int64;]]]
`
	res := archiveStat(t, conn, sp.ID)
	assert.Equal(t, test.Trim(exp), tzngCopy(t, "drop log_id, definition.id", res, "tzng"))
}

func archiveStat(t *testing.T, conn *client.Connection, space api.SpaceID) string {
	r, err := conn.ArchiveStat(context.Background(), space, nil)
	require.NoError(t, err)
	buf := bytes.NewBuffer(nil)
	w := tzngio.NewWriter(zio.NopCloser(buf))
	require.NoError(t, zbuf.Copy(w, r))
	return buf.String()
}

func indexSearch(t *testing.T, conn *client.Connection, space api.SpaceID, indexName string, patterns []string) (string, []interface{}) {
	req := api.IndexSearchRequest{
		IndexName: indexName,
		Patterns:  patterns,
	}
	r, err := conn.IndexSearch(context.Background(), space, req, nil)
	require.NoError(t, err)
	buf := bytes.NewBuffer(nil)
	w := tzngio.NewWriter(zio.NopCloser(buf))
	var msgs []interface{}
	r.SetOnCtrl(func(i interface{}) {
		msgs = append(msgs, i)
	})
	require.NoError(t, zbuf.Copy(w, r))
	return buf.String(), msgs
}

// search runs the provided zql program as a search on the provided
// space, returning the tzng results along with a slice of all control
// messages that were received.
func search(t *testing.T, conn *client.Connection, space api.SpaceID, prog string) (string, []interface{}) {
	parsed, err := compiler.ParseProc(prog)
	require.NoError(t, err)
	proc, err := json.Marshal(parsed)
	require.NoError(t, err)
	req := api.SearchRequest{
		Space: space,
		Proc:  proc,
		Span:  nano.MaxSpan,
		Dir:   -1,
	}
	body, err := conn.SearchRaw(context.Background(), req, nil)
	require.NoError(t, err)
	r := client.NewZngSearch(body)
	buf := bytes.NewBuffer(nil)
	w := tzngio.NewWriter(zio.NopCloser(buf))
	var msgs []interface{}
	r.SetOnCtrl(func(i interface{}) {
		msgs = append(msgs, i)
	})
	require.NoError(t, zbuf.Copy(w, r))
	return buf.String(), msgs
}

func searchTzng(t *testing.T, conn *client.Connection, space api.SpaceID, prog string) string {
	res, err := conn.Search(context.Background(), space, prog)
	require.NoError(t, err)
	buf := bytes.NewBuffer(nil)
	w := tzngio.NewWriter(zio.NopCloser(buf))
	require.NoError(t, zbuf.Copy(w, res))
	return buf.String()
}

func tzngCopy(t *testing.T, prog string, in string, outFormat string) string {
	zctx := resolver.NewContext()
	r := tzngio.NewReader(bytes.NewReader([]byte(in)), zctx)
	buf := bytes.NewBuffer(nil)
	w, err := detector.LookupWriter(zio.NopCloser(buf), zctx, zio.WriterOpts{Format: outFormat})
	require.NoError(t, err)
	p := compiler.MustParseProc(prog)
	err = driver.Copy(context.Background(), w, p, zctx, r, driver.Config{})
	require.NoError(t, err)
	return buf.String()
}

func createTempDir(t *testing.T) string {
	// Replace '/' with '-' so it doesn't try to access dirs that don't exist.
	// Apparently "/" in a filepath for windows still tries to create a
	// directory; this solution works for windows as well.
	name := strings.ReplaceAll(t.Name(), "/", "-")
	dir, err := ioutil.TempDir("", name)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func writeTempFile(t *testing.T, data string) string {
	f, err := ioutil.TempFile("", t.Name())
	require.NoError(t, err)
	name := f.Name()
	t.Cleanup(func() { os.Remove(name) })
	_, err = f.WriteString(data)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return name
}

func newCore(t *testing.T) (*zqd.Core, *client.Connection) {
	root := createTempDir(t)
	return newCoreAtDir(t, root)
}

func newCoreAtDir(t *testing.T, dir string) (*zqd.Core, *client.Connection) {
	require.NoError(t, os.MkdirAll(dir, 0755))
	t.Cleanup(func() { os.RemoveAll(dir) })
	return newCoreWithConfig(t, zqd.Config{Root: dir})
}

func newCoreWithConfig(t *testing.T, conf zqd.Config) (*zqd.Core, *client.Connection) {
	if conf.Root == "" {
		conf.Root = createTempDir(t)
	}
	if conf.Logger == nil {
		conf.Logger = zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel))
	}
	core, err := zqd.NewCore(context.Background(), conf)
	require.NoError(t, err)
	srv := httptest.NewServer(core.HTTPHandler())
	t.Cleanup(srv.Close)
	return core, client.NewConnectionTo(srv.URL)
}

func promCounterValue(g prometheus.Gatherer, name string) interface{} {
	metricFamilies, err := g.Gather()
	if err != nil {
		return err
	}
	for _, mf := range metricFamilies {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	return errors.New("metric not found")
}

func testLauncher(start, wait procFn) pcapanalyzer.Launcher {
	return func(ctx context.Context, r io.Reader, dir string) (pcapanalyzer.ProcessWaiter, error) {
		p := &testPcapProcess{
			ctx:    ctx,
			reader: r,
			wd:     dir,
			wait:   wait,
			start:  start,
		}
		return p, p.Start()
	}
}

type procFn func(t *testPcapProcess) error

type testPcapProcess struct {
	ctx    context.Context
	reader io.Reader
	wd     string
	start  procFn
	wait   procFn
}

func (p *testPcapProcess) Start() error {
	if p.start != nil {
		return p.start(p)
	}
	return nil
}

func (p *testPcapProcess) Wait() error {
	if p.wait != nil {
		return p.wait(p)
	}
	_, err := ioutil.ReadAll(p.reader)
	return err
}

func (p *testPcapProcess) Stdout() string { return "" }

func writeLogsFn(logs []string) procFn {
	return func(p *testPcapProcess) error {
		for _, log := range logs {
			r, err := fs.Open(log)
			if err != nil {
				return err
			}
			defer r.Close()
			base := filepath.Base(r.Name())
			w, err := os.Create(filepath.Join(p.wd, base))
			if err != nil {
				return err
			}
			defer w.Close()
			if _, err = io.Copy(w, r); err != nil {
				return err
			}
		}
		// drain the reader
		_, err := io.Copy(ioutil.Discard, p.reader)
		return err
	}
}
