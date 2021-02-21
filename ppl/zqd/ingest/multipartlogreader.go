package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"sync/atomic"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/driver"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/detector"
	"github.com/brimsec/zq/zio/ndjsonio"
	"github.com/brimsec/zq/zio/zngio"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zqe"
)

const maxShaperAstBytes = 1000 * 1000

type MultipartLogReader struct {
	mr        *multipart.Reader
	opts      zio.ReaderOpts
	stopErr   bool
	shaperAST ast.Proc
	warnings  []string
	zreader   zbuf.ReadCloser
	zctx      *resolver.Context
	nread     int64
}

func NewMultipartLogReader(mr *multipart.Reader, zctx *resolver.Context) *MultipartLogReader {
	return &MultipartLogReader{
		mr:   mr,
		opts: zio.ReaderOpts{Zng: zngio.ReaderOpts{Validate: true}},
		zctx: zctx,
	}
}

func (m *MultipartLogReader) SetStopOnError() {
	m.stopErr = true
}

func (m *MultipartLogReader) Read() (*zng.Record, error) {
read:
	if m.zreader == nil {
		zr, err := m.next()
		if zr == nil || err != nil {
			return nil, err
		}
		m.zreader = zr
	}
	rec, err := m.zreader.Read()
	if err != nil || rec == nil {
		zr := m.zreader
		m.zreader.Close()
		m.zreader = nil
		if err != nil {
			if m.stopErr {
				return nil, err
			}
			m.appendWarning(zr, err)
		}
		goto read
	}
	return rec, err
}

func (m *MultipartLogReader) next() (zbuf.ReadCloser, error) {
next:
	if m.mr == nil {
		return nil, nil
	}
	part, err := m.mr.NextPart()
	if err != nil {
		if err == io.EOF {
			m.mr, err = nil, nil
		}
		return nil, err
	}
	if part.FormName() == "json_config" {
		if err := json.NewDecoder(part).Decode(&m.opts.JSON.TypeConfig); err != nil {
			return nil, zqe.ErrInvalid("bad typing config: %v", err)
		}
		m.opts.JSON.PathRegexp = ndjsonio.DefaultPathRegexp
		goto next
	}
	if part.FormName() == "shaper_ast" {
		raw, err := ioutil.ReadAll(io.LimitReader(part, maxShaperAstBytes))
		if err != nil {
			return nil, zqe.ErrInvalid("shaper_ast too big")
		}
		proc, err := ast.UnpackJSON(nil, raw)
		if err != nil {
			return nil, err
		}
		m.shaperAST = proc
		goto next
	}
	name := part.FileName()
	counter := &mpcounter{part, &m.nread}
	var zr zbuf.ReadCloser
	zr, err = detector.OpenFromNamedReadCloser(m.zctx, counter, name, m.opts)
	if err != nil {
		part.Close()
		if m.stopErr {
			return nil, err
		}
		m.appendWarning(zr, err)
		goto next
	}
	if m.shaperAST != nil {
		zr, err = driver.NewReader(context.Background(), m.shaperAST, m.zctx, zr)
		if err != nil {
			return nil, err
		}
	}
	return zr, err
}

func (m *MultipartLogReader) appendWarning(zr zbuf.Reader, err error) {
	m.warnings = append(m.warnings, fmt.Sprintf("%s: %s", zr, err))
}

func (m *MultipartLogReader) Warnings() []string {
	return m.warnings
}

func (m *MultipartLogReader) BytesRead() int64 {
	return atomic.LoadInt64(&m.nread)
}

type mpcounter struct {
	*multipart.Part
	nread *int64
}

func (r *mpcounter) Read(b []byte) (int, error) {
	n, err := r.Part.Read(b)
	atomic.AddInt64(r.nread, int64(n))
	return n, err
}
