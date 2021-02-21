package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/driver"
	"github.com/brimsec/zq/pkg/iosrc"
	"github.com/brimsec/zq/ppl/zqd/storage"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/detector"
	"github.com/brimsec/zq/zio/ndjsonio"
	"github.com/brimsec/zq/zio/zngio"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zqe"
)

var (
	ErrNoLogIngestSupport = errors.New("space does not support log ingest")
)

type LogOp struct {
	bytesTotal   int64
	warnings     []string
	readers      []zbuf.Reader
	readCounters []*readCounter
	err          error

	warningCh chan string
	zctx      *resolver.Context
}

// Logs ingests the provided list of files into the provided space.
// Like ingest.Pcap, this overwrites any existing data in the space.
func NewLogOp(ctx context.Context, store storage.Storage, req api.LogPostRequest) (*LogOp, error) {
	p := &LogOp{
		warningCh: make(chan string, 5),
		warnings:  make([]string, 0, 5),
		zctx:      resolver.NewContext(),
	}
	opts := zio.ReaderOpts{Zng: zngio.ReaderOpts{Validate: true}}
	//XXX if there is a json config, then the input has to be ndjson
	// and we shouldn't be using the detector.  down the line, when
	// we more holistically support json ingest, there should probably
	// be a different endpoint or other params here which might select
	// the input rules by a named configuration
	if req.JSONTypeConfig != nil {
		opts.JSON.TypeConfig = req.JSONTypeConfig
		opts.JSON.PathRegexp = ndjsonio.DefaultPathRegexp
	}
	proc, err := ast.UnpackJSON(nil, req.Shaper)
	if err != nil {
		return nil, err
	}
	for _, path := range req.Paths {
		rc, size, err := openIncomingLog(ctx, path)
		if err != nil {
			p.closeFiles()
			return nil, err
		}
		sf, err := detector.OpenFromNamedReadCloser(p.zctx, rc, path, opts)
		if err != nil {
			rc.Close()
			if req.StopErr {
				p.closeFiles()
				return nil, err
			}
			p.openWarning(path, err)
			continue
		}
		zr := zbuf.NewWarningReader(sf, p)

		p.bytesTotal += size
		p.readCounters = append(p.readCounters, rc)

		if proc != nil {
			zr, err = driver.NewReader(ctx, proc, p.zctx, zr)
			if err != nil {
				return nil, err
			}
		}
		p.readers = append(p.readers, zr)
	}
	// this is the only goroutine that calls p.Warn()
	go p.start(ctx, store)
	return p, nil
}

func (p *LogOp) Warn(msg string) error {
	// warnings received before we've started our goroutine are
	// saved here and will be drained in start()
	if p.warnings != nil {
		p.warnings = append(p.warnings, msg)
		return nil
	}
	p.warningCh <- msg
	return nil
}

func (p *LogOp) openWarning(path string, err error) {
	p.Warn(fmt.Sprintf("%s: %s", path, err))
}

type readCounter struct {
	readCloser io.ReadCloser
	nread      int64
}

func (rc *readCounter) Read(p []byte) (int, error) {
	n, err := rc.readCloser.Read(p)
	atomic.AddInt64(&rc.nread, int64(n))
	return n, err
}

func (rc *readCounter) bytesRead() int64 {
	return atomic.LoadInt64(&rc.nread)
}

func (rc *readCounter) Close() error {
	return rc.readCloser.Close()
}

func openIncomingLog(ctx context.Context, path string) (*readCounter, int64, error) {
	uri, err := iosrc.ParseURI(path)
	if err != nil {
		return nil, 0, err
	}
	info, err := iosrc.Stat(ctx, uri)
	if err != nil {
		return nil, 0, err
	}
	if info.IsDir() {
		return nil, 0, zqe.E(zqe.Invalid, "path is a directory")
	}
	rc, err := iosrc.NewReader(ctx, uri)
	if err != nil {
		return nil, 0, err
	}
	return &readCounter{readCloser: rc}, info.Size(), nil
}

func (p *LogOp) closeFiles() error {
	var retErr error
	for _, rc := range p.readCounters {
		if err := rc.Close(); err != nil {
			retErr = err
		}
	}
	return retErr
}

func (p *LogOp) bytesRead() int64 {
	var read int64
	for _, rc := range p.readCounters {
		read += rc.bytesRead()
	}
	return read
}

func (p *LogOp) start(ctx context.Context, store storage.Storage) {
	// first drain warnings
	for _, warning := range p.warnings {
		p.warningCh <- warning
	}
	p.warnings = nil

	defer zbuf.CloseReaders(p.readers)
	reader, _ := zbuf.MergeReadersByTsAsReader(ctx, p.readers, store.NativeOrder())
	p.err = store.Write(ctx, p.zctx, reader)
	if err := p.closeFiles(); err != nil && p.err != nil {
		p.err = err
	}
	close(p.warningCh)
}

func (p *LogOp) Stats() api.LogPostStatus {
	return api.LogPostStatus{
		Type:         "LogPostStatus",
		LogTotalSize: p.bytesTotal,
		LogReadSize:  p.bytesRead(),
	}
}

func (p *LogOp) Status() <-chan string {
	return p.warningCh
}

// Error indicates what if any error occurred during import, after the
// Status channel is closed.  The result is undefined while Status is open.
func (p *LogOp) Error() error {
	return p.err
}
