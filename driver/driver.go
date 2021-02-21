package driver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

type Driver interface {
	Warn(msg string) error
	Write(channelID int, batch zbuf.Batch) error
	ChannelEnd(channelID int) error
	Stats(api.ScannerStats) error
}

func Run(ctx context.Context, d Driver, program ast.Proc, zctx *resolver.Context, reader zbuf.Reader, cfg Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux, err := compile(ctx, program, zctx, []zbuf.Reader{reader}, cfg)
	if err != nil {
		return err
	}
	return runMux(mux, d, cfg.StatsTick)
}

func RunParallel(ctx context.Context, d Driver, program ast.Proc, zctx *resolver.Context, readers []zbuf.Reader, cfg Config) error {
	if len(readers) != ast.FanIn(program) {
		return errors.New("number of input sources must match number of parallel inputs in zql query")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux, err := compile(ctx, program, zctx, readers, cfg)
	if err != nil {
		return err
	}
	return runMux(mux, d, cfg.StatsTick)
}

func MultiRun(ctx context.Context, d Driver, program ast.Proc, zctx *resolver.Context, msrc MultiSource, mcfg MultiConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux, err := compileMulti(ctx, program, zctx, msrc, mcfg)
	if err != nil {
		return err
	}
	return runMux(mux, d, mcfg.StatsTick)
}

func runMux(out *muxOutput, d Driver, statsTickCh <-chan time.Time) error {
	for !out.Complete() {
		chunk := out.Pull(statsTickCh)
		if chunk.Err != nil {
			if chunk.Err == errTimeout {
				if err := d.Stats(out.Stats()); err != nil {
					return err
				}
				continue
			}
			if chunk.Err == context.Canceled {
				out.Drain()
			}
			return chunk.Err
		}
		if chunk.Warning != "" {
			if err := d.Warn(chunk.Warning); err != nil {
				return err
			}
		}
		if chunk.Batch == nil {
			// One of the flowgraph tails is done.
			if err := d.ChannelEnd(chunk.ID); err != nil {
				return err
			}
		} else {
			if err := d.Write(chunk.ID, chunk.Batch); err != nil {
				return err
			}
		}
	}
	if statsTickCh != nil {
		return d.Stats(out.Stats())
	}
	return nil
}

// CLI implements Driver.
type CLI struct {
	writers  []zbuf.Writer
	warnings io.Writer
}

func NewCLI(w ...zbuf.Writer) *CLI {
	return &CLI{
		writers: w,
	}
}

func (d *CLI) SetWarningsWriter(w io.Writer) {
	d.warnings = w
}

func (d *CLI) Write(cid int, batch zbuf.Batch) error {
	if len(d.writers) == 1 {
		cid = 0
	}
	for _, r := range batch.Records() {
		if err := d.writers[cid].Write(r); err != nil {
			return err
		}
	}
	batch.Unref()
	return nil
}

func (d *CLI) Warn(msg string) error {
	if d.warnings != nil {
		if _, err := fmt.Fprintln(d.warnings, msg); err != nil {
			return err
		}
	}
	return nil
}

func (d *CLI) ChannelEnd(int) error         { return nil }
func (d *CLI) Stats(api.ScannerStats) error { return nil }

type transformDriver struct {
	w zbuf.Writer
}

func (d *transformDriver) Write(cid int, batch zbuf.Batch) error {
	if cid != 0 {
		return errors.New("transform proc with multiple tails")
	}
	for i := 0; i < batch.Length(); i++ {
		if err := d.w.Write(batch.Index(i)); err != nil {
			return err
		}
	}
	batch.Unref()
	return nil
}

func (d *transformDriver) Warn(warning string) error          { return nil }
func (d *transformDriver) Stats(stats api.ScannerStats) error { return nil }
func (d *transformDriver) ChannelEnd(cid int) error           { return nil }

// Copy applies a proc to all records from a zbuf.Reader, writing to a
// single zbuf.Writer. The proc must have a single tail.
func Copy(ctx context.Context, w zbuf.Writer, prog ast.Proc, zctx *resolver.Context, r zbuf.Reader, cfg Config) error {
	d := &transformDriver{w: w}
	return Run(ctx, d, prog, zctx, r, cfg)
}

type muxReader struct {
	*muxOutput
	batch       zbuf.Batch
	cancel      context.CancelFunc
	index       int
	statsTickCh <-chan time.Time
	zr          io.Closer
}

func (mr *muxReader) Read() (*zng.Record, error) {
read:
	if mr.batch == nil {
		chunk := mr.Pull(mr.statsTickCh)
		if chunk.ID != 0 {
			return nil, errors.New("transform proc with multiple tails")
		}
		if chunk.Batch != nil {
			mr.batch = chunk.Batch
		} else if chunk.Err != nil {
			return nil, chunk.Err
		} else if chunk.Warning != "" {
			goto read
		} else {
			return nil, nil
		}
	}
	if mr.index >= mr.batch.Length() {
		mr.batch.Unref()
		mr.batch, mr.index = nil, 0
		goto read
	}
	rec := mr.batch.Index(mr.index)
	mr.index++
	return rec, nil
}

func (mr *muxReader) Close() error {
	mr.cancel()
	return mr.zr.Close()
}

func NewReader(ctx context.Context, program ast.Proc, zctx *resolver.Context, reader zbuf.Reader) (zbuf.ReadCloser, error) {
	return NewReaderWithConfig(ctx, Config{}, program, zctx, reader)
}

func NewReaderWithConfig(ctx context.Context, conf Config, program ast.Proc, zctx *resolver.Context, reader zbuf.Reader) (zbuf.ReadCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	mux, err := compile(ctx, program, zctx, []zbuf.Reader{reader}, conf)
	if err != nil {
		cancel()
		return nil, err
	}
	mr := &muxReader{
		cancel:      cancel,
		muxOutput:   mux,
		statsTickCh: make(chan time.Time),
		zr:          ioutil.NopCloser(nil),
	}
	if _, ok := reader.(io.Closer); ok {
		mr.zr = reader.(io.Closer)
	}
	return mr, nil
}
