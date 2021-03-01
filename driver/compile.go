package driver

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/brimsec/zq/compiler"
	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/compiler/kernel"
	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/ppl/zqd/worker"
	"github.com/brimsec/zq/proc"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng/resolver"
	"go.uber.org/zap"
)

// XXX ReaderSortKey should be a field.Static.  Issue #1467.
type Config struct {
	Custom            kernel.Hook
	Logger            *zap.Logger
	ReaderSortKey     string
	ReaderSortReverse bool
	Span              nano.Span
	StatsTick         <-chan time.Time
}

type scannerProc struct {
	zbuf.Scanner
}

func (s *scannerProc) Done() {}

type namedScanner struct {
	zbuf.Scanner
	name string
}

func (n *namedScanner) Pull() (zbuf.Batch, error) {
	b, err := n.Scanner.Pull()
	if err != nil {
		err = fmt.Errorf("%s: %w", n.name, err)
	}
	return b, err
}

func compile(ctx context.Context, program ast.Proc, zctx *resolver.Context, readers []zbuf.Reader, cfg Config) (*muxOutput, error) {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if cfg.Span.Dur == 0 {
		cfg.Span = nano.MaxSpan
	}
	runtime, err := compiler.New(zctx, program)
	if err != nil {
		return nil, err
	}
	if err := runtime.Optimize(); err != nil {
		return nil, err
	}
	//XXX we need to compile the flowgraph before we can create the scanners
	// because the scanners create filters which can depend on the dynamic
	// scope of the compiled results.  So, we need to compile to a single
	// proc entry point, then after the compilation is done, we can wire
	// multiple scanners to the runtime object.

	procs := make([]proc.Interface, 0, len(readers))
	scanners := make([]zbuf.Scanner, 0, len(readers))
	for _, r := range readers {
		sn, err := zbuf.NewScanner(ctx, r, runtime, cfg.Span)
		if err != nil {
			return nil, err
		}
		if stringer, ok := r.(fmt.Stringer); ok {
			sn = &namedScanner{sn, stringer.String()}
		}
		scanners = append(scanners, sn)
		procs = append(procs, &scannerProc{sn})
	}

	pctx := &proc.Context{
		Context:     ctx,
		TypeContext: zctx,
		Logger:      cfg.Logger,
		Warnings:    make(chan string, 5),
	}
	if err := runtime.Compile(cfg.Custom, pctx, procs); err != nil {
		return nil, err
	}
	return newMuxOutput(pctx, runtime.Outputs(), zbuf.MultiStats(scanners)), nil
}

type MultiConfig struct {
	Custom      kernel.Hook
	Distributed bool // true if remote request specified worker count
	Order       zbuf.Order
	Logger      *zap.Logger
	Parallelism int
	Span        nano.Span
	StatsTick   <-chan time.Time
	Worker      worker.WorkerConfig
}

func compileMulti(ctx context.Context, program ast.Proc, zctx *resolver.Context, msrc MultiSource, mcfg MultiConfig) (*muxOutput, error) {
	if mcfg.Logger == nil {
		mcfg.Logger = zap.NewNop()
	}
	if mcfg.Span.Dur == 0 {
		mcfg.Span = nano.MaxSpan
	}
	if mcfg.Parallelism == 0 {
		mcfg.Parallelism = runtime.GOMAXPROCS(0)
	}

	sortKey, sortReversed := msrc.OrderInfo()
	runtime, err := compiler.NewWithSortedInput(zctx, program, sortKey, sortReversed)
	if err != nil {
		return nil, err
	}
	if err := runtime.Optimize(); err != nil {
		return nil, err
	}
	if !runtime.IsParallelizable() {
		mcfg.Parallelism = 1
	}
	pctx := &proc.Context{
		Context:     ctx,
		TypeContext: zctx,
		Logger:      mcfg.Logger,
		Warnings:    make(chan string, 5),
	}
	sources, pgroup, err := createParallelGroup(pctx, runtime, msrc, mcfg)
	if err != nil {
		return nil, err
	}
	if len(sources) > 1 {
		runtime.Parallelize(len(sources))
	}
	if err := runtime.Compile(mcfg.Custom, pctx, sources); err != nil {
		return nil, err
	}
	return newMuxOutput(pctx, runtime.Outputs(), pgroup), nil
}
