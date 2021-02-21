package archivestore

import (
	"context"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/driver"
	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/pkg/iosrc"
	"github.com/brimsec/zq/ppl/lake"
	"github.com/brimsec/zq/ppl/lake/chunk"
	"github.com/brimsec/zq/ppl/lake/immcache"
	"github.com/brimsec/zq/ppl/lake/index"
	"github.com/brimsec/zq/ppl/zqd/storage"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zqe"
	"go.uber.org/zap"
)

func Load(ctx context.Context, path iosrc.URI, notifier WriteNotifier, cfg *api.ArchiveConfig, immcache immcache.ImmutableCache) (*Storage, error) {
	co := &lake.CreateOptions{}
	if cfg != nil && cfg.CreateOptions != nil {
		co.LogSizeThreshold = cfg.CreateOptions.LogSizeThreshold
	}
	oo := &lake.OpenOptions{
		ImmutableCache: immcache,
	}
	lk, err := lake.CreateOrOpenLakeWithContext(ctx, path.String(), co, oo)
	if err != nil {
		return nil, err
	}
	return &Storage{
		lk:       lk,
		notifier: notifier,
	}, nil
}

type WriteNotifier interface {
	WriteNotify()
}

type Storage struct {
	lk       *lake.Lake
	notifier WriteNotifier
}

func NewStorage(lk *lake.Lake) *Storage {
	return &Storage{lk: lk}
}

func (s *Storage) Kind() api.StorageKind {
	return api.ArchiveStore
}

func (s *Storage) NativeOrder() zbuf.Order {
	return s.lk.DataOrder
}

func (s *Storage) MultiSource() driver.MultiSource {
	return lake.NewMultiSource(s.lk, nil)
}

func (s *Storage) StaticSource(src driver.Source) driver.MultiSource {
	return lake.NewStaticSource(s.lk, src)
}

func (s *Storage) Summary(ctx context.Context) (storage.Summary, error) {
	var sum storage.Summary
	sum.Kind = api.ArchiveStore
	err := lake.Walk(ctx, s.lk, func(chunk chunk.Chunk) error {
		info, err := iosrc.Stat(ctx, chunk.Path())
		if err != nil {
			return err
		}
		sum.DataBytes += info.Size()
		sum.RecordCount += int64(chunk.RecordCount)
		if sum.Span.Dur == 0 {
			sum.Span = chunk.Span()
		} else {
			sum.Span = sum.Span.Union(chunk.Span())
		}
		return nil
	})
	return sum, err
}

func (s *Storage) Write(ctx context.Context, zctx *resolver.Context, zr zbuf.Reader) error {
	err := lake.Import(ctx, s.lk, zctx, zr)
	if s.notifier != nil {
		s.notifier.WriteNotify()
	}
	return err
}

type Writer struct {
	*lake.Writer
	notifier WriteNotifier
}

func (w *Writer) Close() error {
	err := w.Writer.Close()
	if w.notifier != nil {
		w.notifier.WriteNotify()
	}
	return err
}

// NewWriter returns a writer that will start a compaction when it is closed.
func (s *Storage) NewWriter(ctx context.Context) (*Writer, error) {
	w, err := lake.NewWriter(ctx, s.lk)
	if err != nil {
		return nil, err
	}
	return &Writer{w, s.notifier}, nil
}

func (s *Storage) IndexCreate(ctx context.Context, req api.IndexPostRequest) error {
	var rules []index.Rule
	if req.ZQL != "" {
		// XXX
		// XXX IndexPostRequest.Keys hould take a []field.Static or
		// new api.Field type rather than assume embedded "." works
		// as a field separator.  Issue #1463.
		var fields []field.Static
		for _, key := range req.Keys {
			fields = append(fields, field.Dotted(key))
		}
		rule, err := index.NewZqlRule(req.ZQL, req.OutputFile, fields)
		if err != nil {
			return zqe.E(zqe.Invalid, err)
		}
		rule.Input = req.InputFile
		rules = append(rules, rule)
	}
	for _, pattern := range req.Patterns {
		rule, err := index.NewRule(pattern)
		if err != nil {
			return zqe.E(zqe.Invalid, err)
		}
		rule.Input = req.InputFile
		rules = append(rules, rule)
	}
	// XXX Eventually this method should provide progress updates.
	return lake.ApplyRules(ctx, s.lk, nil, rules...)
}

func (s *Storage) IndexSearch(ctx context.Context, zctx *resolver.Context, query index.Query) (zbuf.ReadCloser, error) {
	return lake.FindReadCloser(ctx, zctx, s.lk, query, lake.AddPath(lake.DefaultAddPathField, false))
}

func (s *Storage) ArchiveStat(ctx context.Context, zctx *resolver.Context) (zbuf.ReadCloser, error) {
	return lake.Stat(ctx, zctx, s.lk)
}

func (s *Storage) Compact(ctx context.Context, logger *zap.Logger) error {
	return lake.Compact(ctx, s.lk, logger)
}

func (s *Storage) Purge(ctx context.Context, logger *zap.Logger) error {
	return lake.Purge(ctx, s.lk, logger)
}
