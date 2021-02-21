package lake

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/brimsec/zq/pkg/iosrc"
	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/ppl/lake/chunk"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zqe"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

const (
	dataDirname = "zd"
	zarExt      = ".zar"
)

// A tsDir is a directory found in the "<DataPath>/zd" directory of the archive,
// and holds all of the data & associated files for a span of time, currently
// fixed to a single day.
type tsDir struct {
	nano.Span
}

func newTsDir(ts nano.Ts) tsDir {
	return tsDir{nano.Span{Ts: ts.Midnight(), Dur: nano.Day}}
}

func parseTsDirName(name string) (tsDir, bool) {
	t, err := time.Parse("20060102", name)
	if err != nil {
		return tsDir{}, false
	}
	return newTsDir(nano.TimeToTs(t)), true
}

func (t tsDir) path(lk *Lake) iosrc.URI {
	return lk.DataPath.AppendPath(dataDirname, t.name())
}

func (t tsDir) name() string {
	return t.Ts.Time().Format("20060102")
}

type tsDirVisitor func(tsd tsDir, unsortedChunks []chunk.Chunk) error

// tsDirVisit calls visitor for each tsDir whose span overlaps with the
// given span. tsDirs are visited in the archive's order, but the
// chunks passed to visitor are not sorted.
func tsDirVisit(ctx context.Context, lk *Lake, filterSpan nano.Span, visitor tsDirVisitor) error {
	zdDir := lk.DataPath.AppendPath(dataDirname)
	dirents, err := iosrc.ReadDir(ctx, zdDir)
	if err != nil {
		return err
	}
	var tsdirs []tsDir
	for _, e := range dirents {
		if !e.IsDir() {
			continue
		}
		tsd, ok := parseTsDirName(e.Name())
		if !ok || !tsd.Overlaps(filterSpan) {
			continue
		}
		tsdirs = append(tsdirs, tsd)
	}
	sort.Slice(tsdirs, func(i, j int) bool {
		if lk.DataOrder == zbuf.OrderAsc {
			return tsdirs[i].Ts < tsdirs[j].Ts
		}
		return tsdirs[j].Ts < tsdirs[i].Ts
	})
	for _, d := range tsdirs {
		dirents, err := iosrc.ReadDir(ctx, zdDir.AppendPath(d.name()))
		if err != nil {
			return err
		}
		chunks, err := tsDirEntriesToChunks(ctx, lk, d, dirents)
		if err != nil {
			return err
		}
		chunks = chunks.Overlapping(filterSpan)
		if err := visitor(d, chunks); err != nil {
			return err
		}
	}
	return nil
}

func tsDirEntriesToChunks(ctx context.Context, lk *Lake, tsDir tsDir, entries []iosrc.Info) (chunk.Chunks, error) {
	type seen struct {
		data bool
		meta bool
	}
	m := make(map[ksuid.KSUID]seen)
	for _, e := range entries {
		if kind, id, ok := chunk.FileMatch(e.Name()); ok {
			if !lk.filterAllowed(id) {
				continue
			}
			s := m[id]
			switch kind {
			case chunk.FileKindData:
				s.data = true
			case chunk.FileKindMetadata:
				s.meta = true
			}
			m[id] = s
		}
	}

	var mu sync.Mutex
	chunks := make([]chunk.Chunk, 0, len(m))
	group, ctx := errgroup.WithContext(ctx)

	for id, seen := range m {
		if !seen.meta || !seen.data {
			continue
		}
		id := id
		group.Go(func() error {
			dir := tsDir.path(lk)
			mdPath := chunk.MetadataPath(dir, id)
			b, err := lk.immfiles.ReadFile(ctx, mdPath)
			if err != nil {
				if zqe.IsNotFound(err) {
					return nil
				}
				return fmt.Errorf("failed to read chunk metadata from %v: %w", mdPath, err)
			}

			md, err := chunk.UnmarshalMetadata(b, lk.DataOrder)
			if err != nil {
				return err
			}

			mu.Lock()
			chunks = append(chunks, md.Chunk(dir, id))
			mu.Unlock()
			return nil
		})
	}

	// Wait for goroutines before accessing chunks to avoid a race condition.
	err := group.Wait()
	return chunks, err
}

type Visitor func(chunk chunk.Chunk) error

// Walk calls visitor for every data chunk in the archive.
func Walk(ctx context.Context, lk *Lake, v Visitor) error {
	return tsDirVisit(ctx, lk, nano.MaxSpan, func(_ tsDir, chunks []chunk.Chunk) error {
		chunk.Sort(lk.DataOrder, chunks)
		for _, c := range chunks {
			if err := iosrc.MkdirAll(c.ZarDir(), 0700); err != nil {
				return err
			}
			if err := v(c); err != nil {
				return err
			}
		}
		return nil
	})
}

// RmDirs descends a directory hierarchy looking for zar dirs and remove
// each such directory and all of its contents.
func RmDirs(ctx context.Context, lk *Lake) error {
	return Walk(ctx, lk, func(chunk chunk.Chunk) error {
		return iosrc.RemoveAll(ctx, chunk.ZarDir())
	})
}

// A SpanInfo is a logical view of the records within a time span, stored
// in one or more Chunks.
type SpanInfo struct {
	Span nano.Span

	// Chunks are the data files that contain records within this SpanInfo.
	// The Chunks may have spans that extend beyond this SpanInfo, so any
	// records from these Chunks should be limited to those that fall within
	// this SpanInfo's Span.
	Chunks []chunk.Chunk
}

func (s SpanInfo) ChunkRange(order zbuf.Order, chunkIdx int) string {
	first, last := spanToFirstLast(order, s.Span)
	c := s.Chunks[chunkIdx]
	return fmt.Sprintf("[%d-%d,%d-%d]", first, last, c.First, c.Last)
}

func (s SpanInfo) Range(order zbuf.Order) string {
	first, last := spanToFirstLast(order, s.Span)
	return fmt.Sprintf("[%d-%d]", first, last)
}

func (si *SpanInfo) RemoveMasked() []chunk.Chunk {
	if len(si.Chunks) == 1 {
		return nil
	}
	var maskIds []ksuid.KSUID
	for _, c := range si.Chunks {
		for _, mid := range c.Masks {
			maskIds = append(maskIds, mid)
		}
	}
	if len(maskIds) == 0 {
		return nil
	}
	var chunks, removed []chunk.Chunk
	for _, c := range si.Chunks {
		var masked bool
		for _, mid := range maskIds {
			if mid == c.Id {
				masked = true
				removed = append(removed, c)
				break
			}
		}
		if !masked {
			chunks = append(chunks, c)
		}
	}
	// No need to sort chunks since we perform the mask removal in-order.
	si.Chunks = chunks
	return removed
}

// SpanWalk calls visitor with each SpanInfo within the filter span.
func SpanWalk(ctx context.Context, lk *Lake, filter nano.Span, visitor func(si SpanInfo) error) error {
	return tsDirVisit(ctx, lk, filter, func(_ tsDir, chunks []chunk.Chunk) error {
		sinfos := mergeChunksToSpans(chunks, lk.DataOrder, filter)
		for _, s := range sinfos {
			for _, c := range s.Chunks {
				if err := iosrc.MkdirAll(c.ZarDir(), 0700); err != nil {
					return err
				}
			}
			if err := visitor(s); err != nil {
				return err
			}
		}
		return nil
	})
}
