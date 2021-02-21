package apiserver

import (
	"context"
	"sync"
	"time"

	"github.com/brimsec/zq/api"
	"golang.org/x/sync/semaphore"
)

type compactor struct {
	cancel      context.CancelFunc
	done        sync.WaitGroup
	manager     *Manager
	notify      chan api.SpaceID
	compactDone chan api.SpaceID
	sem         *semaphore.Weighted
}

const maxConcurrentCompacts = 1

func newCompactor(manager *Manager) *compactor {
	ctx, cancel := context.WithCancel(context.Background())
	c := &compactor{
		cancel:      cancel,
		manager:     manager,
		notify:      make(chan api.SpaceID),
		compactDone: make(chan api.SpaceID),
		sem:         semaphore.NewWeighted(maxConcurrentCompacts),
	}
	c.done.Add(1)
	go func() {
		c.run(ctx)
		c.done.Done()
	}()
	return c
}

func (c *compactor) SpaceCreated(ctx context.Context, id api.SpaceID) {}

func (c *compactor) SpaceDeleted(ctx context.Context, id api.SpaceID) {}

func (c *compactor) SpaceWritten(ctx context.Context, id api.SpaceID) {
	select {
	case c.notify <- id:
	case <-ctx.Done():
	}
}

func (c *compactor) launchCompact(ctx context.Context, id api.SpaceID) {
	go func() {
		if err := c.sem.Acquire(ctx, 1); err != nil {
			return
		}
		if c.manager.Compact(ctx, id) == nil {
			// Wait for one minute before doing purge. This delay is here to prevent
			// the case where a directory listing of chunks is made for search, the tsdir is
			// compacted and purged, then the search attempts to read a deleted chunk from
			// its now stale directory listing.
			// This is a stopgap solution to this problem; a more robust solution
			// should be architected and implemented.
			select {
			case <-time.After(time.Second * 60):
				c.manager.Purge(ctx, id)
			case <-ctx.Done():
			}
		}
		c.sem.Release(1)
		c.compactDone <- id
	}()
}

func (c *compactor) run(ctx context.Context) {
	active := make(map[api.SpaceID]bool)
	for {
		select {
		case id := <-c.notify:
			if _, ok := active[id]; !ok {
				// No compaction active for this space right now.
				active[id] = false
				c.launchCompact(ctx, id)
				continue
			}
			// When the current compaction is done, start another.
			active[id] = true
		case id := <-c.compactDone:
			if active[id] {
				active[id] = false
				c.launchCompact(ctx, id)
				continue
			}
			delete(active, id)
		case <-ctx.Done():
			return
		}
	}
}

func (c *compactor) Shutdown() {
	close(c.notify)
	c.cancel()
	c.done.Wait()
}
