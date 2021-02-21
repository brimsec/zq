package apiserver

import (
	"context"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/pkg/iosrc"
	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/ppl/lake/immcache"
	"github.com/brimsec/zq/ppl/zqd/auth"
	"github.com/brimsec/zq/ppl/zqd/db"
	"github.com/brimsec/zq/ppl/zqd/db/schema"
	"github.com/brimsec/zq/ppl/zqd/pcapstorage"
	"github.com/brimsec/zq/ppl/zqd/storage"
	"github.com/brimsec/zq/ppl/zqd/storage/archivestore"
	"github.com/brimsec/zq/ppl/zqd/storage/filestore"
	"github.com/brimsec/zq/zqe"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

type Manager struct {
	db         db.DB
	immcache   immcache.ImmutableCache
	logger     *zap.Logger
	notifier   Notifier
	registerer prometheus.Registerer
	rootPath   iosrc.URI

	// We keep instances of any loaded filestore because the seek indexes
	// we create for them are not persisted to disk. We are unlikely to
	// implement persistence, since we intend to use archive based
	// storage by default at some point in the future.
	filestores   map[api.SpaceID]*filestore.Storage
	filestoresMu sync.Mutex

	created prometheus.Counter
	deleted prometheus.Counter
}

type Notifier interface {
	Shutdown()
	SpaceCreated(context.Context, api.SpaceID)
	SpaceDeleted(context.Context, api.SpaceID)
	SpaceWritten(context.Context, api.SpaceID)
}

func NewManager(ctx context.Context, logger *zap.Logger, n Notifier, registerer prometheus.Registerer, root iosrc.URI, db db.DB, icache immcache.ImmutableCache) (*Manager, error) {
	factory := promauto.With(registerer)
	m := &Manager{
		db:         db,
		immcache:   icache,
		logger:     logger.Named("manager"),
		notifier:   n,
		registerer: registerer,
		rootPath:   root,

		filestores: make(map[api.SpaceID]*filestore.Storage),

		created: factory.NewCounter(prometheus.CounterOpts{
			Name: "spaces_created_total",
			Help: "Number of spaces created.",
		}),
		deleted: factory.NewCounter(prometheus.CounterOpts{
			Name: "spaces_deleted_total",
			Help: "Number of spaces deleted.",
		}),
	}
	if m.notifier == nil {
		m.notifier = newCompactor(m)
	}
	m.logger.Info("Loaded", zap.String("root", root.String()))
	return m, nil
}

func (m *Manager) Shutdown() {
	m.notifier.Shutdown()
}

func (m *Manager) CreateSpace(ctx context.Context, req api.SpacePostRequest) (api.Space, error) {
	if req.Name == "" && req.DataPath == "" {
		return api.Space{}, zqe.E(zqe.Invalid, "must supply non-empty name or dataPath")
	}
	if !schema.ValidSpaceName(req.Name) {
		return api.Space{}, zqe.E(zqe.Invalid, "name may not contain '/' or non-printable characters")
	}
	id := schema.NewSpaceID()
	var datapath iosrc.URI
	if req.DataPath == "" {
		datapath = m.rootPath.AppendPath(string(id))
	} else {
		var err error
		datapath, err = iosrc.ParseURI(req.DataPath)
		if err != nil {
			return api.Space{}, err
		}
	}
	if err := iosrc.MkdirAll(datapath, 0777); err != nil {
		return api.Space{}, err
	}
	// If name is not set then derive name from DataPath, removing and
	// replacing invalid characters.
	var retryNameConflict bool
	if req.Name == "" {
		retryNameConflict = true
		req.Name = schema.SafeSpaceName(path.Base(datapath.Path))
	}

	var storecfg api.StorageConfig
	if req.Storage != nil {
		storecfg = *req.Storage
	}
	if storecfg.Kind == api.FileStore && api.FileStoreReadOnly {
		return api.Space{}, zqe.ErrInvalid("file storage space creation is disabled")
	}
	if storecfg.Kind == api.UnknownStore {
		storecfg.Kind = api.DefaultStorageKind()
	}
	if storecfg.Kind == api.FileStore && m.rootPath.Scheme != "file" {
		return api.Space{}, zqe.E(zqe.Invalid, "cannot create file storage space on non-file backed data path")
	}

	ident := auth.IdentityFromContext(ctx)
	row := schema.SpaceRow{
		ID:       id,
		Name:     req.Name,
		DataURI:  datapath,
		Storage:  storecfg,
		TenantID: ident.TenantID,
	}

	name := row.Name
	for i := 1; ; i++ {
		err := m.db.CreateSpace(ctx, row)
		if err == nil {
			break
		}
		if retryNameConflict && zqe.IsConflict(err) {
			row.Name = fmt.Sprintf("%s_%d", name, i)
			continue
		}
		return api.Space{}, err
	}

	m.created.Inc()
	si := rowToSpace(row)
	m.notifier.SpaceCreated(ctx, si.ID)
	return si, nil
}

func (m *Manager) GetStorage(ctx context.Context, id api.SpaceID) (storage.Storage, error) {
	sr, err := m.getSpacePermCheck(ctx, id)
	if err != nil {
		return nil, err
	}
	return m.getStorage(ctx, id, sr.DataURI, sr.Storage)
}

func (m *Manager) GetPcapStorage(ctx context.Context, id api.SpaceID) (*pcapstorage.Store, error) {
	sr, err := m.getSpacePermCheck(ctx, id)
	if err != nil {
		return nil, err
	}
	return m.getPcapStorage(ctx, sr.DataURI)
}

type writeNotifier struct {
	ctx      context.Context // XXX We should pass a context to WriteNotify instead.
	id       api.SpaceID
	notifier Notifier
}

func (w writeNotifier) WriteNotify() {
	w.notifier.SpaceWritten(w.ctx, w.id)
}

func (m *Manager) getStorage(ctx context.Context, id api.SpaceID, daturi iosrc.URI, cfg api.StorageConfig) (storage.Storage, error) {
	switch cfg.Kind {
	case api.FileStore:
		m.filestoresMu.Lock()
		defer m.filestoresMu.Unlock()
		st, ok := m.filestores[id]
		if !ok {
			var err error
			st, err = filestore.Load(daturi, m.logger)
			if err != nil {
				return nil, err
			}
			m.filestores[id] = st
		}
		return st, nil
	case api.ArchiveStore:
		wn := &writeNotifier{ctx, id, m.notifier}
		return archivestore.Load(ctx, daturi, wn, cfg.Archive, m.immcache)
	default:
		return nil, zqe.E(zqe.Invalid, "unknown storage kind: %s", cfg.Kind)
	}
}

func (m *Manager) getPcapStorage(ctx context.Context, datauri iosrc.URI) (*pcapstorage.Store, error) {
	p, err := pcapstorage.Load(ctx, datauri)
	if err != nil {
		if zqe.IsNotFound(err) {
			return pcapstorage.New(datauri), nil
		}
		return nil, err
	}
	return p, err
}

func rowToSpace(row schema.SpaceRow) api.Space {
	return api.Space{
		ID:          row.ID,
		DataPath:    row.DataURI,
		Name:        row.Name,
		StorageKind: row.Storage.Kind,
	}
}

func (m *Manager) rowToSpaceInfo(ctx context.Context, sr schema.SpaceRow) (api.SpaceInfo, error) {
	spaceInfo := api.SpaceInfo{Space: rowToSpace(sr)}

	store, err := m.getStorage(ctx, sr.ID, sr.DataURI, sr.Storage)
	if err != nil {
		return api.SpaceInfo{}, err
	}
	sum, err := store.Summary(ctx)
	if err != nil {
		return api.SpaceInfo{}, err
	}
	var span *nano.Span
	if sum.Span.Dur > 0 {
		span = &sum.Span
	}
	spaceInfo.Span = span
	spaceInfo.StorageKind = sum.Kind
	spaceInfo.Size = sum.DataBytes

	pcapstore, err := m.getPcapStorage(ctx, sr.DataURI)
	if err != nil {
		return api.SpaceInfo{}, err
	}
	if !pcapstore.Empty() {
		pcapinfo, err := pcapstore.Info(ctx)
		if err != nil {
			if !zqe.IsNotFound(err) {
				return api.SpaceInfo{}, err
			}
		} else {
			spaceInfo.PcapSize = pcapinfo.PcapSize
			spaceInfo.PcapSupport = true
			spaceInfo.PcapPath = pcapinfo.PcapURI
			if span == nil {
				span = &pcapinfo.Span
			} else {
				union := span.Union(pcapinfo.Span)
				span = &union
			}
			spaceInfo.Span = span
		}
	}

	return spaceInfo, nil
}

func (m *Manager) getSpacePermCheck(ctx context.Context, id api.SpaceID) (schema.SpaceRow, error) {
	sr, err := m.db.GetSpace(ctx, id)
	if err != nil {
		return schema.SpaceRow{}, err
	}
	ident := auth.IdentityFromContext(ctx)
	if sr.TenantID != ident.TenantID {
		return schema.SpaceRow{}, zqe.ErrForbidden()
	}
	return sr, nil
}

func (m *Manager) GetSpace(ctx context.Context, id api.SpaceID) (api.SpaceInfo, error) {
	sr, err := m.getSpacePermCheck(ctx, id)
	if err != nil {
		return api.SpaceInfo{}, err
	}
	return m.rowToSpaceInfo(ctx, sr)
}

func (m *Manager) ListSpaces(ctx context.Context) ([]api.Space, error) {
	ident := auth.IdentityFromContext(ctx)
	rows, err := m.db.ListSpaces(ctx, ident.TenantID)
	if err != nil {
		return nil, err
	}
	res := make([]api.Space, 0, len(rows))
	for _, row := range rows {
		res = append(res, rowToSpace(row))
	}
	return res, nil
}

func (m *Manager) UpdateSpaceName(ctx context.Context, id api.SpaceID, name string) error {
	if name == "" {
		return zqe.E(zqe.Invalid, "cannot set name to an empty string")
	}
	if !schema.ValidSpaceName(name) {
		return zqe.E(zqe.Invalid, "name may not contain '/' or non-printable characters")
	}
	if _, err := m.getSpacePermCheck(ctx, id); err != nil {
		return err
	}
	return m.db.UpdateSpaceName(ctx, id, name)
}

func (m *Manager) DeleteSpace(ctx context.Context, id api.SpaceID) error {
	sr, err := m.getSpacePermCheck(ctx, id)
	if err != nil {
		return err
	}
	if err := m.db.DeleteSpace(ctx, id); err != nil {
		return err
	}
	if sr.Storage.Kind == api.FileStore {
		m.filestoresMu.Lock()
		delete(m.filestores, id)
		m.filestoresMu.Unlock()
	}
	if err := iosrc.RemoveAll(ctx, sr.DataURI); err != nil {
		return err
	}
	m.deleted.Inc()
	m.notifier.SpaceDeleted(ctx, id)
	return nil
}

func (m *Manager) Compact(ctx context.Context, id api.SpaceID) error {
	return m.withArchiveStorage(ctx, id, "Compact", func(s *archivestore.Storage, l *zap.Logger) error {
		return s.Compact(ctx, l)
	})
}

func (m *Manager) Purge(ctx context.Context, id api.SpaceID) error {
	return m.withArchiveStorage(ctx, id, "Purge", func(s *archivestore.Storage, l *zap.Logger) error {
		return s.Purge(ctx, l)
	})
}

type withArchiveStoreFunc func(*archivestore.Storage, *zap.Logger) error

func (m *Manager) withArchiveStorage(ctx context.Context, id api.SpaceID, op string, f withArchiveStoreFunc) error {
	l := m.logger.With(zap.Stringer("space_id", id))
	s, err := m.GetStorage(ctx, id)
	if err != nil {
		l.Warn(op+" failed", zap.Error(err))
		return err
	}
	as, ok := s.(*archivestore.Storage)
	if !ok {
		return nil
	}
	l.Info(op + " started")
	start := time.Now()
	if err := f(as, l); err != nil {
		if err == context.Canceled {
			l.Info(op + " canceled")
		} else {
			l.Warn(op+" failed", zap.Error(err))
		}
		return err
	}
	l.Info(op+" completed", zap.Duration("duration", time.Since(start)))
	return nil
}
