package fuse

import (
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

func WriteCloser(wc zbuf.WriteCloser, zctx *resolver.Context) zbuf.WriteCloser {
	return &writeCloser{wc, NewFuser(zctx, MemMaxBytes)}
}

type writeCloser struct {
	wc    zbuf.WriteCloser
	fuser *Fuser
}

func (w *writeCloser) Write(rec *zng.Record) error {
	return w.fuser.Write(rec)
}

func (w *writeCloser) Close() error {
	err := zbuf.Copy(w.wc, w.fuser)
	if err2 := w.fuser.Close(); err == nil {
		err = err2
	}
	if err2 := w.wc.Close(); err == nil {
		err = err2
	}
	return err
}
