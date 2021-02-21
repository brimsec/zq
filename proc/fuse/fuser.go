package fuse

import (
	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/expr/agg"
	"github.com/brimsec/zq/proc/rename"
	"github.com/brimsec/zq/proc/spill"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

// Fuser buffers records written to it, assembling from them a unified schema of
// fields and types.  Fuser then transforms those records to the unified schema
// as they are read back from it.
type Fuser struct {
	zctx        *resolver.Context
	memMaxBytes int

	nbytes  int
	recs    []*zng.Record
	spiller *spill.File
	types   map[zng.Type]int

	shaper   *expr.Shaper
	renamers map[int]*rename.Function
}

// NewFuser returns a new Fuser.  The Fuser buffers records in memory until
// their cumulative size (measured in zcode.Bytes length) exceeds memMaxBytes,
// at which point it buffers them in a temporary file.
func NewFuser(zctx *resolver.Context, memMaxBytes int) *Fuser {
	return &Fuser{
		zctx:        zctx,
		memMaxBytes: memMaxBytes,
		types:       make(map[zng.Type]int),
		renamers:    make(map[int]*rename.Function),
	}
}

// Close removes the receiver's temporary file if it created one.
func (f *Fuser) Close() error {
	if f.spiller != nil {
		return f.spiller.CloseAndRemove()
	}
	return nil
}

// Write buffers rec. If called after Read, Write panics.
func (f *Fuser) Write(rec *zng.Record) error {
	if f.finished() {
		panic("fuser: write after read")
	}
	if _, ok := f.types[rec.Type]; !ok {
		f.types[rec.Type] = len(f.types)
	}
	if f.spiller != nil {
		return f.spiller.Write(rec)
	}
	return f.stash(rec)
}

func (f *Fuser) stash(rec *zng.Record) error {
	f.nbytes += len(rec.Raw)
	if f.nbytes >= f.memMaxBytes {
		var err error
		f.spiller, err = spill.NewTempFile()
		if err != nil {
			return err
		}
		for _, rec := range f.recs {
			if err := f.spiller.Write(rec); err != nil {
				return err
			}
		}
		f.recs = nil
		return f.spiller.Write(rec)
	}
	rec = rec.Keep()
	f.recs = append(f.recs, rec)
	return nil
}

func (f *Fuser) finished() bool {
	return f.shaper != nil
}

func (f *Fuser) finish() error {
	uber, err := agg.NewSchema(f.zctx)
	if err != nil {
		return err
	}
	for _, typ := range typesInOrder(f.types) {
		if typ != nil {
			if err = uber.Mixin(zng.AliasedType(typ).(*zng.TypeRecord)); err != nil {
				return err
			}
		}
	}

	f.shaper, err = expr.NewShaperType(f.zctx, &expr.RootRecord{}, uber.Type, expr.Fill|expr.Order)
	if err != nil {
		return err
	}
	for typ, renames := range uber.Renames {
		f.renamers[typ] = rename.NewFunction(f.zctx, renames.Srcs, renames.Dsts)
	}

	if f.spiller != nil {
		return f.spiller.Rewind(f.zctx)
	}
	return nil
}

func typesInOrder(in map[zng.Type]int) []zng.Type {
	if len(in) == 0 {
		return nil
	}
	out := make([]zng.Type, len(in))
	for typ, position := range in {
		out[position] = typ
	}
	return out
}

// Read returns the next buffered record after transforming it to the unified
// schema.
func (f *Fuser) Read() (*zng.Record, error) {
	if !f.finished() {
		if err := f.finish(); err != nil {
			return nil, err
		}
	}
	rec, err := f.next()
	if rec == nil || err != nil {
		return nil, err
	}

	if renamer, ok := f.renamers[rec.Type.ID()]; ok {
		rec, err = renamer.Apply(rec)
		if err != nil {
			return nil, err
		}
	}

	return f.shaper.Apply(rec)
}

func (f *Fuser) next() (*zng.Record, error) {
	if f.spiller != nil {
		return f.spiller.Read()
	}
	var rec *zng.Record
	if len(f.recs) > 0 {
		rec = f.recs[0]
		f.recs = f.recs[1:]
	}
	return rec, nil

}
