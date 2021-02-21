package zson

import (
	"sync"

	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

type TypeTable struct {
	mu      sync.Mutex
	toBytes map[zng.Type]zcode.Bytes
	toType  map[string]zng.Type
	zctx    *resolver.Context
}

func NewTypeTable(zctx *resolver.Context) *TypeTable {
	return &TypeTable{
		toBytes: make(map[zng.Type]zcode.Bytes),
		toType:  make(map[string]zng.Type),
		zctx:    zctx,
	}
}

func (t *TypeTable) enter(typ zng.Type, bytes zcode.Bytes) {
	canonical := typ.ZSON()
	t.toBytes[typ] = zcode.Bytes(canonical)
	// We put both the canonical type string and whatever non-canonical
	// string might have been used in case the non-canonical string is
	// used repeatedly so we don't look it up every time.
	t.toType[canonical] = typ
	t.toType[string(bytes)] = typ
}

func (t *TypeTable) LookupValue(typ zng.Type) zng.Value {
	t.mu.Lock()
	defer t.mu.Unlock()
	bytes, ok := t.toBytes[typ]
	if !ok {
		bytes = zcode.Bytes(typ.ZSON())
		t.enter(typ, bytes)
	}
	return zng.Value{zng.TypeType, bytes}
}

func (t *TypeTable) LookupType(zson string) (zng.Type, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	typ, ok := t.toType[zson]
	if !ok {
		var err error
		typ, err = LookupType(t.zctx, zson)
		if err != nil {
			return nil, err
		}
		t.enter(typ, zcode.Bytes(zson))
	}
	return typ, nil
}
