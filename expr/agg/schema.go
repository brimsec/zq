package agg

import (
	"fmt"
	"regexp"

	"github.com/brimsec/zq/field"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

type Renames struct{ Srcs, Dsts []field.Static }

// A fuse schema holds the fused type as well as a per-input-type
// rename specification. The latter is needed when input types have
// name collisions on fields of different types.
type Schema struct {
	zctx    *resolver.Context
	Type    *zng.TypeRecord
	Renames map[int]Renames
	unify   bool
}

func NewSchema(zctx *resolver.Context) (*Schema, error) {
	empty, err := zctx.LookupTypeRecord([]zng.Column{})
	if err != nil {
		return nil, err
	}
	return &Schema{
		zctx:    zctx,
		Type:    empty,
		Renames: make(map[int]Renames),
	}, nil
}

func (s *Schema) Mixin(mix *zng.TypeRecord) error {
	fused, renames, err := s.fuseRecordTypes(s.Type, mix, field.NewRoot(), Renames{})
	if err != nil {
		return err
	}

	s.Type = fused
	s.Renames[mix.ID()] = renames
	return nil
}

func disambiguate(cols []zng.Column, name string) string {
	n := 1
	re := regexp.MustCompile(name + `_(\d+)$`)
	for _, col := range cols {
		if col.Name == name || re.MatchString(col.Name) {
			n++
		}
	}
	if n == 1 {
		return name
	}
	return fmt.Sprintf("%s_%d", name, n)
}

func unify(zctx *resolver.Context, t, u zng.Type) zng.Type {
	tIsUnion := zng.IsUnionType(t)
	uIsUnion := zng.IsUnionType(u)
	switch {
	case tIsUnion && !uIsUnion:
		found := false
		list := t.(*zng.TypeUnion).Types
		for _, t := range list {
			if u == t {
				found = true
			}
		}
		if !found {
			list = append(list, u)
		}
		return zctx.LookupTypeUnion(list)
	case !tIsUnion && !uIsUnion:
		return zctx.LookupTypeUnion([]zng.Type{t, u})
	case tIsUnion && uIsUnion:
		list := t.(*zng.TypeUnion).Types
		for _, u := range u.(*zng.TypeUnion).Types {
			found := false
			for _, t := range list {
				if u == t {
					found = true
				}
			}
			if !found {
				list = append(list, u)
			}
		}
		return zctx.LookupTypeUnion(list)
	case !tIsUnion && uIsUnion:
		return unify(zctx, u, t)
	}
	return nil
}

func (s *Schema) fuseRecordTypes(a, b *zng.TypeRecord, path field.Static, renames Renames) (*zng.TypeRecord, Renames, error) {
	fused := make([]zng.Column, len(a.Columns))
	copy(fused, a.Columns)
	for _, bcol := range b.Columns {
		i, ok := a.ColumnOfField(bcol.Name)
		if !ok {
			fused = append(fused, bcol)
			continue
		}
		acol := a.Columns[i]
		switch {
		case acol == bcol:
			continue
		case zng.IsRecordType(acol.Type) && zng.IsRecordType(bcol.Type):
			var err error
			var nest *zng.TypeRecord
			nest, renames, err = s.fuseRecordTypes(acol.Type.(*zng.TypeRecord), bcol.Type.(*zng.TypeRecord), append(path, bcol.Name), renames)
			if err != nil {
				return nil, renames, err
			}
			fused[i] = zng.Column{acol.Name, nest}
		case s.unify:
			fused[i] = zng.Column{acol.Name, unify(s.zctx, acol.Type, bcol.Type)}

		default:
			dis := disambiguate(fused, acol.Name)
			renames.Srcs = append(renames.Srcs, append(path, acol.Name))
			renames.Dsts = append(renames.Dsts, append(path, dis))
			fused = append(fused, zng.Column{dis, bcol.Type})
		}
	}
	rec, err := s.zctx.LookupTypeRecord(fused)
	return rec, renames, err
}
