package index

import (
	"context"
	"fmt"
	"path"
	"regexp"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/pkg/iosrc"
	"github.com/segmentio/ksuid"
)

type Definition struct {
	Rule
	ID   ksuid.KSUID
	Proc ast.Proc
}

// ReadDefinitions opens and reads all the index defs in the specified
// directory.
func ReadDefinitions(ctx context.Context, dir iosrc.URI) (Definitions, error) {
	infos, err := iosrc.ReadDir(ctx, dir)
	if err != nil {
		return nil, err
	}

	defs := make(Definitions, len(infos))
	for i, info := range infos {
		def, err := ReadDefinition(ctx, dir.AppendPath(info.Name()))
		if err != nil {
			return nil, err
		}
		defs[i] = def
	}

	return defs, nil
}

func ReadDefinition(ctx context.Context, u iosrc.URI) (*Definition, error) {
	id, err := parseDefFile(path.Base(u.Path))
	if err != nil {
		return nil, err
	}
	b, err := iosrc.ReadFile(ctx, u)
	if err != nil {
		return nil, err
	}
	def := &Definition{ID: id}
	def.Rule, err = UnmarshalRule(b)
	if err != nil {
		return nil, err
	}
	def.Proc, err = def.Rule.Proc()
	return def, err
}

func RemoveDefinition(ctx context.Context, dir iosrc.URI, id ksuid.KSUID) error {
	return iosrc.Remove(ctx, dir.AppendPath(defFilename(id)))
}

func WriteRules(ctx context.Context, dir iosrc.URI, rules []Rule) ([]*Definition, error) {
	existing, err := ReadDefinitions(ctx, dir)
	if err != nil {
		return nil, err
	}

	newdefs := make(Definitions, 0, len(rules))
	for _, r := range rules {
		if newdefs.LookupByRule(r) != nil || existing.LookupByRule(r) != nil {
			// skip rules that already exist
			continue
		}

		def, err := NewDefinition(r)
		if err != nil {
			return nil, err
		}
		newdefs = append(newdefs, def)
	}

	for _, d := range newdefs {
		if d.Write(ctx, dir); err != nil {
			return nil, err
		}
	}

	return newdefs, nil
}

func NewDefinition(r Rule) (*Definition, error) {
	proc, err := r.Proc()
	if err != nil {
		return nil, err
	}
	return &Definition{ID: ksuid.New(), Rule: r, Proc: proc}, nil
}

func MustNewDefinition(r Rule) *Definition {
	d, err := NewDefinition(r)
	if err != nil {
		panic(err)
	}
	return d
}

func defFilename(id ksuid.KSUID) string {
	return fmt.Sprintf("idxdef-%s.zng", id)
}

var defFileRegex = regexp.MustCompile(`idxdef-([0-9A-Za-z]{27}).zng$`)

func parseDefFile(name string) (ksuid.KSUID, error) {
	match := defFileRegex.FindStringSubmatch(name)
	if match == nil {
		return ksuid.Nil, fmt.Errorf("invalid definition file: %s", name)
	}
	return ksuid.Parse(match[1])
}

func (d *Definition) Filename() string {
	return defFilename(d.ID)
}

func (d *Definition) Write(ctx context.Context, dir iosrc.URI) error {
	b, err := d.Rule.Marshal()
	if err != nil {
		return err
	}
	return iosrc.WriteFile(ctx, dir.AppendPath(d.Filename()), b)
}

type DefinitionMap map[ksuid.KSUID]*Definition

type Definitions []*Definition

func (l Definitions) Map() DefinitionMap {
	m := make(DefinitionMap)
	for _, def := range l {
		m[def.ID] = def
	}
	return m
}

func (l Definitions) MapByInputPath() map[string][]*Definition {
	m := make(map[string][]*Definition)
	for _, d := range l {
		m[d.Input] = append(m[d.Input], d)
	}
	return m
}

// StandardInputs returns the Defs from the list that have an empty InputPath.
func (l Definitions) StandardInputs() []*Definition {
	var defs []*Definition
	for _, d := range l {
		if d.Input == "" {
			defs = append(defs, d)
		}
	}
	return defs
}

func (l Definitions) LookupByRule(r Rule) *Definition {
	for _, def := range l {
		if def.Rule.Equivalent(r) {
			return def
		}
	}
	return nil
}

func (l Definitions) LookupQuery(query Query) (DefLookup, bool) {
	for _, def := range l {
		if query.Matches(def.Rule) {
			return DefLookup{def.ID, query.Values}, true
		}
	}
	return DefLookup{}, false
}

func (l Definitions) Lookup(id ksuid.KSUID) *Definition {
	for _, def := range l {
		if def.ID == id {
			return def
		}
	}
	return nil
}
