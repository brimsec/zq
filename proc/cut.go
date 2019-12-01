package proc

import (
	"errors"

	"github.com/mccanne/zq/pkg/zeek"
	"github.com/mccanne/zq/pkg/zson"
	"github.com/mccanne/zq/pkg/zval"
)

var ErrNoField = errors.New("cut field not found")

type Cut struct {
	Base
	fields []string
	cutmap map[int]*zson.Descriptor
}

func NewCut(c *Context, parent Proc, fields []string) *Cut {
	return &Cut{
		Base:   Base{Context: c, Parent: parent},
		fields: fields,
		cutmap: make(map[int]*zson.Descriptor),
	}
}

func (c *Cut) lookup(in *zson.Descriptor) *zson.Descriptor {
	d, ok := c.cutmap[in.ID]
	if ok {
		return d
	}
	var columns []zeek.Column
	for _, field := range c.fields {
		colno, ok := in.ColumnOfField(field)
		if !ok {
			// a field is missing... block this descriptor
			c.cutmap[in.ID] = nil
			return nil
		}
		columns = append(columns, in.Type.Columns[colno])
	}
	out := c.Resolver.GetByColumns(columns)
	c.cutmap[in.ID] = out
	return out
}

// CreateCut returns a new record value derived by keeping only the fields
// specified by name in the fields slice.
func (c *Cut) cut(d *zson.Descriptor, in *zson.Record) (*zson.Record, error) {
	var zv zval.Encoding
	for _, column := range d.Type.Columns {
		colno, ok := in.ColumnOfField(column.Name)
		if !ok {
			// XXX put warning back
			return nil, ErrNoField
		}
		zv = append(zv, in.Slice(colno)...)
	}
	return zson.NewRecordNoTs(d, zv), nil
}

func (c *Cut) Pull() (zson.Batch, error) {
	batch, err := c.Get()
	if EOS(batch, err) {
		return nil, err
	}
	defer batch.Unref()
	//
	// Make new records with only the fields specified.
	// If a field specified doesn't exist, we don't include that record.
	// if the types change for the fields specified, we drop those records.
	//
	recs := make([]*zson.Record, 0, batch.Length())
	for k := 0; k < batch.Length(); k++ {
		in := batch.Index(k)
		d := c.lookup(in.Descriptor)
		if d == nil {
			continue
		}
		out, err := c.cut(d, in)
		if err != nil {
			return nil, err
		}
		recs = append(recs, out)
	}
	if recs == nil {
		return nil, nil
	}
	//XXX we should compute a new span here because some records may be dropped
	return zson.NewArray(recs, batch.Span()), nil
}
