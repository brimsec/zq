package emitter

import (
	"bytes"

	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/detector"
	"github.com/brimsec/zq/zng/resolver"
)

type Bytes struct {
	zbuf.Writer
	buf bytes.Buffer
}

func (b *Bytes) Bytes() []byte {
	return b.buf.Bytes()
}

func NewBytes(opts zio.WriterOpts) (*Bytes, error) {
	b := &Bytes{}
	w, err := detector.LookupWriter(zio.NopCloser(&b.buf), resolver.NewContext(), opts)
	if err != nil {
		return nil, err
	}
	b.Writer = w
	return b, nil
}
