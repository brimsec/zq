package detector

import (
	"fmt"
	"io"

	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/csvio"
	"github.com/brimsec/zq/zio/ndjsonio"
	"github.com/brimsec/zq/zio/tableio"
	"github.com/brimsec/zq/zio/textio"
	"github.com/brimsec/zq/zio/tzngio"
	"github.com/brimsec/zq/zio/zeekio"
	"github.com/brimsec/zq/zio/zjsonio"
	"github.com/brimsec/zq/zio/zngio"
	"github.com/brimsec/zq/zio/zsonio"
	"github.com/brimsec/zq/zio/zstio"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zson"
)

type nullWriter struct{}

func (*nullWriter) Write(*zng.Record) error {
	return nil
}

func (*nullWriter) Close() error {
	return nil
}

func LookupWriter(w io.WriteCloser, zctx *resolver.Context, opts zio.WriterOpts) (zbuf.WriteCloser, error) {
	if opts.Format == "" {
		opts.Format = "tzng"
	}
	switch opts.Format {
	case "null":
		return &nullWriter{}, nil
	case "tzng":
		return tzngio.NewWriter(w), nil
	case "zng":
		return zngio.NewWriter(w, opts.Zng), nil
	case "zeek":
		return zeekio.NewWriter(w, opts.UTF8), nil
	case "ndjson":
		return ndjsonio.NewWriter(w), nil
	case "zjson":
		return zjsonio.NewWriter(w), nil
	case "zson":
		return zsonio.NewWriter(w, opts.ZSON), nil
	case "zst":
		return zstio.NewWriter(w, opts.Zst)
	case "text":
		return textio.NewWriter(w, opts.UTF8, opts.Text, opts.EpochDates), nil
	case "table":
		return tableio.NewWriter(w, opts.UTF8, opts.EpochDates), nil
	case "csv":
		return csvio.NewWriter(w, zctx, csvio.WriterOpts{
			EpochDates: opts.EpochDates,
			Fuse:       opts.CSVFuse,
			UTF8:       opts.UTF8,
		}), nil
	default:
		return nil, fmt.Errorf("unknown format: %s", opts.Format)
	}
}

func lookupReader(r io.Reader, zctx *resolver.Context, path string, opts zio.ReaderOpts) (zbuf.Reader, error) {
	switch opts.Format {
	case "tzng":
		return tzngio.NewReader(r, zctx), nil
	case "zeek":
		return zeekio.NewReader(r, zctx)
	case "ndjson":
		return ndjsonio.NewReader(r, zctx, opts.JSON, path)
	case "zjson":
		return zjsonio.NewReader(r, zctx), nil
	case "zng":
		return zngio.NewReaderWithOpts(r, zctx, opts.Zng), nil
	case "zson":
		return zson.NewReader(r, zctx), nil
	case "zst":
		return zstio.NewReader(r, zctx)
	}
	return nil, fmt.Errorf("no such format: \"%s\"", opts.Format)
}
