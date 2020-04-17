package emitter

import (
	"io"
	"os"

	"github.com/brimsec/zq/pkg/bufwriter"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/detector"
)

type noClose struct {
	io.Writer
}

func (*noClose) Close() error {
	return nil
}

func NewFile(path, format string, flags *zio.Flags) (*zio.Writer, error) {
	var f io.WriteCloser
	if path == "" {
		// Don't close stdout in case we live inside something
		// here that runs multiple instances of this to stdout.
		f = &noClose{os.Stdout}
	} else {
		var err error
		flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		file, err := os.OpenFile(path, flags, 0600)
		if err != nil {
			return nil, err
		}
		f = file
	}
	// On close, zio.Writer.Close(), the zng WriteFlusher will be flushed
	// then the bufwriter will closed (which will flush it's internal buffer
	// then close the file)
	w := detector.LookupWriter(format, bufwriter.New(f), flags)
	if w == nil {
		return nil, unknownFormat(format)
	}
	return w, nil
}
