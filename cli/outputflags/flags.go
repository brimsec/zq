package outputflags

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/brimsec/zq/emitter"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/zngio"
	"github.com/brimsec/zq/zio/zstio"
	"golang.org/x/crypto/ssh/terminal"
)

type Flags struct {
	zio.WriterOpts
	DefaultFormat string
	dir           string
	outputFile    string
	forceBinary   bool
	zsonShortcut  bool
	zsonPretty    bool
}

func (f *Flags) Options() zio.WriterOpts {
	return f.WriterOpts
}

func (f *Flags) setFlags(fs *flag.FlagSet) {
	// zio stuff
	fs.BoolVar(&f.CSVFuse, "csvfuse", true, "fuse records for csv output")
	fs.BoolVar(&f.UTF8, "U", false, "display zeek strings as UTF-8")
	fs.BoolVar(&f.Text.ShowTypes, "T", false, "display field types in text output")
	fs.BoolVar(&f.Text.ShowFields, "F", false, "display field names in text output")
	fs.BoolVar(&f.EpochDates, "E", false, "display epoch timestamps in csv, table, and text output")
	fs.IntVar(&f.Zng.StreamRecordsMax, "b", 0, "limit for number of records in each ZNG stream (0 for no limit)")
	fs.IntVar(&f.Zng.LZ4BlockSize, "znglz4blocksize", zngio.DefaultLZ4BlockSize,
		"LZ4 block size in bytes for ZNG compression (nonpositive to disable)")
	fs.IntVar(&f.ZSON.Pretty, "pretty", 4,
		"tab size to pretty print zson output (0 for newline-delimited zson")
	f.Zst.ColumnThresh = zstio.DefaultColumnThresh
	fs.Var(&f.Zst.ColumnThresh, "coltresh", "minimum frame size (MiB) used for zst columns")
	f.Zst.SkewThresh = zstio.DefaultSkewThresh
	fs.Var(&f.Zst.SkewThresh, "skewtresh", "minimum skew size (MiB) used to group zst columns")

	// emitter stuff
	fs.StringVar(&f.dir, "d", "", "directory for output data files")
	fs.StringVar(&f.outputFile, "o", "", "write data to output file")

}

func (f *Flags) SetFlags(fs *flag.FlagSet) {
	f.SetFormatFlags(fs)
	f.setFlags(fs)
}

func (f *Flags) SetFlagsWithFormat(fs *flag.FlagSet, format string) {
	f.setFlags(fs)
	f.Format = format
}

func (f *Flags) SetFormatFlags(fs *flag.FlagSet) {
	if f.DefaultFormat == "" {
		f.DefaultFormat = "zng"
	}
	fs.StringVar(&f.Format, "f", f.DefaultFormat, "format for output data [zng,zst,ndjson,parquet,table,text,csv,zeek,zjson,zson,tzng]")
	fs.BoolVar(&f.zsonShortcut, "z", false, "use line-oriented zson output independent of -f option")
	fs.BoolVar(&f.zsonPretty, "Z", false, "use formatted zson output independent of -f option")
	fs.BoolVar(&f.forceBinary, "B", false, "allow binary zng be sent to a terminal output")
}

func (f *Flags) Init() error {
	if f.zsonShortcut || f.zsonPretty {
		if f.Format != "zng" {
			return errors.New("cannot use -z or -Z with -f")
		}
		f.Format = "zson"
		if !f.zsonPretty {
			f.ZSON.Pretty = 0
		}
	}
	if f.outputFile == "-" {
		f.outputFile = ""
	}
	if f.outputFile == "" && f.Format == "zng" && IsTerminal(os.Stdout) && !f.forceBinary {
		return errors.New("writing binary zng data to terminal; override with -B or use -z for ZSON.")
	}
	return nil
}

func (f *Flags) InitWithFormat(format string) error {
	if f.outputFile == "-" {
		f.outputFile = ""
	}
	if f.outputFile == "" && f.Format == "zng" && IsTerminal(os.Stdout) && !f.forceBinary {
		return errors.New("writing binary zng data to terminal; override with -B or use -z for ZSON.")
	}
	return nil
}

func (f *Flags) FileName() string {
	return f.outputFile
}

func (f *Flags) Open(ctx context.Context) (zbuf.WriteCloser, error) {
	if f.dir != "" {
		d, err := emitter.NewDir(ctx, f.dir, f.outputFile, os.Stderr, f.WriterOpts)
		if err != nil {
			return nil, err
		}
		return d, nil
	}
	w, err := emitter.NewFile(ctx, f.outputFile, f.WriterOpts)
	if err != nil {
		return nil, err
	}
	return w, nil
}

func IsTerminal(f *os.File) bool {
	return terminal.IsTerminal(int(f.Fd()))
}
