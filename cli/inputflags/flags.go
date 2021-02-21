package inputflags

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/brimsec/zq/cli/auto"
	"github.com/brimsec/zq/pkg/iosrc"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/detector"
	"github.com/brimsec/zq/zio/ndjsonio"
	"github.com/brimsec/zq/zio/zngio"
	"github.com/brimsec/zq/zng/resolver"
)

type Flags struct {
	zio.ReaderOpts
	ReadMax  auto.Bytes
	ReadSize auto.Bytes
	// The JSON type config is loaded from the types filie when Init is called.
	jsonTypesFile string
}

func (f *Flags) Options() zio.ReaderOpts {
	return f.ReaderOpts
}

func (f *Flags) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&f.Format, "i", "auto", "format of input data [auto,zng,zst,ndjson,zeek,zjson,tzng,parquet]")
	fs.BoolVar(&f.Zng.Validate, "validate", true, "validate the input format when reading ZNG streams")
	fs.StringVar(&f.jsonTypesFile, "j", "", "path to json types file")
	fs.StringVar(&f.JSON.PathRegexp, "pathregexp", ndjsonio.DefaultPathRegexp,
		"regexp for extracting _path from json log name (when -inferpath=true)")
	f.ReadMax = auto.NewBytes(zngio.MaxSize)
	fs.Var(&f.ReadMax, "readmax", "maximum memory used read buffers in MiB, MB, etc")
	f.ReadSize = auto.NewBytes(zngio.ReadSize)
	fs.Var(&f.ReadSize, "readsize", "target memory used read buffers in MiB, MB, etc")
}

// Init is called after flags have been parsed.
func (f *Flags) Init() error {
	// Catch errors early ... ?! XXX
	if _, err := regexp.Compile(f.JSON.PathRegexp); err != nil {
		return err
	}
	if f.jsonTypesFile != "" {
		c, err := LoadJSONConfig(f.jsonTypesFile)
		if err != nil {
			return err
		}
		f.JSON.TypeConfig = c
	}
	f.Zng.Max = int(f.ReadMax.Bytes)
	if f.Zng.Max < 0 {
		return errors.New("max read buffer size must be greater than zero")
	}
	f.Zng.Size = int(f.ReadSize.Bytes)
	if f.Zng.Size < 0 {
		return errors.New("target read buffer size must be greater than zero")
	}
	return nil
}

func LoadJSONConfig(path string) (*ndjsonio.TypeConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tc ndjsonio.TypeConfig
	if err := json.Unmarshal(data, &tc); err != nil {
		return nil, fmt.Errorf("%s: unmarshaling error: %s", path, err)
	}
	if err := tc.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %s", path, err)
	}
	return &tc, nil
}

func (f *Flags) Open(zctx *resolver.Context, paths []string, stopOnErr bool) ([]zbuf.Reader, error) {
	var readers []zbuf.Reader
	for _, path := range paths {
		if path == "-" {
			path = iosrc.Stdin
		}
		file, err := detector.OpenFile(zctx, path, f.ReaderOpts)
		if err != nil {
			err = fmt.Errorf("%s: %w", path, err)
			if stopOnErr {
				return nil, err
			}
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		readers = append(readers, file)
	}
	return readers, nil
}
