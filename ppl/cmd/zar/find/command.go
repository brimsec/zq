package find

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/brimsec/zq/cli/outputflags"
	"github.com/brimsec/zq/emitter"
	"github.com/brimsec/zq/ppl/cmd/zar/root"
	"github.com/brimsec/zq/ppl/lake"
	"github.com/brimsec/zq/ppl/lake/index"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/mccanne/charm"
)

var Find = &charm.Spec{
	Name:  "find",
	Usage: "find [options] pattern [pattern...]",
	Short: "look through zar index files and displays matches",
	Long: `
"zar find" searches a zar archive
looking for zng files that have been indexed and performs a search on
each such index file in accordance with the specified search pattern.
Indexes are created by "zar index".

For standard indexes, "pattern" argument has the form "field=value" (for field searches)
or ":type=value" (for type searches).  For example, if type "ip" has been
indexed then the IP 10.0.1.2 can be searched by saying

	zar find :ip=10.0.1.2

Or if the field "uri" has been indexed, you might say

	zar find uri=/x/y/z

For custom indexes, the name of index is given by the -x option,
and the "pattern" argument(s) comprise one or more values that
are parseable in accordance with the zng type of the corresponding
search keys.  For example, an index with custom keys of the form

	record[a:record[x:int64,y:ip],b:string]

could be queried using syntax like this

	zar find -x custom 99 10.0.0.1 hello

The results of a search is either a list of the paths of each
zng log that matches the pattern (the default), or a zng stream of the
records of the base layer of the index file (-z)
`,
	New: New,
}

func init() {
	root.Zar.Add(Find)
}

type Command struct {
	*root.Command
	root          string
	skipMissing   bool
	indexFile     string
	pathField     string
	relativePaths bool
	zng           bool
	outputFlags   outputflags.Flags
}

func New(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &Command{Command: parent.(*root.Command)}
	f.StringVar(&c.root, "R", os.Getenv("ZAR_ROOT"), "root location of zar archive to walk")
	f.BoolVar(&c.skipMissing, "Q", false, "skip errors caused by missing index files ")
	f.StringVar(&c.indexFile, "x", "", "name of microindex for custom index searches")
	f.StringVar(&c.pathField, "l", lake.DefaultAddPathField, "zng field name for path name of log file")
	f.BoolVar(&c.relativePaths, "relative", false, "display paths relative to root")
	f.BoolVar(&c.zng, "z", false, "write results as zng stream rather than list of files")

	// Flags added for writers are -f, -T, -F, -E, -U, and -b
	c.outputFlags.SetFlags(f)

	return c, nil
}

func (c *Command) Run(args []string) error {
	defer c.Cleanup()
	if err := c.Init(&c.outputFlags); err != nil {
		return err
	}

	lk, err := lake.OpenLake(c.root, nil)
	if err != nil {
		return err
	}

	query, err := index.ParseQuery(c.indexFile, args)
	if err != nil {
		return err
	}

	var findOptions []lake.FindOption
	if c.pathField != "" {
		findOptions = append(findOptions, lake.AddPath(c.pathField, !c.relativePaths))
	}
	if c.skipMissing {
		findOptions = append(findOptions, lake.SkipMissing())
	}

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()
	outputFile := c.outputFlags.FileName()
	if outputFile == "-" {
		outputFile = ""
	}
	var writer zbuf.WriteCloser
	if c.zng {
		var err error
		writer, err = emitter.NewFile(ctx, outputFile, c.outputFlags.Options())
		if err != nil {
			return err
		}
		defer writer.Close()
	}
	hits := make(chan *zng.Record)
	var searchErr error
	go func() {
		searchErr = lake.Find(ctx, resolver.NewContext(), lk, query, hits, findOptions...)
		close(hits)
	}()
	for hit := range hits {
		var err error
		if writer != nil {
			err = writer.Write(hit)
		} else {
			var path string
			path, err = hit.AccessString(c.pathField)
			if err == nil {
				fmt.Println(path)
			}
		}
		if err != nil {
			return err
		}
	}
	return searchErr
}
