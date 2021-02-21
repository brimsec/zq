package idx

import (
	"flag"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/cli/outputflags"
	"github.com/brimsec/zq/cmd/zapi/cmd"
	"github.com/brimsec/zq/emitter"
	"github.com/brimsec/zq/ppl/lake"
	"github.com/brimsec/zq/zbuf"
	"github.com/mccanne/charm"
)

var Find = &charm.Spec{
	Name:  "find",
	Usage: "find [options] pattern [pattern...]",
	Short: "look through zar index files and displays matches",
	Long: `
"zapi index find" searches an archive-backed space
looking for zng files that have been indexed and performs a search on
each such index file in accordance with the specified search pattern.
Indexes are created by "zapi index create".

For standard indexes, "pattern" argument has the form "field=value" (for field searches)
or ":type=value" (for type searches).  For example, if type "ip" has been
indexed then the IP 10.0.1.2 can be searched by saying

	zapi index find :ip=10.0.1.2

Or if the field "uri" has been indexed, you might say

	zapi index uri=/x/y/z

For custom indexes, the name of index is given by the -x option,
and the "pattern" argument(s) comprise one or more values that
are parseable in accordance with the zng type of the corresponding
search keys.  For example, an index with custom keys of the form

	record[a:record[x:int64,y:ip],b:string]

could be queried using syntax like this

	zapi idx find -x custom 99 10.0.0.1 hello

The results of a search is either a list of the paths of each
zng log that matches the pattern (the default), or a zng stream of the
records of the base layer of the index file (-z)
`,
	New: NewFind,
}

type FindCmd struct {
	*cmd.Command
	indexFile     string
	pathField     string
	relativePaths bool
	zng           bool
	outputFlags   outputflags.Flags
}

func NewFind(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &FindCmd{Command: parent.(*Command).Command}
	f.StringVar(&c.indexFile, "x", "", "name of microindex for custom index searches")
	f.StringVar(&c.pathField, "l", lake.DefaultAddPathField, "zng field name for path name of log file")
	f.BoolVar(&c.relativePaths, "relative", false, "display paths relative to root")
	f.BoolVar(&c.zng, "z", false, "write results as zng stream rather than list of files")

	// Flags added for writers are -f, -T, -F, -E, -U, and -b
	c.outputFlags.SetFlags(f)

	return c, nil
}

func (c *FindCmd) Run(args []string) error {
	defer c.Cleanup()
	if err := c.Init(&c.outputFlags); err != nil {
		return err
	}
	req := api.IndexSearchRequest{IndexName: c.indexFile, Patterns: args}
	id, err := c.SpaceID()
	if err != nil {
		return err
	}
	stream, err := c.Connection().IndexSearch(c.Context(), id, req, nil)
	if err != nil {
		return err
	}
	writer, err := emitter.NewFile(c.Context(), c.outputFlags.FileName(), c.outputFlags.Options())
	if err != nil {
		return err
	}
	defer writer.Close()
	return zbuf.Copy(writer, stream)
}
