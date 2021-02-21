package index

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/brimsec/zq/ppl/cmd/zar/root"
	"github.com/brimsec/zq/ppl/lake"
	"github.com/brimsec/zq/ppl/lake/index"
	"github.com/mccanne/charm"
	"github.com/segmentio/ksuid"
)

var Drop = &charm.Spec{
	Name:  "drop",
	Usage: "drop [-R root] [options] id... ",
	Short: "drop index defintion(s) from archive",
	Long: `
"zar index drop" removes an index definition from the archive then walks through
the tree removing referenced index files.

If the -noapply option is enabled the command will only removed the index
definition. The individual index files will still exist but they will no longer
be queryable.
`,
	New: NewDrop,
}

type DropCommand struct {
	*root.Command
	root     string
	noapply  bool
	progress chan string
	quiet    bool
}

func NewDrop(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &DropCommand{Command: parent.(*Command).Command}
	f.StringVar(&c.root, "R", os.Getenv("ZAR_ROOT"), "root location of zar archive to walk")
	f.BoolVar(&c.noapply, "noapply", false, "remove index definition only")
	f.BoolVar(&c.quiet, "q", false, "do not display progress updates will deleting indices")

	return c, nil
}

func (c *DropCommand) Run(args []string) error {
	return c.run(args)
}

func (c *DropCommand) run(args []string) error {
	defer c.Cleanup()
	if err := c.Init(); err != nil {
		return err
	}

	if len(args) == 0 {
		return errors.New("no index definition specified")
	}

	lk, err := lake.OpenLake(c.root, nil)
	if err != nil {
		return err
	}

	alldefs, err := lk.ReadDefinitions(context.TODO())
	if err != nil {
		return err
	}

	defs := make([]*index.Definition, 0, len(args))
	for _, arg := range args {
		id, err := ksuid.Parse(arg)
		if err != nil {
			return err
		}
		def := alldefs.Lookup(id)
		if def == nil {
			fmt.Fprintf(os.Stderr, "defintion for id '%s' not found\n", arg)
			continue
		}
		defs = append(defs, def)
	}

	if len(defs) == 0 {
		return errors.New("no definitions deleted")
	}

	if err := lake.RemoveDefinitions(context.TODO(), lk, defs...); err != nil {
		return err
	}

	if !c.noapply {
		if !c.quiet {
			c.progress = make(chan string)
			go c.displayProgress()
		}
		if err := lake.RemoveIndices(context.TODO(), lk, c.progress, defs...); err != nil {
			return err
		}
	}
	fmt.Printf("%d index definitions removed\n", len(defs))
	return nil
}

func (c *DropCommand) displayProgress() {
	for line := range c.progress {
		fmt.Println(line)
	}
}
