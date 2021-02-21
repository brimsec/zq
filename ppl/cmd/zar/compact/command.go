package compact

import (
	"context"
	"flag"
	"os"

	"github.com/brimsec/zq/ppl/cmd/zar/root"
	"github.com/brimsec/zq/ppl/lake"
	"github.com/mccanne/charm"
)

var Compact = &charm.Spec{
	Name:  "compact",
	Usage: "compact [-R root]",
	Short: "merge overlapping chunk files",
	Long: `
"zar compact" looks for chunk files whose time ranges overlap, and writes
new chunk files that combine their records.
`,
	New: New,
}

func init() {
	root.Zar.Add(Compact)
}

type Command struct {
	*root.Command
	root  string
	purge bool
}

func New(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &Command{Command: parent.(*root.Command)}
	f.StringVar(&c.root, "R", os.Getenv("ZAR_ROOT"), "root location of zar archive to walk")
	f.BoolVar(&c.purge, "purge", false, "remove chunk files (and associated files) whose data has been combined into other chunks")
	return c, nil
}

func (c *Command) Run(args []string) error {
	defer c.Cleanup()
	if err := c.Init(); err != nil {
		return err
	}

	lk, err := lake.OpenLake(c.root, nil)
	if err != nil {
		return err
	}
	ctx := context.TODO()
	if err := lake.Compact(ctx, lk, nil); err != nil {
		return err
	}
	if c.purge {
		return lake.Purge(ctx, lk, nil)
	}
	return nil
}
