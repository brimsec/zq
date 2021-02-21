package stat

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/brimsec/zq/emitter"
	"github.com/brimsec/zq/ppl/cmd/zar/root"
	"github.com/brimsec/zq/ppl/lake"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/mccanne/charm"
)

var Stat = &charm.Spec{
	Name:  "stat",
	Usage: "stat [-R root] [options]",
	Short: "archive component statistics",
	Long: `
"zar stat" generates a ZNG stream with information about the chunks in
an archive.
`,
	New: New,
}

func init() {
	root.Zar.Add(Stat)
}

type Command struct {
	*root.Command
	root   string
	format string
}

func New(parent charm.Command, f *flag.FlagSet) (charm.Command, error) {
	c := &Command{Command: parent.(*root.Command)}
	f.StringVar(&c.root, "R", os.Getenv("ZAR_ROOT"), "root location of zar archive to walk")
	f.StringVar(&c.format, "f", "table", "format for output data [zng,ndjson,table,text,zeek,zjson,tzng] (default \"table\")")
	return c, nil
}

func (c *Command) Run(args []string) (err error) {
	defer c.Cleanup()
	if err := c.Init(); err != nil {
		return err
	}
	if len(args) > 0 {
		return errors.New("zar stat: too many arguments")
	}

	lk, err := lake.OpenLake(c.root, nil)
	if err != nil {
		return err
	}

	wc, err := emitter.NewFile(context.TODO(), "", zio.WriterOpts{Format: c.format})
	if err != nil {
		return err
	}
	defer func() {
		wcErr := wc.Close()
		if err == nil {
			err = wcErr
		}
	}()

	rc, err := lake.Stat(context.Background(), resolver.NewContext(), lk)
	if err != nil {
		return err
	}
	defer func() {
		rcErr := rc.Close()
		if err == nil {
			err = rcErr
		}
	}()

	return zbuf.Copy(wc, rc)
}
