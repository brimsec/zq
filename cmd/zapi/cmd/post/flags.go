package post

import (
	"errors"
	"flag"

	"github.com/brimsec/zq/api/client"
	"github.com/brimsec/zq/cmd/zapi/cmd"
	"github.com/brimsec/zq/compiler"
	"github.com/brimsec/zq/compiler/ast"
)

type postFlags struct {
	cmd.SpaceCreateFlags
	force     bool
	shaper    string
	shaperAST ast.Proc
	cmd       *cmd.Command
}

func (f *postFlags) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&f.force, "f", false, "create space if specified space does not exist")
	fs.StringVar(&f.shaper, "z", "", "Z shaper script to apply to data before storing")
	f.SpaceCreateFlags.SetFlags(fs)
}

func (f *postFlags) Init() error {
	c := f.cmd
	if err := c.Init(&f.SpaceCreateFlags); err != nil {
		return err
	}
	if f.shaper != "" {
		ast, err := compiler.ParseProc(f.shaper)
		if err != nil {
			return err
		}
		f.shaperAST = ast
	}
	if !f.force {
		return nil
	} else if c.Spacename == "" {
		return errors.New("if -f flag is enabled, a space name must specified")
	}
	sp, err := f.SpaceCreateFlags.Create(c.Context(), c.Connection(), c.Spacename)
	if err != nil {
		if err == client.ErrSpaceExists {
			// Fetch space ID.
			_, err = c.SpaceID()
		}
		return err
	}
	c.SetSpaceID(sp.ID)
	return nil
}
