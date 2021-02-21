package zq

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/brimsec/zq/zio/tzngio"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/ztest"
	"github.com/stretchr/testify/require"
)

func TestZq(t *testing.T) {
	t.Parallel()
	dirs, err := findZTests()
	require.NoError(t, err)
	for d := range dirs {
		d := d
		t.Run(d, func(t *testing.T) {
			t.Parallel()
			ztest.Run(t, d)
		})
	}
	t.Run("ZsonBoomerang", func(t *testing.T) {
		runZsonBoomerangs(t, dirs)
	})
}

func findZTests() (map[string]struct{}, error) {
	dirs := map[string]struct{}{}
	pattern := fmt.Sprintf(`.*ztests\%c.*\.yaml$`, filepath.Separator)
	re := regexp.MustCompile(pattern)
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(path, ".yaml") && re.MatchString(path) {
			dirs[filepath.Dir(path)] = struct{}{}
		}
		return err
	})
	return dirs, err
}

func runZsonBoomerangs(t *testing.T, dirs map[string]struct{}) {
	if testing.Short() {
		return
	}
	bundles, err := findTzngs(t, dirs)
	if err != nil {
		t.Fatal(err)
	}
	shellPath, err := ztest.ShellPath()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bundles {
		b := b
		t.Run(b.TestName, func(t *testing.T) {
			t.Parallel()
			err := b.RunScript(shellPath, ".")
			if err != nil {
				err = &BoomerangError{
					*b.Test.Inputs[0].Data,
					b.FileName,
					err,
				}
			}
			require.NoError(t, err)
		})
	}
}

type BoomerangError struct {
	Zson     string
	FileName string
	Err      error
}

func (b *BoomerangError) Error() string {
	return fmt.Sprintf("%s\n=== with this zson ===\n\n%s\n\n=== from file ===\n\n%s\n\n", b.Err, b.Zson, b.FileName)
}

const script = `
zq -f zson in.tzng > baseline.zson
zq -i zson -f zson baseline.zson > boomerang.zson
diff baseline.zson boomerang.zson
echo EOF
`

var eof = `EOF
`
var empty = ""

func boomerang(zson string) *ztest.ZTest {
	return &ztest.ZTest{
		Script: script,
		Inputs: []ztest.File{
			{
				Name: "in.tzng",
				Data: &zson,
			},
		},
		Outputs: []ztest.File{
			{
				Name: "stdout",
				Data: &eof,
			},
			{
				Name: "stderr",
				Data: &empty,
			},
		},
	}
}

func expectFailure(b ztest.Bundle) bool {
	if b.Test.ErrorRE != "" {
		return true
	}
	for _, f := range b.Test.Outputs {
		if f.Name == "stderr" {
			return true
		}
	}
	return false
}

func isValidTzng(src string) bool {
	r := tzngio.NewReader(strings.NewReader(src), resolver.NewContext())
	for {
		rec, err := r.Read()
		if err != nil {
			return false
		}
		if rec == nil {
			return true
		}
	}
}

func findTzngs(t *testing.T, dirs map[string]struct{}) ([]ztest.Bundle, error) {
	var out []ztest.Bundle
	for path := range dirs {
		bundles, err := ztest.Load(path)
		if err != nil {
			t.Log(err)
			continue
		}
		// Transform the bundles into boomerang tests by taking each
		// tzng source and creating a new ztest.Bundle.
		for _, bundle := range bundles {
			if bundle.Error != nil || expectFailure(bundle) {
				continue
			}
			// Normalize the diffrent kinds of test inputs into
			// a single pattern.
			for _, src := range bundle.Test.Input {
				if !isValidTzng(src) {
					continue
				}
				b := ztest.Bundle{
					TestName: bundle.TestName,
					FileName: bundle.FileName,
					Test:     boomerang(src),
				}
				out = append(out, b)
			}
			for _, src := range bundle.Test.Inputs {
				if src.Data == nil || !isValidTzng(*src.Data) {
					continue
				}
				b := ztest.Bundle{
					TestName: bundle.TestName,
					FileName: bundle.FileName,
					Test:     boomerang(*src.Data),
				}
				out = append(out, b)
			}
		}
	}
	return out, nil
}
