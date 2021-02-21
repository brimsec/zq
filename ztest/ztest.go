// Package ztest runs formulaic tests ("ztests") that can be (1) run in-process
// with the compiled-ini zq code base, (2) run as a sub-process using the zq
// executable build artifact, or (3) run as a bash script running a sequence
// of arbitrary shell commands invoking any of the build artifacts.  The
// first two cases comprise the "ZQL test style" and the last case
// comprises the "script test style".  Case (1) is easier to debug by
// simply running "go test" compared replicating the test using "go run".
// Script-style tests don't have this convenience.
//
// In the ZQL style, ztest runs a ZQL query on an input and checks
// for an expected output.
//
// A ZQL-style test is defined in a YAML file.
//
//    zql: count()
//
//    input: |
//      #0:record[i:int64]
//      0:[1;]
//      0:[2;]
//
//    output: |
//      #0:record[count:uint64]
//      0:[2;]
//
// Input format is detected automatically and can be anything recognized by
// "zq -i auto" (including optional gzip compression).  Output format defaults
// to tzng but can be set to anything accepted by "zq -f".
//
//    zql: count()
//
//    input: |
//      #0:record[i:int64]
//      0:[1;]
//      0:[2;]
//
//    output-flags: -f table
//
//    output: |
//      COUNT
//      2
//
// Alternatively, tests can be configured to run as shell scripts.
// In this style of test, arbitrary bash scripts can run chaining together
// any of zq/cmd tools in addition to zq.  Here, the yaml sets up a collection
// of input files and stdin, the script runs, and the test driver compares expected
// output files, stdout, and stderr with data in the yaml spec.  In this case,
// instead of specifying, "zql", "input", "output", you specify the yaml arrays
// "inputs" and "outputs" --- where each array element defines a file, stdin,
// stdout, or stderr --- and a "script" that specifies a multi-line yaml string
// defining the script, e.g.,
//
// inputs:
//    - name: in1.tzng
//      data: |
//         #0:record[i:int64]
//         0:[1;]
//    - name: stdin
//      data: |
//         #0:record[i:int64]
//         0:[2;]
// script: |
//    zq -o out.tzng in1.tzng -
//    zq -o count.tzng "count()" out.tzng
// outputs:
//    - name: out.tzng
//      data: |
//         #0:record[i:int64]
//         0:[1;]
//         0:[2;]
//    - name: count.tzng
//      data: |
//         #0:record[count:uint64]
//         0:[2;]
//
// Each input and output has a name.  For inputs, a file (source),
// inlined data (data), or hexadecimal data (hex) may be specified.
// If no data is specified, then a file of the same name as the
// name field is looked for in the same directory as the yaml file.
// The source spec is a file path relative to the directory of the
// yaml file.  For outputs, expected output is defined in the same
// fashion as the inputs though you can also specify a "regexp" string
// instead of expected data.  If an output is named "stdout" or "stderr"
// then the actual output is taken from the stdout or stderr of the
// the shell script.
//
// Ztest YAML files for a package should reside in a subdirectory named
// testdata/ztest.
//
//     pkg/
//       pkg.go
//       pkg_test.go
//       testdata/
//         ztest/
//           test-1.yaml
//           test-2.yaml
//           ...
//
// Name YAML files descriptively since each ztest runs as a subtest
// named for the file that defines it.
//
// pkg_test.go should contain a Go test named TestZTest that calls Run.
//
//     func TestZTest(t *testing.T) { ztest.Run(t, "testdata/ztest") }
//
// If the ZTEST_PATH environment variable is unset or empty and the test
// is not a script test, Run runs ztests in the current process and skips
// the script tests.  Otherwise, Run runs each ztest in a separate process
// using the zq executable in the directories specified by ZTEST_PATH.
package ztest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/brimsec/zq/cli/outputflags"
	"github.com/brimsec/zq/compiler"
	"github.com/brimsec/zq/driver"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio/detector"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zqe"
	"github.com/pmezard/go-difflib/difflib"
	"gopkg.in/yaml.v3"
)

func ShellPath() (string, error) {
	path := os.Getenv("ZTEST_PATH")
	if path != "" {
		if out, _, err := runzq(path, "help", nil); err != nil {
			if out != "" {
				out = fmt.Sprintf(" with output %q", out)
			}
			return "", fmt.Errorf("failed to exec zq in dir $ZTEST_PATH %s: %s%s", path, err, out)
		}
	}
	return path, nil
}

type Bundle struct {
	TestName string
	FileName string
	Test     *ZTest
	Error    error
}

func (b *Bundle) RunScript(shellPath, workingDir string) error {
	return b.Test.RunScript(b.TestName, shellPath, workingDir, b.FileName)
}

func Load(dirname string) ([]Bundle, error) {
	var bundles []Bundle
	fileinfos, err := ioutil.ReadDir(dirname)
	if err != nil {
		return nil, err
	}
	for _, fi := range fileinfos {
		filename := fi.Name()
		const dotyaml = ".yaml"
		if !strings.HasSuffix(filename, dotyaml) {
			continue
		}
		testname := strings.TrimSuffix(filename, dotyaml)
		// An absolute path in errors makes the offending file easier to find.
		filename, err := filepath.Abs(filepath.Join(dirname, filename))
		var zt *ZTest
		if err == nil {
			zt, err = FromYAMLFile(filename)
		}
		bundles = append(bundles, Bundle{testname, filename, zt, err})
	}
	return bundles, nil
}

// Run runs the ztests in the directory named dirname.  For each file f.yaml in
// the directory, Run calls FromYAMLFile to load a ztest and then runs it in
// subtest named f.  path is a command search path like the
// PATH environment variable.
func Run(t *testing.T, dirname string) {
	shellPath, err := ShellPath()
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := Load(dirname)
	if err != nil {
		t.Fatal(err)
	}
	for _, bundle := range bundles {
		b := bundle
		t.Run(b.TestName, func(t *testing.T) {
			t.Parallel()
			if b.Error != nil {
				t.Fatalf("%s: %s", b.FileName, b.Error)
			}
			if b.Test.Skip {
				t.Skip("test is disabled")
			}
			b.Test.Run(t, b.TestName, shellPath, dirname, b.FileName)
		})
	}
}

type File struct {
	// Name is the name of the file with respect to the directoy in which
	// the test script runs.  For inputs, if no data source is specified,
	// then name is also the name of a data file in the diectory containing
	// the yaml test file, which is copied to the test script directory.
	// Name can also be stdio (for inputs) or stdout or stderr (for outputs).
	Name string `yaml:"name"`
	// Data, Hex, and Source represents the different ways file data can
	// be defined for this file.  Data is a string turned into the contents
	// of the file, Hex is hex decoded, and Source is a string representing
	// the pathname of a file the repo that is read to comprise the data.
	Data   *string `yaml:"data,omitempty"`
	Hex    string  `yaml:"hex,omitempty"`
	Source string  `yaml:"source,omitempty"`
	// Re is a regular expression describing the contents of the file,
	// which is only applicable to output files.
	Re string `yaml:"regexp,omitempty"`
	// Symlink creates a symlink on the specified directory into a test's local
	// directory. Only applicable to input files.
	Symlink string `yaml:"symlink,omitempty"`
}

func (f *File) check() error {
	cnt := 0
	if f.Data != nil {
		cnt++
	}
	if f.Hex != "" {
		cnt++
	}
	if f.Source != "" {
		cnt++
	}
	if f.Symlink != "" {
		cnt++
	}
	if cnt > 1 {
		return fmt.Errorf("%s: must at most one of data, hex, or source", f.Name)
	}
	return nil
}

func (f *File) load(dir string) ([]byte, *regexp.Regexp, error) {
	if f.Data != nil {
		return []byte(*f.Data), nil, nil
	}
	if f.Hex != "" {
		s, err := decodeHex(f.Hex)
		return []byte(s), nil, err
	}
	if f.Source != "" {
		b, err := ioutil.ReadFile(filepath.Join(dir, f.Source))
		return b, nil, err
	}
	if f.Re != "" {
		re, err := regexp.Compile(f.Re)
		return nil, re, err
	}
	if f.Symlink != "" {
		f.Symlink = filepath.Join(dir, f.Symlink)
		return nil, nil, nil
	}
	b, err := ioutil.ReadFile(filepath.Join(dir, f.Name))
	if err == nil {
		return b, nil, nil
	}
	if os.IsNotExist(err) {
		err = fmt.Errorf("%s: no data source", f.Name)
	}
	return nil, nil, err
}

// ZTest defines a ztest.
type ZTest struct {
	ZQL         string `yaml:"zql,omitempty"`
	Skip        bool   `yaml:"skip,omitempty"`
	Input       Inputs `yaml:"input,omitempty"`
	Output      string `yaml:"output,omitempty"`
	OutputHex   string `yaml:"outputHex,omitempty"`
	OutputFlags string `yaml:"output-flags,omitempty"`
	ErrorRE     string `yaml:"errorRE"`
	errRegex    *regexp.Regexp
	Warnings    string `yaml:"warnings,omitempty"`
	// shell mode params
	Script  string   `yaml:"script,omitempty"`
	Inputs  []File   `yaml:"inputs,omitempty"`
	Outputs []File   `yaml:"outputs,omitempty"`
	Tag     string   `yaml:"tag,omitempty"`
	Env     []string `yaml:"env,omitempty"`
}

func (z *ZTest) check() error {
	if z.ZQL != "" {
		if z.Input == nil {
			return errors.New("input field missing in a zq test")
		}
	} else if z.Script != "" {
		if z.Outputs == nil {
			return errors.New("outputs field missing in a sh test")
		}
		for _, f := range z.Inputs {
			if err := f.check(); err != nil {
				return err
			}
		}
		for _, f := range z.Outputs {
			if err := f.check(); err != nil {
				return err
			}
		}
	} else {
		return errors.New("either a zql field or script field must be present")
	}
	return nil
}

// Inputs is an array of strings. Its only purpose is to support parsing of
// both single string and array yaml values for the field ZTest.Input.
type Inputs []string

func (i *Inputs) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		var inputs []string
		err := value.Decode(&inputs)
		*i = inputs
		return err
	}
	var input string
	if err := value.Decode(&input); err != nil {
		return err
	}
	*i = append(*i, input)
	return nil
}

// Try to decode a yaml-friendly way of representing binary data in hex:
// each line is either a comment explaining the contents (denoted with
// a leading # character), or a sequence of hex digits.
func decodeHex(in string) (string, error) {
	var raw string
	for _, line := range strings.Split(in, "\n") {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		raw += strings.ReplaceAll(line, " ", "")
	}
	out := make([]byte, hex.DecodedLen(len(raw)))
	_, err := hex.Decode(out, []byte(raw))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (z *ZTest) getOutput() (string, error) {
	outlen := len(z.Output)
	hexlen := len(z.OutputHex)
	if outlen > 0 && hexlen > 0 {
		return "", errors.New("Cannot specify both output and outputHex")
	}
	if outlen == 0 && hexlen == 0 {
		return "", nil
	}
	if outlen > 0 {
		return z.Output, nil
	}
	return decodeHex(z.OutputHex)
}

// FromYAMLFile loads a ZTest from the YAML file named filename.
func FromYAMLFile(filename string) (*ZTest, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	d := yaml.NewDecoder(bytes.NewReader(buf))
	d.KnownFields(true)
	var z ZTest
	if err := d.Decode(&z); err != nil {
		return nil, err
	}
	var v interface{}
	if d.Decode(&v) != io.EOF {
		return nil, errors.New("found multiple YAML documents or garbage after first document")
	}
	if z.ErrorRE != "" {
		z.errRegex, err = regexp.Compile(z.ErrorRE)
		if err != nil {
			return nil, err
		}
	}
	return &z, nil
}

func (z *ZTest) ShouldSkip(path string) string {
	if runtime.GOOS == "windows" {
		// XXX skip in windows until we figure out the best
		// way to support script-driven tests across
		// environments
		return "skipping script test on Windows"
	}
	if path == "" {
		return "skipping script test on in-process run"
	}
	if z.Tag != "" && z.Tag != os.Getenv("ZTEST_TAG") {
		return fmt.Sprintf("skipping script test because tag %q does not match ZTEST_TAG=%q", z.Tag, os.Getenv("ZTEST_TAG"))
	}
	return ""
}

func (z *ZTest) RunScript(testname, shellPath, workingDir, filename string) error {
	adir, _ := filepath.Abs(workingDir)
	return runsh(testname, shellPath, adir, z)
}

func (z *ZTest) Run(t *testing.T, testname, path, dirname, filename string) {
	if err := z.check(); err != nil {
		t.Fatalf("%s: bad yaml format: %s", filename, err)
	}
	if z.Script != "" {
		if msg := z.ShouldSkip(path); msg != "" {
			t.Skip(msg)
		}
		if err := z.RunScript(testname, path, dirname, filename); err != nil {
			t.Fatalf("%s: %s", filename, err)
		}
		return
	}
	outputFlags := append([]string{"-f=tzng"}, strings.Fields(z.OutputFlags)...)
	out, errout, err := runzq(path, z.ZQL, outputFlags, z.Input...)
	if err != nil {
		if z.errRegex != nil {
			if !z.errRegex.MatchString(errout) {
				t.Fatalf("%s: error doesn't match expected error regex: %s %s", filename, z.ErrorRE, errout)
			}
		} else {
			if out != "" {
				out = "\noutput:\n" + out
			}
			t.Fatalf("%s: %s%s", filename, err, out)
		}
	} else if z.errRegex != nil {
		t.Fatalf("%s: no error when expecting error regex: %s", filename, z.ErrorRE)
	} else if z.Warnings != errout {
		t.Fatalf("%s: %s", filename, diffErr("warnings", z.Warnings, errout))
	}
	expectedOut, err := z.getOutput()
	if err != nil {
		t.Fatalf("%s: getting test output: %s", filename, err)
	}
	if expectedOut != out {
		t.Fatalf("%s: %s", filename, diffErr("output", expectedOut, out))
	}
}

func diffErr(name, expected, actual string) error {
	if !utf8.ValidString(expected) {
		expected = hex.Dump([]byte(expected))
		actual = hex.Dump([]byte(actual))
	}
	diff, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(expected),
		FromFile: "expected",
		B:        difflib.SplitLines(actual),
		ToFile:   "actual",
		Context:  5,
	})
	if err != nil {
		panic("ztest: " + err.Error())
	}
	return fmt.Errorf("expected and actual %s differ:\n%s", name, diff)
}

func checkPatterns(patterns map[string]*regexp.Regexp, dir *Dir, stdout, stderr string) error {
	for name, re := range patterns {
		var body []byte
		switch name {
		case "stdout":
			body = []byte(stdout)
		case "stderr":
			body = []byte(stderr)
		default:
			var err error
			body, err = dir.Read(name)
			if err != nil {
				return fmt.Errorf("%s: %s", name, err)
			}
		}
		if !re.Match(body) {
			return fmt.Errorf("%s: regex %s does not match %s'", name, re, body)
		}
	}
	return nil
}

func checkData(files map[string][]byte, dir *Dir, stdout, stderr string) error {
	for name, expected := range files {
		var actual []byte
		switch name {
		case "stdout":
			actual = []byte(stdout)
		case "stderr":
			actual = []byte(stderr)
		default:
			var err error
			actual, err = dir.Read(name)
			if err != nil {
				return fmt.Errorf("%s: %s", name, err)
			}
		}
		if !bytes.Equal(expected, actual) {
			return diffErr(name, string(expected), string(actual))
		}
	}
	return nil
}

func runsh(testname, path, dirname string, zt *ZTest) error {
	dir, err := NewDir(testname)
	if err != nil {
		return fmt.Errorf("creating ztest scratch dir: \"%s\": %w", testname, err)
	}
	var stdin io.Reader
	defer dir.RemoveAll()
	for _, f := range zt.Inputs {
		b, re, err := f.load(dirname)
		if err != nil {
			return err
		}
		if f.Symlink != "" {
			if err := dir.Symlink(f.Symlink, f.Name); err != nil {
				return err
			}
			continue
		}
		if f.Name == "stdin" {
			stdin = bytes.NewReader(b)
			continue
		}
		if re != nil {
			return fmt.Errorf("%s: cannot use a regexp pattern in an input", f.Name)
		}
		if err := dir.Write(f.Name, b); err != nil {
			return err
		}
	}
	expectedData := make(map[string][]byte)
	expectedPattern := make(map[string]*regexp.Regexp)
	for _, f := range zt.Outputs {
		b, re, err := f.load(dirname)
		if err != nil {
			return err
		}
		if f.Symlink != "" {
			return fmt.Errorf("%s: cannot use a symlink in an output", f.Name)
		}
		if b != nil {
			expectedData[f.Name] = b
		}
		if re != nil {
			expectedPattern[f.Name] = re
		}
	}
	stdout, stderr, err := RunShell(dir, path, zt.Script, stdin, zt.Env)
	if err != nil {
		// XXX If the err is an exit error, we ignore it and rely on
		// tests that check stderr etc.  We could pull out the exit
		// status and test on this if we added a field for this to
		// the ZTest struct.  I don't think it makes sense to comingle
		// this condition with the stderr checks as in the other
		// testing code path below.
		if _, ok := err.(*exec.ExitError); !ok {
			// Not an exit error from the test shell so there was
			// a problem execing and runnning the shell command...
			return err
		}
	}
	if err := checkPatterns(expectedPattern, dir, stdout, stderr); err != nil {
		return err
	}
	return checkData(expectedData, dir, stdout, stderr)
}

// runzq runs the query in ZQL over inputs and returns the output.  inputs may
// be in any format recognized by "zq -i auto" and may be gzip-compressed.
// outputFlags may contain any flags accepted by cli/outputflags.Flags.  If path
// is empty, the query runs in the current process.  If path is not empty, it
// specifies a command search path used to find a zq executable to run the
// query.
func runzq(path, ZQL string, outputFlags []string, inputs ...string) (string, string, error) {
	var errbuf, outbuf bytes.Buffer
	if path != "" {
		zq, err := lookupzq(path)
		if err != nil {
			return "", "", err
		}
		tmpdir, files, err := tmpInputFiles(inputs)
		if err != nil {
			return "", "", err
		}
		defer os.RemoveAll(tmpdir)
		cmd := exec.Command(zq, append(append(outputFlags, ZQL), files...)...)
		cmd.Stdout = &outbuf
		cmd.Stderr = &errbuf
		err = cmd.Run()
		// If there was an error, errbuf could potentially hold both warnings
		// and error messages, but that's not currently an issue with existing
		// tests.
		return outbuf.String(), errbuf.String(), err
	}
	proc, err := compiler.ParseProc(ZQL)
	if err != nil {
		return "", "", err
	}
	ctx := context.Background()
	zctx := resolver.NewContext()
	rc, err := loadInputs(ctx, inputs, zctx)
	if err != nil {
		return "", err.Error(), err
	}
	var zflags outputflags.Flags
	var flags flag.FlagSet
	zflags.SetFlags(&flags)
	if err := flags.Parse(outputFlags); err != nil {
		return "", "", err
	}
	zw, err := detector.LookupWriter(&nopCloser{&outbuf}, zctx, zflags.Options())
	if err != nil {
		return "", "", err
	}
	d := driver.NewCLI(zw)
	d.SetWarningsWriter(&errbuf)
	err = driver.Run(ctx, d, proc, zctx, rc, driver.Config{})
	if err2 := zw.Close(); err == nil {
		err = err2
	}
	if err != nil {
		errbuf.WriteString(err.Error())
	}
	return outbuf.String(), errbuf.String(), err
}

func lookupzq(path string) (string, error) {
	for _, dir := range filepath.SplitList(path) {
		zq, err := exec.LookPath(filepath.Join(dir, "zq"))
		if err == nil {
			return zq, nil
		}
		if !errors.Is(err, exec.ErrNotFound) {
			return "", err
		}
	}
	return "", zqe.E(zqe.NotFound)
}

func loadInputs(ctx context.Context, inputs []string, zctx *resolver.Context) (zbuf.Reader, error) {
	var readers []zbuf.Reader
	for _, input := range inputs {
		zr, err := detector.NewReader(detector.GzipReader(strings.NewReader(input)), zctx)
		if err != nil {
			return nil, err
		}
		readers = append(readers, zr)
	}
	return zbuf.MergeReadersByTsAsReader(ctx, readers, zbuf.OrderAsc)
}

func tmpInputFiles(inputs []string) (string, []string, error) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		return "", nil, err
	}
	var files []string
	for i, input := range inputs {
		name := fmt.Sprintf("input%d", i+1)
		file := filepath.Join(dir, name)
		if err := ioutil.WriteFile(file, []byte(input), 0644); err != nil {
			os.RemoveAll(dir)
			return "", nil, err
		}
		files = append(files, file)
	}
	return dir, files, nil
}

type nopCloser struct{ io.Writer }

func (*nopCloser) Close() error { return nil }
