package oldconfig_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/pcap"
	"github.com/brimsec/zq/pkg/fs"
	"github.com/brimsec/zq/pkg/iosrc"
	"github.com/brimsec/zq/ppl/zqd/apiserver"
	"github.com/brimsec/zq/ppl/zqd/db/filedb"
	"github.com/brimsec/zq/ppl/zqd/db/filedb/oldconfig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestV3MigrationNoPcap(t *testing.T) {
	tm := newTestMigration(t)

	id := tm.initSpace(oldconfig.ConfigV2{
		Version:  2,
		Name:     "test",
		DataURI:  iosrc.URI{},
		PcapPath: "",
		Storage: api.StorageConfig{
			Kind: api.FileStore,
		},
	})
	conf := tm.spaceInfo(id)

	assert.Equal(t, "test", conf.Name)
	assert.Equal(t, "", conf.PcapPath.String())
	assert.Equal(t, false, conf.PcapSupport)
}

func TestV3MigrationPcap(t *testing.T) {
	tm := newTestMigration(t)
	pcapuri := tm.root.AppendPath("test.pcap")

	id := tm.initSpace(oldconfig.ConfigV2{
		Version:  2,
		Name:     "test",
		DataURI:  iosrc.URI{},
		PcapPath: pcapuri.Filepath(),
		Storage: api.StorageConfig{
			Kind: api.FileStore,
		},
	})
	err := iosrc.WriteFile(context.Background(), pcapuri, nil)
	require.NoError(t, err)
	tm.writeSpaceJSONFile(id, "packets.idx.json", pcap.Index{})

	info := tm.spaceInfo(id)

	assert.Equal(t, "test", info.Name)
	assert.Equal(t, pcapuri, info.PcapPath)
	assert.Equal(t, true, info.PcapSupport)
}

func TestV2Migration(t *testing.T) {
	tm := newTestMigration(t)
	pcapuri := tm.root.AppendPath("test.pcap")

	id := tm.initSpace(oldconfig.ConfigV1{
		Version:  1,
		Name:     "test",
		DataPath: ".",
		PcapPath: pcapuri.Filepath(),
		Storage: api.StorageConfig{
			Kind: api.FileStore,
		},
	})
	err := iosrc.WriteFile(context.Background(), pcapuri, nil)
	require.NoError(t, err)
	tm.writeSpaceJSONFile(id, "packets.idx.json", pcap.Index{})

	info := tm.spaceInfo(id)
	assert.Equal(t, "test", info.Name)
	assert.Equal(t, pcapuri, info.PcapPath)
}

func TestV1Migration(t *testing.T) {
	t.Run("InvalidCharacters", func(t *testing.T) {
		tm := newTestMigration(t)

		tm.initSpace(oldconfig.ConfigV1{Name: "name/𝚭𝚴𝚪/stuff"})

		mgr := tm.manager()
		list, err := mgr.ListSpaces(context.Background())
		require.NoError(t, err)
		require.Len(t, list, 1)
		require.Equal(t, "name_𝚭𝚴𝚪_stuff", list[0].Name)
	})
	t.Run("DuplicateNames", func(t *testing.T) {
		tm := newTestMigration(t)

		tm.initSpace(oldconfig.ConfigV1{Name: "testname"})
		tm.initSpace(oldconfig.ConfigV1{Name: "testname"})

		mgr := tm.manager()
		list, err := mgr.ListSpaces(context.Background())
		require.NoError(t, err)
		require.Len(t, list, 2)
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		require.Equal(t, "testname", list[0].Name)
		require.Equal(t, "testname_01", list[1].Name)
		require.NotEqual(t, list[0].Name, list[1].Name)
	})
}

type testMigration struct {
	*testing.T
	root    iosrc.URI
	mgr     *apiserver.Manager
	counter int
}

func newTestMigration(t *testing.T) *testMigration {
	tm := &testMigration{T: t}
	tm.initRoot()
	return tm
}

func (tm *testMigration) initRoot() {
	root, err := ioutil.TempDir("", "")
	require.NoError(tm.T, err)
	tm.Cleanup(func() {
		os.RemoveAll(root)
	})
	u, err := iosrc.ParseURI(root)
	require.NoError(tm, err)
	tm.root = u
}

func (tm *testMigration) manager() *apiserver.Manager {
	if tm.mgr == nil {
		filedb, err := filedb.Open(context.Background(), zap.NewNop(), tm.root)
		require.NoError(tm.T, err)
		mgr, err := apiserver.NewManager(context.Background(), zap.NewNop(), nil, prometheus.NewRegistry(), tm.root, filedb, nil)
		require.NoError(tm.T, err)
		tm.mgr = mgr
	}
	return tm.mgr
}

func (tm *testMigration) spaceInfo(id api.SpaceID) api.SpaceInfo {
	mgr := tm.manager()
	info, err := mgr.GetSpace(context.Background(), id)
	require.NoError(tm, err)
	return info
}

func (tm *testMigration) initSpace(c interface{}) api.SpaceID {
	tm.counter++
	id := api.SpaceID(fmt.Sprintf("sp_%d", tm.counter))
	spdir := filepath.Join(tm.root.Filepath(), string(id))
	require.NoError(tm, os.Mkdir(spdir, 0700))
	tm.writeSpaceJSONFile(id, oldconfig.ConfigFile, c)
	return id
}

func (tm *testMigration) writeSpaceJSONFile(id api.SpaceID, filename string, c interface{}) {
	spdir := tm.root.AppendPath(string(id)).Filepath()
	require.NoError(tm, fs.MarshalJSONFile(c, filepath.Join(spdir, filename), 0600))
}
