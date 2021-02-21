package chunk

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"github.com/brimsec/zq/pkg/iosrc"
	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zqe"
	"github.com/segmentio/ksuid"
)

// A FileKind is the first part of a file name, used to differentiate files
// when they are listed from the archive's backing store.
type FileKind string

const (
	FileKindUnknown  FileKind = ""
	FileKindData     FileKind = "d"
	FileKindMetadata FileKind = "m"
	FileKindSeek     FileKind = "ts"
)

func (k FileKind) Description() string {
	switch k {
	case FileKindData:
		return "data"
	case FileKindMetadata:
		return "metadata"
	case "FileKindSeek":
		return "seekindex"
	default:
		return "unknown"
	}
}

var fileRegex = regexp.MustCompile(`(d|m)-([0-9A-Za-z]{27}).zng$`)

func FileMatch(s string) (kind FileKind, id ksuid.KSUID, ok bool) {
	match := fileRegex.FindStringSubmatch(s)
	if match == nil {
		return
	}
	k := FileKind(match[1])
	switch k {
	case FileKindData:
	case FileKindMetadata:
	default:
		return
	}
	id, err := ksuid.Parse(match[2])
	if err != nil {
		return
	}
	return k, id, true
}

// A Chunk is a file that holds records ordered according to the archive's
// data order.
// To support reading chunks that contain records originally from one or
// more other chunks, a chunk has a list of chunk IDs it "masks". During a read
// of data for time span T, if chunks X and Y both have data within span T, and
// X masks Y, then only data from X should be used.
// seekIndexPath returns the path of an associated microindex written at import
// time, which can be used to lookup a nearby seek offset for a desired
// timestamp.
// MetadataPath returns the path of an associated zng file that holds
// information about the records in the chunk, including the total number,
// and the first and last record timestamps.
type Chunk struct {
	Dir         iosrc.URI
	Id          ksuid.KSUID
	First       nano.Ts
	Last        nano.Ts
	RecordCount uint64
	Masks       []ksuid.KSUID
	Size        int64
}

func Open(ctx context.Context, dir iosrc.URI, id ksuid.KSUID, order zbuf.Order) (Chunk, error) {
	b, err := iosrc.ReadFile(ctx, MetadataPath(dir, id))
	if err != nil {
		return Chunk{}, err
	}
	meta, err := UnmarshalMetadata(b, order)
	if err != nil {
		return Chunk{}, err
	}
	return meta.Chunk(dir, id), nil
}

func (c Chunk) Path() iosrc.URI {
	return c.Dir.AppendPath(c.FileName())
}

// MaskedPaths returns a list of the iosrc.URIs of chunks that this chunk masks.
func (c Chunk) MaskedPaths() []iosrc.URI {
	paths := make([]iosrc.URI, len(c.Masks))
	for i, m := range c.Masks {
		paths[i] = ChunkPath(c.Dir, m)
	}
	return paths
}

func (c Chunk) SeekIndexPath() iosrc.URI {
	return chunkSeekIndexPath(c.Dir, c.Id)
}

func (c Chunk) MetadataPath() iosrc.URI {
	return MetadataPath(c.Dir, c.Id)
}

func (c Chunk) Span() nano.Span {
	return nano.Span{Ts: c.First, Dur: 1}.Union(nano.Span{Ts: c.Last, Dur: 1})
}

func (c Chunk) FileName() string {
	return ChunkFileName(c.Id)
}

func ChunkFileName(id ksuid.KSUID) string {
	return fmt.Sprintf("%s-%s.zng", FileKindData, id)
}

// ZarDir returns a URI for a directory specific to this data file, expected
// to hold microindexes or other files associated with this chunk's data.
func (c Chunk) ZarDir() iosrc.URI {
	return chunkZarDir(c.Dir, c.Id)
}

// Localize returns a URI that joins the provided relative path name to the
// zardir for this chunk. The special name "_" is mapped to the path of the
// data file for this chunk.
func (c Chunk) Localize(pathname string) iosrc.URI {
	if pathname == "_" {
		return c.Path()
	}
	return c.ZarDir().AppendPath(pathname)
}

func ChunkPath(dir iosrc.URI, id ksuid.KSUID) iosrc.URI {
	return dir.AppendPath(ChunkFileName(id))
}

func chunkSeekIndexPath(tsd iosrc.URI, id ksuid.KSUID) iosrc.URI {
	return tsd.AppendPath(fmt.Sprintf("%s-%s.zng", FileKindSeek, id))
}

func chunkZarDir(dir iosrc.URI, id ksuid.KSUID) iosrc.URI {
	return dir.AppendPath(ChunkFileName(id) + ".zar")
}

func (c Chunk) Range() string {
	return fmt.Sprintf("[%d-%d]", c.First, c.Last)
}

// Remove deletes the data, metadata, seek, and any other associated files
// with the chunk, including the zar directory. Any 'not found' errors will
// be ignored.
func (c Chunk) Remove(ctx context.Context) error {
	uris := []iosrc.URI{
		c.Path(),
		c.ZarDir(),
		c.MetadataPath(),
		c.SeekIndexPath(),
	}
	for _, u := range uris {
		if err := iosrc.RemoveAll(ctx, u); err != nil && !zqe.IsNotFound(err) {
			return err
		}
	}
	return nil
}

type Chunks []Chunk

func (cs Chunks) Overlapping(span nano.Span) Chunks {
	chunks := make(Chunks, 0, len(cs))
	for _, chunk := range cs {
		if span.Overlaps(chunk.Span()) {
			chunks = append(chunks, chunk)
		}
	}
	return chunks
}

func Less(order zbuf.Order, a, b Chunk) bool {
	if order == zbuf.OrderDesc {
		a, b = b, a
	}
	switch {
	case a.First != b.First:
		return a.First < b.First
	case a.Last != b.Last:
		return a.Last < b.Last
	case a.RecordCount != b.RecordCount:
		return a.RecordCount < b.RecordCount
	}
	return ksuid.Compare(a.Id, b.Id) < 0
}

func Sort(order zbuf.Order, c []Chunk) {
	sort.Slice(c, func(i, j int) bool {
		return Less(order, c[i], c[j])
	})
}
