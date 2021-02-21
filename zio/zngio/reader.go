package zngio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/brimsec/zq/expr"
	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/pkg/peeker"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/pierrec/lz4/v4"
)

const (
	ReadSize  = 512 * 1024
	MaxSize   = 10 * 1024 * 1024
	TypeLimit = 10000
)

type Reader struct {
	peeker          *peeker.Reader
	peekerOffset    int64 // never points inside a compressed value message block
	uncompressedBuf *buffer
	// shared/output context
	sctx *resolver.Context
	// internal context implied by zng file
	zctx *resolver.Context
	// mapper to map internal to shared type contexts
	mapper   *resolver.Mapper
	sos      int64
	validate bool
	app      AppMessage
}

type ReaderOpts struct {
	Validate bool
	Size     int
	Max      int
}

type AppMessage struct {
	Code     int
	Encoding int
	Bytes    []byte
}

func NewReader(reader io.Reader, sctx *resolver.Context) *Reader {
	return NewReaderWithOpts(reader, sctx, ReaderOpts{})
}

func NewReaderWithOpts(reader io.Reader, sctx *resolver.Context, opts ReaderOpts) *Reader {
	if opts.Size == 0 {
		opts.Size = ReadSize
	}
	if opts.Max == 0 {
		opts.Max = MaxSize
	}
	if opts.Size > opts.Max {
		opts.Size = opts.Max
	}
	return &Reader{
		peeker:   peeker.NewReader(reader, opts.Size, opts.Max),
		sctx:     sctx,
		zctx:     resolver.NewContext(),
		mapper:   resolver.NewMapper(sctx),
		validate: opts.Validate,
	}
}

func (r *Reader) Position() int64 {
	return r.peekerOffset
}

// SkipStream skips over the records in the current stream and returns
// the first record of the next stream and the start-of-stream position
// of that record.
func (r *Reader) SkipStream() (*zng.Record, int64, error) {
	sos := r.sos
	for {
		rec, err := r.Read()
		if err != nil || sos != r.sos || rec == nil {
			return rec, r.sos, err
		}
	}
}

func (r *Reader) Read() (*zng.Record, error) {
	for {
		rec, msg, err := r.ReadPayload()
		if err != nil {
			return nil, err
		}
		if msg != nil {
			continue
		}
		return rec, err
	}
}

func (r *Reader) ReadPayload() (*zng.Record, *AppMessage, error) {
	for {
		rec, msg, err := r.readPayload(nil)
		if err != nil {
			if err == startBatch || err == endBatch {
				continue
			}
			return nil, nil, err
		}
		return rec, msg, err
	}
}

// LastSOS returns the offset of the most recent Start-of-Stream
func (r *Reader) LastSOS() int64 {
	return r.sos
}

func (r *Reader) reset() {
	r.zctx.Reset()
	r.mapper = resolver.NewMapper(r.sctx)
	r.sos = r.peekerOffset
}

var startBatch = errors.New("start of uncompressed batch")
var endBatch = errors.New("end of uncompressed batch encountered while parsing data")

// ReadPayload returns either data values as zbuf.Record or app-specific
// messages .  The record or message is volatile so they must be
// copied (via copy for message's byte slice or zbuf.Record.Keep()) as
// subsequent calls to Read or ReadPayload will modify the referenced data.
func (r *Reader) readPayload(rec *zng.Record) (*zng.Record, *AppMessage, error) {
	for {
		b, err := r.read(1)
		if err != nil {
			// Having tried to read a single byte above, ErrTruncated means io.EOF.
			if err == io.EOF || err == peeker.ErrTruncated {
				return nil, nil, nil
			}
			return nil, nil, err
		}
		code := b[0]
		if code <= zng.CtrlValueEscape {
			rec, err := r.readValue(rec, int(code))
			return rec, nil, err
		}
		switch code {
		case zng.TypeDefRecord:
			err = r.readTypeRecord()
		case zng.TypeDefSet:
			err = r.readTypeSet()
		case zng.TypeDefArray:
			err = r.readTypeArray()
		case zng.TypeDefUnion:
			err = r.readTypeUnion()
		case zng.TypeDefEnum:
			err = r.readTypeEnum()
		case zng.TypeDefMap:
			err = r.readTypeMap()
		case zng.TypeDefAlias:
			err = r.readTypeAlias()
		case zng.CtrlEOS:
			r.reset()
		case zng.CtrlCompressed:
			return nil, nil, r.readCompressed()
		case zng.CtrlAppMessage:
			msg, err := r.readAppMessage(int(code))
			return nil, msg, err
		default:
			err = fmt.Errorf("unknown zng control code: %d", code)
		}
		if err != nil {
			return nil, nil, err
		}
	}
}

func (r *Reader) readValue(rec *zng.Record, id int) (*zng.Record, error) {
	if id == zng.CtrlValueEscape {
		var err error
		id, err = r.readUvarint()
		if err != nil {
			return nil, err
		}
	}
	len, err := r.readUvarint()
	if err != nil {
		return nil, zng.ErrBadFormat
	}
	b, err := r.read(len)
	if err != nil && err != io.EOF {
		if err == peeker.ErrBufferOverflow {
			return nil, fmt.Errorf("large value of %d bytes exceeds maximum read buffer (%d bytes)", len, r.peeker.Limit())
		}
		return nil, zng.ErrBadFormat
	}
	rec, err = r.parseValue(rec, id, b)
	return rec, err
}

func (r *Reader) readAppMessage(code int) (*AppMessage, error) {
	encoding, err := r.ReadByte()
	if err != nil {
		return nil, zng.ErrBadFormat
	}
	len, err := r.readUvarint()
	if err != nil {
		return nil, zng.ErrBadFormat
	}
	buf, err := r.read(len)
	if err != nil {
		return nil, err
	}
	r.app.Code = code
	r.app.Encoding = int(encoding)
	r.app.Bytes = buf
	return &r.app, err
}

// read returns an error if fewer than n bytes are available.
func (r *Reader) read(n int) ([]byte, error) {
	if r.uncompressedBuf != nil {
		if r.uncompressedBuf.length() > 0 {
			if n > MaxSize {
				return nil, errors.New("zngio: read exceeds MaxSize buffer")
			}
			buf := r.uncompressedBuf.next(n)
			if len(buf) < n {
				return nil, errors.New("zngio: short read from decompression buffer")
			}
			return buf, nil
		}
		r.uncompressedBuf = nil
		return nil, endBatch
	}
	b, err := r.peeker.Read(n)
	r.peekerOffset += int64(len(b))
	return b, err
}

func (r *Reader) readCompressed() error {
	if r.uncompressedBuf != nil {
		return errors.New("zngio: cannot have zng compression inside of compression")
	}
	format, err := r.readUvarint()
	if err != nil {
		return err
	}
	if zng.CompressionFormat(format) != zng.CompressionFormatLZ4 {
		return fmt.Errorf("zngio: unknown compression format 0x%x", format)
	}
	uncompressedLen, err := r.readUvarint()
	if err != nil {
		return err
	}
	if uncompressedLen > MaxSize {
		return errors.New("zngio: uncompressed length exceeds MaxSize")
	}
	compressedLen, err := r.readUvarint()
	if err != nil {
		return err
	}
	zbuf, err := r.read(compressedLen)
	if err != nil {
		return err
	}
	ubuf := newBuffer(uncompressedLen)
	n, err := lz4.UncompressBlock(zbuf, ubuf.Bytes())
	if err != nil {
		return fmt.Errorf("zngio: %w", err)
	}
	if n != uncompressedLen {
		return fmt.Errorf("zngio: got %d uncompressed bytes, expected %d", n, uncompressedLen)
	}
	r.uncompressedBuf = ubuf
	return startBatch
}

func (r *Reader) readUvarint() (int, error) {
	u64, err := binary.ReadUvarint(r)
	return int(u64), err
}

// ReadByte implements io.ByteReader.ReadByte.
func (r *Reader) ReadByte() (byte, error) {
	if r.uncompressedBuf != nil && r.uncompressedBuf.length() > 0 {
		return r.uncompressedBuf.ReadByte()
	}
	b, err := r.peeker.ReadByte()
	if err == nil {
		r.peekerOffset++
	}
	return b, err
}

func (r *Reader) readColumn() (zng.Column, error) {
	len, err := r.readUvarint()
	if err != nil {
		return zng.Column{}, zng.ErrBadFormat
	}
	b, err := r.read(len)
	if err != nil {
		return zng.Column{}, zng.ErrBadFormat
	}
	// pull the name out before the next read which might overwrite the buffer
	name := string(b)
	id, err := r.readUvarint()
	if err != nil {
		return zng.Column{}, zng.ErrBadFormat
	}
	typ, err := r.zctx.LookupType(id)
	if err != nil {
		return zng.Column{}, err
	}
	return zng.NewColumn(name, typ), nil
}

func (r *Reader) readTypeRecord() error {
	ncol, err := r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	var columns []zng.Column
	for k := 0; k < int(ncol); k++ {
		col, err := r.readColumn()
		if err != nil {
			return err
		}
		columns = append(columns, col)
	}
	r.zctx.LookupTypeRecord(columns)
	return nil
}

func (r *Reader) readTypeUnion() error {
	ntyp, err := r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	if ntyp == 0 {
		return errors.New("type union: zero columns not allowed")
	}
	var types []zng.Type
	for k := 0; k < int(ntyp); k++ {
		id, err := r.readUvarint()
		if err != nil {
			return zng.ErrBadFormat
		}
		typ, err := r.zctx.LookupType(int(id))
		if err != nil {
			return err
		}
		types = append(types, typ)
	}
	r.zctx.LookupTypeUnion(types)
	return nil
}

func (r *Reader) readTypeSet() error {
	id, err := r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	typ, err := r.zctx.LookupType(int(id))
	if err != nil {
		return err
	}
	r.zctx.AddType(&zng.TypeSet{Type: typ})
	return nil
}

func (r *Reader) readTypeEnum() error {
	id, err := r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	typ, err := r.zctx.LookupType(int(id))
	if err != nil {
		return err
	}
	nelem, err := r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	var elems []zng.Element
	for k := 0; k < int(nelem); k++ {
		elem, err := r.readElement()
		if err != nil {
			return err
		}
		elems = append(elems, elem)
	}
	r.zctx.LookupTypeEnum(typ, elems)
	return nil
}

func (r *Reader) readElement() (zng.Element, error) {
	n, err := r.readUvarint()
	if err != nil {
		return zng.Element{}, zng.ErrBadFormat
	}
	b, err := r.read(n)
	if err != nil {
		return zng.Element{}, zng.ErrBadFormat
	}
	// pull the name out before the next read which might overwrite the buffer
	name := string(b)
	zv, _, err := zcode.Read(r)
	if err != nil {
		return zng.Element{}, zng.ErrBadFormat
	}
	return zng.Element{name, zv}, nil
}

func (r *Reader) readTypeMap() error {
	id, err := r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	keyType, err := r.zctx.LookupType(int(id))
	if err != nil {
		return err
	}
	id, err = r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	valType, err := r.zctx.LookupType(int(id))
	if err != nil {
		return err
	}
	r.zctx.AddType(&zng.TypeMap{KeyType: keyType, ValType: valType})
	return nil
}

func (r *Reader) readTypeArray() error {
	id, err := r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	inner, err := r.zctx.LookupType(int(id))
	if err != nil {
		return err
	}
	r.zctx.AddType(zng.NewTypeArray(-1, inner))
	return nil
}

func (r *Reader) readTypeAlias() error {
	len, err := r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	b, err := r.read(len)
	if err != nil {
		return zng.ErrBadFormat
	}
	name := string(b)
	id, err := r.readUvarint()
	if err != nil {
		return zng.ErrBadFormat
	}
	inner, err := r.zctx.LookupType(int(id))
	if err != nil {
		return err
	}
	_, err = r.zctx.LookupTypeAlias(name, inner)
	if err != nil {
		return err
	}
	return nil
}

func (r *Reader) parseValue(rec *zng.Record, id int, b []byte) (*zng.Record, error) {
	typ := r.zctx.Lookup(id)
	if typ == nil {
		return nil, zng.ErrTypeIDInvalid
	}
	sharedType := r.mapper.Map(id)
	if sharedType == nil {
		var err error
		sharedType, err = r.mapper.Enter(id, typ)
		if err != nil {
			return nil, err
		}
	}
	if rec == nil {
		rec = zng.NewVolatileRecordFromType(sharedType, b)
	} else {
		*rec = *zng.NewVolatileRecordFromType(sharedType, b)
	}
	if r.validate {
		if err := rec.TypeCheck(); err != nil {
			return nil, err
		}
	}
	return rec, nil
}

var _ zbuf.ScannerAble = (*Reader)(nil)

func (r *Reader) NewScanner(ctx context.Context, pruner zbuf.Filter, s nano.Span) (zbuf.Scanner, error) {
	var bf *expr.BufferFilter
	var f expr.Filter
	if pruner != nil {
		var err error
		bf, err = pruner.AsBufferFilter()
		if err != nil {
			return nil, err
		}
		f, err = pruner.AsFilter()
		if err != nil {
			return nil, err
		}
	}
	return &zngScanner{ctx: ctx, reader: r, bufferFilter: bf, filter: f, span: s}, nil
}
