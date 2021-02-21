package s3io

import (
	"context"
	"errors"
	"fmt"
	"io"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

type Reader struct {
	client s3iface.S3API
	ctx    context.Context
	bucket string
	key    string
	size   int64

	offset int64
	body   io.ReadCloser
}

func NewReader(ctx context.Context, path string, client s3iface.S3API) (*Reader, error) {
	info, err := Stat(ctx, path, client)
	if err != nil {
		return nil, err
	}
	bucket, key, err := parsePath(path)
	if err != nil {
		return nil, err
	}
	return &Reader{
		client: client,
		ctx:    ctx,
		bucket: bucket,
		key:    key,
		size:   info.Size,
	}, nil
}

func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += r.offset
	case io.SeekEnd:
		offset += r.size
	default:
		return 0, errors.New("s3io.Reader.Seek: invalid whence")
	}
	if offset < 0 {
		return 0, errors.New("s3io.Reader.Seek: negative position")
	}
	if offset == r.offset {
		return offset, nil
	}
	r.offset = offset
	if r.body != nil {
		r.body.Close()
		r.body = nil
	}
	return r.offset, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.offset >= r.size {
		return 0, io.EOF
	}
request:
	if r.body == nil {
		body, err := r.makeRequest(r.offset, r.size-r.offset)
		if err != nil {
			return 0, err
		}
		r.body = body
	}

	n, err := r.body.Read(p)
	if errors.Is(err, syscall.ECONNRESET) {
		// If the error is result of a connection reset set the body to nil and
		// attempt to restart the connection at the current offset. There seems to
		// be a curious behavior of the s3 service that happens when a single
		// session maintains numerous long-running download connections to various
		// objects in a bucket- the service appears to reset connections at random.
		//
		// See: https://github.com/aws/aws-sdk-go/issues/1242
		r.body = nil
		goto request
	}
	if err == io.EOF {
		err = nil
	}
	if err == nil {
		r.offset += int64(n)
	}
	return n, err
}

func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	count := int64(len(p))
	if off+count >= r.size {
		count = r.size - off
	}
	b, err := r.makeRequest(off, count)
	if err != nil {
		return 0, err
	}
	defer b.Close()
	return io.ReadAtLeast(b, p, int(count))
}

func (r *Reader) Close() error {
	var err error
	if r.body != nil {
		err = r.body.Close()
		r.body = nil
	}
	return err
}

func (r *Reader) makeRequest(off int64, count int64) (io.ReadCloser, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(r.key),
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", off, off+count-1)),
	}
	res, err := r.client.GetObjectWithContext(r.ctx, input)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}
