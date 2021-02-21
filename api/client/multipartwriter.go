package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"sync"
	"sync/atomic"

	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/pkg/iosrc"
	"github.com/brimsec/zq/zio/ndjsonio"
)

type MultipartWriter struct {
	BytesTotal int64

	bytesRead int64
	form      *multipart.Writer
	pr        *io.PipeReader
	pw        *io.PipeWriter
	start     sync.Once
	readers   []io.Reader
	uris      []iosrc.URI
	json      *ndjsonio.TypeConfig
	shaper    ast.Proc
}

func newMultipartWriter() *MultipartWriter {
	pr, pw := io.Pipe()
	form := multipart.NewWriter(pw)
	return &MultipartWriter{form: form, pr: pr, pw: pw}
}

func MultipartFileWriter(files ...string) (*MultipartWriter, error) {
	m := newMultipartWriter()
	for _, f := range files {
		u, err := iosrc.ParseURI(f)
		if err != nil {
			return nil, err
		}
		info, err := iosrc.Stat(context.Background(), u)
		if err != nil {
			return nil, err
		}
		m.BytesTotal += info.Size()
		m.uris = append(m.uris, u)
	}
	return m, nil
}

func MultipartDataWriter(readers ...io.Reader) (*MultipartWriter, error) {
	m := newMultipartWriter()
	m.readers = readers
	return m, nil
}

func (m *MultipartWriter) SetJSONConfig(config *ndjsonio.TypeConfig) {
	m.json = config
}

func (m *MultipartWriter) SetShaper(shaper ast.Proc) {
	m.shaper = shaper
}

func (m *MultipartWriter) ContentType() string {
	return m.form.FormDataContentType()
}

func (m *MultipartWriter) BytesRead() int64 {
	return atomic.LoadInt64(&m.bytesRead)
}

func (m *MultipartWriter) Read(b []byte) (int, error) {
	m.start.Do(func() {
		go m.run()
	})
	return m.pr.Read(b)
}

func (m *MultipartWriter) run() {
	if err := m.sendJSONConfig(); err != nil {
		m.pw.CloseWithError(err)
		return
	}
	if err := m.sendShaperAST(); err != nil {
		m.pw.CloseWithError(err)
		return
	}
	for _, u := range m.uris {
		if err := m.writeFile(u); err != nil {
			m.pw.CloseWithError(err)
			return
		}
	}
	for i, r := range m.readers {
		if err := m.write(fmt.Sprintf("data%d", i+1), r); err != nil {
			m.pw.CloseWithError(err)
			return
		}
	}
	m.pw.CloseWithError(m.form.Close())
}

func (m *MultipartWriter) writeFile(u iosrc.URI) error {
	r, err := iosrc.NewReader(context.Background(), u)
	if err != nil {
		return err
	}
	defer r.Close()
	return m.write(u.String(), r)
}

func (m *MultipartWriter) write(name string, r io.Reader) error {
	w, err := m.form.CreateFormFile("", name)
	if err != nil {
		return err
	}
	c := &counter{reader: bufio.NewReader(r), nread: &m.bytesRead}
	_, err = io.Copy(w, c)
	return err
}

func (m *MultipartWriter) sendJSONConfig() error {
	if m.json == nil {
		return nil
	}
	w, err := m.form.CreateFormField("json_config")
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(m.json)
}

func (m *MultipartWriter) sendShaperAST() error {
	if m.shaper == nil {
		return nil
	}
	w, err := m.form.CreateFormField("shaper_ast")
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(m.shaper)
}

type counter struct {
	reader io.Reader
	nread  *int64
}

func (r *counter) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	atomic.AddInt64(r.nread, int64(n))
	return n, err
}
