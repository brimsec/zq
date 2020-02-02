package search

import (
	"encoding/json"
	"net/http"

	"github.com/mccanne/zq/zbuf"
	"github.com/mccanne/zq/zio/bzngio"
)

// bzngOutput writes bzng encodings directly to the client via
// binary data sent over http chunked encoding interleaved with json
// protocol messages sent as zng comment payloads.  The simplicity of
// this is a thing of beauty.
type bzngOutput struct {
	*http.Request
	response http.ResponseWriter
	writer   *bzngio.Writer
}

func newBzngOutput(req *http.Request, response http.ResponseWriter) *bzngOutput {
	o := &bzngOutput{
		Request:  req,
		response: response,
		writer:   bzngio.NewWriter(response),
	}
	return o
}

func (r *bzngOutput) flush() {
	r.response.(http.Flusher).Flush()
}

func (r *bzngOutput) Collect() interface{} {
	return "TBD" //XXX
}

func (r *bzngOutput) SendBatch(cid int, batch zbuf.Batch) error {
	for _, rec := range batch.Records() {
		// XXX need to send channel id as control payload
		if err := r.writer.Write(rec); err != nil {
			return err
		}
	}
	batch.Unref()
	r.flush()
	return nil
}

func (r *bzngOutput) End(ctrl interface{}) error {
	return r.SendControl(ctrl)
}

func (r *bzngOutput) SendControl(ctrl interface{}) error {
	msg, err := json.Marshal(ctrl)
	if err != nil {
		//XXX need a better json error message
		return err
	}
	b := []byte("json:")
	if err := r.writer.WriteControl(append(b, msg...)); err != nil {
		return err
	}
	r.flush()
	return nil
}
