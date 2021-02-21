package zqd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/compiler"
	"github.com/brimsec/zq/pcap"
	"github.com/brimsec/zq/pkg/ctxio"
	"github.com/brimsec/zq/ppl/zqd/auth"
	"github.com/brimsec/zq/ppl/zqd/ingest"
	"github.com/brimsec/zq/ppl/zqd/jsonpipe"
	"github.com/brimsec/zq/ppl/zqd/search"
	"github.com/brimsec/zq/ppl/zqd/storage/archivestore"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zqe"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

var errFileStoreReadOnly = zqe.ErrInvalid("file storage spaces are read only")

func errorResponse(e error) (status int, ae *api.Error) {
	status = http.StatusInternalServerError
	ae = &api.Error{Type: "Error"}

	var ze *zqe.Error
	if !errors.As(e, &ze) {
		ae.Message = e.Error()
		return
	}

	switch ze.Kind {
	case zqe.Invalid:
		status = http.StatusBadRequest
	case zqe.NotFound:
		status = http.StatusNotFound
	case zqe.Exists:
		status = http.StatusBadRequest
	case zqe.Conflict:
		status = http.StatusConflict
	case zqe.NoCredentials:
		status = http.StatusUnauthorized
	case zqe.Forbidden:
		status = http.StatusForbidden
	}

	ae.Kind = ze.Kind.String()
	ae.Message = ze.Message()
	return
}

func respond(c *Core, w http.ResponseWriter, r *http.Request, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		c.requestLogger(r).Warn("Error writing response", zap.Error(err))
	}
}

func respondError(c *Core, w http.ResponseWriter, r *http.Request, err error) {
	status, ae := errorResponse(err)
	if status >= 500 {
		c.requestLogger(r).Warn("error", zap.Int("status", status), zap.Error(err))
	}
	respond(c, w, r, status, ae)
}

func request(c *Core, w http.ResponseWriter, r *http.Request, apiobj interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(apiobj); err != nil {
		respondError(c, w, r, zqe.E(zqe.Invalid, err))
		return false
	}
	return true
}

func handleASTPost(c *Core, w http.ResponseWriter, r *http.Request) {
	var req api.ASTRequest
	if !request(c, w, r, &req) {
		return
	}
	proc, err := compiler.ParseProc(req.ZQL)
	if err != nil {
		respondError(c, w, r, zqe.ErrInvalid(err))
		return
	}
	respond(c, w, r, http.StatusOK, proc)
}

func handleSearch(c *Core, w http.ResponseWriter, r *http.Request) {
	var req api.SearchRequest
	if !request(c, w, r, &req) {
		return
	}

	srch, err := search.NewSearchOp(req, c.requestLogger(r))
	if err != nil {
		respondError(c, w, r, err)
		return
	}

	out, err := getSearchOutput(w, r)
	if err != nil {
		respondError(c, w, r, err)
		return
	}

	store, err := c.mgr.GetStorage(r.Context(), req.Space)
	if err != nil {
		respondError(c, w, r, err)
		return
	}

	w.Header().Set("Content-Type", out.ContentType())
	if err := srch.Run(r.Context(), store, out, 0, c.conf.Worker); err != nil {
		c.requestLogger(r).Warn("Error writing response", zap.Error(err))
	}
}

func getSearchOutput(w http.ResponseWriter, r *http.Request) (search.Output, error) {
	ctrl := true
	if r.URL.Query().Get("noctrl") != "" {
		ctrl = false
	}
	format := r.URL.Query().Get("format")
	switch format {
	case "csv":
		return search.NewCSVOutput(w, ctrl), nil
	case "json":
		return search.NewJSONOutput(w, search.DefaultMTU, ctrl), nil
	case "ndjson":
		return search.NewNDJSONOutput(w), nil
	case "zjson":
		return search.NewZJSONOutput(w, search.DefaultMTU, ctrl), nil
	case "zng":
		return search.NewZngOutput(w, ctrl), nil
	default:
		return nil, zqe.E(zqe.Invalid, "unsupported search format: %s", format)
	}
}

func handlePcapSearch(c *Core, w http.ResponseWriter, r *http.Request) {
	var req api.PcapSearch
	if err := req.FromQuery(r.URL.Query()); err != nil {
		respondError(c, w, r, zqe.E(zqe.Invalid, err))
		return
	}
	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}
	pcapstore, err := c.mgr.GetPcapStorage(r.Context(), id)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	if pcapstore.Empty() {
		respondError(c, w, r, zqe.E(zqe.NotFound, "no pcap in this space"))
		return
	}
	reader, err := pcapstore.NewSearch(r.Context(), req)
	if err == pcap.ErrNoPcapsFound {
		respondError(c, w, r, zqe.E(zqe.NotFound, err))
		return
	}
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%s.pcap", reader.ID()))
	_, err = ctxio.Copy(r.Context(), w, reader)
	if err != nil {
		c.requestLogger(r).Error("Error writing packet response", zap.Error(err))
	}
}

func handleSpaceList(c *Core, w http.ResponseWriter, r *http.Request) {
	spaces, err := c.mgr.ListSpaces(r.Context())
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	respond(c, w, r, http.StatusOK, spaces)
}

func handleSpaceGet(c *Core, w http.ResponseWriter, r *http.Request) {
	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}

	info, err := c.mgr.GetSpace(r.Context(), id)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	respond(c, w, r, http.StatusOK, info)
}

func handleSpacePost(c *Core, w http.ResponseWriter, r *http.Request) {
	var req api.SpacePostRequest
	if !request(c, w, r, &req) {
		return
	}

	info, err := c.mgr.CreateSpace(r.Context(), req)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	respond(c, w, r, http.StatusOK, info)
}

func handleSpacePut(c *Core, w http.ResponseWriter, r *http.Request) {
	var req api.SpacePutRequest
	if !request(c, w, r, &req) {
		return
	}
	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}

	if err := c.mgr.UpdateSpaceName(r.Context(), id, req.Name); err != nil {
		respondError(c, w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleSpaceDelete(c *Core, w http.ResponseWriter, r *http.Request) {
	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}

	if err := c.mgr.DeleteSpace(r.Context(), id); err != nil {
		respondError(c, w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handlePcapPost(c *Core, w http.ResponseWriter, r *http.Request) {
	if !c.HasZeek() {
		respondError(c, w, r, zqe.E(zqe.Invalid, "pcap post not supported: Zeek not found"))
		return
	}
	logger := c.requestLogger(r)

	var req api.PcapPostRequest
	if !request(c, w, r, &req) {
		return
	}

	ctx := r.Context()
	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}
	store, err := c.mgr.GetStorage(ctx, id)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	if store.Kind() == api.FileStore && api.FileStoreReadOnly {
		respondError(c, w, r, errFileStoreReadOnly)
		return
	}
	pcapstore, err := c.mgr.GetPcapStorage(ctx, id)
	if err != nil {
		respondError(c, w, r, err)
		return
	}

	op, err := ingest.NewPcapOp(ctx, store, pcapstore, req.Path, c.conf.Suricata, c.conf.Zeek)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/ndjson")
	w.WriteHeader(http.StatusAccepted)
	pipe := jsonpipe.New(w)
	taskID := c.nextTaskID()
	taskStart := api.TaskStart{Type: "TaskStart", TaskID: taskID}
	if err := pipe.Send(taskStart); err != nil {
		logger.Warn("Error sending payload", zap.Error(err))
		return
	}
	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()
	for {
		var done bool
		select {
		case <-op.Done():
			done = true
		case <-op.Snap():
		case warning := <-op.Warn():
			err := pipe.Send(api.PcapPostWarning{
				Type:    "PcapPostWarning",
				Warning: warning,
			})
			if err != nil {
				logger.Warn("error sending payload", zap.Error(err))
				return
			}
		case <-ticker.C:
		}

		sum, err := store.Summary(ctx)
		if err != nil {
			logger.Warn("Error reading storage summary", zap.Error(err))
			return
		}

		status := op.Status()
		status.Span = &sum.Span
		if err := pipe.Send(status); err != nil {
			logger.Warn("Error sending payload", zap.Error(err))
			return
		}
		if done {
			break
		}
	}
	taskEnd := api.TaskEnd{Type: "TaskEnd", TaskID: taskID}

	if ctx.Err() != nil {
		taskEnd.Error = &api.Error{Type: "Error", Message: "pcap post operation canceled"}
	} else if operr := op.Err(); operr != nil {
		var ok bool
		taskEnd.Error, ok = operr.(*api.Error)
		if !ok {
			taskEnd.Error = &api.Error{Type: "Error", Message: operr.Error()}
		}
	}
	if err := pipe.SendFinal(taskEnd); err != nil {
		logger.Warn("Error sending payload", zap.Error(err))
		return
	}
}

func handleLogPost(c *Core, w http.ResponseWriter, r *http.Request) {
	var req api.LogPostRequest
	if !request(c, w, r, &req) {
		return
	}
	if len(req.Paths) == 0 {
		respondError(c, w, r, zqe.E(zqe.Invalid, "empty paths"))
		return
	}
	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}

	store, err := c.mgr.GetStorage(r.Context(), id)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	if store.Kind() == api.FileStore && api.FileStoreReadOnly {
		respondError(c, w, r, errFileStoreReadOnly)
		return
	}

	op, err := ingest.NewLogOp(r.Context(), store, req)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/ndjson")
	w.WriteHeader(http.StatusAccepted)
	logger := c.requestLogger(r)
	pipe := jsonpipe.New(w)
	if err := pipe.SendStart(0); err != nil {
		logger.Warn("error sending payload", zap.Error(err))
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
loop:
	for {
		select {
		case warning, ok := <-op.Status():
			if !ok {
				break loop
			}
			err := pipe.Send(api.LogPostWarning{
				Type:    "LogPostWarning",
				Warning: warning,
			})
			if err != nil {
				logger.Warn("error sending payload", zap.Error(err))
				return
			}
		case <-ticker.C:
			if err := pipe.Send(op.Stats()); err != nil {
				logger.Warn("error sending payload", zap.Error(err))
				return
			}
		}
	}
	// send final status
	if err := pipe.Send(op.Stats()); err != nil {
		logger.Warn("error sending payload", zap.Error(err))
		return
	}
	if err := pipe.SendEnd(0, op.Error()); err != nil {
		logger.Warn("error sending payload", zap.Error(err))
		return
	}
}

func handleLogStream(c *Core, w http.ResponseWriter, r *http.Request) {
	form, err := r.MultipartReader()
	if err != nil {
		respondError(c, w, r, zqe.ErrInvalid(err))
		return
	}

	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}

	store, err := c.mgr.GetStorage(r.Context(), id)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	if store.Kind() == api.FileStore && api.FileStoreReadOnly {
		respondError(c, w, r, errFileStoreReadOnly)
		return
	}

	zctx := resolver.NewContext()
	zr := ingest.NewMultipartLogReader(form, zctx)

	if r.URL.Query().Get("stop_err") != "" {
		zr.SetStopOnError()
	}

	if err := store.Write(r.Context(), zctx, zr); err != nil {
		respondError(c, w, r, err)
		return
	}

	respond(c, w, r, http.StatusOK, api.LogPostResponse{
		Type:      "LogPostResponse",
		BytesRead: zr.BytesRead(),
		Warnings:  zr.Warnings(),
	})
}

func handleIndexPost(c *Core, w http.ResponseWriter, r *http.Request) {
	var req api.IndexPostRequest
	if !request(c, w, r, &req) {
		return
	}
	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}
	store, err := c.mgr.GetStorage(r.Context(), id)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	as, ok := store.(*archivestore.Storage)
	if !ok {
		respondError(c, w, r, zqe.E(zqe.Invalid, "space storage does not support creating indexes"))
		return
	}

	if err := as.IndexCreate(r.Context(), req); err != nil {
		respondError(c, w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleIndexSearch(c *Core, w http.ResponseWriter, r *http.Request) {
	var req api.IndexSearchRequest
	if !request(c, w, r, &req) {
		return
	}
	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}
	store, err := c.mgr.GetStorage(r.Context(), id)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	as, ok := store.(*archivestore.Storage)
	if !ok {
		respondError(c, w, r, zqe.E(zqe.Invalid, "space storage does not support index search"))
		return
	}

	srch, err := search.NewIndexSearchOp(r.Context(), as, req)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	defer srch.Close()

	out, err := getSearchOutput(w, r)
	if err != nil {
		respondError(c, w, r, err)
		return
	}

	w.Header().Set("Content-Type", out.ContentType())
	if err := srch.Run(out); err != nil {
		c.requestLogger(r).Warn("Error writing response", zap.Error(err))
	}
}

type ArchiveStater interface {
	ArchiveStat(context.Context, *resolver.Context) (zbuf.ReadCloser, error)
}

func handleArchiveStat(c *Core, w http.ResponseWriter, r *http.Request) {
	id, ok := extractSpaceID(c, w, r)
	if !ok {
		return
	}
	store, err := c.mgr.GetStorage(r.Context(), id)
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	as, ok := store.(*archivestore.Storage)
	if !ok {
		respondError(c, w, r, zqe.E(zqe.Invalid, "space storage does not support archive stat"))
		return
	}

	rc, err := as.ArchiveStat(r.Context(), resolver.NewContext())
	if err != nil {
		respondError(c, w, r, err)
		return
	}
	defer rc.Close()

	out, err := getSearchOutput(w, r)
	if err != nil {
		respondError(c, w, r, err)
		return
	}

	w.Header().Set("Content-Type", out.ContentType())
	if err := search.SendFromReader(out, rc); err != nil {
		c.requestLogger(r).Warn("Error writing response", zap.Error(err))
	}
}

func extractSpaceID(c *Core, w http.ResponseWriter, r *http.Request) (api.SpaceID, bool) {
	v := mux.Vars(r)
	id, ok := v["space"]
	if !ok {
		respondError(c, w, r, zqe.E(zqe.Invalid, "no space id in path"))
		return "", false
	}
	return api.SpaceID(id), true
}

func handleAuthIdentityGet(c *Core, w http.ResponseWriter, r *http.Request) {
	ident := auth.IdentityFromContext(r.Context())
	respond(c, w, r, http.StatusOK, api.AuthIdentityResponse{
		TenantID: string(ident.TenantID),
		UserID:   string(ident.UserID),
	})
}

func handleAuthMethodGet(c *Core, w http.ResponseWriter, r *http.Request) {
	if c.auth == nil {
		respond(c, w, r, http.StatusOK, api.AuthMethodResponse{Kind: api.AuthMethodNone})
		return
	}
	respond(c, w, r, http.StatusOK, c.auth.MethodResponse())
}
