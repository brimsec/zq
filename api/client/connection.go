package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/compiler/ast"
	"github.com/brimsec/zq/pcap/pcapio"
	"github.com/brimsec/zq/zio/ndjsonio"
	"github.com/brimsec/zq/zqe"
	"github.com/go-resty/resty/v2"
)

const (
	// DefaultPort zqd port to connect with.
	DefaultPort      = 9867
	DefaultUserAgent = "zqd-client-golang"
)

var (
	// ErrSpaceNotFound returns when specified space does not exist.
	ErrSpaceNotFound = errors.New("space not found")
	// ErrSpaceExists returns when specified the space already exists.
	ErrSpaceExists = errors.New("space exists")
	// ErrNoPcapResultsFound returns when a pcap search yields no results
	ErrNoPcapResultsFound = errors.New("no pcap results found for search")
)

type Connection struct {
	client *resty.Client
}

func newConnection(client *resty.Client) *Connection {
	client.SetError(api.Error{})
	client.OnAfterResponse(checkError)
	c := &Connection{client: client}
	c.SetUserAgent(DefaultUserAgent)
	return c
}

// NewConnection creates a new connection with the given useragent string
// and a base URL set up to talk to http://localhost:defaultport
func NewConnection() *Connection {
	u := "http://localhost:" + strconv.Itoa(DefaultPort)
	return NewConnectionTo(u)
}

// NewConnectionTo creates a new connection with the given useragent string
// and a base URL derived from the hostURL argument.
func NewConnectionTo(hostURL string) *Connection {
	client := resty.New()
	client.HostURL = hostURL
	return newConnection(client)
}

// ClientHostURL allows us to print the host in log messages and internal error messages
func (c *Connection) ClientHostURL() string {
	return c.client.HostURL
}

func (c *Connection) SetAuthToken(token string) {
	c.client.SetAuthToken(token)
}

func (c *Connection) SetUserAgent(useragent string) {
	c.client.SetHeader("User-Agent", useragent)
}

func (c *Connection) Do(ctx context.Context, method, url string, body interface{}) (*resty.Response, error) {
	req := c.Request(ctx).SetBody(body)
	return req.Execute(method, url)
}

func checkError(client *resty.Client, resp *resty.Response) error {
	if resp.IsSuccess() {
		return nil
	}
	resErr := &ErrorResponse{Response: resp}
	if err := resp.Error(); err != nil {
		resErr.Err = err.(*api.Error)
	} else {
		resErr.Err = errors.New(resp.String())
	}
	return resErr
}

func (c *Connection) stream(req *resty.Request) (io.ReadCloser, error) {
	resp, err := req.SetDoNotParseResponse(true).Send() // disables middleware
	if err != nil {
		return nil, err
	}
	r := resp.RawBody()
	if resp.IsSuccess() {
		return r, nil
	}
	defer r.Close()
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	resErr := &ErrorResponse{Response: resp}
	if resty.IsJSONType(resp.Header().Get("Content-Type")) {
		var apierr api.Error
		if err := json.Unmarshal(body, &apierr); err != nil {
			return nil, err
		}
		resErr.Err = &apierr
	} else {
		resErr.Err = errors.New(string(body))
	}
	return nil, resErr
}

// SetTimeout sets the underlying http request timeout to the given duration
func (c *Connection) SetTimeout(to time.Duration) {
	c.client.SetTimeout(to)
}

func (c *Connection) URL() string {
	return c.client.HostURL
}

func (c *Connection) SetURL(u string) {
	c.client.SetHostURL(u)
}

func (c *Connection) Request(ctx context.Context) *resty.Request {
	req := c.client.R().SetContext(ctx)
	if requestID := api.RequestIDFromContext(ctx); requestID != "" {
		req = req.SetHeader(api.RequestIDHeader, requestID)
	}
	return req
}

// Ping checks to see if the server and measure the time it takes to
// get back the response.
func (c *Connection) Ping(ctx context.Context) (time.Duration, error) {
	resp, err := c.Request(ctx).
		Get("/status")
	if err != nil {
		return 0, err
	}
	return resp.Time(), nil
}

// Version retrieves the version string from the service.
func (c *Connection) Version(ctx context.Context) (string, error) {
	resp, err := c.Request(ctx).
		SetResult(&api.VersionResponse{}).
		Get("/version")
	if err != nil {
		return "", err
	}
	return resp.Result().(*api.VersionResponse).Version, nil
}

// ZtoAST sends a request to the server to translate a Z program into its
// AST form.
func (c *Connection) ZtoAST(ctx context.Context, zprog string) ([]byte, error) {
	resp, err := c.Request(ctx).
		SetBody(api.ASTRequest{ZQL: zprog}).
		Post("/ast")
	if err != nil {
		return nil, err
	}
	return resp.Body(), nil
}

// SpaceInfo retrieves information about the specified space.
func (c *Connection) SpaceInfo(ctx context.Context, id api.SpaceID) (*api.SpaceInfo, error) {
	path := path.Join("/space", url.PathEscape(string(id)))
	resp, err := c.Request(ctx).
		SetResult(&api.SpaceInfo{}).
		Get(path)
	if err != nil {
		if r, ok := err.(*ErrorResponse); ok && r.StatusCode() == http.StatusNotFound {
			return nil, ErrSpaceNotFound
		}
		return nil, err
	}
	return resp.Result().(*api.SpaceInfo), nil
}

func (c *Connection) SpacePost(ctx context.Context, req api.SpacePostRequest) (*api.Space, error) {
	resp, err := c.Request(ctx).
		SetBody(req).
		SetResult(&api.Space{}).
		Post("/space")
	if err != nil {
		if r, ok := err.(*ErrorResponse); ok && r.StatusCode() == http.StatusConflict {
			return nil, ErrSpaceExists
		}
		return nil, err
	}
	return resp.Result().(*api.Space), nil
}

func (c *Connection) SpacePut(ctx context.Context, id api.SpaceID, req api.SpacePutRequest) error {
	_, err := c.Request(ctx).
		SetBody(req).
		Put(path.Join("/space", string(id)))
	return err
}

func (c *Connection) SpaceList(ctx context.Context) ([]api.Space, error) {
	var res []api.Space
	_, err := c.Request(ctx).
		SetResult(&res).
		Get("/space")
	return res, err
}

func (c *Connection) SpaceLookup(ctx context.Context, name string) (api.SpaceID, error) {
	spaces, err := c.SpaceList(ctx)
	if err != nil {
		return "", err
	}
	for _, s := range spaces {
		if s.Name == name {
			return s.ID, nil
		}
	}
	return "", zqe.ErrNotFound()
}

func (c *Connection) SpaceDelete(ctx context.Context, id api.SpaceID) (err error) {
	path := path.Join("/space", url.PathEscape(string(id)))
	_, err = c.Request(ctx).Delete(path)
	if r, ok := err.(*ErrorResponse); ok && r.StatusCode() == http.StatusNotFound {
		return ErrSpaceNotFound
	}
	return err
}

func (c *Connection) SearchRaw(ctx context.Context, search api.SearchRequest, params map[string]string) (io.ReadCloser, error) {
	req := c.Request(ctx).
		SetBody(search).
		SetQueryParam("format", "zng")
	req.SetQueryParams(params)
	req.Method = http.MethodPost
	req.URL = "/search"
	return c.stream(req)
}

func (c *Connection) WorkerRootSearch(ctx context.Context, search api.WorkerRootRequest, params map[string]string) (io.ReadCloser, error) {
	req := c.Request(ctx).
		SetBody(search).
		SetQueryParam("format", "zng")
	req.SetQueryParams(params)
	req.Method = http.MethodPost
	req.URL = "/worker/rootsearch"
	return c.stream(req)
}

func (c *Connection) WorkerChunkSearch(ctx context.Context, search api.WorkerChunkRequest, params map[string]string) (io.ReadCloser, error) {
	req := c.Request(ctx).
		SetBody(search).
		SetQueryParam("format", "zng")
	req.SetQueryParams(params)
	req.Method = http.MethodPost
	req.URL = "/worker/chunksearch"
	return c.stream(req)
}

// WorkerRelease is a message sent from the zqd root to workers in the parallel group
// when the root process is done and will not be sending additional /worker/chunksearch requests.
func (c *Connection) WorkerRelease(ctx context.Context) error {
	_, err := c.Request(ctx).Get("/worker/release")
	return err
}

// Search sends a search request to the server and returns a ZngSearch
// that the caller uses to stream back results via the Read method.
// Example usage:
//
//	conn := client.NewConnectionTo("http://localhost:9867")
//	spaceID, err := conn.SpaceLookup(ctx, "spaceName")
//	if err != nil { return err }
//	search, err := conn.Search(ctx, spaceID, "_path=conn | count()")
//	if err != nil { return err }
//	for {
//		rec, err := search.Read()
//		if err != nil { return err }
//		if rec == nil {
//			// End of results.
//			return nil
//		}
//		fmt.Println(rec)
//	}
//
func (c *Connection) Search(ctx context.Context, spaceID api.SpaceID, query string) (*ZngSearch, error) {
	procBytes, err := c.ZtoAST(ctx, query)
	if err != nil {
		return nil, err
	}
	r, err := c.SearchRaw(ctx, api.SearchRequest{
		Space: spaceID,
		Proc:  procBytes,
		Dir:   -1,
	}, nil)
	if err != nil {
		return nil, err
	}
	return NewZngSearch(r), nil
}

func (c *Connection) IndexSearch(ctx context.Context, space api.SpaceID, search api.IndexSearchRequest, params map[string]string) (*ZngSearch, error) {
	req := c.Request(ctx).
		SetBody(search).
		SetQueryParam("format", "zng")
	req.SetQueryParams(params)
	req.Method = http.MethodPost
	req.URL = path.Join("/space", string(space), "indexsearch")
	r, err := c.stream(req)
	if err != nil {
		return nil, err
	}
	return NewZngSearch(r), nil
}

func (c *Connection) IndexPost(ctx context.Context, space api.SpaceID, post api.IndexPostRequest) error {
	_, err := c.Request(ctx).
		SetBody(post).
		Post(path.Join("/space", string(space), "index"))
	return err
}

func (c *Connection) ArchiveStat(ctx context.Context, space api.SpaceID, params map[string]string) (*ZngSearch, error) {
	req := c.Request(ctx).
		SetQueryParam("format", "zng")
	req.SetQueryParams(params)
	req.Method = http.MethodGet
	req.URL = path.Join("/space", string(space), "archivestat")
	r, err := c.stream(req)
	if err != nil {
		return nil, err
	}
	return NewZngSearch(r), nil
}

func (c *Connection) PcapPostStream(ctx context.Context, space api.SpaceID, payload api.PcapPostRequest) (*Stream, error) {
	req := c.Request(ctx).
		SetBody(payload)
	req.Method = http.MethodPost
	req.URL = path.Join("/space", string(space), "pcap")
	r, err := c.stream(req)
	if err != nil {
		return nil, err
	}
	jsonpipe := NewJSONPipeScanner(r)
	return NewStream(jsonpipe), nil
}

func (c *Connection) PcapPost(ctx context.Context, space api.SpaceID, payload api.PcapPostRequest) (Payloads, error) {
	stream, err := c.PcapPostStream(ctx, space, payload)
	if err != nil {
		return nil, err
	}
	payloads, err := stream.ReadAll()
	if err != nil {
		return nil, err
	}
	return payloads, payloads.Error()
}

func (c *Connection) PcapSearch(ctx context.Context, space api.SpaceID, payload api.PcapSearch) (*PcapReadCloser, error) {
	req := c.Request(ctx).
		SetQueryParamsFromValues(payload.ToQuery())
	req.Method = http.MethodGet
	req.URL = path.Join("/space", string(space), "pcap")
	r, err := c.stream(req)
	if err != nil {
		if r, ok := err.(*ErrorResponse); ok && r.StatusCode() == http.StatusNotFound {
			return nil, ErrNoPcapResultsFound
		}
		return nil, err
	}
	pr, err := pcapio.NewReader(r)
	if err != nil {
		return nil, err
	}
	return &PcapReadCloser{pr, r}, nil
}

type PcapReadCloser struct {
	pcapio.Reader
	io.Closer
}

type LogPostOpts struct {
	JSON      *ndjsonio.TypeConfig
	StopError bool
	Shaper    ast.Proc
}

func (c *Connection) LogPostPath(ctx context.Context, space api.SpaceID, opts *LogPostOpts, paths ...string) error {
	stream, err := c.LogPostPathStream(ctx, space, opts, paths...)
	if err != nil {
		return err
	}
	payloads, err := stream.ReadAll()
	if err != nil {
		return err
	}
	return payloads.Error()
}

func (c *Connection) LogPostPathStream(ctx context.Context, space api.SpaceID, opts *LogPostOpts, paths ...string) (*Stream, error) {
	body := api.LogPostRequest{
		Paths:          paths,
		JSONTypeConfig: opts.JSON,
		StopErr:        opts.StopError,
	}
	if opts != nil && opts.Shaper != nil {
		raw, err := json.Marshal(opts.Shaper)
		if err != nil {
			return nil, err
		}
		body.Shaper = raw
	}
	req := c.Request(ctx).
		SetBody(body)
	req.Method = http.MethodPost
	req.URL = path.Join("/space", url.PathEscape(string(space)), "log/paths")
	r, err := c.stream(req)
	if err != nil {
		return nil, err
	}
	jsonpipe := NewJSONPipeScanner(r)
	return NewStream(jsonpipe), nil
}

func (c *Connection) LogPost(ctx context.Context, space api.SpaceID, opts *LogPostOpts, paths ...string) (api.LogPostResponse, error) {
	w, err := MultipartFileWriter(paths...)
	if err != nil {
		return api.LogPostResponse{}, err
	}
	return c.LogPostWriter(ctx, space, opts, w)
}

func (c *Connection) LogPostReaders(ctx context.Context, space api.SpaceID, opts *LogPostOpts, readers ...io.Reader) (api.LogPostResponse, error) {
	w, err := MultipartDataWriter(readers...)
	if err != nil {
		return api.LogPostResponse{}, err
	}
	return c.LogPostWriter(ctx, space, opts, w)
}

func (c *Connection) LogPostWriter(ctx context.Context, space api.SpaceID, opts *LogPostOpts, writer *MultipartWriter) (api.LogPostResponse, error) {
	req := c.Request(ctx).
		SetBody(writer).
		SetResult(&api.LogPostResponse{}).
		SetHeader("Content-Type", writer.ContentType())
	if opts != nil {
		if opts.Shaper != nil {
			writer.SetShaper(opts.Shaper)
		}
		if opts.StopError {
			req.SetQueryParam("stop_err", "true")
		}
		if opts.JSON != nil {
			writer.SetJSONConfig(opts.JSON)
		}
	}
	u := path.Join("/space", url.PathEscape(string(space)), "log")
	resp, err := req.Post(u)
	if err != nil {
		return api.LogPostResponse{}, err
	}
	v := resp.Result().(*api.LogPostResponse)
	return *v, nil
}

func (c *Connection) Recruit(ctx context.Context, req api.RecruitRequest) (*api.RecruitResponse, error) {
	resp, err := c.Request(ctx).
		SetBody(req).
		SetResult(&api.RecruitResponse{}).
		Post("/recruiter/recruit")
	if err != nil {
		return nil, err
	}
	return resp.Result().(*api.RecruitResponse), nil
}

func (c *Connection) Register(ctx context.Context, req api.RegisterRequest) (*api.RegisterResponse, error) {
	resp, err := c.Request(ctx).
		SetBody(req).
		SetResult(&api.RegisterResponse{}).
		Post("/recruiter/register")
	if err != nil {
		return nil, err
	}
	return resp.Result().(*api.RegisterResponse), nil
}

func (c *Connection) Deregister(ctx context.Context, req api.DeregisterRequest) (*api.RegisterResponse, error) {
	resp, err := c.Request(ctx).
		SetBody(req).
		SetResult(&api.RegisterResponse{}).
		Post("/recruiter/deregister")
	if err != nil {
		return nil, err
	}
	return resp.Result().(*api.RegisterResponse), nil
}

func (c *Connection) Unreserve(ctx context.Context, req api.UnreserveRequest) (*api.UnreserveResponse, error) {
	resp, err := c.Request(ctx).
		SetBody(req).
		SetResult(&api.UnreserveResponse{}).
		Post("/recruiter/unreserve")
	if err != nil {
		return nil, err
	}
	return resp.Result().(*api.UnreserveResponse), nil
}

func (c *Connection) RecruiterStats(ctx context.Context) (*api.RecruiterStatsResponse, error) {
	resp, err := c.Request(ctx).
		SetResult(&api.RecruiterStatsResponse{}).
		Get("/recruiter/stats")
	if err != nil {
		return nil, err
	}
	return resp.Result().(*api.RecruiterStatsResponse), nil
}

func (c *Connection) AuthMethod(ctx context.Context) (*api.AuthMethodResponse, error) {
	resp, err := c.Request(ctx).
		SetResult(&api.AuthMethodResponse{}).
		Get("/auth/method")
	if err != nil {
		return nil, err
	}
	return resp.Result().(*api.AuthMethodResponse), nil
}

func (c *Connection) AuthIdentity(ctx context.Context) (*api.AuthIdentityResponse, error) {
	resp, err := c.Request(ctx).
		SetResult(&api.AuthIdentityResponse{}).
		Get("/auth/identity")
	if err != nil {
		return nil, err
	}
	return resp.Result().(*api.AuthIdentityResponse), nil
}

type ErrorResponse struct {
	*resty.Response
	Err error
}

func (e *ErrorResponse) Unwrap() error {
	return e.Err
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("status code %d: %v", e.StatusCode(), e.Err)
}
