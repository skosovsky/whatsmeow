package whatsmeow

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
)

var ErrUploadAuthority = errors.New("media upload authority rejected")
var ErrUploadAttempt = errors.New("media upload attempt failed or uncertain")

type uploadAuthorityKey struct{}
type uploadProofKey struct{}

// OriginalUploadProof is private native evidence, available only during a guard.
// Phase is admission, media_connection, upload, upload_write or upload_complete; upload completion is not a send ACK.
type OriginalUploadProof struct {
	SHA256    [32]byte
	Bytes     uint64
	MediaType MediaType
	Phase     string
}

func (p OriginalUploadProof) String() string {
	return fmt.Sprintf("OriginalUploadProof{phase:%s evidence:[REDACTED]}", p.Phase)
}
func (p OriginalUploadProof) GoString() string { return p.String() }

type uploadProofWindow struct {
	authority *uploadAuthority
	proof     OriginalUploadProof
	active    atomic.Bool
}
type uploadAuthority struct {
	proof        OriginalUploadProof
	check        func(context.Context) error
	used, closed atomic.Bool
	fault        atomic.Bool
}

func OriginalUploadSource(ctx context.Context) (OriginalUploadProof, bool) {
	window, _ := ctx.Value(uploadProofKey{}).(*uploadProofWindow)
	authority, _ := ctx.Value(uploadAuthorityKey{}).(*uploadAuthority)
	if window == nil || authority == nil || window.authority != authority || !window.active.Load() || authority.closed.Load() {
		return OriginalUploadProof{}, false
	}
	return window.proof, true
}
func (a *uploadAuthority) checkPhase(ctx context.Context, phase string) (err error) {
	if a == nil || a.closed.Load() || a.check == nil || ctx.Err() != nil {
		return ErrUploadAuthority
	}
	defer func() {
		if recover() != nil {
			err = ErrUploadAuthority
		}
	}()
	proof := a.proof
	proof.Phase = phase
	window := &uploadProofWindow{authority: a, proof: proof}
	window.active.Store(true)
	defer window.active.Store(false)
	if a.check(context.WithValue(ctx, uploadProofKey{}, window)) != nil || ctx.Err() != nil {
		return ErrUploadAuthority
	}
	return nil
}
func uploadPreparationGuard(ctx context.Context) func(context.Context) error {
	a, _ := ctx.Value(uploadAuthorityKey{}).(*uploadAuthority)
	if a == nil {
		return nil
	}
	return func(ctx context.Context) error {
		if a.used.Load() {
			return ErrUploadAuthority
		}
		return a.checkPhase(ctx, "media_connection")
	}
}

// UploadWithAuthority retains original SDK encryption/upload, adds live guards and
// one HTTP attempt. It returns no partial upload material after any failure.
func (cli *Client) UploadWithAuthority(ctx context.Context, plaintext []byte, appInfo MediaType, check func(context.Context) error) (UploadResponse, error) {
	if cli == nil || check == nil || len(plaintext) == 0 {
		return UploadResponse{}, ErrUploadAuthority
	}
	if _, ok := mediaTypeToMMSType[appInfo]; !ok {
		return UploadResponse{}, ErrUploadAuthority
	}
	data := append([]byte(nil), plaintext...)
	a := &uploadAuthority{proof: OriginalUploadProof{SHA256: sha256.Sum256(data), Bytes: uint64(len(data)), MediaType: appInfo}, check: check}
	defer a.closed.Store(true)
	ctx = context.WithValue(ctx, uploadAuthorityKey{}, a)
	if err := a.checkPhase(ctx, "admission"); err != nil {
		return UploadResponse{}, err
	}
	result, err := cli.uploadOwned(ctx, data, appInfo)
	if err != nil {
		if errors.Is(err, ErrUploadAuthority) {
			return UploadResponse{}, ErrUploadAuthority
		}
		return UploadResponse{}, ErrUploadAttempt
	}
	if a.fault.Load() {
		return UploadResponse{}, ErrUploadAttempt
	}
	if err := a.checkPhase(ctx, "upload_complete"); err != nil {
		return UploadResponse{}, err
	}
	return result, nil
}

type uploadConnections struct {
	ctx       context.Context
	mu        sync.Mutex
	sealed    bool
	calls     sync.WaitGroup
	conns     map[*uploadConn]struct{}
	authority *uploadAuthority
}
type uploadConn struct {
	net.Conn
	owner *uploadConnections
}

func (c *uploadConn) Write(data []byte) (n int, err error) {
	active := false
	defer func() {
		if recover() != nil {
			n = 0
			err = ErrUploadAttempt
		}
		if active {
			if err != nil {
				c.owner.authority.fault.Store(true)
			}
			c.owner.calls.Done()
		}
	}()
	c.owner.mu.Lock()
	if c.owner.sealed {
		c.owner.mu.Unlock()
		return 0, ErrUploadAuthority
	}
	c.owner.calls.Add(1)
	active = true
	c.owner.mu.Unlock()
	if err := c.owner.authority.checkPhase(c.owner.ctx, "upload_write"); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}
func (o *uploadConnections) dial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (result net.Conn, err error) {
		registered := false
		defer func() {
			if recover() != nil {
				result = nil
				err = ErrUploadAttempt
			}
			if registered {
				if err != nil {
					o.authority.fault.Store(true)
				}
				o.calls.Done()
			}
		}()
		o.mu.Lock()
		if o.sealed {
			o.mu.Unlock()
			return nil, ErrUploadAuthority
		}
		o.calls.Add(1)
		registered = true
		o.mu.Unlock()
		conn, err := dial(ctx, network, address)
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, err
		}
		if conn == nil {
			return nil, ErrUploadAuthority
		}
		o.mu.Lock()
		if o.sealed {
			o.mu.Unlock()
			_ = conn.Close()
			return nil, ErrUploadAuthority
		}
		tracked := &uploadConn{Conn: conn, owner: o}
		o.conns[tracked] = struct{}{}
		o.mu.Unlock()
		return tracked, nil
	}
}
func (o *uploadConnections) seal() {
	o.mu.Lock()
	o.sealed = true
	conns := make([]*uploadConn, 0, len(o.conns))
	for conn := range o.conns {
		conns = append(conns, conn)
	}
	o.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	o.calls.Wait()
}

type uploadRoundTripper struct {
	authority *uploadAuthority
	transport *http.Transport
}

func (t uploadRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || !t.authority.used.CompareAndSwap(false, true) {
		return nil, ErrUploadAuthority
	}
	if err := t.authority.checkPhase(req.Context(), "upload"); err != nil {
		return nil, err
	}
	return t.transport.RoundTrip(req)
}
func guardedUploadHTTPClient(ctx context.Context, original *http.Client) (*http.Client, func(), error) {
	a, _ := ctx.Value(uploadAuthorityKey{}).(*uploadAuthority)
	if a == nil {
		return original, func() {}, nil
	}
	if a.closed.Load() || a.used.Load() || original == nil {
		return nil, nil, ErrUploadAuthority
	}
	transport := original.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	concrete, ok := transport.(*http.Transport)
	if !ok {
		return nil, nil, ErrUploadAuthority
	}
	private := concrete.Clone()
	// This transport starts empty and serves exactly one guarded RoundTrip.
	// Seal closes its owned connections before CloseIdleConnections sends TLS close alerts.
	private.DisableKeepAlives = false
	private.ForceAttemptHTTP2 = false
	private.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	if private.TLSClientConfig == nil {
		private.TLSClientConfig = &tls.Config{}
	} else {
		private.TLSClientConfig = private.TLSClientConfig.Clone()
	}
	private.TLSClientConfig.NextProtos = []string{"http/1.1"}
	owner := &uploadConnections{ctx: ctx, authority: a, conns: make(map[*uploadConn]struct{})}
	dial := private.DialContext
	if dial == nil {
		if private.Dial != nil {
			legacy := private.Dial
			dial = func(_ context.Context, network, address string) (net.Conn, error) { return legacy(network, address) }
		} else {
			dial = (&net.Dialer{}).DialContext
		}
	}
	private.DialContext = owner.dial(dial)
	private.Dial = nil
	if private.DialTLSContext != nil {
		private.DialTLSContext = owner.dial(private.DialTLSContext)
	} else if private.DialTLS != nil {
		legacy := private.DialTLS
		private.DialTLSContext = owner.dial(func(_ context.Context, network, address string) (net.Conn, error) { return legacy(network, address) })
	}
	private.DialTLS = nil
	client := *original
	client.Transport = uploadRoundTripper{authority: a, transport: private}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrUploadAuthority }
	return &client, func() { owner.seal(); private.CloseIdleConnections() }, nil
}

func decodeGuardedUploadResponse(body io.Reader, resp *UploadResponse) error {
	raw, err := io.ReadAll(io.LimitReader(body, 4097))
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, resp) != nil {
		return ErrUploadAttempt
	}
	parsed, err := url.Parse(resp.URL)
	if err != nil || len(resp.URL) > 2048 || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || len(resp.DirectPath) > 2048 || len(resp.Handle) > 256 || len(resp.ObjectID) > 256 {
		return ErrUploadAttempt
	}
	return nil
}

func (c *uploadConn) Close() (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUploadAttempt
			c.owner.authority.fault.Store(true)
		}
	}()
	return c.Conn.Close()
}

func (c *uploadConn) Read(data []byte) (n int, err error) {
	active := false
	defer func() {
		if recover() != nil {
			n = 0
			err = ErrUploadAttempt
			c.owner.authority.fault.Store(true)
		}
		if active {
			c.owner.calls.Done()
		}
	}()
	c.owner.mu.Lock()
	if c.owner.sealed {
		c.owner.mu.Unlock()
		return 0, ErrUploadAuthority
	}
	c.owner.calls.Add(1)
	active = true
	c.owner.mu.Unlock()
	return c.Conn.Read(data)
}
