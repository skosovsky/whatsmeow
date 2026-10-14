package whatsmeow

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/util/cbcutil"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func uploadTLSFixture(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	cli := NewClient(&store.Device{}, waLog.Noop)
	cli.SetMediaHTTPClient(server.Client())
	cli.mediaConnCache = &MediaConn{Auth: "synthetic-upload-auth", TTL: 3600, FetchedAt: time.Now(), Hosts: []MediaConnHost{{Hostname: strings.TrimPrefix(server.URL, "https://")}}}
	return cli, server
}
func noUploadMaterial(t *testing.T, r UploadResponse) {
	t.Helper()
	if !reflect.DeepEqual(r, UploadResponse{}) {
		t.Fatal("failed attempt exposed usable upload material")
	}
}

const syntheticUploadResponse = `{"url":"https://example.invalid/attachment","direct_path":"/synthetic/attachment"}`

func TestGuardedUploadOriginalEncryptedHTTPBytesAndProofLifetime(t *testing.T) {
	for _, kind := range []MediaType{MediaDocument, MediaImage, MediaVideo, MediaAudio} {
		t.Run(string(kind), func(t *testing.T) {
			// Arrange: original SDK encryption over an owned TLS HTTP endpoint.
			var requests atomic.Int32
			received := make(chan []byte, 1)
			cli, _ := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodPost {
					t.Error("unexpected method")
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				received <- data
				_, _ = io.WriteString(w, syntheticUploadResponse)
			}))
			original := []byte("Привет e\u0301 🙂")
			plaintext := append([]byte(nil), original...)
			expectedHash := sha256.Sum256(original)
			var captures []context.Context
			var phases []string
			check := func(ctx context.Context) error {
				proof, ok := OriginalUploadSource(ctx)
				if !ok || proof.SHA256 != expectedHash || proof.Bytes != uint64(len(original)) || proof.MediaType != kind {
					t.Error("missing/changed native source proof")
				}
				for _, previous := range captures {
					if _, ok := OriginalUploadSource(previous); ok {
						t.Error("expired proof became active again")
					}
				}
				captures = append(captures, ctx)
				phases = append(phases, proof.Phase)
				if proof.Phase == "admission" {
					for i := range plaintext {
						plaintext[i] = 'x'
					}
				}
				return nil
			}
			// Act: caller mutation after admission cannot change the SDK's owned copy.
			resp, err := cli.UploadWithAuthority(context.Background(), plaintext, kind, check)
			// Assert: one actual original encrypted POST and unchanged plaintext/hash/MAC.
			corePhases := []string{}
			writes := 0
			for _, phase := range phases {
				if phase == "upload_write" {
					writes++
				} else {
					corePhases = append(corePhases, phase)
				}
			}
			if err != nil || requests.Load() != 1 || writes == 0 || !reflect.DeepEqual(corePhases, []string{"admission", "upload", "upload_complete"}) {
				t.Fatal(err, requests.Load(), phases)
			}
			payload := <-received
			if len(payload) < 10 {
				t.Fatal("missing encrypted MAC")
			}
			encHash := sha256.Sum256(payload)
			if !bytes.Equal(encHash[:], resp.FileEncSHA256) || !bytes.Equal(expectedHash[:], resp.FileSHA256) || resp.FileLength != uint64(len(original)) {
				t.Fatal("native digest/length mismatch")
			}
			iv, key, macKey, _ := getMediaKeys(resp.MediaKey, kind)
			mac := hmac.New(sha256.New, macKey)
			_, _ = mac.Write(iv)
			_, _ = mac.Write(payload[:len(payload)-10])
			if !hmac.Equal(mac.Sum(nil)[:10], payload[len(payload)-10:]) {
				t.Fatal("invalid native MAC")
			}
			decrypted, err := cbcutil.Decrypt(key, iv, append([]byte(nil), payload[:len(payload)-10]...))
			if err != nil || !bytes.Equal(decrypted, original) {
				t.Fatal("literal plaintext changed", err)
			}
			for _, captured := range captures {
				if _, ok := OriginalUploadSource(captured); ok {
					t.Fatal("proof survives callback")
				}
			}
			// Even the captured SDK context cannot create another physical attempt.
			if _, err := cli.Upload(captures[1], original, kind); err == nil || requests.Load() != 1 {
				t.Fatal("captured context resent upload", err, requests.Load())
			}
		})
	}
}

func TestGuardedUploadDenialPanicAndCancellationNoUsableResponse(t *testing.T) {
	for _, mode := range []string{"admission-denial", "upload-denial", "upload-panic", "upload-cancel", "completion-denial", "nil-hook"} {
		t.Run(mode, func(t *testing.T) {
			// Arrange.
			var requests atomic.Int32
			cli, _ := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = io.WriteString(w, syntheticUploadResponse)
			}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			check := func(ctx context.Context) error {
				proof, ok := OriginalUploadSource(ctx)
				if !ok {
					return errors.New("missing proof")
				}
				switch mode {
				case "admission-denial":
					if proof.Phase == "admission" {
						return errors.New("private-upload-canary")
					}
				case "upload-denial":
					if proof.Phase == "upload" {
						return errors.New("private-upload-canary")
					}
				case "upload-panic":
					if proof.Phase == "upload" {
						panic("private-upload-canary")
					}
				case "upload-cancel":
					if proof.Phase == "upload" {
						cancel()
					}
				case "completion-denial":
					if proof.Phase == "upload_complete" {
						return errors.New("private-upload-canary")
					}
				}
				return nil
			}
			if mode == "nil-hook" {
				check = nil
			}
			// Act.
			resp, err := cli.UploadWithAuthority(ctx, []byte("synthetic"), MediaDocument, check)
			// Assert: no partial material or raw callback secret; completion denial does not replay its one POST.
			want := int32(0)
			if mode == "completion-denial" {
				want = 1
			}
			if err == nil || strings.Contains(err.Error(), "canary") || requests.Load() != want {
				t.Fatal(err, requests.Load(), want)
			}
			noUploadMaterial(t, resp)
		})
	}
}

func TestGuardedUploadRedirectAndBoundedResponseRefusal(t *testing.T) {
	for _, mode := range []string{"redirect", "malformed", "oversized", "empty-url", "userinfo", "trailing-json"} {
		t.Run(mode, func(t *testing.T) {
			// Arrange.
			var requests atomic.Int32
			cli, server := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				switch mode {
				case "redirect":
					w.Header().Set("Location", "/second-upload")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "malformed":
					_, _ = io.WriteString(w, "{")
				case "oversized":
					_, _ = io.WriteString(w, `{"url":"https://example.invalid/`+strings.Repeat("x", 5000)+`"}`)
				case "empty-url":
					_, _ = io.WriteString(w, `{}`)
				case "userinfo":
					_, _ = io.WriteString(w, `{"url":"https://private-canary@example.invalid/attachment"}`)
				case "trailing-json":
					_, _ = io.WriteString(w, syntheticUploadResponse+`{}`)
				}
			}))
			original := server.Client()
			transport := original.Transport
			// Act.
			resp, err := cli.UploadWithAuthority(context.Background(), []byte("abc"), MediaDocument, func(context.Context) error { return nil })
			// Assert: no redirect request, partial response or configured client mutation.
			if err == nil || strings.Contains(err.Error(), "canary") || requests.Load() != 1 || original.Transport != transport || original.CheckRedirect != nil {
				t.Fatal(err, requests.Load())
			}
			noUploadMaterial(t, resp)
		})
	}
}

type uploadHeldWriteConn struct {
	net.Conn
	after                            bool
	entered, release, exited, closed chan struct{}
	hold, closeOnce                  sync.Once
}

func (c *uploadHeldWriteConn) Write(data []byte) (n int, err error) {
	if !bytes.HasPrefix(data, []byte("POST ")) {
		return c.Conn.Write(data)
	}
	held := false
	c.hold.Do(func() { held = true })
	if !held {
		return c.Conn.Write(data)
	}
	if c.after {
		n, err = c.Conn.Write(data)
	}
	close(c.entered)
	<-c.release
	defer close(c.exited)
	if c.after {
		return n, err
	}
	return c.Conn.Write(data)
}
func (c *uploadHeldWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestGuardedUploadCancellationJoinsOriginalPhysicalWrite(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-emission", true: "after-emission"}[after], func(t *testing.T) {
			// Arrange: the original HTTP/1 TLS request writer stays active across cancellation.
			var requests atomic.Int32
			received := make(chan struct{}, 1)
			cli, server := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				select {
				case received <- struct{}{}:
				default:
				}
				_, _ = io.WriteString(w, syntheticUploadResponse)
			}))
			transport := server.Client().Transport.(*http.Transport).Clone()
			config := transport.TLSClientConfig.Clone()
			held := &uploadHeldWriteConn{after: after, entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{}), closed: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(held.release) }) }
			t.Cleanup(release)
			transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: config}
				conn, err := dialer.DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				held.Conn = conn
				return held, nil
			}
			cli.SetMediaHTTPClient(&http.Client{Transport: transport})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			// Act.
			go func() {
				resp, err := cli.UploadWithAuthority(ctx, []byte("abc"), MediaDocument, func(context.Context) error { return nil })
				if !reflect.DeepEqual(resp, UploadResponse{}) {
					result <- errors.New("partial material")
					return
				}
				result <- err
			}()
			select {
			case <-held.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("physical writer not entered")
			}
			if after {
				select {
				case <-received:
				case <-time.After(3 * time.Second):
					t.Fatal("original POST not observed")
				}
			}
			cancel()
			select {
			case <-held.closed:
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation did not close original connection")
			}
			// Assert: the method stays alive while the created Write is held, then joins it.
			select {
			case err := <-result:
				t.Fatal("returned before physical Write exit", err)
			case <-time.After(30 * time.Millisecond):
			}
			release()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("cancelled write succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("writer exit not joined")
			}
			select {
			case <-held.exited:
			default:
				t.Fatal("write still active")
			}
			want := int32(0)
			if after {
				want = 1
			}
			if requests.Load() != want {
				t.Fatal(requests.Load(), want)
			}
		})
	}
}

func TestGuardedUploadColdMediaConnChecksOriginalNativeIQ(t *testing.T) {
	// Arrange: original SDK Noise/frame writer and an owned loopback websocket.
	cli := NewClient(&store.Device{}, waLog.Noop)
	var frames atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.CloseNow()
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
			frames.Add(1)
		}
	}))
	defer server.Close()
	fs := socket.NewFrameSocket(waLog.Noop, nil)
	fs.URL = "ws" + strings.TrimPrefix(server.URL, "http")
	fs.Header = nil
	fs.HTTPHeaders = http.Header{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := fs.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	ns, err := socket.NewNoiseHandshake().Finish(fs, func(context.Context, []byte) {}, func(context.Context, *socket.NoiseSocket, bool) {})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(0)
	cli.socket = ns
	phases := []string{}
	// Act: fresh media connection IQ reaches the original physical guard and is denied there.
	resp, err := cli.UploadWithAuthority(ctx, []byte("abc"), MediaDocument, func(ctx context.Context) error {
		proof, ok := OriginalUploadSource(ctx)
		if !ok {
			t.Error("native source absent")
		}
		phases = append(phases, proof.Phase)
		if proof.Phase == "media_connection" {
			return errors.New("private-preparation-canary")
		}
		return nil
	})
	// Assert: neither IQ bytes nor CDN upload; no raw callback text or response material.
	if err == nil || strings.Contains(err.Error(), "canary") || frames.Load() != 0 || !reflect.DeepEqual(phases, []string{"admission", "media_connection"}) {
		t.Fatal(err, frames.Load(), phases)
	}
	noUploadMaterial(t, resp)
}

type rejectedUploadTransport struct{ calls atomic.Int32 }

func (t *rejectedUploadTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, errors.New("private-transport-canary")
}
func TestGuardedUploadRefusesOpaqueTransportBeforeAnyRequest(t *testing.T) {
	// Arrange: an opaque transport could hide redirects/retries and must not execute.
	cli := NewClient(&store.Device{}, waLog.Noop)
	transport := &rejectedUploadTransport{}
	cli.SetMediaHTTPClient(&http.Client{Transport: transport})
	// Act.
	resp, err := cli.UploadWithAuthority(context.Background(), []byte("abc"), MediaDocument, func(context.Context) error { return nil })
	// Assert.
	if !errors.Is(err, ErrUploadAuthority) || transport.calls.Load() != 0 {
		t.Fatal(err, transport.calls.Load())
	}
	noUploadMaterial(t, resp)
}

func TestGuardedUploadCancellationJoinsOriginalDial(t *testing.T) {
	// Arrange: a configured concrete transport's original Dial cannot be assumed finished on cancellation.
	cli := NewClient(&store.Device{}, waLog.Noop)
	cli.mediaConnCache = &MediaConn{TTL: 3600, FetchedAt: time.Now(), Hosts: []MediaConnHost{{Hostname: "synthetic.invalid"}}}
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	transport := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
		close(entered)
		<-release
		defer close(exited)
		return nil, errors.New("private-dial-canary")
	}}
	cli.SetMediaHTTPClient(&http.Client{Transport: transport})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	// Act.
	go func() {
		resp, err := cli.UploadWithAuthority(ctx, []byte("abc"), MediaDocument, func(context.Context) error { return nil })
		if !reflect.DeepEqual(resp, UploadResponse{}) {
			result <- errors.New("partial response")
			return
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original Dial did not enter")
	}
	cancel()
	// Assert: cancelled request cannot return while the original Dial is still held.
	select {
	case err := <-result:
		t.Fatal("returned before Dial exit", err)
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-result:
		if err == nil || strings.Contains(err.Error(), "canary") {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original Dial did not exit")
	}
	select {
	case <-exited:
	default:
		t.Fatal("Dial remains active")
	}
}

func TestGuardedUploadPreservesOrdinarySDKUploadCompatibility(t *testing.T) {
	// Arrange: stock Upload retains the configured HTTP redirect behavior.
	var requests atomic.Int32
	cli, _ := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path != "/second" {
			w.Header().Set("Location", "/second")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		_, _ = io.WriteString(w, syntheticUploadResponse)
	}))
	// Act: no guarded API or context.
	resp, err := cli.Upload(context.Background(), []byte("abc"), MediaDocument)
	// Assert: upstream ordinary behavior remains compatible; guarded tests independently refuse this second POST.
	if err != nil || requests.Load() != 2 || resp.URL != "https://example.invalid/attachment" || resp.FileLength != 3 {
		t.Fatal(err, requests.Load())
	}
}

func TestGuardedUploadEmptyMediaConnectionAndDialPanicFailClosed(t *testing.T) {
	for _, mode := range []string{"empty-hosts", "dial-panic"} {
		t.Run(mode, func(t *testing.T) {
			// Arrange: synthetic original media metadata and a concrete transport; no DNS/network call.
			cli := NewClient(&store.Device{}, waLog.Noop)
			cli.mediaConnCache = &MediaConn{TTL: 3600, FetchedAt: time.Now()}
			var dials atomic.Int32
			transport := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				panic("private-dial-panic-canary")
			}}
			cli.SetMediaHTTPClient(&http.Client{Transport: transport})
			if mode == "dial-panic" {
				cli.mediaConnCache.Hosts = []MediaConnHost{{Hostname: "synthetic.invalid"}}
			}
			// Act.
			resp, err := cli.UploadWithAuthority(context.Background(), []byte("abc"), MediaDocument, func(context.Context) error { return nil })
			// Assert: no process panic, raw panic text or partial response.
			want := int32(0)
			if mode == "dial-panic" {
				want = 1
			}
			if err == nil || strings.Contains(err.Error(), "canary") || dials.Load() != want {
				t.Fatal(err, dials.Load())
			}
			noUploadMaterial(t, resp)
		})
	}
}

type uploadHeldReadConn struct {
	net.Conn
	entered, release, exited, closed chan struct{}
	hold, closeOnce                  sync.Once
}

func (c *uploadHeldReadConn) Read(data []byte) (int, error) {
	held := false
	c.hold.Do(func() { held = true })
	if held {
		close(c.entered)
		<-c.release
		defer close(c.exited)
	}
	return c.Conn.Read(data)
}
func (c *uploadHeldReadConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func TestGuardedUploadCancellationJoinsOriginalPhysicalRead(t *testing.T) {
	// Arrange: actual HTTP reader on an owned TLS connection remains active after Close.
	received := make(chan struct{}, 1)
	cli, server := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case received <- struct{}{}:
		default:
		}
		_, _ = io.WriteString(w, syntheticUploadResponse)
	}))
	transport := server.Client().Transport.(*http.Transport).Clone()
	config := transport.TLSClientConfig.Clone()
	held := &uploadHeldReadConn{entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{}), closed: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(held.release) }) }
	t.Cleanup(release)
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: config}
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		held.Conn = conn
		return held, nil
	}
	cli.SetMediaHTTPClient(&http.Client{Transport: transport})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	// Act.
	go func() {
		resp, err := cli.UploadWithAuthority(ctx, []byte("abc"), MediaDocument, func(context.Context) error { return nil })
		if !reflect.DeepEqual(resp, UploadResponse{}) {
			result <- errors.New("partial response")
			return
		}
		result <- err
	}()
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("physical reader did not enter")
	}
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("original POST not observed")
	}
	cancel()
	select {
	case <-held.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not close original connection")
	}
	// Assert: method exit joins the original held Read even though cancellation already closed its connection.
	select {
	case err := <-result:
		t.Fatal("returned before physical Read exit", err)
	case <-time.After(30 * time.Millisecond):
	}
	release()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled read succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("physical Read did not exit")
	}
	select {
	case <-held.exited:
	default:
		t.Fatal("physical Read remains active")
	}
}

type uploadPanicWriteConn struct {
	net.Conn
	after    bool
	observed <-chan struct{}
	once     sync.Once
}

func (c *uploadPanicWriteConn) Write(data []byte) (int, error) {
	if !bytes.HasPrefix(data, []byte("POST ")) {
		return c.Conn.Write(data)
	}
	panicNow := false
	c.once.Do(func() { panicNow = true })
	if !panicNow {
		return c.Conn.Write(data)
	}
	if c.after {
		if _, err := c.Conn.Write(data); err != nil {
			return 0, err
		}
		select {
		case <-c.observed:
		case <-time.After(3 * time.Second):
			return 0, errors.New("peer did not observe original POST")
		}
	}
	panic("private-physical-write-canary")
}
func TestGuardedUploadOriginalWriterPanicNeverReturnsUsableMetadata(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-emission", true: "after-observed-emission"}[after], func(t *testing.T) {
			// Arrange: genuine original HTTP writer can panic before or after actual owned TLS emission.
			var requests atomic.Int32
			observed := make(chan struct{}, 1)
			cli, server := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				select {
				case observed <- struct{}{}:
				default:
				}
				_, _ = io.WriteString(w, syntheticUploadResponse)
			}))
			transport := server.Client().Transport.(*http.Transport).Clone()
			config := transport.TLSClientConfig.Clone()
			transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: config}
				conn, err := dialer.DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return &uploadPanicWriteConn{Conn: conn, after: after, observed: observed}, nil
			}
			cli.SetMediaHTTPClient(&http.Client{Transport: transport})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			// Act.
			resp, err := cli.UploadWithAuthority(ctx, []byte("abc"), MediaDocument, func(context.Context) error { return nil })
			// Assert: a concurrent HTTP response cannot hide the physical writer fault; never replay or expose raw panic text.
			want := int32(0)
			if after {
				want = 1
			}
			if err == nil || strings.Contains(err.Error(), "canary") || requests.Load() != want {
				t.Fatal(err, requests.Load(), want)
			}
			noUploadMaterial(t, resp)
		})
	}
}

func TestGuardedUploadCapturedActiveContextCannotUseStockUploadPaths(t *testing.T) {
	// Arrange: captured contexts are rejected even while their proof window is active.
	var requests atomic.Int32
	cli, _ := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, syntheticUploadResponse)
	}))
	reader := &uploadCountedReader{}
	check := func(ctx context.Context) error {
		// Act: bypass attempts must fail before consuming authority or reading a supplied Reader.
		paths := []func() (UploadResponse, error){func() (UploadResponse, error) { return cli.Upload(ctx, []byte("wrong bytes"), MediaDocument) }, func() (UploadResponse, error) {
			return cli.UploadReader(ctx, reader, nil, MediaDocument)
		}, func() (UploadResponse, error) { return cli.UploadNewsletter(ctx, []byte("wrong bytes"), MediaDocument) }, func() (UploadResponse, error) {
			return cli.UploadNewsletterReader(ctx, reader, MediaDocument)
		}}
		for _, call := range paths {
			resp, err := call()
			if !errors.Is(err, ErrUploadAuthority) {
				t.Error("captured context bypassed native path", err)
			}
			noUploadMaterial(t, resp)
		}
		return nil
	}
	resp, err := cli.UploadWithAuthority(context.Background(), []byte("abc"), MediaDocument, check)
	// Assert: only the original owned SDK path creates one valid upload.
	if err != nil || requests.Load() != 1 || resp.FileLength != 3 || reader.calls.Load() != 0 {
		t.Fatal(err, requests.Load())
	}
}

type uploadCountedReader struct{ calls atomic.Int32 }

func (r *uploadCountedReader) Read([]byte) (int, error) {
	r.calls.Add(1)
	return 0, errors.New("reader must not execute")
}
func (r *uploadCountedReader) Seek(int64, int) (int64, error) {
	r.calls.Add(1)
	return 0, errors.New("seeker must not execute")
}

func TestGuardedUploadRechecksLiveAuthorityAfterOriginalDial(t *testing.T) {
	// Arrange: original SDK HTTP dial completes only after operator authority was revoked.
	var requests atomic.Int32
	cli, server := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, syntheticUploadResponse)
	}))
	transport := server.Client().Transport.(*http.Transport).Clone()
	config := transport.TLSClientConfig.Clone()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: config}
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		close(entered)
		<-release
		return conn, nil
	}
	cli.SetMediaHTTPClient(&http.Client{Transport: transport})
	var allowed atomic.Bool
	allowed.Store(true)
	var writes atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	// Act: RoundTrip admission succeeds, but the actual HTTP Write sees revoked authority after dialing.
	go func() {
		resp, err := cli.UploadWithAuthority(ctx, []byte("abc"), MediaDocument, func(ctx context.Context) error {
			proof, ok := OriginalUploadSource(ctx)
			if !ok {
				return errors.New("missing native source")
			}
			if proof.Phase == "upload_write" {
				writes.Add(1)
			}
			if !allowed.Load() {
				return errors.New("private-revocation-canary")
			}
			return nil
		})
		if !reflect.DeepEqual(resp, UploadResponse{}) {
			result <- errors.New("partial response")
			return
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original Dial not entered")
	}
	allowed.Store(false)
	unblock()
	// Assert: no original POST is emitted even though earlier upload admission succeeded.
	select {
	case err := <-result:
		if err == nil || strings.Contains(err.Error(), "canary") {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked original attempt did not finish")
	}
	if requests.Load() != 0 || writes.Load() == 0 {
		t.Fatal(requests.Load(), writes.Load())
	}
}

func TestGuardedUploadAcceptedResponseWithPeerConnectionClose(t *testing.T) {
	// Arrange: an owned TLS peer may explicitly close after a valid upload response.
	var requests atomic.Int32
	cli, _ := uploadTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, syntheticUploadResponse)
	}))
	// Act.
	resp, err := cli.UploadWithAuthority(context.Background(), []byte("abc"), MediaDocument, func(context.Context) error { return nil })
	// Assert: normal TLS shutdown cannot be confused with failure of the original request writer.
	if err != nil || requests.Load() != 1 || resp.FileLength != 3 {
		t.Fatal(err, requests.Load())
	}
}
