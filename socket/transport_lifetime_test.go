package socket

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	waLog "go.mau.fi/whatsmeow/util/log"
)

type blockingWire struct {
	panicWrite                       bool
	entered, closed, release, exited chan struct{}
	closeOnce, releaseOnce           sync.Once
	writes                           atomic.Int32
}

func newBlockingWire() *blockingWire {
	return &blockingWire{entered: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
}
func (w *blockingWire) Read([]byte) (int, error) { <-w.closed; return 0, io.EOF }
func (w *blockingWire) Close() error             { w.closeOnce.Do(func() { close(w.closed) }); return nil }
func (w *blockingWire) Write([]byte) (int, error) {
	if w.writes.Add(1) != 1 {
		return 0, errors.New("unexpected second physical write")
	}
	close(w.entered)
	<-w.release
	close(w.exited)
	if w.panicWrite {
		panic("private-native-writer-canary")
	}
	return 0, net.ErrClosed
}
func (w *blockingWire) unblock() { w.releaseOnce.Do(func() { close(w.release) }) }

type syntheticUpgrade func(*http.Request) (*http.Response, error)

func (f syntheticUpgrade) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testCipher(t *testing.T) cipher.AEAD {
	t.Helper()
	b, e := aes.NewCipher(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func blockingNoise(t *testing.T, w *blockingWire) *NoiseSocket {
	t.Helper()
	hc := &http.Client{Transport: syntheticUpgrade(func(r *http.Request) (*http.Response, error) {
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		return &http.Response{StatusCode: 101, Header: http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}, "Sec-Websocket-Accept": {base64.StdEncoding.EncodeToString(sum[:])}}, Body: w, Request: r}, nil
	})}
	conn, _, e := websocket.Dial(context.Background(), "ws://synthetic.invalid", &websocket.DialOptions{HTTPClient: hc})
	if e != nil {
		t.Fatal(e)
	}
	connectionCtx, cancel := context.WithCancel(context.Background())
	fs := &FrameSocket{cancelCtx: connectionCtx, parentCtx: connectionCtx, cancel: cancel, log: waLog.Noop}
	fs.conn.Store(conn)
	t.Cleanup(func() { w.unblock(); fs.Close(0) })
	return &NoiseSocket{fs: fs, writeKey: testCipher(t), stopConsumer: make(chan struct{})}
}
func waitSignal(t *testing.T, c <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatal(label)
	}
}
func TestNoiseCancellationWaitsForActualWebsocketWriteExit(t *testing.T) {
	// Arrange: actual coder websocket and Noise/Frame sockets; only network body Write is controlled.
	wire := newBlockingWire()
	ns := blockingNoise(t, wire)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ns.SendFrame(ctx, []byte(strings.Repeat("x", 32768))) }()
	waitSignal(t, wire.entered, "physical write did not enter")
	// Act: caller cancellation reaches connection Close, but physical Write deliberately stays active.
	cancel()
	waitSignal(t, wire.closed, "caller context did not reach connection")
	// Assert: method return cannot abandon that actual writer.
	select {
	case e := <-done:
		t.Fatal("abandoned active physical writer", e)
	default:
	}
	if wire.writes.Load() != 1 {
		t.Fatal("extra physical writer")
	}
	wire.unblock()
	waitSignal(t, wire.exited, "physical writer did not exit")
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("lost cancellation", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Noise call did not finish")
	}
	if !ns.destroyed.Load() || ns.fs.IsConnected() {
		t.Fatal("ambiguous encrypted session retained")
	}
	if e := ns.SendFrame(context.Background(), []byte("later")); !errors.Is(e, ErrSocketClosed) || wire.writes.Load() != 1 {
		t.Fatal("reused ambiguous session", e)
	}
}
func TestNoiseQueuedCancellationCreatesNoWriterOrCounter(t *testing.T) {
	// Arrange: first actual physical writer occupies the queue.
	wire := newBlockingWire()
	ns := blockingNoise(t, wire)
	first, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	done := make(chan error, 1)
	go func() { done <- ns.SendFrame(first, make([]byte, 32768)) }()
	waitSignal(t, wire.entered, "first writer did not enter")
	queued, cancelQueued := context.WithCancel(context.Background())
	defer cancelQueued()
	queuedStarted, queuedDone := make(chan struct{}), make(chan error, 1)
	go func() { close(queuedStarted); queuedDone <- ns.SendFrame(queued, []byte("must not encrypt or write")) }()
	waitSignal(t, queuedStarted, "queued caller did not start")
	select {
	case err := <-queuedDone:
		t.Fatal("queued writer bypassed occupied admission", err)
	default:
	}
	// Act: cancellation interrupts the waiting caller without creating a later writer.
	cancelQueued()
	var e error
	select {
	case e = <-queuedDone:
	case <-time.After(5 * time.Second):
		t.Fatal("queued cancellation remained blocked")
	}
	// Assert: no second worker/frame/counter while first writer remains held.
	if !errors.Is(e, context.Canceled) || wire.writes.Load() != 1 || ns.writeCounter != 1 {
		t.Fatal("queued cancellation leaked writer/counter", e)
	}

	select {
	case <-done:
		t.Fatal("first writer returned before exit")
	default:
	}
	cancelFirst()
	waitSignal(t, wire.closed, "first connection not cancelled")
	wire.unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("first writer did not finish")
	}
}
func TestNoiseSuccessfulFramesKeepCounterAndLiteralPayload(t *testing.T) {
	// Arrange: real local websocket receiver; decryption proves physical bytes and encryption counters.
	received := make(chan []byte, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := websocket.Accept(w, r, nil)
		if e != nil {
			t.Error(e)
			return
		}
		defer c.CloseNow()
		for range 2 {
			_, p, e := c.Read(r.Context())
			if e != nil {
				t.Error(e)
				return
			}
			received <- p
		}
	}))
	defer server.Close()
	conn, _, e := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if e != nil {
		t.Fatal(e)
	}
	connectionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := &FrameSocket{cancelCtx: connectionCtx, parentCtx: connectionCtx, cancel: cancel, log: waLog.Noop}
	fs.conn.Store(conn)
	defer fs.Close(0)
	key := testCipher(t)
	ns := &NoiseSocket{fs: fs, writeKey: key, stopConsumer: make(chan struct{})}
	for n, payload := range []string{"Кириллица e\u0301", "literal second"} {
		// Act.
		ctx, finish := context.WithTimeout(context.Background(), time.Second)
		e = ns.SendFrame(ctx, []byte(payload))
		finish()
		if e != nil {
			t.Fatal(e)
		}
		// Assert.
		select {
		case frame := <-received:
			if len(frame) < 3 || int(frame[0])<<16|int(frame[1])<<8|int(frame[2]) != len(frame)-3 {
				t.Fatal("invalid frame length")
			}
			plaintext, e := key.Open(nil, generateIV(uint32(n)), frame[3:], nil)
			if e != nil || string(plaintext) != payload {
				t.Fatal("literal/counter mismatch", e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("physical frame absent")
		}
	}
	if ns.writeCounter != 2 || ns.destroyed.Load() {
		t.Fatal("successful counter/lifecycle")
	}
}

func TestNoiseWriterPanicClosesSessionAndRedactsDiagnostic(t *testing.T) {
	// Arrange: real websocket writer, failing only at its actual network Write boundary.
	wire := newBlockingWire()
	wire.panicWrite = true
	wire.unblock()
	ns := blockingNoise(t, wire)
	// Act: a physical writer panic must return only a fixed error and release writer admission.
	err := ns.SendFrame(context.Background(), make([]byte, 32768))
	// Assert: no reusable ambiguous session, raw panic or second physical write.
	if !errors.Is(err, errNoiseWritePanic) || strings.Contains(err.Error(), "private-native") || !ns.destroyed.Load() || ns.fs.IsConnected() {
		t.Fatal("unsafe panic outcome", err)
	}
	if err = ns.SendFrame(context.Background(), []byte("later")); !errors.Is(err, ErrSocketClosed) || wire.writes.Load() != 1 {
		t.Fatal("panic session reused", err)
	}
}

func TestNoiseDeadlineReachesActualWriterAndWaitsForExit(t *testing.T) {
	// Arrange: the real websocket stack with a physical writer ignoring Close until released.
	wire := newBlockingWire()
	ns := blockingNoise(t, wire)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ns.SendFrame(ctx, make([]byte, 32768)) }()
	waitSignal(t, wire.entered, "deadline writer did not enter")
	// Act: the original deadline must close the actual connection, not just return from Noise.
	waitSignal(t, wire.closed, "original deadline did not reach the physical writer")
	// Assert: physical lifetime is still held until real Write return, with the original timeout reported.
	select {
	case err := <-done:
		t.Fatal("deadline abandoned physical writer", err)
	default:
	}
	wire.unblock()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("lost original deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deadline writer did not finish")
	}
	if wire.writes.Load() != 1 || !ns.destroyed.Load() || ns.fs.IsConnected() {
		t.Fatal("deadline retained ambiguous session or sent twice")
	}
}

func TestNoiseFinalAuthorityRefusalKeepsCounterAndSession(t *testing.T) {
	for _, mode := range []string{"deny", "panic", "cancel-during-check"} {
		t.Run(mode, func(t *testing.T) {
			// Arrange: real websocket/Noise/Frame stack; no physical write is authorized.
			wire := newBlockingWire()
			ns := blockingNoise(t, wire)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			check := func(context.Context) error {
				calls++
				if len(ns.writeGate) != 1 {
					t.Error("authority ran before writer admission")
				}
				switch mode {
				case "panic":
					panic("private-frame-authority-canary")
				case "cancel-during-check":
					cancel()
					return nil
				default:
					return errors.New("private-frame-authority-canary")
				}
			}
			// Act: refuse at the actual Noise boundary before Seal or Write.
			err := ns.SendFrameWithGuard(ctx, []byte("must not be written"), check)
			// Assert: no physical worker/counter consumption or ambiguous-session close.
			want := ErrFrameAuthority
			if mode == "cancel-during-check" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || strings.Contains(err.Error(), "canary") || calls != 1 || wire.writes.Load() != 0 || ns.writeCounter != 0 || ns.destroyed.Load() || !ns.fs.IsConnected() || len(ns.writeGate) != 0 {
				t.Fatal("authority failure touched transport/session", err, calls, wire.writes.Load(), ns.writeCounter)
			}
		})
	}
}

func TestNoiseFinalAuthorityRunsAfterQueuedAdmission(t *testing.T) {
	for _, mode := range []string{"revoked-after-queue", "cancelled-in-queue"} {
		t.Run(mode, func(t *testing.T) {
			// Arrange: occupy native writer admission without encryption or a physical worker.
			wire := newBlockingWire()
			ns := blockingNoise(t, wire)
			ns.writeGateOnce.Do(func() { ns.writeGate = make(chan struct{}, 1) })
			ns.writeGate <- struct{}{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var revoked atomic.Bool
			var calls atomic.Int32
			ready, done := make(chan struct{}), make(chan error, 1)
			go func() {
				close(ready)
				done <- ns.SendFrameWithGuard(ctx, []byte("never emit"), func(context.Context) error {
					calls.Add(1)
					if revoked.Load() {
						return errors.New("authority revoked")
					}
					return nil
				})
			}()
			waitSignal(t, ready, "queued request did not start")
			// Act: change authority/cancellation while physical admission is occupied.
			revoked.Store(true)
			if mode == "cancelled-in-queue" {
				cancel()
			} else {
				<-ns.writeGate
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("queued authority remained blocked")
			}
			if mode == "cancelled-in-queue" {
				<-ns.writeGate
			}
			// Assert: denied after queue admission or cancelled without invoking the callback.
			want, wantCalls := ErrFrameAuthority, int32(1)
			if mode == "cancelled-in-queue" {
				want, wantCalls = context.Canceled, 0
			}
			if !errors.Is(err, want) || calls.Load() != wantCalls || wire.writes.Load() != 0 || ns.writeCounter != 0 || ns.destroyed.Load() || len(ns.writeGate) != 0 {
				t.Fatal("queue authority leaked frame/counter", err, calls.Load())
			}
		})
	}
}

func TestNoiseAuthenticatedFrameProofIsExactActiveAndSingleUse(t *testing.T) {
	// Arrange: real AEAD receive path and private callback proof.
	ns := &NoiseSocket{readKey: testCipher(t), fs: &FrameSocket{log: waLog.Noop}}
	data := []byte("owned-authenticated-plaintext")
	var captured context.Context
	calls := 0
	ns.onFrame = func(ctx context.Context, plain []byte) {
		calls++
		captured = ctx
		// Act / Assert: foreign socket/bytes cannot consume the original proof.
		if (&NoiseSocket{}).ConsumeAuthenticatedFrame(ctx, plain) || ns.ConsumeAuthenticatedFrame(ctx, []byte("changed")) || ns.ConsumeAuthenticatedFrame(context.Background(), plain) {
			t.Fatal("foreign receive proof accepted")
		}
		if !ns.ConsumeAuthenticatedFrame(ctx, plain) || ns.ConsumeAuthenticatedFrame(ctx, plain) {
			t.Fatal("original proof not single-use")
		}
	}
	ns.receiveEncryptedFrame(context.Background(), ns.readKey.Seal(nil, generateIV(0), data, nil))
	if calls != 1 || ns.ConsumeAuthenticatedFrame(captured, data) || ns.ConsumeAuthenticatedFrame(nil, data) {
		t.Fatal("captured/invalid proof revived")
	}
	// A callback that does not consume still cannot use its proof after return.
	ns.onFrame = func(ctx context.Context, _ []byte) { calls++; captured = ctx }
	ns.receiveEncryptedFrame(context.Background(), ns.readKey.Seal(nil, generateIV(1), data, nil))
	if calls != 2 || ns.ConsumeAuthenticatedFrame(captured, data) {
		t.Fatal("expired unused proof revived")
	}
	// Failed authentication creates no callback or proof.
	ns.receiveEncryptedFrame(context.Background(), []byte("not-authenticated"))
	if calls != 2 {
		t.Fatal("failed AEAD dispatched receive proof")
	}
}
