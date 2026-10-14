package whatsmeow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/hkdf"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
)

func TestFrameAuthoritySelectsOriginalNodeAndConsumesOnce(t *testing.T) {
	// Arrange: synthetic original message admission with a trusted callback counter.
	var calls atomic.Int32
	ctx := withFrameAuthority(context.Background(), "message", "ORIGINAL", func(context.Context) error { calls.Add(1); return nil })
	// Act: preparatory IQ does not consume; changed message ID is denied; concurrent original attempts compete.
	if frameGuardForNode(ctx, waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": "PREP"}}) != nil {
		t.Fatal("preparatory node consumed message authority")
	}
	wrong := frameGuardForNode(ctx, waBinary.Node{Tag: "message", Attrs: waBinary.Attrs{"id": "OTHER"}})
	if !errors.Is(wrong(ctx), socket.ErrFrameAuthority) {
		t.Fatal("foreign message was admitted")
	}
	guard := frameGuardForNode(ctx, waBinary.Node{Tag: "message", Attrs: waBinary.Attrs{"id": "ORIGINAL", "to": types.NewJID("123", types.GroupServer)}})
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if guard(ctx) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	// Assert: exactly one original attempt; wrong-ID refusal did not consume it.
	if calls.Load() != 1 || accepted.Load() != 1 {
		t.Fatal(calls.Load(), accepted.Load())
	}
}

func TestFrameAuthorityFailureCannotObtainAnotherAttempt(t *testing.T) {
	// Arrange: a failing trusted callback cannot mint a second entitlement.
	calls := 0
	ctx := withFrameAuthority(context.Background(), "iq", "ORIGINAL", func(context.Context) error { calls++; return errors.New("synthetic rejection") })
	guard := frameGuardForNode(ctx, waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": "ORIGINAL", "to": types.NewJID("123", types.GroupServer)}})
	// Act.
	first, second := guard(ctx), guard(ctx)
	// Assert: initial refusal is terminal for that SDK invocation.
	if first == nil || !errors.Is(second, socket.ErrFrameAuthority) || calls != 1 {
		t.Fatal(first, second, calls)
	}
}

func TestNativeIQBeforeWriteDenialAndForcedNoRetry(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "disconnect-no-resend", true: "authority-denied"}[denied], func(t *testing.T) {
			// Arrange: actual SDK IQ/Noise/Frame and local websocket; no personal session.
			cli := NewClient(&store.Device{}, waLog.Noop)
			var frames atomic.Int32
			key := make([]byte, 32)
			if _, err := io.ReadFull(hkdf.New(sha256.New, nil, nil, nil), key); err != nil {
				t.Fatal(err)
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			aead, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			target := types.NewJID("123-456", types.GroupServer)
			id := "SYNTHETIC_ORIGINAL_IQ"
			received := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := websocket.Accept(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.CloseNow()
				for {
					_, frame, err := conn.Read(r.Context())
					if err != nil {
						return
					}
					if frames.Add(1) != 1 {
						t.Error("IQ guard permitted resend")
						return
					}
					if len(frame) < 3 {
						t.Error("truncated physical IQ frame")
						return
					}
					plain, err := aead.Open(nil, make([]byte, 12), frame[3:], nil)
					if err != nil {
						t.Error(err)
						return
					}
					unpacked, err := waBinary.Unpack(plain)
					if err != nil {
						t.Error(err)
						return
					}
					node, err := waBinary.Unmarshal(unpacked)
					if err != nil {
						t.Error(err)
						return
					}
					subject := node.GetChildByTag("subject")
					body, ok := subject.Content.([]byte)
					if node.Tag != "iq" || node.Attrs["id"] != id || node.Attrs["to"] != target || !ok || string(body) != "Тема e\u0301 🙂" {
						t.Error("IQ correlation/literal bytes changed")
						return
					}
					cli.clearResponseWaiters(xmlStreamEndNode)
					received <- struct{}{}
				}
			}))
			defer server.Close()
			fs := socket.NewFrameSocket(waLog.Noop, nil)
			fs.URL = "ws" + strings.TrimPrefix(server.URL, "http")
			fs.HTTPHeaders = http.Header{}
			fs.Header = nil
			connCtx, stop := context.WithCancel(context.Background())
			defer stop()
			if err := fs.Connect(connCtx); err != nil {
				t.Fatal(err)
			}
			ns, err := socket.NewNoiseHandshake().Finish(fs, func(context.Context, []byte) {}, func(context.Context, *socket.NoiseSocket, bool) {})
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close(0)
			cli.socket = ns
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			query := infoQuery{Namespace: "w:g2", Type: iqSet, To: target, ID: id, Content: []waBinary.Node{{Tag: "subject", Content: []byte("Тема e\u0301 🙂")}}, BeforeWrite: func(ctx context.Context) error {
				calls++
				if ctx.Err() != nil || frames.Load() != 0 {
					t.Error("IQ guard outside original physical attempt")
				}
				if denied {
					return errors.New("private-iq-authority-canary")
				}
				return nil
			}}
			// Act: caller omits NoRetry; configured authority must force it anyway.
			_, err = cli.sendIQ(ctx, query)
			// Assert: refused IQ creates zero frames; accepted attempt is not resent after disconnect.
			if calls != 1 {
				t.Fatal("IQ authority not called exactly once", calls)
			}
			if denied {
				if !errors.Is(err, socket.ErrFrameAuthority) || strings.Contains(err.Error(), "canary") || frames.Load() != 0 {
					t.Fatal("denied IQ side effect", err, frames.Load())
				}
			} else {
				var disconnected *DisconnectedError
				if !errors.As(err, &disconnected) || disconnected.Action != "info query" {
					t.Fatal("IQ disconnect classification", err)
				}
				select {
				case <-received:
				case <-time.After(5 * time.Second):
					t.Fatal("physical IQ evidence absent")
				}
				if frames.Load() != 1 {
					t.Fatal("IQ resend", frames.Load())
				}
			}
			cli.responseWaitersLock.Lock()
			waiters := len(cli.responseWaiters)
			cli.responseWaitersLock.Unlock()
			if waiters != 0 {
				t.Fatal("IQ leaked response waiter", waiters)
			}
		})
	}
}

func TestOriginalMessageDestinationIsBoundToNativeCallbackLifetime(t *testing.T) {
	// Arrange: typed original destination and request-scoped authority.
	destination := types.NewJID("777", types.HiddenUserServer)
	var captured context.Context
	ctx := withFrameAuthority(context.Background(), "message", "ORIGINAL", func(ctx context.Context) error {
		captured = ctx
		actual, ok := OriginalMessageDestination(ctx)
		if !ok || actual != destination {
			t.Fatal("native destination proof missing", actual)
		}
		return nil
	})
	if _, ok := OriginalMessageDestination(ctx); ok {
		t.Fatal("unconsumed context invented destination")
	}
	// Act: malformed/missing destination is refused; actual original node is admitted once.
	for _, attrs := range []waBinary.Attrs{{"id": "ORIGINAL"}, {"id": "ORIGINAL", "to": "777@lid"}, {"id": "OTHER", "to": destination}} {
		guard := frameGuardForNode(ctx, waBinary.Node{Tag: "message", Attrs: attrs})
		if !errors.Is(guard(ctx), socket.ErrFrameAuthority) {
			t.Fatal("untyped destination accepted")
		}
		// Each malformed destination has terminal authority; use a fresh original root.
		ctx = withFrameAuthority(context.Background(), "message", "ORIGINAL", func(ctx context.Context) error {
			captured = ctx
			actual, ok := OriginalMessageDestination(ctx)
			if !ok || actual != destination {
				t.Fatal("wrong native destination")
			}
			return nil
		})
	}
	guard := frameGuardForNode(ctx, waBinary.Node{Tag: "message", Attrs: waBinary.Attrs{"id": "ORIGINAL", "to": destination}})
	if err := guard(ctx); err != nil {
		t.Fatal(err)
	}
	// Assert: neither original nor retained callback context has active authority after return.
	if captured == nil {
		t.Fatal("original callback not invoked")
	}
	if _, ok := OriginalMessageDestination(captured); ok {
		t.Fatal("completed callback retained active proof")
	}
	if _, ok := OriginalMessageDestination(ctx); ok {
		t.Fatal("original context gained destination proof")
	}
	if !errors.Is(guard(ctx), socket.ErrFrameAuthority) {
		t.Fatal("native authority reused")
	}
}
