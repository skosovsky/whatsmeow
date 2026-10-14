package whatsmeow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"github.com/coder/websocket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
	"golang.org/x/crypto/hkdf"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
)

func TestNativePrivacyGuardedOriginalFrame(t *testing.T) {
	for _, name := range []types.PrivacySettingType{"groupadd", "last", "status", "profile", "readreceipts", "online", "calladd", "messages", "defense", "stickers"} {
		for _, mode := range []string{"ack", "foreign", "content", "wrong-id", "extra", "disconnect", "denied", "panic", "cancel"} {
			denied := mode == "denied" || mode == "panic" || mode == "cancel"
			value := types.PrivacySetting("all")
			if name == "defense" {
				value = "on_standard"
			}
			if name == "stickers" {
				value = "contacts"
			}
			t.Run(string(name)+"/"+mode, func(t *testing.T) {
				// Arrange: actual SDK IQ/Noise/Frame and local websocket; no personal session.
				cli := NewClient(&store.Device{}, waLog.Noop)
				originalCache := &types.PrivacySettings{ReadReceipts: "none"}
				cli.privacySettingsCache.Store(originalCache)
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
				target := types.ServerJID
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
						privacy := node.GetChildByTag("privacy")
						category := privacy.GetChildByTag("category")
						id, ok := node.Attrs["id"].(string)
						if node.Tag != "iq" || !ok || id == "" || node.Attrs["to"] != target || node.Attrs["xmlns"] != "privacy" || node.Attrs["type"] != "set" || category.Attrs["name"] != string(name) || category.Attrs["value"] != string(value) || len(node.GetChildren()) != 1 || len(privacy.GetChildren()) != 1 {
							t.Error("privacy IQ literal binding changed")
							return
						}
						if mode == "ack" || mode == "foreign" || mode == "content" || mode == "wrong-id" || mode == "extra" {
							cli.responseWaitersLock.Lock()
							waiter := cli.responseWaiters[id]
							delete(cli.responseWaiters, id)
							cli.responseWaitersLock.Unlock()
							response := &waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": id, "type": "result", "from": types.ServerJID}}
							if mode == "foreign" {
								response.Attrs["from"] = types.NewJID("777", types.DefaultUserServer)
							}
							if mode == "content" {
								response.Content = []waBinary.Node{{Tag: "privacy"}}
							}
							if mode == "wrong-id" {
								response.Attrs["id"] = "OTHER"
							}
							if mode == "extra" {
								response.Attrs["extra"] = "canary"
							}
							waiter <- response
						} else {
							cli.clearResponseWaiters(xmlStreamEndNode)
						}
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
				guard := func(ctx context.Context) error {
					calls++
					if ctx.Err() != nil || frames.Load() != 0 {
						t.Error("IQ guard outside original physical attempt")
					}
					if mode == "panic" {
						panic("private-iq-authority-canary")
					}
					if mode == "cancel" {
						cancel()
						return nil
					}
					if denied {
						return errors.New("private-iq-authority-canary")
					}
					return nil
				}
				// Act: invoke the actual guarded privacy mutation.
				err = cli.SetPrivacySettingGuarded(ctx, name, value, guard)
				// Assert: refused IQ creates zero frames; accepted attempt is not resent after disconnect.
				if cli.privacySettingsCache.Load() != originalCache || originalCache.ReadReceipts != "none" {
					t.Fatal("guarded mutation changed original cache")
				}
				if calls != 1 {
					t.Fatal("IQ authority not called exactly once", calls)
				}
				if denied {
					if (mode != "cancel" && !errors.Is(err, socket.ErrFrameAuthority)) || (mode == "cancel" && !errors.Is(err, context.Canceled)) || strings.Contains(err.Error(), "canary") || frames.Load() != 0 {
						t.Fatal("denied IQ side effect", err, frames.Load())
					}
				} else {
					var disconnected *DisconnectedError
					if (mode == "ack" && err != nil) || ((mode == "foreign" || mode == "content" || mode == "wrong-id" || mode == "extra") && (err == nil || strings.Contains(err.Error(), "canary"))) || (mode == "disconnect" && (!errors.As(err, &disconnected) || disconnected.Action != "info query")) {
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
}

func TestPrivacyGuardedMissingAuthority(t *testing.T) {
	// Arrange: SDK has no connected transport.
	cli := NewClient(&store.Device{}, waLog.Noop)
	// Act.
	err := cli.SetPrivacySettingGuarded(context.Background(), "readreceipts", "all", nil)
	// Assert: authority refusal precedes transport access.
	if !errors.Is(err, socket.ErrFrameAuthority) {
		t.Fatal(err)
	}
}
