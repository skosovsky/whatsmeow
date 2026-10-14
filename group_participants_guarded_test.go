package whatsmeow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"

	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestNativeParticipantsGuardedOriginalFrame(t *testing.T) {
	for _, action := range []ParticipantChange{ParticipantChangeAdd, ParticipantChangeRemove, ParticipantChangePromote, ParticipantChangeDemote} {
		for _, mode := range []string{"ack", "foreign", "content", "wrong-id", "extra", "disconnect", "denied", "panic", "cancel", "pn-drift", "token-drift"} {
			denied := mode == "denied" || mode == "panic" || mode == "cancel"
			t.Run(string(action)+"/"+mode, func(t *testing.T) {
				// Arrange: actual SDK IQ/Noise/Frame and local websocket; no personal session.
				own := types.NewJID("123", types.DefaultUserServer)
				cache := &guardedParticipantCache{pn: types.NewJID("456", types.DefaultUserServer), lid: types.NewJID("789", types.HiddenUserServer), token: []byte("private-token-canary")}
				cli := NewClient(&store.Device{ID: &own, LIDs: cache, PrivacyTokens: cache}, waLog.Noop)
				cli.lastTCTokenDBPrune = time.Now()
				targets := []GroupParticipantUpdateTarget{{JID: types.NewJID("789", types.HiddenUserServer), PhoneNumber: types.NewJID("456", types.DefaultUserServer)}}
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
				target := types.NewJID("123", types.GroupServer)
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
						update := node.GetChildByTag(string(action))
						participant := update.GetChildByTag("participant")
						id, ok := node.Attrs["id"].(string)
						if node.Tag != "iq" || !ok || id == "" || node.Attrs["to"] != target || node.Attrs["xmlns"] != "w:g2" || node.Attrs["type"] != "set" || participant.Attrs["jid"] != types.NewJID("789", types.HiddenUserServer) || len(node.GetChildren()) != 1 || len(update.GetChildren()) != 1 {
							t.Error("participant IQ literal binding changed")
							return
						}

						if action == ParticipantChangeAdd {
							privacy := participant.GetChildByTag("privacy")
							if participant.Attrs["phone_number"] != types.NewJID("456", types.DefaultUserServer) || string(privacy.Content.([]byte)) != "private-token-canary" {
								t.Error("original cached add preparation missing")
								return
							}
						} else if participant.Content != nil {
							t.Error("non-add privacy preparation")
							return
						}
						if mode == "ack" || mode == "foreign" || mode == "content" || mode == "wrong-id" || mode == "extra" {
							cli.responseWaitersLock.Lock()
							waiter := cli.responseWaiters[id]
							delete(cli.responseWaiters, id)
							cli.responseWaitersLock.Unlock()
							response := &waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": id, "type": "result", "from": target}, Content: []waBinary.Node{{Tag: string(action), Content: []waBinary.Node{{Tag: "participant", Attrs: waBinary.Attrs{"jid": types.NewJID("789", types.HiddenUserServer)}}}}}}
							if mode == "foreign" {
								response.Attrs["from"] = types.NewJID("777", types.DefaultUserServer)
							}
							if mode == "content" {
								response.Content = []waBinary.Node{{Tag: "foreign"}}
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
					if mode == "pn-drift" {
						cache.pn = types.NewJID("999", types.DefaultUserServer)
						if action != ParticipantChangeAdd {
							return errors.New("canary")
						}
					}
					if mode == "token-drift" {
						cache.token = []byte("changed-token-canary")
						if action != ParticipantChangeAdd {
							return errors.New("canary")
						}
					}
					if denied {
						return errors.New("private-iq-authority-canary")
					}
					return nil
				}
				// Act: invoke the actual guarded participant mutation.
				results, err := cli.UpdateGroupParticipantsGuarded(ctx, target, targets, action, func(context.Context) error { targets[0].JID = types.NewJID("999", types.DefaultUserServer); return nil }, guard)
				if mode == "ack" && (len(results) != 1 || results[0].JID != types.NewJID("789", types.HiddenUserServer) || results[0].Error != 0 || results[0].InvitationRequired) {
					t.Fatal("native result lost original target")
				}
				// Assert: refused IQ creates zero frames; accepted attempt is not resent after disconnect.
				if calls != 1 {
					t.Fatal("IQ authority not called exactly once", calls)
				}
				if denied || mode == "pn-drift" || mode == "token-drift" {
					if err == nil || strings.Contains(err.Error(), "canary") || frames.Load() != 0 {
						t.Fatal("denied IQ side effect", err, frames.Load())
					}
				} else {

					if (mode == "ack" && err != nil) || ((mode == "foreign" || mode == "content" || mode == "wrong-id" || mode == "extra") && (err == nil || strings.Contains(err.Error(), "canary"))) || (mode == "disconnect" && err == nil) {
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

type guardedParticipantCache struct {
	store.NoopStore
	pn, lid types.JID
	token   []byte
}

func (s *guardedParticipantCache) GetPNForLID(context.Context, types.JID) (types.JID, error) {
	return s.pn, nil
}
func (s *guardedParticipantCache) GetLIDForPN(context.Context, types.JID) (types.JID, error) {
	return s.lid, nil
}
func (s *guardedParticipantCache) GetPrivacyToken(context.Context, types.JID) (*store.PrivacyToken, error) {
	return &store.PrivacyToken{Token: s.token, Timestamp: time.Now()}, nil
}

func TestGuardedParticipantsResultValidation(t *testing.T) {
	for _, action := range []ParticipantChange{ParticipantChangeAdd, ParticipantChangeRemove, ParticipantChangePromote, ParticipantChangeDemote} {
		for _, fault := range []string{"ok", "invitation", "foreign", "duplicate", "missing", "malformed-error", "overflow", "zero-invite", "foreign-action", "extra-action", "raw-content", "wrong-from", "wrong-id"} {
			t.Run(string(action)+"/"+fault, func(t *testing.T) {
				// Arrange: original correlated synthetic SDK response, complete two-target set.
				group := types.NewJID("123", types.GroupServer)
				targets := []GroupParticipantUpdateTarget{{JID: types.NewJID("456", types.DefaultUserServer), PhoneNumber: types.NewJID("456", types.DefaultUserServer)}, {JID: types.NewJID("457", types.DefaultUserServer), PhoneNumber: types.NewJID("457", types.DefaultUserServer)}}
				participants := []waBinary.Node{{Tag: "participant", Attrs: waBinary.Attrs{"jid": targets[0].JID}}, {Tag: "participant", Attrs: waBinary.Attrs{"jid": targets[1].JID, "error": "403"}}}
				if fault == "invitation" || fault == "zero-invite" {
					participants[1].Content = []waBinary.Node{{Tag: "add_request", Attrs: waBinary.Attrs{"code": "private-invite-canary", "expiration": "2000000000"}}}
					if fault == "zero-invite" {
						participants[1].Attrs["error"] = "0"
					}
				}
				if fault == "foreign" {
					participants[1].Attrs["jid"] = types.NewJID("999", types.DefaultUserServer)
				}
				if fault == "duplicate" {
					participants[1].Attrs["jid"] = targets[0].JID
				}
				if fault == "missing" {
					participants = participants[:1]
				}
				if fault == "malformed-error" {
					participants[1].Attrs["error"] = "not-a-code"
				}
				if fault == "overflow" {
					participants[1].Attrs["error"] = "10000"
				}
				node := &waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": "original", "type": "result", "from": group}, Content: []waBinary.Node{{Tag: string(action), Content: participants}}}
				if fault == "foreign-action" {
					node.Content = []waBinary.Node{{Tag: "foreign", Content: participants}}
				}
				if fault == "extra-action" {
					node.Content = append(node.Content.([]waBinary.Node), waBinary.Node{Tag: string(action)})
				}
				if fault == "raw-content" {
					node.Content = []byte("private-node-canary")
				}
				if fault == "wrong-from" {
					node.Attrs["from"] = types.NewJID("999", types.GroupServer)
				}
				if fault == "wrong-id" {
					node.Attrs["id"] = "foreign"
				}
				// Act: only original SDK parser semantics enter the lean result projection.
				result, err := parseGuardedParticipantResults(node, group, "original", targets, action)
				// Assert: complete partial outcomes are retained; secrets and malformed ACKs are rejected.
				good := fault == "ok" || fault == "invitation" && action == ParticipantChangeAdd
				if good {
					if err != nil || len(result) != 2 || result[0].Error != 0 || result[1].Error != 403 || result[1].InvitationRequired != (fault == "invitation") {
						t.Fatal("partial result", err)
					}
				} else if err == nil || len(result) != 0 {
					t.Fatal("bad response accepted")
				}
				if strings.Contains(fmt.Sprintf("%#v %v", result, err), "canary") {
					t.Fatal("bearer material leaked")
				}
			})
		}
	}
}

func TestGuardedParticipantsMissingPreparationAndInputAuthority(t *testing.T) {
	// Arrange: original SDK with no connected transport, so refusals precede any writer.
	cli := NewClient(&store.Device{}, waLog.Noop)
	group := types.NewJID("123", types.GroupServer)
	targets := []GroupParticipantUpdateTarget{{JID: types.NewJID("456", types.DefaultUserServer), PhoneNumber: types.NewJID("456", types.DefaultUserServer)}}
	for _, mode := range []string{"prepare-nil", "write-nil", "prepare-denied", "prepare-panic", "cancelled", "device", "foreign-group", "duplicate", "alias-duplicate", "invalid-action", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			targetCopy := append([]GroupParticipantUpdateTarget(nil), targets...)
			chat := group
			action := ParticipantChangeAdd
			prepare := func(context.Context) error { return nil }
			write := prepare
			switch mode {
			case "prepare-nil":
				prepare = nil
			case "write-nil":
				write = nil
			case "prepare-denied":
				prepare = func(context.Context) error { return errors.New("private-canary") }
			case "prepare-panic":
				prepare = func(context.Context) error { panic("private-canary") }
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "device":
				targetCopy[0].JID.Device = 1
			case "foreign-group":
				chat.User = "invalid"
			case "duplicate":
				targetCopy = append(targetCopy, targetCopy[0])
			case "alias-duplicate":
				targetCopy = append(targetCopy, GroupParticipantUpdateTarget{JID: types.NewJID("789", types.HiddenUserServer), PhoneNumber: targets[0].PhoneNumber})
			case "invalid-action":
				action = "clear"
			case "too-many":
				targetCopy = make([]GroupParticipantUpdateTarget, 21)
			}
			// Act / Assert: invalid authority/input cannot access nil stores or emit a frame.
			results, err := cli.UpdateGroupParticipantsGuarded(ctx, chat, targetCopy, action, prepare, write)
			if err == nil || len(results) != 0 || strings.Contains(err.Error(), "canary") {
				t.Fatal("unsafe preparation", err)
			}
		})
	}
}
