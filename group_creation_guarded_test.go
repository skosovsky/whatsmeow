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

func TestNativeCreationGuardedOriginalFrame(t *testing.T) {
	for _, action := range []ParticipantChange{ParticipantChangeAdd} {
		for _, mode := range []string{"ack", "foreign", "content", "wrong-id", "extra", "disconnect", "denied", "panic", "cancel", "pn-drift", "token-drift", "actor-drift"} {
			denied := mode == "denied" || mode == "panic" || mode == "cancel"
			t.Run(string(action)+"/"+mode, func(t *testing.T) {
				// Arrange: actual SDK IQ/Noise/Frame and local websocket; no personal session.
				own := types.NewJID("123", types.DefaultUserServer)
				cache := &guardedParticipantCache{pn: types.NewJID("456", types.DefaultUserServer), lid: types.NewJID("789", types.HiddenUserServer), token: []byte("private-token-canary")}
				cli := NewClient(&store.Device{ID: &own, LIDs: cache, PrivacyTokens: cache}, waLog.Noop)
				cli.lastTCTokenDBPrune = time.Now()
				targets := []GroupParticipantUpdateTarget{{JID: types.NewJID("789", types.HiddenUserServer), PhoneNumber: types.NewJID("456", types.DefaultUserServer)}}
				var frames atomic.Int32
				var originalID atomic.Value
				var captured context.Context
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
				target := types.GroupServerJID
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
						update := node.GetChildByTag("create")
						participant := update.GetChildByTag("participant")
						id, ok := node.Attrs["id"].(string)
						if observed, _ := originalID.Load().(string); observed == "" || observed != id {
							t.Error("creation frame ID differs from original callback correlation")
							return
						}
						if node.Tag != "iq" || !ok || id == "" || node.Attrs["to"] != target || node.Attrs["xmlns"] != "w:g2" || node.Attrs["type"] != "set" || participant.Attrs["jid"] != types.NewJID("789", types.HiddenUserServer) || len(node.GetChildren()) != 1 || len(update.GetChildren()) != 4 {
							t.Error("participant IQ literal binding changed")
							return
						}

						if action == ParticipantChangeAdd {
							if update.Attrs["subject"] != "  Команда ☕  " {
								t.Error("literal name changed")
								return
							}
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
							response := creationResultNode(id, creationSDKRequest())
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
					id, ok := OriginalGroupCreationRequestID(ctx)
					if !ok || id == "" {
						t.Error("active original creation frame correlation absent")
					}
					originalID.Store(id)
					captured = ctx
					// Even the same ID on another active frame cannot borrow this proof.
					other := withFrameAuthority(ctx, "iq", id, func(other context.Context) error {
						if value, available := OriginalGroupCreationRequestID(other); available || value != "" {
							t.Error("another IQ authority borrowed creation correlation")
						}
						return nil
					})
					if err := frameGuardForNode(other, waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": id}})(other); err != nil {
						t.Error("synthetic unrelated frame check failed", err)
					}
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
					if mode == "actor-drift" {
						changed := types.NewJID("999", types.DefaultUserServer)
						cli.Store.ID = &changed
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
				receipt, err := cli.CreateGroupGuarded(ctx, GroupCreationGuardedRequest{Name: "  Команда ☕  ", CreatorPN: own, Targets: targets}, func(preparing context.Context) error {
					if calls == 0 {
						if id, available := OriginalGroupCreationRequestID(preparing); available || id != "" {
							t.Error("preparation obtained frame correlation before admission")
						}
					}
					targets[0].JID = types.NewJID("999", types.DefaultUserServer)
					return nil
				}, guard)
				if mode == "ack" && (receipt == nil || len(receipt.Results) != 1 || receipt.Results[0].JID != types.NewJID("789", types.HiddenUserServer) || receipt.Results[0].Error != 0 || receipt.Results[0].InvitationRequired) {
					t.Fatal("native result lost original target")
				}
				// Assert: refused IQ creates zero frames; accepted attempt is not resent after disconnect.
				if calls != 1 {
					t.Fatal("IQ authority not called exactly once", calls)
				}
				if id, available := OriginalGroupCreationRequestID(captured); available || id != "" {
					t.Fatal("captured callback context revived creation correlation")
				}
				if denied || mode == "pn-drift" || mode == "token-drift" || mode == "actor-drift" {
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

func TestOriginalCreationCorrelationRefusesCallerContexts(t *testing.T) {
	// Arrange: caller/background/preparation contexts cannot issue private proof.
	for _, ctx := range []context.Context{nil, context.Background(), context.WithValue(context.Background(), "groupCreationFrameKey", "asserted IQ ID"), withFrameAuthority(context.Background(), "iq", "asserted IQ ID", func(context.Context) error { return nil })} {
		// Act.
		id, available := OriginalGroupCreationRequestID(ctx)
		// Assert.
		if available || id != "" {
			t.Fatal("caller context acquired creation correlation")
		}
	}
}

func creationSDKRequest() GroupCreationGuardedRequest {
	return GroupCreationGuardedRequest{Name: "  Команда ☕  ", CreatorPN: types.NewJID("123", types.DefaultUserServer), Targets: []GroupParticipantUpdateTarget{{JID: types.NewJID("789", types.HiddenUserServer), PhoneNumber: types.NewJID("456", types.DefaultUserServer)}}}
}
func creationResultNode(id string, r GroupCreationGuardedRequest) *waBinary.Node {
	return &waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": id, "type": "result", "from": types.GroupServerJID}, Content: []waBinary.Node{{Tag: "group", Attrs: waBinary.Attrs{"id": "987654", "subject": r.Name, "creator": r.CreatorPN}, Content: []waBinary.Node{{Tag: "participant", Attrs: waBinary.Attrs{"jid": r.CreatorPN, "type": "superadmin"}}, {Tag: "participant", Attrs: waBinary.Attrs{"jid": r.Targets[0].JID, "phone_number": r.Targets[0].PhoneNumber}}}}}}
}
func TestGuardedCreationStrictReceiptAndInput(t *testing.T) {
	changes := map[string]func(*waBinary.Node){
		"size": func(n *waBinary.Node) { n.Content.([]waBinary.Node)[0].Attrs["size"] = "500" },
		"unknown-role": func(n *waBinary.Node) {
			n.Content.([]waBinary.Node)[0].Content.([]waBinary.Node)[1].Attrs["type"] = "unknown-role"
		},
		"id": func(n *waBinary.Node) { n.Attrs["id"] = "other" }, "source": func(n *waBinary.Node) { n.Attrs["from"] = types.NewJID("987654", types.GroupServer) },
		"subject": func(n *waBinary.Node) { n.Content.([]waBinary.Node)[0].Attrs["subject"] = "changed" },
		"creator": func(n *waBinary.Node) {
			n.Content.([]waBinary.Node)[0].Attrs["creator"] = types.NewJID("999", types.DefaultUserServer)
		},
		"role": func(n *waBinary.Node) {
			n.Content.([]waBinary.Node)[0].Content.([]waBinary.Node)[0].Attrs["type"] = "admin"
		},
		"partial": func(n *waBinary.Node) {
			g := &n.Content.([]waBinary.Node)[0]
			g.Content = g.Content.([]waBinary.Node)[:1]
		},
		"duplicate": func(n *waBinary.Node) {
			g := &n.Content.([]waBinary.Node)[0]
			m := g.Content.([]waBinary.Node)
			g.Content = append(m, m[1])
		},
		"pn": func(n *waBinary.Node) {
			n.Content.([]waBinary.Node)[0].Content.([]waBinary.Node)[1].Attrs["phone_number"] = types.NewJID("999", types.DefaultUserServer)
		},
		"locked": func(n *waBinary.Node) {
			g := &n.Content.([]waBinary.Node)[0]
			g.Content = append(g.Content.([]waBinary.Node), waBinary.Node{Tag: "locked"})
		},
		"group": func(n *waBinary.Node) { n.Content.([]waBinary.Node)[0].Attrs["id"] = "987654@g.us" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			// Arrange.
			r := creationSDKRequest()
			n := creationResultNode("original", r)
			change(n)
			// Act.
			result, err := parseGuardedCreationResult(n, "original", r)
			// Assert.
			if err == nil || result != nil {
				t.Fatal("malformed receipt exposed")
			}
		})
	}
	// Arrange: complete failed-add response containing an invitation bearer.
	r := creationSDKRequest()
	n := creationResultNode("original", r)
	m := &n.Content.([]waBinary.Node)[0].Content.([]waBinary.Node)[1]
	m.Attrs["error"] = "403"
	m.Content = []waBinary.Node{{Tag: "add_request", Attrs: waBinary.Attrs{"code": "private-invitation-canary", "expiration": "2000000000"}}}
	// Act.
	result, err := parseGuardedCreationResult(n, "original", r)
	// Assert.
	if err != nil || len(result.Results) != 1 || !result.Results[0].InvitationRequired || result.Results[0].Error != 403 {
		t.Fatal("invitation outcome", err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", result, result), "canary") {
		t.Fatal("receipt formatting leaked")
	}
	for _, change := range []func(*GroupCreationGuardedRequest){func(r *GroupCreationGuardedRequest) { r.Name = "\n" }, func(r *GroupCreationGuardedRequest) { r.Targets = append(r.Targets, r.Targets[0]) }, func(r *GroupCreationGuardedRequest) { r.Targets[0].PhoneNumber = r.CreatorPN }, func(r *GroupCreationGuardedRequest) { r.Name = strings.Repeat("😀", 101) }} {
		r := creationSDKRequest()
		change(&r)
		if validateGuardedCreation(r) == nil {
			t.Fatal("invalid request")
		}
	}
}

func TestGuardedCreationTwentyTargetsAndOptionalPhoneHint(t *testing.T) {
	// Arrange: maximum bounded target table and reverse native ACK order.
	r := creationSDKRequest()
	r.Targets = nil
	for i := 0; i < 20; i++ {
		r.Targets = append(r.Targets, GroupParticipantUpdateTarget{JID: types.NewJID(fmt.Sprint(1000+i), types.HiddenUserServer), PhoneNumber: types.NewJID(fmt.Sprint(2000+i), types.DefaultUserServer)})
	}
	n := creationResultNode("original", r)
	g := &n.Content.([]waBinary.Node)[0]
	rows := []waBinary.Node{g.Content.([]waBinary.Node)[0]}
	for i := 19; i >= 0; i-- {
		rows = append(rows, waBinary.Node{Tag: "participant", Attrs: waBinary.Attrs{"jid": r.Targets[i].JID}})
	}
	g.Content = rows
	// Act: omitted PN hints retain the already-frozen exact effective JID binding.
	result, err := parseGuardedCreationResult(n, "original", r)
	// Assert.
	if err != nil || len(result.Results) != 20 {
		t.Fatal("bounded complete result", err)
	}
	r.Targets = append(r.Targets, r.Targets[0])
	if validateGuardedCreation(r) == nil {
		t.Fatal("21 targets accepted")
	}
}
