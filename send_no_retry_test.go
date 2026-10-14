package whatsmeow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waMsgApplication"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestSendMessageNoRetryCountsActualNoiseFrames(t *testing.T) {
	for _, scenario := range []string{"upstream-retry-baseline", "approved-no-retry", "guard-forces-no-retry"} {
		noRetry := scenario != "upstream-retry-baseline"
		t.Run(scenario, func(t *testing.T) {
			// Arrange: real SendMessage/Noise/Frame/websocket; only server response delivery is synthetic.
			owner := types.NewJID("123", types.DefaultUserServer)
			target := types.NewJID("456", types.NewsletterServer)
			cli := NewClient(&store.Device{ID: &owner}, waLog.Noop)
			cli.SendReportingTokens = false
			cli.UseRetryMessageStore = noRetry // nil EventBuffer proves approved sends skip durable retry storage.
			cli.isLoggedIn.Store(true)
			var frames atomic.Int32
			received := make(chan struct{}, 2)
			original := "SYNTHETIC_ORIGINAL_MESSAGE"
			literal := "Кириллица e\u0301 🙂"
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
					n := frames.Add(1)
					if n > 2 {
						t.Error("extra physical frame")
						return
					}
					if len(frame) < 3 || int(frame[0])<<16|int(frame[1])<<8|int(frame[2]) != len(frame)-3 {
						t.Error("invalid frame length")
						return
					}
					iv := make([]byte, 12)
					binary.BigEndian.PutUint32(iv[8:], uint32(n-1))
					plaintext, err := aead.Open(nil, iv, frame[3:], nil)
					if err != nil {
						t.Error("native cipher mismatch", err)
						return
					}
					unpacked, err := waBinary.Unpack(plaintext)
					if err != nil {
						t.Error("native unpack mismatch", err)
						return
					}
					node, err := waBinary.Unmarshal(unpacked)
					if err != nil {
						t.Error("native node mismatch", err)
						return
					}
					if node.Tag != "message" || node.Attrs["id"] != original || node.Attrs["to"] != target {
						t.Error("immutable wire binding", node)
						return
					}
					body := node.GetChildByTag("plaintext")
					message := &waE2E.Message{}
					raw, ok := body.Content.([]byte)
					if !ok || proto.Unmarshal(raw, message) != nil || message.GetConversation() != literal {
						t.Error("literal payload changed")
						return
					}
					if n == 1 {
						cli.clearResponseWaiters(xmlStreamEndNode)
					} else {
						cli.clearResponseWaiters(&waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"id": original, "t": time.Now().Unix()}})
					}
					received <- struct{}{}
				}
			}))
			defer server.Close()
			fs := socket.NewFrameSocket(waLog.Noop, nil)
			fs.URL = "ws" + strings.TrimPrefix(server.URL, "http")
			fs.HTTPHeaders = http.Header{}
			fs.Header = nil
			connection, cancelConnection := context.WithCancel(context.Background())
			defer cancelConnection()
			if err := fs.Connect(connection); err != nil {
				t.Fatal(err)
			}
			ns, err := socket.NewNoiseHandshake().Finish(fs, func(context.Context, []byte) {}, func(context.Context, *socket.NoiseSocket, bool) {})
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close(0)
			cli.socket = ns
			// Act: actual SDK message waits for the synthetic disconnect after its first physical frame.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			options := SendRequestExtra{ID: original, NoRetry: noRetry}
			guardCalls := 0
			if scenario == "guard-forces-no-retry" {
				options.NoRetry = false
				options.BeforeWrite = func(receivedCtx context.Context) error {
					guardCalls++
					if receivedCtx.Err() != nil || frames.Load() != 0 {
						t.Error("guard ran after physical write")
					}
					return nil
				}
			}
			response, err := cli.SendMessage(ctx, target, &waE2E.Message{Conversation: proto.String(literal)}, options)
			if scenario == "guard-forces-no-retry" && guardCalls != 1 {
				t.Fatal("native guard count", guardCalls)
			}
			// Assert: native retry baseline emits two, explicit NoRetry one, with original ID and decrypted bytes.
			want := int32(2)
			if noRetry {
				want = 1
				var disconnected *DisconnectedError
				if !errors.As(err, &disconnected) || disconnected.Action != "message send" {
					t.Fatal("disconnect was misclassified", err)
				}
			} else if err != nil {
				t.Fatal("baseline retry failed", err)
			}
			for range want {
				select {
				case <-received:
				case <-time.After(5 * time.Second):
					t.Fatal("physical frame evidence absent")
				}
			}
			if cached := cli.getRecentMessage(target, original); cached.IsEmpty() != noRetry {
				t.Fatal("NoRetry payload cache boundary")
			}
			if frames.Load() != want || response.ID != original {
				t.Fatal("physical attempt count or correlation", frames.Load(), response.ID)
			}
		})
	}
}

func TestDisableRetryReceiptsRefusesBeforePayloadLookup(t *testing.T) {
	for _, source := range []string{"cached-wa", "cached-fb", "fresh-durable-store", "fresh-callback", "malformed-receipt"} {
		t.Run(source, func(t *testing.T) {
			// Arrange: no session/network, and poison every downstream lookup/callback.
			cli := NewClient(&store.Device{}, waLog.Noop)
			cli.DisableRetryReceipts = true
			cli.UseRetryMessageStore = source == "fresh-durable-store"
			cli.GetMessageForRetry = func(types.JID, types.JID, types.MessageID) *waE2E.Message { panic("unexpected payload lookup") }
			cli.PreRetryCallback = func(*events.Receipt, types.MessageID, int, *waE2E.Message) bool { panic("unexpected retry callback") }
			chat := types.NewJID("456", types.NewsletterServer)
			id := types.MessageID("SYNTHETIC_RETRY")
			if source == "cached-wa" {
				cli.recentMessagesMap[recentMessageKey{chat, id}] = RecentMessage{wa: &waE2E.Message{Conversation: proto.String("literal")}}
			}
			if source == "cached-fb" {
				cli.recentMessagesMap[recentMessageKey{chat, id}] = RecentMessage{fb: &waMsgApplication.MessageApplication{}}
			}
			node := &waBinary.Node{Tag: "receipt", Content: []waBinary.Node{{Tag: "retry", Attrs: waBinary.Attrs{"id": string(id), "t": "123", "count": "1"}}}}
			if source == "malformed-receipt" {
				node = nil
			}
			// Act: exercise the real native retry handler, not a callback stand-in.
			err := cli.handleRetryReceipt(context.Background(), &events.Receipt{MessageSource: types.MessageSource{Chat: chat}}, node)
			// Assert: no parsing/lookup/counter/encryption/socket access was necessary.
			if err != nil || len(cli.incomingRetryRequestCounter) != 0 || cli.socket != nil {
				t.Fatalf("retry side effect: err=%v", err)
			}
		})
	}
}

func TestReceiptRetryDefaultPreservesPayloadLookup(t *testing.T) {
	// Arrange: upstream default must still reach the documented fallback callback.
	cli := NewClient(&store.Device{}, waLog.Noop)
	cli.UseRetryMessageStore = false
	calls := 0
	cli.GetMessageForRetry = func(types.JID, types.JID, types.MessageID) *waE2E.Message { calls++; return nil }
	node := &waBinary.Node{Content: []waBinary.Node{{Tag: "retry", Attrs: waBinary.Attrs{"id": "SYNTHETIC_RETRY", "t": "123", "count": "1"}}}}
	// Act.
	err := cli.handleRetryReceipt(context.Background(), &events.Receipt{MessageSource: types.MessageSource{Chat: types.NewJID("456", types.NewsletterServer)}}, node)
	// Assert: normal missing-message error after exactly one fallback lookup.
	if cli.DisableRetryReceipts || err == nil || calls != 1 {
		t.Fatalf("default changed: err=%v calls=%d", err, calls)
	}
}
