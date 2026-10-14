//go:build wa_mcp_native_test

package whatsmeow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/groups"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/util/optional"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// NativeMCPTestTransport exists only under an explicit test build tag. It owns
// its ephemeral loopback connection and has no caller-supplied network target.
type NativeMCPTestTransport struct {
	Client                *Client
	Nodes                 chan *waBinary.Node
	Handled               chan *waBinary.Node
	frames                atomic.Int32
	noise                 *socket.NoiseSocket
	body                  *nativeMCPWriteBody
	responseWriteMu       sync.Mutex
	responseWriteObserver chan error
	peerIncoming          chan nativeMCPIncoming
}

type nativeMCPIncoming struct {
	node      waBinary.Node
	result    chan error
	closePeer bool
}

func (f *NativeMCPTestTransport) Frames() int32 { return f.frames.Load() }

func NewNativeMCPTestTransport(t *testing.T, respond func(context.Context, *waBinary.Node) *waBinary.Node) *NativeMCPTestTransport {
	t.Helper()
	owner := types.NewJID("447700900999", types.DefaultUserServer)
	cli := NewClient(&store.Device{ID: &owner}, waLog.Noop)
	cli.EnableAutoReconnect = false
	cli.isLoggedIn.Store(true)
	cli.DisableRetryReceipts = true
	f := &NativeMCPTestTransport{Client: cli, Nodes: make(chan *waBinary.Node, 16), Handled: make(chan *waBinary.Node, 16), peerIncoming: make(chan nativeMCPIncoming, 1)}
	keys := make([]byte, 64)
	if _, err := io.ReadFull(hkdf.New(sha256.New, nil, nil, nil), keys); err != nil {
		t.Fatal(err)
	}
	cipherFor := func(key []byte) cipher.AEAD {
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return aead
	}
	fromClient, toClient := cipherFor(keys[:32]), cipherFor(keys[32:])
	serverDone, disconnected := make(chan struct{}), make(chan struct{})
	var disconnectOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverDone)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.CloseNow()
		var received, sent uint32
		iv := func(n uint32) []byte { b := make([]byte, 12); binary.BigEndian.PutUint32(b[8:], n); return b }
		var peerWriteMu sync.Mutex
		sendResponse := func(answer waBinary.Node) error {
			peerWriteMu.Lock()
			defer peerWriteMu.Unlock()
			encoded, err := waBinary.Marshal(answer)
			if err != nil {
				return err
			}
			encrypted := toClient.Seal(nil, iv(sent), encoded, nil)
			sent++
			wire := make([]byte, len(encrypted)+3)
			wire[0], wire[1], wire[2] = byte(len(encrypted)>>16), byte(len(encrypted)>>8), byte(len(encrypted))
			copy(wire[3:], encrypted)
			err = conn.Write(r.Context(), websocket.MessageBinary, wire)
			f.responseWriteMu.Lock()
			observer := f.responseWriteObserver
			f.responseWriteObserver = nil
			f.responseWriteMu.Unlock()
			if observer != nil {
				observer <- err
				close(observer)
			} else if err != nil {
				t.Error(err)
			}
			return err
		}
		peerStop, peerExited := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(peerExited)
			for {
				select {
				case incoming := <-f.peerIncoming:
					if incoming.closePeer {
						conn.CloseNow()
						incoming.result <- nil
						return
					}
					incoming.result <- sendResponse(incoming.node)
				case <-peerStop:
					return
				}
			}
		}()
		defer func() { close(peerStop); conn.CloseNow(); <-peerExited }()
		for {
			_, packet, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			f.frames.Add(1)
			if len(packet) < 3 || int(packet[0])<<16|int(packet[1])<<8|int(packet[2]) != len(packet)-3 {
				t.Error("invalid native frame length")
				return
			}
			plain, err := fromClient.Open(nil, iv(received), packet[3:], nil)
			received++
			if err != nil {
				t.Error("native frame decryption", err)
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
			f.Nodes <- node
			answer := respond(r.Context(), node)
			if answer == nativeMCPWithheldResponse {
				continue
			}
			if answer == nil {
				return
			} // actual socket close drives the native disconnect waiter.
			if err := sendResponse(*answer); err != nil {
				return
			}
		}
	}))
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	fs := socket.NewFrameSocket(waLog.Noop, &http.Client{Transport: nativeMCPRoundTripper{base: transport, fixture: f}})
	fs.URL = "ws" + strings.TrimPrefix(server.URL, "http")
	fs.HTTPHeaders = http.Header{}
	fs.Header = nil
	ctx, cancel := context.WithCancel(context.Background())
	queue := make(chan *waBinary.Node, handlerQueueSize)
	handlerDone := make(chan struct{})
	if err := fs.Connect(ctx); err != nil {
		cancel()
		server.Close()
		t.Fatal(err)
	}
	ns, err := socket.NewNoiseHandshake().Finish(fs, func(ctx context.Context, data []byte) {
		cli.handleFrame(ctx, data, queue)
		plain, err := waBinary.Unpack(data)
		if err != nil {
			t.Error("observing handled native frame", err)
			return
		}
		node, err := waBinary.Unmarshal(plain)
		if err != nil {
			t.Error("observing handled native node", err)
			return
		}
		select {
		case f.Handled <- node:
		case <-ctx.Done():
		default:
			t.Error("native handled-node observation exceeded fixture budget")
		}
	}, func(ctx context.Context, ns *socket.NoiseSocket, remote bool) {
		defer disconnectOnce.Do(func() { close(disconnected) })
		cli.onDisconnect(ctx, ns, remote)
	})
	if err != nil {
		fs.Close(0)
		cancel()
		server.Close()
		t.Fatal(err)
	}
	cli.socket = ns
	f.noise = ns
	cli.handlerQueueWait = handlerDone
	go cli.handlerQueueLoop(ctx, fs.Context(), queue, handlerDone)
	t.Cleanup(func() {
		fs.Close(0)
		cancel()
		for name, ch := range map[string]<-chan struct{}{"server": serverDone, "native-disconnect": disconnected, "native-handler": handlerDone} {
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
				t.Errorf("owned %s worker did not exit", name)
			}
		}
		server.Close()
	})
	return f
}

// HoldWriter occupies actual Noise admission before encryption, then refuses its
// synthetic barrier frame. Release observes return of that actual queued method.
func (f *NativeMCPTestTransport) HoldWriter(t *testing.T) func() {
	t.Helper()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- f.noise.SendFrameWithGuard(context.Background(), []byte("synthetic barrier"), func(context.Context) error { close(entered); <-release; return socket.ErrFrameAuthority })
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("native barrier not admitted")
	}
	var once sync.Once
	finish := func() {
		once.Do(func() {
			close(release)
			select {
			case err := <-done:
				if err != socket.ErrFrameAuthority {
					t.Error("barrier emitted/failed", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("barrier worker did not exit")
			}
		})
	}
	t.Cleanup(finish)
	return finish
}

// WaitForIQWaiter observes SDK request admission while HoldWriter prevents any
// native writer callback or encryption. No operation state is used as a proxy.
func (f *NativeMCPTestTransport) WaitForIQWaiter(t *testing.T) {
	f.WaitForResponseWaiter(t, "")
}

// HasResponseWaiter observes the actual SDK map under its original lock.
func (f *NativeMCPTestTransport) HasResponseWaiter(id string) bool {
	f.Client.responseWaitersLock.Lock()
	defer f.Client.responseWaitersLock.Unlock()
	_, present := f.Client.responseWaiters[id]
	return present
}

// ResponseWaiterIDs observes owned original SDK admission, without registering a
// waiter or supplying a writer capability. Only the synthetic native tag builds it.
func (f *NativeMCPTestTransport) ResponseWaiterIDs() []string {
	f.Client.responseWaitersLock.Lock()
	defer f.Client.responseWaitersLock.Unlock()
	ids := make([]string, 0, len(f.Client.responseWaiters))
	for id := range f.Client.responseWaiters {
		ids = append(ids, id)
	}
	return ids
}

// ObserveNextPeerResponseWrite reports the actual owned peer websocket Write,
// including an expected failure after original socket cancellation. It neither
// injects a SDK result nor changes frame/writer authority. Arm only while the
// synthetic response callback is held; the caller must observe its terminal result.
func (f *NativeMCPTestTransport) ObserveNextPeerResponseWrite(t *testing.T) <-chan error {
	t.Helper()
	f.responseWriteMu.Lock()
	defer f.responseWriteMu.Unlock()
	if f.responseWriteObserver != nil {
		t.Fatal("peer response write observer already armed")
	}
	f.responseWriteObserver = make(chan error, 1)
	return f.responseWriteObserver
}

// WaitForResponseWaiter observes the exact original SDK message/IQ waiter while
// a held physical gate prevents its completion. Stored operation state alone is
// never used as proof that the SDK admitted the original request.
func (f *NativeMCPTestTransport) WaitForResponseWaiter(t *testing.T, id string) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		f.Client.responseWaitersLock.Lock()
		admitted := len(f.Client.responseWaiters) > 0
		if id != "" {
			_, admitted = f.Client.responseWaiters[id]
		}
		f.Client.responseWaitersLock.Unlock()
		if admitted {
			return
		}
		select {
		case <-timer.C:
			t.Fatal("native response waiter admission not observed")
		case <-ticker.C:
		}
	}
}

// NativeMCPPhysicalWrite is a test-only gate inside the upgraded connection's
// actual body.Write. Close observes cancellation but cannot release the gate.
type NativeMCPPhysicalWrite struct {
	Entered, Closed, Exited chan struct{}
	release                 chan struct{}
	once                    sync.Once
	closeOnce               sync.Once
	afterWrite              bool
}

func (g *NativeMCPPhysicalWrite) Release() { g.once.Do(func() { close(g.release) }) }

type nativeMCPWriteBody struct {
	io.ReadWriteCloser
	mu     sync.Mutex
	gate   *NativeMCPPhysicalWrite
	writes atomic.Int32
}

func (b *nativeMCPWriteBody) Write(data []byte) (int, error) {
	b.writes.Add(1)
	b.mu.Lock()
	g := b.gate
	b.mu.Unlock()
	if g == nil {
		return b.ReadWriteCloser.Write(data)
	}
	defer close(g.Exited)
	if g.afterWrite {
		n, err := b.ReadWriteCloser.Write(data)
		close(g.Entered)
		<-g.release
		return n, err
	}
	close(g.Entered)
	<-g.release
	return b.ReadWriteCloser.Write(data)
}
func (b *nativeMCPWriteBody) Close() error {
	b.mu.Lock()
	g := b.gate
	b.mu.Unlock()
	err := b.ReadWriteCloser.Close()
	if g != nil {
		// Observe completed physical Close. Signalling before Close returns lets
		// a held Write race a still-open body when the test releases its gate.
		g.closeOnce.Do(func() { close(g.Closed) })
	}
	return err
}

type nativeMCPRoundTripper struct {
	base    http.RoundTripper
	fixture *NativeMCPTestTransport
}

func (r nativeMCPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := r.base.RoundTrip(req)
	if err == nil && response.StatusCode == http.StatusSwitchingProtocols {
		body, ok := response.Body.(io.ReadWriteCloser)
		if !ok {
			response.Body.Close()
			return nil, io.ErrUnexpectedEOF
		}
		wrapped := &nativeMCPWriteBody{ReadWriteCloser: body}
		r.fixture.body = wrapped
		response.Body = wrapped
	}
	return response, err
}
func (f *NativeMCPTestTransport) ArmPhysicalWrite(t *testing.T) *NativeMCPPhysicalWrite {
	t.Helper()
	return f.armPhysicalWrite(t, false)
}

// ArmPhysicalWriteAfterEmission holds return after actual underlying Write.
// The caller must separately observe a complete decrypted packet at the peer.
func (f *NativeMCPTestTransport) ArmPhysicalWriteAfterEmission(t *testing.T) *NativeMCPPhysicalWrite {
	t.Helper()
	return f.armPhysicalWrite(t, true)
}
func (f *NativeMCPTestTransport) armPhysicalWrite(t *testing.T, afterWrite bool) *NativeMCPPhysicalWrite {
	t.Helper()
	g := &NativeMCPPhysicalWrite{Entered: make(chan struct{}), Closed: make(chan struct{}), Exited: make(chan struct{}), release: make(chan struct{}), afterWrite: afterWrite}
	f.body.mu.Lock()
	if f.body.gate != nil {
		f.body.mu.Unlock()
		t.Fatal("physical gate already armed")
	}
	f.body.gate = g
	f.body.mu.Unlock()
	t.Cleanup(g.Release)
	return g
}
func (f *NativeMCPTestTransport) PhysicalWrites() int32 { return f.body.writes.Load() }

// InitGroupSignal provisions two independent owned SQLite SDK stores. The only
// cached participant device is the sender's current device; production SDK
// excludes it from pairwise distribution. Receiver state is provisioned here,
// never copied from the sender's post-encryption record.
func (f *NativeMCPTestTransport) InitGroupSignal(t *testing.T, target types.JID) func(context.Context, *waBinary.Node) (*waE2E.Message, error) {
	t.Helper()
	ctx := context.Background()
	owner := types.NewJID("447700900999", types.DefaultUserServer)
	owner.Device = 1
	sender := nativeMCPSignalDevice(t, filepath.Join(t.TempDir(), "sender.db"), owner)
	receiver := nativeMCPSignalDevice(t, filepath.Join(t.TempDir(), "receiver.db"), types.NewJID("447700900998", types.DefaultUserServer))
	f.Client.Store = sender
	f.Client.groupCache[target] = &groupMetaCache{Members: []types.JID{owner.ToNonAD()}}
	f.Client.userDevicesCache[owner.ToNonAD()] = deviceCache{devices: []types.JID{owner}}
	key := protocol.NewSenderKeyName(target.String(), sender.LID.SignalAddress())
	senderBuilder := groups.NewGroupSessionBuilder(sender, pbSerializer)
	distribution, err := senderBuilder.Create(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	peerDistribution, err := protocol.NewSenderKeyDistributionMessageFromBytes(distribution.Serialize(), pbSerializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatal(err)
	}
	receiverBuilder := groups.NewGroupSessionBuilder(receiver, pbSerializer)
	if err := receiverBuilder.Process(ctx, key, peerDistribution); err != nil {
		t.Fatal(err)
	}
	cipher := groups.NewGroupCipher(receiverBuilder, key, receiver)
	return func(ctx context.Context, node *waBinary.Node) (*waE2E.Message, error) {
		if node.Tag != "message" || node.Attrs["to"] != target {
			return nil, fmt.Errorf("unexpected group message envelope")
		}
		var encrypted []byte
		for _, child := range node.GetChildren() {
			if child.Tag == "enc" && child.Attrs["type"] == "skmsg" {
				encrypted, _ = child.Content.([]byte)
			}
		}
		if len(encrypted) == 0 {
			return nil, fmt.Errorf("missing Signal sender-key ciphertext")
		}
		msg, err := protocol.NewSenderKeyMessageFromBytes(encrypted, pbSerializer.SenderKeyMessage)
		if err != nil {
			return nil, err
		}
		plain, err := cipher.Decrypt(ctx, msg)
		if err != nil {
			return nil, err
		}
		plain, err = unpadMessage(plain, 2)
		if err != nil {
			return nil, err
		}
		result := &waE2E.Message{}
		if err := proto.Unmarshal(plain, result); err != nil {
			return nil, err
		}
		return result, nil
	}
}

func nativeMCPSignalDevice(t *testing.T, path string, id types.JID) *store.Device {
	t.Helper()
	ctx := context.Background()
	uri := (&url.URL{Scheme: "file", Path: path}).String() + "?_foreign_keys=on"
	container, err := sqlstore.New(ctx, "sqlite3", uri, waLog.Noop)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { container.Close() })
	device := container.NewDevice()
	device.ID = &id
	device.LID = types.NewJID(id.User, types.HiddenUserServer)
	// Fixed-size synthetic certificate fields satisfy local storage only;
	// no WhatsApp certificate authentication is claimed by this fixture.
	device.Account = &waAdv.ADVSignedDeviceIdentity{Details: []byte{}, AccountSignature: make([]byte, 64), AccountSignatureKey: make([]byte, 32), DeviceSignature: make([]byte, 64)}
	if err := device.Save(ctx); err != nil {
		t.Fatal(err)
	}
	return device
}

// InitDirectSignal provisions real independent pairwise session/prekeys on owned
// SQLite devices. Sender database shares the app's synthetic directory so exact
// local PN/LID lookup uses the same production read-only database boundary.
func (f *NativeMCPTestTransport) InitDirectSignal(t *testing.T, dir string, pn, lid types.JID) func(context.Context, *waBinary.Node) (*waE2E.Message, error) {
	t.Helper()
	ctx := context.Background()
	owner := types.NewJID("447700900999", types.DefaultUserServer)
	owner.Device = 1
	sender := nativeMCPSignalDevice(t, filepath.Join(dir, "whatsapp.db"), owner)
	receiverID := pn
	receiverID.Device = 1
	receiver := nativeMCPSignalDevice(t, filepath.Join(t.TempDir(), "receiver.db"), receiverID)
	receiver.LID = lid
	if err := receiver.Save(ctx); err != nil {
		t.Fatal(err)
	}
	f.Client.Store = sender
	if err := sender.LIDs.PutLIDMapping(ctx, lid, pn); err != nil {
		t.Fatal(err)
	}
	if err := sender.LIDs.PutLIDMapping(ctx, sender.LID, owner.ToNonAD()); err != nil {
		t.Fatal(err)
	}
	receiverDevice := lid
	receiverDevice.Device = 1
	f.Client.userDevicesCache[lid] = deviceCache{devices: []types.JID{receiverDevice}}
	f.Client.userDevicesCache[sender.LID] = deviceCache{devices: []types.JID{sender.GetLID()}}
	key, err := receiver.PreKeys.GenOnePreKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bundle := prekey.NewBundle(receiver.RegistrationID, 1, optional.NewOptionalUint32(key.KeyID), receiver.SignedPreKey.KeyID, ecc.NewDjbECPublicKey(*key.Pub), ecc.NewDjbECPublicKey(*receiver.SignedPreKey.Pub), *receiver.SignedPreKey.Signature, identity.NewKey(ecc.NewDjbECPublicKey(*receiver.IdentityKey.Pub)))
	builder := session.NewBuilderFromSignal(sender, receiverDevice.SignalAddress(), pbSerializer)
	if err := builder.ProcessBundle(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	// Current cached privacy evidence suppresses unrelated async token issuance.
	if err := sender.PrivacyTokens.PutPrivacyTokens(ctx, store.PrivacyToken{User: lid, Token: []byte("synthetic-token"), Timestamp: time.Now(), SenderTimestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	f.Client.lastTCTokenDBPrune = time.Now()
	peerBuilder := session.NewBuilderFromSignal(receiver, sender.GetLID().SignalAddress(), pbSerializer)
	cipher := session.NewCipher(peerBuilder, sender.GetLID().SignalAddress())
	return func(ctx context.Context, node *waBinary.Node) (*waE2E.Message, error) {
		if node.Tag != "message" || node.Attrs["to"] != lid {
			return nil, fmt.Errorf("unexpected direct message envelope")
		}
		participantNode := node.GetChildByTag("participants")
		participants := participantNode.GetChildren()
		if len(participants) != 1 || participants[0].Tag != "to" || participants[0].Attrs["jid"] != receiverDevice {
			return nil, fmt.Errorf("unexpected direct recipient device")
		}
		child := participants[0].GetChildByTag("enc")
		data, ok := child.Content.([]byte)
		if !ok {
			return nil, fmt.Errorf("missing pairwise ciphertext")
		}
		var plain []byte
		var err error
		switch child.Attrs["type"] {
		case "pkmsg":
			msg, e := protocol.NewPreKeySignalMessageFromBytes(data, pbSerializer.PreKeySignalMessage, pbSerializer.SignalMessage)
			if e != nil {
				return nil, e
			}
			plain, err = cipher.DecryptMessage(ctx, msg)
		case "msg":
			msg, e := protocol.NewSignalMessageFromBytes(data, pbSerializer.SignalMessage)
			if e != nil {
				return nil, e
			}
			plain, err = cipher.Decrypt(ctx, msg)
		default:
			return nil, fmt.Errorf("unexpected pairwise cipher type")
		}
		if err != nil {
			return nil, err
		}
		plain, err = unpadMessage(plain, 2)
		if err != nil {
			return nil, err
		}
		result := &waE2E.Message{}
		if err := proto.Unmarshal(plain, result); err != nil {
			return nil, err
		}
		return result, nil
	}
}

// RedirectDirectAlias mutates only fixture-owned SDK routing. The app's original
// approved recipient fingerprint stays unchanged.
func (f *NativeMCPTestTransport) RedirectDirectAlias(t *testing.T, pn, lid, foreign types.JID) {
	t.Helper()
	if err := f.Client.Store.LIDs.PutLIDMapping(context.Background(), foreign, pn); err != nil {
		t.Fatal(err)
	}
	f.Client.userDevicesCache[foreign] = f.Client.userDevicesCache[lid]
}
func (f *NativeMCPTestTransport) RemoveDirectAlias(t *testing.T, dir string, lid types.JID) {
	t.Helper()
	uri := (&url.URL{Scheme: "file", Path: filepath.Join(dir, "whatsapp.db")}).String()
	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	changed, err := db.Exec("DELETE FROM whatsmeow_lid_map WHERE lid=?", lid.User)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := changed.RowsAffected()
	if err != nil || rows != 1 {
		t.Fatal("owned original alias not removed", rows, err)
	}
}

// NativeMCPTestWithholdResponse keeps the original socket alive and emits no
// packet. Pointer identity is consumed only by this owned test server.
var nativeMCPWithheldResponse = &waBinary.Node{}

func NativeMCPTestWithholdResponse() *waBinary.Node { return nativeMCPWithheldResponse }

// DeliverIncoming sends only from the owned encrypted synthetic peer. It creates
// no client frame, waiter or SDK request and observes the actual websocket Write.
func (f *NativeMCPTestTransport) DeliverIncoming(t *testing.T, node waBinary.Node) {
	t.Helper()
	result := make(chan error, 1)
	select {
	case f.peerIncoming <- nativeMCPIncoming{node: node, result: result}:
	case <-time.After(5 * time.Second):
		t.Fatal("owned peer delivery admission timed out")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("owned peer write failed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned peer write did not return")
	}
}

// ClosePeer closes the actual owned server websocket, exercising the native
// disconnect callback rather than the intentional Client.Disconnect path.
func (f *NativeMCPTestTransport) ClosePeer(t *testing.T) {
	t.Helper()
	result := make(chan error, 1)
	select {
	case f.peerIncoming <- nativeMCPIncoming{result: result, closePeer: true}:
	case <-time.After(5 * time.Second):
		t.Fatal("owned peer close admission timed out")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned peer close did not return")
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.Client.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("native peer disconnect did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}

// HoldSocketIdentityLock exercises actual SDK connection/disconnect lock contention.
// It changes no identity/socket and is available only in synthetic test builds.
func (f *NativeMCPTestTransport) HoldSocketIdentityLock(t *testing.T) func() {
	t.Helper()
	f.Client.socketLock.Lock()
	var once sync.Once
	release := func() { once.Do(f.Client.socketLock.Unlock) }
	t.Cleanup(release)
	return release
}
