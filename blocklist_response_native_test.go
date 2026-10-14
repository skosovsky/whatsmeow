//go:build wa_mcp_native_test

package whatsmeow

import (
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
)

func TestNativeBlockResponseSocketReplacementRevokesDerivedResult(t *testing.T) {
	// Arrange: two actual connected encrypted synthetic sockets, with identical
	// actor identity. The envelope alone provides no original application intent.
	original := NewNativeMCPTestTransport(t, nil)
	replacement := NewNativeMCPTestTransport(t, nil)
	request := BlockActionGuardedRequest{
		ActorPN:  original.Client.Store.ID.ToNonAD(),
		PhoneJID: types.NewJID("456", types.DefaultUserServer),
		LIDJID:   types.NewJID("777", types.HiddenUserServer),
		Action:   "block",
	}
	responses := make(chan *BlockActionResponse, 1)
	original.Client.AddEventHandler(func(event any) {
		if response, ok := event.(*BlockActionResponse); ok {
			responses <- response
		}
	})
	const id = "original-synthetic-IQ"
	original.DeliverIncoming(t, *blocklistResult(id, blocklistItem(request.LIDJID)))
	var response *BlockActionResponse
	select {
	case response = <-responses:
	case <-time.After(5 * time.Second):
		t.Fatal("authenticated response missing")
	}
	derived, err := response.Result(original.Client, id, request)
	if err != nil {
		t.Fatal("positive response control", err)
	}
	if blocked, err := derived.Result(original.Client, id, request); err != nil || !blocked {
		t.Fatal("positive derived result control", err)
	}
	// Act: replace the current socket under the actual SDK identity lock, without
	// disconnecting the original. Restore before fixture cleanup or any network IO.
	original.Client.socketLock.Lock()
	original.Client.socket = replacement.noise
	original.Client.socketLock.Unlock()
	defer func() {
		original.Client.socketLock.Lock()
		original.Client.socket = original.noise
		original.Client.socketLock.Unlock()
	}()
	// Assert: both original and replacement remain connected, yet neither retained
	// envelope nor already derived opaque result survives current socket replacement.
	if !original.noise.IsConnected() || !replacement.noise.IsConnected() {
		t.Fatal("replacement test accidentally disconnected a socket")
	}
	if got, err := response.Result(original.Client, id, request); err == nil || got != nil {
		t.Fatal("old socket envelope accepted")
	}
	if blocked, err := derived.Result(original.Client, id, request); err == nil || blocked {
		t.Fatal("derived result lost original socket binding")
	}
}
