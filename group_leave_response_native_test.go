//go:build wa_mcp_native_test

package whatsmeow

import (
	"context"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

func TestNativeGroupLeaveProofCurrentSocketReplacement(t *testing.T) {
	// Arrange: two real connected owned encrypted sockets; original guarded SET on first.
	first := NewNativeMCPTestTransport(t, func(_ context.Context, n *waBinary.Node) *waBinary.Node {
		return &waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": n.Attrs["id"], "type": "result", "from": types.GroupServerJID}}
	})
	second := NewNativeMCPTestTransport(t, func(context.Context, *waBinary.Node) *waBinary.Node {
		t.Error("replacement socket emitted")
		return nil
	})
	own := first.Client.Store.ID.ToNonAD()
	r := GroupLeaveGuardedRequest{ActorPN: own, ActorJID: own, GroupJID: types.NewJID("123", types.GroupServer)}
	id := ""
	result, err := first.Client.LeaveGroupGuarded(context.Background(), r, func(ctx context.Context) error { return ctx.Err() }, func(ctx context.Context) error {
		var ok bool
		id, ok = OriginalGroupLeaveRequestID(ctx)
		if !ok {
			t.Error("missing original callback proof")
		}
		return ctx.Err()
	})
	if err != nil || result.Verify(first.Client, id, r) != nil {
		t.Fatal("original proof", err)
	}
	// Act: replace the current socket under actual SDK socket identity lock.
	first.Client.socketLock.Lock()
	original := first.Client.socket
	first.Client.socket = second.noise
	first.Client.socketLock.Unlock()
	refused := result.Verify(first.Client, id, r)
	first.Client.socketLock.Lock()
	first.Client.socket = original
	first.Client.socketLock.Unlock()
	// Assert: connected foreign socket cannot validate original result; restore original permits it.
	if refused == nil || result.Verify(first.Client, id, r) != nil || first.Frames() != 1 || second.Frames() != 0 {
		t.Fatal("socket replacement receipt binding")
	}
	// Identity lock contention itself cannot assert current connection identity.
	release := first.HoldSocketIdentityLock(t)
	if result.Verify(first.Client, id, r) == nil {
		release()
		t.Fatal("contended socket identity accepted")
	}
	release()
	if result.Verify(first.Client, id, r) != nil {
		t.Fatal("original socket after contention refused")
	}
}

func TestNativeLateGroupLeaveResponseSocketAndDeviceBinding(t *testing.T) {
	// Arrange: original authenticated unmatched response; envelope alone is not
	// original application intent. Two actual connected Noise sockets are used.
	first := NewNativeMCPTestTransport(t, nil)
	second := NewNativeMCPTestTransport(t, nil)
	own := first.Client.Store.ID.ToNonAD()
	request := GroupLeaveGuardedRequest{ActorPN: own, ActorJID: own, GroupJID: types.NewJID("123", types.GroupServer)}
	responses := make(chan *GroupLeaveResponse, 1)
	first.Client.AddEventHandler(func(event any) {
		if r, ok := event.(*GroupLeaveResponse); ok {
			responses <- r
		}
	})
	const id = "original-late-leave-IQ"
	first.DeliverIncoming(t, waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": id, "type": "result", "from": types.GroupServerJID}})
	var response *GroupLeaveResponse
	select {
	case response = <-responses:
	case <-time.After(5 * time.Second):
		t.Fatal("authenticated leave response missing")
	}
	result, err := response.Result(first.Client, id, request)
	if err != nil || result.Verify(first.Client, id, request) != nil {
		t.Fatal("positive late response", err)
	}
	// Act / Assert: same-account foreign socket invalidates both retained layers.
	first.Client.socketLock.Lock()
	original := first.Client.socket
	first.Client.socket = second.noise
	first.Client.socketLock.Unlock()
	refused := result.Verify(first.Client, id, request)
	_, responseErr := response.Result(first.Client, id, request)
	first.Client.socketLock.Lock()
	first.Client.socket = original
	first.Client.socketLock.Unlock()
	if refused == nil || responseErr == nil || !first.noise.IsConnected() || !second.noise.IsConnected() {
		t.Fatal("socket-bound late proof accepted foreign socket")
	}
	release := first.HoldSocketIdentityLock(t)
	if result.Verify(first.Client, id, request) == nil {
		release()
		t.Fatal("contended socket identity accepted")
	}
	release()
	device := first.Client.Store
	for _, mode := range []string{"full-ad-id", "lid", "device"} {
		originalID, originalLID := device.ID, device.LID
		switch mode {
		case "full-ad-id":
			changed := *device.ID
			changed.Device++
			device.ID = &changed
		case "lid":
			device.LID = types.NewJID("999", types.HiddenUserServer)
		case "device":
			copy := *device
			first.Client.Store = &copy
		}
		refused := result.Verify(first.Client, id, request)
		_, responseErr := response.Result(first.Client, id, request)
		first.Client.Store = device
		device.ID = originalID
		device.LID = originalLID
		if refused == nil || responseErr == nil || result.Verify(first.Client, id, request) != nil {
			t.Fatal("late response lost captured device binding", mode)
		}
	}
	if first.Frames() != 0 || second.Frames() != 0 {
		t.Fatal("read-only envelope emitted frames")
	}
}

func TestNativeLateGroupLeaveOriginalCaptureWithoutWaiter(t *testing.T) {
	// Arrange: retain the actual registered SDK attempt of one emitted encrypted
	// SET. Reinsert that same pointer after timeout solely to model the real
	// interval between waiter removal and registered-attempt defer cleanup.
	attempts := make(chan *groupLeaveSDKAttempt, 1)
	ids := make(chan string, 1)
	var fixture *NativeMCPTestTransport
	fixture = NewNativeMCPTestTransport(t, func(_ context.Context, node *waBinary.Node) *waBinary.Node {
		id := node.Attrs["id"].(string)
		actual, ok := fixture.Client.groupLeaveAttempts.Load(id)
		if !ok {
			t.Error("original SDK registration missing")
			return NativeMCPTestWithholdResponse()
		}
		attempts <- actual.(*groupLeaveSDKAttempt)
		ids <- id
		return NativeMCPTestWithholdResponse()
	})
	own := fixture.Client.Store.ID.ToNonAD()
	request := GroupLeaveGuardedRequest{ActorPN: own, ActorJID: own, GroupJID: types.NewJID("123", types.GroupServer)}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	result, err := fixture.Client.LeaveGroupGuarded(ctx, request, func(ctx context.Context) error { return ctx.Err() }, func(ctx context.Context) error { return ctx.Err() })
	if err == nil || result != nil || len(fixture.ResponseWaiterIDs()) != 0 {
		t.Fatal("original waiter not removed", err)
	}
	original, id := <-attempts, <-ids
	if !original.passed.Load() || original.ack.Load() || fixture.Frames() != 1 {
		t.Fatal("retained registration was not original emitted attempt")
	}
	fixture.Client.groupLeaveAttempts.Store(id, original)
	defer fixture.Client.groupLeaveAttempts.CompareAndDelete(id, original)
	responses := make(chan *GroupLeaveResponse, 1)
	fixture.Client.AddEventHandler(func(event any) {
		if r, ok := event.(*GroupLeaveResponse); ok {
			responses <- r
		}
	})
	// Act: actual authenticated frame first reaches original capture, then finds
	// no waiter. Its one-use private frame origin must still reach the envelope.
	fixture.DeliverIncoming(t, waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": id, "type": "result", "from": types.GroupServerJID}})
	var response *GroupLeaveResponse
	select {
	case response = <-responses:
	case <-time.After(5 * time.Second):
		t.Fatal("original captured origin lost during waiter removal")
	}
	// Assert: original capture and derived late result both retain authentic origin.
	derived, err := response.Result(fixture.Client, id, request)
	if err != nil || derived.Verify(fixture.Client, id, request) != nil || !original.ack.Load() || fixture.Frames() != 1 {
		t.Fatal("waiter removal changed original proof", err)
	}
}
