package whatsmeow

import (
	"context"
	"strings"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

func TestGroupLeaveRequestClosedSemanticBinding(t *testing.T) {
	// Arrange: canonical paired actor, exact own participant and group.
	valid := GroupLeaveGuardedRequest{ActorPN: types.NewJID("123", types.DefaultUserServer), ActorLID: types.NewJID("789", types.HiddenUserServer), ActorJID: types.NewJID("123", types.DefaultUserServer), GroupJID: types.NewJID("456", types.GroupServer)}
	for _, actor := range []types.JID{valid.ActorPN, valid.ActorLID} {
		r := valid
		r.ActorJID = actor
		if !validGroupLeaveRequest(r) {
			t.Fatal("own actor refused")
		}
	}
	for _, change := range []func(*GroupLeaveGuardedRequest){
		func(r *GroupLeaveGuardedRequest) { r.ActorPN.Device = 1 },
		func(r *GroupLeaveGuardedRequest) { r.ActorPN.Integrator = 1 },
		func(r *GroupLeaveGuardedRequest) { r.ActorLID.Integrator = 1 },
		func(r *GroupLeaveGuardedRequest) { r.GroupJID.Integrator = 1 },
		func(r *GroupLeaveGuardedRequest) { r.ActorPN.User = "0" },
		func(r *GroupLeaveGuardedRequest) { r.ActorJID = types.NewJID("999", types.HiddenUserServer) },
		func(r *GroupLeaveGuardedRequest) { r.ActorLID.Device = 1 },
		func(r *GroupLeaveGuardedRequest) { r.ActorLID.Server = types.DefaultUserServer },
		func(r *GroupLeaveGuardedRequest) { r.GroupJID.Server = types.DefaultUserServer },
		func(r *GroupLeaveGuardedRequest) { r.GroupJID.Device = 1 },
		func(r *GroupLeaveGuardedRequest) { r.GroupJID.User = "" },
		func(r *GroupLeaveGuardedRequest) { r.GroupJID.User = "1-2-3" },
		func(r *GroupLeaveGuardedRequest) { r.GroupJID.User = "1-" },
		func(r *GroupLeaveGuardedRequest) { r.GroupJID.User = "1a" },
	} {
		// Act / Assert: schema-like shapes never replace own actor semantics.
		r := valid
		change(&r)
		if validGroupLeaveRequest(r) {
			t.Fatal("foreign/malformed request accepted")
		}
	}
	if _, ok := OriginalGroupLeaveRequestID(nil); ok {
		t.Fatal("nil correlation")
	}
	if _, ok := OriginalGroupLeaveRequestID(context.Background()); ok {
		t.Fatal("ordinary context correlation")
	}
	if (&GroupLeaveGuardedResult{}).Verify(&Client{}, "id", valid) == nil {
		t.Fatal("zero evidence accepted")
	}
}
func TestGroupLeaveACKExactClosedEnvelope(t *testing.T) {
	for _, mode := range []string{"valid", "empty", "id", "missing-id", "type", "from", "string-from", "tag", "extra", "content", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			// Arrange: exact correlated result from group service.
			n := &waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": "original", "from": types.GroupServerJID, "type": "result"}}
			switch mode {
			case "empty":
				n.Content = []waBinary.Node{}
			case "id":
				n.Attrs["id"] = "foreign"
			case "missing-id":
				delete(n.Attrs, "id")
			case "type":
				n.Attrs["type"] = "error"
			case "from":
				n.Attrs["from"] = types.ServerJID
			case "string-from":
				n.Attrs["from"] = "g.us"
			case "tag":
				n.Tag = "ack"
			case "extra":
				n.Attrs["canary"] = "private"
			case "content":
				n.Content = []waBinary.Node{{Tag: "group"}}
			case "bytes":
				n.Content = []byte{}
			}
			// Act / Assert: malformed whole response is refused.
			if strictGroupLeaveACK(n, "original") != (mode == "valid" || mode == "empty") {
				t.Fatal("ACK shape mismatch")
			}
		})
	}
	for _, id := range []string{strings.Repeat("a", 129), "привет", "with space"} {
		n := &waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": id, "type": "result", "from": types.GroupServerJID}}
		if strictGroupLeaveACK(n, id) {
			t.Fatal("unbounded or noncanonical correlation")
		}
	}
	if strictGroupLeaveACK(nil, "id") || strictGroupLeaveACK(&waBinary.Node{}, "") {
		t.Fatal("zero ACK")
	}
}
