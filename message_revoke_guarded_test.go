// Copyright (c) 2026 Sergey Kosovsky
// SPDX-License-Identifier: MPL-2.0

package whatsmeow

import (
	"context"
	"encoding/json"
	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
	"strings"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

func TestMessageRevokeSDKClosedRequest(t *testing.T) {
	// Arrange: canonical own direct request with exact Unicode target bytes.
	r := MessageRevokeGuardedRequest{ActorPN: types.NewJID("123", types.DefaultUserServer), ActorLID: types.NewJID("789", types.HiddenUserServer), ChatJID: types.NewJID("456", types.DefaultUserServer), TargetSender: types.NewJID("123", types.DefaultUserServer), TargetFromMe: true, TargetID: "сообщение-é", TransportID: "ORIGINAL_ATTEMPT"}
	if !validMessageRevokeRequest(r) {
		t.Fatal("canonical request refused")
	}
	for _, change := range []func(*MessageRevokeGuardedRequest){
		func(r *MessageRevokeGuardedRequest) { r.ActorPN.Device = 1 }, func(r *MessageRevokeGuardedRequest) { r.ActorLID.Integrator = 1 },
		func(r *MessageRevokeGuardedRequest) { r.ChatJID.Device = 1 }, func(r *MessageRevokeGuardedRequest) { r.TargetSender.Device = 1 },
		func(r *MessageRevokeGuardedRequest) { r.TargetFromMe = false }, func(r *MessageRevokeGuardedRequest) { r.TargetSender = types.NewJID("999", types.DefaultUserServer) },
		func(r *MessageRevokeGuardedRequest) { r.TargetID = string([]byte{255}) }, func(r *MessageRevokeGuardedRequest) { r.TargetID = strings.Repeat("я", 129) },
		func(r *MessageRevokeGuardedRequest) { r.TargetID = "a\x00b" }, func(r *MessageRevokeGuardedRequest) { r.TargetID = "" },
		func(r *MessageRevokeGuardedRequest) { r.TransportID = "свой" }, func(r *MessageRevokeGuardedRequest) { r.TransportID = "with space" },
		func(r *MessageRevokeGuardedRequest) {
			r.TargetID = r.TransportID
		},
	} {
		// Act / Assert: shaped data cannot substitute sender/account/target proof.
		bad := r
		change(&bad)
		if validMessageRevokeRequest(bad) {
			t.Fatal("invalid request accepted")
		}
	}
	for _, raw := range []string{`{}`, `{"client":{},"attempt":{"ack":true,"passed":true}}`} {
		// Act / Assert: imported result JSON and zero pointer establish no origin.
		var proof MessageRevokeGuardedResult
		if json.Unmarshal([]byte(raw), &proof) != nil || proof.Verify(&Client{}, r) == nil {
			t.Fatal("fabricated proof")
		}
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, ok := OriginalMessageRevokeRequest(ctx); ok {
			t.Fatal("ordinary original correlation")
		}
		if _, ok := OriginalMessageRevokeNonce(ctx); ok {
			t.Fatal("ordinary original nonce")
		}
	}
	if _, err := (*Client)(nil).RevokeMessageGuarded(context.Background(), r, nil); err == nil {
		t.Fatal("nil SDK accepted")
	}
}

func TestMessageRevokeSDKStrictACK(t *testing.T) {
	wire := types.NewJID("456", types.GroupServer)
	for _, mode := range []string{"valid", "empty", "phash", "bad-phash", "foreign-id", "class", "from", "string-from", "tag", "extra", "missing", "bad-time", "zero-time", "leading-zero", "content"} {
		t.Run(mode, func(t *testing.T) {
			// Arrange: closed correlated message ACK from exact original destination.
			n := &waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"id": "ORIGINAL", "class": "message", "from": wire, "t": "1780000000"}}
			switch mode {
			case "phash":
				n.Attrs["phash"] = "2:synthetic"
			case "bad-phash":
				n.Attrs["phash"] = strings.Repeat("a", 257)
			case "empty":
				n.Content = []waBinary.Node{}
			case "foreign-id":
				n.Attrs["id"] = "FOREIGN"
			case "class":
				n.Attrs["class"] = "receipt"
			case "from":
				n.Attrs["from"] = types.ServerJID
			case "string-from":
				n.Attrs["from"] = wire.String()
			case "tag":
				n.Tag = "iq"
			case "extra":
				n.Attrs["error"] = "0"
			case "missing":
				delete(n.Attrs, "t")
			case "bad-time":
				n.Attrs["t"] = "oops"
			case "zero-time":
				n.Attrs["t"] = "0"
			case "leading-zero":
				n.Attrs["t"] = "01780000000"
			case "content":
				n.Content = []byte{}
			}
			// Act / Assert: ACK envelope is closed; its shape alone still is not origin.
			if strictMessageRevokeACK(n, "ORIGINAL", wire) != (mode == "valid" || mode == "empty" || mode == "phash") {
				t.Fatal("ACK shape mismatch")
			}
		})
	}
}

func TestMessageRevokeSDKAdmissionDenyWithoutAttempt(t *testing.T) {
	for _, mode := range []string{"nil-context", "missing-deadline", "long-deadline", "expired", "cancelled", "nil-writer", "capacity", "actor"} {
		t.Run(mode, func(t *testing.T) {
			// Arrange: canonical device without a socket; no case may reach transport.
			owner := types.NewJID("123", types.DefaultUserServer)
			cli := NewClient(&store.Device{ID: &owner}, waLog.Noop)
			r := MessageRevokeGuardedRequest{ActorPN: owner, ChatJID: types.NewJID("456", types.DefaultUserServer), TargetSender: owner, TargetFromMe: true, TargetID: "точный-id", TransportID: "ATTEMPT"}
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			writer := func(context.Context) error { t.Fatal("denied admission called writer"); return nil }
			switch mode {
			case "nil-context":
				ctx = nil
			case "missing-deadline":
				ctx = context.Background()
			case "long-deadline":
				long, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				ctx = long
			case "expired":
				short, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				ctx = short
			case "cancelled":
				stop()
			case "nil-writer":
				writer = nil
			case "capacity":
				cli.messageRevokeAdmission.Store(64)
			case "actor":
				r.ActorPN = types.NewJID("999", types.DefaultUserServer)
				r.TargetSender = r.ActorPN
			}
			// Act.
			proof, err := cli.RevokeMessageGuarded(ctx, r, writer)
			// Assert: no leaked admission slot/attempt on any early refusal.
			if err == nil || proof != nil {
				t.Fatal("invalid admission passed")
			}
			count := int32(0)
			cli.messageRevokeAttempts.Range(func(any, any) bool { count++; return true })
			want := int32(0)
			if mode == "capacity" {
				want = 64
			}
			if count != 0 || cli.messageRevokeAdmission.Load() != want {
				t.Fatal("attempt/admission leaked")
			}
		})
	}
}
