package whatsmeow

import (
	"context"
	"errors"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/types"
)

func TestGuardedSendRejectsNonNoiseTransport(t *testing.T) {
	// Arrange: the PR #1226 seam can send plain frames but cannot prove Noise authority.
	transport := newOutboundTestSocket(1)
	cli := newOutboundTestClient(t, transport)
	calls := 0
	ctx := withFrameAuthority(context.Background(), "message", "guarded", func(context.Context) error {
		calls++
		return nil
	})
	node := waBinary.Node{Tag: "message", Attrs: waBinary.Attrs{"id": "guarded", "to": types.NewJID("123", types.DefaultUserServer)}}
	// Act.
	_, err := cli.sendNodeAndGetData(ctx, node)
	// Assert: even an allowing callback cannot substitute for the original Noise boundary.
	if !errors.Is(err, socket.ErrFrameAuthority) || calls != 0 || len(transport.frames) != 0 {
		t.Fatalf("guard bypass: err=%v callbacks=%d frames=%d", err, calls, len(transport.frames))
	}
}

func TestUnmatchedMutationRejectsNonNoiseTransport(t *testing.T) {
	// Arrange: a response from the PR #1226 seam has no authenticated Noise proof.
	cli := newOutboundTestClient(t, newOutboundTestSocket(1))
	// Act.
	accepted := cli.handleUnmatchedMutationFrame(context.Background(), &waBinary.Node{Tag: "iq"}, nil, nil)
	// Assert.
	if accepted {
		t.Fatal("non-Noise transport produced mutation authority")
	}
}
