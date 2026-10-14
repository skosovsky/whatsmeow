package whatsmeow

import (
	"context"
	"sync/atomic"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/types"
)

type frameAuthorityKey struct{}

// Binds a native guard to the exact NoiseSocket selected for this physical write.
type frameSocketKey struct{}
type frameDestinationKey struct{}
type frameDestination struct {
	authority *frameAuthority
	chat      types.JID
}

// OriginalMessageDestination is readable only inside the consumed native frame
// callback. Its private evidence comes from the original serialized node.
func OriginalMessageDestination(ctx context.Context) (types.JID, bool) {
	proof, ok := ctx.Value(frameDestinationKey{}).(frameDestination)
	authority, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
	if !ok || authority == nil || proof.authority != authority || authority.tag != "message" || !authority.used.Load() || !authority.active.Load() || proof.chat.IsEmpty() {
		return types.JID{}, false
	}
	return proof.chat, true
}

type frameAuthority struct {
	tag, id string
	used    atomic.Bool
	active  atomic.Bool
	check   func(context.Context) error
}

func withFrameAuthority(ctx context.Context, tag, id string, check func(context.Context) error) context.Context {
	if check == nil {
		return ctx
	}
	return context.WithValue(ctx, frameAuthorityKey{}, &frameAuthority{tag: tag, id: id, check: check})
}

func frameGuardForNode(ctx context.Context, node waBinary.Node) func(context.Context) error {
	authority, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
	if authority == nil || node.Tag != authority.tag {
		return nil
	}
	id, ok := node.Attrs["id"].(string)
	if !ok || authority.id == "" || id != authority.id {
		return func(context.Context) error { return socket.ErrFrameAuthority }
	}
	return func(ctx context.Context) error {
		if !authority.used.CompareAndSwap(false, true) {
			return socket.ErrFrameAuthority
		}
		authority.active.Store(true)
		defer authority.active.Store(false)
		if authority.tag == "message" {
			chat, ok := node.Attrs["to"].(types.JID)
			if !ok || chat.IsEmpty() {
				return socket.ErrFrameAuthority
			}
			ctx = context.WithValue(ctx, frameDestinationKey{}, frameDestination{authority, chat})
		}
		return authority.check(ctx)
	}
}
