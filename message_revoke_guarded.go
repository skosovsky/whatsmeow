// Copyright (c) 2026 Sergey Kosovsky
// SPDX-License-Identifier: MPL-2.0

package whatsmeow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

var errMessageRevoke = errors.New("original message revoke evidence unavailable")

type MessageRevokeGuardedRequest struct {
	ActorPN, ActorLID, ChatJID, TargetSender types.JID
	TargetFromMe                             bool
	TargetID, TransportID                    string
}

func (MessageRevokeGuardedRequest) String() string     { return "message revoke SDK request [redacted]" }
func (r MessageRevokeGuardedRequest) GoString() string { return r.String() }

func validMessageRevokeRequest(r MessageRevokeGuardedRequest) bool {
	if !canonicalParticipantJID(r.ActorPN) || r.ActorPN.Server != types.DefaultUserServer || r.ActorPN.Integrator != 0 || !canonicalParticipantJID(r.TargetSender) || r.TargetSender.Integrator != 0 || (r.ActorLID != (types.JID{}) && (!canonicalParticipantJID(r.ActorLID) || r.ActorLID.Server != types.HiddenUserServer || r.ActorLID.Integrator != 0)) {
		return false
	}
	if r.ChatJID.Server == types.GroupServer {
		if !validGroupLeaveRequest(GroupLeaveGuardedRequest{ActorPN: r.ActorPN, ActorLID: r.ActorLID, ActorJID: r.ActorPN, GroupJID: r.ChatJID}) {
			return false
		}
	} else if !canonicalParticipantJID(r.ChatJID) || r.ChatJID.Integrator != 0 || !r.TargetFromMe {
		return false
	}
	if r.TargetFromMe && r.TargetSender != r.ActorPN && (r.ActorLID.IsEmpty() || r.TargetSender != r.ActorLID) {
		return false
	}
	if !r.TargetFromMe && (r.TargetSender == r.ActorPN || !r.ActorLID.IsEmpty() && r.TargetSender == r.ActorLID) {
		return false
	}
	return len(r.TargetID) > 0 && len(r.TargetID) <= 256 && utf8.ValidString(r.TargetID) && strings.IndexFunc(r.TargetID, func(c rune) bool { return c < 32 || c == 127 }) == -1 && validRevokeTransportID(r.TransportID) && r.TransportID != r.TargetID
}
func validRevokeTransportID(id string) bool {
	return len(id) > 0 && len(id) <= 128 && strings.IndexFunc(id, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':' || c == '-')
	}) == -1
}

type messageRevokeFrameKey struct{}
type messageRevokeFrameBinding struct {
	authority *frameAuthority
	request   MessageRevokeGuardedRequest
	source    context.Context
	attempt   *messageRevokeSDKAttempt
}

// OriginalMessageRevokeRequest supplies correlation only during the active
// original physical callback. Returned scalars never grant application authority.
func OriginalMessageRevokeRequest(ctx context.Context) (MessageRevokeGuardedRequest, bool) {
	if ctx == nil || ctx.Err() != nil {
		return MessageRevokeGuardedRequest{}, false
	}
	p, ok := ctx.Value(messageRevokeFrameKey{}).(messageRevokeFrameBinding)
	a, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
	if !ok || a == nil || p.authority != a || a.tag != "message" || a.id != p.request.TransportID || !a.used.Load() || !a.active.Load() {
		return MessageRevokeGuardedRequest{}, false
	}
	if p.source == nil || p.source.Err() != nil {
		return MessageRevokeGuardedRequest{}, false
	}
	original, bounded := p.source.Deadline()
	received, receivedOK := ctx.Deadline()
	if !bounded || !receivedOK || original != received {
		return MessageRevokeGuardedRequest{}, false
	}
	return p.request, true
}

// OriginalMessageRevokeNonce correlates only the active original physical attempt.
func OriginalMessageRevokeNonce(ctx context.Context) (string, bool) {
	if _, ok := OriginalMessageRevokeRequest(ctx); !ok {
		return "", false
	}
	p, _ := ctx.Value(messageRevokeFrameKey{}).(messageRevokeFrameBinding)
	if p.attempt == nil || len(p.attempt.nonce) != 64 {
		return "", false
	}
	return p.attempt.nonce, true
}

type messageRevokeSDKAttempt struct {
	request             MessageRevokeGuardedRequest
	nonce               string
	device              *store.Device
	deviceID, deviceLID types.JID
	socket              atomic.Pointer[socket.NoiseSocket]
	wire                types.JID // published before passed.Store, then immutable
	passed, ack         atomic.Bool
}

func (a *messageRevokeSDKAttempt) actorMatches(cli *Client) bool {
	return a != nil && cli != nil && cli.Store == a.device && cli.Store != nil && cli.Store.ID != nil && *cli.Store.ID == a.deviceID && cli.Store.LID == a.deviceLID && cli.Store.ID.ToNonAD() == a.request.ActorPN && cli.Store.LID.ToNonAD() == a.request.ActorLID
}

type MessageRevokeGuardedResult struct {
	client  *Client
	attempt *messageRevokeSDKAttempt
}

func (*MessageRevokeGuardedResult) String() string {
	return "original message revoke result [redacted]"
}
func (r *MessageRevokeGuardedResult) GoString() string { return r.String() }
func (r *MessageRevokeGuardedResult) Verify(cli *Client, request MessageRevokeGuardedRequest) error {
	if r == nil || r.client != cli || r.attempt == nil || r.attempt.request != request || !validMessageRevokeRequest(request) || !r.attempt.passed.Load() || !r.attempt.ack.Load() || !r.attempt.actorMatches(cli) || !cli.groupLeaveSocketMatches(r.attempt.socket.Load()) {
		return errMessageRevoke
	}
	return nil
}

// VerifyOriginalAttempt additionally binds original private admission, not merely
// an identical request tuple from another genuine SDK send.
func (r *MessageRevokeGuardedResult) VerifyOriginalAttempt(cli *Client, request MessageRevokeGuardedRequest, nonce string) error {
	if r.Verify(cli, request) != nil || len(nonce) != 64 || r.attempt.nonce != nonce {
		return errMessageRevoke
	}
	return nil
}

func strictMessageRevokeACK(n *waBinary.Node, id string, wire types.JID) bool {
	if n == nil || !validRevokeTransportID(id) || n.Tag != "ack" || (len(n.Attrs) != 4 && len(n.Attrs) != 5) || n.Attrs["id"] != id || n.Attrs["class"] != "message" || n.Attrs["from"] != wire || wire.IsEmpty() {
		return false
	}
	if len(n.Attrs) == 5 {
		phash, ok := n.Attrs["phash"].(string)
		if !ok || len(phash) == 0 || len(phash) > 256 || !utf8.ValidString(phash) || strings.IndexFunc(phash, func(c rune) bool { return c < 32 || c == 127 }) != -1 {
			return false
		}
	}
	stamp, ok := n.Attrs["t"].(string)
	if !ok || len(stamp) == 0 || len(stamp) > 12 || strings.IndexFunc(stamp, func(c rune) bool { return c < '0' || c > '9' }) != -1 {
		return false
	}
	seconds, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || seconds <= 0 || seconds > 253402300799 || strconv.FormatInt(seconds, 10) != stamp {
		return false
	}
	if n.Content == nil {
		return true
	}
	children, ok := n.Content.([]waBinary.Node)
	return ok && len(children) == 0
}
func (cli *Client) captureOriginalMessageRevokeACK(ctx context.Context, n *waBinary.Node, frame []byte) {
	if cli == nil || ctx == nil || n == nil || len(frame) == 0 {
		return
	}
	id, ok := n.Attrs["id"].(string)
	if !ok {
		return
	}
	raw, ok := cli.messageRevokeAttempts.Load(id)
	if !ok {
		return
	}
	a, ok := raw.(*messageRevokeSDKAttempt)
	if !ok || a == nil || !a.passed.Load() || !a.actorMatches(cli) || !strictMessageRevokeACK(n, id, a.wire) {
		return
	}
	ns := a.socket.Load()
	if !cli.groupLeaveSocketMatches(ns) || !ns.ConsumeAuthenticatedFrame(ctx, frame) {
		return
	}
	a.ack.Store(true)
}

// RevokeMessageGuarded never accepts arbitrary protobuf, response or retry options.
// Physical guards must perform local IO only: Noise holds its writer gate there.
func (cli *Client) RevokeMessageGuarded(ctx context.Context, r MessageRevokeGuardedRequest, beforeWrite func(context.Context) error) (result *MessageRevokeGuardedResult, err error) {
	defer func() {
		if recover() != nil || err != nil {
			result = nil
			err = errMessageRevoke
		}
	}()
	if cli == nil || ctx == nil || ctx.Err() != nil || beforeWrite == nil || !validMessageRevokeRequest(r) || cli.Store == nil || cli.Store.ID == nil {
		return nil, errMessageRevoke
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) || time.Until(deadline) > 30*time.Second {
		return nil, errMessageRevoke
	}
	if cli.messageRevokeAdmission.Add(1) > 64 {
		cli.messageRevokeAdmission.Add(-1)
		return nil, errMessageRevoke
	}
	defer cli.messageRevokeAdmission.Add(-1)
	var origin [32]byte
	if _, err := rand.Read(origin[:]); err != nil {
		return nil, errMessageRevoke
	}
	a := &messageRevokeSDKAttempt{request: r, nonce: hex.EncodeToString(origin[:]), device: cli.Store, deviceID: *cli.Store.ID, deviceLID: cli.Store.LID}
	if !a.actorMatches(cli) {
		return nil, errMessageRevoke
	}
	if _, loaded := cli.messageRevokeAttempts.LoadOrStore(r.TransportID, a); loaded {
		return nil, errMessageRevoke
	}
	defer cli.messageRevokeAttempts.CompareAndDelete(r.TransportID, a)
	guard := func(ctx context.Context) error {
		authority, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
		ns, _ := ctx.Value(frameSocketKey{}).(*socket.NoiseSocket)
		wire, ok := OriginalMessageDestination(ctx)
		if !ok || authority == nil || authority.tag != "message" || authority.id != r.TransportID || !a.actorMatches(cli) || !cli.groupLeaveSocketMatches(ns) {
			return errMessageRevoke
		}
		if wire != r.ChatJID {
			if r.ChatJID.Server != types.DefaultUserServer || wire.Server != types.HiddenUserServer || cli.Store.LIDs == nil {
				return errMessageRevoke
			}
			mapped, e := cli.Store.LIDs.GetLIDForPN(ctx, r.ChatJID)
			if e != nil || mapped != wire {
				return errMessageRevoke
			}
		}
		original := context.WithValue(ctx, messageRevokeFrameKey{}, messageRevokeFrameBinding{authority, r, ctx, a})
		if checkParticipantPreparation(original, beforeWrite) != nil || !a.actorMatches(cli) || !cli.groupLeaveSocketMatches(ns) {
			return errMessageRevoke
		}
		a.wire = wire
		a.socket.Store(ns)
		a.passed.Store(true)
		return ctx.Err()
	}
	response, err := cli.SendMessage(ctx, r.ChatJID, cli.BuildRevoke(r.ChatJID, r.TargetSender, r.TargetID), SendRequestExtra{ID: r.TransportID, NoRetry: true, BeforeWrite: guard})
	if err != nil || ctx.Err() != nil || response.ID != r.TransportID || !a.passed.Load() || response.Chat != a.wire || !a.ack.Load() {
		return nil, errMessageRevoke
	}
	result = &MessageRevokeGuardedResult{client: cli, attempt: a}
	if result.Verify(cli, r) != nil {
		return nil, errMessageRevoke
	}
	return result, nil
}
