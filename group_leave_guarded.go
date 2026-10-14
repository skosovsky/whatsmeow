// Copyright (c) 2026 Sergey Kosovsky
// SPDX-License-Identifier: MPL-2.0

package whatsmeow

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

var errGroupLeave = errors.New("original group leave attempt unavailable")

type GroupLeaveGuardedRequest struct{ ActorPN, ActorLID, ActorJID, GroupJID types.JID }

func (GroupLeaveGuardedRequest) String() string     { return "group leave request [redacted]" }
func (r GroupLeaveGuardedRequest) GoString() string { return r.String() }

func validGroupLeaveRequest(r GroupLeaveGuardedRequest) bool {
	if r.ActorPN.Integrator != 0 || r.ActorLID.Integrator != 0 || r.GroupJID.Integrator != 0 || !canonicalParticipantJID(r.ActorPN) || r.ActorPN.Server != types.DefaultUserServer || (r.ActorLID != (types.JID{}) && (!canonicalParticipantJID(r.ActorLID) || r.ActorLID.Server != types.HiddenUserServer)) || !canonicalParticipantJID(r.ActorJID) || (r.ActorJID != r.ActorPN && (r.ActorLID.IsEmpty() || r.ActorJID != r.ActorLID)) || r.GroupJID.ToNonAD() != r.GroupJID || r.GroupJID.Server != types.GroupServer || len(r.GroupJID.String()) > 256 {
		return false
	}
	parts := strings.Split(r.GroupJID.User, "-")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.IndexFunc(part, func(c rune) bool { return c < '0' || c > '9' }) != -1 {
			return false
		}
	}
	return true
}
func (cli *Client) groupLeaveActorMatches(r GroupLeaveGuardedRequest) bool {
	return cli != nil && cli.Store != nil && cli.Store.ID != nil && cli.Store.ID.ToNonAD() == r.ActorPN && cli.Store.LID.ToNonAD() == r.ActorLID
}
func (cli *Client) groupLeaveSocketMatches(ns *socket.NoiseSocket) bool {
	if cli == nil || ns == nil || !cli.socketLock.TryRLock() {
		return false
	}
	current := cli.socket == ns && ns.IsConnected()
	cli.socketLock.RUnlock()
	return current
}

type groupLeaveFrameKey struct{}
type groupLeaveFrameProof struct {
	authority *frameAuthority
	id        string
}

// Correlation only in the original active physical callback, never permission.
func OriginalGroupLeaveRequestID(ctx context.Context) (string, bool) {
	if ctx == nil || ctx.Err() != nil {
		return "", false
	}
	p, ok := ctx.Value(groupLeaveFrameKey{}).(groupLeaveFrameProof)
	a, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
	if !ok || a == nil || p.authority != a || a.tag != "iq" || p.id == "" || p.id != a.id || !a.used.Load() || !a.active.Load() {
		return "", false
	}
	return p.id, true
}

type groupLeaveSDKAttempt struct {
	request             GroupLeaveGuardedRequest
	device              *store.Device
	deviceID, deviceLID types.JID
	socket              atomic.Pointer[socket.NoiseSocket]
	passed, ack         atomic.Bool
}

func (a *groupLeaveSDKAttempt) actorMatches(cli *Client) bool {
	return a != nil && cli != nil && cli.Store == a.device && cli.Store != nil && cli.Store.ID != nil && *cli.Store.ID == a.deviceID && cli.Store.LID == a.deviceLID && cli.groupLeaveActorMatches(a.request)
}

// Original SDK response evidence. Zero/JSON/naked nodes cannot create its origin.
type GroupLeaveGuardedResult struct {
	client      *Client
	attempt     *groupLeaveSDKAttempt
	id          string
	late        *GroupLeaveResponse
	lateRequest GroupLeaveGuardedRequest
}

func (*GroupLeaveGuardedResult) String() string     { return "group leave result [redacted]" }
func (r *GroupLeaveGuardedResult) GoString() string { return r.String() }
func (r *GroupLeaveGuardedResult) Verify(cli *Client, id string, request GroupLeaveGuardedRequest) error {
	if r != nil && r.late != nil {
		if r.client != cli || r.id != id || r.lateRequest != request {
			return errGroupLeave
		}
		return r.late.verify(cli, id, request)
	}
	if r == nil || cli == nil || r.client != cli || id == "" || id != r.id || r.attempt == nil || r.attempt.request != request || !validGroupLeaveRequest(request) || !r.attempt.actorMatches(cli) || !r.attempt.passed.Load() || !r.attempt.ack.Load() || !cli.groupLeaveSocketMatches(r.attempt.socket.Load()) {
		return errGroupLeave
	}
	return nil
}
func strictGroupLeaveACK(node *waBinary.Node, id string) bool {
	if len(id) < 1 || len(id) > 128 || strings.IndexFunc(id, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':' || c == '-')
	}) != -1 {
		return false
	}
	if node == nil || node.Tag != "iq" || len(node.Attrs) != 3 || node.Attrs["id"] != id || node.Attrs["type"] != "result" || node.Attrs["from"] != types.GroupServerJID {
		return false
	}
	if node.Content == nil {
		return true
	}
	children, ok := node.Content.([]waBinary.Node)
	return ok && len(children) == 0
}

// Called only at the original decoded frame boundary, before waiter routing.
// Raw ReceiveResponse cannot provide the NoiseSocket's private frame proof.
func (cli *Client) captureOriginalGroupLeaveACK(ctx context.Context, node *waBinary.Node, frame []byte) *socket.NoiseSocket {
	if cli == nil || ctx == nil || node == nil || len(frame) == 0 {
		return nil
	}
	id, ok := node.Attrs["id"].(string)
	if !ok || !strictGroupLeaveACK(node, id) {
		return nil
	}
	raw, ok := cli.groupLeaveAttempts.Load(id)
	if !ok {
		return nil
	}
	attempt, ok := raw.(*groupLeaveSDKAttempt)
	if !ok || attempt == nil || !attempt.passed.Load() || !attempt.actorMatches(cli) {
		return nil
	}
	ns := attempt.socket.Load()
	if !cli.groupLeaveSocketMatches(ns) || !ns.ConsumeAuthenticatedFrame(ctx, frame) {
		return nil
	}
	attempt.ack.Store(true)
	return ns
}

// LeaveGroupGuarded owns a single no-retry physical attempt. Application policy,
// consumed grant, durable journal and outcome CAS belong to the trusted caller.
func (cli *Client) LeaveGroupGuarded(ctx context.Context, r GroupLeaveGuardedRequest, prepare, beforeWrite func(context.Context) error) (result *GroupLeaveGuardedResult, err error) {
	defer func() {
		if recover() != nil {
			result, err = nil, errGroupLeave
		}
	}()
	if ctx == nil || prepare == nil || beforeWrite == nil {
		return nil, socket.ErrFrameAuthority
	}
	if cli == nil {
		return nil, ErrClientIsNil
	}
	if !validGroupLeaveRequest(r) || !cli.groupLeaveActorMatches(r) {
		return nil, errGroupLeave
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	device := cli.Store
	deviceID, deviceLID := *device.ID, device.LID
	check := func(ctx context.Context) error {
		if checkParticipantPreparation(ctx, prepare) != nil || cli.Store != device || !cli.groupLeaveActorMatches(r) || *cli.Store.ID != deviceID || cli.Store.LID != deviceLID {
			return socket.ErrFrameAuthority
		}
		return ctx.Err()
	}
	if err := check(ctx); err != nil {
		return nil, err
	}
	id := cli.generateRequestID()
	attempt := &groupLeaveSDKAttempt{request: r, device: device, deviceID: deviceID, deviceLID: deviceLID}
	if _, loaded := cli.groupLeaveAttempts.LoadOrStore(id, attempt); loaded {
		return nil, errGroupLeave
	}
	defer cli.groupLeaveAttempts.CompareAndDelete(id, attempt)
	guard := func(ctx context.Context) error {
		if err := check(ctx); err != nil {
			return err
		}
		a, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
		ns, _ := ctx.Value(frameSocketKey{}).(*socket.NoiseSocket)
		if a == nil || a.tag != "iq" || a.id != id || !a.used.Load() || !a.active.Load() || !cli.groupLeaveSocketMatches(ns) {
			return socket.ErrFrameAuthority
		}
		proof := context.WithValue(ctx, groupLeaveFrameKey{}, groupLeaveFrameProof{a, id})
		if checkParticipantPreparation(proof, beforeWrite) != nil {
			return socket.ErrFrameAuthority
		}
		if err := check(ctx); err != nil {
			return err
		}
		if !cli.groupLeaveSocketMatches(ns) {
			return socket.ErrFrameAuthority
		}
		attempt.socket.Store(ns)
		attempt.passed.Store(true)
		return nil
	}
	node, err := cli.sendIQ(ctx, infoQuery{Namespace: "w:g2", Type: iqSet, To: types.GroupServerJID, ID: id, NoRetry: true, BeforeWrite: guard, Content: []waBinary.Node{{Tag: "leave", Content: []waBinary.Node{{Tag: "group", Attrs: waBinary.Attrs{"id": r.GroupJID}}}}}})
	if err != nil || !strictGroupLeaveACK(node, id) {
		return nil, errGroupLeave
	}
	result = &GroupLeaveGuardedResult{client: cli, attempt: attempt, id: id}
	if result.Verify(cli, id, r) != nil {
		return nil, errGroupLeave
	}
	return result, nil
}

// MaxGroupLeaveResponseBytes bounds private decoded late ACK evidence.
const MaxGroupLeaveResponseBytes = 4096

// GroupLeaveResponse exists only at the original authenticated unmatched-frame
// boundary. It is correlation evidence, never application policy or SQL authority.
type GroupLeaveResponse struct {
	client              *Client
	socket              *socket.NoiseSocket
	device              *store.Device
	deviceID, deviceLID types.JID
	id                  string
	data                []byte
}

func (*GroupLeaveResponse) String() string     { return "group leave response [redacted]" }
func (r *GroupLeaveResponse) GoString() string { return r.String() }
func (r *GroupLeaveResponse) RequestID() string {
	if r == nil || r.client == nil || r.socket == nil || r.device == nil {
		return ""
	}
	return r.id
}
func (r *GroupLeaveResponse) current(cli *Client) bool {
	return r != nil && cli != nil && r.client == cli && cli.Store != nil && cli.Store == r.device && cli.Store.ID != nil && *cli.Store.ID == r.deviceID && cli.Store.LID == r.deviceLID && cli.groupLeaveSocketMatches(r.socket)
}
func (r *GroupLeaveResponse) verify(cli *Client, id string, request GroupLeaveGuardedRequest) error {
	if !r.current(cli) || id == "" || r.id != id || len(r.data) == 0 || len(r.data) > MaxGroupLeaveResponseBytes || !validGroupLeaveRequest(request) || !cli.groupLeaveActorMatches(request) {
		return errGroupLeave
	}
	node, err := waBinary.Unmarshal(bytes.Clone(r.data))
	if err != nil || !strictGroupLeaveACK(node, id) || !r.current(cli) || !cli.groupLeaveActorMatches(request) {
		return errGroupLeave
	}
	return nil
}

// Result binds an authenticated late ACK to expected original journal metadata.
// The caller must independently verify that journal, policy and consumed grant.
func (r *GroupLeaveResponse) Result(cli *Client, id string, request GroupLeaveGuardedRequest) (*GroupLeaveGuardedResult, error) {
	if err := r.verify(cli, id, request); err != nil {
		return nil, err
	}
	result := &GroupLeaveGuardedResult{client: cli, id: id, late: r, lateRequest: request}
	if err := result.Verify(cli, id, request); err != nil {
		return nil, err
	}
	return result, nil
}
func (cli *Client) dispatchUnmatchedGroupLeaveResponse(ns *socket.NoiseSocket, node *waBinary.Node, data []byte) bool {
	if cli == nil || ns == nil || node == nil || len(data) == 0 || len(data) > MaxGroupLeaveResponseBytes || cli.Store == nil || cli.Store.ID == nil || !cli.groupLeaveSocketMatches(ns) {
		return false
	}
	id, ok := node.Attrs["id"].(string)
	if !ok || !strictGroupLeaveACK(node, id) {
		return false
	}
	response := &GroupLeaveResponse{client: cli, socket: ns, device: cli.Store, deviceID: *cli.Store.ID, deviceLID: cli.Store.LID, id: id, data: bytes.Clone(data)}
	if !response.current(cli) {
		return false
	}
	cli.dispatchEvent(response)
	return true
}
