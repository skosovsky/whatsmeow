// Copyright (c) 2026 Sergey Kosovsky
// SPDX-License-Identifier: MPL-2.0

package whatsmeow

import (
	"bytes"
	"context"
	"errors"
	"unicode/utf8"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/types"
)

var errBlockAction = errors.New("block action unavailable")

type BlockActionGuardedRequest struct {
	ActorPN  types.JID `json:"actor_pn"`
	ActorLID types.JID `json:"actor_lid"`
	PhoneJID types.JID `json:"phone_jid"`
	LIDJID   types.JID `json:"lid_jid"`
	Action   string    `json:"action"`
}

func (BlockActionGuardedRequest) String() string     { return "block action request [redacted]" }
func (r BlockActionGuardedRequest) GoString() string { return r.String() }

func validBlockActionRequest(r BlockActionGuardedRequest) bool {
	return canonicalBlocklistJID(r.ActorPN) && r.ActorPN.Server == types.DefaultUserServer &&
		(r.ActorLID == (types.JID{}) || canonicalBlocklistJID(r.ActorLID) && r.ActorLID.Server == types.HiddenUserServer) &&
		canonicalBlocklistJID(r.PhoneJID) && r.PhoneJID.Server == types.DefaultUserServer &&
		canonicalBlocklistJID(r.LIDJID) && r.LIDJID.Server == types.HiddenUserServer &&
		r.PhoneJID != r.ActorPN && r.LIDJID != r.ActorLID && (r.Action == "block" || r.Action == "unblock")
}

func (cli *Client) blockActorMatches(r BlockActionGuardedRequest) bool {
	return cli != nil && cli.Store != nil && cli.Store.ID != nil &&
		cli.Store.ID.ToNonAD() == r.ActorPN && cli.Store.LID.ToNonAD() == r.ActorLID
}

type blockActionFrameKey struct{}
type blockActionFrameProof struct {
	authority *frameAuthority
	id        string
}

// OriginalBlockActionRequestID grants correlation only during the original
// consumed SET frame callback. It is not dispatch or receipt authority.
func OriginalBlockActionRequestID(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	p, ok := ctx.Value(blockActionFrameKey{}).(blockActionFrameProof)
	a, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
	if !ok || a == nil || p.authority != a || a.tag != "iq" || p.id == "" || p.id != a.id || !a.used.Load() || !a.active.Load() {
		return "", false
	}
	return p.id, true
}

// BlockActionGuardedResult is SDK-owned original response evidence. JSON and
// zero values cannot recreate it; application authority is checked separately.
type BlockActionGuardedResult struct {
	client  *Client
	request BlockActionGuardedRequest
	id      string
	blocked bool
	socket  *socket.NoiseSocket
}

func (*BlockActionGuardedResult) String() string     { return "block action result [redacted]" }
func (r *BlockActionGuardedResult) GoString() string { return r.String() }

func (r *BlockActionGuardedResult) Result(cli *Client, id string, request BlockActionGuardedRequest) (bool, error) {
	if r == nil || cli == nil || r.client != cli || id == "" || id != r.id || r.request != request || !validBlockActionRequest(request) || !cli.blockActorMatches(request) {
		return false, errBlockAction
	}
	if r.socket != nil && !cli.blockResponseSocketMatches(r.socket) {
		return false, errBlockAction
	}
	return r.blocked, nil
}

// UpdateBlocklistGuarded uses only frozen reciprocal cached aliases. It sends
// one SET, with no discovery/retry, and returns no other contact's metadata.
func (cli *Client) UpdateBlocklistGuarded(ctx context.Context, r BlockActionGuardedRequest, prepare, beforeWrite func(context.Context) error) (result *BlockActionGuardedResult, err error) {
	defer func() {
		if recover() != nil {
			result, err = nil, errBlockAction
		}
	}()
	if ctx == nil || prepare == nil || beforeWrite == nil {
		return nil, socket.ErrFrameAuthority
	}
	if cli == nil {
		return nil, ErrClientIsNil
	}
	if !validBlockActionRequest(r) || !cli.blockActorMatches(r) || cli.Store.LIDs == nil {
		return nil, errBlockAction
	}
	check := func(ctx context.Context) error {
		if err := checkParticipantPreparation(ctx, prepare); err != nil {
			return err
		}
		if !cli.blockActorMatches(r) {
			return socket.ErrFrameAuthority
		}
		lid, err := cli.Store.LIDs.GetLIDForPN(ctx, r.PhoneJID)
		if err != nil || lid != r.LIDJID {
			return socket.ErrFrameAuthority
		}
		if err := checkParticipantPreparation(ctx, prepare); err != nil {
			return err
		}
		pn, err := cli.Store.LIDs.GetPNForLID(ctx, r.LIDJID)
		if err != nil || pn != r.PhoneJID {
			return socket.ErrFrameAuthority
		}
		if err := checkParticipantPreparation(ctx, prepare); err != nil {
			return err
		}
		if !cli.blockActorMatches(r) {
			return socket.ErrFrameAuthority
		}
		return nil
	}
	if err := check(ctx); err != nil {
		return nil, err
	}
	id := cli.generateRequestID()
	guard := func(ctx context.Context) error {
		if err := check(ctx); err != nil {
			return err
		}
		a, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
		if a == nil || a.tag != "iq" || a.id != id || !a.used.Load() || !a.active.Load() {
			return socket.ErrFrameAuthority
		}
		proof := context.WithValue(ctx, blockActionFrameKey{}, blockActionFrameProof{a, id})
		if err := checkParticipantPreparation(proof, beforeWrite); err != nil {
			return err
		}
		return check(ctx)
	}
	attrs := waBinary.Attrs{"jid": r.LIDJID, "action": r.Action}
	if r.Action == "block" {
		attrs["pn_jid"] = r.PhoneJID
	}
	node, err := cli.sendIQ(ctx, infoQuery{Namespace: "blocklist", Type: iqSet, To: types.ServerJID, ID: id, NoRetry: true, BeforeWrite: guard, Content: []waBinary.Node{{Tag: "item", Attrs: attrs}}})
	if err != nil {
		return nil, errBlockAction
	}
	list, err := strictBlocklistResponse(node, id)
	if err != nil || !cli.blockActorMatches(r) {
		return nil, errBlockAction
	}
	blocked := false
	for _, jid := range list.JIDs {
		blocked = blocked || jid == r.PhoneJID || jid == r.LIDJID
	}
	if blocked != (r.Action == "block") {
		return nil, errBlockAction
	}
	return &BlockActionGuardedResult{client: cli, request: r, id: id, blocked: blocked}, nil
}

var errBlocklistResponse = errors.New("blocklist response unavailable")

// GetBlocklistGuarded performs one read with trusted authority at physical write.
// It rejects the whole malformed result instead of silently omitting contacts.
// Returned state is not proof of any prior mutation or permission to retry it.
func (cli *Client) GetBlocklistGuarded(ctx context.Context, beforeWrite func(context.Context) error) (*types.Blocklist, error) {
	if beforeWrite == nil {
		return nil, socket.ErrFrameAuthority
	}
	if cli == nil {
		return nil, ErrClientIsNil
	}
	id := cli.generateRequestID()
	node, err := cli.sendIQ(ctx, infoQuery{Namespace: "blocklist", Type: iqGet, To: types.ServerJID, ID: id, NoRetry: true, BeforeWrite: beforeWrite})
	if err != nil {
		return nil, err
	}
	return strictBlocklistResponse(node, id)
}

func strictBlocklistResponse(node *waBinary.Node, id string) (*types.Blocklist, error) {
	if id == "" || node == nil || node.Tag != "iq" || len(node.Attrs) != 3 || node.Attrs["id"] != id || node.Attrs["type"] != "result" || node.Attrs["from"] != types.ServerJID {
		return nil, errBlocklistResponse
	}
	children, ok := node.Content.([]waBinary.Node)
	if !ok || len(children) != 1 {
		return nil, errBlocklistResponse
	}
	list := children[0]
	if list.Tag != "list" || len(list.Attrs) > 1 {
		return nil, errBlocklistResponse
	}
	for key, value := range list.Attrs {
		s, ok := value.(string)
		if key != "dhash" || !ok || len(s) > 256 || !utf8.ValidString(s) {
			return nil, errBlocklistResponse
		}
	}
	var items []waBinary.Node
	if list.Content != nil {
		items, ok = list.Content.([]waBinary.Node)
		if !ok {
			return nil, errBlocklistResponse
		}
	}
	if len(items) > 10000 {
		return nil, errBlocklistResponse
	}
	out := &types.Blocklist{JIDs: make([]types.JID, 0, len(items))}
	seen := make(map[types.JID]struct{}, len(items))
	bytes := 0
	for _, item := range items {
		jid, ok := item.Attrs["jid"].(types.JID)
		if item.Tag != "item" || len(item.Attrs) != 1 || item.Content != nil || !ok || !canonicalBlocklistJID(jid) {
			return nil, errBlocklistResponse
		}
		if _, duplicate := seen[jid]; duplicate {
			return nil, errBlocklistResponse
		}
		seen[jid] = struct{}{}
		bytes += len(jid.String())
		if bytes > 16<<20 {
			return nil, errBlocklistResponse
		}
		out.JIDs = append(out.JIDs, jid)
	}
	return out, nil
}

func canonicalBlocklistJID(jid types.JID) bool {
	if (jid.Server != types.DefaultUserServer && jid.Server != types.HiddenUserServer) || jid != jid.ToNonAD() || len(jid.User) == 0 || len(jid.User) > 256 {
		return false
	}
	for _, r := range jid.User {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(jid.String()) <= 256
}

// BlockActionResponse owns unmatched authenticated blocklist IQ evidence, not
// application correlation or permission. Zero/JSON cannot recreate its origin.
type BlockActionResponse struct {
	client *Client
	socket *socket.NoiseSocket
	id     string
	data   []byte
}

func (*BlockActionResponse) String() string     { return "block action response [redacted]" }
func (r *BlockActionResponse) GoString() string { return r.String() }
func (r *BlockActionResponse) RequestID() string {
	if r == nil || r.client == nil || r.socket == nil {
		return ""
	}
	return r.id
}
func (cli *Client) blockResponseSocketMatches(ns *socket.NoiseSocket) bool {
	if cli == nil || ns == nil || !cli.socketLock.TryRLock() {
		return false
	}
	current := cli.socket == ns && ns.IsConnected()
	cli.socketLock.RUnlock()
	return current
}

// Result binds authenticated late data to the expected original journal request.
// Returned opaque result retains socket binding for every later proof/CAS check.
func (r *BlockActionResponse) Result(cli *Client, id string, request BlockActionGuardedRequest) (*BlockActionGuardedResult, error) {
	if r == nil || cli == nil || r.client != cli || id == "" || id != r.id || len(r.data) == 0 || len(r.data) > 16*1024*1024 || !validBlockActionRequest(request) || !cli.blockActorMatches(request) || !cli.blockResponseSocketMatches(r.socket) {
		return nil, errBlockAction
	}
	node, err := waBinary.Unmarshal(bytes.Clone(r.data))
	if err != nil {
		return nil, errBlockAction
	}
	list, err := strictBlocklistResponse(node, id)
	if err != nil {
		return nil, errBlockAction
	}
	blocked := false
	for _, jid := range list.JIDs {
		if jid == request.PhoneJID || jid == request.LIDJID {
			blocked = true
		}
	}
	if blocked != (request.Action == "block") || !cli.blockActorMatches(request) || !cli.blockResponseSocketMatches(r.socket) {
		return nil, errBlockAction
	}
	return &BlockActionGuardedResult{client: cli, request: request, id: id, blocked: blocked, socket: r.socket}, nil
}
func (cli *Client) dispatchUnmatchedBlockResponse(ns *socket.NoiseSocket, node *waBinary.Node, data []byte) bool {
	if ns == nil || node == nil || len(data) == 0 || len(data) > 16*1024*1024 {
		return false
	}
	id, ok := node.Attrs["id"].(string)
	if !ok || len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':' || c == '-') {
			return false
		}
	}
	if _, err := strictBlocklistResponse(node, id); err != nil {
		return false
	}
	cli.dispatchEvent(&BlockActionResponse{client: cli, socket: ns, id: id, data: bytes.Clone(data)})
	return true
}

// Mutation response families share one consumption of original authenticated-frame
// authority, after waiter routing. Never consume once per event subscriber.
func (cli *Client) handleUnmatchedMutationFrame(ctx context.Context, node *waBinary.Node, frame, decoded []byte) bool {
	if !cli.socketLock.TryRLock() {
		return false
	}
	ns, ok := cli.socket.(*socket.NoiseSocket)
	authenticated := ok && ns.ConsumeAuthenticatedFrame(ctx, frame)
	cli.socketLock.RUnlock()
	return authenticated && (cli.dispatchUnmatchedCreationResponse(ns, node, decoded) || cli.dispatchUnmatchedBlockResponse(ns, node, decoded) || cli.dispatchUnmatchedGroupLeaveResponse(ns, node, decoded))
}
