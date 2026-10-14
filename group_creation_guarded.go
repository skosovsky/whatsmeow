// Copyright (c) 2026 Sergey Kosovsky
// SPDX-License-Identifier: MPL-2.0
package whatsmeow

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/types"
)

var errGuardedCreation = errors.New("group creation attempt unavailable")

type groupCreationFrameKey struct{}
type groupCreationFrameProof struct {
	authority *frameAuthority
	id        string
}

// OriginalGroupCreationRequestID exposes correlation only while the original
// consumed creation frame callback is active. It grants no send/receipt authority.
// Captured contexts cannot revive this proof or bind it to another IQ callback.
func OriginalGroupCreationRequestID(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	proof, ok := ctx.Value(groupCreationFrameKey{}).(groupCreationFrameProof)
	authority, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
	if !ok || authority == nil || proof.authority != authority || authority.tag != "iq" || proof.id == "" || proof.id != authority.id || !authority.used.Load() || !authority.active.Load() {
		return "", false
	}
	return proof.id, true
}

type GroupCreationGuardedRequest struct {
	Name                  string
	CreatorPN, CreatorLID types.JID
	Targets               []GroupParticipantUpdateTarget
}
type GroupCreationGuardedResult struct {
	GroupJID types.JID
	Results  []GroupParticipantUpdateResult
}

func (GroupCreationGuardedRequest) String() string     { return "group creation request [redacted]" }
func (r GroupCreationGuardedRequest) GoString() string { return r.String() }
func (GroupCreationGuardedResult) String() string      { return "group creation result [redacted]" }
func (r GroupCreationGuardedResult) GoString() string  { return r.String() }
func validateGuardedCreation(r GroupCreationGuardedRequest) error {
	if !utf8.ValidString(r.Name) || len(r.Name) > 400 || utf8.RuneCountInString(r.Name) > 100 || strings.TrimSpace(r.Name) == "" || !canonicalParticipantJID(r.CreatorPN) || r.CreatorPN.Server != types.DefaultUserServer {
		return errGuardedCreation
	}
	for _, c := range r.Name {
		if unicode.IsControl(c) {
			return errGuardedCreation
		}
	}
	if !r.CreatorLID.IsEmpty() && (!canonicalParticipantJID(r.CreatorLID) || r.CreatorLID.Server != types.HiddenUserServer) {
		return errGuardedCreation
	}
	if validateParticipantUpdate(types.NewJID("1", types.GroupServer), r.Targets, ParticipantChangeAdd) != nil {
		return errGuardedCreation
	}
	for _, t := range r.Targets {
		if t.PhoneNumber == r.CreatorPN || t.JID == r.CreatorLID {
			return errGuardedCreation
		}
	}
	return nil
}
func (cli *Client) creationActorMatches(r GroupCreationGuardedRequest) bool {
	return cli != nil && cli.Store != nil && cli.Store.ID != nil && cli.Store.ID.ToNonAD() == r.CreatorPN && cli.Store.LID.ToNonAD() == r.CreatorLID
}

// CreateGroupGuarded supports only the frozen normal-group defaults. Authority
// callbacks belong to the application, not to incoming/model assertions.
func (cli *Client) CreateGroupGuarded(ctx context.Context, r GroupCreationGuardedRequest, prepare, beforeWrite func(context.Context) error) (*GroupCreationGuardedResult, error) {
	if cli == nil {
		return nil, ErrClientIsNil
	}
	if len(r.Targets) > 20 || prepare == nil || beforeWrite == nil {
		return nil, socket.ErrFrameAuthority
	}
	r.Targets = slices.Clone(r.Targets)
	if validateGuardedCreation(r) != nil || !cli.creationActorMatches(r) {
		return nil, errGuardedCreation
	}
	if err := checkParticipantPreparation(ctx, prepare); err != nil {
		return nil, err
	}
	nodes := make([]waBinary.Node, 0, len(r.Targets)+3)
	snapshots := make([]participantAddSnapshot, len(r.Targets))
	for i, t := range r.Targets {
		snapshot, err := cli.participantAddEvidence(ctx, t, prepare)
		if err != nil {
			return nil, errGuardedCreation
		}
		snapshots[i] = snapshot
		n := waBinary.Node{Tag: "participant", Attrs: waBinary.Attrs{"jid": t.JID}}
		if t.JID.Server == types.HiddenUserServer {
			n.Attrs["phone_number"] = t.PhoneNumber
		}
		if len(snapshot.token) > 0 {
			n.Content = []waBinary.Node{{Tag: "privacy", Content: bytes.Clone(snapshot.token)}}
		}
		nodes = append(nodes, n)
	}
	nodes = append(nodes, waBinary.Node{Tag: "member_add_mode", Content: "all_member_add"}, waBinary.Node{Tag: "ephemeral", Attrs: waBinary.Attrs{"expiration": 0}}, waBinary.Node{Tag: "membership_approval_mode", Content: []waBinary.Node{{Tag: "group_join", Attrs: waBinary.Attrs{"state": "off"}}}})
	check := func(ctx context.Context) error {
		if err := checkParticipantPreparation(ctx, prepare); err != nil || !cli.creationActorMatches(r) {
			return socket.ErrFrameAuthority
		}
		for i, t := range r.Targets {
			s, err := cli.participantAddEvidence(ctx, t, prepare)
			if err != nil || s.storageJID != snapshots[i].storageJID || !bytes.Equal(s.token, snapshots[i].token) {
				return socket.ErrFrameAuthority
			}
		}
		return nil
	}
	id := cli.generateRequestID()
	guard := func(ctx context.Context) error {
		if err := check(ctx); err != nil {
			return err
		}
		authority, _ := ctx.Value(frameAuthorityKey{}).(*frameAuthority)
		if authority == nil || authority.tag != "iq" || authority.id != id || !authority.used.Load() || !authority.active.Load() {
			return socket.ErrFrameAuthority
		}
		ctx = context.WithValue(ctx, groupCreationFrameKey{}, groupCreationFrameProof{authority, id})
		if err := checkParticipantPreparation(ctx, beforeWrite); err != nil {
			return err
		}
		return check(ctx)
	}
	node, err := cli.sendIQ(ctx, infoQuery{Namespace: "w:g2", Type: iqSet, To: types.GroupServerJID, ID: id, NoRetry: true, BeforeWrite: guard, Content: []waBinary.Node{{Tag: "create", Attrs: waBinary.Attrs{"subject": r.Name}, Content: nodes}}})
	if err != nil {
		return nil, errGuardedCreation
	}
	return parseGuardedCreationResult(node, id, r)
}
func parseGuardedCreationResult(node *waBinary.Node, id string, r GroupCreationGuardedRequest) (*GroupCreationGuardedResult, error) {
	if validateGuardedCreation(r) != nil || node == nil || node.Tag != "iq" || len(node.Attrs) != 3 || id == "" || node.Attrs["id"] != id || node.Attrs["type"] != "result" || node.Attrs["from"] != types.GroupServerJID {
		return nil, errGuardedCreation
	}
	children, ok := node.Content.([]waBinary.Node)
	if !ok || len(children) != 1 || children[0].Tag != "group" {
		return nil, errGuardedCreation
	}
	g := children[0]
	for k, v := range g.Attrs {
		switch k {
		case "id", "subject", "creator", "creator_pn", "s_o", "s_o_pn", "creation", "s_t", "size", "p_v_id", "a_v_id", "addressing_mode", "creator_country_code":
		default:
			return nil, errGuardedCreation
		}
		switch v := v.(type) {
		case string:
			if len(v) > 512 || !utf8.ValidString(v) {
				return nil, errGuardedCreation
			}
		case types.JID:
			if len(v.String()) > 256 || v.ToNonAD() != v {
				return nil, errGuardedCreation
			}
		case int, int64, uint64:
		default:
			return nil, errGuardedCreation
		}
	}
	a := g.AttrGetter()
	jid := types.NewJID(a.String("id"), types.GroupServer)
	subject := a.String("subject")
	creator := a.JID("creator")
	pn := a.OptionalJIDOrEmpty("creator_pn")
	if a.Error() != nil || subject != r.Name || validateParticipantUpdate(jid, r.Targets, ParticipantChangeAdd) != nil || creator != r.CreatorPN && (r.CreatorLID.IsEmpty() || creator != r.CreatorLID) || !pn.IsEmpty() && pn != r.CreatorPN {
		return nil, errGuardedCreation
	}
	members, ok := g.Content.([]waBinary.Node)
	if !ok || len(members) > len(r.Targets)+5 {
		return nil, errGuardedCreation
	}
	targets := make([]waBinary.Node, 0, len(r.Targets))
	own := false
	defaults := map[string]bool{}
	for _, m := range members {
		if m.Tag != "participant" {
			if defaults[m.Tag] {
				return nil, errGuardedCreation
			}
			defaults[m.Tag] = true
			switch m.Tag {
			case "member_add_mode":
				v, ok := m.Content.([]byte)
				if !ok || string(v) != "all_member_add" || len(m.Attrs) != 0 {
					return nil, errGuardedCreation
				}
			case "ephemeral":
				ag := m.AttrGetter()
				if len(m.Attrs) != 1 || ag.Int("expiration") != 0 || ag.Error() != nil || m.Content != nil {
					return nil, errGuardedCreation
				}
			case "membership_approval_mode":
				nested, ok := m.Content.([]waBinary.Node)
				if !ok || len(m.Attrs) != 0 || len(nested) != 1 || nested[0].Tag != "group_join" || len(nested[0].Attrs) != 1 || nested[0].Attrs["state"] != "off" || nested[0].Content != nil {
					return nil, errGuardedCreation
				}
			default:
				return nil, errGuardedCreation
			}
			continue
		}
		ag := m.AttrGetter()
		member := parseParticipant(ag, &m)
		isOwn := member.JID == r.CreatorPN || !r.CreatorLID.IsEmpty() && member.JID == r.CreatorLID
		if !isOwn {
			targets = append(targets, m)
			continue
		}
		if own || ag.Error() != nil || !member.IsSuperAdmin || member.Error != 0 || m.Content != nil || len(m.Attrs) > 4 {
			return nil, errGuardedCreation
		}
		for k := range m.Attrs {
			if k != "jid" && k != "type" && k != "phone_number" && k != "lid" {
				return nil, errGuardedCreation
			}
		}
		if member.JID.Server == types.HiddenUserServer && !member.PhoneNumber.IsEmpty() && member.PhoneNumber != r.CreatorPN || !member.LID.IsEmpty() && member.LID != r.CreatorLID {
			return nil, errGuardedCreation
		}
		own = true
	}
	if !own {
		return nil, errGuardedCreation
	}
	// Reuse the reviewed native participant parser after proving original envelope.
	synthetic := &waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": id, "type": "result", "from": jid}, Content: []waBinary.Node{{Tag: "add", Content: targets}}}
	results, err := parseGuardedParticipantResults(synthetic, jid, id, r.Targets, ParticipantChangeAdd)
	if err != nil {
		return nil, errGuardedCreation
	}
	for i, result := range results {
		for _, t := range r.Targets {
			if t.JID == result.JID {
				ag := targets[i].AttrGetter()
				member := parseParticipant(ag, &targets[i])
				role := ag.OptionalString("type")
				if ag.Error() != nil || !member.PhoneNumber.IsEmpty() && member.PhoneNumber != t.PhoneNumber || member.IsAdmin || role != "" && role != "member" {
					return nil, errGuardedCreation
				}
			}
		}
	}
	if _, present := g.Attrs["size"]; present {
		applied := 1
		for _, result := range results {
			if result.Error == 0 {
				applied++
			}
		}
		if a.Int("size") != applied || a.Error() != nil {
			return nil, errGuardedCreation
		}
	}
	return &GroupCreationGuardedResult{GroupJID: jid, Results: slices.Clone(results)}, nil
}

// GroupCreationResponse owns unmatched authenticated response evidence. Its zero
// value and imported JSON carry no proof. It grants no application CAS authority.
type GroupCreationResponse struct {
	client *Client
	socket *socket.NoiseSocket
	id     string
	data   []byte
}

func (*GroupCreationResponse) String() string     { return "group creation response [redacted]" }
func (r *GroupCreationResponse) GoString() string { return r.String() }

// RequestID is private correlation metadata, not a receipt or retry entitlement.
func (r *GroupCreationResponse) RequestID() string {
	if r == nil || r.client == nil || r.socket == nil {
		return ""
	}
	return r.id
}

// Result validates the actual unmatched response against the original frozen
// request. Current identity/socket and exact request ID must still match.
func (r *GroupCreationResponse) Result(cli *Client, id string, request GroupCreationGuardedRequest) (*GroupCreationGuardedResult, error) {
	if r == nil || cli == nil || r.client != cli || r.socket == nil || id == "" || id != r.id || len(r.data) == 0 || len(r.data) > 32*1024 || !cli.creationActorMatches(request) {
		return nil, errGuardedCreation
	}
	if !cli.socketLock.TryRLock() {
		return nil, errGuardedCreation
	}
	current := cli.socket == r.socket && r.socket.IsConnected()
	cli.socketLock.RUnlock()
	if !current {
		return nil, errGuardedCreation
	}
	node, err := waBinary.Unmarshal(bytes.Clone(r.data))
	if err != nil {
		return nil, errGuardedCreation
	}
	request.Targets = slices.Clone(request.Targets)
	return parseGuardedCreationResult(node, id, request)
}

func (cli *Client) dispatchUnmatchedCreationResponse(ns *socket.NoiseSocket, node *waBinary.Node, data []byte) bool {
	if ns == nil || len(data) == 0 || len(data) > 32*1024 || node == nil || node.Tag != "iq" || node.Attrs["type"] != "result" || node.Attrs["from"] != types.GroupServerJID {
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
	children, ok := node.Content.([]waBinary.Node)
	if !ok || len(children) != 1 || children[0].Tag != "group" {
		return false
	}
	cli.dispatchEvent(&GroupCreationResponse{client: cli, socket: ns, id: id, data: bytes.Clone(data)})
	return true
}
