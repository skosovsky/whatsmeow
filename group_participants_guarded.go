// Copyright (c) 2026 Sergey Kosovsky
// SPDX-License-Identifier: MPL-2.0

package whatsmeow

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/types"
)

var errGuardedParticipants = errors.New("group participant attempt unavailable")

// GroupParticipantUpdateTarget freezes the primary JID and add's original PN binding.
type GroupParticipantUpdateTarget struct {
	JID, PhoneNumber types.JID
}

// GroupParticipantUpdateResult excludes privacy and invitation bearer material.
type GroupParticipantUpdateResult struct {
	JID                types.JID
	Error              int
	InvitationRequired bool
}

func (GroupParticipantUpdateTarget) String() string     { return "participant target [redacted]" }
func (GroupParticipantUpdateResult) String() string     { return "participant result [redacted]" }
func (t GroupParticipantUpdateTarget) GoString() string { return t.String() }
func (r GroupParticipantUpdateResult) GoString() string { return r.String() }

func canonicalParticipantJID(jid types.JID) bool {
	if jid.ToNonAD() != jid || len(jid.String()) > 256 || jid.User == "" || jid.User[0] < '1' || jid.User[0] > '9' || (jid.Server != types.DefaultUserServer && jid.Server != types.HiddenUserServer) {
		return false
	}
	return strings.IndexFunc(jid.User, func(r rune) bool { return r < '0' || r > '9' }) == -1
}

func validateParticipantUpdate(jid types.JID, targets []GroupParticipantUpdateTarget, action ParticipantChange) error {
	if jid.Server != types.GroupServer || jid.ToNonAD() != jid || jid.User == "" || len(jid.String()) > 256 || len(targets) < 1 || len(targets) > 20 {
		return errGuardedParticipants
	}
	switch action {
	case ParticipantChangeAdd, ParticipantChangeRemove, ParticipantChangePromote, ParticipantChangeDemote:
	default:
		return errGuardedParticipants
	}
	seen := make(map[types.JID]bool, len(targets))
	seenPN := make(map[types.JID]bool, len(targets))
	groupParts := strings.Split(jid.User, "-")
	if len(groupParts) > 2 {
		return errGuardedParticipants
	}
	for _, part := range groupParts {
		if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) != -1 {
			return errGuardedParticipants
		}
	}
	for _, target := range targets {
		if !canonicalParticipantJID(target.JID) || seen[target.JID] {
			return errGuardedParticipants
		}
		seen[target.JID] = true
		if action == ParticipantChangeAdd && (!canonicalParticipantJID(target.PhoneNumber) || target.PhoneNumber.Server != types.DefaultUserServer || target.JID.Server == types.DefaultUserServer && target.PhoneNumber != target.JID) {
			return errGuardedParticipants
		}
		if action == ParticipantChangeAdd {
			if seenPN[target.PhoneNumber] {
				return errGuardedParticipants
			}
			seenPN[target.PhoneNumber] = true
		}
	}
	return nil
}

func checkParticipantPreparation(ctx context.Context, check func(context.Context) error) (err error) {
	defer func() {
		if recover() != nil {
			err = socket.ErrFrameAuthority
		}
	}()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if check == nil || check(ctx) != nil {
		return socket.ErrFrameAuthority
	}
	return ctx.Err()
}

type participantAddSnapshot struct {
	token      []byte
	storageJID types.JID
}

func (cli *Client) participantAddEvidence(ctx context.Context, target GroupParticipantUpdateTarget, check func(context.Context) error) (participantAddSnapshot, error) {
	if err := checkParticipantPreparation(ctx, check); err != nil {
		return participantAddSnapshot{}, err
	}
	if cli.Store == nil || cli.Store.LIDs == nil || cli.Store.PrivacyTokens == nil {
		return participantAddSnapshot{}, errGuardedParticipants
	}
	if target.JID.Server == types.HiddenUserServer {
		pn, err := cli.Store.LIDs.GetPNForLID(ctx, target.JID)
		if err != nil || pn != target.PhoneNumber {
			return participantAddSnapshot{}, errGuardedParticipants
		}
		if err := checkParticipantPreparation(ctx, check); err != nil {
			return participantAddSnapshot{}, err
		}
	}
	storageJID := target.JID
	if target.JID.Server == types.DefaultUserServer {
		lid, err := cli.Store.LIDs.GetLIDForPN(ctx, target.JID)
		if err != nil {
			return participantAddSnapshot{}, errGuardedParticipants
		}
		if !lid.IsEmpty() {
			if !canonicalParticipantJID(lid) || lid.Server != types.HiddenUserServer {
				return participantAddSnapshot{}, errGuardedParticipants
			}
			pn, err := cli.Store.LIDs.GetPNForLID(ctx, lid)
			if err != nil || pn != target.PhoneNumber {
				return participantAddSnapshot{}, errGuardedParticipants
			}
			storageJID = lid
		}
		if err := checkParticipantPreparation(ctx, check); err != nil {
			return participantAddSnapshot{}, err
		}
	}
	token, err := cli.ensureTCToken(ctx, target.JID)
	if err != nil || len(token) > 4096 {
		return participantAddSnapshot{}, errGuardedParticipants
	}
	if err := checkParticipantPreparation(ctx, check); err != nil {
		return participantAddSnapshot{}, err
	}
	// ensureTCToken may itself resolve PN-to-LID: verify that its cached binding
	// did not change between preparation reads before exposing copied token bytes.
	if target.JID.Server == types.DefaultUserServer {
		current, err := cli.Store.LIDs.GetLIDForPN(ctx, target.JID)
		if current.IsEmpty() {
			current = target.JID
		}
		if err != nil || current != storageJID {
			return participantAddSnapshot{}, errGuardedParticipants
		}
	} else {
		current, err := cli.Store.LIDs.GetPNForLID(ctx, target.JID)
		if err != nil || current != target.PhoneNumber {
			return participantAddSnapshot{}, errGuardedParticipants
		}
	}
	if err := checkParticipantPreparation(ctx, check); err != nil {
		return participantAddSnapshot{}, err
	}
	return participantAddSnapshot{token: bytes.Clone(token), storageJID: storageJID}, nil
}

// UpdateGroupParticipantsGuarded preserves cached native add preparation, owns all
// input, and sends one NoRetry IQ under the original physical frame authority.
// Both callbacks must be trusted application authority, never model assertions.
func (cli *Client) UpdateGroupParticipantsGuarded(ctx context.Context, jid types.JID, targets []GroupParticipantUpdateTarget, action ParticipantChange, prepare, beforeWrite func(context.Context) error) ([]GroupParticipantUpdateResult, error) {
	if prepare == nil || beforeWrite == nil {
		return nil, socket.ErrFrameAuthority
	}
	if cli == nil {
		return nil, ErrClientIsNil
	}
	targets = slices.Clone(targets)
	if err := validateParticipantUpdate(jid, targets, action); err != nil {
		return nil, err
	}
	if err := checkParticipantPreparation(ctx, prepare); err != nil {
		return nil, err
	}
	content := make([]waBinary.Node, len(targets))
	snapshots := make([]participantAddSnapshot, len(targets))
	for i, target := range targets {
		content[i] = waBinary.Node{Tag: "participant", Attrs: waBinary.Attrs{"jid": target.JID}}
		if action == ParticipantChangeAdd {
			snapshot, err := cli.participantAddEvidence(ctx, target, prepare)
			if err != nil {
				return nil, err
			}
			snapshots[i] = snapshot
			token := snapshot.token
			if target.JID.Server == types.HiddenUserServer {
				content[i].Attrs["phone_number"] = target.PhoneNumber
			}
			if len(token) > 0 {
				content[i].Content = []waBinary.Node{{Tag: "privacy", Content: token}}
			}
		}
	}
	id := cli.generateRequestID()
	checkSnapshots := func(ctx context.Context) error {
		if err := checkParticipantPreparation(ctx, prepare); err != nil {
			return err
		}
		if action == ParticipantChangeAdd {
			for i, target := range targets {
				snapshot, err := cli.participantAddEvidence(ctx, target, prepare)
				if err != nil || snapshot.storageJID != snapshots[i].storageJID || !bytes.Equal(snapshot.token, snapshots[i].token) {
					return socket.ErrFrameAuthority
				}
			}
		}
		return nil
	}
	guard := func(ctx context.Context) error {
		if err := checkSnapshots(ctx); err != nil {
			return err
		}
		if err := beforeWrite(ctx); err != nil {
			return err
		}
		return checkSnapshots(ctx)
	}
	node, err := cli.sendIQ(ctx, infoQuery{Namespace: "w:g2", Type: iqSet, To: jid, ID: id, NoRetry: true, BeforeWrite: guard, Content: []waBinary.Node{{Tag: string(action), Content: content}}})
	if err != nil {
		return nil, errGuardedParticipants
	}
	return parseGuardedParticipantResults(node, jid, id, targets, action)
}

func parseGuardedParticipantResults(node *waBinary.Node, jid types.JID, id string, targets []GroupParticipantUpdateTarget, action ParticipantChange) ([]GroupParticipantUpdateResult, error) {
	if validateParticipantUpdate(jid, targets, action) != nil || node == nil || node.Tag != "iq" || len(node.Attrs) != 3 || node.Attrs["id"] != id || id == "" || node.Attrs["type"] != "result" || node.Attrs["from"] != jid {
		return nil, errGuardedParticipants
	}
	children, ok := node.Content.([]waBinary.Node)
	if !ok || len(children) != 1 || children[0].Tag != string(action) || len(children[0].Attrs) != 0 {
		return nil, errGuardedParticipants
	}
	participants, ok := children[0].Content.([]waBinary.Node)
	if !ok || len(participants) != len(targets) {
		return nil, errGuardedParticipants
	}
	wanted := make(map[types.JID]bool, len(targets))
	for _, target := range targets {
		wanted[target.JID] = true
	}
	results := make([]GroupParticipantUpdateResult, 0, len(targets))
	for _, child := range participants {
		if child.Tag != "participant" || len(child.Attrs) > 6 {
			return nil, errGuardedParticipants
		}
		for key := range child.Attrs {
			switch key {
			case "jid", "error", "type", "phone_number", "lid", "display_name":
			default:
				return nil, errGuardedParticipants
			}
		}
		attrs := child.AttrGetter()
		parsed := parseParticipant(attrs, &child)
		if attrs.Error() != nil || !wanted[parsed.JID] || parsed.Error < 0 || parsed.Error > 9999 || len(parsed.DisplayName) > 4096 {
			return nil, errGuardedParticipants
		}
		delete(wanted, parsed.JID)
		if child.Content != nil {
			nested, ok := child.Content.([]waBinary.Node)
			if !ok || len(nested) != 1 || nested[0].Tag != "add_request" || len(nested[0].Attrs) != 2 || nested[0].Content != nil || parsed.AddRequest == nil || action != ParticipantChangeAdd || parsed.Error == 0 {
				return nil, errGuardedParticipants
			}
			add := nested[0].AttrGetter()
			code, expiration := add.String("code"), add.UnixTime("expiration")
			if add.Error() != nil || len(code) < 1 || len(code) > 256 || expiration.Unix() <= 0 {
				return nil, errGuardedParticipants
			}
		}
		results = append(results, GroupParticipantUpdateResult{JID: parsed.JID, Error: parsed.Error, InvitationRequired: parsed.AddRequest != nil})
	}
	return results, nil
}
