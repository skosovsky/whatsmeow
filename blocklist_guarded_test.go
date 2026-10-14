package whatsmeow

import (
	"context"
	"errors"
	"strings"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/types"
)

func blocklistResult(id string, items ...waBinary.Node) *waBinary.Node {
	return &waBinary.Node{Tag: "iq", Attrs: waBinary.Attrs{"id": id, "type": "result", "from": types.ServerJID}, Content: []waBinary.Node{{Tag: "list", Content: items}}}
}
func blocklistItem(jid types.JID) waBinary.Node {
	return waBinary.Node{Tag: "item", Attrs: waBinary.Attrs{"jid": jid}}
}

func TestBlockActionRequestAndOpaqueZeroBoundaries(t *testing.T) {
	// Arrange: exact frozen pair and actor, without a network connection.
	valid := BlockActionGuardedRequest{ActorPN: types.NewJID("123", types.DefaultUserServer), ActorLID: types.NewJID("900", types.HiddenUserServer), PhoneJID: types.NewJID("456", types.DefaultUserServer), LIDJID: types.NewJID("777", types.HiddenUserServer), Action: "block"}
	for _, action := range []string{"block", "unblock"} {
		r := valid
		r.Action = action
		if !validBlockActionRequest(r) {
			t.Fatal("valid request refused")
		}
		r.ActorLID = types.JID{}
		if !validBlockActionRequest(r) {
			t.Fatal("absent own LID refused")
		}
	}
	for _, mutate := range []func(*BlockActionGuardedRequest){
		func(r *BlockActionGuardedRequest) { r.ActorPN.Device = 1 },
		func(r *BlockActionGuardedRequest) { r.ActorLID = types.JID{Server: types.HiddenUserServer} },
		func(r *BlockActionGuardedRequest) { r.PhoneJID = r.ActorPN },
		func(r *BlockActionGuardedRequest) { r.LIDJID = r.ActorLID },
		func(r *BlockActionGuardedRequest) { r.PhoneJID.Server = types.GroupServer },
		func(r *BlockActionGuardedRequest) { r.LIDJID.Device = 1 },
		func(r *BlockActionGuardedRequest) { r.Action = "BLOCK" },
	} {
		// Act / Assert: legal JSON shape alone cannot establish actor/self semantics.
		r := valid
		mutate(&r)
		if validBlockActionRequest(r) {
			t.Fatal("invalid semantic request accepted")
		}
	}
	if id, ok := OriginalBlockActionRequestID(context.Background()); ok || id != "" {
		t.Fatal("ordinary context acquired proof")
	}
	if id, ok := OriginalBlockActionRequestID(nil); ok || id != "" {
		t.Fatal("nil context acquired proof")
	}
	guard := func(context.Context) error { return nil }
	var nilClient *Client
	if out, err := nilClient.UpdateBlocklistGuarded(context.Background(), valid, guard, guard); !errors.Is(err, ErrClientIsNil) || out != nil {
		t.Fatal("nil SDK admitted", err)
	}
	if out, err := nilClient.UpdateBlocklistGuarded(nil, valid, guard, guard); !errors.Is(err, socket.ErrFrameAuthority) || out != nil {
		t.Fatal("nil context admitted", err)
	}
	if out, err := nilClient.UpdateBlocklistGuarded(context.Background(), valid, nil, guard); !errors.Is(err, socket.ErrFrameAuthority) || out != nil {
		t.Fatal("nil prepare admitted", err)
	}
	if out, err := nilClient.UpdateBlocklistGuarded(context.Background(), valid, guard, nil); !errors.Is(err, socket.ErrFrameAuthority) || out != nil {
		t.Fatal("nil final guard admitted", err)
	}
	if value, err := (&BlockActionGuardedResult{}).Result(nil, "original", valid); err == nil || value {
		t.Fatal("zero SDK result accepted")
	}
}

func TestStrictBlocklistResponse(t *testing.T) {
	pn, lid := types.NewJID("456", types.DefaultUserServer), types.NewJID("777", types.HiddenUserServer)
	for _, mode := range []string{"valid", "empty", "hash", "nil", "id", "tag", "type", "from", "extra", "missing-list", "many-lists", "list-tag", "list-attr", "hash-type", "hash-limit", "hash-utf8", "list-bytes", "list-count", "item-tag", "item-attr", "item-content", "item-missing", "jid-string", "jid-group", "jid-device", "jid-alpha", "jid-empty", "jid-limit", "duplicate", "skip-invalid"} {
		t.Run(mode, func(t *testing.T) {
			// Arrange: original correlated result; one changed field must fail the whole list.
			node := blocklistResult("original", blocklistItem(pn), blocklistItem(lid))
			list := &node.Content.([]waBinary.Node)[0]
			item := &list.Content.([]waBinary.Node)[0]
			switch mode {
			case "empty":
				list.Content = nil
			case "hash":
				list.Attrs = waBinary.Attrs{"dhash": "opaque"}
			case "nil":
				node = nil
			case "id":
				node.Attrs["id"] = "other"
			case "tag":
				node.Tag = "message"
			case "type":
				node.Attrs["type"] = "get"
			case "from":
				node.Attrs["from"] = pn
			case "extra":
				node.Attrs["extra"] = "private canary"
			case "missing-list":
				node.Content = nil
			case "many-lists":
				node.Content = append(node.Content.([]waBinary.Node), waBinary.Node{Tag: "list"})
			case "list-tag":
				list.Tag = "privacy"
			case "list-attr":
				list.Attrs = waBinary.Attrs{"extra": "private canary"}
			case "hash-type":
				list.Attrs = waBinary.Attrs{"dhash": 123}
			case "hash-limit":
				list.Attrs = waBinary.Attrs{"dhash": strings.Repeat("x", 257)}
			case "hash-utf8":
				list.Attrs = waBinary.Attrs{"dhash": string([]byte{255})}
			case "list-bytes":
				list.Content = []byte("private canary")
			case "list-count":
				list.Content = make([]waBinary.Node, 10001)
			case "item-tag":
				item.Tag = "other"
			case "item-attr":
				item.Attrs["extra"] = "private canary"
			case "item-content":
				item.Content = []waBinary.Node{}
			case "item-missing":
				item.Attrs = nil
			case "jid-string":
				item.Attrs["jid"] = pn.String()
			case "jid-group":
				item.Attrs["jid"] = types.NewJID("123", types.GroupServer)
			case "jid-device":
				j := pn
				j.Device = 1
				item.Attrs["jid"] = j
			case "jid-alpha":
				item.Attrs["jid"] = types.NewJID("hello", types.DefaultUserServer)
			case "jid-empty":
				item.Attrs["jid"] = types.JID{}
			case "jid-limit":
				item.Attrs["jid"] = types.NewJID(strings.Repeat("1", 256), types.DefaultUserServer)
			case "duplicate":
				list.Content = []waBinary.Node{blocklistItem(pn), blocklistItem(pn)}
			case "skip-invalid":
				list.Content = []waBinary.Node{blocklistItem(pn), {Tag: "item", Attrs: waBinary.Attrs{"jid": "private canary"}}}
			}
			// Act.
			out, err := strictBlocklistResponse(node, "original")
			// Assert: malformed children are never omitted to manufacture absence.
			valid := mode == "valid" || mode == "empty" || mode == "hash"
			if valid {
				if err != nil || out == nil || out.DHash != "" {
					t.Fatal("valid result refused", err)
				}
				if mode == "empty" {
					if len(out.JIDs) != 0 {
						t.Fatal("not empty")
					}
				} else {
					if len(out.JIDs) != 2 || out.JIDs[0] != pn || out.JIDs[1] != lid {
						t.Fatal("wrong owned identities")
					}
					list.Content.([]waBinary.Node)[0].Attrs["jid"] = types.NewJID("999", types.HiddenUserServer)
					if out.JIDs[0] != pn {
						t.Fatal("result aliases source")
					}
				}
			} else if !errors.Is(err, errBlocklistResponse) || out != nil || strings.Contains(err.Error(), "canary") {
				t.Fatal("malformed result accepted", err)
			}
		})
	}
}

func TestBlocklistGuardedMissingAuthority(t *testing.T) {
	// Arrange: no SDK or transport; authority must be required first.
	var cli *Client
	// Act.
	out, err := cli.GetBlocklistGuarded(context.Background(), nil)
	// Assert.
	if out != nil || !errors.Is(err, socket.ErrFrameAuthority) {
		t.Fatal("authority bypass", err)
	}
	out, err = cli.GetBlocklistGuarded(context.Background(), func(context.Context) error { return nil })
	if out != nil || !errors.Is(err, ErrClientIsNil) {
		t.Fatal("nil client accepted", err)
	}
}
