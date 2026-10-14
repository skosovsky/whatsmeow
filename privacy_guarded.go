// Copyright (c) 2026 Sergey Kosovsky
// SPDX-License-Identifier: MPL-2.0

package whatsmeow

import (
	"context"
	"errors"
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/types"
)

// SetPrivacySettingGuarded sends one privacy mutation with trusted authority
// checked immediately before the physical write. It never retries or accesses
// the privacy cache. A nil error means the exact empty IQ result from the server
// matched the original request ID;
// it does not prove the current privacy snapshot.
func (cli *Client) SetPrivacySettingGuarded(ctx context.Context, name types.PrivacySettingType, value types.PrivacySetting, beforeWrite func(context.Context) error) error {
	if beforeWrite == nil {
		return socket.ErrFrameAuthority
	}
	if cli == nil {
		return ErrClientIsNil
	}
	id := cli.generateRequestID()
	node, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "privacy", Type: iqSet, To: types.ServerJID,
		ID: id, NoRetry: true, BeforeWrite: beforeWrite,
		Content: []waBinary.Node{{Tag: "privacy", Content: []waBinary.Node{{Tag: "category", Attrs: waBinary.Attrs{"name": string(name), "value": string(value)}}}}},
	})
	if err != nil {
		return err
	}
	if node == nil || node.Tag != "iq" || len(node.Attrs) != 3 || node.Attrs["id"] != id || node.Attrs["type"] != "result" || node.Attrs["from"] != types.ServerJID || node.Content != nil {
		return errors.New("privacy mutation response unavailable")
	}
	return nil
}
