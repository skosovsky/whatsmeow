// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package socket

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
)

type NoiseSocket struct {
	fs            *FrameSocket
	onFrame       FrameHandler
	writeKey      cipher.AEAD
	readKey       cipher.AEAD
	writeCounter  uint32
	readCounter   uint32
	writeGate     chan struct{}
	writeGateOnce sync.Once
	destroyed     atomic.Bool
	stopConsumer  chan struct{}
}

type DisconnectHandler func(ctx context.Context, socket *NoiseSocket, remote bool)
type FrameHandler func(context.Context, []byte)

func newNoiseSocket(
	fs *FrameSocket,
	writeKey, readKey cipher.AEAD,
	frameHandler FrameHandler,
	disconnectHandler DisconnectHandler,
) (*NoiseSocket, error) {
	ns := &NoiseSocket{
		fs:           fs,
		writeKey:     writeKey,
		readKey:      readKey,
		onFrame:      frameHandler,
		stopConsumer: make(chan struct{}),
	}
	fs.OnDisconnect = func(ctx context.Context, remote bool) {
		disconnectHandler(ctx, ns, remote)
	}
	go ns.consumeFrames(fs.Context(), fs.Frames)
	return ns, nil
}

func (ns *NoiseSocket) consumeFrames(ctx context.Context, frames <-chan []byte) {
	if ctx == nil {
		// ctx being nil implies the connection already closed somehow
		return
	}
	ctxDone := ctx.Done()
	for {
		select {
		case frame := <-frames:
			ns.receiveEncryptedFrame(ctx, frame)
		case <-ctxDone:
			return
		case <-ns.stopConsumer:
			return
		}
	}
}

func generateIV(count uint32) []byte {
	iv := make([]byte, 12)
	binary.BigEndian.PutUint32(iv[8:], count)
	return iv
}

func (ns *NoiseSocket) Stop(disconnect, allowOnDisconnect bool) {
	if ns.destroyed.CompareAndSwap(false, true) {
		close(ns.stopConsumer)
		if !allowOnDisconnect {
			ns.fs.OnDisconnect = nil
		}
		if disconnect {
			ns.fs.Close(websocket.StatusNormalClosure)
		}
	}
}

var errNoiseWritePanic = errors.New("noise frame writer failed")

// SendFrame holds writer admission through the actual websocket write. Cancellation
// cannot abandon a writer goroutine that later emits an authorized frame.
func (ns *NoiseSocket) SendFrame(ctx context.Context, plaintext []byte) error {
	return ns.SendFrameWithGuard(ctx, plaintext, nil)
}

// ErrFrameAuthority deliberately contains no callback diagnostics or payload.
var ErrFrameAuthority = errors.New("frame authority denied")

func checkFrameAuthority(ctx context.Context, check func(context.Context) error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrFrameAuthority
		}
	}()
	if check != nil && check(ctx) != nil {
		return ErrFrameAuthority
	}
	return ctx.Err()
}

// SendFrameWithGuard evaluates trusted authority after writer admission and before encryption.
func (ns *NoiseSocket) SendFrameWithGuard(ctx context.Context, plaintext []byte, beforeWrite func(context.Context) error) (err error) {
	ns.writeGateOnce.Do(func() { ns.writeGate = make(chan struct{}, 1) })
	select {
	case ns.writeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-ns.writeGate }()
	defer func() {
		if recover() != nil {
			err = errNoiseWritePanic
			ns.destroyed.Store(true)
			ns.fs.Close(0)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if ns.destroyed.Load() {
		return ErrSocketClosed
	}
	if err := checkFrameAuthority(ctx, beforeWrite); err != nil {
		return err
	}
	// Encryption counters must never be reused after an uncertain or cancelled write.
	ciphertext := ns.writeKey.Seal(nil, generateIV(ns.writeCounter), plaintext, nil)
	ns.writeCounter++
	err = ns.fs.SendFrameContext(ctx, ciphertext)
	if err != nil {
		ns.destroyed.Store(true)
		// No close control frame is attempted after an ambiguous encrypted write.
		ns.fs.Close(0)
	}
	return err
}

func (ns *NoiseSocket) receiveEncryptedFrame(ctx context.Context, ciphertext []byte) {
	plaintext, err := ns.readKey.Open(ciphertext[:0], generateIV(ns.readCounter), ciphertext, nil)
	ns.readCounter++
	if err != nil {
		ns.fs.log.Warnf("Failed to decrypt frame: %v", err)
		return
	}
	proof := &authenticatedFrame{socket: ns, digest: sha256.Sum256(plaintext)}
	proof.active.Store(true)
	defer proof.active.Store(false)
	ns.onFrame(context.WithValue(ctx, authenticatedFrameKey{}, proof), plaintext)
}

type authenticatedFrameKey struct{}
type authenticatedFrame struct {
	socket *NoiseSocket
	digest [32]byte
	active atomic.Bool
	used   atomic.Bool
}

// ConsumeAuthenticatedFrame proves only the original decrypted receive boundary.
// A captured context cannot mint another proof or bind different bytes/socket.
func (ns *NoiseSocket) ConsumeAuthenticatedFrame(ctx context.Context, data []byte) bool {
	if ns == nil || ctx == nil {
		return false
	}
	p, ok := ctx.Value(authenticatedFrameKey{}).(*authenticatedFrame)
	return ok && p != nil && p.socket == ns && p.active.Load() && p.digest == sha256.Sum256(data) && p.used.CompareAndSwap(false, true)
}

func (ns *NoiseSocket) IsConnected() bool {
	return ns.fs.IsConnected()
}
