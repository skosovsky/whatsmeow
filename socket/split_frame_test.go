package socket

import (
	"bytes"
	"testing"
)

func TestReviewSplitFrameReassembly(t *testing.T) {
	// Arrange: one six-byte Noise payload split across two websocket messages.
	fs := &FrameSocket{Frames: make(chan []byte, 1)}
	// Act.
	fs.processData([]byte{0, 0, 6, 'a', 'b', 'c', 'd'})
	fs.processData([]byte{'e', 'f'})
	// Assert.
	select {
	case got := <-fs.Frames:
		if !bytes.Equal(got, []byte("abcdef")) {
			t.Fatalf("payload corruption: %x", got)
		}
	default:
		t.Fatal("frame not delivered")
	}
}
