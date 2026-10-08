package main

// Regression tests for:
//  1. ingress-overflow self-deadlock: enqueueDataFrame held bufMu while
//     calling Reset()/Close(), whose cleanup re-locks bufMu (sync.Mutex is
//     not reentrant) — froze the whole session read loop.
//  2. premature EOF: readClosed was set as soon as FIN was ENQUEUED, even
//     while it sat in ingress behind undelivered data, so Read could return
//     io.EOF and truncate the stream tail under backpressure.

import (
	"io"
	"testing"
	"time"
)

// runWithin fails the test if fn does not return within d (deadlock guard).
func runWithin(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: did not return within %v (deadlock)", what, d)
	}
}

func TestMuxStreamIngressOverflowDoesNotDeadlock(t *testing.T) {
	s := newMuxStream(11, &reorderMockSession{})
	defer s.Close()

	rejected := false
	runWithin(t, 5*time.Second, "client enqueueDataFrame overflow", func() {
		// readChan (AppQueue) + ingress (IngressQueue) + 1 stalled in
		// PushDataFrame; the next frame must overflow and Reset.
		for i := 0; i < muxStreamAppQueue+muxStreamIngressQueue+16; i++ {
			if !s.enqueueDataFrame(muxDataFrame{data: []byte{byte(i)}}) {
				rejected = true
				return
			}
			if i == muxStreamAppQueue {
				// let deliveryLoop pick a frame and stall on full readChan
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	if !rejected {
		t.Fatalf("expected ingress overflow to reject a frame")
	}
	select {
	case <-s.closed:
	default:
		t.Fatalf("stream should be reset after ingress overflow")
	}
}

func TestMuxServerStreamIngressOverflowDoesNotDeadlock(t *testing.T) {
	sess := &MuxServerSession{streams: make(map[uint32]*MuxServerStream), closed: make(chan struct{})}
	s := newMuxServerStream(13, sess)
	defer s.Close()

	rejected := false
	runWithin(t, 5*time.Second, "server enqueueDataFrame overflow", func() {
		for i := 0; i < muxStreamAppQueue+muxStreamIngressQueue+16; i++ {
			if !s.enqueueDataFrame(muxDataFrame{data: []byte{byte(i)}}) {
				rejected = true
				return
			}
			if i == muxStreamAppQueue {
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	if !rejected {
		t.Fatalf("expected ingress overflow to reject a frame")
	}
	select {
	case <-s.closed:
	default:
		t.Fatalf("stream should be closed after ingress overflow")
	}
}

func TestMuxStreamQueuedFINDoesNotTruncateTail(t *testing.T) {
	s := newMuxStream(15, &reorderMockSession{})
	defer s.Close()

	// Fill readChan so later frames take the ingress (slow) path.
	for i := 0; i < muxStreamAppQueue; i++ {
		if !s.enqueueDataFrame(muxDataFrame{data: []byte{0xCC}}) {
			t.Fatalf("fill frame %d rejected", i)
		}
	}
	if !s.enqueueDataFrame(muxDataFrame{data: []byte{0xDD}}) { // tail data
		t.Fatalf("tail frame rejected")
	}
	if !s.enqueueDataFrame(muxDataFrame{data: nil}) { // FIN behind it
		t.Fatalf("FIN rejected")
	}
	if s.readClosed.Load() {
		t.Fatalf("readClosed set while FIN still queued behind undelivered data")
	}

	got := make([]byte, 0, muxStreamAppQueue+1)
	buf := make([]byte, 64)
	runWithin(t, 5*time.Second, "drain stream", func() {
		for {
			n, err := s.Read(buf)
			got = append(got, buf[:n]...)
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Errorf("unexpected read error: %v", err)
				return
			}
		}
	})
	if len(got) != muxStreamAppQueue+1 || got[len(got)-1] != 0xDD {
		t.Fatalf("tail truncated: got %d bytes (want %d), last=0x%X", len(got), muxStreamAppQueue+1, got[len(got)-1])
	}
	// EOF must be sticky.
	if n, err := s.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("second Read after EOF: n=%d err=%v", n, err)
	}
}
