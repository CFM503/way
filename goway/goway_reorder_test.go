package main

// Regression tests for the v1.8.15 fast-path frame-REORDER bug (fixed by the
// inFlight gate in MuxStream/MuxServerStream.enqueueDataFrame).
//
// Mechanism being guarded: with the stream's byte budget nearly full, a
// large frame A misses the budget and falls back to ingress; deliveryLoop
// dequeues A and PushDataFrame STALLS (releasing bufMu while waiting on
// hasSpace). Without the inFlight == 0 gate, a later SMALL frame B passed
// the fast path (len(ingress)==0 + budget fits) and overtook the stalled
// A — same-stream FIFO violation. Confirmed 3/3 before the fix.
//
// Deterministic sequence used here: fill the budget with 144 real 65535B
// fast-path frames (144*65535 = limit-144), then enqueue A (misses budget,
// stalls in PushDataFrame), then B (fits budget but inFlight==1 forces the
// fallback behind A). Consuming one frame's worth of bytes wakes A; both
// must then emerge in enqueue order (A before B).

import (
	"bytes"
	"testing"
	"time"
)

type reorderMockSession struct{}

func (m *reorderMockSession) SendFrame(streamID uint32, cmd byte, payload []byte) error {
	return nil
}
func (m *reorderMockSession) RemoveStream(streamID uint32) {}

const (
	reorderFillFrames = 144 // 144*65535 = mux*StreamBufferLimit - 144
	reorderFrameSize  = 65535
)

// waitQueueDepth polls until the stream's delivery channel holds want
// frames (with a timeout), so both stalled frames have settled.
func waitQueueDepth(t *testing.T, depth func() int, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if depth() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("queue never reached %d frames (now %d)", want, depth())
}

// waitIngressDrained waits until deliveryLoop has dequeued everything from
// ingress (the stalled frame is now inside PushDataFrame's wait).
func waitIngressDrained(t *testing.T, depth func() int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if depth() == 0 {
			time.Sleep(50 * time.Millisecond) // let PushDataFrame enter its wait
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("ingress never drained")
}

func TestMuxStreamFastPathCannotReorderUnderBackpressure(t *testing.T) {
	s := newMuxStream(7, &reorderMockSession{})
	defer s.Close()

	fill := bytes.Repeat([]byte{0xCC}, reorderFrameSize)
	for i := 0; i < reorderFillFrames; i++ {
		if !s.enqueueDataFrame(muxDataFrame{data: fill}) {
			t.Fatalf("fill frame %d rejected", i)
		}
	}

	big := bytes.Repeat([]byte{0xAA}, reorderFrameSize) // A: misses the budget
	if !s.enqueueDataFrame(muxDataFrame{data: big}) {
		t.Fatalf("enqueue A failed")
	}
	waitIngressDrained(t, func() int {
		s.bufMu.Lock()
		defer s.bufMu.Unlock()
		return len(s.ingress)
	})

	small := []byte{0xBB} // B: fits the budget, but must queue behind A
	if !s.enqueueDataFrame(muxDataFrame{data: small}) {
		t.Fatalf("enqueue B failed")
	}

	// Simulate the app consuming one frame: wakes A's stalled PushDataFrame.
	s.consumedBytes(reorderFrameSize)
	waitQueueDepth(t, func() int { return len(s.readChan) }, reorderFillFrames+2)

	buf := make([]byte, reorderFrameSize)
	for i := 0; i < reorderFillFrames; i++ {
		n, err := s.Read(buf)
		if err != nil || n != reorderFrameSize || buf[0] != 0xCC {
			t.Fatalf("fill frame %d: n=%d first=0x%X err=%v", i, n, buf[0], err)
		}
	}
	n, err := s.Read(buf)
	if err != nil || n != reorderFrameSize || buf[0] != 0xAA {
		t.Fatalf("REORDER or corruption: expected stalled frame A (0xAA) after fill, got n=%d first=0x%X err=%v", n, buf[0], err)
	}
	b := make([]byte, 16)
	n, err = s.Read(b)
	if err != nil || n != 1 || b[0] != 0xBB {
		t.Fatalf("expected frame B (0xBB) last, got n=%d first=0x%X err=%v", n, b[0], err)
	}
}

func TestMuxServerStreamFastPathCannotReorderUnderBackpressure(t *testing.T) {
	sess := &MuxServerSession{streams: make(map[uint32]*MuxServerStream), closed: make(chan struct{})}
	s := newMuxServerStream(9, sess)
	defer s.Close()

	fill := bytes.Repeat([]byte{0xCC}, reorderFrameSize)
	for i := 0; i < reorderFillFrames; i++ {
		if !s.enqueueDataFrame(muxDataFrame{data: fill}) {
			t.Fatalf("fill frame %d rejected", i)
		}
	}

	big := bytes.Repeat([]byte{0xAA}, reorderFrameSize)
	if !s.enqueueDataFrame(muxDataFrame{data: big}) {
		t.Fatalf("enqueue A failed")
	}
	waitIngressDrained(t, func() int {
		s.bufMu.Lock()
		defer s.bufMu.Unlock()
		return len(s.ingress)
	})

	small := []byte{0xBB}
	if !s.enqueueDataFrame(muxDataFrame{data: small}) {
		t.Fatalf("enqueue B failed")
	}

	// Simulate the target pump consuming one frame: wakes A's stalled
	// PushDataFrame.
	s.consumedBytes(reorderFrameSize)
	waitQueueDepth(t, func() int { return len(s.writeChan) }, reorderFillFrames+2)

	expect := func(wantLen int, wantFirst byte, what string) {
		t.Helper()
		select {
		case f := <-s.writeChan:
			if len(f.data) != wantLen || f.data[0] != wantFirst {
				t.Fatalf("%s: got len=%d first=0x%X (want len=%d first=0x%X) — REORDER", what, len(f.data), f.data[0], wantLen, wantFirst)
			}
			f.release()
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no frame on writeChan", what)
		}
	}
	for i := 0; i < reorderFillFrames; i++ {
		expect(reorderFrameSize, 0xCC, "fill")
	}
	expect(reorderFrameSize, 0xAA, "stalled frame A")
	expect(1, 0xBB, "frame B")
}
