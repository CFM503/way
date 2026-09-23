package main

import (
	"testing"
	"time"
)

func TestCreditGateUnboundedPasses(t *testing.T) {
	g := newCreditGate()
	if !g.Acquire(1<<20, nil) {
		t.Fatal("unbounded acquire must pass")
	}
}

func TestCreditGateThrottlesUntilRelease(t *testing.T) {
	g := newCreditGate()
	g.Enable(100)
	if !g.Acquire(60, nil) {
		t.Fatal("first acquire must pass")
	}
	done := make(chan bool, 1)
	go func() { done <- g.Acquire(60, nil) }()
	select {
	case <-done:
		t.Fatal("acquire passed without credit")
	case <-time.After(50 * time.Millisecond):
	}
	g.Release(60)
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("release woke waiter with abort")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("release did not wake waiter")
	}
}

func TestCreditGateReleaseCappedAtWindow(t *testing.T) {
	g := newCreditGate()
	g.Enable(100)
	if !g.Acquire(100, nil) {
		t.Fatal("drain failed")
	}
	g.Release(1_000_000)
	if !g.Acquire(100, nil) {
		t.Fatal("one window of credit must be available")
	}
	done := make(chan bool, 1)
	go func() { done <- g.Acquire(1, nil) }()
	select {
	case <-done:
		t.Fatal("window inflated beyond advertised max")
	case <-time.After(50 * time.Millisecond):
	}
	g.Close()
}

func TestCreditGateCloseUnblocksWaiters(t *testing.T) {
	g := newCreditGate()
	g.Enable(1)
	if !g.Acquire(1, nil) {
		t.Fatal("drain failed")
	}
	done := make(chan bool, 1)
	go func() { done <- g.Acquire(64*1024, nil) }()
	time.Sleep(20 * time.Millisecond)
	g.Close()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("closed-state acquire must pass, not abort")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not wake waiter")
	}
	if !g.Acquire(1<<30, nil) {
		t.Fatal("closed gate must stay pass-through")
	}
}

func TestCreditGateWaitChannelAborts(t *testing.T) {
	g := newCreditGate()
	g.Enable(1)
	if !g.Acquire(1, nil) {
		t.Fatal("drain failed")
	}
	wait := make(chan struct{})
	done := make(chan bool, 1)
	go func() { done <- g.Acquire(100, wait) }()
	time.Sleep(20 * time.Millisecond)
	close(wait)
	select {
	case ok := <-done:
		if ok {
			t.Fatal("wait-channel abort must return false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wait-channel close did not abort Acquire")
	}
}

func TestCreditGateOversizedAcquireClampsToWindow(t *testing.T) {
	g := newCreditGate()
	g.Enable(64)
	// Larger than the window: served from a full window instead of
	// waiting forever.
	if !g.Acquire(64*1024, nil) {
		t.Fatal("oversized acquire must clamp to window")
	}
	g.Close()
}

func TestCreditGateEnableIdempotent(t *testing.T) {
	g := newCreditGate()
	g.Enable(100)
	if !g.Acquire(100, nil) {
		t.Fatal("drain failed")
	}
	g.Enable(100)
	done := make(chan bool, 1)
	go func() { done <- g.Acquire(1, nil) }()
	select {
	case <-done:
		t.Fatal("re-enable refilled a live window")
	case <-time.After(50 * time.Millisecond):
	}
	g.Close()
}

func TestApplyPeerVersionEnablesStreamGates(t *testing.T) {
	s := &MuxClientSession{
		streams: make(map[uint32]*MuxStream),
		closed:  make(chan struct{}),
	}
	st := newMuxStream(1, s)
	s.streams[1] = st

	// Payload: [version=1][window_kib=1024 BE].
	payload := []byte{muxProtoVersion, byte(muxInitialWindowKib >> 8), byte(muxInitialWindowKib & 0xff)}
	s.applyPeerVersion(payload)

	if got := s.peerWindow.Load(); got != int64(muxInitialWindowKib)*1024 {
		t.Fatalf("peerWindow = %d, want %d", got, int64(muxInitialWindowKib)*1024)
	}
	if st.sendGate.state.Load() != gateBounded {
		t.Fatal("live stream gate was not enabled by VERSION")
	}

	// A second VERSION must not change the window.
	s.applyPeerVersion([]byte{muxProtoVersion, 0x00, 0x80}) // 128 KiB
	if got := s.peerWindow.Load(); got != int64(muxInitialWindowKib)*1024 {
		t.Fatalf("second VERSION overwrote window: %d", got)
	}

	// Truncated / zero-version payloads are ignored.
	s2 := &MuxClientSession{streams: make(map[uint32]*MuxStream), closed: make(chan struct{})}
	s2.applyPeerVersion([]byte{1, 0})
	s2.applyPeerVersion([]byte{0, 4, 0})
	if s2.peerWindow.Load() != 0 {
		t.Fatal("invalid VERSION payload must be ignored")
	}
}

func TestApplyWindowCreditsStreamGate(t *testing.T) {
	s := &MuxClientSession{
		streams: make(map[uint32]*MuxStream),
		closed:  make(chan struct{}),
	}
	st := newMuxStream(7, s)
	s.streams[7] = st
	st.sendGate.Enable(4096)
	if !st.sendGate.Acquire(4096, nil) {
		t.Fatal("drain failed")
	}

	var wb [4]byte
	putBe32(wb[:], 4096)
	s.applyWindow(7, wb[:])
	if avail := st.sendGate.available.Load(); avail != 4096 {
		t.Fatalf("available = %d, want 4096", avail)
	}

	// Unknown stream id and malformed payloads must not panic.
	s.applyWindow(99, wb[:])
	s.applyWindow(7, []byte{0, 0})
}

func TestVersionPayloadEncoding(t *testing.T) {
	p := []byte{muxProtoVersion, byte(muxInitialWindowKib >> 8), byte(muxInitialWindowKib & 0xff)}
	if len(p) != 3 {
		t.Fatalf("VERSION payload length = %d, want 3", len(p))
	}
	kib := int(p[1])<<8 | int(p[2])
	if kib != muxInitialWindowKib {
		t.Fatalf("decoded kib = %d, want %d", kib, muxInitialWindowKib)
	}
}

func putBe32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
