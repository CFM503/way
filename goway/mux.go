// goway – mux
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- Mux (Multiplexing) Subsystem ---

const (
	MuxCmdSYN     byte = 0x01 // New Stream: [TargetLen uint16][TargetAddr string][InitialData...]
	MuxCmdDATA    byte = 0x02 // Stream Data: [Data...]
	MuxCmdFIN     byte = 0x03 // Stream Half-Close / EOF
	MuxCmdRST     byte = 0x04 // Stream Abrupt Reset / Error
	MuxCmdVERSION byte = 0x05 // W3: [Version uint8][WindowKib uint16 BE], stream id 0
	MuxCmdWINDOW  byte = 0x06 // W3: [CreditBytes uint32 BE]
	MuxHeaderLen       = 7    // 4B StreamID + 1B Cmd + 2B PayloadLen

	// Client-side Mux stream buffer limit.
	// Invariant: >= muxInitialWindowKib*1024 + muxWindowRefresh, else the
	// ingress queue fills before credit can drain -> spurious RST under
	// high-BDP load (guarded by TestStreamBufferLimitCoversWindow).
	// 9MiB = window (8192KiB) + refresh (1MiB) exactly: the Phase-2 40MiB
	// headroom was sized for the reverted 32MiB window arm and let streams
	// retain pooled frame buffers ~+11% RSS vs v1.8.12 at c32 loopback.
	muxClientStreamBufferLimit = 9 * 1024 * 1024

	// Server-side Mux stream buffer limit.
	// Same window+refresh invariant as the client side.
	muxServerStreamBufferLimit = 9 * 1024 * 1024
	// Frame-count queue depths. PushDataFrame budgets bytes (buffer limits
	// above, 9MiB), so the frame depths must not bind first: at maximum
	// frame size (65535B) a 9MiB budget needs 144 frames; 768 slots keep
	// burst absorption far above the budget (small-frame bursts bind the
	// byte budget before depth, and 768 still bounds the "ingress queue
	// full" reset risk observed under 40ms netem when the window was
	// raised without scaling these). Frame depths only bound burst
	// absorption, never steady-state memory (credit gating does).
	// Invariant guarded by TestStreamBufferLimitCoversWindow.
	muxStreamIngressQueue = 256
	muxStreamAppQueue     = 256 // client readChan / server writeChan depth
	muxPushStallTimeout   = 15 * time.Second

	// W3 flow control: version advertised in VERSION frames, initial
	// per-stream receive window (KiB), and the consumed-byte threshold
	// that triggers a WINDOW refund. Probe-negotiated: peers predating
	// these commands skip them silently, keeping v1 behavior.
	// v1.8.13 Phase 2 tried 32768/8MiB here: 40ms-netem throughput improved
	// (c8/c32 download +10%/+16%) but RSS regressed to concurrency x window
	// (c32: 338MB -> 982MB, sign 10/0) and the forward-optimization rule
	// requires reverting on any metric beyond noise. Data: bench_p2_netem.csv.
	muxProtoVersion     byte = 1
	muxInitialWindowKib      = 8192
	muxWindowRefresh         = 1024 * 1024
	muxWindowMinKib          = 64

	// muxRefundThreshold is the consumed-byte count that triggers a WINDOW
	// refund, clamped to half the advertised window. Without the clamp, a
	// future window smaller than muxWindowRefresh could exhaust the peer's
	// send credit before any refund fires (refundPending never reaches the
	// threshold -> permanent silent stall). Invariant guarded by
	// TestRefundThresholdNeverExceedsHalfWindow.
	muxRefundThreshold = min(muxWindowRefresh, muxInitialWindowKib*1024/2)
)

// muxDataChunkLimit caps one MUX DATA frame's PLAINTEXT payload. Legacy
// mode allows the full uint16 range (65535); AEAD mode must leave room for
// the inline [nonce|tag] overhead so the sealed frame still fits a uint16
// MUX length. main() lowers it to 65535-aeadOverhead under -cipher aead.
var muxDataChunkLimit = 65535

// creditGate throttles sends on one stream once the peer's VERSION frame
// has been observed. Before negotiation it is Unbounded (v1 behavior);
// Close switches it to pass-through so a dying stream can never park a
// sender waiting for WINDOWs that will never arrive.
//
// Forward-optimization note (2026-09-23): the hot path (Acquire fast
// attempt, Release) is lock-free — atomics only. enableMu serializes the
// rare Enable/Close state transitions alone, so steady-state sends never
// take a mutex (the previous per-chunk Mutex/Unlock pair is gone).
type creditGate struct {
	enableMu  sync.Mutex    // serializes Enable/Close transitions only
	state     atomic.Int32  // gateUnbounded | gateBounded | gateClosed
	window    atomic.Int64  // stored before state flips to bounded
	available atomic.Int64  // bounded credit, CAS-consumed
	credit    chan struct{} // buffered(1): credit-release signal
	done      chan struct{} // closed by Close: wakes every waiter
}

const (
	gateUnbounded int32 = 0
	gateBounded   int32 = 1
	gateClosed    int32 = 2
)

func newCreditGate() *creditGate {
	return &creditGate{
		credit: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

// Enable enters bounded mode with the advertised window (idempotent:
// the first VERSION wins and cannot refill a live window). window and
// available are stored before the state flip so any Acquire that observes
// gateBounded also observes a fully initialized window.
func (g *creditGate) Enable(window int64) {
	if window < 1 {
		window = 1
	}
	g.enableMu.Lock()
	if g.state.Load() == gateUnbounded {
		g.window.Store(window)
		g.available.Store(window)
		g.state.Store(gateBounded)
	}
	g.enableMu.Unlock()
}

// Release credits consumed bytes back (capped at the advertised window).
// Lock-free CAS; the token send wakes one blocked Acquire (buffered(1)
// preserves a pending token across races, matching the old semantics).
func (g *creditGate) Release(n int64) {
	if n <= 0 || g.state.Load() != gateBounded {
		return
	}
	w := g.window.Load()
	for {
		avail := g.available.Load()
		next := avail + n
		if next > w {
			next = w
		}
		if g.available.CompareAndSwap(avail, next) {
			break
		}
	}
	select {
	case g.credit <- struct{}{}:
	default:
	}
}

// Close wakes all waiters; subsequent Acquire calls pass through.
func (g *creditGate) Close() {
	g.enableMu.Lock()
	if g.state.Load() != gateClosed {
		g.state.Store(gateClosed)
		close(g.done)
	}
	g.enableMu.Unlock()
}

// Acquire consumes n bytes of credit, blocking while the window is
// exhausted. Returns false only when the caller's wait channel (stream
// closed) fires first; unbounded/closed states return true immediately.
// n is clamped to the window so an oversized frame cannot deadlock.
// Fast path: one state load + one CAS, no mutex.
func (g *creditGate) Acquire(n int, wait <-chan struct{}) bool {
	need := int64(n)
	for {
		if g.state.Load() != gateBounded {
			return true
		}
		if w := g.window.Load(); need > w {
			need = w
		}
		avail := g.available.Load()
		if avail >= need && g.available.CompareAndSwap(avail, avail-need) {
			return true
		}
		select {
		case <-g.credit:
		case <-g.done:
		case <-wait:
			return false
		}
	}
}

// muxDataFrame encapsulates a payload slice along with ownership of a pooled buffer from sync.Pool.
type muxDataFrame struct {
	data []byte
	bPtr *[]byte
	pool *sync.Pool
}

func (f *muxDataFrame) release() {
	if f.bPtr != nil && f.pool != nil {
		f.pool.Put(f.bPtr)
		f.bPtr = nil
		f.pool = nil
	}
	f.data = nil
}

type MuxSessionInterface interface {
	SendFrame(streamID uint32, cmd byte, payload []byte) error
	RemoveStream(streamID uint32)
}

// MuxStream represents an individual multiplexed stream on the client side.
type MuxStream struct {
	id          uint32
	session     MuxSessionInterface
	readChan    chan muxDataFrame
	curFrame    muxDataFrame
	readBuf     []byte
	readPos     int
	closeOnce   sync.Once
	closed      chan struct{}
	readClosed  atomic.Bool
	bufMu       sync.Mutex
	queuedBytes int64
	hasSpace    chan struct{}
	onClose     func()
	readMu      sync.Mutex
	ingress     chan muxDataFrame
	// inFlight counts frames admitted through ingress that have not yet been
	// pushed into readChan (or abandoned). The direct-push fast path in
	// enqueueDataFrame is allowed only while inFlight == 0: a stalled
	// PushDataFrame holds its frame OUTSIDE ingress, so len(ingress)==0 does
	// not imply ordering is safe — without this gate a later smaller frame
	// bypassed the stalled one and reordered the stream (regression test:
	// TestMuxStreamFastPathCannotReorderUnderBackpressure).
	inFlight atomic.Int64
	// W3 upload credit: bounded once the server's VERSION is observed.
	sendGate *creditGate
	// W3 refund accumulator for WINDOW frames (bytes consumed locally).
	refundPending int64
}

func newMuxStream(id uint32, session MuxSessionInterface) *MuxStream {
	st := &MuxStream{id: id, session: session, readChan: make(chan muxDataFrame, muxStreamAppQueue), closed: make(chan struct{}), hasSpace: make(chan struct{}, 1), ingress: make(chan muxDataFrame, muxStreamIngressQueue), sendGate: newCreditGate()}
	go st.deliveryLoop()
	return st
}

func (s *MuxStream) enqueueDataFrame(frame muxDataFrame) bool {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	select {
	case <-s.closed:
		frame.release()
		return false
	default:
	}
	if frame.data == nil {
		s.readClosed.Store(true)
	}
	dataLen := int64(len(frame.data))
	// Fast path: if ingress queue is empty, NO frame is in flight between
	// ingress and readChan (inFlight == 0), and the byte budget allows,
	// bypass deliveryLoop directly into readChan. inFlight gating is what
	// preserves per-stream FIFO: without it a smaller frame overtakes a
	// stalled PushDataFrame (v1.8.15 reorder bug).
	if len(s.ingress) == 0 && s.inFlight.Load() == 0 && s.queuedBytes+dataLen <= muxClientStreamBufferLimit {
		select {
		case s.readChan <- frame:
			s.queuedBytes += dataLen
			return true
		default:
		}
	}
	// Fallback path: queue into ingress for deliveryLoop backpressure handling
	s.inFlight.Add(1)
	select {
	case s.ingress <- frame:
		return true
	default:
		s.inFlight.Add(-1)
		logWarn("[MUX] Stream %d ingress queue full, resetting stream", s.id)
		frame.release()
		s.Reset()
		return false
	}
}

func (s *MuxStream) deliveryLoop() {
	for {
		select {
		case <-s.closed:
			return
		case frame := <-s.ingress:
			if !s.PushDataFrame(frame) {
				frame.release()
			}
			s.inFlight.Add(-1)
		}
	}
}

func (s *MuxStream) PushDataFrame(frame muxDataFrame) bool {
	dataLen := int64(len(frame.data))
	// One reusable stall Timer for the whole call: the old path allocated a
	// fresh time.NewTimer on EVERY backpressure wakeup.
	stall := time.NewTimer(muxPushStallTimeout)
	defer func() {
		if !stall.Stop() {
			select {
			case <-stall.C:
			default:
			}
		}
	}()
	for {
		s.bufMu.Lock()
		select {
		case <-s.closed:
			s.bufMu.Unlock()
			return false
		default:
		}
		if frame.data == nil {
			s.readClosed.Store(true)
		}
		if s.queuedBytes+dataLen <= muxClientStreamBufferLimit {
			select {
			case s.readChan <- frame:
				s.queuedBytes += dataLen
				s.bufMu.Unlock()
				return true
			default:
			}
		}
		s.bufMu.Unlock()
		if !stall.Stop() {
			select {
			case <-stall.C:
			default:
			}
		}
		stall.Reset(muxPushStallTimeout)
		select {
		case <-s.closed:
			return false
		case <-s.hasSpace:
			continue
		case <-stall.C:
			logWarn("[MUX] Stream %d receive backpressure timeout, resetting stream", s.id)
			s.Reset()
			return false
		}
	}
}

func (s *MuxStream) PushData(data []byte) bool {
	return s.PushDataFrame(muxDataFrame{data: data})
}

func (s *MuxStream) PushEOF() {
	s.readClosed.Store(true)
	select {
	case <-s.closed:
	default:
		select {
		case s.readChan <- muxDataFrame{data: nil}:
		default:
		}
	}
}

func (s *MuxStream) consumedBytes(n int) {
	if n <= 0 {
		return
	}
	s.bufMu.Lock()
	s.queuedBytes -= int64(n)
	if s.queuedBytes < 0 {
		s.queuedBytes = 0
	}
	if s.queuedBytes < muxClientStreamBufferLimit {
		select {
		case s.hasSpace <- struct{}{}:
		default:
		}
	}
	s.bufMu.Unlock()
}

func (s *MuxStream) QueuedBytes() int64 {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	return s.queuedBytes
}

func (s *MuxStream) Read(p []byte) (n int, err error) {
	for {
		s.readMu.Lock()
		if s.readPos < len(s.readBuf) {
			n = copy(p, s.readBuf[s.readPos:])
			s.readPos += n
			if s.readPos >= len(s.readBuf) {
				s.curFrame.release()
				s.readBuf = nil
				s.readPos = 0
			}
			s.readMu.Unlock()
			s.consumedBytes(n)
			return n, nil
		}
		if s.readClosed.Load() && len(s.readChan) == 0 {
			s.readMu.Unlock()
			return 0, io.EOF
		}
		s.readMu.Unlock()

		select {
		case <-s.closed:
			s.readMu.Lock()
			s.curFrame.release()
			s.readBuf = nil
			s.readPos = 0
			s.readMu.Unlock()
			if s.readClosed.Load() {
				return 0, io.EOF
			}
			return 0, errors.New("stream closed")
		case frame, ok := <-s.readChan:
			select {
			case <-s.closed:
				frame.release()
				s.readMu.Lock()
				s.curFrame.release()
				s.readBuf = nil
				s.readPos = 0
				s.readMu.Unlock()
				if s.readClosed.Load() {
					return 0, io.EOF
				}
				return 0, errors.New("stream closed")
			default:
			}
			if !ok || frame.data == nil {
				s.readMu.Lock()
				s.curFrame.release()
				s.readBuf = nil
				s.readPos = 0
				s.readMu.Unlock()
				return 0, io.EOF
			}
			s.readMu.Lock()
			s.curFrame = frame
			s.readBuf = frame.data
			s.readPos = 0
			s.readMu.Unlock()
		}
	}
}

func (s *MuxStream) Write(p []byte) (n int, err error) {
	select {
	case <-s.closed:
		return 0, errors.New("stream closed")
	default:
	}
	const maxChunkCap = 65528
	total := len(p)
	for len(p) > 0 {
		chunk := len(p)
		if chunk > maxChunkCap {
			chunk = maxChunkCap
		}
		if chunk > muxDataChunkLimit {
			chunk = muxDataChunkLimit
		}
		// W3 upload gate: bounded once the peer's VERSION arrived.
		if !s.sendGate.Acquire(chunk, s.closed) {
			return total - len(p), errors.New("stream closed")
		}
		if err := s.session.SendFrame(s.id, MuxCmdDATA, p[:chunk]); err != nil {
			return total - len(p), err
		}
		p = p[chunk:]
	}
	return total, nil
}

func (s *MuxStream) cleanup() {
	s.readMu.Lock()
	s.curFrame.release()
	s.readBuf = nil
	s.readPos = 0
	s.readMu.Unlock()
	s.bufMu.Lock()
	s.queuedBytes = 0
	s.bufMu.Unlock()
	for {
		select {
		case f := <-s.readChan:
			f.release()
		default:
			for {
				select {
				case f := <-s.ingress:
					f.release()
				default:
					return
				}
			}
		}
	}
}

func (s *MuxStream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.sendGate.Close()
		s.session.SendFrame(s.id, MuxCmdFIN, nil)
		s.session.RemoveStream(s.id)
		s.cleanup()
		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

func (s *MuxStream) Reset() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.sendGate.Close()
		s.session.SendFrame(s.id, MuxCmdRST, nil)
		s.session.RemoveStream(s.id)
		s.cleanup()
		if s.onClose != nil {
			s.onClose()
		}
	})
}

// MuxClientSession handles a single WebSocket tunnel carrying multiple MuxStreams.
type muxOutboundFrame struct {
	bPtr       *[]byte
	pool       *sync.Pool
	payloadOff int
	payloadLen int
	opcode     byte
	ping       bool
	// MUX routing identity for fair scheduling. streamID selects the
	// per-stream queue; cmd selects the priority lane (everything except
	// MuxCmdDATA is latency-sensitive control traffic).
	streamID uint32
	cmd      byte
}

// muxStreamQueue is one stream's FIFO inside the fair writer, with a
// deficit-round-robin byte credit.
type muxStreamQueue struct {
	frames  []muxOutboundFrame
	deficit int
}

// muxOutboundWriter serializes frames from all streams of one MUX session
// onto a single WebSocket connection with per-stream fairness.
//
// The previous design drained a single FIFO channel: one bulk stream could
// bury interactive streams behind megabytes of queued data (a stalled video
// that only recovers on refresh). This design keeps one FIFO per stream
// plus a priority lane, scheduled as:
//
//  1. priority lane first: ping + SYN/FIN/RST control frames;
//  2. deficit round robin across streams (64KB quantum each) for DATA.
//
// enqueue() blocks when the total queued backlog reaches
// muxOutboundQueueDepth, preserving the old backpressure contract.
// Locks are never held across network IO.
type muxOutboundWriter struct {
	conn     net.Conn
	prng     *maskPRNG
	crypto   *Crypto
	masked   bool
	mu       sync.Mutex
	cond     *sync.Cond
	streams  map[uint32]*muxStreamQueue
	rotation []uint32
	pos      int
	priority []muxOutboundFrame
	total    int
	closed   bool
	done     chan struct{}
	closeMu  sync.Once
	// writeTimeout bounds each egress write; 0 disables (test fixtures).
	// lastWriteSet is only touched by the loop goroutine.
	writeTimeout time.Duration
	lastWriteSet time.Time
	// scratch is the loop goroutine's writev batch buffer (Phase 4).
	scratch []muxOutboundFrame
	// scratchBufs is the loop goroutine's reused net.Buffers slice (zero heap alloc).
	scratchBufs net.Buffers
	// batchMax caps the writev drain (1 = single-frame fast link, up to
	// muxWritevMaxFrames on weak-net); set once from the handshake
	// classification before loop() starts, read-only afterwards.
	batchMax int
}

const (
	// Total queued frames across all streams + priority lane. Raised from
	// the old FIFO depth of 8: fairness now protects interactive streams,
	// so bulk streams may use deeper backlog (~4MB worst case at 64KB).
	muxOutboundQueueDepth = 64
	// Per-stream byte credit added each deficit round.
	// Set to 128KB so that even maximum-size MUX frames with -obfs padding (~67KB)
	// can be dispatched in a single round without deficit underflow stall.
	muxDRRQuantum = 128 * 1024
	// Cap accumulated credit so a long-idle stream cannot hog the link.
	muxDRRMaxDeficit = 512 * 1024
	// Max random padding appended to MUX DATA frames when -obfs is on.
	// Sized near MTU so padded lengths spread across the full range.
	obfsPadMax = 1400
	// Phase 4 writev: coalesce scheduled frames per egress syscall.
	// Adaptive cap by handshake classification: loopback/low-RTT links
	// regress -3~12% c32 throughput with multi-frame batches (writev burst
	// serializes send/recv on the same host), while weak-net (40ms) gains
	// up to +21% c32 up. The mux handshake duration (~2-3 RTT) classifies
	// the link once per session: slow -> batch up to muxWritevMaxFrames,
	// fast -> single-frame writes. No per-write state (write-duration EMA
	// proved unusable: loopback backpressure blocks writes too).
	muxWritevMaxFrames = 8
	muxWritevMaxBytes  = 256 * 1024
	// Handshake durations above this classify the link as weak-net
	// (RTT-bound) -> enable writev batching; at/below -> single-frame.
	// Loopback/LAN setups measure <10ms, 40ms netem ~80-120ms.
	muxWritevSlowLinkSetup = 30 * time.Millisecond
)

func newMuxOutboundWriter(conn net.Conn, prng *maskPRNG, crypto *Crypto, masked bool, writeTimeout time.Duration) *muxOutboundWriter {
	return newMuxOutboundWriterBatched(conn, prng, crypto, masked, writeTimeout, muxWritevMaxFrames)
}

// newMuxOutboundWriterBatched is newMuxOutboundWriter with an explicit
// writev batch cap chosen by the caller's handshake classification.
func newMuxOutboundWriterBatched(conn net.Conn, prng *maskPRNG, crypto *Crypto, masked bool, writeTimeout time.Duration, batchMax int) *muxOutboundWriter {
	w := &muxOutboundWriter{
		conn:         conn,
		prng:         prng,
		crypto:       crypto,
		masked:       masked,
		streams:      make(map[uint32]*muxStreamQueue),
		done:         make(chan struct{}),
		writeTimeout: writeTimeout,
		batchMax:     batchMax,
		scratchBufs:  make(net.Buffers, 0, muxWritevMaxFrames),
	}
	w.cond = sync.NewCond(&w.mu)
	go w.loop()
	return w
}

// writevBatchFor maps a mux handshake duration (~2-3 RTT) to the egress
// writev batch cap: weak-net (slow setup) batches, fast links stay
// single-frame.
func writevBatchFor(setupDur time.Duration) int {
	if setupDur > muxWritevSlowLinkSetup {
		return muxWritevMaxFrames
	}
	return 1
}

func (w *muxOutboundWriter) releaseFrame(f muxOutboundFrame) {
	if f.bPtr != nil && f.pool != nil {
		f.pool.Put(f.bPtr)
	}
}

// frameWireLen is the on-wire MUX cost of a queued frame (header included),
// used for deficit accounting.
func frameWireLen(f muxOutboundFrame) int {
	if f.payloadLen > 0 {
		return f.payloadLen
	}
	return MuxHeaderLen
}

func (w *muxOutboundWriter) writeFrame(f muxOutboundFrame) error {
	if f.ping {
		return writeWSFrame(w.conn, nil, 0x9, w.masked)
	}
	slice, err := w.encodeFrame(f)
	if err != nil {
		return err
	}
	_, err = w.conn.Write(slice)
	return err
}

// encodeFrame renders a data frame (header + mask + cipher) in place inside
// its pooled buffer and returns the wire slice. No copy, no syscall. In
// AEAD mode the payload was already sealed at enqueue time, so crypto is
// dropped here (mask-only/header-only encode).
func (w *muxOutboundWriter) encodeFrame(f muxOutboundFrame) ([]byte, error) {
	if f.bPtr == nil || f.pool == nil {
		return nil, errors.New("invalid mux outbound frame")
	}
	if w.masked {
		return encodeMuxFrameFused(*f.bPtr, f.payloadOff, f.payloadLen, f.opcode, w.prng, w.crypto.xorOnly())
	}
	return encodeMuxFrameUnmasked(*f.bPtr, f.payloadOff, f.payloadLen, f.opcode, w.crypto.xorOnly())
}

// dropAllLocked releases every queued frame and resets scheduling state.
// Caller must hold w.mu.
func (w *muxOutboundWriter) dropAllLocked() {
	for _, f := range w.priority {
		w.releaseFrame(f)
	}
	w.priority = nil
	for _, q := range w.streams {
		for _, f := range q.frames {
			w.releaseFrame(f)
		}
	}
	w.streams = make(map[uint32]*muxStreamQueue)
	w.rotation = nil
	w.pos = 0
	w.total = 0
}

// removeLocked deletes one stream's queue. Caller must hold w.mu; it
// returns the doomed frames for release AFTER unlock to keep the critical
// section free of foreign calls.
func (w *muxOutboundWriter) removeLocked(id uint32) []muxOutboundFrame {
	q := w.streams[id]
	if q == nil {
		return nil
	}
	doomed := q.frames
	delete(w.streams, id)
	for i, sid := range w.rotation {
		if sid == id {
			w.rotation = append(w.rotation[:i], w.rotation[i+1:]...)
			if w.pos > i {
				w.pos--
			}
			break
		}
	}
	if w.pos >= len(w.rotation) {
		w.pos = 0
	}
	return doomed
}

func (w *muxOutboundWriter) loop() {
	defer close(w.done)
	for {
		f, ok := w.next()
		if !ok {
			return
		}
		// Phase 4: coalesce already-queued frames into one writev syscall.
		// tryNext never blocks, so batching adds no latency for idle links;
		// DRR fairness and frame order are unchanged (popLocked sequence).
		batch := append(w.scratch[:0], f)
		batchBytes := frameWireLen(f) + MuxHeaderLen + 14
		for len(batch) < w.batchMax && batchBytes < muxWritevMaxBytes {
			f2, ok2 := w.tryNext()
			if !ok2 {
				break
			}
			batch = append(batch, f2)
			batchBytes += frameWireLen(f2) + MuxHeaderLen + 14
		}
		w.scratch = batch
		refreshWriteDeadline(w.conn, w.writeTimeout, &w.lastWriteSet)
		err := w.writeBatch(batch)
		for i := range batch {
			w.releaseFrame(batch[i])
		}
		if err != nil {
			w.mu.Lock()
			w.closed = true
			w.dropAllLocked()
			w.cond.Broadcast()
			w.mu.Unlock()
			_ = w.conn.Close()
			return
		}
	}
}

// writeBatch sends one or more already-scheduled frames as a single
// net.Buffers.WriteTo (one writev syscall for TCP). Ping frames keep their
// existing encode path and flush the accumulator first.
func (w *muxOutboundWriter) writeBatch(batch []muxOutboundFrame) error {
	if len(batch) == 1 {
		return w.writeFrame(batch[0])
	}
	w.scratchBufs = w.scratchBufs[:0]
	for i := range batch {
		f := batch[i]
		if f.ping {
			if len(w.scratchBufs) > 0 {
				if _, err := w.scratchBufs.WriteTo(w.conn); err != nil {
					return err
				}
				w.scratchBufs = w.scratchBufs[:0]
			}
			if err := w.writeFrame(f); err != nil {
				return err
			}
			continue
		}
		slice, err := w.encodeFrame(f)
		if err != nil {
			return err
		}
		w.scratchBufs = append(w.scratchBufs, slice)
	}
	if len(w.scratchBufs) == 0 {
		return nil
	}
	_, err := w.scratchBufs.WriteTo(w.conn)
	return err
}

// next pops the next frame to send: priority lane first, then deficit
// round robin. Never holds the lock across network IO.
func (w *muxOutboundWriter) next() (muxOutboundFrame, bool) {
	var empty muxOutboundFrame
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		if f, ok := w.popLocked(); ok {
			return f, true
		}
		if w.closed {
			return empty, false
		}
		w.cond.Wait()
	}
}

// tryNext pops a ready frame without blocking (writev batch drain).
func (w *muxOutboundWriter) tryNext() (muxOutboundFrame, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.popLocked()
}

// popLocked serves one ready frame. Caller must hold w.mu.
func (w *muxOutboundWriter) popLocked() (muxOutboundFrame, bool) {
	var empty muxOutboundFrame
	// Scan priority queue to find the first unblocked control frame.
	// Only stream-CLOSING controls (FIN/RST) yield while their own
	// stream still has pending DATA frames — else the peer closes
	// early and drops the tail. SYN never yields: it creates the
	// peer-side stream, so yielding it makes the peer drop its own
	// DATA as unknown-stream (caught live on the RushWay side: full
	// flows vanishing under burst with zero error logs).
	// Frames for other streams (or pings) are never head-of-line blocked.
	for i := 0; i < len(w.priority); i++ {
		f := w.priority[i]
		blocked := false
		if !f.ping && f.streamID != 0 && (f.cmd == MuxCmdFIN || f.cmd == MuxCmdRST) {
			if q := w.streams[f.streamID]; q != nil && len(q.frames) > 0 {
				blocked = true
			}
		}
		if !blocked {
			w.priority = append(w.priority[:i], w.priority[i+1:]...)
			w.total--
			w.cond.Signal()
			return f, true
		}
	}
	if f, ok := w.nextDataLocked(); ok {
		w.total--
		w.cond.Signal()
		return f, true
	}
	return empty, false
}

// nextDataLocked serves one frame by deficit round robin. Caller must hold w.mu.
func (w *muxOutboundWriter) nextDataLocked() (muxOutboundFrame, bool) {
	var empty muxOutboundFrame
	if len(w.rotation) == 0 {
		return empty, false
	}
	for {
		hasFrames := false
		start := w.pos % len(w.rotation)
		for k := 0; k < len(w.rotation); k++ {
			idx := (start + k) % len(w.rotation)
			id := w.rotation[idx]
			q := w.streams[id]
			if q == nil || len(q.frames) == 0 {
				continue
			}
			hasFrames = true
			q.deficit += muxDRRQuantum
			if q.deficit > muxDRRMaxDeficit {
				q.deficit = muxDRRMaxDeficit
			}
			head := q.frames[0]
			if frameWireLen(head) > q.deficit {
				continue
			}
			q.frames[0] = muxOutboundFrame{}
			q.frames = q.frames[1:]
			q.deficit -= frameWireLen(head)
			if len(q.frames) == 0 {
				delete(w.streams, id)
				w.rotation = append(w.rotation[:idx], w.rotation[idx+1:]...)
			}
			// Advance PAST the served stream so the next round starts with
			// its successor (strict rotation; idx would stick to one bulk
			// stream otherwise).
			w.pos = idx + 1
			return head, true
		}
		if !hasFrames {
			return empty, false
		}
	}
}

func (w *muxOutboundWriter) enqueue(f muxOutboundFrame) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for w.total >= muxOutboundQueueDepth && !w.closed {
		w.cond.Wait()
	}
	if w.closed {
		w.releaseFrame(f)
		return false
	}
	if f.ping || (f.cmd != 0 && f.cmd != MuxCmdDATA) {
		w.priority = append(w.priority, f)
	} else {
		q := w.streams[f.streamID]
		if q == nil {
			q = &muxStreamQueue{}
			w.streams[f.streamID] = q
			w.rotation = append(w.rotation, f.streamID)
		}
		q.frames = append(q.frames, f)
	}
	w.total++
	w.cond.Signal()
	return true
}

func (w *muxOutboundWriter) enqueuePing() bool {
	return w.enqueue(muxOutboundFrame{ping: true})
}

// dropStream discards a dead stream's queued frames so they neither block
// the rotation nor leak pool buffers.
func (w *muxOutboundWriter) dropStream(id uint32) {
	w.mu.Lock()
	doomed := w.removeLocked(id)
	for range doomed {
		w.total--
	}
	w.cond.Broadcast()
	w.mu.Unlock()
	for _, f := range doomed {
		w.releaseFrame(f)
	}
}

func (w *muxOutboundWriter) close() {
	w.closeMu.Do(func() {
		w.mu.Lock()
		w.closed = true
		w.dropAllLocked()
		w.cond.Broadcast()
		w.mu.Unlock()
	})
	<-w.done
}

type MuxClientSession struct {
	wsConn        net.Conn
	br            *bufio.Reader
	wsTCPConn     *net.TCPConn
	cfg           *Config
	streams       map[uint32]*MuxStream
	streamsMu     sync.RWMutex
	nextStreamID  uint32
	closed        chan struct{}
	closeOnce     sync.Once
	prng          *maskPRNG
	writer        *muxOutboundWriter
	activeStreams atomic.Int64
	// W3: peer-advertised receive window in bytes (0 = not negotiated).
	peerWindow atomic.Int64
}

func (s *MuxClientSession) ActiveStreams() int64 {
	cnt := s.activeStreams.Load()
	if cnt < 0 {
		return 0
	}
	return cnt
}

func (s *MuxClientSession) decrementActiveStreams() {
	for {
		cur := s.activeStreams.Load()
		if cur <= 0 {
			s.activeStreams.Store(0)
			return
		}
		if s.activeStreams.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

func newMuxClientSession(wsConn net.Conn, br *bufio.Reader, wsTCPConn *net.TCPConn, cfg *Config, setupDur time.Duration) *MuxClientSession {
	prng := maskPool.Get().(*maskPRNG)
	s := &MuxClientSession{wsConn: wsConn, br: br, wsTCPConn: wsTCPConn, cfg: cfg, streams: make(map[uint32]*MuxStream), closed: make(chan struct{}), prng: prng}
	s.writer = newMuxOutboundWriterBatched(wsConn, prng, cfg.Crypto, true, time.Duration(cfg.ConnTimeout)*time.Second, writevBatchFor(setupDur))
	// W3 version negotiation: advertise our version + initial receive
	// window right after the session handshake. Old servers skip the
	// unknown command; new servers answer with their own VERSION.
	s.SendFrame(0, MuxCmdVERSION, []byte{muxProtoVersion, byte(muxInitialWindowKib >> 8), byte(muxInitialWindowKib & 0xff)})
	go s.readLoop()
	go s.heartbeatLoop()
	return s
}

// applyPeerVersion records the peer's advertised window (first VERSION
// wins) and retroactively enables bounded sends on every live stream.
func (s *MuxClientSession) applyPeerVersion(payload []byte) {
	if len(payload) != 3 || payload[0] < 1 || s.peerWindow.Load() != 0 {
		return
	}
	kib := int(binary.BigEndian.Uint16(payload[1:3]))
	if kib < muxWindowMinKib {
		kib = muxWindowMinKib
	}
	window := int64(kib) * 1024
	s.peerWindow.Store(window)
	s.streamsMu.RLock()
	for _, st := range s.streams {
		st.sendGate.Enable(window)
	}
	s.streamsMu.RUnlock()
	logDebug("[CLIENT-MUX] peer VERSION received; send window enabled (kib=%d)", kib)
}

// applyWindow refunds upload credit for one stream.
func (s *MuxClientSession) applyWindow(streamID uint32, payload []byte) {
	if len(payload) != 4 {
		return
	}
	credit := binary.BigEndian.Uint32(payload)
	if credit == 0 || uint64(credit) > uint64(muxInitialWindowKib)*1024*64 {
		return
	}
	s.streamsMu.RLock()
	st, ok := s.streams[streamID]
	s.streamsMu.RUnlock()
	if ok {
		st.sendGate.Release(int64(credit))
	}
}

// muxHeartbeatInterval is the client keepalive ping period. Package-level
// var so tests can shorten it.
var muxHeartbeatInterval = 25 * time.Second

func (s *MuxClientSession) heartbeatLoop() {
	ticker := time.NewTicker(muxHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			// Ping unconditionally whenever the writer is up. The previous
			// condition (skip while streams exist) meant an active-but-idle
			// session — open streams, no traffic — never pinged, both sides'
			// rolling read deadlines fired at ConnTimeout (60s), and Close
			// reset EVERY stream (paused video, idle SSH). Any received frame
			// refreshes the peer's deadline; peers auto-pong (readWSFrameInto
			// 0x9/0xA handling), so 24B/interval keeps the tunnel alive.
			if s.writer == nil {
				continue
			}
			_ = s.writer.enqueuePing()
		}
	}
}

func (s *MuxClientSession) IsAlive() bool {
	select {
	case <-s.closed:
		return false
	default:
		return true
	}
}

func (s *MuxClientSession) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.wsConn != nil {
			_ = s.wsConn.Close()
		}
		if s.writer != nil {
			s.writer.close()
		}
		s.streamsMu.Lock()
		activeStreams := make([]*MuxStream, 0, len(s.streams))
		for _, st := range s.streams {
			activeStreams = append(activeStreams, st)
		}
		s.streams = make(map[uint32]*MuxStream)
		s.streamsMu.Unlock()
		for _, st := range activeStreams {
			st.Reset()
		}
		if s.prng != nil {
			maskPool.Put(s.prng)
			s.prng = nil
		}
	})
}

func (s *MuxClientSession) RemoveStream(streamID uint32) {
	s.streamsMu.Lock()
	delete(s.streams, streamID)
	s.streamsMu.Unlock()
	if s.writer != nil {
		s.writer.dropStream(streamID)
	}
}

func (s *MuxClientSession) SendFrame(streamID uint32, cmd byte, payload []byte) error {
	select {
	case <-s.closed:
		return errors.New("mux session closed")
	default:
	}
	if s.wsConn == nil || s.cfg == nil || s.cfg.BufPool == nil || s.writer == nil {
		return nil
	}
	payloadLen := len(payload)
	if payloadLen > 65535 {
		return fmt.Errorf("mux frame payload %d exceeds maximum uint16 length (65535)", payloadLen)
	}
	aead := s.cfg.Crypto != nil && !s.cfg.Crypto.isXOR()
	wireLen := payloadLen
	if aead && payloadLen > 0 {
		wireLen += aeadOverhead
	}
	frameLen := MuxHeaderLen + wireLen
	bPtr := s.cfg.BufPool.Get().(*[]byte)
	buf := *bPtr
	if frameLen+14 > len(buf) {
		s.cfg.BufPool.Put(bPtr)
		return errors.New("mux frame exceeds buffer size")
	}
	frameStart := 14
	binary.BigEndian.PutUint32(buf[frameStart:frameStart+4], streamID)
	buf[frameStart+4] = cmd
	binary.BigEndian.PutUint16(buf[frameStart+5:frameStart+7], uint16(wireLen))
	if payloadLen > 0 {
		copy(buf[frameStart+7:frameStart+7+payloadLen], payload)
		if aead {
			// AEAD: plaintext becomes [nonce|ct|tag] in place; the MUX
			// header above already declares the sealed (wire) length.
			s.cfg.Crypto.SealRegion(buf[frameStart+7:], payloadLen)
		}
	}
	// NB: cipher is applied at write time by writeMuxFrameFused (single
	// cipher+mask pass); do NOT TransformInPlace here.
	padLen := 0
	if cmd == MuxCmdDATA && s.cfg.Obfs {
		if room := len(buf) - 14 - frameLen; room > 0 {
			if room > obfsPadMax {
				room = obfsPadMax
			}
			prng := maskPool.Get().(*maskPRNG)
			padLen = prng.randIntn(room + 1)
			prng.fillRandom(buf[frameStart+frameLen : frameStart+frameLen+padLen])
			maskPool.Put(prng)
		}
	}
	frame := muxOutboundFrame{bPtr: bPtr, pool: s.cfg.BufPool, payloadOff: frameStart, payloadLen: frameLen + padLen, opcode: 0x2, streamID: streamID, cmd: cmd}
	if !s.writer.enqueue(frame) {
		return errors.New("mux session writer closed")
	}
	return nil
}

func (s *MuxClientSession) readLoop() {
	defer s.Close()
	bPtr := s.cfg.BufPool.Get().(*[]byte)
	defer func() {
		if bPtr != nil {
			s.cfg.BufPool.Put(bPtr)
			bPtr = nil
		}
	}()
	buf := *bPtr
	var lastDeadline time.Time

	for {
		if deadlineThrottle(&lastDeadline) {
			setTCPReadDeadline(s.wsTCPConn, s.cfg.ConnTimeout)
		}
		data, err := readWSFrameIntoFused(s.br, s.wsConn, buf[14:], s.cfg.Crypto.xorOnly())
		if err != nil {
			return
		}

		if len(data) < MuxHeaderLen {
			continue
		}
		streamID := binary.BigEndian.Uint32(data[:4])
		cmd := data[4]
		payloadLen := int(binary.BigEndian.Uint16(data[5:7]))
		if len(data) < MuxHeaderLen+payloadLen {
			continue
		}
		payload := data[MuxHeaderLen : MuxHeaderLen+payloadLen]

		// AEAD mode: the sealed region [nonce|ct|tag] is opened in place
		// before any dispatch; empty payloads (FIN/RST) were never sealed.
		if s.cfg.Crypto != nil && !s.cfg.Crypto.isXOR() && len(payload) > 0 {
			var openErr error
			payload, openErr = s.cfg.Crypto.OpenRegion(payload)
			if openErr != nil {
				logDebug("[CLIENT-MUX] Stream %d aead open failed: %v", streamID, openErr)
				continue
			}
		}

		// W3 control frames arrive before the stream lookup: VERSION uses
		// stream id 0 (not in the map) and WINDOW must not be swallowed
		// by the unknown-stream skip.
		if cmd == MuxCmdVERSION {
			s.applyPeerVersion(payload)
			continue
		}
		if cmd == MuxCmdWINDOW {
			s.applyWindow(streamID, payload)
			continue
		}

		s.streamsMu.RLock()
		st, ok := s.streams[streamID]
		s.streamsMu.RUnlock()

		if !ok {
			continue
		}

		switch cmd {
		case MuxCmdDATA:
			if len(payload) > 0 {
				frame := muxDataFrame{
					data: payload,
					bPtr: bPtr,
					pool: s.cfg.BufPool,
				}
				bPtr = s.cfg.BufPool.Get().(*[]byte)
				buf = *bPtr
				st.enqueueDataFrame(frame)
				stats.AddBytes(0, int64(len(payload)))
			}
		case MuxCmdFIN:
			st.enqueueDataFrame(muxDataFrame{data: nil})
		case MuxCmdRST:
			st.Reset()
		}
	}
}

// MuxClientPool manages active Mux sessions on the client side.
type MuxClientPool struct {
	cfg      *Config
	sessions []*MuxClientSession
	mu       sync.Mutex
	maxSess  int
	roundIdx uint32
	dialing  int
	closed   bool
}

func NewMuxClientPool(cfg *Config, maxSessions int) *MuxClientPool {
	return &MuxClientPool{
		cfg:      cfg,
		maxSess:  maxSessions,
		sessions: make([]*MuxClientSession, 0, maxSessions),
	}
}

func (p *MuxClientPool) pickBestSessionLocked() *MuxClientSession {
	if len(p.sessions) == 0 {
		return nil
	}
	if len(p.sessions) == 1 {
		return p.sessions[0]
	}

	var minStreams int64 = -1
	var candidates []*MuxClientSession

	for _, s := range p.sessions {
		cnt := s.ActiveStreams()
		if minStreams == -1 || cnt < minStreams {
			minStreams = cnt
			candidates = candidates[:0]
			candidates = append(candidates, s)
		} else if cnt == minStreams {
			candidates = append(candidates, s)
		}
	}

	if len(candidates) == 1 {
		return candidates[0]
	}

	idx := atomic.AddUint32(&p.roundIdx, 1) % uint32(len(candidates))
	return candidates[idx]
}

func (p *MuxClientPool) GetSession() (*MuxClientSession, error) {
	p.mu.Lock()

	// Filter out dead sessions
	valid := p.sessions[:0]
	for _, s := range p.sessions {
		if s.IsAlive() {
			valid = append(valid, s)
		}
	}
	p.sessions = valid

	// If at least one session is active, select the least loaded (least active streams, with round-robin tie-breaking)
	if len(p.sessions) > 0 {
		sess := p.pickBestSessionLocked()
		sess.activeStreams.Add(1)

		// If pool capacity is not yet reached, trigger background dial to scale up
		if !p.closed && len(p.sessions)+p.dialing < p.maxSess {
			p.dialing++
			go p.dialBackgroundSession()
		}

		p.mu.Unlock()
		return sess, nil
	}

	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("mux client pool closed")
	}

	// No sessions alive. Dial synchronously, releasing lock during network I/O
	p.dialing++
	p.mu.Unlock()

	sess, err := p.dialNewSession()

	p.mu.Lock()
	p.dialing--
	if err != nil {
		// If another goroutine succeeded while we were dialing, use that
		if len(p.sessions) > 0 {
			s := p.pickBestSessionLocked()
			s.activeStreams.Add(1)
			p.mu.Unlock()
			return s, nil
		}
		p.mu.Unlock()
		return nil, err
	}

	if p.closed {
		p.mu.Unlock()
		sess.Close()
		return nil, errors.New("mux client pool closed")
	}

	p.sessions = append(p.sessions, sess)
	sess.activeStreams.Add(1)
	p.mu.Unlock()
	return sess, nil
}

func (p *MuxClientPool) dialBackgroundSession() {
	sess, err := p.dialNewSession()
	p.mu.Lock()
	p.dialing--
	if err == nil {
		if !p.closed && len(p.sessions) < p.maxSess {
			p.sessions = append(p.sessions, sess)
		} else {
			sess.Close()
		}
	}
	p.mu.Unlock()
}

func (p *MuxClientPool) dialNewSession() (*MuxClientSession, error) {
	setupStart := time.Now()
	wsConn, br, wsTCPConn, err := dialUpstreamWS(p.cfg)
	if err != nil {
		return nil, err
	}

	targetPayload := []byte("MUX\n")
	targetPayload = p.cfg.Crypto.sealFrame(targetPayload)
	if err := writeWSFrame(wsConn, targetPayload, 0x2, true); err != nil {
		wsConn.Close()
		return nil, err
	}

	setTCPReadDeadline(wsTCPConn, p.cfg.ConnTimeout)
	okFrame, err := readWSFrame(br, wsConn, p.cfg.Crypto)
	if err != nil {
		wsConn.Close()
		return nil, err
	}
	if !strings.HasPrefix(string(okFrame), "OK") {
		wsConn.Close()
		return nil, errors.New("mux auth rejected by server")
	}

	logInfo("[MUX] Client session established to upstream")
	return newMuxClientSession(wsConn, br, wsTCPConn, p.cfg, time.Since(setupStart)), nil
}

func (p *MuxClientPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, s := range p.sessions {
		s.Close()
	}
	p.sessions = nil
}

// relayMuxClient multiplexes a single user connection over an active MuxSession.
func relayMuxClient(localConn net.Conn, ver byte, initialPayload []byte, targetAddr string, cfg *Config) bool {
	session, err := cfg.MuxPool.GetSession()
	if err != nil || session == nil {
		return false
	}

	streamID := atomic.AddUint32(&session.nextStreamID, 1)
	if streamID == 0 {
		streamID = atomic.AddUint32(&session.nextStreamID, 1)
	}
	stream := newMuxStream(streamID, session)
	// W3: start bounded if the server already advertised its window.
	if w := session.peerWindow.Load(); w > 0 {
		stream.sendGate.Enable(w)
	}
	stream.onClose = func() {
		session.decrementActiveStreams()
	}

	session.streamsMu.Lock()
	session.streams[streamID] = stream
	session.streamsMu.Unlock()

	defer stream.Close()

	tLen := len(targetAddr)
	if tLen > 65535-2 {
		logError("[CLIENT-MUX] Target address length %d exceeds max protocol limit", tLen)
		return false
	}
	maxInitialInSYN := muxDataChunkLimit - 2 - tLen
	var synInitial []byte
	var remainingInitial []byte
	if len(initialPayload) > maxInitialInSYN {
		synInitial = initialPayload[:maxInitialInSYN]
		remainingInitial = initialPayload[maxInitialInSYN:]
	} else {
		synInitial = initialPayload
	}

	needed := 2 + tLen + len(synInitial)
	var synStack [256]byte
	var synPayload []byte
	if needed <= len(synStack) {
		synPayload = synStack[:needed]
	} else {
		synPayload = make([]byte, needed)
	}
	binary.BigEndian.PutUint16(synPayload[:2], uint16(tLen))
	copy(synPayload[2:2+tLen], targetAddr)
	if len(synInitial) > 0 {
		copy(synPayload[2+tLen:], synInitial)
	}

	if err := session.SendFrame(streamID, MuxCmdSYN, synPayload); err != nil {
		logDebug("[CLIENT-MUX] Send SYN failed: %v", err)
		session.RemoveStream(streamID)
		return false
	}

	if len(remainingInitial) > 0 {
		if _, err := stream.Write(remainingInitial); err != nil {
			logDebug("[CLIENT-MUX] Write remaining initial DATA failed: %v", err)
			return false
		}
	}

	if ver == 0x05 {
		if _, err := localConn.Write(socks5OKResp); err != nil {
			stream.Close()
			return true
		}
	} else if initialPayload == nil {
		if _, err := localConn.Write(http200Resp); err != nil {
			stream.Close()
			return true
		}
	}

	logDebug("[CLIENT-MUX] Stream %d -> %s (0-RTT)", streamID, targetAddr)

	errCh := make(chan error, 2)

	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		for {
			nr, errRead := localConn.Read(buf)
			if nr > 0 {
				if _, errWrite := stream.Write(buf[:nr]); errWrite != nil {
					errCh <- errWrite
					return
				}
				stats.AddBytes(int64(nr), 0)
			}
			if errRead != nil {
				stream.Close()
				errCh <- errRead
				return
			}
		}
	}()

	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		// W3 receive-side refund accumulator (client -> server WINDOW).
		var refundPending int64
		// The local app may stop draining (M6 wedge): bound the egress
		// write so this pump cannot pin its buffers forever.
		var lastWriteSet time.Time
		writeTimeout := time.Duration(cfg.ConnTimeout) * time.Second
		for {
			nr, errRead := stream.Read(buf)
			if nr > 0 {
				refreshWriteDeadline(localConn, writeTimeout, &lastWriteSet)
				if _, errWrite := localConn.Write(buf[:nr]); errWrite != nil {
					errCh <- errWrite
					return
				}
				stats.AddBytes(0, int64(nr))
				// Only accumulate once the server negotiated.
				if session.peerWindow.Load() == 0 {
					refundPending = 0
				} else {
					refundPending += int64(nr)
					if refundPending >= muxRefundThreshold {
						var wb [4]byte
						binary.BigEndian.PutUint32(wb[:], uint32(refundPending))
						refundPending = 0
						_ = session.SendFrame(streamID, MuxCmdWINDOW, wb[:])
					}
				}
			}
			if errRead != nil {
				errCh <- errRead
				return
			}
		}
	}()

	<-errCh
	localConn.Close()
	stream.Close()
	return true
}

// MuxServerSession handles a single WebSocket tunnel on the server side.
// Egress is serialized by a dedicated muxOutboundWriter (same DRR +
// priority scheduler as the client) — there is no writeMu across IO.
type MuxServerSession struct {
	wsConn    net.Conn
	br        *bufio.Reader
	wsTCPConn *net.TCPConn
	cfg       *Config
	writer    *muxOutboundWriter
	streams   map[uint32]*MuxServerStream
	streamsMu sync.RWMutex
	closed    chan struct{}
	closeOnce sync.Once
	// W3: peer-advertised receive window in bytes (0 = not negotiated).
	peerWindow atomic.Int64
}

type MuxServerStream struct {
	id          uint32
	session     *MuxServerSession
	writeChan   chan muxDataFrame
	targetMu    sync.Mutex
	targetConn  net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
	bufMu       sync.Mutex
	queuedBytes int64
	hasSpace    chan struct{}
	ingress     chan muxDataFrame
	// inFlight: same FIFO-preservation gate as MuxStream — see the comment
	// there. Fast-path direct pushes into writeChan require inFlight == 0.
	inFlight atomic.Int64
	// W3 upload credit toward the client: bounded once the client's
	// VERSION frame is observed.
	sendGate *creditGate
	// W3 refund accumulator (bytes written to the target -> WINDOW).
	refundPending int64
}

func newMuxServerStream(id uint32, session *MuxServerSession) *MuxServerStream {
	st := &MuxServerStream{id: id, session: session, writeChan: make(chan muxDataFrame, muxStreamAppQueue), closed: make(chan struct{}), hasSpace: make(chan struct{}, 1), ingress: make(chan muxDataFrame, muxStreamIngressQueue), sendGate: newCreditGate()}
	// nil session is tolerated (bare fixtures): those streams can never
	// negotiate, so the gate simply stays unbounded.
	if session != nil {
		if w := session.peerWindow.Load(); w > 0 {
			st.sendGate.Enable(w)
		}
	}
	go st.deliveryLoop()
	return st
}

// addConsumed books n bytes written toward the target and emits a WINDOW
// refund once the refresh threshold is reached. Single-goroutine per
// stream (handleNewStream hands off to its pump before any concurrency).
func (s *MuxServerStream) addConsumed(n int) {
	if n <= 0 {
		return
	}
	if s.session.peerWindow.Load() == 0 {
		s.refundPending = 0
		return
	}
	s.refundPending += int64(n)
	if s.refundPending < muxRefundThreshold {
		return
	}
	var wb [4]byte
	binary.BigEndian.PutUint32(wb[:], uint32(s.refundPending))
	s.refundPending = 0
	_ = s.session.SendFrame(s.id, MuxCmdWINDOW, wb[:])
}

func (s *MuxServerStream) enqueueDataFrame(frame muxDataFrame) bool {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	select {
	case <-s.closed:
		frame.release()
		return false
	default:
	}
	dataLen := int64(len(frame.data))
	// Fast path: if ingress queue is empty, no frame is in flight
	// (inFlight == 0) and the byte budget allows, bypass deliveryLoop
	// directly into writeChan. inFlight gating preserves per-stream FIFO
	// (see MuxStream.enqueueDataFrame).
	if len(s.ingress) == 0 && s.inFlight.Load() == 0 && s.queuedBytes+dataLen <= muxServerStreamBufferLimit {
		select {
		case s.writeChan <- frame:
			s.queuedBytes += dataLen
			return true
		default:
		}
	}
	s.inFlight.Add(1)
	select {
	case s.ingress <- frame:
		return true
	default:
		s.inFlight.Add(-1)
		logWarn("[SERVER-MUX] Stream %d ingress queue full, resetting stream", s.id)
		frame.release()
		s.Close()
		_ = s.session.SendFrame(s.id, MuxCmdRST, nil)
		return false
	}
}

func (s *MuxServerStream) deliveryLoop() {
	for {
		select {
		case <-s.closed:
			return
		case frame := <-s.ingress:
			if !s.PushDataFrame(frame) {
				frame.release()
			}
			s.inFlight.Add(-1)
		}
	}
}

func (s *MuxServerStream) PushDataFrame(frame muxDataFrame) bool {
	dataLen := int64(len(frame.data))
	// One reusable stall Timer for the whole call (see MuxStream).
	stall := time.NewTimer(muxPushStallTimeout)
	defer func() {
		if !stall.Stop() {
			select {
			case <-stall.C:
			default:
			}
		}
	}()
	for {
		s.bufMu.Lock()
		select {
		case <-s.closed:
			s.bufMu.Unlock()
			return false
		default:
		}
		if s.queuedBytes+dataLen <= muxServerStreamBufferLimit {
			select {
			case s.writeChan <- frame:
				s.queuedBytes += dataLen
				s.bufMu.Unlock()
				return true
			default:
			}
		}
		s.bufMu.Unlock()
		if !stall.Stop() {
			select {
			case <-stall.C:
			default:
			}
		}
		stall.Reset(muxPushStallTimeout)
		select {
		case <-s.closed:
			return false
		case <-s.hasSpace:
			continue
		case <-stall.C:
			logWarn("[SERVER-MUX] Stream %d receive backpressure timeout, resetting stream", s.id)
			s.Close()
			_ = s.session.SendFrame(s.id, MuxCmdRST, nil)
			return false
		}
	}
}

func (s *MuxServerStream) PushData(data []byte) bool {
	return s.PushDataFrame(muxDataFrame{data: data})
}

func (s *MuxServerStream) consumedBytes(n int) {
	if n <= 0 {
		return
	}
	s.bufMu.Lock()
	s.queuedBytes -= int64(n)
	if s.queuedBytes < 0 {
		s.queuedBytes = 0
	}
	if s.queuedBytes < muxServerStreamBufferLimit {
		select {
		case s.hasSpace <- struct{}{}:
		default:
		}
	}
	s.bufMu.Unlock()
}

func (s *MuxServerStream) QueuedBytes() int64 {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	return s.queuedBytes
}

func (s *MuxServerStream) setTargetConn(conn net.Conn) bool {
	s.targetMu.Lock()
	defer s.targetMu.Unlock()
	select {
	case <-s.closed:
		if conn != nil {
			_ = conn.Close()
		}
		return false
	default:
	}
	if s.targetConn != nil {
		_ = s.targetConn.Close()
	}
	s.targetConn = conn
	return true
}

func (s *MuxServerStream) closeTargetConn() {
	s.targetMu.Lock()
	defer s.targetMu.Unlock()
	if s.targetConn != nil {
		_ = s.targetConn.Close()
		s.targetConn = nil
	}
}

func (s *MuxServerStream) targetConnSnapshot() net.Conn {
	s.targetMu.Lock()
	defer s.targetMu.Unlock()
	return s.targetConn
}

func (s *MuxServerStream) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.sendGate.Close()
		s.closeTargetConn()
		s.bufMu.Lock()
		s.queuedBytes = 0
		s.bufMu.Unlock()
		for {
			select {
			case frame := <-s.writeChan:
				frame.release()
			case frame := <-s.ingress:
				frame.release()
			default:
				return
			}
		}
	})
}

func (s *MuxServerSession) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.wsConn.Close()
		if s.writer != nil {
			s.writer.close()
		}

		s.streamsMu.Lock()
		activeStreams := make([]*MuxServerStream, 0, len(s.streams))
		for _, st := range s.streams {
			activeStreams = append(activeStreams, st)
		}
		s.streams = make(map[uint32]*MuxServerStream)
		s.streamsMu.Unlock()

		for _, st := range activeStreams {
			st.Close()
		}
	})
}

func (s *MuxServerSession) SendFrame(streamID uint32, cmd byte, payload []byte) error {
	select {
	case <-s.closed:
		return errors.New("mux server session closed")
	default:
	}
	if s.writer == nil {
		return s.sendFrameInline(streamID, cmd, payload)
	}
	payloadLen := len(payload)
	if payloadLen > 65535 {
		return fmt.Errorf("mux server frame payload %d exceeds maximum uint16 length (65535)", payloadLen)
	}
	aead := s.cfg.Crypto != nil && !s.cfg.Crypto.isXOR()
	wireLen := payloadLen
	if aead && payloadLen > 0 {
		wireLen += aeadOverhead
	}
	frameLen := MuxHeaderLen + wireLen
	bPtr := s.cfg.BufPool.Get().(*[]byte)
	buf := *bPtr
	if frameLen+14 > len(buf) {
		s.cfg.BufPool.Put(bPtr)
		return errors.New("mux server frame exceeds buffer")
	}
	frameStart := 14
	binary.BigEndian.PutUint32(buf[frameStart:frameStart+4], streamID)
	buf[frameStart+4] = cmd
	binary.BigEndian.PutUint16(buf[frameStart+5:frameStart+7], uint16(wireLen))
	if payloadLen > 0 {
		copy(buf[frameStart+7:frameStart+7+payloadLen], payload)
		if aead {
			s.cfg.Crypto.SealRegion(buf[frameStart+7:], payloadLen)
		}
	}
	// NB: cipher is applied at write time by writeMuxFrameUnmasked (single
	// pass, unmasked server frames); do NOT TransformInPlace here.
	padLen := 0
	if cmd == MuxCmdDATA && s.cfg.Obfs {
		if room := len(buf) - 14 - frameLen; room > 0 {
			if room > obfsPadMax {
				room = obfsPadMax
			}
			prng := maskPool.Get().(*maskPRNG)
			padLen = prng.randIntn(room + 1)
			prng.fillRandom(buf[frameStart+frameLen : frameStart+frameLen+padLen])
			maskPool.Put(prng)
		}
	}
	frame := muxOutboundFrame{bPtr: bPtr, pool: s.cfg.BufPool, payloadOff: frameStart, payloadLen: frameLen + padLen, opcode: 0x2, streamID: streamID, cmd: cmd}
	if !s.writer.enqueue(frame) {
		return errors.New("mux server session writer closed")
	}
	return nil
}

// sendFrameInline is the legacy direct-write path used only when a bare
// MuxServerSession fixture has no writer (unit tests that construct the
// struct literal without handleServerMux). Production always sets writer.
// AEAD mode is unsupported here (tests only exercise legacy XOR).
func (s *MuxServerSession) sendFrameInline(streamID uint32, cmd byte, payload []byte) error {
	if s.wsConn == nil || s.cfg == nil || s.cfg.BufPool == nil {
		return errors.New("mux server session not initialized")
	}
	if s.cfg.Crypto != nil && !s.cfg.Crypto.isXOR() {
		return errors.New("sendFrameInline does not support aead mode")
	}
	payloadLen := len(payload)
	if payloadLen > 65535 {
		return fmt.Errorf("mux server frame payload %d exceeds maximum uint16 length (65535)", payloadLen)
	}

	frameLen := MuxHeaderLen + payloadLen
	bPtr := s.cfg.BufPool.Get().(*[]byte)
	defer s.cfg.BufPool.Put(bPtr)
	buf := *bPtr

	if frameLen+14 > len(buf) {
		return errors.New("mux server frame exceeds buffer")
	}

	frameStart := 14
	binary.BigEndian.PutUint32(buf[frameStart:frameStart+4], streamID)
	buf[frameStart+4] = cmd
	binary.BigEndian.PutUint16(buf[frameStart+5:frameStart+7], uint16(payloadLen))
	if payloadLen > 0 {
		copy(buf[frameStart+7:frameStart+7+payloadLen], payload)
	}

	if s.cfg.Crypto != nil {
		s.cfg.Crypto.TransformInPlace(buf[frameStart : frameStart+frameLen])
	}

	// Unilateral obfuscation, server side: same random-pad semantics as the
	// client path; receivers slice by the declared MUX length.
	writeLen := frameLen
	if cmd == MuxCmdDATA && s.cfg.Obfs {
		if room := len(buf) - 14 - frameLen; room > 0 {
			if room > obfsPadMax {
				room = obfsPadMax
			}
			padLen := mrand.Intn(room + 1)
			mrand.Read(buf[frameStart+frameLen : frameStart+frameLen+padLen])
			writeLen = frameLen + padLen
		}
	}

	return writeWSFramePreallocated(s.wsConn, buf, frameStart, writeLen, 0x2, false)
}

func handleServerMux(wsConn net.Conn, br *bufio.Reader, wsTCPConn *net.TCPConn, cfg *Config, setupDur time.Duration) {
	logInfo("[SERVER] Mux Session requested")
	var ok []byte
	ok = okCiphered(cfg.Crypto)
	if err := writeWSFrame(wsConn, ok, 0x2, false); err != nil {
		return
	}

	session := &MuxServerSession{
		wsConn:    wsConn,
		br:        br,
		wsTCPConn: wsTCPConn,
		cfg:       cfg,
		streams:   make(map[uint32]*MuxServerStream),
		closed:    make(chan struct{}),
	}
	// Server never masks; prng unused by the unmasked write path.
	session.writer = newMuxOutboundWriterBatched(wsConn, nil, cfg.Crypto, false, time.Duration(cfg.ConnTimeout)*time.Second, writevBatchFor(setupDur))
	defer session.Close()

	// W3 version negotiation: advertise our version + initial receive
	// window right after the session handshake. Old clients skip the
	// unknown command; new clients answer with their own VERSION.
	_ = session.SendFrame(0, MuxCmdVERSION, []byte{muxProtoVersion, byte(muxInitialWindowKib >> 8), byte(muxInitialWindowKib & 0xff)})

	logInfo("[SERVER] Mux Session active")

	bPtr := cfg.BufPool.Get().(*[]byte)
	defer func() {
		if bPtr != nil {
			cfg.BufPool.Put(bPtr)
			bPtr = nil
		}
	}()
	buf := *bPtr
	var lastDeadline time.Time

	for {
		if deadlineThrottle(&lastDeadline) {
			setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
		}
		data, err := readWSFrameIntoFused(br, wsConn, buf[14:], cfg.Crypto.xorOnly())
		if err != nil {
			return
		}

		if len(data) < MuxHeaderLen {
			continue
		}
		streamID := binary.BigEndian.Uint32(data[:4])
		cmd := data[4]
		payloadLen := int(binary.BigEndian.Uint16(data[5:7]))
		if len(data) < MuxHeaderLen+payloadLen {
			continue
		}
		payload := data[MuxHeaderLen : MuxHeaderLen+payloadLen]

		// AEAD mode: open the sealed region in place before dispatch
		// (empty payloads — FIN/RST — were never sealed).
		if cfg.Crypto != nil && !cfg.Crypto.isXOR() && len(payload) > 0 {
			var openErr error
			payload, openErr = cfg.Crypto.OpenRegion(payload)
			if openErr != nil {
				logDebug("[SERVER-MUX] Stream %d aead open failed: %v", streamID, openErr)
				continue
			}
		}

		// W3 control frames: VERSION records the client's window (first
		// wins) and enables bounded server->client sends on live streams;
		// WINDOW credits a specific stream's upload gate.
		if cmd == MuxCmdVERSION {
			if len(payload) == 3 && payload[0] >= 1 && session.peerWindow.Load() == 0 {
				kib := int(binary.BigEndian.Uint16(payload[1:3]))
				if kib < muxWindowMinKib {
					kib = muxWindowMinKib
				}
				window := int64(kib) * 1024
				session.peerWindow.Store(window)
				session.streamsMu.RLock()
				for _, st := range session.streams {
					st.sendGate.Enable(window)
				}
				session.streamsMu.RUnlock()
				logDebug("[SERVER-MUX] peer VERSION received; send window enabled (kib=%d)", kib)
			}
			continue
		}
		if cmd == MuxCmdWINDOW {
			if len(payload) == 4 {
				credit := binary.BigEndian.Uint32(payload)
				if credit > 0 && uint64(credit) <= uint64(muxInitialWindowKib)*1024*64 {
					session.streamsMu.RLock()
					st, ok := session.streams[streamID]
					session.streamsMu.RUnlock()
					if ok {
						st.sendGate.Release(int64(credit))
					}
				}
			}
			continue
		}

		switch cmd {
		case MuxCmdSYN:
			if len(payload) < 2 {
				continue
			}
			tLen := int(binary.BigEndian.Uint16(payload[:2]))
			if len(payload) < 2+tLen {
				continue
			}
			targetStr := string(payload[2 : 2+tLen])
			var initialData []byte
			if len(payload) > 2+tLen {
				initialData = make([]byte, len(payload)-(2+tLen))
				copy(initialData, payload[2+tLen:])
			}

			st := newMuxServerStream(streamID, session)
			session.streamsMu.Lock()
			session.streams[streamID] = st
			session.streamsMu.Unlock()

			go session.handleNewStream(st, targetStr, initialData)

		case MuxCmdDATA:
			session.streamsMu.RLock()
			st, ok := session.streams[streamID]
			session.streamsMu.RUnlock()
			if ok && len(payload) > 0 {
				frame := muxDataFrame{
					data: payload,
					bPtr: bPtr,
					pool: cfg.BufPool,
				}
				bPtr = cfg.BufPool.Get().(*[]byte)
				buf = *bPtr
				st.enqueueDataFrame(frame)
			}

		case MuxCmdFIN:
			session.streamsMu.RLock()
			st, ok := session.streams[streamID]
			session.streamsMu.RUnlock()
			if ok {
				st.enqueueDataFrame(muxDataFrame{data: nil})
			}

		case MuxCmdRST:
			session.streamsMu.RLock()
			st, ok := session.streams[streamID]
			session.streamsMu.RUnlock()
			if ok {
				st.Close()
			}
		}
	}
}

func (s *MuxServerSession) handleNewStream(st *MuxServerStream, targetStr string, initialData []byte) {
	defer func() {
		if r := recover(); r != nil {
			logError("[SERVER-MUX] Stream %d handler recovered from panic: %v", st.id, r)
		}
		st.Close()
		s.streamsMu.Lock()
		delete(s.streams, st.id)
		s.streamsMu.Unlock()
	}()

	targetAddr := resolveTargetAddr(s.cfg.Resolver, targetStr)
	if serverTargetBlocked(s.cfg, targetAddr) {
		logWarn("[SERVER-MUX] Blocked local target (server-block-local): %s", targetAddr)
		s.SendFrame(st.id, MuxCmdRST, nil)
		return
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, time.Duration(s.cfg.ConnTimeout)*time.Second)
	if err != nil {
		logDebug("[SERVER-MUX] Dial %s failed: %v", targetAddr, err)
		s.SendFrame(st.id, MuxCmdRST, nil)
		return
	}

	optimizeSocket(targetConn, s.cfg)
	if !st.setTargetConn(targetConn) {
		return
	}

	if len(initialData) > 0 {
		var lastWriteSet time.Time
		refreshWriteDeadline(targetConn, time.Duration(s.cfg.ConnTimeout)*time.Second, &lastWriteSet)
		if _, err := targetConn.Write(initialData); err != nil {
			logDebug("[SERVER-MUX] Write initialData to %s failed: %v", targetAddr, err)
			s.SendFrame(st.id, MuxCmdRST, nil)
			return
		}
		stats.AddBytes(int64(len(initialData)), 0)
		st.addConsumed(len(initialData))
	}

	logDebug("[SERVER-MUX] Stream %d -> %s", st.id, targetStr)

	go func() {
		var lastWriteSet time.Time
		writeTimeout := time.Duration(s.cfg.ConnTimeout) * time.Second
		for {
			select {
			case <-st.closed:
				return
			case frame, ok := <-st.writeChan:
				if !ok || frame.data == nil {
					if tc, ok := targetConn.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					return
				}
				data := frame.data
				refreshWriteDeadline(targetConn, writeTimeout, &lastWriteSet)
				// Receive direction (client -> target): no send-credit
				// charge here; book consumption for WINDOW refunds instead.
				_, err := targetConn.Write(data)
				st.consumedBytes(len(data))
				st.addConsumed(len(data))
				frame.release()
				if err != nil {
					st.Close()
					return
				}
				stats.AddBytes(int64(len(data)), 0)
			}
		}
	}()

	bPtr := s.cfg.BufPool.Get().(*[]byte)
	defer s.cfg.BufPool.Put(bPtr)
	buf := *bPtr
	readBuf := buf
	if len(readBuf) > 65535 {
		readBuf = readBuf[:65535]
	}
	for {
		nr, errRead := targetConn.Read(readBuf)
		if nr > 0 {
			// W3 server->client send gate: credit granted by the client's
			// WINDOW frames; unbounded until its VERSION arrived.
			if !st.sendGate.Acquire(nr, st.closed) {
				return
			}
			// AEAD mode caps plaintext per frame below the read size, so
			// split large reads into wire-legal DATA frames (legacy mode
			// sends nr in one frame exactly as before).
			for off := 0; off < nr; {
				chunk := nr - off
				if chunk > muxDataChunkLimit {
					chunk = muxDataChunkLimit
				}
				if errWrite := s.SendFrame(st.id, MuxCmdDATA, readBuf[off:off+chunk]); errWrite != nil {
					return
				}
				off += chunk
			}
			stats.AddBytes(0, int64(nr))
		}
		if errRead != nil {
			if errRead == io.EOF {
				s.SendFrame(st.id, MuxCmdFIN, nil)
			} else {
				s.SendFrame(st.id, MuxCmdRST, nil)
			}
			return
		}
	}
}
