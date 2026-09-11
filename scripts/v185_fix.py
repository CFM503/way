from pathlib import Path

path = Path('goway/goway.go')
text = path.read_text()
old_start = text.index('type MuxClientSession struct {')
old_end = text.index('func (s *MuxClientSession) readLoop() {', old_start)

new_block = r'''type muxOutboundFrame struct {
	bPtr       *[]byte
	pool       *sync.Pool
	payloadOff int
	payloadLen int
	opcode     byte
	ping       bool
}

type muxOutboundWriter struct {
	conn    net.Conn
	prng    *maskPRNG
	q       chan muxOutboundFrame
	closed  chan struct{}
	done    chan struct{}
	closeMu sync.Once
}

const muxOutboundQueueDepth = 8

func newMuxOutboundWriter(conn net.Conn, prng *maskPRNG) *muxOutboundWriter {
	w := &muxOutboundWriter{conn: conn, prng: prng, q: make(chan muxOutboundFrame, muxOutboundQueueDepth), closed: make(chan struct{}), done: make(chan struct{})}
	go w.loop()
	return w
}

func (w *muxOutboundWriter) releaseFrame(f muxOutboundFrame) {
	if f.bPtr != nil && f.pool != nil {
		f.pool.Put(f.bPtr)
	}
}

func (w *muxOutboundWriter) writeFrame(f muxOutboundFrame) error {
	if f.ping {
		return writeWSFrame(w.conn, nil, 0x9, true)
	}
	if f.bPtr == nil || f.pool == nil {
		return errors.New("invalid mux outbound frame")
	}
	return writeWSFramePreallocatedFast(w.conn, *f.bPtr, f.payloadOff, f.payloadLen, f.opcode, w.prng)
}

func (w *muxOutboundWriter) loop() {
	defer close(w.done)
	for {
		select {
		case <-w.closed:
			for {
				select {
				case f := <-w.q:
					w.releaseFrame(f)
				default:
					return
				}
			}
		case f := <-w.q:
			if err := w.writeFrame(f); err != nil {
				w.releaseFrame(f)
				_ = w.conn.Close()
				for {
					select {
					case queued := <-w.q:
						w.releaseFrame(queued)
					default:
						return
					}
				}
			}
			w.releaseFrame(f)
		}
	}
}

func (w *muxOutboundWriter) enqueue(f muxOutboundFrame) bool {
	select {
	case <-w.closed:
		w.releaseFrame(f)
		return false
	case <-w.done:
		w.releaseFrame(f)
		return false
	case w.q <- f:
		return true
	}
}

func (w *muxOutboundWriter) enqueuePing() bool {
	return w.enqueue(muxOutboundFrame{ping: true})
}

func (w *muxOutboundWriter) close() {
	w.closeMu.Do(func() { close(w.closed) })
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

func newMuxClientSession(wsConn net.Conn, br *bufio.Reader, wsTCPConn *net.TCPConn, cfg *Config) *MuxClientSession {
	prng := maskPool.Get().(*maskPRNG)
	s := &MuxClientSession{wsConn: wsConn, br: br, wsTCPConn: wsTCPConn, cfg: cfg, streams: make(map[uint32]*MuxStream), closed: make(chan struct{}), prng: prng}
	s.writer = newMuxOutboundWriter(wsConn, prng)
	go s.readLoop()
	go s.heartbeatLoop()
	return s
}

func (s *MuxClientSession) heartbeatLoop() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			if s.ActiveStreams() > 0 || s.writer == nil {
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
	frameLen := MuxHeaderLen + payloadLen
	bPtr := s.cfg.BufPool.Get().(*[]byte)
	buf := *bPtr
	if frameLen+14 > len(buf) {
		s.cfg.BufPool.Put(bPtr)
		return errors.New("mux frame exceeds buffer size")
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
	frame := muxOutboundFrame{bPtr: bPtr, pool: s.cfg.BufPool, payloadOff: frameStart, payloadLen: frameLen, opcode: 0x2}
	if !s.writer.enqueue(frame) {
		return errors.New("mux session writer closed")
	}
	return nil
}

'''

text = text[:old_start] + new_block + text[old_end:]
text = text.replace('Version        = "1.8.4"', 'Version        = "1.8.5-performance"', 1)
path.write_text(text)

proto = Path('goway/v185_performance_prototype_test.go')
if proto.exists():
    proto.unlink()
