// goway – udp
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"golang.org/x/net/ipv4"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- UDP batch reads (recvmmsg) ---
//
// All four UDP relay loops used to call ReadFromUDP once per datagram —
// one syscall per DNS-sized packet. udpBatch drains up to udpBatchCount
// datagrams per recvmmsg syscall via x/net/ipv4 ReadBatch and processes
// them with the exact same per-datagram logic. Where the platform lacks
// recvmmsg (e.g. Windows) the first ReadBatch error pins a fallback to
// plain ReadFromUDP, so behavior is identical everywhere, only slower.
// Batch buffers are 64KB (no truncation vs. today's 64KB read bufs);
// 8 x 64KB = 512KB per UDP associate session, released on return.

const udpBatchCount = 8
const udpBatchBufSize = 65535

type udpBatch struct {
	pc       *ipv4.PacketConn
	conn     *net.UDPConn
	msgs     []ipv4.Message
	addrs    []net.UDPAddr
	fallback bool
	// write side (sendmmsg); only populated on instances from newUDPBatchWriter
	wmsgs     []ipv4.Message
	wbufs     [][]byte
	wcount    int
	wup       bool
	wfallback bool
}

func newUDPBatch(conn *net.UDPConn) *udpBatch {
	b := &udpBatch{
		conn:  conn,
		pc:    ipv4.NewPacketConn(conn),
		msgs:  make([]ipv4.Message, udpBatchCount),
		addrs: make([]net.UDPAddr, udpBatchCount),
	}
	for i := range b.msgs {
		b.msgs[i].Buffers = [][]byte{make([]byte, udpBatchBufSize)}
		b.msgs[i].Addr = &b.addrs[i]
	}
	return b
}

// read returns the number of freshly received datagrams (≥1). Message i is
// b.msgs[i].Buffers[0][:b.msgs[i].N] from b.msgs[i].Addr (*net.UDPAddr).
// Any error is fatal to the caller, exactly like ReadFromUDP today.
func (b *udpBatch) read() (int, error) {
	if !b.fallback {
		if n, err := b.pc.ReadBatch(b.msgs, 0); err == nil {
			return n, nil
		}
		b.fallback = true
	}
	n, addr, err := b.conn.ReadFromUDP(b.msgs[0].Buffers[0])
	if err != nil {
		return 0, err
	}
	b.msgs[0].N = n
	b.msgs[0].Addr = addr
	return 1, nil
}

// cloneUDPAddr deep-copies an address for storage beyond the current batch
// (batch Addr slots are reused on the next read).
func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	cp := *a
	if a.IP != nil {
		cp.IP = append(net.IP(nil), a.IP...)
	}
	return &cp
}

// udpAddrCache memoizes ResolveUDPAddr results for one UDP relay session —
// the old path parsed "ip:port" and allocated a fresh *net.UDPAddr for
// EVERY datagram. Bounded: a full cache is reset wholesale (a session
// talking to >4096 distinct endpoints is pathological; correctness is
// unaffected either way).
type udpAddrCache struct {
	mu sync.Mutex
	m  map[udpAddrKey]*net.UDPAddr
}

type udpAddrKey struct {
	host string
	port int
}

func (c *udpAddrCache) get(host string, port int, resolver *RemoteResolver) *net.UDPAddr {
	key := udpAddrKey{host: host, port: port}
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[udpAddrKey]*net.UDPAddr)
	}
	if a, ok := c.m[key]; ok {
		c.mu.Unlock()
		return a
	}
	c.mu.Unlock()

	targetIP := host
	if resolver != nil {
		if resolvedIP, rErr := resolver.Resolve(host); rErr == nil {
			targetIP = resolvedIP
		}
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, strconv.Itoa(port)))
	if err != nil {
		return nil
	}

	c.mu.Lock()
	if len(c.m) >= 4096 {
		c.m = make(map[udpAddrKey]*net.UDPAddr)
	}
	c.m[key] = raddr
	c.mu.Unlock()
	return raddr
}

// --- UDP batch writes (sendmmsg) ---
//
// The tunnel→UDP direction used to issue one WriteToUDP syscall per
// datagram. newUDPBatchWriter queues up to udpBatchCount datagrams and
// drains them with a single ipv4 WriteBatch (sendmmsg) — the mirror of
// the read side. Callers must flush before their next blocking read,
// when the queue fills, and on loop exit, so batching only covers
// datagrams whose frames were already sitting in the bufio buffer (no
// added latency). Payloads are copied: callers reuse their read buffer
// on the next iteration. On platforms without sendmmsg (everything but
// Linux) datagrams are written through immediately, exactly like the
// old code path; write slots are 8×64KB per session, mirroring the
// read side, and live as long as the session.

// newUDPBatchWriter creates the write half for one relay direction; up
// selects the stats direction (true: tunnel→target, false: target→app).
func newUDPBatchWriter(conn *net.UDPConn, up bool) *udpBatch {
	b := &udpBatch{
		conn:      conn,
		pc:        ipv4.NewPacketConn(conn),
		wup:       up,
		wfallback: runtime.GOOS != "linux",
	}
	b.wmsgs = make([]ipv4.Message, udpBatchCount)
	b.wbufs = make([][]byte, udpBatchCount)
	for i := range b.wmsgs {
		b.wbufs[i] = make([]byte, udpBatchBufSize)
		b.wmsgs[i].Buffers = [][]byte{b.wbufs[i][:0]}
	}
	return b
}

// queueWrite hands one datagram to the writer, copying the payload into a
// batch slot (or writing through immediately when the batch is unusable,
// empty datagrams would violate the "at least one byte" batch contract,
// or the datagram does not fit a slot). On success the datagram is
// accounted to stats either here (immediate path) or at flush time.
func (b *udpBatch) queueWrite(payload []byte, addr *net.UDPAddr) error {
	if b.wfallback || len(payload) == 0 || len(payload) > udpBatchBufSize {
		_, err := b.conn.WriteToUDP(payload, addr)
		if err == nil {
			b.addWriteStats(len(payload))
		}
		return err
	}
	if b.wcount == udpBatchCount {
		_ = b.flushWrites() // errors surface on the loop's periodic flush
	}
	copy(b.wbufs[b.wcount], payload)
	b.wmsgs[b.wcount].Buffers[0] = b.wbufs[b.wcount][:len(payload)]
	b.wmsgs[b.wcount].Addr = addr
	b.wcount++
	return nil
}

// flushWrites sends every queued datagram — one sendmmsg on Linux, plus
// per-datagram WriteToUDP for anything the batch did not take (partial
// send, or all of it when running in fallback mode). Sent bytes are
// accounted to stats; the first error is returned for logging.
func (b *udpBatch) flushWrites() error {
	if b.wcount == 0 {
		return nil
	}
	n := b.wcount
	b.wcount = 0
	var firstErr error
	done := 0
	if !b.wfallback {
		m, err := b.pc.WriteBatch(b.wmsgs[:n], 0)
		if err != nil {
			b.wfallback = true // batch unusable from now on
			firstErr = err
		}
		if m > 0 {
			batched := 0
			for i := 0; i < m; i++ {
				batched += len(b.wmsgs[i].Buffers[0])
			}
			b.addWriteStats(batched)
		}
		done = m
	}
	for i := done; i < n; i++ {
		buf := b.wmsgs[i].Buffers[0]
		dst, ok := b.wmsgs[i].Addr.(*net.UDPAddr)
		if !ok {
			if firstErr == nil {
				firstErr = errors.New("udpBatch: write address is not *net.UDPAddr")
			}
			continue
		}
		if _, err := b.conn.WriteToUDP(buf, dst); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			b.addWriteStats(len(buf))
		}
	}
	return firstErr
}

func (b *udpBatch) addWriteStats(n int) {
	if b.wup {
		stats.AddBytes(int64(n), 0)
	} else {
		stats.AddBytes(0, int64(n))
	}
}

func handleServerUDP(wsConn net.Conn, br *bufio.Reader, wsTCPConn *net.TCPConn, cfg *Config) {
	logInfo("[SERVER] UDP Tunnel requested")
	var ok []byte
	ok = okCiphered(cfg.Crypto)
	if err := writeWSFrame(wsConn, ok, 0x2, false); err != nil {
		return
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		logError("handleServerUDP ListenUDP err: %v", err)
		return
	}
	defer udpConn.Close()
	defer wsConn.Close()

	logInfo("[SERVER] UDP Tunnel active")

	errCh := make(chan error, 2)

	// WS -> UDP (Server receives WS frames containing SOCKS5 UDP packets from client)
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lastDeadline time.Time
		wb := newUDPBatchWriter(udpConn, true)
		var addrCache udpAddrCache
		defer func() { _ = wb.flushWrites() }()
		for {
			if deadlineThrottle(&lastDeadline) {
				setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
			}
			if br.Buffered() == 0 {
				if errF := wb.flushWrites(); errF != nil {
					logDebug("[SERVER-UDP] batch flush failed: %v", errF)
				}
			}
			data, errRead := readWSFrameIntoFused(br, wsConn, buf[14:], cfg.Crypto)
			if errRead != nil {
				err = errRead
				return
			}
			if len(data) < 7 {
				continue
			}
			// Parse SOCKS5 UDP header: [RSV(2), FRAG(1), ATYP(1), ADDR..., PORT(2), PAYLOAD...]
			atyp := data[3]
			var offset int
			var host string
			if atyp == 0x01 { // IPv4
				if len(data) < 10 {
					continue
				}
				host = net.IP(data[4:8]).String()
				offset = 8
			} else if atyp == 0x03 { // Domain
				dlen := int(data[4])
				if len(data) < 5+dlen+2 {
					continue
				}
				host = string(data[5 : 5+dlen])
				offset = 5 + dlen
			} else if atyp == 0x04 { // IPv6
				if len(data) < 22 {
					continue
				}
				host = net.IP(data[4:20]).String()
				offset = 20
			} else {
				continue
			}

			if len(data) < offset+2 {
				continue
			}
			port := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			payload := data[offset+2:]

			if serverTargetBlocked(cfg, net.JoinHostPort(host, strconv.Itoa(port))) {
				logWarn("[SERVER-UDP] Blocked local target (server-block-local): %s:%d", host, port)
				continue
			}

			raddr := addrCache.get(host, port, cfg.Resolver)
			if raddr == nil {
				logDebug("[SERVER-UDP] ResolveUDPAddr %s:%d failed", host, port)
				continue
			}

			if errWrite := wb.queueWrite(payload, raddr); errWrite != nil {
				logDebug("[SERVER-UDP] WriteToUDP failed: %v", errWrite)
			}
		}
	}()

	// UDP -> WS (Server reads responses from UDP targets and writes back as WS frames)
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		rawBuf := *bPtr
		batch := newUDPBatch(udpConn)
		var lastWriteSet time.Time
		writeTimeout := time.Duration(cfg.ConnTimeout) * time.Second
		for {
			count, errRead := batch.read()
			if errRead != nil {
				err = errRead
				return
			}
			for i := 0; i < count; i++ {
				n := batch.msgs[i].N
				raddr := batch.msgs[i].Addr.(*net.UDPAddr)
				pkt := batch.msgs[i].Buffers[0][:n]
				frameData := rawBuf[14:]
				frameData[0] = 0
				frameData[1] = 0
				frameData[2] = 0
				var hdrLen int
				ip4 := raddr.IP.To4()
				if ip4 != nil {
					frameData[3] = 0x01
					copy(frameData[4:8], ip4)
					binary.BigEndian.PutUint16(frameData[8:10], uint16(raddr.Port))
					hdrLen = 10
				} else {
					frameData[3] = 0x04
					copy(frameData[4:20], raddr.IP.To16())
					binary.BigEndian.PutUint16(frameData[20:22], uint16(raddr.Port))
					hdrLen = 22
				}
				totalLen := hdrLen + n
				maxPayload := len(rawBuf) - 14
				if cfg.Crypto != nil && !cfg.Crypto.isXOR() {
					maxPayload -= aeadOverhead
				}
				if totalLen > maxPayload {
					continue
				}
				copy(frameData[hdrLen:], pkt)

				wireLen := totalLen
				if cfg.Crypto != nil {
					if cfg.Crypto.isXOR() {
						cfg.Crypto.TransformInPlace(frameData[:totalLen])
					} else if totalLen > 0 {
						wireLen = cfg.Crypto.SealRegion(rawBuf[14:], totalLen)
					}
				}

				refreshWriteDeadline(wsConn, writeTimeout, &lastWriteSet)
				if errWrite := writeWSFramePreallocated(wsConn, rawBuf, 14, wireLen, 0x2, false); errWrite != nil {
					err = errWrite
					return
				}
				stats.AddBytes(0, int64(n))
			}
		}
	}()

	<-errCh
}

func handleClientUDP(localConn net.Conn, cfg *Config) {
	var localIP net.IP = net.IPv4(127, 0, 0, 1)
	if tcpAddr, ok := localConn.LocalAddr().(*net.TCPAddr); ok && tcpAddr.IP != nil {
		if !tcpAddr.IP.IsUnspecified() {
			localIP = tcpAddr.IP
		}
	}

	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		localConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpListener.Close()

	boundAddr := udpListener.LocalAddr().(*net.UDPAddr)
	var resp [10]byte
	resp[0] = 0x05 // VER
	resp[1] = 0x00 // SUCCESS
	resp[2] = 0x00 // RSV
	resp[3] = 0x01 // ATYP IPv4
	ip4 := boundAddr.IP.To4()
	if ip4 != nil {
		copy(resp[4:8], ip4)
	} else {
		copy(resp[4:8], []byte{127, 0, 0, 1})
	}
	binary.BigEndian.PutUint16(resp[8:10], uint16(boundAddr.Port))
	if _, err := localConn.Write(resp[:]); err != nil {
		return
	}

	if cfg.IsQUICUpstream && cfg.QUICPool != nil {
		handleClientUDPQUIC(localConn, boundAddr, udpListener, cfg)
		return
	}

	wsConn, br, wsTCPConn, err := dialUpstreamWS(cfg)
	if err != nil {
		logError("[UDP] Upstream dial failed: %v", err)
		return
	}
	defer wsConn.Close()

	targetPayload := []byte("UDP\n")
	targetPayload = cfg.Crypto.sealFrame(targetPayload)
	if err := writeWSFrame(wsConn, targetPayload, 0x2, true); err != nil {
		return
	}

	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	okFrame, err := readWSFrame(br, wsConn, cfg.Crypto)
	if err != nil {
		logError("[UDP] Read OK failed: %v", err)
		return
	}
	if !strings.HasPrefix(string(okFrame), "OK") {
		logError("[UDP] Auth rejected by server")
		return
	}

	logInfo("[UDP] Tunnel established on port %d", boundAddr.Port)

	var clientUDPAddr atomic.Pointer[net.UDPAddr]
	errCh := make(chan error, 2)

	// UDP -> WS (Client sends UDP packets to udpListener, forward as WS frames)
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		batch := newUDPBatch(udpListener)
		var lastWriteSet time.Time
		writeTimeout := time.Duration(cfg.ConnTimeout) * time.Second
		for {
			count, errRead := batch.read()
			if errRead != nil {
				err = errRead
				return
			}
			for i := 0; i < count; i++ {
				n := batch.msgs[i].N
				pkt := batch.msgs[i].Buffers[0][:n]
				clientUDPAddr.Store(cloneUDPAddr(batch.msgs[i].Addr.(*net.UDPAddr)))
				copy(buf[14:], pkt)
				wireLen := n
				if cfg.Crypto != nil {
					if cfg.Crypto.isXOR() {
						cfg.Crypto.TransformInPlace(buf[14 : 14+n])
					} else if n > 0 {
						wireLen = cfg.Crypto.SealRegion(buf[14:], n)
					}
				}
				refreshWriteDeadline(wsConn, writeTimeout, &lastWriteSet)
				if errWrite := writeWSFramePreallocatedFast(wsConn, buf, 14, wireLen, 0x2, prng); errWrite != nil {
					err = errWrite
					return
				}
				stats.AddBytes(int64(n), 0)
			}
		}
	}()

	// WS -> UDP (Server sends WS frames back, unmask, write to client's UDP address)
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lastDeadline time.Time
		wb := newUDPBatchWriter(udpListener, false)
		defer func() { _ = wb.flushWrites() }()
		for {
			if deadlineThrottle(&lastDeadline) {
				setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
			}
			if br.Buffered() == 0 {
				if errF := wb.flushWrites(); errF != nil {
					logDebug("[CLIENT-UDP] batch flush failed: %v", errF)
				}
			}
			data, errRead := readWSFrameIntoFused(br, wsConn, buf[14:], cfg.Crypto)
			if errRead != nil {
				err = errRead
				return
			}
			cAddr := clientUDPAddr.Load()
			if cAddr != nil {
				if errWrite := wb.queueWrite(data, cAddr); errWrite != nil {
					logDebug("[CLIENT-UDP] WriteToUDP failed: %v", errWrite)
				}
			}
		}
	}()

	// Monitor liveness: terminate UDP immediately when local TCP closes or tunnel errors
	tcpDone := make(chan struct{})
	go func() {
		var dummy [1]byte
		for {
			_, err := localConn.Read(dummy[:])
			if err != nil {
				break
			}
		}
		close(tcpDone)
	}()

	select {
	case <-tcpDone:
	case <-errCh:
	}

	udpListener.Close()
	wsConn.Close()
	localConn.Close()
}

type preReader struct {
	r   net.Conn
	buf []byte
	pos int
}

func (pr *preReader) Read(p []byte) (int, error) {
	if pr.pos < len(pr.buf) {
		n := copy(p, pr.buf[pr.pos:])
		pr.pos += n
		return n, nil
	}
	return pr.r.Read(p)
}
