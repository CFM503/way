// goway – quic
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ==================== QUIC TRANSPORT SUBSYSTEM ====================

// quicCertSeedPrefix domain-separates the key-derived QUIC certificate
// seed so the proxy key is never directly reusable as an Ed25519 seed.
const quicCertSeedPrefix = "GOWAY-QUIC-CERT-SEED:"

// publicKeyOf returns the public half of an ECDSA or Ed25519 private key.
func publicKeyOf(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	}
	return nil
}

// pinnedQUICPublicKey derives the deterministic QUIC server certificate
// public key from the shared proxy key. Both sides run the same derivation,
// letting the client pin the server cert instead of skipping verification.
func pinnedQUICPublicKey(key string) ed25519.PublicKey {
	seed := sha256.Sum256([]byte(quicCertSeedPrefix + key))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey)
}

// generateSelfSignedCert generates the QUIC server TLS certificate. With a
// proxy key set it is DETERMINISTIC (Ed25519 from a key-derived seed), so a
// client with the same key can pin it (-verify-quic). Without a key
// (-allow-open) it falls back to a fresh random ECDSA P-256 cert.
func generateSelfSignedCert(key string) (tls.Certificate, error) {
	var priv interface{}
	if key != "" {
		seed := sha256.Sum256([]byte(quicCertSeedPrefix + key))
		priv = ed25519.NewKeyFromSeed(seed[:])
	} else {
		legacy, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		priv = legacy
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GOWAY"},
			CommonName:   "goway.internal",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"goway.internal", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKeyOf(priv), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		// Trimmed (v1.8.7): idle 60s -> 30s so dead mobile conns are
		// reclaimed faster; explicit per-conn stream caps bound a
		// malicious peer's stream table; DATAGRAM support disabled —
		// no Send/ReceiveDatagram call exists anywhere, so negotiating
		// it only costs handshake bytes. KeepAlive stays 15s: longer
		// risks NAT-binding loss on strict networks.
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		// v1.8.13 Phase 3: stream cap 512->4096 (client pool opens one
		// stream per local conn; 512 stalled bursts above 512 concurrent
		// conns) and receive windows x2 for high-BDP paths. All four
		// windows must stay <= their Max or quic-go rejects the config.
		MaxIncomingStreams:             4096,
		MaxIncomingUniStreams:          128,
		InitialStreamReceiveWindow:     4 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,
		MaxConnectionReceiveWindow:     32 * 1024 * 1024,
		EnableDatagrams:                false,
	}
}

// --- QUIC Server ---

func startQUICServer(listenAddr string, cfg *Config, shutdown <-chan struct{}) {
	cert, err := generateSelfSignedCert(cfg.Key)
	if err != nil {
		logError("[QUIC-SERVER] Failed to generate self-signed cert: %v", err)
		return
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"goway-quic", "h3"},
	}

	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		logError("[QUIC-SERVER] ResolveUDPAddr %s err: %v", listenAddr, err)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logError("[QUIC-SERVER] Failed to bind UDP %s: %v", listenAddr, err)
		return
	}
	_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)

	listener, err := quic.Listen(udpConn, tlsConf, defaultQUICConfig())
	if err != nil {
		logError("[QUIC-SERVER] quic.Listen on %s err: %v", listenAddr, err)
		udpConn.Close()
		return
	}
	logInfo("[QUIC-SERVER] Listening on UDP %s (QUIC Mode)", listenAddr)

	go func() {
		<-shutdown
		listener.Close()
	}()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			select {
			case <-shutdown:
				return
			default:
				logError("[QUIC-SERVER] Accept err: %v", err)
				return
			}
		}

		go handleQUICConnection(conn, cfg)
	}
}

func handleQUICConnection(qConn quic.Connection, cfg *Config) {
	defer qConn.CloseWithError(0, "connection closed")

	for {
		stream, err := qConn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		if !tryAcquireConn(int64(cfg.MaxConns)) {
			logWarn("[QUIC-SERVER] MaxConns (%d) reached, rejecting stream", cfg.MaxConns)
			_ = stream.Close()
			continue
		}

		go func(st quic.Stream) {
			defer releaseConn()
			handleQUICStream(st, cfg)
		}(stream)
	}
}

var bufioReaderPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReaderSize(nil, 4096)
	},
}

func getBufioReader(r io.Reader) *bufio.Reader {
	br := bufioReaderPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

func putBufioReader(br *bufio.Reader) {
	br.Reset(nil)
	bufioReaderPool.Put(br)
}

func handleQUICStream(stream quic.Stream, cfg *Config) {
	defer stream.Close()

	br := getBufioReader(stream)
	defer putBufioReader(br)
	targetLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	targetStr := strings.TrimSpace(targetLine)

	// Authentication check if key is set
	if clean, ok := verifyAuthKey(targetStr, cfg.Key); !ok {
		logWarn("[QUIC-SERVER] Auth rejected for stream from %v", stream.StreamID())
		stream.Write([]byte("ERR: AUTH_FAILED\n"))
		return
	} else {
		targetStr = clean
	}

	switch classifyServerTarget(targetStr) {
	case 'u':
		handleQUICServerUDP(stream, br, cfg)
		return
	}

	// Remote DNS resolution for target address
	targetAddr := resolveTargetAddr(cfg.Resolver, targetStr)
	if serverTargetBlocked(cfg, targetAddr) {
		logWarn("[QUIC-SERVER] Blocked local target (server-block-local): %s", targetAddr)
		stream.Write([]byte("ERR: BLOCKED_LOCAL\n"))
		return
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, time.Duration(cfg.ConnTimeout)*time.Second)
	if err != nil {
		logDebug("[QUIC-SERVER] Dial %s failed: %v", targetAddr, err)
		stream.Write([]byte("ERR: DIAL_FAILED\n"))
		return
	}
	defer targetConn.Close()
	optimizeSocket(targetConn, cfg)

	if _, err := stream.Write([]byte("OK\n")); err != nil {
		return
	}

	logDebug("[QUIC-SERVER] Stream %d -> %s", stream.StreamID(), targetStr)

	errCh := make(chan error, 2)
	// Egress writes get a deadline too (M6): a wedged peer must fail the
	// write instead of pinning the relay goroutine forever.
	writeTimeout := time.Duration(cfg.ConnTimeout) * time.Second

	// Stream -> Target
	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lastWriteSet time.Time
		for {
			nr, errRead := br.Read(buf)
			if nr > 0 {
				refreshWriteDeadline(targetConn, writeTimeout, &lastWriteSet)
				if _, errWrite := targetConn.Write(buf[:nr]); errWrite != nil {
					errCh <- errWrite
					return
				}
				stats.AddBytes(int64(nr), 0)
			}
			if errRead != nil {
				if tc, ok := targetConn.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				errCh <- errRead
				return
			}
		}
	}()

	// Target -> Stream
	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lastWriteSet time.Time
		for {
			nr, errRead := targetConn.Read(buf)
			if nr > 0 {
				refreshWriteDeadline(stream, writeTimeout, &lastWriteSet)
				if _, errWrite := stream.Write(buf[:nr]); errWrite != nil {
					errCh <- errWrite
					return
				}
				stats.AddBytes(0, int64(nr))
			}
			if errRead != nil {
				stream.CancelRead(0)
				errCh <- errRead
				return
			}
		}
	}()

	<-errCh
}

func handleQUICServerUDP(stream quic.Stream, br *bufio.Reader, cfg *Config) {
	if _, err := stream.Write([]byte("OK\n")); err != nil {
		return
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		logError("[QUIC-UDP] ListenUDP err: %v", err)
		return
	}
	defer udpConn.Close()

	errCh := make(chan error, 2)

	// Stream -> UDP
	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lenBuf [2]byte
		wb := newUDPBatchWriter(udpConn, true)
		var addrCache udpAddrCache
		defer func() { _ = wb.flushWrites() }()
		for {
			if br.Buffered() == 0 {
				_ = wb.flushWrites()
			}
			if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
				errCh <- err
				return
			}
			pLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if pLen > len(buf) {
				errCh <- errors.New("udp packet too large")
				return
			}
			if _, err := io.ReadFull(br, buf[:pLen]); err != nil {
				errCh <- err
				return
			}

			data := buf[:pLen]
			if len(data) < 10 {
				continue
			}
			atyp := data[3]
			var host string
			var offset int
			if atyp == 0x01 {
				host = net.IP(data[4:8]).String()
				offset = 8
			} else if atyp == 0x03 {
				nameLen := int(data[4])
				offset = 5 + nameLen
				if len(data) < offset+2 {
					continue
				}
				host = string(data[5:offset])
			} else if atyp == 0x04 {
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
				continue
			}
			if errWrite := wb.queueWrite(payload, raddr); errWrite != nil {
				logDebug("[QUIC-UDP] WriteToUDP failed: %v", errWrite)
			}
		}
	}()

	// UDP -> Stream
	go func() {
		// Single buffer [2B len | SOCKS5-UDP hdr | payload] — one stream
		// Write per datagram instead of the old len-prefix + payload pair.
		out := make([]byte, 2+65535)
		batch := newUDPBatch(udpConn)
		var lastWriteSet time.Time
		writeTimeout := time.Duration(cfg.ConnTimeout) * time.Second
		for {
			count, errRead := batch.read()
			if errRead != nil {
				errCh <- errRead
				return
			}
			for i := 0; i < count; i++ {
				n := batch.msgs[i].N
				raddr := batch.msgs[i].Addr.(*net.UDPAddr)
				hdr := out[2:]
				hdr[0] = 0
				hdr[1] = 0
				hdr[2] = 0
				var hdrLen int
				ip4 := raddr.IP.To4()
				if ip4 != nil {
					hdr[3] = 0x01
					copy(hdr[4:8], ip4)
					binary.BigEndian.PutUint16(hdr[8:10], uint16(raddr.Port))
					hdrLen = 10
				} else {
					hdr[3] = 0x04
					copy(hdr[4:20], raddr.IP.To16())
					binary.BigEndian.PutUint16(hdr[20:22], uint16(raddr.Port))
					hdrLen = 22
				}
				if n > len(hdr)-hdrLen {
					continue // oversized datagram; cannot fit the frame
				}
				copy(hdr[hdrLen:], batch.msgs[i].Buffers[0][:n])
				totalLen := hdrLen + n
				binary.BigEndian.PutUint16(out[:2], uint16(totalLen))
				refreshWriteDeadline(stream, writeTimeout, &lastWriteSet)
				if _, errWrite := stream.Write(out[:2+totalLen]); errWrite != nil {
					errCh <- errWrite
					return
				}
				stats.AddBytes(0, int64(n))
			}
		}
	}()

	<-errCh
}

// --- QUIC Client Pool ---

type QUICClientPool struct {
	cfg      *Config
	conns    []quic.Connection // live connections, len <= maxConns
	next     uint32            // round-robin index over conns
	mu       sync.Mutex
	dialAddr string
	tlsConf  *tls.Config
	dialing  chan struct{} // single-flight barrier while a dial is in progress
	closed   bool
	maxConns int
}

func NewQUICClientPool(cfg *Config) (*QUICClientPool, error) {
	u, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialAddr := net.JoinHostPort(host, port)

	sni := host
	if cfg.FakeHost != "" {
		sni = strings.Split(cfg.FakeHost, ":")[0]
	}

	tlsConf := &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"goway-quic", "h3"},
		InsecureSkipVerify: !cfg.VerifySSL,
	}

	// -verify-quic: pin the server certificate to the key-derived Ed25519
	// public key instead of trusting any self-signed cert (the server must
	// run this version or newer and be started with the same -k).
	if cfg.VerifyQUIC && cfg.Key != "" {
		expected := pinnedQUICPublicKey(cfg.Key)
		tlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("quic pin: no server certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("quic pin: parse certificate: %w", err)
			}
			pk, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok || !bytes.Equal(pk, expected) {
				return errors.New("quic pin: server certificate does not match the key-derived pinned key")
			}
			return nil
		}
	}

	maxConns := cfg.QUICConns
	if maxConns < 1 {
		maxConns = 1
	}
	if maxConns > 16 {
		maxConns = 16
	}

	return &QUICClientPool{
		cfg:      cfg,
		dialAddr: dialAddr,
		tlsConf:  tlsConf,
		maxConns: maxConns,
	}, nil
}

func (p *QUICClientPool) removeConnLocked(conn quic.Connection) {
	for i, c := range p.conns {
		if c == conn {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			return
		}
	}
}

func (p *QUICClientPool) GetStream() (quic.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.cfg.ConnTimeout)*time.Second)
	defer cancel()

	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errors.New("quic client pool closed")
		}

		// 1. Round-robin over live connections; OpenStreamSync runs OUTSIDE
		// the lock. With maxConns == 1 this is exactly the v1.8.15 behavior.
		if len(p.conns) > 0 {
			conn := p.conns[p.next%uint32(len(p.conns))]
			p.next++
			p.mu.Unlock()

			stream, err := conn.OpenStreamSync(ctx)
			if err == nil {
				p.maybeTopUp()
				return stream, nil
			}

			// OpenStreamSync failed on this connection: drop it to avoid a
			// leak and try another (or dial) on the next loop iteration.
			_ = conn.CloseWithError(0x01, "stream open failed")
			p.mu.Lock()
			p.removeConnLocked(conn)
			p.mu.Unlock()
			continue
		}

		// 2. If another goroutine is currently dialing, wait on its barrier outside the lock
		if p.dialing != nil {
			waitCh := p.dialing
			p.mu.Unlock()

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-waitCh:
				// Dialer finished; loop back to check newly established connection
				continue
			}
		}

		// 3. We are the elected dialer: set up dialing barrier and release mutex
		dialingCh := make(chan struct{})
		p.dialing = dialingCh
		p.mu.Unlock()

		// Perform DNS resolution, DialAddr and OpenStreamSync completely OUTSIDE p.mu
		return p.dialAndOpenStream(ctx, dialingCh)
	}
}

// maybeTopUp dials one background connection when the pool is below
// maxConns, so parallel congestion windows actually accumulate under load.
// No-op for the default maxConns == 1.
func (p *QUICClientPool) maybeTopUp() {
	p.mu.Lock()
	if p.closed || p.dialing != nil || len(p.conns) >= p.maxConns {
		p.mu.Unlock()
		return
	}
	dialingCh := make(chan struct{})
	p.dialing = dialingCh
	p.mu.Unlock()

	go func() {
		topCtx, cancel := context.WithTimeout(context.Background(), time.Duration(p.cfg.ConnTimeout)*time.Second)
		defer cancel()
		newConn, err := p.dialConn(topCtx)

		p.mu.Lock()
		p.dialing = nil
		switch {
		case err != nil:
			// transient dial failure: leave the pool as-is
		case p.closed:
			if newConn != nil {
				_ = newConn.CloseWithError(0, "client closed")
			}
		default:
			p.conns = append(p.conns, newConn)
		}
		close(dialingCh)
		p.mu.Unlock()
	}()
}

func (p *QUICClientPool) dialAndOpenStream(ctx context.Context, dialingCh chan struct{}) (quic.Stream, error) {
	var newConn quic.Connection
	var stream quic.Stream
	var dialErr error

	defer func() {
		p.mu.Lock()
		if dialErr != nil || stream == nil {
			if newConn != nil {
				_ = newConn.CloseWithError(0x01, "stream open failed")
			}
		} else if !p.closed {
			p.conns = append(p.conns, newConn)
		} else {
			// Pool was closed while dialing
			if newConn != nil {
				_ = newConn.CloseWithError(0, "client closed")
			}
			if stream != nil {
				_ = stream.Close()
				stream = nil
			}
			dialErr = errors.New("quic client pool closed")
		}
		p.dialing = nil
		close(dialingCh)
		p.mu.Unlock()
	}()

	newConn, dialErr = p.dialConn(ctx)
	if dialErr != nil {
		return nil, dialErr
	}

	// OpenStreamSync on the newly established connection outside lock
	stream, dialErr = newConn.OpenStreamSync(ctx)
	if dialErr != nil {
		return nil, dialErr
	}

	return stream, nil
}

// dialConn performs DNS resolution, UDP socket bind (4MB kernel buffers)
// and the QUIC handshake, completely outside p.mu.
func (p *QUICClientPool) dialConn(ctx context.Context) (quic.Connection, error) {
	// 1. DNS Resolve outside lock
	actualAddr := resolveTargetAddr(p.cfg.Resolver, p.dialAddr)

	// 2. Bind UDP with 4MB buffers and Dial outside lock
	udpAddr, rErr := net.ResolveUDPAddr("udp", actualAddr)
	if rErr != nil {
		return nil, rErr
	}
	udpConn, lErr := net.ListenUDP("udp", nil)
	if lErr != nil {
		return nil, lErr
	}
	_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)

	newConn, dialErr := quic.Dial(ctx, udpConn, udpAddr, p.tlsConf, defaultQUICConfig())
	if dialErr != nil {
		udpConn.Close()
		return nil, dialErr
	}
	return newConn, nil
}

func (p *QUICClientPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, c := range p.conns {
		c.CloseWithError(0, "client closed")
	}
	p.conns = nil
}

// relayQUICClient relays a client TCP connection through QUIC tunnel.
func relayQUICClient(localConn net.Conn, ver byte, initialPayload []byte, targetAddr string, cfg *Config) bool {
	if cfg.QUICPool == nil {
		return false
	}

	stream, err := cfg.QUICPool.GetStream()
	if err != nil {
		logError("[CLIENT-QUIC] GetStream failed: %v", err)
		return false
	}
	defer stream.Close()

	header := targetAddr
	if cfg.Key != "" {
		header = cfg.Key + " " + targetAddr
	}
	header += "\n"

	if _, err := stream.Write([]byte(header)); err != nil {
		return false
	}

	br := bufio.NewReader(stream)
	resp, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(resp, "OK") {
		logError("[CLIENT-QUIC] Upstream rejected target: %v, resp: %s", err, resp)
		return false
	}

	if ver == 0x05 {
		if _, err := localConn.Write(socks5OKResp); err != nil {
			return true
		}
	} else if initialPayload == nil {
		if _, err := localConn.Write(http200Resp); err != nil {
			return true
		}
	}

	if len(initialPayload) > 0 {
		if _, err := stream.Write(initialPayload); err != nil {
			return true
		}
		stats.AddBytes(int64(len(initialPayload)), 0)
	}

	errCh := make(chan error, 2)
	// Egress writes get a deadline too (M6): a wedged peer must fail the
	// write instead of pinning the relay goroutine forever.
	writeTimeout := time.Duration(cfg.ConnTimeout) * time.Second

	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lastWriteSet time.Time
		for {
			nr, errRead := localConn.Read(buf)
			if nr > 0 {
				refreshWriteDeadline(stream, writeTimeout, &lastWriteSet)
				if _, errWrite := stream.Write(buf[:nr]); errWrite != nil {
					errCh <- errWrite
					return
				}
				stats.AddBytes(int64(nr), 0)
			}
			if errRead != nil {
				stream.CancelWrite(0)
				errCh <- errRead
				return
			}
		}
	}()

	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lastWriteSet time.Time
		for {
			nr, errRead := br.Read(buf)
			if nr > 0 {
				refreshWriteDeadline(localConn, writeTimeout, &lastWriteSet)
				if _, errWrite := localConn.Write(buf[:nr]); errWrite != nil {
					errCh <- errWrite
					return
				}
				stats.AddBytes(0, int64(nr))
			}
			if errRead != nil {
				errCh <- errRead
				return
			}
		}
	}()

	<-errCh
	localConn.Close()
	return true
}

func handleClientUDPQUIC(localConn net.Conn, boundAddr *net.UDPAddr, udpListener *net.UDPConn, cfg *Config) {
	stream, err := cfg.QUICPool.GetStream()
	if err != nil {
		logError("[CLIENT-QUIC-UDP] GetStream failed: %v", err)
		return
	}
	defer stream.Close()

	header := "UDP"
	if cfg.Key != "" {
		header = cfg.Key + " UDP"
	}
	header += "\n"

	if _, err := stream.Write([]byte(header)); err != nil {
		return
	}

	br := bufio.NewReader(stream)
	resp, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(resp, "OK") {
		logError("[CLIENT-QUIC-UDP] Auth rejected by server: %s", resp)
		return
	}

	logInfo("[CLIENT-QUIC-UDP] Tunnel established on port %d", boundAddr.Port)

	var clientUDPAddr atomic.Pointer[net.UDPAddr]
	errCh := make(chan error, 2)

	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		batch := newUDPBatch(udpListener)
		var lastWriteSet time.Time
		writeTimeout := time.Duration(cfg.ConnTimeout) * time.Second
		for {
			count, errRead := batch.read()
			if errRead != nil {
				errCh <- errRead
				return
			}
			for i := 0; i < count; i++ {
				n := batch.msgs[i].N
				pkt := batch.msgs[i].Buffers[0][:n]
				clientUDPAddr.Store(cloneUDPAddr(batch.msgs[i].Addr.(*net.UDPAddr)))
				// [2B len | payload] in one buffer — one stream Write per
				// datagram instead of the old len-prefix + payload pair.
				binary.BigEndian.PutUint16(buf[:2], uint16(n))
				copy(buf[2:], pkt)
				refreshWriteDeadline(stream, writeTimeout, &lastWriteSet)
				if _, errWrite := stream.Write(buf[:2+n]); errWrite != nil {
					errCh <- errWrite
					return
				}
				stats.AddBytes(int64(n), 0)
			}
		}
	}()

	go func() {
		rawBuf := make([]byte, 65535)
		var lenBuf [2]byte
		wb := newUDPBatchWriter(udpListener, false)
		defer func() { _ = wb.flushWrites() }()
		for {
			if br.Buffered() == 0 {
				_ = wb.flushWrites()
			}
			if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
				errCh <- err
				return
			}
			pLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if pLen > len(rawBuf) {
				errCh <- errors.New("udp packet too large")
				return
			}
			if _, err := io.ReadFull(br, rawBuf[:pLen]); err != nil {
				errCh <- err
				return
			}
			cAddr := clientUDPAddr.Load()
			if cAddr != nil {
				if errWrite := wb.queueWrite(rawBuf[:pLen], cAddr); errWrite != nil {
					logDebug("[CLIENT-QUIC-UDP] WriteToUDP failed: %v", errWrite)
				}
			}
		}
	}()

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
	stream.Close()
	localConn.Close()
}
