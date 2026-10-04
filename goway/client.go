// goway – client
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func dialUpstreamPooledWS(cfg *Config) (*PooledConn, *net.TCPConn, error) {
	if connPool != nil {
		if pooledConn := connPool.Get(); pooledConn != nil {
			logDebug("[CLIENT] Using pooled connection")
			return pooledConn, extractTCPConn(pooledConn.wsConn), nil
		}
	}

	wsHost := cfg.UpstreamHost
	wsPort := cfg.UpstreamPort

	dialHost := wsHost
	if cfg.Resolver != nil {
		if resolvedIP, resolveErr := cfg.Resolver.Resolve(wsHost); resolveErr == nil {
			dialHost = resolvedIP
		} else {
			logError("[DNS] Failed to resolve upstream %s: %v", wsHost, resolveErr)
		}
	}

	dialAddr := net.JoinHostPort(dialHost, wsPort)
	sniHostname := sanitizeHeader(wsHost)
	if cfg.FakeHost != "" {
		sniHostname = sanitizeHeader(strings.Split(cfg.FakeHost, ":")[0])
	}

	dialer := &net.Dialer{Timeout: time.Duration(cfg.ConnTimeout) * time.Second}
	var wsConn net.Conn
	var err error
	if cfg.UpstreamIsWSS {
		conf := pickProfileTLSConfig().Clone()
		conf.ServerName = sniHostname
		wsConn, err = tls.DialWithDialer(dialer, "tcp", dialAddr, conf)
	} else {
		wsConn, err = dialer.Dial("tcp", dialAddr)
	}

	if err != nil {
		if cfg.FakeHost != "" {
			wsConn = nil
			fallbackConn := dialFallback(dialer, wsHost, wsPort, sniHostname, cfg)
			if fallbackConn != nil {
				wsConn = fallbackConn
				err = nil
			}
		}
		if wsConn == nil {
			return nil, nil, err
		}
	}

	optimizeSocket(wsConn, cfg)
	wsTCPConn := extractTCPConn(wsConn)
	br := bufio.NewReaderSize(wsConn, MaxHeaderSize)

	if err := performWSHandshake(wsConn, br, cfg, wsHost, sniHostname); err != nil {
		wsConn.Close()
		return nil, nil, err
	}

	pooled := &PooledConn{
		wsConn:   wsConn,
		br:       br,
		created:  time.Now(),
		lastUsed: time.Now(),
	}
	return pooled, wsTCPConn, nil
}

func dialUpstreamWS(cfg *Config) (net.Conn, *bufio.Reader, *net.TCPConn, error) {
	pooled, wsTCPConn, err := dialUpstreamPooledWS(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	return pooled.wsConn, pooled.br, wsTCPConn, nil
}

// --- Client Mode ---
func handleClient(localConn net.Conn, cfg *Config) {
	var stackBuf [256]byte
	nr, err := localConn.Read(stackBuf[:])
	if err != nil || nr == 0 {
		return
	}

	pr := preReader{r: localConn, buf: stackBuf[:nr], pos: 1}
	var targetHost string
	var targetPort string
	var initialPayload []byte

	ver := stackBuf[0]
	if ver == 0x05 {
		// SOCKS5: read greeting methods from pre-buffer with zero syscalls
		var nmBuf [1]byte
		if _, err := io.ReadFull(&pr, nmBuf[:]); err != nil {
			return
		}
		nmethods := int(nmBuf[0])
		var discard []byte
		if nmethods <= 8 {
			var dbuf [8]byte
			discard = dbuf[:nmethods]
		} else {
			discard = make([]byte, nmethods)
		}
		if _, err := io.ReadFull(&pr, discard); err != nil {
			return
		}

		if _, err := localConn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		var reqHead [4]byte
		if _, err := io.ReadFull(&pr, reqHead[:]); err != nil {
			return
		}
		cmd := reqHead[1]
		atyp := reqHead[3]

		if cmd == 0x03 {
			// SOCKS5 UDP ASSOCIATE: strictly check all read errors to avoid processing truncated requests
			if atyp == 0x01 {
				var ipBuf [4]byte
				if _, err := io.ReadFull(&pr, ipBuf[:]); err != nil {
					return
				}
			} else if atyp == 0x03 {
				var lenBuf [1]byte
				if _, err := io.ReadFull(&pr, lenBuf[:]); err != nil {
					return
				}
				domainBuf := make([]byte, int(lenBuf[0]))
				if _, err := io.ReadFull(&pr, domainBuf); err != nil {
					return
				}
			} else if atyp == 0x04 {
				var ipBuf [16]byte
				if _, err := io.ReadFull(&pr, ipBuf[:]); err != nil {
					return
				}
			} else {
				return
			}
			var portBuf [2]byte
			if _, err := io.ReadFull(&pr, portBuf[:]); err != nil {
				return
			}

			_ = localConn.SetDeadline(time.Time{})
			handleClientUDP(localConn, cfg)
			return
		}

		if cmd != 0x01 {
			// RFC 1928 §6: reply with "command not supported" (0x07) so the
			// client fails fast instead of hanging waiting for a response.
			localConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}

		if atyp == 0x01 {
			var ipBuf [4]byte
			if _, err := io.ReadFull(&pr, ipBuf[:]); err != nil {
				return
			}
			targetHost = net.IP(ipBuf[:]).String()
		} else if atyp == 0x03 {
			var lenBuf [1]byte
			if _, err := io.ReadFull(&pr, lenBuf[:]); err != nil {
				return
			}
			domainBuf := make([]byte, int(lenBuf[0]))
			if _, err := io.ReadFull(&pr, domainBuf); err != nil {
				return
			}
			targetHost = string(domainBuf)
		} else if atyp == 0x04 {
			var ipBuf [16]byte
			if _, err := io.ReadFull(&pr, ipBuf[:]); err != nil {
				return
			}
			targetHost = "[" + net.IP(ipBuf[:]).String() + "]"
		}

		var portBuf [2]byte
		if _, err := io.ReadFull(&pr, portBuf[:]); err != nil {
			return
		}
		portVal := binary.BigEndian.Uint16(portBuf[:])
		targetPort = strconv.Itoa(int(portVal))

		// If initial application data was already received in the pre-buffer
		// (e.g. 0-RTT TLS ClientHello), capture it as initialPayload for MUX SYN.
		if pr.pos < len(pr.buf) {
			rem := pr.buf[pr.pos:]
			initialPayload = make([]byte, len(rem))
			copy(initialPayload, rem)
		}
	} else {
		// HTTP Proxy: read full request header handling TCP fragmentation
		restPtr := cfg.HeaderBufPool.Get().(*[]byte)
		restBuf := *restPtr
		totalRead := copy(restBuf, stackBuf[:nr])

		for {
			if bytes.Contains(restBuf[:totalRead], []byte("\r\n\r\n")) ||
				bytes.Contains(restBuf[:totalRead], []byte("\n\n")) {
				break
			}
			if totalRead >= len(restBuf) {
				cfg.HeaderBufPool.Put(restPtr)
				return
			}
			n, readErr := localConn.Read(restBuf[totalRead:])
			if n > 0 {
				totalRead += n
			}
			if readErr != nil {
				if totalRead <= 1 {
					cfg.HeaderBufPool.Put(restPtr)
					return
				}
				break
			}
		}

		headerBytes := restBuf[:totalRead]
		firstLineEnd := bytes.Index(headerBytes, crlfB)
		if firstLineEnd < 0 {
			firstLineEnd = bytes.IndexByte(headerBytes, '\n')
			if firstLineEnd < 0 {
				cfg.HeaderBufPool.Put(restPtr)
				return
			}
		}
		firstLine := headerBytes[:firstLineEnd]
		sp1 := bytes.IndexByte(firstLine, ' ')
		if sp1 < 0 {
			cfg.HeaderBufPool.Put(restPtr)
			return
		}
		rest := firstLine[sp1+1:]
		sp2 := bytes.IndexByte(rest, ' ')
		var urlBytes []byte
		if sp2 >= 0 {
			urlBytes = rest[:sp2]
		} else {
			urlBytes = rest
		}

		var method string
		methodBytes := firstLine[:sp1]
		if bytes.Equal(methodBytes, []byte("GET")) {
			method = "GET"
		} else if bytes.Equal(methodBytes, []byte("CONNECT")) {
			method = "CONNECT"
		} else if bytes.Equal(methodBytes, []byte("POST")) {
			method = "POST"
		} else if bytes.Equal(methodBytes, []byte("PUT")) {
			method = "PUT"
		} else if bytes.Equal(methodBytes, []byte("DELETE")) {
			method = "DELETE"
		} else if bytes.Equal(methodBytes, []byte("HEAD")) {
			method = "HEAD"
		} else if bytes.Equal(methodBytes, []byte("OPTIONS")) {
			method = "OPTIONS"
		} else if bytes.Equal(methodBytes, []byte("PATCH")) {
			method = "PATCH"
		} else {
			method = string(methodBytes)
		}
		urlPart := string(urlBytes)

		if method == "CONNECT" {
			if strings.Contains(urlPart, ":") {
				h, p, splitErr := net.SplitHostPort(urlPart)
				if splitErr != nil {
					cfg.HeaderBufPool.Put(restPtr)
					return
				}
				targetHost = h
				targetPort = p
			} else {
				targetHost = urlPart
				targetPort = "443"
			}
			cfg.HeaderBufPool.Put(restPtr)
			initialPayload = nil
		} else {
			fullData := make([]byte, totalRead)
			copy(fullData, headerBytes)
			cfg.HeaderBufPool.Put(restPtr)
			initialPayload = fullData

			u, err := url.Parse(urlPart)
			if err == nil && u.Host != "" {
				if strings.Contains(u.Host, ":") {
					h, p, splitErr := net.SplitHostPort(u.Host)
					if splitErr != nil {
						return
					}
					targetHost = h
					targetPort = p
				} else {
					targetHost = u.Host
					targetPort = "80"
				}
			} else {
				// Search Host header at byte level
				searchData := fullData[firstLineEnd+1:]
				for len(searchData) > 0 {
					lineEnd := bytes.Index(searchData, crlfB)
					var line []byte
					if lineEnd < 0 {
						line = searchData
						searchData = nil
					} else {
						line = searchData[:lineEnd]
						searchData = searchData[lineEnd+2:]
					}
					if len(line) > 5 && indexFold(line[:5], "host:") == 0 {
						val := strings.TrimSpace(string(line[5:]))
						if strings.Contains(val, ":") {
							h, p, splitErr := net.SplitHostPort(val)
							if splitErr != nil {
								return
							}
							targetHost = h
							targetPort = p
						} else {
							targetHost = val
							targetPort = "80"
						}
						break
					}
				}
			}
		}
	}

	if targetHost == "" {
		return
	}

	if cfg.BlockLocal && isLocalTarget(targetHost) {
		logWarn("[CLIENT] Blocked local traffic attempt: %s:%s", targetHost, targetPort)
		return
	}

	targetAddr := net.JoinHostPort(targetHost, targetPort)
	_ = localConn.SetDeadline(time.Time{})

	// If QUIC upstream is configured, relay via QUIC
	if cfg.IsQUICUpstream && cfg.QUICPool != nil {
		if relayQUICClient(localConn, ver, initialPayload, targetAddr, cfg) {
			return
		}
	}

	if cfg.Mux && cfg.MuxPool != nil {
		if relayMuxClient(localConn, ver, initialPayload, targetAddr, cfg) {
			return
		}
	}

	// Connect Upstream WS (use pre-parsed URL from startup)
	pooledConn, wsTCPConn, err := dialUpstreamPooledWS(cfg)
	if err != nil {
		logError("Upstream fail: %v", err)
		return
	}
	wsConn := pooledConn.wsConn
	br := pooledConn.br

	// In non-Mux mode, each WebSocket connection is dedicated to a single target relay.
	// The server closes the connection upon relay completion, so post-relay connections
	// cannot be reused. connPool serves as a pre-warmed 0-RTT dial pool.
	defer wsConn.Close()

	optimizeSocket(localConn, cfg)
	localTCPConn := extractTCPConn(localConn)

	targetPayload := []byte(targetHost + ":" + targetPort + "\n")
	targetPayload = cfg.Crypto.sealFrame(targetPayload)
	if err := writeWSFrame(wsConn, targetPayload, 0x2, true); err != nil {
		return
	}

	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	okFrame, err := readWSFrame(br, wsConn, cfg.Crypto)
	if err != nil {
		logError("Read OK failed: %v", err)
		return
	}
	if !strings.HasPrefix(string(okFrame), "OK") {
		logError("Auth rejected by server")
		return
	}

	if ver == 0x05 {
		if _, err := localConn.Write(socks5OKResp); err != nil {
			return
		}
	} else if initialPayload == nil {
		if _, err := localConn.Write(http200Resp); err != nil {
			return
		}
	}

	if initialPayload != nil {
		if err := writeWSFrame(wsConn, initialPayload, 0x2, true); err != nil {
			return
		}
	}

	logInfo("[CLIENT] Tunnel -> %s:%s", targetHost, targetPort)

	errCh := make(chan error, 2)
	// Egress writes get a deadline too (M6): a server that stops reading
	// (or a local app that stops draining) must fail, not wedge us.
	writeTimeout := time.Duration(cfg.ConnTimeout) * time.Second

	// Local -> WS (UPLOAD) — client-to-server frames must be masked (RFC 6455)
	// Use per-goroutine maskPRNG from pool to avoid crypto/rand syscall per frame.
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		var lastDeadline time.Time
		var lastWriteSet time.Time
		var localUp int64
		for {
			if deadlineThrottle(&lastDeadline) {
				setTCPReadDeadline(localTCPConn, cfg.ConnTimeout)
				if localUp > 0 {
					stats.AddBytes(localUp, 0)
					localUp = 0
				}
			}
			nr, errRead := localConn.Read(buf[14:])
			if errRead != nil {
				if localUp > 0 {
					stats.AddBytes(localUp, 0)
				}
				err = errRead
				return
			}

			// Client->server frames are masked; AEAD mode seals the
			// payload in place first (legacy XOR ships relay payloads as-is).
			wireLen := nr
			if rc := relayCrypto(cfg); rc != nil && nr > 0 {
				wireLen = rc.SealRegion(buf[14:], nr)
			}
			refreshWriteDeadline(wsConn, writeTimeout, &lastWriteSet)
			if errWrite := writeWSFramePreallocatedFast(wsConn, buf, 14, wireLen, 0x2, prng); errWrite != nil {
				if localUp > 0 {
					stats.AddBytes(localUp, 0)
				}
				err = errWrite
				return
			}
			localUp += int64(nr)
		}
	}()

	// WS -> Local (DOWNLOAD) — server frames are unmasked, no mask generation needed
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lastDeadline time.Time
		var lastWriteSet time.Time
		var localDown int64
		for {
			if deadlineThrottle(&lastDeadline) {
				setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
				if localDown > 0 {
					stats.AddBytes(0, localDown)
					localDown = 0
				}
			}
			data, errRead := readWSFrameInto(br, wsConn, buf[14:], relayCrypto(cfg))
			if errRead != nil {
				if localDown > 0 {
					stats.AddBytes(0, localDown)
				}
				err = errRead
				return
			}

			// Write coalescing: try to write data immediately
			// For download direction, we write as-is since data comes from WebSocket frames
			refreshWriteDeadline(localConn, writeTimeout, &lastWriteSet)
			if _, errWrite := localConn.Write(data); errWrite != nil {
				if localDown > 0 {
					stats.AddBytes(0, localDown)
				}
				err = errWrite
				return
			}
			localDown += int64(len(data))
		}
	}()

	<-errCh
}

// wsGUID is the WebSocket magic GUID per RFC 6455.
