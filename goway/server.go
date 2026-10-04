// goway – server
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"time"
)

func handleConnection(conn net.Conn, cfg *Config) {
	defer conn.Close()
	if cfg.ConnTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(cfg.ConnTimeout) * time.Second))
	}

	if cfg.Upstream == "" {
		handleServer(conn, cfg)
	} else {
		handleClient(conn, cfg)
	}
}

// --- Server Mode ---
// classifyServerTarget routes the decrypted auth frame's first token.
// The tunnel requests are EXACT tokens ("UDP"/"MUX") — a prefix match here
// misrouted real targets like "udp-example.com:443" or "mux.dev:443" into
// the UDP/MUX tunnels, breaking those sites.
// 'u' = UDP tunnel, 'm' = MUX session, 't' = plain TCP target.
func classifyServerTarget(targetStr string) byte {
	if targetStr == "" {
		return 't'
	}
	switch {
	case strings.EqualFold(targetStr, "UDP"):
		return 'u'
	case strings.EqualFold(targetStr, "MUX"):
		return 'm'
	}
	return 't'
}

func handleServer(wsConn net.Conn, cfg *Config) {
	logDebug("handleServer started for %v", wsConn.RemoteAddr())
	setupStart := time.Now()
	br := bufio.NewReaderSize(wsConn, MaxHeaderSize)
	wsTCPConn := extractTCPConn(wsConn) // cached for tight-loop deadline sets

	headerBytes, err := readUntilCRLFCRLF(br)
	if err != nil {
		logError("handleServer read headers err: %v", err)
		wsConn.Write(http400Resp)
		return
	}
	if indexFold(headerBytes, "upgrade: websocket") < 0 {
		logError("handleServer missing upgrade: websocket")
		wsConn.Write(http400Resp)
		return
	}

	var wsKey string
	if idx := indexFold(headerBytes, "sec-websocket-key:"); idx >= 0 {
		start := idx + 19
		end := bytes.Index(headerBytes[start:], crlfB)
		if end < 0 {
			end = len(headerBytes)
		} else {
			end += start
		}
		if val := bytes.TrimSpace(headerBytes[start:end]); len(val) > 0 {
			wsKey = string(val)
		}
	}

	if wsKey == "" {
		logError("handleServer missing wsKey")
		return
	}

	acc := computeAcceptKey(wsKey)
	// Pre-allocated prefix + accept key + suffix (avoids Buffer + 3 allocs)
	respBuf := make([]byte, len(wsUpgradePrefix)+len(acc)+len(wsUpgradeSuffix))
	copy(respBuf, wsUpgradePrefix)
	copy(respBuf[len(wsUpgradePrefix):], acc)
	copy(respBuf[len(wsUpgradePrefix)+len(acc):], wsUpgradeSuffix)
	if _, err := wsConn.Write(respBuf); err != nil {
		return
	}

	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	authData, err := readWSFrame(br, wsConn, cfg.Crypto)
	if err != nil {
		logError("handleServer read auth data err: %v", err)
		return
	}

	// Handshake done: drop the accept-time absolute deadline set in
	// handleConnection (it would otherwise kill this session on its first
	// write past ConnTimeout — SetReadDeadline refreshes never touch the
	// write half). Relay loops manage their own rolling read deadlines.
	_ = wsConn.SetDeadline(time.Time{})

	targetBytes := bytes.TrimSpace(authData)
	if idx := bytes.IndexByte(targetBytes, ' '); idx >= 0 {
		targetBytes = targetBytes[:idx]
	}
	targetStr := string(targetBytes)

	logDebug("handleServer targetStr: %s", targetStr)

	switch classifyServerTarget(targetStr) {
	case 'u':
		handleServerUDP(wsConn, br, wsTCPConn, cfg)
		return
	case 'm':
		handleServerMux(wsConn, br, wsTCPConn, cfg, time.Since(setupStart))
		return
	}

	// Remote DNS resolution for target address
	targetStr = resolveTargetAddr(cfg.Resolver, targetStr)
	if serverTargetBlocked(cfg, targetStr) {
		logWarn("[SERVER] Blocked local target (server-block-local): %s", targetStr)
		return
	}

	targetConn, err := net.DialTimeout("tcp", targetStr, time.Duration(cfg.ConnTimeout)*time.Second)
	if err != nil {
		logError("handleServer net.DialTimeout err: %v", err)
		return
	}
	defer targetConn.Close()

	optimizeSocket(wsConn, cfg)
	optimizeSocket(targetConn, cfg)

	// Resolve target TCPConn once for use in tight loop
	targetTCPConn := extractTCPConn(targetConn)

	logInfo("[SERVER] Connect -> %s", targetStr)

	var ok []byte
	ok = okCiphered(cfg.Crypto)
	if err := writeWSFrame(wsConn, ok, 0x2, false); err != nil {
		return
	}

	errCh := make(chan error, 2)
	// Egress writes get a deadline too (M6): a client or target that stops
	// draining must fail the write instead of wedging the relay forever.
	writeTimeout := time.Duration(cfg.ConnTimeout) * time.Second

	// WS -> TCP (server receives masked frames from client, unmasks, writes to target)
	// No mask generation needed here — server never masks outbound TCP data.
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lastDeadline time.Time
		var lastWriteSet time.Time
		var localUp int64 // batch counter — avoids atomic on every frame
		for {
			if deadlineThrottle(&lastDeadline) {
				setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
				if localUp > 0 {
					stats.AddBytes(localUp, 0)
					localUp = 0
				}
			}
			data, errRead := readWSFrameInto(br, wsConn, buf[14:], relayCrypto(cfg))
			if errRead != nil {
				if localUp > 0 {
					stats.AddBytes(localUp, 0)
				}
				err = errRead
				return
			}
			refreshWriteDeadline(targetConn, writeTimeout, &lastWriteSet)
			if _, errWrite := targetConn.Write(data); errWrite != nil {
				if localUp > 0 {
					stats.AddBytes(localUp, 0)
				}
				err = errWrite
				return
			}
			localUp += int64(len(data))
		}
	}()

	// TCP -> WS (server reads from target, writes unmasked WS frames to client)
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
				setTCPReadDeadline(targetTCPConn, cfg.ConnTimeout)
				if localDown > 0 {
					stats.AddBytes(0, localDown)
					localDown = 0
				}
			}
			nr, errRead := targetConn.Read(buf[14:])
			if errRead != nil {
				if localDown > 0 {
					stats.AddBytes(0, localDown)
				}
				err = errRead
				return
			}
			// Server->client frames are unmasked (masked=false) — no PRNG
			// needed. AEAD mode seals the payload in place first (legacy
			// XOR mode ships relay payloads as-is).
			wireLen := nr
			if rc := relayCrypto(cfg); rc != nil && nr > 0 {
				wireLen = rc.SealRegion(buf[14:], nr)
			}
			refreshWriteDeadline(wsConn, writeTimeout, &lastWriteSet)
			if errWrite := writeWSFramePreallocated(wsConn, buf, 14, wireLen, 0x2, false); errWrite != nil {
				if localDown > 0 {
					stats.AddBytes(0, localDown)
				}
				err = errWrite
				return
			}
			localDown += int64(nr)
		}
	}()

	<-errCh
}

func isLocalTarget(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// serverTargetBlocked enforces -server-block-local on server-mode dial
// targets (opt-in; default off = behavior identical to prior releases).
// Without it, a server — especially with -allow-open — dials anything the
// client asks, including the server's own loopback and LAN.
func serverTargetBlocked(cfg *Config, target string) bool {
	if cfg == nil || !cfg.ServerBlockLocal || target == "" {
		return false
	}
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	return isLocalTarget(host)
}
