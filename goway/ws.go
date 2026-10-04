// goway – ws
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// --- Browser Profile System ---
// Each profile bundles UA, TLS cipher/curve preferences, and HTTP headers
// that must match each other. Cloudflare cross-checks these signals.

type BrowserProfile struct {
	UA          string
	AcceptLang  string
	SecChUA     string // Chrome Client Hints; empty for Firefox/Safari
	SecChUAMob  string // "?0" desktop, "?1" mobile
	SecChUAPlat string // e.g. `"Windows"`, `"macOS"`, `"Android"`
	IsChromium  bool   // drives TLS cipher ordering
	IsMobile    bool
	// TLS tuning
	CipherSuites []uint16
	CurvePrefs   []tls.CurveID
}

// tlsCiphersChrome136 mirrors Chrome 136 ClientHello cipher suite order.
// Verified against: https://tls.peet.ws/api/all (Chrome 136 / Win10)
var tlsCiphersChrome136 = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

// tlsCiphersFirefox138 mirrors Firefox 138 ClientHello cipher suite order.
var tlsCiphersFirefox138 = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

// curvePrefsChrome mirrors Chrome's ECDH named group preference order.
var curvePrefsChrome = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

// curvePrefsFirefox mirrors Firefox's group preference order.
var curvePrefsFirefox = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

var browserProfiles = []BrowserProfile{
	// --- Chrome 136 Windows ---
	{
		UA:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
		AcceptLang:   "en-US,en;q=0.9",
		SecChUA:      `"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:   "?0",
		SecChUAPlat:  `"Windows"`,
		IsChromium:   true,
		CipherSuites: tlsCiphersChrome136,
		CurvePrefs:   curvePrefsChrome,
	},
	// --- Chrome 136 macOS ---
	{
		UA:           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
		AcceptLang:   "en-US,en;q=0.9",
		SecChUA:      `"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:   "?0",
		SecChUAPlat:  `"macOS"`,
		IsChromium:   true,
		CipherSuites: tlsCiphersChrome136,
		CurvePrefs:   curvePrefsChrome,
	},
	// --- Chrome 136 Windows (zh-CN user) ---
	{
		UA:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
		AcceptLang:   "zh-CN,zh;q=0.9,en;q=0.8",
		SecChUA:      `"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:   "?0",
		SecChUAPlat:  `"Windows"`,
		IsChromium:   true,
		CipherSuites: tlsCiphersChrome136,
		CurvePrefs:   curvePrefsChrome,
	},
	// --- Edge 136 Windows ---
	{
		UA:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
		AcceptLang:   "en-US,en;q=0.9",
		SecChUA:      `"Chromium";v="136", "Microsoft Edge";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:   "?0",
		SecChUAPlat:  `"Windows"`,
		IsChromium:   true,
		CipherSuites: tlsCiphersChrome136,
		CurvePrefs:   curvePrefsChrome,
	},
	// --- Firefox 138 Windows ---
	{
		UA:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
		AcceptLang:   "en-US,en;q=0.5",
		SecChUA:      "", // Firefox does not send sec-ch-ua
		SecChUAMob:   "",
		SecChUAPlat:  "",
		IsChromium:   false,
		CipherSuites: tlsCiphersFirefox138,
		CurvePrefs:   curvePrefsFirefox,
	},
	// --- Firefox 138 macOS ---
	{
		UA:           "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:138.0) Gecko/20100101 Firefox/138.0",
		AcceptLang:   "en-US,en;q=0.5",
		SecChUA:      "",
		SecChUAMob:   "",
		SecChUAPlat:  "",
		IsChromium:   false,
		CipherSuites: tlsCiphersFirefox138,
		CurvePrefs:   curvePrefsFirefox,
	},
	// --- Chrome 136 Android (mobile) ---
	{
		UA:           "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36",
		AcceptLang:   "en-US,en;q=0.9",
		SecChUA:      `"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:   "?1",
		SecChUAPlat:  `"Android"`,
		IsChromium:   true,
		IsMobile:     true,
		CipherSuites: tlsCiphersChrome136,
		CurvePrefs:   curvePrefsChrome,
	},
}

func pickBrowserProfile() BrowserProfile {
	return browserProfiles[mrand.Intn(len(browserProfiles))]
}

// Pre-built TLS configs for each browser profile (avoids per-connection clone)
var profileTLSConfigs []*tls.Config

func initProfileTLSConfigs(base *tls.Config) {
	profileTLSConfigs = make([]*tls.Config, len(browserProfiles))
	for i, p := range browserProfiles {
		conf := base.Clone()
		conf.CipherSuites = p.CipherSuites
		conf.CurvePreferences = p.CurvePrefs
		conf.NextProtos = []string{"http/1.1"}
		profileTLSConfigs[i] = conf
	}
}

func pickProfileTLSConfig() *tls.Config {
	if len(profileTLSConfigs) == 0 {
		return &tls.Config{InsecureSkipVerify: true}
	}
	return profileTLSConfigs[mrand.Intn(len(profileTLSConfigs))]
}

// --- Header Sanitization ---

func sanitizeHeader(value string) string {
	if value == "" {
		return ""
	}
	b := []byte(value)
	n := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c != '\r' && c != '\n' {
			b[n] = c
			n++
		}
	}
	// Trim leading whitespace
	start := 0
	for start < n && (b[start] == ' ' || b[start] == '\t') {
		start++
	}
	// Trim trailing whitespace
	end := n
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t') {
		end--
	}
	return string(b[start:end])
}

// --- WebSocket Framing ---

func getWSHeader(dataLen int, opcode byte, masked bool) []byte {
	var buf [14]byte
	buf[0] = 0b10000000 | opcode
	maskBit := byte(0)
	if masked {
		maskBit = 128
	}
	n := 2
	if dataLen < 126 {
		buf[1] = byte(dataLen) | maskBit
	} else if dataLen < 65536 {
		buf[1] = 126 | maskBit
		binary.BigEndian.PutUint16(buf[2:4], uint16(dataLen))
		n = 4
	} else {
		buf[1] = 127 | maskBit
		binary.BigEndian.PutUint64(buf[2:10], uint64(dataLen))
		n = 10
	}
	return buf[:n]
}

func writeWSFramePreallocated(w io.Writer, buf []byte, payloadOffset int, payloadLen int, opcode byte, masked bool) error {
	hdrLen := 2
	if payloadLen >= 65536 {
		hdrLen = 10
	} else if payloadLen >= 126 {
		hdrLen = 4
	}

	var frameStart int
	if masked {
		frameStart = payloadOffset - 4 - hdrLen
	} else {
		frameStart = payloadOffset - hdrLen
	}

	if frameStart < 0 {
		return errors.New("buffer pre-padding is insufficient")
	}

	buf[frameStart] = 0b10000000 | opcode
	maskBit := byte(0)
	if masked {
		maskBit = 128
	}

	if payloadLen < 126 {
		buf[frameStart+1] = byte(payloadLen) | maskBit
	} else if payloadLen < 65536 {
		buf[frameStart+1] = 126 | maskBit
		binary.BigEndian.PutUint16(buf[frameStart+2:frameStart+4], uint16(payloadLen))
	} else {
		buf[frameStart+1] = 127 | maskBit
		binary.BigEndian.PutUint64(buf[frameStart+2:frameStart+10], uint64(payloadLen))
	}

	if masked {
		mkOffset := frameStart + hdrLen
		mk := buf[mkOffset : mkOffset+4]
		prng := maskPool.Get().(*maskPRNG)
		readMask(mk, prng)
		maskPool.Put(prng)
		maskWord := binary.NativeEndian.Uint32(mk)

		payload := buf[payloadOffset : payloadOffset+payloadLen]
		i := 0
		for ; i+4 <= payloadLen; i += 4 {
			binary.NativeEndian.PutUint32(payload[i:],
				binary.NativeEndian.Uint32(payload[i:])^maskWord)
		}
		for ; i < payloadLen; i++ {
			payload[i] ^= mk[i&3]
		}
	}

	var totalLen int
	if masked {
		totalLen = hdrLen + 4 + payloadLen
	} else {
		totalLen = hdrLen + payloadLen
	}

	_, err := w.Write(buf[frameStart : frameStart+totalLen])
	return err
}

// writeWSFramePreallocatedFast is identical to writeWSFramePreallocated but
// uses a caller-supplied maskPRNG instead of crypto/rand for mask generation.
// Called from relay goroutines; saves one getrandom() syscall (~300ns) per frame.
func writeWSFramePreallocatedFast(w io.Writer, buf []byte, payloadOffset int, payloadLen int, opcode byte, prng *maskPRNG) error {
	hdrLen := 2
	if payloadLen >= 65536 {
		hdrLen = 10
	} else if payloadLen >= 126 {
		hdrLen = 4
	}

	frameStart := payloadOffset - 4 - hdrLen
	if frameStart < 0 {
		return errors.New("buffer pre-padding is insufficient")
	}

	buf[frameStart] = 0b10000000 | opcode

	if payloadLen < 126 {
		buf[frameStart+1] = byte(payloadLen) | 128
	} else if payloadLen < 65536 {
		buf[frameStart+1] = 126 | 128
		binary.BigEndian.PutUint16(buf[frameStart+2:frameStart+4], uint16(payloadLen))
	} else {
		buf[frameStart+1] = 127 | 128
		binary.BigEndian.PutUint64(buf[frameStart+2:frameStart+10], uint64(payloadLen))
	}

	mkOffset := frameStart + hdrLen
	mk := buf[mkOffset : mkOffset+4]
	readMask(mk, prng) // fast xorshift64 — no syscall
	maskWord := binary.NativeEndian.Uint32(mk)

	payload := buf[payloadOffset : payloadOffset+payloadLen]
	i := 0
	for ; i+4 <= payloadLen; i += 4 {
		binary.NativeEndian.PutUint32(payload[i:],
			binary.NativeEndian.Uint32(payload[i:])^maskWord)
	}
	for ; i < payloadLen; i++ {
		payload[i] ^= mk[i&3]
	}

	_, err := w.Write(buf[frameStart : frameStart+hdrLen+4+payloadLen])
	return err
}

// writeMuxFrameFused wraps a pre-encoded MUX region in its WS frame while
// applying the cipher keystream and the WS mask in a SINGLE pass
// (word ^ keystream ^ mask64). It replaces the old two-pass sequence
// (Crypto.TransformInPlace at enqueue + mask-only write here) on the client
// MUX hot path, halving bulk memory traffic. Offset semantics are identical
// to the two-pass version (region-relative, matching TransformInPlace), so
// wire bytes after receiver-side invert are bit-identical; the obfs tail,
// if any, is inside the region and ignored by declared-length slicing.
// crypto == nil degrades to the mask-only fast path.
func encodeMuxFrameFused(buf []byte, payloadOffset int, payloadLen int, opcode byte, prng *maskPRNG, crypto *Crypto) ([]byte, error) {
	hdrLen := 2
	if payloadLen >= 65536 {
		hdrLen = 10
	} else if payloadLen >= 126 {
		hdrLen = 4
	}

	frameStart := payloadOffset - 4 - hdrLen
	if frameStart < 0 {
		return nil, errors.New("buffer pre-padding is insufficient")
	}

	buf[frameStart] = 0b10000000 | opcode

	if payloadLen < 126 {
		buf[frameStart+1] = byte(payloadLen) | 128
	} else if payloadLen < 65536 {
		buf[frameStart+1] = 126 | 128
		binary.BigEndian.PutUint16(buf[frameStart+2:frameStart+4], uint16(payloadLen))
	} else {
		buf[frameStart+1] = 127 | 128
		binary.BigEndian.PutUint64(buf[frameStart+2:frameStart+10], uint64(payloadLen))
	}

	mkOffset := frameStart + hdrLen
	mk := buf[mkOffset : mkOffset+4]
	readMask(mk, prng) // fast xorshift64 — no syscall

	region := buf[payloadOffset : payloadOffset+payloadLen]
	if crypto == nil {
		maskWord := binary.NativeEndian.Uint32(mk)
		i := 0
		for ; i+4 <= payloadLen; i += 4 {
			binary.NativeEndian.PutUint32(region[i:],
				binary.NativeEndian.Uint32(region[i:])^maskWord)
		}
		for ; i < payloadLen; i++ {
			region[i] ^= mk[i&3]
		}
	} else {
		ek := crypto.expandedKey
		maskWord := binary.NativeEndian.Uint32(mk)
		mask64 := uint64(maskWord) | (uint64(maskWord) << 32)
		i := 0
		for ; i+8 <= payloadLen; i += 8 {
			off := i & (cryptoChunkSize - 1)
			binary.NativeEndian.PutUint64(region[i:],
				binary.NativeEndian.Uint64(region[i:])^
					binary.NativeEndian.Uint64(ek[off:])^mask64)
		}
		for ; i < payloadLen; i++ {
			region[i] ^= ek[i&(cryptoChunkSize-1)] ^ mk[i&3]
		}
	}

	return buf[frameStart : frameStart+hdrLen+4+payloadLen], nil
}

func writeMuxFrameFused(w io.Writer, buf []byte, payloadOffset int, payloadLen int, opcode byte, prng *maskPRNG, crypto *Crypto) error {
	slice, err := encodeMuxFrameFused(buf, payloadOffset, payloadLen, opcode, prng, crypto)
	if err != nil {
		return err
	}
	_, err = w.Write(slice)
	return err
}

// writeMuxFrameUnmasked wraps a pre-encoded MUX region in an UNMASKED WS
// frame while applying the cipher keystream in a single pass — the server
// egress counterpart of writeMuxFrameFused. Server→client frames are never
// masked, so there is no mask key; XOR is region-relative and matches
// Crypto.TransformInPlace (offset resets per call region). The obfs tail,
// if any, sits inside the declared-length region and is ignored by
// receivers that slice by the MUX header length. crypto == nil is a pure
// header assembly pass.
func encodeMuxFrameUnmasked(buf []byte, payloadOffset int, payloadLen int, opcode byte, crypto *Crypto) ([]byte, error) {
	hdrLen := 2
	if payloadLen >= 65536 {
		hdrLen = 10
	} else if payloadLen >= 126 {
		hdrLen = 4
	}

	frameStart := payloadOffset - hdrLen
	if frameStart < 0 {
		return nil, errors.New("buffer pre-padding is insufficient")
	}

	buf[frameStart] = 0b10000000 | opcode

	if payloadLen < 126 {
		buf[frameStart+1] = byte(payloadLen)
	} else if payloadLen < 65536 {
		buf[frameStart+1] = 126
		binary.BigEndian.PutUint16(buf[frameStart+2:frameStart+4], uint16(payloadLen))
	} else {
		buf[frameStart+1] = 127
		binary.BigEndian.PutUint64(buf[frameStart+2:frameStart+10], uint64(payloadLen))
	}

	region := buf[payloadOffset : payloadOffset+payloadLen]
	if crypto != nil {
		ek := crypto.expandedKey
		i := 0
		for ; i+8 <= payloadLen; i += 8 {
			off := i & (cryptoChunkSize - 1)
			binary.NativeEndian.PutUint64(region[i:],
				binary.NativeEndian.Uint64(region[i:])^
					binary.NativeEndian.Uint64(ek[off:]))
		}
		for ; i < payloadLen; i++ {
			region[i] ^= ek[i&(cryptoChunkSize-1)]
		}
	}

	return buf[frameStart : frameStart+hdrLen+payloadLen], nil
}

func writeMuxFrameUnmasked(w io.Writer, buf []byte, payloadOffset int, payloadLen int, opcode byte, crypto *Crypto) error {
	slice, err := encodeMuxFrameUnmasked(buf, payloadOffset, payloadLen, opcode, crypto)
	if err != nil {
		return err
	}
	_, err = w.Write(slice)
	return err
}

func writeWSFrame(w io.Writer, data []byte, opcode byte, masked bool) error {
	if !masked {
		header := getWSHeader(len(data), opcode, false)
		bufs := net.Buffers{header, data}
		_, err := bufs.WriteTo(w)
		return err
	}

	dl := len(data)
	hdrLen := 2
	if dl >= 65536 {
		hdrLen = 10
	} else if dl >= 126 {
		hdrLen = 4
	}
	total := hdrLen + 4 + dl
	var frame []byte
	var stackBuf [smallFrameSize + 14]byte
	if total <= len(stackBuf) {
		frame = stackBuf[:total]
	} else {
		frame = make([]byte, total)
	}

	frame[0] = 0b10000000 | opcode
	if dl < 126 {
		frame[1] = byte(dl) | 128
	} else if dl < 65536 {
		frame[1] = 126 | 128
		binary.BigEndian.PutUint16(frame[2:4], uint16(dl))
	} else {
		frame[1] = 127 | 128
		binary.BigEndian.PutUint64(frame[2:10], uint64(dl))
	}

	mk := frame[hdrLen : hdrLen+4]
	rand.Read(mk) // handshake path: crypto/rand is fine here (not per-frame hot path)
	maskWord := binary.NativeEndian.Uint32(mk)

	copy(frame[hdrLen+4:], data)

	payload := frame[hdrLen+4:]
	i := 0
	for ; i+4 <= dl; i += 4 {
		binary.NativeEndian.PutUint32(payload[i:],
			binary.NativeEndian.Uint32(payload[i:])^maskWord)
	}
	for ; i < dl; i++ {
		payload[i] ^= mk[i&3]
	}

	_, err := w.Write(frame)
	return err
}

func optimizeSocket(conn net.Conn, cfg *Config) {
	var netConn net.Conn = conn
	if tlsConn, ok := conn.(*tls.Conn); ok {
		netConn = tlsConn.NetConn()
	}

	tcpConn, ok := netConn.(*net.TCPConn)
	if !ok {
		return
	}
	if !cfg.NoTcpNoDelay {
		if err := tcpConn.SetNoDelay(true); err != nil {
			logDebug("SetNoDelay failed: %v", err)
		}
	}
	if !cfg.NoTcpKeepAlive {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			logDebug("SetKeepAlive failed: %v", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			logDebug("SetKeepAlivePeriod failed: %v", err)
		}
	}
	if cfg.SocketBuffer > 0 {
		if err := tcpConn.SetReadBuffer(cfg.SocketBuffer * 1024); err != nil {
			logDebug("SetReadBuffer failed: %v", err)
		}
		if err := tcpConn.SetWriteBuffer(cfg.SocketBuffer * 1024); err != nil {
			logDebug("SetWriteBuffer failed: %v", err)
		}
	}
}

// extractTCPConn extracts the underlying *net.TCPConn from a net.Conn
// (unwrapping TLS if necessary). Returns nil if not backed by TCP.
func extractTCPConn(conn net.Conn) *net.TCPConn {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		tc, _ := tlsConn.NetConn().(*net.TCPConn)
		return tc
	}
	tc, _ := conn.(*net.TCPConn)
	return tc
}

// setTCPReadDeadline sets a read deadline directly on a pre-resolved *net.TCPConn.
func setTCPReadDeadline(tcpConn *net.TCPConn, timeoutSec int) {
	if tcpConn == nil || timeoutSec <= 0 {
		return
	}
	tcpConn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
}

// deadlineThrottle avoids calling SetReadDeadline on every relay iteration.
// Returns true if the deadline should be updated (at most once per 500ms).
// time.Now() is ~20ns vs SetReadDeadline ~500ns syscall, so checking first saves ~96%.
func deadlineThrottle(lastSet *time.Time) bool {
	now := time.Now()
	if now.Sub(*lastSet) >= 500*time.Millisecond {
		*lastSet = now
		return true
	}
	return false
}

// writeDeadlineSetter is the SetWriteDeadline subset shared by net.Conn
// and quic.Stream.
type writeDeadlineSetter interface {
	SetWriteDeadline(t time.Time) error
}

// refreshWriteDeadline pushes conn's write deadline to now+timeout, at
// most once per 500ms (same rationale as deadlineThrottle: time.Now()
// ~20ns vs the syscall ~500ns). Without it a peer that stops draining
// (wedge-app, stalled target) pins the relay goroutine and its buffers
// forever — the process previously set no write deadline anywhere.
// timeout <= 0 disables the mechanism.
func refreshWriteDeadline(conn writeDeadlineSetter, timeout time.Duration, lastSet *time.Time) {
	if timeout <= 0 {
		return
	}
	if deadlineThrottle(lastSet) {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	}
}

func readUntilCRLFCRLF(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(MaxHeaderSize)
	for {
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			return nil, errors.New("header too large")
		}
		if err != nil {
			return nil, err
		}
		if len(line) > MaxHeaderSize-buf.Len() {
			return nil, errors.New("header too large")
		}
		buf.Write(line)
		b := buf.Bytes()
		n := len(b)
		if n >= 4 && b[n-4] == '\r' && b[n-3] == '\n' && b[n-2] == '\r' && b[n-1] == '\n' {
			return b, nil
		}
		if n >= MaxHeaderSize {
			return nil, errors.New("header too large")
		}
	}
}

// handshakeBufPool pools bytes.Buffer for WebSocket handshake requests.
// Avoids per-connection allocation of ~512 byte buffers.
var handshakeBufPool = sync.Pool{
	New: func() interface{} {
		buf := bytes.NewBuffer(make([]byte, 0, 512))
		return buf
	},
}

// validateWSHandshakeResponse parses and verifies the HTTP status line of a WebSocket handshake response.
// It strictly checks whether the status line contains 101 Switching Protocols and distinguishes
// specific errors for 200, 301, 302, 400, 403, 502, etc.
func validateWSHandshakeResponse(respBytes []byte) error {
	if len(respBytes) == 0 {
		return errors.New("empty websocket handshake response")
	}
	firstLineEnd := bytes.Index(respBytes, crlfB)
	if firstLineEnd < 0 {
		firstLineEnd = len(respBytes)
	}
	firstLine := string(respBytes[:firstLineEnd])
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return fmt.Errorf("malformed websocket handshake response: %q", firstLine)
	}
	statusCode := parts[1]
	if statusCode == "101" {
		return nil
	}
	switch statusCode {
	case "200":
		return errors.New("handshake failed: server returned 200 OK instead of 101 Switching Protocols (upstream may not support WebSocket)")
	case "301", "302", "307", "308":
		return fmt.Errorf("handshake failed: server redirected with HTTP %s", statusCode)
	case "400":
		return errors.New("handshake failed: HTTP 400 Bad Request")
	case "403":
		return errors.New("handshake failed: HTTP 403 Forbidden (check CDN / firewall rules)")
	case "404":
		return errors.New("handshake failed: HTTP 404 Not Found")
	case "502":
		return errors.New("handshake failed: HTTP 502 Bad Gateway")
	case "503":
		return errors.New("handshake failed: HTTP 503 Service Unavailable")
	case "504":
		return errors.New("handshake failed: HTTP 504 Gateway Timeout")
	default:
		return fmt.Errorf("handshake failed: unexpected HTTP status %s (%s)", statusCode, firstLine)
	}
}

// performWSHandshake sends a WebSocket handshake request and strictly validates the 101 response.
func performWSHandshake(wsConn net.Conn, br *bufio.Reader, cfg *Config, wsHost, sniHostname string) error {
	wsURL := cfg.ParsedUpstream
	path := "/"
	if wsURL != nil && wsURL.Path != "" {
		path = wsURL.Path
	}
	profile := pickBrowserProfile()
	var wsKey [16]byte
	if _, err := rand.Read(wsKey[:]); err != nil {
		return err
	}
	wsKeyStr := base64.StdEncoding.EncodeToString(wsKey[:])

	hostHeader := sanitizeHeader(wsHost)
	if cfg.FakeHost != "" {
		hostHeader = sanitizeHeader(cfg.FakeHost)
	}

	protocolScheme := "http"
	if cfg.UpstreamIsWSS {
		protocolScheme = "https"
	}

	secFetchSite := "cross-site"
	if sniHostname == strings.Split(hostHeader, ":")[0] {
		secFetchSite = "same-origin"
	}

	reqLine := "GET " + path + " HTTP/1.1\r\n"

	fixedTop := []string{
		"Host: " + hostHeader,
		"Connection: Upgrade",
		"Upgrade: websocket",
	}

	shufflable := []string{
		"Pragma: no-cache",
		"Cache-Control: no-cache",
		"User-Agent: " + profile.UA,
		"Accept-Language: " + profile.AcceptLang,
		"Accept-Encoding: gzip, deflate, br, zstd",
		"Origin: " + protocolScheme + "://" + sniHostname,
	}

	if profile.IsChromium && profile.SecChUA != "" {
		shufflable = append(shufflable,
			"sec-ch-ua: "+profile.SecChUA,
			"sec-ch-ua-mobile: "+profile.SecChUAMob,
			"sec-ch-ua-platform: "+profile.SecChUAPlat,
		)
	}

	fixedBottom := []string{
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: " + wsKeyStr,
		"Sec-Fetch-Dest: websocket",
		"Sec-Fetch-Mode: websocket",
		"Sec-Fetch-Site: " + secFetchSite,
	}

	for i := len(shufflable) - 1; i > 0; i-- {
		j := mrand.Intn(i + 1)
		shufflable[i], shufflable[j] = shufflable[j], shufflable[i]
	}

	handshakeBuf := handshakeBufPool.Get().(*bytes.Buffer)
	handshakeBuf.Reset()
	handshakeBuf.WriteString(reqLine)
	for _, h := range fixedTop {
		handshakeBuf.WriteString(h)
		handshakeBuf.WriteString("\r\n")
	}
	for _, h := range shufflable {
		handshakeBuf.WriteString(h)
		handshakeBuf.WriteString("\r\n")
	}
	for _, h := range fixedBottom {
		handshakeBuf.WriteString(h)
		handshakeBuf.WriteString("\r\n")
	}
	handshakeBuf.WriteString("\r\n")

	if _, err := wsConn.Write(handshakeBuf.Bytes()); err != nil {
		handshakeBufPool.Put(handshakeBuf)
		return err
	}
	handshakeBufPool.Put(handshakeBuf)

	wsTCPConn := extractTCPConn(wsConn)
	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	respBytes, err := readUntilCRLFCRLF(br)
	if err != nil {
		return err
	}
	return validateWSHandshakeResponse(respBytes)
}

// dialFallback attempts to resolve the fakehost domain to get alternative
// Cloudflare edge IPs when the primary upstream IP is unreachable.
func dialFallback(dialer *net.Dialer, wsHost, wsPort, sniHostname string, cfg *Config) net.Conn {
	if net.ParseIP(wsHost) == nil {
		return nil
	}
	ips, err := net.LookupIP(sniHostname)
	if err != nil || len(ips) == 0 {
		return nil
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 == nil {
			continue
		}
		fallbackAddr := net.JoinHostPort(ip.String(), wsPort)
		if fallbackAddr == net.JoinHostPort(wsHost, wsPort) {
			continue
		}
		logInfo("[DNS] Trying fallback Cloudflare edge: %s (fakehost: %s)", fallbackAddr, sniHostname)
		var conn net.Conn
		if cfg.UpstreamIsWSS {
			conf := pickProfileTLSConfig().Clone()
			conf.ServerName = sniHostname
			conn, err = tls.DialWithDialer(dialer, "tcp", fallbackAddr, conf)
		} else {
			conn, err = dialer.Dial("tcp", fallbackAddr)
		}
		if err != nil {
			logDebug("[DNS] Fallback dial %s failed: %v", fallbackAddr, err)
			continue
		}
		return conn
	}
	return nil
}

// --- Connection Pool ---
// Pre-established WebSocket connections to reduce per-connection setup overhead.
// Each pooled connection has completed TCP+TLS+WS handshake but has NOT sent
// the target frame yet. When grabbed from the pool, the target frame is sent
// and the connection becomes ready for data relay.

type PooledConn struct {
	wsConn   net.Conn
	br       *bufio.Reader
	created  time.Time
	lastUsed time.Time
}

type ConnPool struct {
	conns       []*PooledConn
	mu          sync.Mutex
	cfg         *Config
	maxSize     int
	maxAge      time.Duration
	idleTimeout time.Duration
	closed      bool
	stopChan    chan struct{}
	stopOnce    sync.Once
	deadIPs     map[string]time.Time // temporarily suppress failed IPs
	refillCh    chan struct{}
}

func NewConnPool(cfg *Config, maxSize int) *ConnPool {
	p := &ConnPool{
		conns:       make([]*PooledConn, 0, maxSize),
		cfg:         cfg,
		maxSize:     maxSize,
		maxAge:      5 * time.Minute,
		idleTimeout: 30 * time.Second,
		deadIPs:     make(map[string]time.Time),
		stopChan:    make(chan struct{}),
		refillCh:    make(chan struct{}, 1),
	}
	// Start background goroutine to maintain pool
	go p.maintainLoop()
	return p
}

func (p *ConnPool) maintainLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.cleanup()
			p.refill()
		case <-p.refillCh:
			p.refill()
		}
	}
}

func (p *ConnPool) refill() {
	for i := 0; i < p.maxSize; i++ {
		p.mu.Lock()
		if p.closed || len(p.conns) >= p.maxSize {
			p.mu.Unlock()
			break
		}
		p.mu.Unlock()

		conn := p.createConn()
		if conn == nil {
			break
		}

		p.mu.Lock()
		if p.closed || len(p.conns) >= p.maxSize {
			p.mu.Unlock()
			conn.wsConn.Close()
			break
		}
		p.conns = append(p.conns, conn)
		p.mu.Unlock()
	}
}

func (p *ConnPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	valid := p.conns[:0]
	for _, c := range p.conns {
		if now.Sub(c.created) > p.maxAge || now.Sub(c.lastUsed) > p.idleTimeout {
			c.wsConn.Close()
		} else {
			valid = append(valid, c)
		}
	}
	p.conns = valid
}

func (p *ConnPool) createConn() *PooledConn {
	cfg := p.cfg
	wsHost := cfg.UpstreamHost
	wsPort := cfg.UpstreamPort

	// DNS resolution
	dialHost := wsHost
	if cfg.Resolver != nil {
		if resolvedIP, resolveErr := cfg.Resolver.Resolve(wsHost); resolveErr == nil {
			dialHost = resolvedIP
		} else {
			logDebug("[POOL] DNS resolve failed for upstream %s: %v", wsHost, resolveErr)
			return nil
		}
	}

	dialAddr := net.JoinHostPort(dialHost, wsPort)
	sniHostname := sanitizeHeader(wsHost)
	if cfg.FakeHost != "" {
		sniHostname = sanitizeHeader(strings.Split(cfg.FakeHost, ":")[0])
	}

	dialer := &net.Dialer{Timeout: time.Duration(cfg.ConnTimeout) * time.Second}

	// Skip recently failed IPs, but allow retry after cooldown.
	p.mu.Lock()
	if until, ok := p.deadIPs[dialHost]; ok {
		if time.Now().Before(until) {
			p.mu.Unlock()
			return p.tryFallbackDial(dialer, wsHost, wsPort, sniHostname)
		}
		delete(p.deadIPs, dialHost)
	}
	p.mu.Unlock()

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
		logDebug("[POOL] Dial %s failed: %v", dialAddr, err)
		// Temporarily suppress this IP; retry it after cooldown.
		p.mu.Lock()
		p.deadIPs[dialHost] = time.Now().Add(5 * time.Minute)
		p.mu.Unlock()
		if cfg.FakeHost != "" {
			fallbackConn := p.tryFallbackDial(dialer, wsHost, wsPort, sniHostname)
			if fallbackConn != nil {
				return fallbackConn
			}
		}
		return nil
	}

	optimizeSocket(wsConn, cfg)
	br := bufio.NewReaderSize(wsConn, MaxHeaderSize)
	if err := performWSHandshake(wsConn, br, cfg, wsHost, sniHostname); err != nil {
		wsConn.Close()
		return nil
	}

	return &PooledConn{
		wsConn:   wsConn,
		br:       br,
		created:  time.Now(),
		lastUsed: time.Now(),
	}
}

// tryFallbackDial attempts to resolve the fakehost domain to get alternative
// Cloudflare edge IPs when the primary upstream IP is unreachable.
func (p *ConnPool) tryFallbackDial(dialer *net.Dialer, wsHost, wsPort, sniHostname string) *PooledConn {
	conn := dialFallback(dialer, wsHost, wsPort, sniHostname, p.cfg)
	if conn == nil {
		return nil
	}
	optimizeSocket(conn, p.cfg)
	br := bufio.NewReaderSize(conn, MaxHeaderSize)
	return p.doHandshake(conn, br, p.cfg, sniHostname)
}

func (p *ConnPool) doHandshake(wsConn net.Conn, br *bufio.Reader, cfg *Config, sniHostname string) *PooledConn {
	if err := performWSHandshake(wsConn, br, cfg, cfg.UpstreamHost, sniHostname); err != nil {
		wsConn.Close()
		return nil
	}
	return &PooledConn{
		wsConn:   wsConn,
		br:       br,
		created:  time.Now(),
		lastUsed: time.Now(),
	}
}

func (p *ConnPool) Get() *PooledConn {
	p.mu.Lock()

	if p.closed || len(p.conns) == 0 {
		p.mu.Unlock()
		return nil
	}

	// Pop last connection
	n := len(p.conns)
	conn := p.conns[n-1]
	p.conns = p.conns[:n-1]
	conn.lastUsed = time.Now()
	p.mu.Unlock()

	// Non-blocking signal to maintainLoop to refill pool immediately
	select {
	case p.refillCh <- struct{}{}:
	default:
	}

	return conn
}

func (p *ConnPool) Put(conn *PooledConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed || len(p.conns) >= p.maxSize {
		conn.wsConn.Close()
		return
	}

	// Check if connection is still valid
	if time.Since(conn.created) > p.maxAge {
		conn.wsConn.Close()
		return
	}

	conn.lastUsed = time.Now()
	p.conns = append(p.conns, conn)
}

func (p *ConnPool) Close() {
	p.stopOnce.Do(func() {
		close(p.stopChan)
	})
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, c := range p.conns {
		c.wsConn.Close()
	}
	p.conns = nil
}

// Global connection pool (initialized in main)
var connPool *ConnPool

// readWSFrameInto reads one WebSocket data frame from r, writing any Ping replies
// to w. buf is used as scratch space; if the payload fits it is returned as a
// sub-slice of buf (zero alloc). If not, a heap slice is allocated.
// For the handshake path (readWSFrame), pass a nil buf — small payloads are
// read on the stack and handed back as a heap copy, large payloads are read
// straight into the heap slice returned to the caller (no intermediate copy).
func readWSFrameInto(r io.Reader, w io.Writer, buf []byte, crypto *Crypto) ([]byte, error) {
	return readWSFrameIntoFused(r, w, buf, crypto)
}

// readWSFrameIntoFused reads one WebSocket data frame from r, writing any Ping replies
// to w. If crypto != nil and the frame is masked, unmasking and keystream decryption
// are applied in a SINGLE 64-bit fused pass (payload ^ mask64 ^ keystream), halving
// memory bus traffic on the ingress hot path.
func readWSFrameIntoFused(r io.Reader, w io.Writer, buf []byte, crypto *Crypto) ([]byte, error) {
	for {
		var head [2]byte
		if _, err := io.ReadFull(r, head[:]); err != nil {
			return nil, err
		}

		fin := (head[0] & 0x80) != 0
		opcode := head[0] & 0x0F
		masked := (head[1] & 0x80) != 0
		payloadLen := uint64(head[1] & 0x7F)

		if payloadLen == 126 {
			var b [2]byte
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return nil, err
			}
			payloadLen = uint64(binary.BigEndian.Uint16(b[:]))
		} else if payloadLen == 127 {
			var b [8]byte
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return nil, err
			}
			payloadLen = binary.BigEndian.Uint64(b[:])
		}

		if payloadLen > uint64(MaxWSFrameSize) {
			return nil, errors.New("frame too large")
		}

		// RFC 6455 §5.5: Control frames (Close, Ping, Pong)
		if opcode >= 0x8 {
			if !fin {
				return nil, errors.New("control frame must not be fragmented")
			}
			if payloadLen > 125 {
				return nil, errors.New("control frame payload exceeds 125 bytes")
			}
		} else {
			// RFC 6455 §5.4: Data frames
			if opcode == 0x0 || !fin {
				return nil, errors.New("fragmented websocket frames not supported")
			}
			if opcode != 0x1 && opcode != 0x2 {
				return nil, fmt.Errorf("unsupported websocket opcode: 0x%X", opcode)
			}
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(r, maskKey[:]); err != nil {
				return nil, err
			}
		}

		// Buffer selection:
		//   relay path  (buf != nil): use caller's buf if it fits, else heap-alloc.
		//   handshake path (buf == nil): stack for small frames; large frames are
		//   read directly into the heap slice handed back to the caller.
		var payload []byte
		var stackBuf [smallFrameSize]byte
		var heapOwned []byte

		if buf != nil {
			// relay path — zero-copy into caller's buffer when possible
			if payloadLen <= uint64(len(buf)) {
				payload = buf[:payloadLen]
			} else {
				payload = make([]byte, payloadLen)
			}
		} else {
			// handshake path
			if payloadLen <= smallFrameSize {
				payload = stackBuf[:payloadLen]
			} else {
				heapOwned = make([]byte, payloadLen)
				payload = heapOwned
			}
		}

		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}

		// Ingress unmask + decryption:
		// Data frames: single-pass fused 64-bit XOR when masked and legacy
		// XOR crypto; AEAD mode only unmasks here (the WS mask is stripped
		// first) and then opens [nonce|ct|tag] in place.
		// Control frames: unmask only (RFC 6455 control payloads are never ciphered).
		if opcode < 0x8 {
			aead := crypto != nil && !crypto.isXOR()
			if masked && crypto != nil && !aead {
				ek := crypto.expandedKey
				maskWord := binary.NativeEndian.Uint32(maskKey[:])
				mask64 := uint64(maskWord) | (uint64(maskWord) << 32)
				i := 0
				for ; i+8 <= len(payload); i += 8 {
					off := i & (cryptoChunkSize - 1)
					binary.NativeEndian.PutUint64(payload[i:],
						binary.NativeEndian.Uint64(payload[i:])^
							binary.NativeEndian.Uint64(ek[off:])^mask64)
				}
				for ; i < len(payload); i++ {
					payload[i] ^= ek[i&(cryptoChunkSize-1)] ^ maskKey[i&3]
				}
			} else if masked {
				maskWord := binary.NativeEndian.Uint32(maskKey[:])
				mask64 := uint64(maskWord) | (uint64(maskWord) << 32)
				i := 0
				for ; i+8 <= len(payload); i += 8 {
					binary.NativeEndian.PutUint64(payload[i:],
						binary.NativeEndian.Uint64(payload[i:])^mask64)
				}
				for ; i < len(payload); i++ {
					payload[i] ^= maskKey[i&3]
				}
			} else if crypto != nil && !aead {
				crypto.TransformInPlace(payload)
			}
			if aead {
				var openErr error
				payload, openErr = crypto.OpenRegion(payload)
				if openErr != nil {
					return nil, openErr
				}
			}
		} else if masked {
			maskWord := binary.NativeEndian.Uint32(maskKey[:])
			i := 0
			for ; i+4 <= len(payload); i += 4 {
				binary.NativeEndian.PutUint32(payload[i:],
					binary.NativeEndian.Uint32(payload[i:])^maskWord)
			}
			for ; i < len(payload); i++ {
				payload[i] ^= maskKey[i&3]
			}
		}

		switch opcode {
		case 0x1, 0x2: // Text, Binary
			if buf != nil {
				// relay path — payload already lives in caller's buffer
				return payload, nil
			}
			if heapOwned != nil {
				// handshake path, large frame — read straight into the
				// heap slice we hand back, no copy (payload may be shorter
				// than the wire frame after AEAD open)
				return payload, nil
			}
			// handshake path, stack payload — must return a heap slice
			// (len(payload), not the wire payloadLen: AEAD open shrinks it)
			heapPayload := make([]byte, len(payload))
			copy(heapPayload, payload)
			return heapPayload, nil
		case 0x8: // Close
			return nil, io.EOF
		case 0x9: // Ping
			if w != nil {
				if err := writeWSFrame(w, payload, 0xA, !masked); err != nil {
					return nil, err
				}
			}
		case 0xA: // Pong
			// Discard pong and continue reading
		default:
			return nil, fmt.Errorf("unexpected websocket opcode: 0x%X", opcode)
		}
	}
}

// readWSFrame is the handshake-path wrapper: no caller buffer, returns heap
// copy. crypto (XOR or AEAD) is applied to data frames here; control frames
// are never ciphered.
func readWSFrame(r io.Reader, w io.Writer, crypto *Crypto) ([]byte, error) {
	return readWSFrameIntoFused(r, w, nil, crypto)
}

var wsGUID = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

func computeAcceptKey(challenge string) string {
	sha1buf := make([]byte, 0, len(challenge)+len(wsGUID))
	sha1buf = append(sha1buf, challenge...)
	sha1buf = append(sha1buf, wsGUID...)
	sum := sha1.Sum(sha1buf)
	// Pre-allocate exact base64 output size (28 bytes for 20-byte SHA1)
	var b64 [28]byte
	base64.StdEncoding.Encode(b64[:], sum[:])
	return string(b64[:])
}

func asciiToLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

func indexFold(data []byte, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	// Pre-lower substr so inner loop avoids asciiToLower on every comparison.
	// Substr is ≤19 bytes — compiler stack-allocates this slice.
	sub := []byte(substr)
	for i := 0; i < n; i++ {
		sub[i] = asciiToLower(sub[i])
	}
	first := sub[0]
	for i := 0; i <= len(data)-n; i++ {
		if asciiToLower(data[i]) != first {
			continue
		}
		j := 1
		for ; j < n; j++ {
			if asciiToLower(data[i+j]) != sub[j] {
				break
			}
		}
		if j == n {
			return i
		}
	}
	return -1
}
