package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	Version        = "1.1.12a"
	MaxWSFrameSize = 16 * 1024 * 1024 // 16MB
	MaxHeaderSize  = 8192
	CRLF           = "\r\n"
	CRLFCRLF       = "\r\n\r\n"
)

// ANSI colors
const (
	AnsiReset   = "\033[0m"
	AnsiCyan    = "\033[36m"
	AnsiGreen   = "\033[32m"
	AnsiYellow  = "\033[33m"
	AnsiMagenta = "\033[35m"
	AnsiRed     = "\033[31m"
	AnsiGrey    = "\033[90m"
)

// --- Statistics ---

type Statistics struct {
	activeConns int64
	bytesUp     int64
	bytesDown   int64
}

var stats Statistics

func (s *Statistics) AddConn() {
	atomic.AddInt64(&s.activeConns, 1)
}

func (s *Statistics) RemoveConn() {
	atomic.AddInt64(&s.activeConns, -1)
}

func (s *Statistics) AddBytes(up, down int64) {
	if up > 0 {
		atomic.AddInt64(&s.bytesUp, up)
	}
	if down > 0 {
		atomic.AddInt64(&s.bytesDown, down)
	}
}

// --- Crypto ---

const cryptoChunkSize = 65536 // 64KB pre-expanded key chunk

type Crypto struct {
	keyBytes    []byte
	expandedKey []byte
	keyLen      int
}

func NewCrypto(key string) *Crypto {
	if key == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(key))
	kl := len(hash)
	// Pre-expand key to cryptoChunkSize for single-loop bulk XOR
	ek := bytes.Repeat(hash[:], cryptoChunkSize/kl+1)[:cryptoChunkSize]
	return &Crypto{
		keyBytes:    hash[:],
		expandedKey: ek,
		keyLen:      kl,
	}
}

func (c *Crypto) TransformInPlace(data []byte) {
	if c == nil || len(data) == 0 {
		return
	}
	ek := c.expandedKey
	n := len(data)
	i := 0
	// Bulk: 8-byte XOR against pre-expanded key — single loop, no nesting
	for ; i+8 <= n; i += 8 {
		off := i & (cryptoChunkSize - 1)
		binary.NativeEndian.PutUint64(data[i:],
			binary.NativeEndian.Uint64(data[i:])^
				binary.NativeEndian.Uint64(ek[off:]))
	}
	// Tail: byte-by-byte for remainder (< 8 bytes)
	for ; i < n; i++ {
		data[i] ^= ek[i&(cryptoChunkSize-1)]
	}
}

// --- Config ---

type Config struct {
	ProxyHost      string
	ProxyPort      int
	Upstream       string
	FakeHost       string
	Key            string
	BufferSize     int
	NoTcpNoDelay   bool
	NoTcpKeepAlive bool
	SocketBuffer   int
	ConnTimeout    int
	VerifySSL      bool
	MaxConns       int
	BlockLocal     bool
	AllowOpen      bool

	// Internal derived
	Crypto        *Crypto
	UserAgent     string
	DNS           string
	BufPool       *sync.Pool
	HeaderBufPool *sync.Pool
	TLSBase       *tls.Config
}

// --- Logger ---

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

var globalLogLevel = INFO

func parseLogLevel(levelStr string) LogLevel {
	switch strings.ToUpper(levelStr) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARN":
		return WARN
	case "ERROR":
		return ERROR
	default:
		return INFO
	}
}

func logDebug(format string, v ...interface{}) {
	if globalLogLevel <= DEBUG {
		log.Printf(AnsiCyan+"[DEBUG] "+format+AnsiReset, v...)
	}
}

func logInfo(format string, v ...interface{}) {
	if globalLogLevel <= INFO {
		log.Printf(AnsiGreen+"[INFO] "+format+AnsiReset, v...)
	}
}

func logWarn(format string, v ...interface{}) {
	if globalLogLevel <= WARN {
		log.Printf(AnsiYellow+"[WARN] "+format+AnsiReset, v...)
	}
}

func logError(format string, v ...interface{}) {
	if globalLogLevel <= ERROR {
		log.Printf(AnsiRed+"[ERROR] "+format+AnsiReset, v...)
	}
}

// --- User-Agent Pool ---

var uaPool = []string{
	// Chrome 136 - Windows/Mac/Linux
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
	// Firefox 138 - Windows/Mac/Linux
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:138.0) Gecko/20100101 Firefox/138.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
	// Edge 136
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
	// Safari 18.4 - macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
	// Mobile: iOS Safari 18.4
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
	// Mobile: Android Chrome 136
	"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36",
	// Mobile: Android WebView (common in apps)
	"Mozilla/5.0 (Linux; Android 14; Pixel 7 Build/AP2A.240405.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/136.0.0.0 Mobile Safari/537.36",
}

var acceptLangPool = []string{
	"en-US,en;q=0.9",
	"en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
	"en-GB,en;q=0.9,en-US;q=0.8",
	"zh-CN,zh;q=0.9,en;q=0.8",
	"en-US,en;q=0.9,ja;q=0.8",
}

func pickUA() string {
	return uaPool[mrand.Intn(len(uaPool))]
}

func pickAcceptLang() string {
	return acceptLangPool[mrand.Intn(len(acceptLangPool))]
}

// --- Header Sanitization ---

func sanitizeHeader(value string) string {
	if value == "" {
		return ""
	}
	s := strings.ReplaceAll(value, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.TrimSpace(s)
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

func createWSFrame(data []byte, opcode byte, masked bool) []byte {
	hdr := getWSHeader(len(data), opcode, masked)
	if masked {
		frame := make([]byte, len(hdr)+4+len(data))
		copy(frame, hdr)
		mk := frame[len(hdr) : len(hdr)+4]
		rand.Read(mk)
		payload := frame[len(hdr)+4:]
		copy(payload, data)
		maskWord := binary.NativeEndian.Uint32(mk)
		i := 0
		for ; i+4 <= len(payload); i += 4 {
			binary.NativeEndian.PutUint32(payload[i:],
				binary.NativeEndian.Uint32(payload[i:])^maskWord)
		}
		for ; i < len(payload); i++ {
			payload[i] ^= mk[i&3]
		}
		return frame
	}
	return append(hdr, data...)
}

func writeWSFrame(w io.Writer, data []byte, opcode byte, masked bool) error {
	if !masked {
		header := getWSHeader(len(data), opcode, false)
		bufs := net.Buffers{header, data}
		_, err := bufs.WriteTo(w)
		return err
	}

	// Masked: single allocation for header + 4-byte maskKey + data
	dl := len(data)
	hdrLen := 2
	if dl >= 65536 {
		hdrLen = 10
	} else if dl >= 126 {
		hdrLen = 4
	}
	total := hdrLen + 4 + dl
	frame := make([]byte, total)

	// Build header in-place (avoids getWSHeader stack→heap escape)
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

	// Generate mask key directly into frame
	mk := frame[hdrLen : hdrLen+4]
	rand.Read(mk)
	maskWord := binary.NativeEndian.Uint32(mk)

	// Copy data after header+mask
	copy(frame[hdrLen+4:], data)

	// XOR mask data in-place (4-byte batches + tail)
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

func readUntilCRLFCRLF(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(1024)
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		b := buf.Bytes()
		n := len(b)
		if n >= 4 &&
			b[n-4] == '\r' && b[n-3] == '\n' &&
			b[n-2] == '\r' && b[n-1] == '\n' {
			return b, nil
		}
		if n > MaxHeaderSize {
			return nil, errors.New("header too large")
		}
	}
}

func readWSFrame(r io.Reader, w io.Writer) ([]byte, error) {
	for {
		var head [2]byte
		if _, err := io.ReadFull(r, head[:]); err != nil {
			return nil, err
		}

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

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(r, maskKey[:]); err != nil {
				return nil, err
			}
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}

		if masked {
			mk := maskKey[:]
			maskWord := binary.NativeEndian.Uint32(mk)
			i := 0
			for ; i+4 <= len(payload); i += 4 {
				binary.NativeEndian.PutUint32(payload[i:],
					binary.NativeEndian.Uint32(payload[i:])^maskWord)
			}
			for ; i < len(payload); i++ {
				payload[i] ^= mk[i&3]
			}
		}

		if opcode == 0x0 || opcode == 0x1 || opcode == 0x2 {
			return payload, nil
		}
		if opcode == 0x8 {
			return nil, io.EOF
		}
		if opcode == 0x9 {
			if w != nil {
				if err := writeWSFrame(w, payload, 0xA, true); err != nil {
					return nil, err
				}
			}
			continue
		}
		continue
	}
}

// --- Main Logic ---

func main() {
	pFlag := flag.String("p", "", "Listen Address (e.g. :8080)")
	upFlag := flag.String("up", "", "Upstream WebSocket URL")
	kFlag := flag.String("k", "", "Authentication Key")
	logFlag := flag.String("log", "INFO", "Log Level")
	fakeHostFlag := flag.String("fakehost", "", "Spoofing Hostname")
	wFlag := flag.Int("W", 0, "App Buffer Size in KB")
	noDelayFlag := flag.Bool("no-tcp-nodelay", false, "Disable TCP_NODELAY")
	keepAliveFlag := flag.Bool("no-tcp-keepalive", false, "Disable TCP KeepAlive")
	sockBufFlag := flag.Int("socket-buffer", 0, "Kernel Socket Buffer")
	connTimeoutFlag := flag.Int("connection-timeout", 300, "Connection Timeout")
	verifySSLFlag := flag.Bool("verify-ssl", false, "Enable SSL Verification")
	maxConnFlag := flag.Int("max-conn", 1000, "Max Concurrent Connections")
	blockLocalFlag := flag.Bool("block-local", false, "Drop local/LAN traffic (Client mode)")
	allowOpenFlag := flag.Bool("allow-open", false, "Allow server mode without authentication key")

	flag.Parse()

	globalLogLevel = parseLogLevel(*logFlag)

	if *pFlag == "" {
		fmt.Println("Error: -p is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg := Config{
		Upstream:       *upFlag,
		FakeHost:       *fakeHostFlag,
		Key:            *kFlag,
		BufferSize:     65536,
		NoTcpNoDelay:   *noDelayFlag,
		NoTcpKeepAlive: *keepAliveFlag,
		SocketBuffer:   *sockBufFlag,
		ConnTimeout:    *connTimeoutFlag,
		VerifySSL:      *verifySSLFlag,
		MaxConns:       *maxConnFlag,
		BlockLocal:     *blockLocalFlag,
		AllowOpen:      *allowOpenFlag,
	}

	host := "0.0.0.0"
	portStr := *pFlag
	if strings.Contains(*pFlag, ":") {
		parts := strings.Split(*pFlag, ":")
		if len(parts) == 2 {
			if parts[0] != "" {
				host = parts[0]
			}
			portStr = parts[1]
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Printf("Error: invalid port '%s'\n", portStr)
		os.Exit(1)
	}
	cfg.ProxyHost = host
	cfg.ProxyPort = port

	if *wFlag > 0 {
		cfg.BufferSize = *wFlag * 1024
	}

	cfg.Crypto = NewCrypto(cfg.Key)

	// Server mode without authentication is an open proxy risk
	if cfg.Upstream == "" && cfg.Crypto == nil && !cfg.AllowOpen {
		fmt.Println("Error: Server mode requires -k (authentication key) or --allow-open flag")
		os.Exit(1)
	}

	// Print Banner
	mode := "Server"
	if cfg.Upstream != "" {
		mode = "Client (HTTP + SOCKS5)"
	}

	fmt.Printf("%sGOWAY v%s%s\n", AnsiCyan, Version, AnsiReset)
	fmt.Printf("%s%s%s\n", AnsiCyan, strings.Repeat("-", 60), AnsiReset)

	listenAddr := fmt.Sprintf("%s:%d", cfg.ProxyHost, cfg.ProxyPort)
	fmt.Printf(" [+] Mode:        %s%s%s\n", AnsiGreen, mode, AnsiReset)
	fmt.Printf(" [+] Listen:      %s%s%s\n", AnsiYellow, listenAddr, AnsiReset)

	if cfg.Upstream != "" {
		fmt.Printf(" [+] Upstream:    %s%s%s\n", AnsiMagenta, cfg.Upstream, AnsiReset)
		verifyStr := "Disabled (Insecure)"
		verifyCol := AnsiRed
		if cfg.VerifySSL {
			verifyStr = "Enabled"
			verifyCol = AnsiGreen
		}
		fmt.Printf(" [+] SSL Verify:  %s%s%s\n", verifyCol, verifyStr, AnsiReset)
		fmt.Printf(" [+] User-Agent:  %sRandomized (Sticky)%s\n", AnsiGreen, AnsiReset)
	}

	dnsCol := AnsiYellow
	fmt.Printf(" [+] DNS:         %sSystem default%s\n", dnsCol, AnsiReset)

	if cfg.Crypto != nil {
		fmt.Printf(" [+] Auth:        %sEnabled (XOR)%s\n", AnsiGreen, AnsiReset)
	} else if cfg.Upstream == "" {
		fmt.Printf(" [+] Auth:        %sDISABLED (--allow-open enabled — Open Proxy!)%s\n", AnsiRed, AnsiReset)
	} else {
		// Client mode without key: server may still accept unauthenticated
		fmt.Printf(" [+] Auth:        %sDISABLED%s\n", AnsiYellow, AnsiReset)
	}

	bufKB := cfg.BufferSize / 1024
	bufInfo := fmt.Sprintf("%d KB", bufKB)
	if cfg.SocketBuffer > 0 {
		bufInfo += fmt.Sprintf(" (Socket: %d KB)", cfg.SocketBuffer)
	}
	fmt.Printf(" [+] Buffer:      %s\n", bufInfo)
	fmt.Printf(" [+] Max Conns:   %d\n", cfg.MaxConns)

	cfg.TLSBase = &tls.Config{
		InsecureSkipVerify: !cfg.VerifySSL,
		MinVersion:         tls.VersionTLS12,
	}

	cfg.BufPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, cfg.BufferSize); return &buf
		},
	}

	cfg.HeaderBufPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, MaxHeaderSize)
			return &buf
		},
	}

	fmt.Printf("%s%s%s\n", AnsiCyan, strings.Repeat("-", 60), AnsiReset)
	fmt.Printf("%s[INFO] Proxy listening... (Press Ctrl+C to stop)%s\n\n", AnsiCyan, AnsiReset)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to bind: %v", err)
	}

	// Graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	shutdown := make(chan struct{})

	go func() {
		<-sigCh
		logInfo("Received shutdown signal, closing listener...")
		close(shutdown)
		listener.Close()
	}()

	go monitorStats(shutdown)

	logInfo("Proxy listening on %s...", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-shutdown:
				// Normal shutdown
			default:
				logDebug("Accept error: %v", err)
			}
			break
		}

		if atomic.LoadInt64(&stats.activeConns) >= int64(cfg.MaxConns) {
			logWarn("MaxConns (%d) reached, rejecting connection", cfg.MaxConns)
			conn.Close()
			continue
		}

		stats.AddConn()
		go func(c net.Conn) {
			defer stats.RemoveConn()
			handleConnection(c, &cfg)
		}(conn)
	}

	logInfo("Proxy stopped.")
}

func monitorStats(shutdown <-chan struct{}) {
	var lastUp, lastDown int64
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			currUp := atomic.LoadInt64(&stats.bytesUp)
			currDown := atomic.LoadInt64(&stats.bytesDown)
			active := atomic.LoadInt64(&stats.activeConns)

			upSpeed := float64(currUp-lastUp) / 3.0 / 1024.0 / 1024.0
			downSpeed := float64(currDown-lastDown) / 3.0 / 1024.0 / 1024.0

			lastUp = currUp
			lastDown = currDown

			if globalLogLevel <= INFO {
				fmt.Printf("\r%s[STATS] Conns: %d | Up: %.2f MB/s | Down: %.2f MB/s%s",
					AnsiGrey, active, upSpeed, downSpeed, AnsiReset)
			}
		}
	}
}

func handleConnection(conn net.Conn, cfg *Config) {
	defer conn.Close()

	if cfg.Upstream == "" {
		handleServer(conn, cfg)
	} else {
		handleClient(conn, cfg)
	}
}

// --- Server Mode ---
func handleServer(wsConn net.Conn, cfg *Config) {
	logDebug("handleServer started for %v", wsConn.RemoteAddr())
	br := bufio.NewReaderSize(wsConn, MaxHeaderSize)
	wsTCPConn := extractTCPConn(wsConn) // cached for tight-loop deadline sets

	headerBytes, err := readUntilCRLFCRLF(br)
	if err != nil {
		logError("handleServer read headers err: %v", err)
		wsConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	if indexFold(headerBytes, "upgrade: websocket") < 0 {
		logError("handleServer missing upgrade: websocket")
		wsConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	var wsKey string
	if idx := indexFold(headerBytes, "sec-websocket-key:"); idx >= 0 {
		start := idx + 19
		end := bytes.Index(headerBytes[start:], []byte("\r\n"))
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
	if _, err := wsConn.Write([]byte(fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc))); err != nil {
		return
	}

	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	authData, err := readWSFrame(br, wsConn)
	if err != nil {
		logError("handleServer read auth data err: %v", err)
		return
	}

	if cfg.Crypto != nil {
		cfg.Crypto.TransformInPlace(authData)
	}

	targetBytes := bytes.TrimSpace(authData)
	if idx := bytes.IndexByte(targetBytes, ' '); idx >= 0 {
		targetBytes = targetBytes[:idx]
	}
	targetStr := string(targetBytes)

	logDebug("handleServer targetStr: %s", targetStr)

	targetConn, err := net.DialTimeout("tcp4", targetStr, time.Duration(cfg.ConnTimeout)*time.Second)
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

	ok := []byte("OK\n")
	if cfg.Crypto != nil {
		cfg.Crypto.TransformInPlace(ok)
	}
	if err := writeWSFrame(wsConn, ok, 0x2, false); err != nil {
		return
	}

	errCh := make(chan error, 2)

	// WS -> TCP
	go func() {
		var err error
		defer func() { errCh <- err }()
		for {
			setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
			data, errRead := readWSFrame(br, wsConn)
			if errRead != nil {
				err = errRead
				return
			}
			if _, errWrite := targetConn.Write(data); errWrite != nil {
				err = errWrite
				return
			}
			stats.AddBytes(int64(len(data)), 0)
		}
	}()

	// TCP -> WS
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		for {
			setTCPReadDeadline(targetTCPConn, cfg.ConnTimeout)
			nr, errRead := targetConn.Read(buf)
			if errRead != nil {
				err = errRead
				return
			}
			if errWrite := writeWSFrame(wsConn, buf[:nr], 0x2, false); errWrite != nil {
				err = errWrite
				return
			}
			stats.AddBytes(0, int64(nr))
		}
	}()

	<-errCh
}

func isLocalTarget(host string) bool {
	if strings.EqualFold(host, "localhost") ||
		host == "127.0.0.1" || host == "::1" || host == "[::1]" || host == "0.0.0.0" {
		return true
	}
	// Private IPv4 always starts with '1' (10.x, 172.16+, 192.168.x).
	// Skip ToLower allocation for the common case of public hostnames.
	if len(host) > 0 && host[0] != '1' {
		return false
	}
	h := strings.ToLower(host)
	if strings.HasPrefix(h, "192.168.") || strings.HasPrefix(h, "10.") {
		return true
	}
	if strings.HasPrefix(h, "172.") {
		if dot := strings.IndexByte(h[4:], '.'); dot >= 0 {
			if b, err := strconv.Atoi(h[4 : 4+dot]); err == nil && b >= 16 && b <= 31 {
				return true
			}
		}
	}
	return false
}

// --- Client Mode ---
func handleClient(localConn net.Conn, cfg *Config) {
	buf := make([]byte, 1)
	if _, err := localConn.Read(buf); err != nil {
		return
	}

	var targetHost string
	var targetPort string
	var initialPayload []byte

	ver := buf[0]
	if ver == 0x05 {
		// SOCKS5
		var nmBuf [1]byte
		if _, err := localConn.Read(nmBuf[:]); err != nil {
			return
		}
		nmethods := int(nmBuf[0])
		discard := make([]byte, nmethods)
		if _, err := localConn.Read(discard); err != nil {
			return
		}

		if _, err := localConn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		var reqHead [4]byte
		if _, err := localConn.Read(reqHead[:]); err != nil {
			return
		}
		cmd := reqHead[1]
		atyp := reqHead[3]

		if cmd != 0x01 {
			return
		}

		if atyp == 0x01 {
			var ipBuf [4]byte
			if _, err := io.ReadFull(localConn, ipBuf[:]); err != nil {
				return
			}
			targetHost = net.IP(ipBuf[:]).String()
		} else if atyp == 0x03 {
			var lenBuf [1]byte
			if _, err := io.ReadFull(localConn, lenBuf[:]); err != nil {
				return
			}
			domainBuf := make([]byte, int(lenBuf[0]))
			if _, err := io.ReadFull(localConn, domainBuf); err != nil {
				return
			}
			targetHost = string(domainBuf)
		} else if atyp == 0x04 {
			var ipBuf [16]byte
			if _, err := io.ReadFull(localConn, ipBuf[:]); err != nil {
				return
			}
			targetHost = "[" + net.IP(ipBuf[:]).String() + "]"
		}

		var portBuf [2]byte
		if _, err := io.ReadFull(localConn, portBuf[:]); err != nil {
			return
		}
		portVal := binary.BigEndian.Uint16(portBuf[:])
		targetPort = strconv.Itoa(int(portVal))
	} else {
		// HTTP Proxy
		restPtr := cfg.HeaderBufPool.Get().(*[]byte)
		restBuf := *restPtr
		n, readErr := localConn.Read(restBuf)
		if readErr != nil && n == 0 {
			cfg.HeaderBufPool.Put(restPtr)
			return
		}
		// Parse first line from restBuf (avoids fullData alloc for CONNECT)
		firstLineEnd := bytes.Index(restBuf[:n], []byte("\r\n"))
		if firstLineEnd < 0 {
			cfg.HeaderBufPool.Put(restPtr)
			return
		}
		reqLine := string(buf[0]) + string(restBuf[:firstLineEnd])
		parts := strings.Fields(reqLine)
		if len(parts) < 2 {
			cfg.HeaderBufPool.Put(restPtr)
			return
		}
		method := parts[0]
		urlPart := parts[1]

		if method == "CONNECT" {
			if strings.Contains(urlPart, ":") {
				h, p, splitErr := net.SplitHostPort(urlPart)
				if splitErr != nil {
					cfg.HeaderBufPool.Put(restPtr)
					return
				}
				targetHost = h
				targetPort = p
			}
			cfg.HeaderBufPool.Put(restPtr)
			initialPayload = nil
		} else {
			fullData := make([]byte, 1+n)
			copy(fullData, buf)
			copy(fullData[1:], restBuf[:n])
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
				searchData := fullData[firstLineEnd+3:]
				for len(searchData) > 0 {
					lineEnd := bytes.Index(searchData, []byte("\r\n"))
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

	// Connect Upstream WS
	wsURL, err := url.Parse(cfg.Upstream)
	if err != nil {
		logError("Invalid upstream URL: %v", err)
		return
	}
	var wsConn net.Conn

	wsHost := wsURL.Hostname()
	wsPort := wsURL.Port()
	if wsPort == "" {
		if wsURL.Scheme == "wss" || wsURL.Scheme == "https" {
			wsPort = "443"
		} else {
			wsPort = "80"
		}
	}

	dialAddr := net.JoinHostPort(wsHost, wsPort)
	sniHostname := sanitizeHeader(wsHost)
	if cfg.FakeHost != "" {
		sniHostname = sanitizeHeader(strings.Split(cfg.FakeHost, ":")[0])
	}

	if wsURL.Scheme == "wss" || wsURL.Scheme == "https" {
		conf := cfg.TLSBase.Clone()
		conf.ServerName = sniHostname
		wsConn, err = tls.Dial("tcp", dialAddr, conf)
	} else {
		wsConn, err = net.Dial("tcp", dialAddr)
	}

	if err != nil {
		logError("Upstream fail: %v", err)
		return
	}
	defer wsConn.Close()

	optimizeSocket(localConn, cfg)
	optimizeSocket(wsConn, cfg)

	localTCPConn := extractTCPConn(localConn)
	wsTCPConn := extractTCPConn(wsConn)

	br := bufio.NewReaderSize(wsConn, MaxHeaderSize)

	path := wsURL.Path
	if path == "" {
		path = "/"
	}
	wsKey := make([]byte, 16)
	if _, err := rand.Read(wsKey); err != nil {
		return
	}
	wsKeyStr := base64.StdEncoding.EncodeToString(wsKey)

	hostHeader := sanitizeHeader(wsHost)
	if cfg.FakeHost != "" {
		hostHeader = sanitizeHeader(cfg.FakeHost)
	}

	userAgent := pickUA()
	acceptLang := pickAcceptLang()
	protocolScheme := "http"
	if wsURL.Scheme == "wss" || wsURL.Scheme == "https" {
		protocolScheme = "https"
	}

	secFetch := "websocket"

	reqLine := fmt.Sprintf("GET %s HTTP/1.1\r\n", path)
	headers := []string{
		fmt.Sprintf("Host: %s", hostHeader),
		"Connection: Upgrade",
		"Pragma: no-cache",
		"Cache-Control: no-cache",
		fmt.Sprintf("User-Agent: %s", userAgent),
		"Upgrade: websocket",
		fmt.Sprintf("Origin: %s://%s", protocolScheme, sniHostname),
		"Sec-WebSocket-Version: 13",
		fmt.Sprintf("Sec-WebSocket-Key: %s", wsKeyStr),
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
		fmt.Sprintf("Accept-Language: %s", acceptLang),
		"Accept-Encoding: gzip, deflate, br, zstd",
		fmt.Sprintf("Sec-Fetch-Dest: %s", secFetch),
		"Sec-Fetch-Mode: websocket",
		"Sec-Fetch-Site: cross-site",
	}

	// Fisher-Yates shuffle
	for i := len(headers) - 1; i > 0; i-- {
		j := mrand.Intn(i + 1)
		headers[i], headers[j] = headers[j], headers[i]
	}

	var handshakeBuf bytes.Buffer
	handshakeBuf.Grow(len(reqLine) + len(headers)*80 + 2)
	handshakeBuf.WriteString(reqLine)
	for _, h := range headers {
		handshakeBuf.WriteString(h)
		handshakeBuf.WriteString("\r\n")
	}
	handshakeBuf.WriteString("\r\n")

	if _, err := wsConn.Write(handshakeBuf.Bytes()); err != nil {
		return
	}

	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	respBytes, err := readUntilCRLFCRLF(br)
	if err != nil {
		logError("Handshake read failed: %v", err)
		return
	}
	if !bytes.Contains(respBytes, []byte("101")) {
		logError("Handshake failed status: %s", string(respBytes))
		return
	}

	targetPayload := []byte(fmt.Sprintf("%s:%s\n", targetHost, targetPort))
	padLen := 1 + mrand.Intn(40)
	for i := 0; i < padLen; i++ {
		targetPayload = append(targetPayload, ' ')
	}

	if cfg.Crypto != nil {
		cfg.Crypto.TransformInPlace(targetPayload)
	}
	if err := writeWSFrame(wsConn, targetPayload, 0x2, true); err != nil {
		return
	}

	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	okFrame, err := readWSFrame(br, wsConn)
	if err != nil {
		logError("Read OK failed: %v", err)
		return
	}
	if cfg.Crypto != nil {
		cfg.Crypto.TransformInPlace(okFrame)
	}
	if !strings.HasPrefix(string(okFrame), "OK") {
		logError("Auth rejected by server")
		return
	}

	if ver == 0x05 {
		if _, err := localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
	} else if initialPayload == nil {
		if _, err := localConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
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

	// Local -> WS (UPLOAD)
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		for {
			setTCPReadDeadline(localTCPConn, cfg.ConnTimeout)
			nr, errRead := localConn.Read(buf)
			if errRead != nil {
				err = errRead
				return
			}
			data := buf[:nr]
			if errWrite := writeWSFrame(wsConn, data, 0x2, true); errWrite != nil {
				err = errWrite
				return
			}
			stats.AddBytes(int64(nr), 0)
		}
	}()

	// WS -> Local (DOWNLOAD)
	go func() {
		var err error
		defer func() { errCh <- err }()
		for {
			setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
			data, errRead := readWSFrame(br, wsConn)
			if errRead != nil {
				err = errRead
				return
			}
			if _, errWrite := localConn.Write(data); errWrite != nil {
				err = errWrite
				return
			}
			stats.AddBytes(0, int64(len(data)))
		}
	}()

	<-errCh
}

func computeAcceptKey(challenge string) string {
	h := sha1.New()
	h.Write([]byte(challenge))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
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
