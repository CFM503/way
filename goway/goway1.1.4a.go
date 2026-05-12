package main

import (
	"bufio"
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
	Version        = "1.1.4a"
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

type Crypto struct {
	keyBytes []byte
	keyLen   int
}

func NewCrypto(key string) *Crypto {
	if key == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(key))
	return &Crypto{
		keyBytes: hash[:],
		keyLen:   len(hash),
	}
}

func (c *Crypto) Transform(data []byte) []byte {
	if c == nil || len(data) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ c.keyBytes[i%c.keyLen]
	}
	return out
}

func (c *Crypto) TransformInPlace(data []byte) {
	if c == nil || len(data) == 0 {
		return
	}
	key := c.keyBytes
	kl := c.keyLen
	i := 0
	for ; i+kl <= len(data); i += kl {
		for j := 0; j < kl; j++ {
			data[i+j] ^= key[j]
		}
	}
	for ; i < len(data); i++ {
		data[i] ^= key[i%kl]
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
	Crypto    *Crypto
	UserAgent string
	DNS       string
	BufPool   *sync.Pool
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
		for i := range payload {
			payload[i] ^= mk[i&3]
		}
		return frame
	}
	return append(hdr, data...)
}

func writeWSFrame(w io.Writer, data []byte, opcode byte, masked bool) error {
	header := getWSHeader(len(data), opcode, masked)
	if masked {
		maskKey := make([]byte, 4)
		rand.Read(maskKey)
		header = append(header, maskKey...)
		frame := make([]byte, len(header)+len(data))
		copy(frame, header)
		copy(frame[len(header):], data)
		for i := len(header); i < len(frame); i++ {
			frame[i] ^= maskKey[(i-len(header))&3]
		}
		_, err := w.Write(frame)
		return err
	}

	bufs := net.Buffers{header, data}
	_, err := bufs.WriteTo(w)
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

// setReadDeadline sets a read deadline on the underlying TCP connection
// to detect idle/hung connections.
func setReadDeadline(conn net.Conn, timeoutSec int) {
	if timeoutSec <= 0 {
		return
	}
	var tcpConn *net.TCPConn
	if tlsConn, ok := conn.(*tls.Conn); ok {
		tcpConn, _ = tlsConn.NetConn().(*net.TCPConn)
	} else {
		tcpConn, _ = conn.(*net.TCPConn)
	}
	if tcpConn != nil {
		tcpConn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	}
}

func readUntilCRLFCRLF(br *bufio.Reader) ([]byte, error) {
	res := make([]byte, 0, 512)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		res = append(res, line...)
		n := len(res)
		if n >= 4 &&
			res[n-4] == '\r' && res[n-3] == '\n' &&
			res[n-2] == '\r' && res[n-1] == '\n' {
			break
		}
		if n > MaxHeaderSize {
			return nil, errors.New("header too large")
		}
	}
	return res, nil
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
			b := make([]byte, 2)
			if _, err := io.ReadFull(r, b); err != nil {
				return nil, err
			}
			payloadLen = uint64(binary.BigEndian.Uint16(b))
		} else if payloadLen == 127 {
			b := make([]byte, 8)
			if _, err := io.ReadFull(r, b); err != nil {
				return nil, err
			}
			payloadLen = binary.BigEndian.Uint64(b)
		}

		if payloadLen > uint64(MaxWSFrameSize) {
			return nil, errors.New("frame too large")
		}

		var maskKey []byte
		if masked {
			maskKey = make([]byte, 4)
			if _, err := io.ReadFull(r, maskKey); err != nil {
				return nil, err
			}
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}

		if masked {
			for i := 0; i < len(payload); i++ {
				payload[i] ^= maskKey[i&3]
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
				if _, err := w.Write(createWSFrame(payload, 0xA, true)); err != nil {
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

	cfg.BufPool = &sync.Pool{
		New: func() interface{} {
			b := make([]byte, cfg.BufferSize)
			return &b
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
	br := bufio.NewReader(wsConn)

	headerBytes, err := readUntilCRLFCRLF(br)
	if err != nil {
		logError("handleServer read headers err: %v", err)
		wsConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	headerStr := string(headerBytes)

	if !strings.Contains(strings.ToLower(headerStr), "upgrade: websocket") {
		logError("handleServer missing upgrade: websocket")
		wsConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	var wsKey string
	for _, line := range strings.Split(headerStr, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
			_, val, ok := strings.Cut(line, ":")
			if ok {
				wsKey = strings.TrimSpace(val)
			}
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

	setReadDeadline(wsConn, cfg.ConnTimeout)
	authData, err := readWSFrame(br, wsConn)
	if err != nil {
		logError("handleServer read auth data err: %v", err)
		return
	}

	if cfg.Crypto != nil {
		cfg.Crypto.TransformInPlace(authData)
	}

	targetStr := strings.TrimSpace(string(authData))
	targetStr = strings.Fields(targetStr)[0]

	logDebug("handleServer targetStr: %s", targetStr)

	targetConn, err := net.DialTimeout("tcp4", targetStr, time.Duration(cfg.ConnTimeout)*time.Second)
	if err != nil {
		logError("handleServer net.DialTimeout err: %v", err)
		return
	}
	defer targetConn.Close()

	optimizeSocket(wsConn, cfg)
	optimizeSocket(targetConn, cfg)

	logInfo("[SERVER] Connect -> %s", targetStr)

	ok := []byte("OK\n")
	if cfg.Crypto != nil {
		cfg.Crypto.TransformInPlace(ok)
	}
	if _, err := wsConn.Write(createWSFrame(ok, 0x2, false)); err != nil {
		return
	}

	errCh := make(chan error, 2)

	// WS -> TCP
	go func() {
		var err error
		defer func() { errCh <- err }()
		for {
			setReadDeadline(wsConn, cfg.ConnTimeout)
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
			setReadDeadline(targetConn, cfg.ConnTimeout)
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
	h := strings.ToLower(host)
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]" || h == "0.0.0.0" {
		return true
	}
	if strings.HasPrefix(h, "192.168.") || strings.HasPrefix(h, "10.") {
		return true
	}
	if strings.HasPrefix(h, "172.") {
		parts := strings.Split(h, ".")
		if len(parts) >= 2 {
			if b, err := strconv.Atoi(parts[1]); err == nil && b >= 16 && b <= 31 {
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
		nmBuf := make([]byte, 1)
		if _, err := localConn.Read(nmBuf); err != nil {
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

		reqHead := make([]byte, 4)
		if _, err := localConn.Read(reqHead); err != nil {
			return
		}
		cmd := reqHead[1]
		atyp := reqHead[3]

		if cmd != 0x01 {
			return
		}

		if atyp == 0x01 {
			ipBuf := make([]byte, 4)
			if _, err := io.ReadFull(localConn, ipBuf); err != nil {
				return
			}
			targetHost = net.IP(ipBuf).String()
		} else if atyp == 0x03 {
			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(localConn, lenBuf); err != nil {
				return
			}
			domainBuf := make([]byte, int(lenBuf[0]))
			if _, err := io.ReadFull(localConn, domainBuf); err != nil {
				return
			}
			targetHost = string(domainBuf)
		} else if atyp == 0x04 {
			ipBuf := make([]byte, 16)
			if _, err := io.ReadFull(localConn, ipBuf); err != nil {
				return
			}
			targetHost = "[" + net.IP(ipBuf).String() + "]"
		}

		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(localConn, portBuf); err != nil {
			return
		}
		portVal := binary.BigEndian.Uint16(portBuf)
		targetPort = strconv.Itoa(int(portVal))
	} else {
		// HTTP Proxy
		restBuf := make([]byte, 8192)
		n, readErr := localConn.Read(restBuf)
		if readErr != nil && n == 0 {
			return
		}
		fullData := append(buf, restBuf[:n]...)

		initialPayload = fullData

		reqStr := string(fullData)
		lines := strings.Split(reqStr, "\r\n")
		if len(lines) == 0 {
			return
		}
		reqLine := lines[0]
		parts := strings.Fields(reqLine)
		if len(parts) < 2 {
			return
		}
		method := parts[0]
		urlPart := parts[1]

		if method == "CONNECT" {
			if strings.Contains(urlPart, ":") {
				h, p, splitErr := net.SplitHostPort(urlPart)
				if splitErr != nil {
					return
				}
				targetHost = h
				targetPort = p
			}
			initialPayload = nil
		} else {
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
				for _, l := range lines {
					if strings.HasPrefix(strings.ToLower(l), "host:") {
						val := strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
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
		conf := &tls.Config{
			InsecureSkipVerify: !cfg.VerifySSL,
			ServerName:         sniHostname,
			MinVersion:         tls.VersionTLS12,
		}
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

	br := bufio.NewReader(wsConn)

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

	var handshakeBuf strings.Builder
	handshakeBuf.Grow(len(reqLine) + len(headers)*80 + 2)
	handshakeBuf.WriteString(reqLine)
	for _, h := range headers {
		handshakeBuf.WriteString(h)
		handshakeBuf.WriteString("\r\n")
	}
	handshakeBuf.WriteString("\r\n")

	if _, err := wsConn.Write([]byte(handshakeBuf.String())); err != nil {
		return
	}

	setReadDeadline(wsConn, cfg.ConnTimeout)
	respBytes, err := readUntilCRLFCRLF(br)
	if err != nil {
		logError("Handshake read failed: %v", err)
		return
	}
	if !strings.Contains(string(respBytes), "101") {
		logError("Handshake failed status: %s", string(respBytes))
		return
	}

	targetPayload := []byte(fmt.Sprintf("%s:%s\n", targetHost, targetPort))
	padLen := 1 + mrand.Intn(40)
	targetPayload = append(targetPayload, []byte(strings.Repeat(" ", padLen))...)

	if cfg.Crypto != nil {
		cfg.Crypto.TransformInPlace(targetPayload)
	}
	if _, err := wsConn.Write(createWSFrame(targetPayload, 0x2, true)); err != nil {
		return
	}

	setReadDeadline(wsConn, cfg.ConnTimeout)
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
			setReadDeadline(localConn, cfg.ConnTimeout)
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
			setReadDeadline(wsConn, cfg.ConnTimeout)
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
