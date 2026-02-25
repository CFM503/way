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
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Version        = "1.0.8a"
	MaxWSFrameSize = 16 * 1024 * 1024 // 16MB
	// MaxHeaderSize increased to accommodate some large headers, but pyway limits to 8192
	MaxHeaderSize = 8192
	CRLF          = "\r\n"
	CRLFCRLF      = "\r\n\r\n"
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

// Crypto implements a basic XOR obfuscation.
// WARNING: This is NOT cryptographically secure. It is only intended
// to obfuscate payload patterns to evade simple Deep Packet Inspection (DPI).
type Crypto struct {
	keyBytes []byte
	keyLen   int
}

func NewCrypto(key string) *Crypto {
	if key == "" {
		return nil
	}
	// Hashes the key with SHA256 to create a 32-byte key for XOR
	hash := sha256.Sum256([]byte(key))
	return &Crypto{
		keyBytes: hash[:],
		keyLen:   len(hash),
	}
}

// Simple XOR transform
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
	for i := 0; i < len(data); i++ {
		data[i] ^= c.keyBytes[i%c.keyLen]
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

	// Internal derived
	Crypto    *Crypto
	UserAgent string
	DNS       string
	BufPool   *sync.Pool
}

// --- Logger ---

// Loglevel type and constants
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

// --- WebSocket Framing ---

func getWSHeader(dataLen int, opcode byte, masked bool) []byte {
	header := make([]byte, 0, 14)
	finBit := byte(0b10000000)
	header = append(header, finBit|opcode)

	maskBit := byte(0)
	if masked {
		maskBit = 128
	}

	if dataLen < 126 {
		header = append(header, byte(dataLen)|maskBit)
	} else if dataLen < 65536 {
		header = append(header, 126|maskBit)
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(dataLen))
		header = append(header, b...)
	} else {
		header = append(header, 127|maskBit)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(dataLen))
		header = append(header, b...)
	}
	return header
}

func createWSFrame(data []byte, opcode byte, masked bool) []byte {
	header := getWSHeader(len(data), opcode, masked)
	if masked {
		maskKey := make([]byte, 4)
		rand.Read(maskKey)
		header = append(header, maskKey...)

		payload := make([]byte, len(data))
		for i := 0; i < len(data); i++ {
			payload[i] = data[i] ^ maskKey[i&3]
		}
		return append(header, payload...)
	}
	return append(header, data...)
}

// In-place WS Frame creation. Requires dst to have enough capacity (len(data) + 14)
// dst buffer should have the payload starting at dst[offset:], where offset is the header length.
// We will write header backwards.
// A simpler zero-copy approach: We pass the payload and an empty slice that has enough capacity.
func writeWSFrame(w io.Writer, data []byte, opcode byte, masked bool) error {
	header := getWSHeader(len(data), opcode, masked)
	if masked {
		maskKey := make([]byte, 4)
		rand.Read(maskKey)
		header = append(header, maskKey...)
		w.Write(header)

		// In-place mask of data
		for i := 0; i < len(data); i++ {
			data[i] ^= maskKey[i&3]
		}
		_, err := w.Write(data)
		return err
	}

	netbs := make([][]byte, 2)
	netbs[0] = header
	netbs[1] = data
	// If w is a net.Buffers, we could use that, but simple Write is fine for now
	w.Write(header)
	_, err := w.Write(data)
	return err
}

func optimizeSocket(conn net.Conn, cfg *Config) {
	// If conn is a tls.Conn, get the underlying net.Conn
	var netConn net.Conn = conn
	if tlsConn, ok := conn.(*tls.Conn); ok {
		netConn = tlsConn.NetConn()
	}

	tcpConn, ok := netConn.(*net.TCPConn)
	if !ok {
		return
	}
	if !cfg.NoTcpNoDelay {
		tcpConn.SetNoDelay(true)
	}
	if !cfg.NoTcpKeepAlive {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	if cfg.SocketBuffer > 0 {
		tcpConn.SetReadBuffer(cfg.SocketBuffer * 1024)
		tcpConn.SetWriteBuffer(cfg.SocketBuffer * 1024)
	}
}

// Helper to read until CRLFCRLF from a buffered reader without losing bytes
func readUntilCRLFCRLF(br *bufio.Reader) ([]byte, error) {
	var res []byte
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		res = append(res, line...)
		if strings.HasSuffix(string(res), CRLFCRLF) {
			break
		}
		if len(res) > MaxHeaderSize {
			return nil, errors.New("header too large")
		}
	}
	return res, nil
}

func readWSFrame(r io.Reader, w io.Writer) ([]byte, error) {
	for {
		head := make([]byte, 2)
		if _, err := io.ReadFull(r, head); err != nil {
			return nil, err
		}

		opcode := head[0] & 0x0F
		// masked := (head[1] & 0x80) != 0 // Client side, server shouldn't mask usually but we handle it
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

		// Handle Opcodes
		if opcode == 0x0 || opcode == 0x1 || opcode == 0x2 {
			return payload, nil
		}
		if opcode == 0x8 {
			return nil, io.EOF
		}
		if opcode == 0x9 {
			// Reply Pong
			if w != nil {
				w.Write(createWSFrame(payload, 0xA, true)) // Client masks pong to server
			}
			continue
		}
		continue
	}
}

// --- Main Logic ---

func main() {
	// Parse Flags
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
	}

	// Parse Listen Address
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
	port, _ := strconv.Atoi(portStr)
	cfg.ProxyHost = host
	cfg.ProxyPort = port

	if *wFlag > 0 {
		cfg.BufferSize = *wFlag * 1024
	}

	cfg.Crypto = NewCrypto(cfg.Key)

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
	} else {
		fmt.Printf(" [+] Auth:        %sDISABLED (Open Proxy Risk!)%s\n", AnsiRed, AnsiReset)
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

	go monitorStats()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to bind: %v", err)
	}

	logInfo("Proxy listening on %s...", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		stats.AddConn()
		go func(c net.Conn) {
			defer stats.RemoveConn()
			handleConnection(c, &cfg)
		}(conn)
	}
}

func monitorStats() {
	var lastUp, lastDown int64
	for {
		time.Sleep(3 * time.Second)
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

func handleConnection(conn net.Conn, cfg *Config) {
	defer conn.Close()

	if cfg.Upstream == "" {
		handleServer(conn, cfg)
	} else {
		handleClient(conn, cfg)
	}
}

// --- Server Mode: Accepts WebSocket, Extracts Target, Connects to Target ---
func handleServer(wsConn net.Conn, cfg *Config) {
	logDebug("handleServer started for %v", wsConn.RemoteAddr())
	br := bufio.NewReader(wsConn)
	// 1. Handshake
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

	// Find Key
	var wsKey string
	for _, line := range strings.Split(headerStr, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				wsKey = strings.TrimSpace(parts[1])
			}
		}
	}

	if wsKey == "" {
		logError("handleServer missing wsKey")
		return
	}

	acc := computeAcceptKey(wsKey)
	wsConn.Write([]byte(fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc)))

	// 2. Read Auth Frame
	authData, err := readWSFrame(br, wsConn)
	if err != nil {
		logError("handleServer read auth data err: %v", err)
		return
	}

	if cfg.Crypto != nil {
		authData = cfg.Crypto.Transform(authData)
	}

	targetStr := strings.TrimSpace(string(authData))
	targetStr = strings.Fields(targetStr)[0] // Take first word

	logDebug("handleServer targetStr: %s", targetStr)
	// 3. Connect to Target
	// Force IPv4 to prevent IPv6 routing issues on some VPS
	targetConn, err := net.DialTimeout("tcp4", targetStr, time.Duration(cfg.ConnTimeout)*time.Second)
	if err != nil {
		logError("handleServer net.DialTimeout err: %v", err)
		return
	}
	defer targetConn.Close()

	optimizeSocket(wsConn, cfg)
	optimizeSocket(targetConn, cfg)

	logInfo("[SERVER] Connect -> %s", targetStr)

	// 4. Send OK
	ok := []byte("OK\n")
	if cfg.Crypto != nil {
		ok = cfg.Crypto.Transform(ok)
	}
	if _, err := wsConn.Write(createWSFrame(ok, 0x2, false)); err != nil {
		return
	}

	// 5. Tunnel — NO crypto on tunnel data (only auth/OK frames use crypto)
	errCh := make(chan error, 2)

	// WS -> TCP (raw, no crypto)
	go func() {
		var err error
		defer func() { errCh <- err }()
		for {
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

	// TCP -> WS (raw, no crypto)
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		for {
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
	if strings.HasPrefix(h, "172.") { // 172.16.x.x - 172.31.x.x
		parts := strings.Split(h, ".")
		if len(parts) >= 2 {
			if b, err := strconv.Atoi(parts[1]); err == nil && b >= 16 && b <= 31 {
				return true
			}
		}
	}
	return false
}

// --- Client Mode: Accepts SOCKS5/HTTP, Connects WS Upstream ---
func handleClient(localConn net.Conn, cfg *Config) {
	// 1. Sniff protocol
	buf := make([]byte, 1) // Read first byte
	if _, err := localConn.Read(buf); err != nil {
		return
	}

	var targetHost string
	var targetPort string
	var initialPayload []byte // Valid payload to forward

	ver := buf[0]
	if ver == 0x05 {
		// SOCKS5
		// Client Hello: 05 XX ...
		// Consume methods
		// We skipped num_methods already? No.
		// ver (1) + nmethods (1) + methods (n)
		// We read ver.
		nmBuf := make([]byte, 1)
		if _, err := localConn.Read(nmBuf); err != nil {
			return
		}
		nmethods := int(nmBuf[0])
		discard := make([]byte, nmethods)
		if _, err := localConn.Read(discard); err != nil {
			return
		}

		// Send Method Selection: No Auth
		if _, err := localConn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		// Request
		// Ver(1) Cmd(1) Rsv(1) Atyp(1)
		reqHead := make([]byte, 4)
		if _, err := localConn.Read(reqHead); err != nil {
			return
		}
		cmd := reqHead[1]
		atyp := reqHead[3]

		if cmd != 0x01 {
			return
		} // Only CONNECT

		if atyp == 0x01 { // IPv4
			ipBuf := make([]byte, 4)
			if _, err := io.ReadFull(localConn, ipBuf); err != nil {
				return
			}
			targetHost = net.IP(ipBuf).String()
		} else if atyp == 0x03 { // Domain
			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(localConn, lenBuf); err != nil { // Ignore unread bytes error
				return
			}
			domainBuf := make([]byte, int(lenBuf[0]))
			if _, err := io.ReadFull(localConn, domainBuf); err != nil {
				return
			}
			targetHost = string(domainBuf)
		} else if atyp == 0x04 { // IPv6
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

		// Reply Success later
	} else {
		// HTTP Proxy
		// Read until line end
		// Reconstruct request line
		// This part is tricky to do perfectly without buffering, but we can do a simple read
		// Assuming we read enough to parse headers.
		// We'll revert to reading a chunk.
		restBuf := make([]byte, 8192)
		n, _ := localConn.Read(restBuf)
		fullData := append(buf, restBuf[:n]...) // Prepend the first byte

		initialPayload = fullData // For HTTP, we might forward the payload if it's not CONNECT

		// Parse HTTP
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
			// CONNECT host:port HTTP/1.1
			if strings.Contains(urlPart, ":") {
				h, p, _ := net.SplitHostPort(urlPart)
				targetHost = h
				targetPort = p
			}
			initialPayload = nil // Don't forward CONNECT payload
		} else {
			// GET http://host/path HTTP/1.1
			u, err := url.Parse(urlPart)
			if err == nil && u.Host != "" {
				if strings.Contains(u.Host, ":") {
					h, p, _ := net.SplitHostPort(u.Host)
					targetHost = h
					targetPort = p
				} else {
					targetHost = u.Host
					targetPort = "80"
				}
			} else {
				// Search Host header
				for _, l := range lines {
					if strings.HasPrefix(strings.ToLower(l), "host:") {
						val := strings.TrimSpace(strings.Split(l, ":")[1])
						if strings.Contains(val, ":") {
							h, p, _ := net.SplitHostPort(val)
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

	// Local Network Interception Check
	if isLocalTarget(targetHost) {
		if cfg.BlockLocal {
			logWarn("[CLIENT] Blocked local traffic attempt: %s:%s", targetHost, targetPort)
			return // Drop connection entirely
		}
	}

	// 2. Connect Upstream WS
	wsURL, _ := url.Parse(cfg.Upstream)
	var wsConn net.Conn
	var err error

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
	sniHostname := wsHost
	if cfg.FakeHost != "" {
		sniHostname = strings.Split(cfg.FakeHost, ":")[0]
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

	// Send Upgrade
	path := wsURL.Path
	if path == "" {
		path = "/"
	}
	wsKey := make([]byte, 16)
	rand.Read(wsKey)
	wsKeyStr := base64.StdEncoding.EncodeToString(wsKey)

	hostHeader := wsHost
	if cfg.FakeHost != "" {
		hostHeader = cfg.FakeHost
	}

	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
	protocolScheme := "http"
	if wsURL.Scheme == "wss" || wsURL.Scheme == "https" {
		protocolScheme = "https"
	}

	handshake := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: Upgrade\r\n"+
		"Pragma: no-cache\r\n"+
		"Cache-Control: no-cache\r\n"+
		"User-Agent: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Origin: %s://%s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n",
		path, hostHeader, userAgent, protocolScheme, sniHostname, wsKeyStr)

	if _, err := wsConn.Write([]byte(handshake)); err != nil {
		return
	}

	// Read Response
	respBytes, err := readUntilCRLFCRLF(br)
	if err != nil {
		logError("Handshake read failed: %v", err)
		return
	}
	if !strings.Contains(string(respBytes), "101") {
		logError("Handshake failed status: %s", string(respBytes))
		return
	}

	// 3. Send Target Info (Auth Frame)
	targetPayload := []byte(fmt.Sprintf("%s:%s\n", targetHost, targetPort))
	// Random padding 1-40 spaces
	padLen := 10 // Using fixed for now but adding random requires math/rand
	targetPayload = append(targetPayload, []byte(strings.Repeat(" ", padLen))...)

	if cfg.Crypto != nil {
		targetPayload = cfg.Crypto.Transform(targetPayload)
	}
	wsConn.Write(createWSFrame(targetPayload, 0x2, true))

	// 4. Wait for OK
	okFrame, err := readWSFrame(br, wsConn)
	if err != nil {
		logError("Read OK failed: %v", err)
		return
	}
	if cfg.Crypto != nil {
		okFrame = cfg.Crypto.Transform(okFrame)
	}
	if !strings.HasPrefix(string(okFrame), "OK") {
		logError("Auth rejected by server")
		return
	}

	// 5. Reply to Local Client
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

	// 6. Tunnel
	errCh := make(chan error, 2)

	// Local -> WS (UPLOAD) — NO crypto on tunnel data, only auth/OK frames use crypto
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		for {
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

	// WS -> Local (DOWNLOAD) — NO crypto on tunnel data
	go func() {
		var err error
		defer func() { errCh <- err }()
		for {
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
