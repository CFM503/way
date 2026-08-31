package main

import (
	"bufio"
	"bytes"
	"context"
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
	"math"
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
	Version        = "1.6.0"
	MaxWSFrameSize = 64 * 1024 * 1024 // 64MB (increased from 16MB for better throughput)
	MaxHeaderSize  = 8192
	CRLF           = "\r\n"
	CRLFCRLF       = "\r\n\r\n"
)

var (
	okBytes = []byte("OK\n")
	crlfB   = []byte{'\r', '\n'}

	// Pre-allocated static responses (avoid per-connection alloc)
	socks5OKResp     = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	http200Resp      = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	http400Resp      = []byte("HTTP/1.1 400 Bad Request\r\n\r\n")
	wsUpgradePrefix  = []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
	wsUpgradeSuffix  = []byte("\r\n\r\n")
)

// --- Fast Mask PRNG ---
// WebSocket masking only requires unpredictability from the server's perspective,
// not cryptographic randomness. RFC 6455 §10.3 says masking prevents proxy
// cache poisoning; it is NOT a security primitive. Using crypto/rand here
// costs a getrandom() syscall (~300ns) per frame — replaced with a per-goroutine
// xorshift64 that amortises to ~2ns/frame with zero syscalls.
//
// goroutineMask is a goroutine-local PRNG state stored in a sync.Pool so each
// relay goroutine gets its own instance (no lock contention).

type maskPRNG struct{ state uint64 }

var maskPool = sync.Pool{
	New: func() interface{} {
		var seed [8]byte
		rand.Read(seed[:]) // one-time crypto seed per goroutine
		s := binary.LittleEndian.Uint64(seed[:])
		if s == 0 {
			s = 0xdeadbeefcafebabe
		}
		return &maskPRNG{state: s}
	},
}

// next returns the next 32-bit mask via xorshift64.
func (p *maskPRNG) next32() uint32 {
	x := p.state
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	p.state = x
	return uint32(x)
}

// readMask fills a 4-byte slice with fast pseudorandom mask bytes.
func readMask(dst []byte, p *maskPRNG) {
	v := p.next32()
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

// Small-frame stack threshold for readWSFrame pool optimization
const smallFrameSize = 512
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
// Cache-line layout: hot counters (written by every relay goroutine) separated
// from speed floats (written once per second by monitorStats) to prevent
// false sharing on multi-core CPUs.

type Statistics struct {
	// Hot path — written by every relay goroutine via atomic ops.
	activeConns int64
	bytesUp     int64
	bytesDown   int64
	_pad        [5]int64 // pad to 64-byte cache line boundary

	// Written only by monitorStats (once/sec); stored as math/bits uint64
	// to allow atomic load/store without a mutex.
	speedUpBits   uint64 // math.Float64bits(MB/s)
	speedDownBits uint64
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

func (s *Statistics) SetSpeeds(up, down float64) {
	atomic.StoreUint64(&s.speedUpBits, math.Float64bits(up))
	atomic.StoreUint64(&s.speedDownBits, math.Float64bits(down))
}

func (s *Statistics) Speeds() (up, down float64) {
	return math.Float64frombits(atomic.LoadUint64(&s.speedUpBits)),
		math.Float64frombits(atomic.LoadUint64(&s.speedDownBits))
}
// --- TUI / GUI-Style CLI Implementation ---

var (
	tuiEnabled bool
	tuiLogMu   sync.Mutex

	// Ring buffer for TUI logs — avoids O(n) slice-copy every 100 entries.
	tuiRingBuf [100]string
	tuiRingLen int // number of valid entries (≤ 100)
	tuiRingPos int // index of next write slot

	tuiRefreshCh = make(chan struct{}, 1)
)

func initWindowsConsole() {
	// No-op on single-file cross-platform version
}

func getTerminalSize() (width int, height int) {
	return 80, 24
}

func addTuiLog(line string) {
	tuiLogMu.Lock()
	line = strings.TrimSpace(line)
	tuiRingBuf[tuiRingPos] = line
	tuiRingPos = (tuiRingPos + 1) % len(tuiRingBuf)
	if tuiRingLen < len(tuiRingBuf) {
		tuiRingLen++
	}
	tuiLogMu.Unlock()
	triggerTuiRefresh()
}

// tuiLogSlice returns the last n entries from the ring buffer in order.
// Must be called with tuiLogMu held.
func tuiLogSlice(n int) []string {
	if n > tuiRingLen {
		n = tuiRingLen
	}
	out := make([]string, n)
	// oldest entry that falls within the window
	start := (tuiRingPos - n + len(tuiRingBuf)) % len(tuiRingBuf)
	for i := 0; i < n; i++ {
		out[i] = tuiRingBuf[(start+i)%len(tuiRingBuf)]
	}
	return out
}

// spaces is a 200-char padding source; sliced instead of strings.Repeat per call.
const spaces = "                                                                                                                                                                                                        "

func padRight(s string, n int) string {
	if n <= 0 {
		return s
	}
	if n > len(spaces) {
		n = len(spaces)
	}
	return s + spaces[:n]
}

func triggerTuiRefresh() {
	select {
	case tuiRefreshCh <- struct{}{}:
	default:
	}
}



func visibleLength(s string) int {
	inEscape := false
	length := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if s[i] == 'm' {
				inEscape = false
			}
			continue
		}
		length++
	}
	return length
}

func padVisible(s string, width int) string {
	vl := visibleLength(s)
	if vl >= width {
		return s
	}
	pad := width - vl
	if pad > len(spaces) {
		pad = len(spaces)
	}
	return s + spaces[:pad]
}

func truncateVisible(s string, maxLen int) string {
	vl := visibleLength(s)
	if vl <= maxLen {
		return s
	}
	var result strings.Builder
	inEscape := false
	visibleCount := 0
	limit := maxLen - 3
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEscape = true
			result.WriteByte(s[i])
			continue
		}
		if inEscape {
			result.WriteByte(s[i])
			if s[i] == 'm' {
				inEscape = false
			}
			continue
		}
		if visibleCount < limit {
			result.WriteByte(s[i])
			visibleCount++
		} else {
			break
		}
	}
	result.WriteString("...")
	result.WriteString(AnsiReset)
	return result.String()
}

func drawTuiRow(buf *bytes.Buffer, content string, width int) {
	buf.WriteString("│ ")
	visibleLen := visibleLength(content)
	buf.WriteString(content)
	pad := width - 4 - visibleLen
	if pad > 0 {
		if pad > len(spaces) {
			pad = len(spaces)
		}
		buf.WriteString(spaces[:pad])
	}
	buf.WriteString(" │\n")
}

func formatTwoColumns(leftLabel, leftVal, rightLabel, rightVal string, colWidth int) string {
	leftStr := leftLabel + leftVal
	rightStr := rightLabel + rightVal
	return padVisible(leftStr, colWidth) + rightStr
}

func formatBytes(bytes int64) string {
	if bytes == 0 {
		return "0 B"
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func drawTUI(cfg *Config) {
	termWidth, termHeight := getTerminalSize()

	boxWidth := termWidth - 2
	if boxWidth < 50 {
		boxWidth = 50
	}
	if boxWidth > 110 {
		boxWidth = 110
	}

	innerWidth := boxWidth - 4
	colWidth := innerWidth / 2

	// Cache border strings (avoid strings.Repeat every 500ms)
	if cfg.TUIBorderWidth != boxWidth {
		hLine := strings.Repeat("─", boxWidth-2)
		cfg.TUIBorderTop = "┌" + hLine + "┐\n"
		cfg.TUIBorderMid = "├" + hLine + "┤\n"
		cfg.TUIBorderBottom = "└" + hLine + "┘\n"
		cfg.TUIBorderWidth = boxWidth
	}

	var buf bytes.Buffer
	buf.Grow(boxWidth * (termHeight + 2)) // pre-allocate for full screen
	buf.WriteString("\033[H\033[J")

	// Top Border
	buf.WriteString(cfg.TUIBorderTop)

	// Title — use spaces slice instead of strings.Repeat
	title := "GOWAY Proxy Dashboard (v" + Version + ")"
	pad := (boxWidth - 2 - len(title)) / 2
	if pad < 0 {
		pad = 0
	}
	rpad := boxWidth - 2 - pad - len(title)
	buf.WriteString("│")
	if pad > 0 && pad <= len(spaces) {
		buf.WriteString(spaces[:pad])
	}
	buf.WriteString(AnsiCyan + title + AnsiReset)
	if rpad > 0 && rpad <= len(spaces) {
		buf.WriteString(spaces[:rpad])
	}
	buf.WriteString("│\n")
	buf.WriteString(cfg.TUIBorderMid)

	// Config Panel
	mode := "Server"
	if cfg.Upstream != "" {
		mode = "Client (HTTP + SOCKS5)"
	}
	modeCol := AnsiGreen + mode + AnsiReset
	if cfg.Upstream == "" {
		modeCol = AnsiYellow + mode + AnsiReset
	}
	maxConnVal := fmt.Sprintf("%d", cfg.MaxConns)
	drawTuiRow(&buf, formatTwoColumns("Mode:      ", modeCol, "Max Conns:   ", maxConnVal, colWidth), boxWidth)

	listenVal := fmt.Sprintf("%s:%d", cfg.ProxyHost, cfg.ProxyPort)
	timeoutVal := fmt.Sprintf("%ds", cfg.ConnTimeout)
	drawTuiRow(&buf, formatTwoColumns("Listen:    ", AnsiYellow+listenVal+AnsiReset, "Timeout:     ", AnsiYellow+timeoutVal+AnsiReset, colWidth), boxWidth)

	upstreamVal := "N/A"
	if cfg.Upstream != "" {
		upstreamVal = cfg.Upstream
	}
	blockLocalVal := "Disabled"
	blockLocalCol := AnsiRed + blockLocalVal + AnsiReset
	if cfg.BlockLocal {
		blockLocalVal = "Enabled"
		blockLocalCol = AnsiGreen + blockLocalVal + AnsiReset
	}
	drawTuiRow(&buf, formatTwoColumns("Upstream:  ", AnsiMagenta+upstreamVal+AnsiReset, "Block Local: ", blockLocalCol, colWidth), boxWidth)

	var sslVerifyStr string
	if cfg.Upstream != "" {
		if cfg.VerifySSL {
			sslVerifyStr = AnsiGreen + "Enabled" + AnsiReset
		} else {
			sslVerifyStr = AnsiRed + "Disabled (Insecure)" + AnsiReset
		}
	} else {
		sslVerifyStr = AnsiGrey + "N/A" + AnsiReset
	}

	var authStr string
	if cfg.Crypto != nil {
		authStr = AnsiGreen + "Enabled (XOR)" + AnsiReset
	} else if cfg.Upstream == "" {
		authStr = AnsiRed + "DISABLED (Open Proxy!)" + AnsiReset
	} else {
		authStr = AnsiYellow + "Disabled" + AnsiReset
	}
	drawTuiRow(&buf, formatTwoColumns("Auth:      ", authStr, "SSL Verify:  ", sslVerifyStr, colWidth), boxWidth)

	var dnsStr string
	if cfg.Resolver != nil {
		dnsStr = AnsiGreen + "Remote: " + cfg.Resolver.serverIP + AnsiReset
	} else {
		dnsStr = AnsiYellow + "System Default" + AnsiReset
	}
	var levelStr string
	switch globalLogLevel {
	case DEBUG:
		levelStr = AnsiCyan + "DEBUG" + AnsiReset
	case INFO:
		levelStr = AnsiGreen + "INFO" + AnsiReset
	case WARN:
		levelStr = AnsiYellow + "WARN" + AnsiReset
	case ERROR:
		levelStr = AnsiRed + "ERROR" + AnsiReset
	}
	drawTuiRow(&buf, formatTwoColumns("DNS:       ", dnsStr, "Log Level:   ", levelStr, colWidth), boxWidth)

	bufKB := cfg.BufferSize / 1024
	bufInfo := fmt.Sprintf("%d KB", bufKB)
	if cfg.SocketBuffer > 0 {
		bufInfo += fmt.Sprintf(" (Socket: %d KB)", cfg.SocketBuffer)
	}

	ndVal := AnsiGreen + "On" + AnsiReset
	if cfg.NoTcpNoDelay {
		ndVal = AnsiRed + "Off" + AnsiReset
	}
	kaVal := AnsiGreen + "On" + AnsiReset
	if cfg.NoTcpKeepAlive {
		kaVal = AnsiRed + "Off" + AnsiReset
	}
	tcpSettings := fmt.Sprintf("NoDelay:%s KeepAlive:%s", ndVal, kaVal)
	drawTuiRow(&buf, formatTwoColumns("Buffer:    ", bufInfo, "TCP Settings:", tcpSettings, colWidth), boxWidth)

	configLines := 6
	if cfg.FakeHost != "" {
		drawTuiRow(&buf, formatTwoColumns("Fake Host: ", AnsiMagenta+cfg.FakeHost+AnsiReset, "", "", colWidth), boxWidth)
		configLines = 7
	}

	buf.WriteString(cfg.TUIBorderMid)

	// Stats Panel
	active := atomic.LoadInt64(&stats.activeConns)
	currUp := atomic.LoadInt64(&stats.bytesUp)
	currDown := atomic.LoadInt64(&stats.bytesDown)
	speedUp, speedDown := stats.Speeds() // atomic load — no race

	activeStr := fmt.Sprintf("%d / %d", active, cfg.MaxConns)
	speedDownStr := fmt.Sprintf("%.2f MB/s", speedDown)
	speedUpStr := fmt.Sprintf("%.2f MB/s", speedUp)
	totalDownStr := formatBytes(currDown)
	totalUpStr := formatBytes(currUp)

	drawTuiRow(&buf, formatTwoColumns("Conns:     ", activeStr, "", "", colWidth), boxWidth)
	drawTuiRow(&buf, formatTwoColumns("Download:  ", speedDownStr, "Total Down:  ", totalDownStr, colWidth), boxWidth)
	drawTuiRow(&buf, formatTwoColumns("Upload:    ", speedUpStr, "Total Up:    ", totalUpStr, colWidth), boxWidth)

	buf.WriteString(cfg.TUIBorderMid)

	// Calculate remaining lines for logs — local variable, never touches shared state.
	usedHeight := 3 + configLines + 4 + 2 + 1
	logLines := termHeight - usedHeight
	if logLines < 5 {
		logLines = 5
	}

	// Logs Panel — read from ring buffer (no slice reallocation)
	drawTuiRow(&buf, AnsiCyan+"Recent Logs:"+AnsiReset, boxWidth)
	tuiLogMu.Lock()
	logs := tuiLogSlice(logLines)
	tuiLogMu.Unlock()

	for _, line := range logs {
		line = truncateVisible(line, innerWidth)
		drawTuiRow(&buf, line, boxWidth)
	}
	for i := len(logs); i < logLines; i++ {
		drawTuiRow(&buf, "", boxWidth)
	}

	// Bottom Border
	buf.WriteString(cfg.TUIBorderBottom)

	os.Stdout.Write(buf.Bytes())
}

func tuiRefreshLoop(cfg *Config, shutdown <-chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	drawTUI(cfg)
	dirty := false
	for {
		select {
		case <-shutdown:
			return
		case <-tuiRefreshCh:
			dirty = true
		case <-ticker.C:
			if dirty {
				drawTUI(cfg)
				dirty = false
			}
		}
	}
}
// --- Crypto ---

const cryptoChunkSize = 262144 // 256KB pre-expanded key chunk (increased from 64KB)

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
	// Pre-expand key to cryptoChunkSize + 8 for single-loop bulk XOR (prevents panic at end boundary)
	ek := bytes.Repeat(hash[:], (cryptoChunkSize+8)/kl+1)[:cryptoChunkSize+8]
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
	TUI            bool

	// Internal derived
	Crypto        *Crypto
	UserAgent     string
	DNS           string
	Resolver      *RemoteResolver
	BufPool       *sync.Pool
	HeaderBufPool *sync.Pool
	TLSBase       *tls.Config

	// Pre-parsed upstream URL (avoid per-connection url.Parse)
	ParsedUpstream *url.URL
	UpstreamHost   string
	UpstreamPort   string
	UpstreamIsWSS  bool

	// TUI border cache
	TUIBorderTop    string
	TUIBorderMid    string
	TUIBorderBottom string
	TUIBorderWidth  int
}

// --- DNS Resolver ---

type dnsCacheEntry struct {
	ip      string
	expires time.Time
}

type RemoteResolver struct {
	serverIP  string
	resolver  *net.Resolver
	sysResolv *net.Resolver // pre-allocated; avoids per-call allocation on fallback
	timeout   time.Duration
	cache     map[string]dnsCacheEntry
	cacheMu   sync.RWMutex
	cacheTTL  time.Duration
}

func NewRemoteResolver(serverIP string) *RemoteResolver {
	r := &RemoteResolver{
		serverIP:  serverIP,
		timeout:   5 * time.Second,
		sysResolv: &net.Resolver{PreferGo: false},
		cache:     make(map[string]dnsCacheEntry),
		cacheTTL:  5 * time.Minute,
	}
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			return d.DialContext(ctx, network, net.JoinHostPort(serverIP, "53"))
		},
	}
	return r
}

func (r *RemoteResolver) Resolve(host string) (string, error) {
	// If already an IP, return as-is
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// Check cache first
	r.cacheMu.RLock()
	if entry, ok := r.cache[host]; ok && time.Now().Before(entry.expires) {
		r.cacheMu.RUnlock()
		return entry.ip, nil
	}
	r.cacheMu.RUnlock()

	// Try remote DNS with timeout
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	addrs, err := r.resolver.LookupHost(ctx, host)
	if err == nil && len(addrs) > 0 {
		logInfo("[DNS] %s -> %s (remote: %s)", host, addrs[0], r.serverIP)
		// Cache the result
		r.cacheMu.Lock()
		r.cache[host] = dnsCacheEntry{ip: addrs[0], expires: time.Now().Add(r.cacheTTL)}
		r.cacheMu.Unlock()
		return addrs[0], nil
	}

	if err != nil {
		logWarn("[DNS] Remote lookup failed for %s: %v, falling back to system DNS", host, err)
	} else {
		logWarn("[DNS] Remote lookup returned no addresses for %s, falling back to system DNS", host)
	}

	// Fallback to pre-allocated system resolver (no heap alloc here)
	sysCtx, sysCancel := context.WithTimeout(context.Background(), r.timeout)
	defer sysCancel()
	sysAddrs, sysErr := r.sysResolv.LookupHost(sysCtx, host)
	if sysErr != nil {
		return "", fmt.Errorf("DNS resolution failed for %s: remote=%v, system=%v", host, err, sysErr)
	}
	if len(sysAddrs) == 0 {
		return "", fmt.Errorf("DNS resolution returned no addresses for %s", host)
	}
	logInfo("[DNS] %s -> %s (system fallback)", host, sysAddrs[0])
	// Cache the system fallback result too
	r.cacheMu.Lock()
	r.cache[host] = dnsCacheEntry{ip: sysAddrs[0], expires: time.Now().Add(r.cacheTTL)}
	r.cacheMu.Unlock()
	return sysAddrs[0], nil
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
		if tuiEnabled {
			addTuiLog(time.Now().Format("15:04:05") + " " + AnsiCyan + "[DEBUG] " + fmt.Sprintf(format, v...) + AnsiReset)
		} else {
			log.Printf(AnsiCyan+"[DEBUG] "+format+AnsiReset, v...)
		}
	}
}

func logInfo(format string, v ...interface{}) {
	if globalLogLevel <= INFO {
		if tuiEnabled {
			addTuiLog(time.Now().Format("15:04:05") + " " + AnsiGreen + "[INFO] " + fmt.Sprintf(format, v...) + AnsiReset)
		} else {
			log.Printf(AnsiGreen+"[INFO] "+format+AnsiReset, v...)
		}
	}
}

func logWarn(format string, v ...interface{}) {
	if globalLogLevel <= WARN {
		if tuiEnabled {
			addTuiLog(time.Now().Format("15:04:05") + " " + AnsiYellow + "[WARN] " + fmt.Sprintf(format, v...) + AnsiReset)
		} else {
			log.Printf(AnsiYellow+"[WARN] "+format+AnsiReset, v...)
		}
	}
}

func logError(format string, v ...interface{}) {
	if globalLogLevel <= ERROR {
		if tuiEnabled {
			addTuiLog(time.Now().Format("15:04:05") + " " + AnsiRed + "[ERROR] " + fmt.Sprintf(format, v...) + AnsiReset)
		} else {
			log.Printf(AnsiRed+"[ERROR] "+format+AnsiReset, v...)
		}
	}
}

// --- Browser Profile System ---
// Each profile bundles UA, TLS cipher/curve preferences, and HTTP headers
// that must match each other. Cloudflare cross-checks these signals.

type BrowserProfile struct {
	UA           string
	AcceptLang   string
	SecChUA      string   // Chrome Client Hints; empty for Firefox/Safari
	SecChUAMob   string   // "?0" desktop, "?1" mobile
	SecChUAPlat  string   // e.g. `"Windows"`, `"macOS"`, `"Android"`
	IsChromium   bool     // drives TLS cipher ordering
	IsMobile     bool
	// TLS tuning
	CipherSuites    []uint16
	CurvePrefs      []tls.CurveID
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
		UA:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
		AcceptLang:  "en-US,en;q=0.9",
		SecChUA:     `"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:  "?0",
		SecChUAPlat: `"Windows"`,
		IsChromium:  true,
		CipherSuites: tlsCiphersChrome136,
		CurvePrefs:   curvePrefsChrome,
	},
	// --- Chrome 136 macOS ---
	{
		UA:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
		AcceptLang:  "en-US,en;q=0.9",
		SecChUA:     `"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:  "?0",
		SecChUAPlat: `"macOS"`,
		IsChromium:  true,
		CipherSuites: tlsCiphersChrome136,
		CurvePrefs:   curvePrefsChrome,
	},
	// --- Chrome 136 Windows (zh-CN user) ---
	{
		UA:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
		AcceptLang:  "zh-CN,zh;q=0.9,en;q=0.8",
		SecChUA:     `"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:  "?0",
		SecChUAPlat: `"Windows"`,
		IsChromium:  true,
		CipherSuites: tlsCiphersChrome136,
		CurvePrefs:   curvePrefsChrome,
	},
	// --- Edge 136 Windows ---
	{
		UA:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
		AcceptLang:  "en-US,en;q=0.9",
		SecChUA:     `"Chromium";v="136", "Microsoft Edge";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:  "?0",
		SecChUAPlat: `"Windows"`,
		IsChromium:  true,
		CipherSuites: tlsCiphersChrome136,
		CurvePrefs:   curvePrefsChrome,
	},
	// --- Firefox 138 Windows ---
	{
		UA:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
		AcceptLang:  "en-US,en;q=0.5",
		SecChUA:     "", // Firefox does not send sec-ch-ua
		SecChUAMob:  "",
		SecChUAPlat: "",
		IsChromium:  false,
		CipherSuites: tlsCiphersFirefox138,
		CurvePrefs:   curvePrefsFirefox,
	},
	// --- Firefox 138 macOS ---
	{
		UA:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:138.0) Gecko/20100101 Firefox/138.0",
		AcceptLang:  "en-US,en;q=0.5",
		SecChUA:     "",
		SecChUAMob:  "",
		SecChUAPlat: "",
		IsChromium:  false,
		CipherSuites: tlsCiphersFirefox138,
		CurvePrefs:   curvePrefsFirefox,
	},
	// --- Chrome 136 Android (mobile) ---
	{
		UA:          "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36",
		AcceptLang:  "en-US,en;q=0.9",
		SecChUA:     `"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"`,
		SecChUAMob:  "?1",
		SecChUAPlat: `"Android"`,
		IsChromium:  true,
		IsMobile:    true,
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
		// maskPRNG is passed in from the relay goroutine — zero syscalls
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

func readUntilCRLFCRLF(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(MaxHeaderSize)
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

// largeFramePool pools buffers for WS frames larger than smallFrameSize.
// Stored as *[]byte so the pool can hold variable-length slices without
// the type assertion overhead of interface{} wrapping a plain []byte.
var largeFramePool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32*1024) // 32KB default; grown as needed
		return &buf
	},
}

// handshakeBufPool pools bytes.Buffer for WebSocket handshake requests.
// Avoids per-connection allocation of ~512 byte buffers.
var handshakeBufPool = sync.Pool{
	New: func() interface{} {
		buf := bytes.NewBuffer(make([]byte, 0, 512))
		return buf
	},
}

// tryClientFallbackDial attempts to resolve the fakehost domain to get
// alternative Cloudflare edge IPs when the primary upstream IP is unreachable.
func tryClientFallbackDial(dialer *net.Dialer, wsHost, wsPort, sniHostname string, cfg *Config) net.Conn {
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
	wsConn    net.Conn
	br        *bufio.Reader
	created   time.Time
	lastUsed  time.Time
}

type ConnPool struct {
	conns       []*PooledConn
	mu          sync.Mutex
	cfg         *Config
	maxSize     int
	maxAge      time.Duration
	idleTimeout time.Duration
	closed      bool
	deadIPs     map[string]time.Time // cache unreachable IPs to avoid repeated timeouts
}

func NewConnPool(cfg *Config, maxSize int) *ConnPool {
	p := &ConnPool{
		conns:       make([]*PooledConn, 0, maxSize),
		cfg:         cfg,
		maxSize:     maxSize,
		maxAge:      5 * time.Minute,
		idleTimeout: 30 * time.Second,
		deadIPs:     make(map[string]time.Time),
	}
	// Start background goroutine to maintain pool
	go p.maintainLoop()
	return p
}

func (p *ConnPool) maintainLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.cleanup()
		// Fill pool to half capacity
		for i := 0; i < p.maxSize/2; i++ {
			p.mu.Lock()
			if p.closed || len(p.conns) >= p.maxSize/2 {
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
	wsURL := cfg.ParsedUpstream
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

	// Skip known-dead IPs (cached for 5 minutes after failure)
	p.mu.Lock()
	if deadAt, ok := p.deadIPs[dialHost]; ok {
		p.mu.Unlock()
		if time.Since(deadAt) < 5*time.Minute {
			logDebug("[POOL] Skipping dead IP %s (failed %s ago)", dialHost, time.Since(deadAt).Round(time.Second))
			return p.tryFallbackDial(dialer, wsHost, wsPort, sniHostname)
		}
		p.mu.Lock()
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
		// Mark IP as dead to avoid repeated timeouts
		p.mu.Lock()
		p.deadIPs[dialHost] = time.Now()
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

	// WebSocket handshake
	profile := pickBrowserProfile()
	path := wsURL.Path
	if path == "" {
		path = "/"
	}
	var wsKey [16]byte
	if _, err := rand.Read(wsKey[:]); err != nil {
		wsConn.Close()
		return nil
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
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
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
		wsConn.Close()
		return nil
	}
	handshakeBufPool.Put(handshakeBuf)

	// Read handshake response
	wsTCPConn := extractTCPConn(wsConn)
	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	respBytes, err := readUntilCRLFCRLF(br)
	if err != nil || !bytes.Contains(respBytes, []byte("101")) {
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
	cfg := p.cfg
	// Only try fallback if wsHost is already an IP (no point retrying a domain)
	if net.ParseIP(wsHost) == nil {
		return nil
	}
	// Try resolving the sniHostname (fakehost) to get Cloudflare edge IPs
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
		logDebug("[POOL] Trying fallback Cloudflare edge: %s", fallbackAddr)
		var wsConn net.Conn
		if cfg.UpstreamIsWSS {
			conf := pickProfileTLSConfig().Clone()
			conf.ServerName = sniHostname
			wsConn, err = tls.DialWithDialer(dialer, "tcp", fallbackAddr, conf)
		} else {
			wsConn, err = dialer.Dial("tcp", fallbackAddr)
		}
		if err != nil {
			logDebug("[POOL] Fallback dial %s failed: %v", fallbackAddr, err)
			p.mu.Lock()
			p.deadIPs[ip.String()] = time.Now()
			p.mu.Unlock()
			continue
		}
		optimizeSocket(wsConn, cfg)
		br := bufio.NewReaderSize(wsConn, MaxHeaderSize)
		pConn := p.doHandshake(wsConn, br, cfg, sniHostname)
		if pConn != nil {
			return pConn
		}
		wsConn.Close()
	}
	return nil
}

func (p *ConnPool) doHandshake(wsConn net.Conn, br *bufio.Reader, cfg *Config, sniHostname string) *PooledConn {
	wsURL := cfg.ParsedUpstream
	profile := pickBrowserProfile()
	path := wsURL.Path
	if path == "" {
		path = "/"
	}
	var wsKey [16]byte
	if _, err := rand.Read(wsKey[:]); err != nil {
		return nil
	}
	wsKeyStr := base64.StdEncoding.EncodeToString(wsKey[:])

	hostHeader := sanitizeHeader(cfg.UpstreamHost)
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
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
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
		return nil
	}
	handshakeBufPool.Put(handshakeBuf)

	wsTCPConn := extractTCPConn(wsConn)
	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	respBytes, err := readUntilCRLFCRLF(br)
	if err != nil || !bytes.Contains(respBytes, []byte("101")) {
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
	defer p.mu.Unlock()

	if p.closed || len(p.conns) == 0 {
		return nil
	}

	// Pop last connection
	n := len(p.conns)
	conn := p.conns[n-1]
	p.conns = p.conns[:n-1]
	conn.lastUsed = time.Now()
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

	p.conns = append(p.conns, conn)
}

func (p *ConnPool) Close() {
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
// For the handshake path (readWSFrame), pass a nil buf — the function falls back
// to largeFramePool for large frames and returns a heap-owned copy.
func readWSFrameInto(r io.Reader, w io.Writer, buf []byte) ([]byte, error) {
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

		// Buffer selection:
		//   relay path  (buf != nil): use caller's buf if it fits, else heap-alloc.
		//   handshake path (buf == nil): use stack for small frames, largeFramePool
		//   for large ones, then copy to heap before returning.
		var payload []byte
		var stackBuf [smallFrameSize]byte
		var poolPtr *[]byte

		if buf != nil {
			// relay path — zero-copy into caller's buffer when possible
			if payloadLen <= uint64(len(buf)) {
				payload = buf[:payloadLen]
			} else {
				payload = make([]byte, payloadLen)
			}
		} else {
			// handshake path — pool-backed temporary buffer
			if payloadLen <= smallFrameSize {
				payload = stackBuf[:payloadLen]
			} else {
				poolPtr = largeFramePool.Get().(*[]byte)
				if uint64(cap(*poolPtr)) < payloadLen {
					*poolPtr = make([]byte, payloadLen)
				}
				payload = (*poolPtr)[:payloadLen]
			}
		}

		if _, err := io.ReadFull(r, payload); err != nil {
			if poolPtr != nil {
				largeFramePool.Put(poolPtr)
			}
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

		switch opcode {
		case 0x0, 0x1, 0x2: // Text, Binary, Continuation
			if buf != nil {
				// relay path — payload already lives in caller's buffer
				return payload, nil
			}
			// handshake path — must return heap-owned slice
			heapPayload := make([]byte, payloadLen)
			copy(heapPayload, payload)
			if poolPtr != nil {
				largeFramePool.Put(poolPtr)
			}
			return heapPayload, nil
		case 0x8: // Close
			if poolPtr != nil {
				largeFramePool.Put(poolPtr)
			}
			return nil, io.EOF
		case 0x9: // Ping
			if w != nil {
				if err := writeWSFrame(w, payload, 0xA, true); err != nil {
					if poolPtr != nil {
						largeFramePool.Put(poolPtr)
					}
					return nil, err
				}
			}
			if poolPtr != nil {
				largeFramePool.Put(poolPtr)
			}
		}
	}
}

// readWSFrame is the handshake-path wrapper: no caller buffer, returns heap copy.
func readWSFrame(r io.Reader, w io.Writer) ([]byte, error) {
	return readWSFrameInto(r, w, nil)
}

// --- Main Logic ---

func main() {
	initWindowsConsole()

	pFlag := flag.String("p", "", "Listen Address (e.g. :8080)")
	upFlag := flag.String("up", "", "Upstream WebSocket URL")
	kFlag := flag.String("k", "", "Authentication Key")
	logFlag := flag.String("log", "INFO", "Log Level")
	fakeHostFlag := flag.String("fakehost", "", "Spoofing Hostname")
	wFlag := flag.Int("W", 1024, "App Buffer Size in KB (default 1MB)")
	noDelayFlag := flag.Bool("no-tcp-nodelay", false, "Disable TCP_NODELAY")
	keepAliveFlag := flag.Bool("no-tcp-keepalive", false, "Disable TCP KeepAlive")
	sockBufFlag := flag.Int("socket-buffer", 8192, "Kernel Socket Buffer in KB (default 8MB)")
	connTimeoutFlag := flag.Int("connection-timeout", 60, "Connection Timeout in seconds (default 60s)")
	verifySSLFlag := flag.Bool("verify-ssl", false, "Enable SSL Verification")
	maxConnFlag := flag.Int("max-conn", 1000, "Max Concurrent Connections")
	blockLocalFlag := flag.Bool("block-local", true, "Drop local/LAN traffic (Client mode)")
	allowOpenFlag := flag.Bool("allow-open", false, "Allow server mode without authentication key")
	dnsFlag := flag.String("dns", "", "Remote DNS server IP (e.g. 8.8.8.8)")
	tuiFlag := flag.Bool("tui", false, "Enable GUI-style Terminal User Interface")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("GOWAY v%s\n", Version)
		os.Exit(0)
	}

	globalLogLevel = parseLogLevel(*logFlag)
	tuiEnabled = *tuiFlag

	if *pFlag == "" {
		fmt.Println("Error: -p is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg := Config{
		Upstream:       *upFlag,
		FakeHost:       *fakeHostFlag,
		Key:            *kFlag,
		BufferSize:     1048576, // 1MB default (increased from 256KB for better throughput)
		NoTcpNoDelay:   *noDelayFlag,
		NoTcpKeepAlive: *keepAliveFlag,
		SocketBuffer:   *sockBufFlag,
		ConnTimeout:    *connTimeoutFlag,
		VerifySSL:      *verifySSLFlag,
		MaxConns:       *maxConnFlag,
		BlockLocal:     *blockLocalFlag,
		AllowOpen:      *allowOpenFlag,
		TUI:            tuiEnabled,
	}

	if *dnsFlag != "" {
		if net.ParseIP(*dnsFlag) == nil {
			fmt.Printf("Error: -dns requires a valid IP address (e.g. 8.8.8.8), got '%s'\n", *dnsFlag)
			os.Exit(1)
		}
		cfg.Resolver = NewRemoteResolver(*dnsFlag)
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

	// Parse upstream URL once at startup — avoids per-connection url.Parse alloc.
	if cfg.Upstream != "" {
		parsedUp, upErr := url.Parse(cfg.Upstream)
		if upErr != nil {
			fmt.Printf("Error: invalid upstream URL '%s': %v\n", cfg.Upstream, upErr)
			os.Exit(1)
		}
		cfg.ParsedUpstream = parsedUp
		cfg.UpstreamIsWSS = strings.EqualFold(parsedUp.Scheme, "wss")

		upHost := parsedUp.Hostname()
		upPort := parsedUp.Port()
		if upPort == "" {
			if cfg.UpstreamIsWSS {
				upPort = "443"
			} else {
				upPort = "80"
			}
		}
		cfg.UpstreamHost = upHost
		cfg.UpstreamPort = upPort
	}

	// Server mode without authentication is an open proxy risk
	if cfg.Upstream == "" && cfg.Crypto == nil && !cfg.AllowOpen {
		fmt.Println("Error: Server mode requires -k (authentication key) or --allow-open flag")
		os.Exit(1)
	}

	listenAddr := fmt.Sprintf("%s:%d", cfg.ProxyHost, cfg.ProxyPort)

	if !tuiEnabled {
		// Print Banner
		mode := "Server"
		if cfg.Upstream != "" {
			mode = "Client (HTTP + SOCKS5)"
		}

		fmt.Printf("%sGOWAY v%s%s\n", AnsiCyan, Version, AnsiReset)
		fmt.Printf("%s%s%s\n", AnsiCyan, strings.Repeat("-", 60), AnsiReset)

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
			fmt.Printf(" [+] User-Agent:  %sBrowser Profile (Sticky TLS+UA)%s\n", AnsiGreen, AnsiReset)
		}

		if cfg.Resolver != nil {
			fmt.Printf(" [+] DNS:         %sRemote: %s (UDP+TCP)%s\n", AnsiGreen, cfg.Resolver.serverIP, AnsiReset)
		} else {
			fmt.Printf(" [+] DNS:         %sSystem default%s\n", AnsiYellow, AnsiReset)
		}

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
	}

	cfg.TLSBase = &tls.Config{
		InsecureSkipVerify: !cfg.VerifySSL,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(128), // TLS session resumption
	}

	// Pre-build TLS configs for each browser profile
	if cfg.Upstream != "" && cfg.UpstreamIsWSS {
		initProfileTLSConfigs(cfg.TLSBase)
	}

	bufSize := cfg.BufferSize + 14
	cfg.BufPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, bufSize)
			return &buf
		},
	}

	cfg.HeaderBufPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, MaxHeaderSize)
			return &buf
		},
	}

	// Initialize connection pool for client mode (pre-establish WebSocket connections)
	if cfg.Upstream != "" {
		connPool = NewConnPool(&cfg, 10) // Pool of 10 pre-established connections
	}

	if !tuiEnabled {
		fmt.Printf("%s%s%s\n", AnsiCyan, strings.Repeat("-", 60), AnsiReset)
		fmt.Printf("%s[INFO] Proxy listening... (Press Ctrl+C to stop)%s\n\n", AnsiCyan, AnsiReset)
	}

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

	if tuiEnabled {
		fmt.Print("\033[2J\033[?25l") // Clear screen & hide cursor
		defer fmt.Print("\033[?25h\033[2J\033[H") // Restore cursor & clear screen on exit
		go tuiRefreshLoop(&cfg, shutdown)
	}

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
	interval := 3 * time.Second
	if tuiEnabled {
		interval = 1 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			currUp := atomic.LoadInt64(&stats.bytesUp)
			currDown := atomic.LoadInt64(&stats.bytesDown)
			active := atomic.LoadInt64(&stats.activeConns)

			secs := interval.Seconds()
			upSpeed := float64(currUp-lastUp) / secs / 1024.0 / 1024.0
			downSpeed := float64(currDown-lastDown) / secs / 1024.0 / 1024.0

			lastUp = currUp
			lastDown = currDown

			// Atomic write — eliminates data race on speedUp/speedDown.
			stats.SetSpeeds(upSpeed, downSpeed)

			if !tuiEnabled {
				if globalLogLevel <= INFO {
					fmt.Printf("\r%s[STATS] Conns: %d | Up: %.2f MB/s | Down: %.2f MB/s%s",
						AnsiGrey, active, upSpeed, downSpeed, AnsiReset)
				}
			} else {
				triggerTuiRefresh()
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

	// Remote DNS resolution for target address
	if cfg.Resolver != nil {
		host, port, splitErr := net.SplitHostPort(targetStr)
		if splitErr == nil {
			if resolvedIP, resolveErr := cfg.Resolver.Resolve(host); resolveErr == nil {
				targetStr = net.JoinHostPort(resolvedIP, port)
			} else {
				logError("[DNS] Failed to resolve %s: %v", host, resolveErr)
			}
		}
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
	if cfg.Crypto != nil {
		ok = make([]byte, 3)
		copy(ok, "OK\n")
		cfg.Crypto.TransformInPlace(ok)
	} else {
		ok = okBytes
	}
	if err := writeWSFrame(wsConn, ok, 0x2, false); err != nil {
		return
	}

	errCh := make(chan error, 2)

	// WS -> TCP (server receives masked frames from client, unmasks, writes to target)
	// No mask generation needed here — server never masks outbound TCP data.
	go func() {
		var err error
		defer func() { errCh <- err }()
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		var lastDeadline time.Time
		var localUp int64 // batch counter — avoids atomic on every frame
		for {
			if deadlineThrottle(&lastDeadline) {
				setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
				if localUp > 0 {
					stats.AddBytes(localUp, 0)
					localUp = 0
				}
			}
			data, errRead := readWSFrameInto(br, wsConn, buf[14:])
			if errRead != nil {
				if localUp > 0 {
					stats.AddBytes(localUp, 0)
				}
				err = errRead
				return
			}
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
			// Server->client frames are unmasked (masked=false) — no PRNG needed
			if errWrite := writeWSFramePreallocated(wsConn, buf, 14, nr, 0x2, false); errWrite != nil {
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
	if strings.EqualFold(host, "localhost") ||
		host == "127.0.0.1" || host == "::1" || host == "[::1]" || host == "0.0.0.0" {
		return true
	}
	// IPv6 local address ranges check (link-local and unique local)
	if strings.HasPrefix(host, "fe80:") || strings.HasPrefix(host, "fc00:") || strings.HasPrefix(host, "fd00:") ||
		strings.HasPrefix(host, "[fe80:") || strings.HasPrefix(host, "[fc00:") || strings.HasPrefix(host, "[fd00:") {
		return true
	}
	// Private IPv4 always starts with '1' (10.x, 172.16+, 192.168.x).
	// Skip ToLower allocation for the common case of public hostnames.
	if len(host) == 0 || host[0] != '1' {
		return false
	}
	// Byte-level prefix check (zero allocation, no strings.ToLower)
	h := host
	if len(h) >= 8 && h[0] == '1' && h[1] == '9' && h[2] == '2' && h[3] == '.' &&
		h[4] == '1' && h[5] == '6' && h[6] == '8' && h[7] == '.' {
		return true
	}
	if len(h) >= 3 && h[0] == '1' && h[1] == '0' && h[2] == '.' {
		return true
	}
	if len(h) >= 4 && h[0] == '1' && h[1] == '7' && h[2] == '2' && h[3] == '.' {
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
	var buf [1]byte
	if _, err := localConn.Read(buf[:]); err != nil {
		return
	}

	var targetHost string
	var targetPort string
	var initialPayload []byte

	ver := buf[0]
	if ver == 0x05 {
		// SOCKS5
		var nmBuf [1]byte
		if _, err := io.ReadFull(localConn, nmBuf[:]); err != nil {
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
		if _, err := io.ReadFull(localConn, discard); err != nil {
			return
		}

		if _, err := localConn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		var reqHead [4]byte
		if _, err := io.ReadFull(localConn, reqHead[:]); err != nil {
			return
		}
		cmd := reqHead[1]
		atyp := reqHead[3]

		if cmd != 0x01 {
			// RFC 1928 §6: reply with "command not supported" (0x07) so the
			// client fails fast instead of hanging waiting for a response.
			localConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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
		// Parse first line byte-level (avoids string concat + Fields allocs)
		firstLineEnd := bytes.Index(restBuf[:n], crlfB)
		if firstLineEnd < 0 {
			cfg.HeaderBufPool.Put(restPtr)
			return
		}
		firstLine := restBuf[:firstLineEnd]
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
		// Reconstruct full method name with allocation-free fast-path matching
		var method string
		firstPart := firstLine[:sp1]
		if buf[0] == 'G' && bytes.Equal(firstPart, []byte("ET")) {
			method = "GET"
		} else if buf[0] == 'C' && bytes.Equal(firstPart, []byte("ONNECT")) {
			method = "CONNECT"
		} else if buf[0] == 'P' && bytes.Equal(firstPart, []byte("OST")) {
			method = "POST"
		} else if buf[0] == 'P' && bytes.Equal(firstPart, []byte("UT")) {
			method = "PUT"
		} else if buf[0] == 'D' && bytes.Equal(firstPart, []byte("ELETE")) {
			method = "DELETE"
		} else if buf[0] == 'H' && bytes.Equal(firstPart, []byte("EAD")) {
			method = "HEAD"
		} else if buf[0] == 'O' && bytes.Equal(firstPart, []byte("PTIONS")) {
			method = "OPTIONS"
		} else if buf[0] == 'P' && bytes.Equal(firstPart, []byte("ATCH")) {
			method = "PATCH"
		} else {
			method = string(buf[0]) + string(firstPart)
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
			}
			cfg.HeaderBufPool.Put(restPtr)
			initialPayload = nil
		} else {
			fullData := make([]byte, 1+n)
			copy(fullData, buf[:])
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

	// Connect Upstream WS (use pre-parsed URL from startup)
	var wsConn net.Conn
	var wsTCPConn *net.TCPConn
	var br *bufio.Reader
	wsURL := cfg.ParsedUpstream
	wsHost := cfg.UpstreamHost
	wsPort := cfg.UpstreamPort
	profile := pickBrowserProfile()

	// Try connection pool first (pre-established connections)
	var pooledConn *PooledConn
	if connPool != nil {
		pooledConn = connPool.Get()
	}

	if pooledConn != nil {
		// Use pre-established connection from pool (skips TCP+TLS+WS handshake)
		wsConn = pooledConn.wsConn
		br = pooledConn.br
		wsTCPConn = extractTCPConn(wsConn)
		logDebug("[CLIENT] Using pooled connection")
	} else {
		// Create new connection (original path)
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
				fallbackConn := tryClientFallbackDial(dialer, wsHost, wsPort, sniHostname, cfg)
				if fallbackConn != nil {
					wsConn = fallbackConn
				}
			}
			if wsConn == nil {
				logError("Upstream fail: %v", err)
				return
			}
		}

		optimizeSocket(wsConn, cfg)
		wsTCPConn = extractTCPConn(wsConn)
		br = bufio.NewReaderSize(wsConn, MaxHeaderSize)

		// WebSocket handshake
		path := wsURL.Path
		if path == "" {
			path = "/"
		}
		var wsKey [16]byte
		if _, err := rand.Read(wsKey[:]); err != nil {
			return
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
			"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
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
			return
		}
		handshakeBufPool.Put(handshakeBuf)

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
	}

	defer func() {
		wsConn.Close()
	}()

	optimizeSocket(localConn, cfg)
	localTCPConn := extractTCPConn(localConn)

	base := targetHost + ":" + targetPort + "\n"
	padLen := 1 + mrand.Intn(40)
	targetPayload := make([]byte, len(base)+padLen)
	copy(targetPayload, base)
	// fill padding with spaces (constant, no allocation)
	for i := len(base); i < len(targetPayload); i++ {
		targetPayload[i] = ' '
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

			// Write coalescing: try to read more data before writing
			// This reduces the number of small WebSocket frames
			totalRead := nr
			for totalRead < len(buf)-14 {
				// Set a short read deadline to check for more data
				localConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
				moreRead, moreErr := localConn.Read(buf[14+totalRead:])
				if moreErr != nil || moreRead == 0 {
					break
				}
				totalRead += moreRead
			}
			// Restore the original deadline
			setTCPReadDeadline(localTCPConn, cfg.ConnTimeout)

			if errWrite := writeWSFramePreallocatedFast(wsConn, buf, 14, totalRead, 0x2, prng); errWrite != nil {
				if localUp > 0 {
					stats.AddBytes(localUp, 0)
				}
				err = errWrite
				return
			}
			localUp += int64(totalRead)
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
		var localDown int64
		for {
			if deadlineThrottle(&lastDeadline) {
				setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
				if localDown > 0 {
					stats.AddBytes(0, localDown)
					localDown = 0
				}
			}
			data, errRead := readWSFrameInto(br, wsConn, buf[14:])
			if errRead != nil {
				if localDown > 0 {
					stats.AddBytes(0, localDown)
				}
				err = errRead
				return
			}

			// Write coalescing: try to write data immediately
			// For download direction, we write as-is since data comes from WebSocket frames
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
