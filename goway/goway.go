package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/ipv4"
)

const (
	Version        = "1.8.8"
	MaxWSFrameSize = 64 * 1024 * 1024 // 64MB (increased from 16MB for better throughput)
	MaxHeaderSize  = 8192
	CRLF           = "\r\n"
	CRLFCRLF       = "\r\n\r\n"
)

var (
	okBytes = []byte("OK\n")
	crlfB   = []byte{'\r', '\n'}

	// Pre-allocated static responses (avoid per-connection alloc)
	socks5OKResp    = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	http200Resp     = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	http400Resp     = []byte("HTTP/1.1 400 Bad Request\r\n\r\n")
	wsUpgradePrefix = []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
	wsUpgradeSuffix = []byte("\r\n\r\n")
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

func tryAcquireConn(max int64) bool {
	for {
		cur := atomic.LoadInt64(&stats.activeConns)
		if cur >= max {
			return false
		}
		if atomic.CompareAndSwapInt64(&stats.activeConns, cur, cur+1) {
			return true
		}
	}
}

func releaseConn() {
	for {
		cur := atomic.LoadInt64(&stats.activeConns)
		if cur <= 0 {
			atomic.StoreInt64(&stats.activeConns, 0)
			return
		}
		if atomic.CompareAndSwapInt64(&stats.activeConns, cur, cur-1) {
			return
		}
	}
}

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
	expandedKey []byte
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
		expandedKey: ek,
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
	Mux            bool
	MuxSessions    int
	Obfs           bool

	// Internal derived
	Crypto         *Crypto
	Resolver       *RemoteResolver
	BufPool        *sync.Pool
	HeaderBufPool  *sync.Pool
	TLSBase        *tls.Config
	MuxPool        *MuxClientPool
	QUICPool       *QUICClientPool
	IsQUICUpstream bool

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

// Log file support: circular buffer of last 10 plain-text entries
var (
	logFilePath string
	logRingBuf  [10]string
	logRingPos  int
	logRingLen  int
	logRingMu   sync.Mutex
)

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
		msg := fmt.Sprintf(format, v...)
		if tuiEnabled {
			addTuiLog(time.Now().Format("15:04:05") + " " + AnsiYellow + "[WARN] " + msg + AnsiReset)
		} else {
			log.Printf(AnsiYellow+"[WARN] "+format+AnsiReset, v...)
		}
		addLogFileEntry("[WARN] " + msg)
	}
}

func logError(format string, v ...interface{}) {
	if globalLogLevel <= ERROR {
		msg := fmt.Sprintf(format, v...)
		if tuiEnabled {
			addTuiLog(time.Now().Format("15:04:05") + " " + AnsiRed + "[ERROR] " + msg + AnsiReset)
		} else {
			log.Printf(AnsiRed+"[ERROR] "+format+AnsiReset, v...)
		}
		addLogFileEntry("[ERROR] " + msg)
	}
}

func addLogFileEntry(entry string) {
	logRingMu.Lock()
	defer logRingMu.Unlock()
	if logFilePath == "" {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	logRingBuf[logRingPos] = ts + " " + entry
	logRingPos = (logRingPos + 1) % len(logRingBuf)
	if logRingLen < len(logRingBuf) {
		logRingLen++
	}
	var lines []string
	start := (logRingPos - logRingLen + len(logRingBuf)) % len(logRingBuf)
	for i := 0; i < logRingLen; i++ {
		lines = append(lines, logRingBuf[(start+i)%len(logRingBuf)])
	}
	_ = os.WriteFile(logFilePath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func saveLogFile() {
	logRingMu.Lock()
	defer logRingMu.Unlock()
	if logFilePath == "" || logRingLen == 0 {
		return
	}
	var lines []string
	start := (logRingPos - logRingLen + len(logRingBuf)) % len(logRingBuf)
	for i := 0; i < logRingLen; i++ {
		lines = append(lines, logRingBuf[(start+i)%len(logRingBuf)])
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(logFilePath, []byte(content), 0644); err != nil {
		log.Printf("Failed to save log file: %v", err)
	} else {
		log.Printf("Log saved to %s (%d entries)", logFilePath, logRingLen)
	}
}

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

// writeMuxFrameFused wraps a pre-encoded MUX region in its WS frame while
// applying the cipher keystream and the WS mask in a SINGLE pass
// (word ^ keystream ^ mask64). It replaces the old two-pass sequence
// (Crypto.TransformInPlace at enqueue + mask-only write here) on the client
// MUX hot path, halving bulk memory traffic. Offset semantics are identical
// to the two-pass version (region-relative, matching TransformInPlace), so
// wire bytes after receiver-side invert are bit-identical; the obfs tail,
// if any, is inside the region and ignored by declared-length slicing.
// crypto == nil degrades to the mask-only fast path.
func writeMuxFrameFused(w io.Writer, buf []byte, payloadOffset int, payloadLen int, opcode byte, prng *maskPRNG, crypto *Crypto) error {
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

// largeFramePool pools buffers for WS frames larger than smallFrameSize.
// Stored as *[]byte so the pool can hold variable-length slices without
// the type assertion overhead of interface{} wrapping a plain []byte.
const maxPooledFrameCap = 64 * 1024 // Cap pool retention at 64KB to avoid holding huge buffers

var largeFramePool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32*1024) // 32KB default; grown as needed
		return &buf
	},
}

func putLargeFrame(p *[]byte) {
	if p != nil && cap(*p) <= maxPooledFrameCap {
		largeFramePool.Put(p)
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
// For the handshake path (readWSFrame), pass a nil buf — the function falls back
// to largeFramePool for large frames and returns a heap-owned copy.
func readWSFrameInto(r io.Reader, w io.Writer, buf []byte) ([]byte, error) {
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
			putLargeFrame(poolPtr)
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
		case 0x1, 0x2: // Text, Binary
			if buf != nil {
				// relay path — payload already lives in caller's buffer
				return payload, nil
			}
			// handshake path — must return heap-owned slice
			heapPayload := make([]byte, payloadLen)
			copy(heapPayload, payload)
			putLargeFrame(poolPtr)
			return heapPayload, nil
		case 0x8: // Close
			putLargeFrame(poolPtr)
			return nil, io.EOF
		case 0x9: // Ping
			if w != nil {
				if err := writeWSFrame(w, payload, 0xA, !masked); err != nil {
					putLargeFrame(poolPtr)
					return nil, err
				}
			}
			putLargeFrame(poolPtr)
		case 0xA: // Pong
			putLargeFrame(poolPtr)
			// Discard pong and continue reading
		default:
			putLargeFrame(poolPtr)
			return nil, fmt.Errorf("unexpected websocket opcode: 0x%X", opcode)
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
	defer saveLogFile()

	pFlag := flag.String("p", "", "Listen Address (e.g. :8080 or 0.0.0.0:8080) [Required]")
	upFlag := flag.String("up", "", "Upstream WebSocket/QUIC URL (e.g. ws://host:port, wss://host:port, quic://host:port). Omit for Server mode")
	kFlag := flag.String("k", "", "Authentication and XOR encryption key")
	fakeHostFlag := flag.String("fakehost", "", "Spoofing Hostname / SNI for Cloudflare CDN or reverse proxies")
	muxFlag := flag.Bool("mux", true, "Enable 0-RTT Connection Multiplexing (default true)")
	noMuxFlag := flag.Bool("no-mux", false, "Disable 0-RTT Connection Multiplexing (fallback to 1:1 pool)")
	muxSessionsFlag := flag.Int("mux-sessions", 4, "Number of parallel physical Mux sessions (default 4, max 64)")
	obfsFlag := flag.Bool("obfs", false, "Pad MUX DATA frames with random lengths to resist packet-size fingerprinting")
	wFlag := flag.Int("W", 128, "App Buffer Size in KB (default 128KB, recommend 256-1024 for high-throughput streaming)")
	sockBufFlag := flag.Int("socket-buffer", 0, "Kernel Socket Buffer in KB (default 0 = OS auto-tuning)")
	noDelayFlag := flag.Bool("no-tcp-nodelay", false, "Disable TCP_NODELAY (disable Nagle bypass)")
	keepAliveFlag := flag.Bool("no-tcp-keepalive", false, "Disable TCP KeepAlive probes")
	dnsFlag := flag.String("dns", "", "Remote DNS server IP for target host resolution (e.g. 8.8.8.8)")
	blockLocalFlag := flag.Bool("block-local", true, "Drop local/LAN loopback traffic in Client mode (default true)")
	noBlockLocalFlag := flag.Bool("no-block-local", false, "Allow local/LAN loopback traffic in Client mode")
	verifySSLFlag := flag.Bool("verify-ssl", false, "Enable strict SSL certificate verification for wss:// upstream")
	allowOpenFlag := flag.Bool("allow-open", false, "Allow server mode without authentication key (open proxy risk)")
	maxConnFlag := flag.Int("max-conn", 1500, "Max Concurrent Connections (default 1500)")
	connTimeoutFlag := flag.Int("connection-timeout", 60, "Connection/idle timeout in seconds (default 60s)")
	logFlag := flag.String("log", "INFO", "Log Level: DEBUG, INFO, WARN, ERROR (default INFO)")
	logFileFlag := flag.String("log-file", "", "Save last 10 log entries to file on exit (e.g. goway.log)")
	tuiFlag := flag.Bool("tui", false, "Enable GUI-style Terminal User Interface dashboard")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	cpuProfileFlag := flag.String("cpuprofile", "", "Write cpu profile to file (for PGO compilation)")
	cpuProfileDurationFlag := flag.Int("cpuprofile-duration", 0, "Stop CPU profile after N seconds")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "GOWAY v%s - High-Performance Secure Proxy (WebSocket & QUIC)\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Server Mode:  goway -p <listen_addr> -k <key> [options]\n")
		fmt.Fprintf(os.Stderr, "  Client Mode:  goway -p <listen_addr> -up <upstream_url> -k <key> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Quick Start Examples:\n")
		fmt.Fprintf(os.Stderr, "  # 1. Start Server (WebSocket + QUIC dual stack on port 8880):\n")
		fmt.Fprintf(os.Stderr, "    goway -p :8880 -k mypassword\n\n")
		fmt.Fprintf(os.Stderr, "  # 2. Start Client (SOCKS5/HTTP on port 1080 via WebSocket):\n")
		fmt.Fprintf(os.Stderr, "    goway -p :1080 -up ws://server.com:8880 -k mypassword\n\n")
		fmt.Fprintf(os.Stderr, "  # 3. Start Client via Cloudflare CDN (with SNI spoofing):\n")
		fmt.Fprintf(os.Stderr, "    goway -p :1080 -up ws://cf-ip:8880 -fakehost server.com -k mypassword\n\n")
		fmt.Fprintf(os.Stderr, "  # 4. Start Client via QUIC Mode (low-latency UDP for weak network):\n")
		fmt.Fprintf(os.Stderr, "    goway -p :1080 -up quic://server.com:8880 -k mypassword\n\n")
		fmt.Fprintf(os.Stderr, "Core Parameters:\n")
		fmt.Fprintf(os.Stderr, "  -p string\n")
		fmt.Fprintf(os.Stderr, "        Listen Address (e.g. :8080 or 0.0.0.0:8080) [Required]\n")
		fmt.Fprintf(os.Stderr, "  -up string\n")
		fmt.Fprintf(os.Stderr, "        Upstream WebSocket/QUIC URL (e.g. ws://host:port, wss://host:port, quic://host:port)\n")
		fmt.Fprintf(os.Stderr, "        If omitted, runs as Server; if specified, runs as Client\n")
		fmt.Fprintf(os.Stderr, "  -k string\n")
		fmt.Fprintf(os.Stderr, "        Authentication and XOR encryption key (Required for server unless -allow-open)\n")
		fmt.Fprintf(os.Stderr, "  -fakehost string\n")
		fmt.Fprintf(os.Stderr, "        Spoofing Hostname / SNI for Cloudflare CDN or reverse proxies\n\n")
		fmt.Fprintf(os.Stderr, "Performance & Multiplexing:\n")
		fmt.Fprintf(os.Stderr, "  -mux\n")
		fmt.Fprintf(os.Stderr, "        Enable 0-RTT Connection Multiplexing (default true)\n")
		fmt.Fprintf(os.Stderr, "  -no-mux\n")
		fmt.Fprintf(os.Stderr, "        Disable 0-RTT Connection Multiplexing (fallback to 1:1 pool)\n")
		fmt.Fprintf(os.Stderr, "  -mux-sessions int\n")
		fmt.Fprintf(os.Stderr, "        Number of parallel physical Mux sessions (default 4, max 64)\n")
		fmt.Fprintf(os.Stderr, "  -W int\n")
		fmt.Fprintf(os.Stderr, "        App Buffer Size in KB (default 64, recommend 512-1024 for 4K streaming)\n")
		fmt.Fprintf(os.Stderr, "  -socket-buffer int\n")
		fmt.Fprintf(os.Stderr, "        Kernel Socket Buffer in KB (default 0 = OS auto-tuning)\n")
		fmt.Fprintf(os.Stderr, "  -no-tcp-nodelay\n")
		fmt.Fprintf(os.Stderr, "        Disable TCP_NODELAY (disable Nagle bypass)\n")
		fmt.Fprintf(os.Stderr, "  -no-tcp-keepalive\n")
		fmt.Fprintf(os.Stderr, "        Disable TCP KeepAlive probes\n\n")
		fmt.Fprintf(os.Stderr, "Security & Networking:\n")
		fmt.Fprintf(os.Stderr, "  -dns string\n")
		fmt.Fprintf(os.Stderr, "        Remote DNS server IP for target host resolution (e.g. 8.8.8.8, 1.1.1.1)\n")
		fmt.Fprintf(os.Stderr, "  -block-local\n")
		fmt.Fprintf(os.Stderr, "        Drop local/LAN loopback traffic in Client mode (default true)\n")
		fmt.Fprintf(os.Stderr, "  -no-block-local\n")
		fmt.Fprintf(os.Stderr, "        Allow local/LAN loopback traffic in Client mode\n")
		fmt.Fprintf(os.Stderr, "  -verify-ssl\n")
		fmt.Fprintf(os.Stderr, "        Enable strict SSL certificate verification for wss:// upstream\n")
		fmt.Fprintf(os.Stderr, "  -allow-open\n")
		fmt.Fprintf(os.Stderr, "        Allow server mode without authentication key (open proxy risk)\n")
		fmt.Fprintf(os.Stderr, "  -max-conn int\n")
		fmt.Fprintf(os.Stderr, "        Max Concurrent Connections limit (default 1500)\n")
		fmt.Fprintf(os.Stderr, "  -connection-timeout int\n")
		fmt.Fprintf(os.Stderr, "        Idle connection timeout in seconds (default 60)\n\n")
		fmt.Fprintf(os.Stderr, "Diagnostics & UI:\n")
		fmt.Fprintf(os.Stderr, "  -log string\n")
		fmt.Fprintf(os.Stderr, "        Log Level: DEBUG, INFO, WARN, ERROR (default \"INFO\")\n")
		fmt.Fprintf(os.Stderr, "  -log-file string\n")
		fmt.Fprintf(os.Stderr, "        Save last 10 warning/error log entries to file on exit (e.g. goway.log)\n")
		fmt.Fprintf(os.Stderr, "  -tui\n")
		fmt.Fprintf(os.Stderr, "        Enable GUI-style Terminal User Interface dashboard\n")
		fmt.Fprintf(os.Stderr, "  -version\n")
		fmt.Fprintf(os.Stderr, "        Print version and exit\n")
		fmt.Fprintf(os.Stderr, "  -cpuprofile string\n")
		fmt.Fprintf(os.Stderr, "        Write CPU execution profile to file (for PGO compilation)\n")
		fmt.Fprintf(os.Stderr, "  -cpuprofile-duration int\n")
		fmt.Fprintf(os.Stderr, "        Stop CPU profiling after N seconds\n")
	}

	flag.Parse()

	if *cpuProfileFlag != "" {
		if f, err := os.Create(*cpuProfileFlag); err == nil {
			_ = pprof.StartCPUProfile(f)
			if *cpuProfileDurationFlag > 0 {
				time.AfterFunc(time.Duration(*cpuProfileDurationFlag)*time.Second, func() {
					pprof.StopCPUProfile()
					_ = f.Close()
				})
			} else {
				defer pprof.StopCPUProfile()
			}
		}
	}

	if *versionFlag {
		fmt.Printf("GOWAY v%s\n", Version)
		os.Exit(0)
	}

	globalLogLevel = parseLogLevel(*logFlag)
	tuiEnabled = *tuiFlag
	logFilePath = *logFileFlag

	pInput := strings.TrimSpace(*pFlag)
	if pInput == "" {
		fmt.Println("Error: -p is required")
		flag.Usage()
		os.Exit(1)
	}

	if *maxConnFlag <= 0 || *maxConnFlag > 1000000 {
		fmt.Printf("Error: -max-conn must be between 1 and 1000000, got %d\n", *maxConnFlag)
		os.Exit(1)
	}
	if *sockBufFlag < 0 || *sockBufFlag > 1048576 {
		fmt.Printf("Error: -socket-buffer must be between 0 and 1048576 KB, got %d\n", *sockBufFlag)
		os.Exit(1)
	}
	if *connTimeoutFlag <= 0 || *connTimeoutFlag > 86400 {
		fmt.Printf("Error: -connection-timeout must be between 1 and 86400 seconds, got %d\n", *connTimeoutFlag)
		os.Exit(1)
	}
	if *wFlag <= 0 || *wFlag > 12288 {
		fmt.Printf("Error: -W (buffer size in KB) must be between 1 and 12288, got %d\n", *wFlag)
		os.Exit(1)
	}
	if *muxSessionsFlag < 1 || *muxSessionsFlag > 64 {
		fmt.Printf("Error: -mux-sessions must be between 1 and 64, got %d\n", *muxSessionsFlag)
		os.Exit(1)
	}
	if *fakeHostFlag != "" {
		fakeHostClean := strings.TrimSpace(*fakeHostFlag)
		if strings.ContainsAny(fakeHostClean, " \t\r\n/") {
			fmt.Printf("Error: invalid -fakehost '%s': contains whitespace or invalid characters\n", *fakeHostFlag)
			os.Exit(1)
		}
	}

	cfg := Config{
		Upstream:       *upFlag,
		FakeHost:       *fakeHostFlag,
		Key:            *kFlag,
		BufferSize:     *wFlag * 1024,
		NoTcpNoDelay:   *noDelayFlag,
		NoTcpKeepAlive: *keepAliveFlag,
		SocketBuffer:   *sockBufFlag,
		ConnTimeout:    *connTimeoutFlag,
		VerifySSL:      *verifySSLFlag,
		MaxConns:       *maxConnFlag,
		BlockLocal:     *blockLocalFlag && !*noBlockLocalFlag,
		AllowOpen:      *allowOpenFlag,
		TUI:            tuiEnabled,
		Mux:            *muxFlag && !*noMuxFlag,
		MuxSessions:    *muxSessionsFlag,
		Obfs:           *obfsFlag,
	}

	if *dnsFlag != "" {
		dnsClean := strings.TrimSpace(*dnsFlag)
		if net.ParseIP(dnsClean) == nil {
			fmt.Printf("Error: -dns requires a valid IP address (e.g. 8.8.8.8), got '%s'\n", *dnsFlag)
			os.Exit(1)
		}
		cfg.Resolver = NewRemoteResolver(dnsClean)
	}

	var host string
	var portStr string
	if strings.Contains(pInput, ":") {
		h, p, splitErr := net.SplitHostPort(pInput)
		if splitErr != nil {
			fmt.Printf("Error: invalid listen address '%s': %v\n", pInput, splitErr)
			os.Exit(1)
		}
		if h == "" {
			host = "0.0.0.0"
		} else {
			host = h
		}
		portStr = p
	} else {
		host = "0.0.0.0"
		portStr = pInput
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		fmt.Printf("Error: invalid port '%s' (must be 1-65535)\n", portStr)
		os.Exit(1)
	}
	cfg.ProxyHost = host
	cfg.ProxyPort = port

	cfg.Crypto = NewCrypto(cfg.Key)

	// Parse upstream URL once at startup — avoids per-connection url.Parse alloc.
	if cfg.Upstream != "" {
		parsedUp, upErr := url.Parse(cfg.Upstream)
		if upErr != nil || parsedUp.Host == "" {
			fmt.Printf("Error: invalid upstream URL '%s': valid format ws://host:port, wss://host:port, quic://host:port\n", cfg.Upstream)
			os.Exit(1)
		}
		scheme := strings.ToLower(parsedUp.Scheme)
		if scheme != "ws" && scheme != "wss" && scheme != "quic" && scheme != "quic+tls" {
			fmt.Printf("Error: unsupported upstream scheme '%s' in '%s' (supported: ws, wss, quic, quic+tls)\n", parsedUp.Scheme, cfg.Upstream)
			os.Exit(1)
		}
		cfg.ParsedUpstream = parsedUp
		cfg.IsQUICUpstream = (scheme == "quic" || scheme == "quic+tls")
		cfg.UpstreamIsWSS = (scheme == "wss")

		upHost := parsedUp.Hostname()
		upPort := parsedUp.Port()
		if upPort == "" {
			if cfg.UpstreamIsWSS || cfg.IsQUICUpstream {
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

	listenAddr := net.JoinHostPort(cfg.ProxyHost, strconv.Itoa(cfg.ProxyPort))

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
			muxStr := AnsiGreen + fmt.Sprintf("Enabled (0-RTT Multiplexing, sessions: %d)", cfg.MuxSessions) + AnsiReset
			if !cfg.Mux {
				muxStr = AnsiYellow + "Disabled (1:1 Legacy)" + AnsiReset
			}
			fmt.Printf(" [+] Mux:         %s\n", muxStr)
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
	if bufSize < 65536+14+MuxHeaderLen {
		bufSize = 65536 + 14 + MuxHeaderLen
	}
	if bufSize > 12*1024*1024+14+MuxHeaderLen {
		bufSize = 12*1024*1024 + 14 + MuxHeaderLen
	}
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

	// Initialize connection pool for client mode
	if cfg.Upstream != "" {
		if cfg.IsQUICUpstream {
			qp, qErr := NewQUICClientPool(&cfg)
			if qErr != nil {
				log.Fatalf("Failed to initialize QUIC pool: %v", qErr)
			}
			cfg.QUICPool = qp
		} else {
			if cfg.Mux {
				cfg.MuxPool = NewMuxClientPool(&cfg, cfg.MuxSessions)
			} else {
				connPool = NewConnPool(&cfg, 10) // Pool of 10 pre-established connections for non-Mux mode
			}
		}

		// Startup test: verify upstream IP is reachable (asynchronous with fast 3s timeout)
		if net.ParseIP(cfg.UpstreamHost) != nil {
			go func() {
				probeTimeout := 3 * time.Second
				if cfg.ConnTimeout > 0 && cfg.ConnTimeout < 3 {
					probeTimeout = time.Duration(cfg.ConnTimeout) * time.Second
				}
				testDialer := &net.Dialer{Timeout: probeTimeout}
				testAddr := net.JoinHostPort(cfg.UpstreamHost, cfg.UpstreamPort)
				if _, err := testDialer.Dial("tcp", testAddr); err != nil {
					logWarn("Upstream IP %s is unreachable: %v", testAddr, err)
					logWarn("All connections will use DNS-resolved Cloudflare edges via -fakehost")
					if connPool != nil {
						connPool.mu.Lock()
						connPool.deadIPs[cfg.UpstreamHost] = time.Now().Add(5 * time.Minute)
						connPool.mu.Unlock()
					}
				} else {
					logInfo("Upstream IP %s is reachable", testAddr)
				}
			}()
		}
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
		saveLogFile()
		if cfg.QUICPool != nil {
			cfg.QUICPool.Close()
		}
		if cfg.MuxPool != nil {
			cfg.MuxPool.Close()
		}
		if connPool != nil {
			connPool.Close()
		}
		pprof.StopCPUProfile()
		close(shutdown)
		listener.Close()
	}()

	if tuiEnabled {
		fmt.Print("\033[2J\033[?25l")             // Clear screen & hide cursor
		defer fmt.Print("\033[?25h\033[2J\033[H") // Restore cursor & clear screen on exit
		go tuiRefreshLoop(&cfg, shutdown)
	}

	go monitorStats(shutdown)

	if cfg.Upstream == "" {
		go startQUICServer(listenAddr, &cfg, shutdown)
	}

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

		if !tryAcquireConn(int64(cfg.MaxConns)) {
			logWarn("MaxConns (%d) reached, rejecting connection", cfg.MaxConns)
			_ = conn.Close()
			continue
		}

		go func(c net.Conn) {
			defer releaseConn()
			handleConnection(c, &cfg)
		}(conn)
	}

	logInfo("Proxy stopped.")
	saveLogFile()
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

// --- Mux (Multiplexing) Subsystem ---

const (
	MuxCmdSYN    byte = 0x01 // New Stream: [TargetLen uint16][TargetAddr string][InitialData...]
	MuxCmdDATA   byte = 0x02 // Stream Data: [Data...]
	MuxCmdFIN    byte = 0x03 // Stream Half-Close / EOF
	MuxCmdRST    byte = 0x04 // Stream Abrupt Reset / Error
	MuxHeaderLen      = 7    // 4B StreamID + 1B Cmd + 2B PayloadLen

	// Client-side Mux stream buffer limit.
	// Kept lower to reduce per-stream memory usage on client instances.
	muxClientStreamBufferLimit = 8 * 1024 * 1024

	// Server-side Mux stream buffer limit.
	// Kept higher to provide additional buffering headroom for
	// downstream fan-out / asymmetric traffic patterns.
	muxServerStreamBufferLimit = 8 * 1024 * 1024
	muxStreamIngressQueue      = 128
	muxPushStallTimeout        = 15 * time.Second
)

// muxDataFrame encapsulates a payload slice along with ownership of a pooled buffer from sync.Pool.
type muxDataFrame struct {
	data []byte
	bPtr *[]byte
	pool *sync.Pool
}

func (f *muxDataFrame) release() {
	if f.bPtr != nil && f.pool != nil {
		f.pool.Put(f.bPtr)
		f.bPtr = nil
		f.pool = nil
	}
	f.data = nil
}

type MuxSessionInterface interface {
	SendFrame(streamID uint32, cmd byte, payload []byte) error
	RemoveStream(streamID uint32)
}

// MuxStream represents an individual multiplexed stream on the client side.
type MuxStream struct {
	id          uint32
	session     MuxSessionInterface
	readChan    chan muxDataFrame
	curFrame    muxDataFrame
	readBuf     []byte
	readPos     int
	closeOnce   sync.Once
	closed      chan struct{}
	readClosed  atomic.Bool
	bufMu       sync.Mutex
	queuedBytes int64
	hasSpace    chan struct{}
	onClose     func()
	readMu      sync.Mutex
	ingress     chan muxDataFrame
}

func newMuxStream(id uint32, session MuxSessionInterface) *MuxStream {
	st := &MuxStream{id: id, session: session, readChan: make(chan muxDataFrame, 128), closed: make(chan struct{}), hasSpace: make(chan struct{}, 1), ingress: make(chan muxDataFrame, muxStreamIngressQueue)}
	go st.deliveryLoop()
	return st
}

func (s *MuxStream) enqueueDataFrame(frame muxDataFrame) bool {
	select {
	case <-s.closed:
		frame.release()
		return false
	case s.ingress <- frame:
		return true
	default:
		logWarn("[MUX] Stream %d ingress queue full, resetting stream", s.id)
		frame.release()
		s.Reset()
		return false
	}
}

func (s *MuxStream) deliveryLoop() {
	for {
		select {
		case <-s.closed:
			return
		case frame := <-s.ingress:
			if !s.PushDataFrame(frame) {
				frame.release()
			}
		}
	}
}

func (s *MuxStream) PushDataFrame(frame muxDataFrame) bool {
	dataLen := int64(len(frame.data))
	for {
		s.bufMu.Lock()
		select {
		case <-s.closed:
			s.bufMu.Unlock()
			return false
		default:
		}
		if frame.data == nil {
			s.readClosed.Store(true)
		}
		if s.queuedBytes+dataLen <= muxClientStreamBufferLimit {
			select {
			case s.readChan <- frame:
				s.queuedBytes += dataLen
				s.bufMu.Unlock()
				return true
			default:
			}
		}
		s.bufMu.Unlock()
		deadline := time.NewTimer(muxPushStallTimeout)
		select {
		case <-s.closed:
			if !deadline.Stop() {
				<-deadline.C
			}
			return false
		case <-s.hasSpace:
			if !deadline.Stop() {
				<-deadline.C
			}
			continue
		case <-deadline.C:
			logWarn("[MUX] Stream %d receive backpressure timeout, resetting stream", s.id)
			s.Reset()
			return false
		}
	}
}

func (s *MuxStream) PushData(data []byte) bool {
	return s.PushDataFrame(muxDataFrame{data: data})
}

func (s *MuxStream) PushEOF() {
	s.readClosed.Store(true)
	select {
	case <-s.closed:
	default:
		select {
		case s.readChan <- muxDataFrame{data: nil}:
		default:
		}
	}
}

func (s *MuxStream) consumedBytes(n int) {
	if n <= 0 {
		return
	}
	s.bufMu.Lock()
	s.queuedBytes -= int64(n)
	if s.queuedBytes < 0 {
		s.queuedBytes = 0
	}
	if s.queuedBytes < muxClientStreamBufferLimit {
		select {
		case s.hasSpace <- struct{}{}:
		default:
		}
	}
	s.bufMu.Unlock()
}

func (s *MuxStream) QueuedBytes() int64 {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	return s.queuedBytes
}

func (s *MuxStream) Read(p []byte) (n int, err error) {
	for {
		s.readMu.Lock()
		if s.readPos < len(s.readBuf) {
			n = copy(p, s.readBuf[s.readPos:])
			s.readPos += n
			if s.readPos >= len(s.readBuf) {
				s.curFrame.release()
				s.readBuf = nil
				s.readPos = 0
			}
			s.readMu.Unlock()
			s.consumedBytes(n)
			return n, nil
		}
		if s.readClosed.Load() && len(s.readChan) == 0 {
			s.readMu.Unlock()
			return 0, io.EOF
		}
		s.readMu.Unlock()

		select {
		case <-s.closed:
			s.readMu.Lock()
			s.curFrame.release()
			s.readBuf = nil
			s.readPos = 0
			s.readMu.Unlock()
			if s.readClosed.Load() {
				return 0, io.EOF
			}
			return 0, errors.New("stream closed")
		case frame, ok := <-s.readChan:
			select {
			case <-s.closed:
				frame.release()
				s.readMu.Lock()
				s.curFrame.release()
				s.readBuf = nil
				s.readPos = 0
				s.readMu.Unlock()
				if s.readClosed.Load() {
					return 0, io.EOF
				}
				return 0, errors.New("stream closed")
			default:
			}
			if !ok || frame.data == nil {
				s.readMu.Lock()
				s.curFrame.release()
				s.readBuf = nil
				s.readPos = 0
				s.readMu.Unlock()
				return 0, io.EOF
			}
			s.readMu.Lock()
			s.curFrame = frame
			s.readBuf = frame.data
			s.readPos = 0
			s.readMu.Unlock()
		}
	}
}

func (s *MuxStream) Write(p []byte) (n int, err error) {
	select {
	case <-s.closed:
		return 0, errors.New("stream closed")
	default:
	}
	const maxChunk = 65528
	total := len(p)
	for len(p) > 0 {
		chunk := len(p)
		if chunk > maxChunk {
			chunk = maxChunk
		}
		if err := s.session.SendFrame(s.id, MuxCmdDATA, p[:chunk]); err != nil {
			return total - len(p), err
		}
		p = p[chunk:]
	}
	return total, nil
}

func (s *MuxStream) cleanup() {
	s.readMu.Lock()
	s.curFrame.release()
	s.readBuf = nil
	s.readPos = 0
	s.readMu.Unlock()
	s.bufMu.Lock()
	s.queuedBytes = 0
	s.bufMu.Unlock()
	for {
		select {
		case f := <-s.readChan:
			f.release()
		default:
			for {
				select {
				case f := <-s.ingress:
					f.release()
				default:
					return
				}
			}
		}
	}
}

func (s *MuxStream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.session.SendFrame(s.id, MuxCmdFIN, nil)
		s.session.RemoveStream(s.id)
		s.cleanup()
		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

func (s *MuxStream) Reset() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.session.SendFrame(s.id, MuxCmdRST, nil)
		s.session.RemoveStream(s.id)
		s.cleanup()
		if s.onClose != nil {
			s.onClose()
		}
	})
}

// MuxClientSession handles a single WebSocket tunnel carrying multiple MuxStreams.
type muxOutboundFrame struct {
	bPtr       *[]byte
	pool       *sync.Pool
	payloadOff int
	payloadLen int
	opcode     byte
	ping       bool
	// MUX routing identity for fair scheduling. streamID selects the
	// per-stream queue; cmd selects the priority lane (everything except
	// MuxCmdDATA is latency-sensitive control traffic).
	streamID uint32
	cmd      byte
}

// muxStreamQueue is one stream's FIFO inside the fair writer, with a
// deficit-round-robin byte credit.
type muxStreamQueue struct {
	frames  []muxOutboundFrame
	deficit int
}

// muxOutboundWriter serializes frames from all streams of one MUX session
// onto a single WebSocket connection with per-stream fairness.
//
// The previous design drained a single FIFO channel: one bulk stream could
// bury interactive streams behind megabytes of queued data (a stalled video
// that only recovers on refresh). This design keeps one FIFO per stream
// plus a priority lane, scheduled as:
//
//  1. priority lane first: ping + SYN/FIN/RST control frames;
//  2. deficit round robin across streams (64KB quantum each) for DATA.
//
// enqueue() blocks when the total queued backlog reaches
// muxOutboundQueueDepth, preserving the old backpressure contract.
// Locks are never held across network IO.
type muxOutboundWriter struct {
	conn     net.Conn
	prng     *maskPRNG
	crypto   *Crypto
	mu       sync.Mutex
	cond     *sync.Cond
	streams  map[uint32]*muxStreamQueue
	rotation []uint32
	pos      int
	priority []muxOutboundFrame
	total    int
	closed   bool
	done     chan struct{}
	closeMu  sync.Once
}

const (
	// Total queued frames across all streams + priority lane. Raised from
	// the old FIFO depth of 8: fairness now protects interactive streams,
	// so bulk streams may use deeper backlog (~4MB worst case at 64KB).
	muxOutboundQueueDepth = 64
	// Per-stream byte credit added each deficit round.
	muxDRRQuantum = 64 * 1024
	// Cap accumulated credit so a long-idle stream cannot hog the link.
	muxDRRMaxDeficit = 256 * 1024
	// Max random padding appended to MUX DATA frames when -obfs is on.
	// Sized near MTU so padded lengths spread across the full range.
	obfsPadMax = 1400
)

func newMuxOutboundWriter(conn net.Conn, prng *maskPRNG, crypto *Crypto) *muxOutboundWriter {
	w := &muxOutboundWriter{
		conn:    conn,
		prng:    prng,
		crypto:  crypto,
		streams: make(map[uint32]*muxStreamQueue),
		done:    make(chan struct{}),
	}
	w.cond = sync.NewCond(&w.mu)
	go w.loop()
	return w
}

func (w *muxOutboundWriter) releaseFrame(f muxOutboundFrame) {
	if f.bPtr != nil && f.pool != nil {
		f.pool.Put(f.bPtr)
	}
}

// frameWireLen is the on-wire MUX cost of a queued frame (header included),
// used for deficit accounting.
func frameWireLen(f muxOutboundFrame) int {
	if f.payloadLen > 0 {
		return f.payloadLen
	}
	return MuxHeaderLen
}

func (w *muxOutboundWriter) writeFrame(f muxOutboundFrame) error {
	if f.ping {
		return writeWSFrame(w.conn, nil, 0x9, true)
	}
	if f.bPtr == nil || f.pool == nil {
		return errors.New("invalid mux outbound frame")
	}
	return writeMuxFrameFused(w.conn, *f.bPtr, f.payloadOff, f.payloadLen, f.opcode, w.prng, w.crypto)
}

// dropAllLocked releases every queued frame and resets scheduling state.
// Caller must hold w.mu.
func (w *muxOutboundWriter) dropAllLocked() {
	for _, f := range w.priority {
		w.releaseFrame(f)
	}
	w.priority = nil
	for _, q := range w.streams {
		for _, f := range q.frames {
			w.releaseFrame(f)
		}
	}
	w.streams = make(map[uint32]*muxStreamQueue)
	w.rotation = nil
	w.pos = 0
	w.total = 0
}

// removeLocked deletes one stream's queue. Caller must hold w.mu; it
// returns the doomed frames for release AFTER unlock to keep the critical
// section free of foreign calls.
func (w *muxOutboundWriter) removeLocked(id uint32) []muxOutboundFrame {
	q := w.streams[id]
	if q == nil {
		return nil
	}
	doomed := q.frames
	delete(w.streams, id)
	for i, sid := range w.rotation {
		if sid == id {
			w.rotation = append(w.rotation[:i], w.rotation[i+1:]...)
			if w.pos > i {
				w.pos--
			}
			break
		}
	}
	if w.pos >= len(w.rotation) {
		w.pos = 0
	}
	return doomed
}

func (w *muxOutboundWriter) loop() {
	defer close(w.done)
	for {
		f, ok := w.next()
		if !ok {
			return
		}
		if err := w.writeFrame(f); err != nil {
			w.mu.Lock()
			w.closed = true
			w.dropAllLocked()
			w.cond.Broadcast()
			w.mu.Unlock()
			_ = w.conn.Close()
			return
		}
		w.releaseFrame(f)
	}
}

// next pops the next frame to send: priority lane first, then deficit
// round robin. Never holds the lock across network IO.
func (w *muxOutboundWriter) next() (muxOutboundFrame, bool) {
	var empty muxOutboundFrame
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		if len(w.priority) > 0 {
			f := w.priority[0]
			// Self-ordering: a control frame yields while its own stream
			// still has queued DATA — else the peer closes early and drops
			// the tail (proven by FinNeverOvertakesOwnData). Ping/system
			// frames and controls for streams with empty queues jump at
			// once; the deferred control is reconsidered every round, so
			// it still precedes other streams' later bulk.
			blocked := false
			if !f.ping && f.streamID != 0 {
				if q := w.streams[f.streamID]; q != nil && len(q.frames) > 0 {
					blocked = true
				}
			}
			if !blocked {
				w.priority[0] = muxOutboundFrame{}
				w.priority = w.priority[1:]
				w.total--
				w.cond.Signal()
				return f, true
			}
		}
		if f, ok := w.nextDataLocked(); ok {
			w.total--
			w.cond.Signal()
			return f, true
		}
		if w.closed {
			return empty, false
		}
		w.cond.Wait()
	}
}

// nextDataLocked serves one frame by deficit round robin. Caller must hold w.mu.
func (w *muxOutboundWriter) nextDataLocked() (muxOutboundFrame, bool) {
	var empty muxOutboundFrame
	if len(w.rotation) == 0 {
		return empty, false
	}
	start := w.pos % len(w.rotation)
	for k := 0; k < len(w.rotation); k++ {
		idx := (start + k) % len(w.rotation)
		id := w.rotation[idx]
		q := w.streams[id]
		if q == nil || len(q.frames) == 0 {
			continue
		}
		q.deficit += muxDRRQuantum
		if q.deficit > muxDRRMaxDeficit {
			q.deficit = muxDRRMaxDeficit
		}
		head := q.frames[0]
		if frameWireLen(head) > q.deficit {
			continue
		}
		q.frames[0] = muxOutboundFrame{}
		q.frames = q.frames[1:]
		q.deficit -= frameWireLen(head)
		if len(q.frames) == 0 {
			delete(w.streams, id)
			w.rotation = append(w.rotation[:idx], w.rotation[idx+1:]...)
		}
		// Advance PAST the served stream so the next round starts with
		// its successor (strict rotation; idx would stick to one bulk
		// stream otherwise).
		w.pos = idx + 1
		return head, true
	}
	return empty, false
}

func (w *muxOutboundWriter) enqueue(f muxOutboundFrame) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for w.total >= muxOutboundQueueDepth && !w.closed {
		w.cond.Wait()
	}
	if w.closed {
		w.releaseFrame(f)
		return false
	}
	if f.ping || (f.cmd != 0 && f.cmd != MuxCmdDATA) {
		w.priority = append(w.priority, f)
	} else {
		q := w.streams[f.streamID]
		if q == nil {
			q = &muxStreamQueue{}
			w.streams[f.streamID] = q
			w.rotation = append(w.rotation, f.streamID)
		}
		q.frames = append(q.frames, f)
	}
	w.total++
	w.cond.Signal()
	return true
}

func (w *muxOutboundWriter) enqueuePing() bool {
	return w.enqueue(muxOutboundFrame{ping: true})
}

// dropStream discards a dead stream's queued frames so they neither block
// the rotation nor leak pool buffers.
func (w *muxOutboundWriter) dropStream(id uint32) {
	w.mu.Lock()
	doomed := w.removeLocked(id)
	for range doomed {
		w.total--
	}
	w.cond.Broadcast()
	w.mu.Unlock()
	for _, f := range doomed {
		w.releaseFrame(f)
	}
}

func (w *muxOutboundWriter) close() {
	w.closeMu.Do(func() {
		w.mu.Lock()
		w.closed = true
		w.dropAllLocked()
		w.cond.Broadcast()
		w.mu.Unlock()
	})
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
	s.writer = newMuxOutboundWriter(wsConn, prng, cfg.Crypto)
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
	if s.writer != nil {
		s.writer.dropStream(streamID)
	}
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
	// NB: cipher is applied at write time by writeMuxFrameFused (single
	// cipher+mask pass); do NOT TransformInPlace here.
	padLen := 0
	if cmd == MuxCmdDATA && s.cfg.Obfs {
		if room := len(buf) - 14 - frameLen; room > 0 {
			if room > obfsPadMax {
				room = obfsPadMax
			}
			padLen = mrand.Intn(room + 1)
			// Random fill: zero padding would itself be fingerprintable.
			mrand.Read(buf[frameStart+frameLen : frameStart+frameLen+padLen])
		}
	}
	frame := muxOutboundFrame{bPtr: bPtr, pool: s.cfg.BufPool, payloadOff: frameStart, payloadLen: frameLen + padLen, opcode: 0x2, streamID: streamID, cmd: cmd}
	if !s.writer.enqueue(frame) {
		return errors.New("mux session writer closed")
	}
	return nil
}

func (s *MuxClientSession) readLoop() {
	defer s.Close()
	bPtr := s.cfg.BufPool.Get().(*[]byte)
	defer func() {
		if bPtr != nil {
			s.cfg.BufPool.Put(bPtr)
			bPtr = nil
		}
	}()
	buf := *bPtr
	var lastDeadline time.Time

	for {
		if deadlineThrottle(&lastDeadline) {
			setTCPReadDeadline(s.wsTCPConn, s.cfg.ConnTimeout)
		}
		data, err := readWSFrameInto(s.br, s.wsConn, buf[14:])
		if err != nil {
			return
		}
		if s.cfg.Crypto != nil {
			s.cfg.Crypto.TransformInPlace(data)
		}

		if len(data) < MuxHeaderLen {
			continue
		}
		streamID := binary.BigEndian.Uint32(data[:4])
		cmd := data[4]
		payloadLen := int(binary.BigEndian.Uint16(data[5:7]))
		if len(data) < MuxHeaderLen+payloadLen {
			continue
		}
		payload := data[MuxHeaderLen : MuxHeaderLen+payloadLen]

		s.streamsMu.RLock()
		st, ok := s.streams[streamID]
		s.streamsMu.RUnlock()

		if !ok {
			continue
		}

		switch cmd {
		case MuxCmdDATA:
			if len(payload) > 0 {
				frame := muxDataFrame{
					data: payload,
					bPtr: bPtr,
					pool: s.cfg.BufPool,
				}
				bPtr = s.cfg.BufPool.Get().(*[]byte)
				buf = *bPtr
				st.enqueueDataFrame(frame)
				stats.AddBytes(0, int64(len(payload)))
			}
		case MuxCmdFIN:
			st.enqueueDataFrame(muxDataFrame{data: nil})
		case MuxCmdRST:
			st.Reset()
		}
	}
}

// MuxClientPool manages active Mux sessions on the client side.
type MuxClientPool struct {
	cfg      *Config
	sessions []*MuxClientSession
	mu       sync.Mutex
	maxSess  int
	roundIdx uint32
	dialing  int
	closed   bool
}

func NewMuxClientPool(cfg *Config, maxSessions int) *MuxClientPool {
	return &MuxClientPool{
		cfg:      cfg,
		maxSess:  maxSessions,
		sessions: make([]*MuxClientSession, 0, maxSessions),
	}
}

func (p *MuxClientPool) pickBestSessionLocked() *MuxClientSession {
	if len(p.sessions) == 0 {
		return nil
	}
	if len(p.sessions) == 1 {
		return p.sessions[0]
	}

	var minStreams int64 = -1
	var candidates []*MuxClientSession

	for _, s := range p.sessions {
		cnt := s.ActiveStreams()
		if minStreams == -1 || cnt < minStreams {
			minStreams = cnt
			candidates = candidates[:0]
			candidates = append(candidates, s)
		} else if cnt == minStreams {
			candidates = append(candidates, s)
		}
	}

	if len(candidates) == 1 {
		return candidates[0]
	}

	idx := atomic.AddUint32(&p.roundIdx, 1) % uint32(len(candidates))
	return candidates[idx]
}

func (p *MuxClientPool) GetSession() (*MuxClientSession, error) {
	p.mu.Lock()

	// Filter out dead sessions
	valid := p.sessions[:0]
	for _, s := range p.sessions {
		if s.IsAlive() {
			valid = append(valid, s)
		}
	}
	p.sessions = valid

	// If at least one session is active, select the least loaded (least active streams, with round-robin tie-breaking)
	if len(p.sessions) > 0 {
		sess := p.pickBestSessionLocked()
		sess.activeStreams.Add(1)

		// If pool capacity is not yet reached, trigger background dial to scale up
		if !p.closed && len(p.sessions)+p.dialing < p.maxSess {
			p.dialing++
			go p.dialBackgroundSession()
		}

		p.mu.Unlock()
		return sess, nil
	}

	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("mux client pool closed")
	}

	// No sessions alive. Dial synchronously, releasing lock during network I/O
	p.dialing++
	p.mu.Unlock()

	sess, err := p.dialNewSession()

	p.mu.Lock()
	p.dialing--
	if err != nil {
		// If another goroutine succeeded while we were dialing, use that
		if len(p.sessions) > 0 {
			s := p.pickBestSessionLocked()
			s.activeStreams.Add(1)
			p.mu.Unlock()
			return s, nil
		}
		p.mu.Unlock()
		return nil, err
	}

	if p.closed {
		p.mu.Unlock()
		sess.Close()
		return nil, errors.New("mux client pool closed")
	}

	p.sessions = append(p.sessions, sess)
	sess.activeStreams.Add(1)
	p.mu.Unlock()
	return sess, nil
}

func (p *MuxClientPool) dialBackgroundSession() {
	sess, err := p.dialNewSession()
	p.mu.Lock()
	p.dialing--
	if err == nil {
		if !p.closed && len(p.sessions) < p.maxSess {
			p.sessions = append(p.sessions, sess)
		} else {
			sess.Close()
		}
	}
	p.mu.Unlock()
}

func (p *MuxClientPool) dialNewSession() (*MuxClientSession, error) {
	wsConn, br, wsTCPConn, err := dialUpstreamWS(p.cfg)
	if err != nil {
		return nil, err
	}

	targetPayload := []byte("MUX\n")
	if p.cfg.Crypto != nil {
		p.cfg.Crypto.TransformInPlace(targetPayload)
	}
	if err := writeWSFrame(wsConn, targetPayload, 0x2, true); err != nil {
		wsConn.Close()
		return nil, err
	}

	setTCPReadDeadline(wsTCPConn, p.cfg.ConnTimeout)
	okFrame, err := readWSFrame(br, wsConn)
	if err != nil {
		wsConn.Close()
		return nil, err
	}
	if p.cfg.Crypto != nil {
		p.cfg.Crypto.TransformInPlace(okFrame)
	}
	if !strings.HasPrefix(string(okFrame), "OK") {
		wsConn.Close()
		return nil, errors.New("mux auth rejected by server")
	}

	logInfo("[MUX] Client session established to upstream")
	return newMuxClientSession(wsConn, br, wsTCPConn, p.cfg), nil
}

func (p *MuxClientPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, s := range p.sessions {
		s.Close()
	}
	p.sessions = nil
}

// relayMuxClient multiplexes a single user connection over an active MuxSession.
func relayMuxClient(localConn net.Conn, ver byte, initialPayload []byte, targetAddr string, cfg *Config) bool {
	session, err := cfg.MuxPool.GetSession()
	if err != nil || session == nil {
		return false
	}

	streamID := atomic.AddUint32(&session.nextStreamID, 1)
	stream := newMuxStream(streamID, session)
	stream.onClose = func() {
		session.decrementActiveStreams()
	}

	session.streamsMu.Lock()
	session.streams[streamID] = stream
	session.streamsMu.Unlock()

	defer stream.Close()

	tLen := len(targetAddr)
	if tLen > 65535-2 {
		logError("[CLIENT-MUX] Target address length %d exceeds max protocol limit", tLen)
		return false
	}
	maxInitialInSYN := 65535 - 2 - tLen
	var synInitial []byte
	var remainingInitial []byte
	if len(initialPayload) > maxInitialInSYN {
		synInitial = initialPayload[:maxInitialInSYN]
		remainingInitial = initialPayload[maxInitialInSYN:]
	} else {
		synInitial = initialPayload
	}

	synPayload := make([]byte, 2+tLen+len(synInitial))
	binary.BigEndian.PutUint16(synPayload[:2], uint16(tLen))
	copy(synPayload[2:2+tLen], targetAddr)
	if len(synInitial) > 0 {
		copy(synPayload[2+tLen:], synInitial)
	}

	if err := session.SendFrame(streamID, MuxCmdSYN, synPayload); err != nil {
		logDebug("[CLIENT-MUX] Send SYN failed: %v", err)
		session.RemoveStream(streamID)
		return false
	}

	if len(remainingInitial) > 0 {
		if _, err := stream.Write(remainingInitial); err != nil {
			logDebug("[CLIENT-MUX] Write remaining initial DATA failed: %v", err)
			return false
		}
	}

	if ver == 0x05 {
		if _, err := localConn.Write(socks5OKResp); err != nil {
			stream.Close()
			return true
		}
	} else if initialPayload == nil {
		if _, err := localConn.Write(http200Resp); err != nil {
			stream.Close()
			return true
		}
	}

	logDebug("[CLIENT-MUX] Stream %d -> %s (0-RTT)", streamID, targetAddr)

	errCh := make(chan error, 2)

	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		for {
			nr, errRead := localConn.Read(buf)
			if nr > 0 {
				if _, errWrite := stream.Write(buf[:nr]); errWrite != nil {
					errCh <- errWrite
					return
				}
				stats.AddBytes(int64(nr), 0)
			}
			if errRead != nil {
				stream.Close()
				errCh <- errRead
				return
			}
		}
	}()

	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		for {
			nr, errRead := stream.Read(buf)
			if nr > 0 {
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
	stream.Close()
	return true
}

// MuxServerSession handles a single WebSocket tunnel on the server side.
type MuxServerSession struct {
	wsConn    net.Conn
	br        *bufio.Reader
	wsTCPConn *net.TCPConn
	cfg       *Config
	writeMu   sync.Mutex
	streams   map[uint32]*MuxServerStream
	streamsMu sync.RWMutex
	closed    chan struct{}
	closeOnce sync.Once
}

type MuxServerStream struct {
	id          uint32
	session     *MuxServerSession
	writeChan   chan muxDataFrame
	targetMu    sync.Mutex
	targetConn  net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
	bufMu       sync.Mutex
	queuedBytes int64
	hasSpace    chan struct{}
	ingress     chan muxDataFrame
}

func newMuxServerStream(id uint32, session *MuxServerSession) *MuxServerStream {
	st := &MuxServerStream{id: id, session: session, writeChan: make(chan muxDataFrame, 256), closed: make(chan struct{}), hasSpace: make(chan struct{}, 1), ingress: make(chan muxDataFrame, muxStreamIngressQueue)}
	go st.deliveryLoop()
	return st
}

func (s *MuxServerStream) enqueueDataFrame(frame muxDataFrame) bool {
	select {
	case <-s.closed:
		frame.release()
		return false
	case s.ingress <- frame:
		return true
	default:
		logWarn("[SERVER-MUX] Stream %d ingress queue full, resetting stream", s.id)
		frame.release()
		s.Close()
		_ = s.session.SendFrame(s.id, MuxCmdRST, nil)
		return false
	}
}

func (s *MuxServerStream) deliveryLoop() {
	for {
		select {
		case <-s.closed:
			return
		case frame := <-s.ingress:
			if !s.PushDataFrame(frame) {
				frame.release()
			}
		}
	}
}

func (s *MuxServerStream) PushDataFrame(frame muxDataFrame) bool {
	dataLen := int64(len(frame.data))
	for {
		s.bufMu.Lock()
		select {
		case <-s.closed:
			s.bufMu.Unlock()
			return false
		default:
		}
		if s.queuedBytes+dataLen <= muxServerStreamBufferLimit {
			select {
			case s.writeChan <- frame:
				s.queuedBytes += dataLen
				s.bufMu.Unlock()
				return true
			default:
			}
		}
		s.bufMu.Unlock()
		deadline := time.NewTimer(muxPushStallTimeout)
		select {
		case <-s.closed:
			if !deadline.Stop() {
				<-deadline.C
			}
			return false
		case <-s.hasSpace:
			if !deadline.Stop() {
				<-deadline.C
			}
			continue
		case <-deadline.C:
			logWarn("[SERVER-MUX] Stream %d receive backpressure timeout, resetting stream", s.id)
			s.Close()
			_ = s.session.SendFrame(s.id, MuxCmdRST, nil)
			return false
		}
	}
}

func (s *MuxServerStream) PushData(data []byte) bool {
	return s.PushDataFrame(muxDataFrame{data: data})
}

func (s *MuxServerStream) consumedBytes(n int) {
	if n <= 0 {
		return
	}
	s.bufMu.Lock()
	s.queuedBytes -= int64(n)
	if s.queuedBytes < 0 {
		s.queuedBytes = 0
	}
	if s.queuedBytes < muxServerStreamBufferLimit {
		select {
		case s.hasSpace <- struct{}{}:
		default:
		}
	}
	s.bufMu.Unlock()
}

func (s *MuxServerStream) QueuedBytes() int64 {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	return s.queuedBytes
}

func (s *MuxServerStream) setTargetConn(conn net.Conn) bool {
	s.targetMu.Lock()
	defer s.targetMu.Unlock()
	select {
	case <-s.closed:
		if conn != nil {
			_ = conn.Close()
		}
		return false
	default:
	}
	if s.targetConn != nil {
		_ = s.targetConn.Close()
	}
	s.targetConn = conn
	return true
}

func (s *MuxServerStream) closeTargetConn() {
	s.targetMu.Lock()
	defer s.targetMu.Unlock()
	if s.targetConn != nil {
		_ = s.targetConn.Close()
		s.targetConn = nil
	}
}

func (s *MuxServerStream) targetConnSnapshot() net.Conn {
	s.targetMu.Lock()
	defer s.targetMu.Unlock()
	return s.targetConn
}

func (s *MuxServerStream) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.closeTargetConn()
		s.bufMu.Lock()
		s.queuedBytes = 0
		s.bufMu.Unlock()
		for {
			select {
			case frame := <-s.writeChan:
				frame.release()
			case frame := <-s.ingress:
				frame.release()
			default:
				return
			}
		}
	})
}

func (s *MuxServerSession) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.wsConn.Close()

		s.streamsMu.Lock()
		activeStreams := make([]*MuxServerStream, 0, len(s.streams))
		for _, st := range s.streams {
			activeStreams = append(activeStreams, st)
		}
		s.streams = make(map[uint32]*MuxServerStream)
		s.streamsMu.Unlock()

		for _, st := range activeStreams {
			st.Close()
		}
	})
}

func (s *MuxServerSession) SendFrame(streamID uint32, cmd byte, payload []byte) error {
	select {
	case <-s.closed:
		return errors.New("mux server session closed")
	default:
	}

	payloadLen := len(payload)
	if payloadLen > 65535 {
		return fmt.Errorf("mux server frame payload %d exceeds maximum uint16 length (65535)", payloadLen)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	frameLen := MuxHeaderLen + payloadLen
	bPtr := s.cfg.BufPool.Get().(*[]byte)
	defer s.cfg.BufPool.Put(bPtr)
	buf := *bPtr

	if frameLen+14 > len(buf) {
		return errors.New("mux server frame exceeds buffer")
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

	// Unilateral obfuscation, server side: same random-pad semantics as the
	// client path; receivers slice by the declared MUX length.
	writeLen := frameLen
	if cmd == MuxCmdDATA && s.cfg.Obfs {
		if room := len(buf) - 14 - frameLen; room > 0 {
			if room > obfsPadMax {
				room = obfsPadMax
			}
			padLen := mrand.Intn(room + 1)
			mrand.Read(buf[frameStart+frameLen : frameStart+frameLen+padLen])
			writeLen = frameLen + padLen
		}
	}

	return writeWSFramePreallocated(s.wsConn, buf, frameStart, writeLen, 0x2, false)
}

func handleServerMux(wsConn net.Conn, br *bufio.Reader, wsTCPConn *net.TCPConn, cfg *Config) {
	logInfo("[SERVER] Mux Session requested")
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

	session := &MuxServerSession{
		wsConn:    wsConn,
		br:        br,
		wsTCPConn: wsTCPConn,
		cfg:       cfg,
		streams:   make(map[uint32]*MuxServerStream),
		closed:    make(chan struct{}),
	}
	defer session.Close()

	logInfo("[SERVER] Mux Session active")

	bPtr := cfg.BufPool.Get().(*[]byte)
	defer func() {
		if bPtr != nil {
			cfg.BufPool.Put(bPtr)
			bPtr = nil
		}
	}()
	buf := *bPtr
	var lastDeadline time.Time

	for {
		if deadlineThrottle(&lastDeadline) {
			setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
		}
		data, err := readWSFrameInto(br, wsConn, buf[14:])
		if err != nil {
			return
		}
		if cfg.Crypto != nil {
			cfg.Crypto.TransformInPlace(data)
		}

		if len(data) < MuxHeaderLen {
			continue
		}
		streamID := binary.BigEndian.Uint32(data[:4])
		cmd := data[4]
		payloadLen := int(binary.BigEndian.Uint16(data[5:7]))
		if len(data) < MuxHeaderLen+payloadLen {
			continue
		}
		payload := data[MuxHeaderLen : MuxHeaderLen+payloadLen]

		switch cmd {
		case MuxCmdSYN:
			if len(payload) < 2 {
				continue
			}
			tLen := int(binary.BigEndian.Uint16(payload[:2]))
			if len(payload) < 2+tLen {
				continue
			}
			targetStr := string(payload[2 : 2+tLen])
			var initialData []byte
			if len(payload) > 2+tLen {
				initialData = make([]byte, len(payload)-(2+tLen))
				copy(initialData, payload[2+tLen:])
			}

			st := newMuxServerStream(streamID, session)
			session.streamsMu.Lock()
			session.streams[streamID] = st
			session.streamsMu.Unlock()

			go session.handleNewStream(st, targetStr, initialData)

		case MuxCmdDATA:
			session.streamsMu.RLock()
			st, ok := session.streams[streamID]
			session.streamsMu.RUnlock()
			if ok && len(payload) > 0 {
				frame := muxDataFrame{
					data: payload,
					bPtr: bPtr,
					pool: cfg.BufPool,
				}
				bPtr = cfg.BufPool.Get().(*[]byte)
				buf = *bPtr
				st.enqueueDataFrame(frame)
			}

		case MuxCmdFIN:
			session.streamsMu.RLock()
			st, ok := session.streams[streamID]
			session.streamsMu.RUnlock()
			if ok {
				st.enqueueDataFrame(muxDataFrame{data: nil})
			}

		case MuxCmdRST:
			session.streamsMu.RLock()
			st, ok := session.streams[streamID]
			session.streamsMu.RUnlock()
			if ok {
				st.Close()
			}
		}
	}
}

func (s *MuxServerSession) handleNewStream(st *MuxServerStream, targetStr string, initialData []byte) {
	defer func() {
		st.Close()
		s.streamsMu.Lock()
		delete(s.streams, st.id)
		s.streamsMu.Unlock()
	}()

	targetAddr := targetStr
	if s.cfg.Resolver != nil {
		host, port, splitErr := net.SplitHostPort(targetStr)
		if splitErr == nil {
			if resolvedIP, resolveErr := s.cfg.Resolver.Resolve(host); resolveErr == nil {
				targetAddr = net.JoinHostPort(resolvedIP, port)
			}
		}
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, time.Duration(s.cfg.ConnTimeout)*time.Second)
	if err != nil {
		logDebug("[SERVER-MUX] Dial %s failed: %v", targetAddr, err)
		s.SendFrame(st.id, MuxCmdRST, nil)
		return
	}

	optimizeSocket(targetConn, s.cfg)
	if !st.setTargetConn(targetConn) {
		return
	}

	if len(initialData) > 0 {
		if _, err := targetConn.Write(initialData); err != nil {
			logDebug("[SERVER-MUX] Write initialData to %s failed: %v", targetAddr, err)
			s.SendFrame(st.id, MuxCmdRST, nil)
			return
		}
		stats.AddBytes(int64(len(initialData)), 0)
	}

	logDebug("[SERVER-MUX] Stream %d -> %s", st.id, targetStr)

	go func() {
		for {
			select {
			case <-st.closed:
				return
			case frame, ok := <-st.writeChan:
				if !ok || frame.data == nil {
					if tc, ok := targetConn.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					return
				}
				data := frame.data
				_, err := targetConn.Write(data)
				st.consumedBytes(len(data))
				frame.release()
				if err != nil {
					st.Close()
					return
				}
				stats.AddBytes(int64(len(data)), 0)
			}
		}
	}()

	bPtr := s.cfg.BufPool.Get().(*[]byte)
	defer s.cfg.BufPool.Put(bPtr)
	buf := *bPtr
	readBuf := buf
	if len(readBuf) > 65535 {
		readBuf = readBuf[:65535]
	}
	for {
		nr, errRead := targetConn.Read(readBuf)
		if nr > 0 {
			if errWrite := s.SendFrame(st.id, MuxCmdDATA, readBuf[:nr]); errWrite != nil {
				return
			}
			stats.AddBytes(0, int64(nr))
		}
		if errRead != nil {
			if errRead == io.EOF {
				s.SendFrame(st.id, MuxCmdFIN, nil)
			} else {
				s.SendFrame(st.id, MuxCmdRST, nil)
			}
			return
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

	if strings.EqualFold(targetStr, "UDP") || strings.HasPrefix(strings.ToUpper(targetStr), "UDP") {
		handleServerUDP(wsConn, br, wsTCPConn, cfg)
		return
	}
	if strings.EqualFold(targetStr, "MUX") || strings.HasPrefix(strings.ToUpper(targetStr), "MUX") {
		handleServerMux(wsConn, br, wsTCPConn, cfg)
		return
	}

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

func handleServerUDP(wsConn net.Conn, br *bufio.Reader, wsTCPConn *net.TCPConn, cfg *Config) {
	logInfo("[SERVER] UDP Tunnel requested")
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
		for {
			if deadlineThrottle(&lastDeadline) {
				setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
			}
			data, errRead := readWSFrameInto(br, wsConn, buf[14:])
			if errRead != nil {
				err = errRead
				return
			}
			if cfg.Crypto != nil {
				cfg.Crypto.TransformInPlace(data)
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

			targetIP := host
			if cfg.Resolver != nil {
				if resolvedIP, rErr := cfg.Resolver.Resolve(host); rErr == nil {
					targetIP = resolvedIP
				}
			}
			raddr, rErr := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, strconv.Itoa(port)))
			if rErr != nil {
				logDebug("[SERVER-UDP] ResolveUDPAddr %s:%d failed: %v", targetIP, port, rErr)
				continue
			}

			if _, errWrite := udpConn.WriteToUDP(payload, raddr); errWrite != nil {
				logDebug("[SERVER-UDP] WriteToUDP failed: %v", errWrite)
			} else {
				stats.AddBytes(int64(len(payload)), 0)
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
				if totalLen > len(rawBuf)-14 {
					continue
				}
				copy(frameData[hdrLen:], pkt)

				if cfg.Crypto != nil {
					cfg.Crypto.TransformInPlace(frameData[:totalLen])
				}

				if errWrite := writeWSFramePreallocated(wsConn, rawBuf, 14, totalLen, 0x2, false); errWrite != nil {
					err = errWrite
					return
				}
				stats.AddBytes(0, int64(n))
			}
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
	if cfg.Crypto != nil {
		cfg.Crypto.TransformInPlace(targetPayload)
	}
	if err := writeWSFrame(wsConn, targetPayload, 0x2, true); err != nil {
		return
	}

	setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
	okFrame, err := readWSFrame(br, wsConn)
	if err != nil {
		logError("[UDP] Read OK failed: %v", err)
		return
	}
	if cfg.Crypto != nil {
		cfg.Crypto.TransformInPlace(okFrame)
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
				if cfg.Crypto != nil {
					cfg.Crypto.TransformInPlace(buf[14 : 14+n])
				}
				if errWrite := writeWSFramePreallocatedFast(wsConn, buf, 14, n, 0x2, prng); errWrite != nil {
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
		for {
			if deadlineThrottle(&lastDeadline) {
				setTCPReadDeadline(wsTCPConn, cfg.ConnTimeout)
			}
			data, errRead := readWSFrameInto(br, wsConn, buf[14:])
			if errRead != nil {
				err = errRead
				return
			}
			if cfg.Crypto != nil {
				cfg.Crypto.TransformInPlace(data)
			}
			cAddr := clientUDPAddr.Load()
			if cAddr != nil {
				if _, errWrite := udpListener.WriteToUDP(data, cAddr); errWrite != nil {
					logDebug("[CLIENT-UDP] WriteToUDP failed: %v", errWrite)
				} else {
					stats.AddBytes(0, int64(len(data)))
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

		if cmd == 0x03 {
			// SOCKS5 UDP ASSOCIATE: strictly check all read errors to avoid processing truncated requests
			if atyp == 0x01 {
				var ipBuf [4]byte
				if _, err := io.ReadFull(localConn, ipBuf[:]); err != nil {
					return
				}
			} else if atyp == 0x03 {
				var lenBuf [1]byte
				if _, err := io.ReadFull(localConn, lenBuf[:]); err != nil {
					return
				}
				domainBuf := make([]byte, int(lenBuf[0]))
				if _, err := io.ReadFull(localConn, domainBuf); err != nil {
					return
				}
			} else if atyp == 0x04 {
				var ipBuf [16]byte
				if _, err := io.ReadFull(localConn, ipBuf[:]); err != nil {
					return
				}
			} else {
				return
			}
			var portBuf [2]byte
			if _, err := io.ReadFull(localConn, portBuf[:]); err != nil {
				return
			}

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
		// HTTP Proxy: read full request header handling TCP fragmentation
		restPtr := cfg.HeaderBufPool.Get().(*[]byte)
		restBuf := *restPtr
		restBuf[0] = buf[0]
		totalRead := 1

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

			if errWrite := writeWSFramePreallocatedFast(wsConn, buf, 14, nr, 0x2, prng); errWrite != nil {
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

// ==================== QUIC TRANSPORT SUBSYSTEM ====================

// generateSelfSignedCert generates an in-memory ECDSA P-256 TLS 1.3 certificate for QUIC server.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
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
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
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
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		MaxIncomingStreams:             512,
		MaxIncomingUniStreams:          128,
		InitialStreamReceiveWindow:     2 * 1024 * 1024,
		MaxStreamReceiveWindow:         8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 4 * 1024 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024 * 1024,
		EnableDatagrams:                false,
	}
}

// --- QUIC Server ---

func startQUICServer(listenAddr string, cfg *Config, shutdown <-chan struct{}) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		logError("[QUIC-SERVER] Failed to generate self-signed cert: %v", err)
		return
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"goway-quic", "h3"},
	}

	listener, err := quic.ListenAddr(listenAddr, tlsConf, defaultQUICConfig())
	if err != nil {
		logError("[QUIC-SERVER] Failed to bind UDP %s: %v", listenAddr, err)
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

func handleQUICStream(stream quic.Stream, cfg *Config) {
	defer stream.Close()

	br := bufio.NewReader(stream)
	targetLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	targetStr := strings.TrimSpace(targetLine)

	// Authentication check if key is set
	if cfg.Key != "" {
		parts := strings.SplitN(targetStr, " ", 2)
		if len(parts) != 2 || parts[0] != cfg.Key {
			logWarn("[QUIC-SERVER] Auth rejected for stream from %v", stream.StreamID())
			stream.Write([]byte("ERR: AUTH_FAILED\n"))
			return
		}
		targetStr = parts[1]
	}

	if strings.EqualFold(targetStr, "UDP") || strings.HasPrefix(strings.ToUpper(targetStr), "UDP") {
		handleQUICServerUDP(stream, br, cfg)
		return
	}

	// Remote DNS resolution for target address
	targetAddr := targetStr
	if cfg.Resolver != nil {
		host, port, splitErr := net.SplitHostPort(targetStr)
		if splitErr == nil {
			if resolvedIP, resolveErr := cfg.Resolver.Resolve(host); resolveErr == nil {
				targetAddr = net.JoinHostPort(resolvedIP, port)
			}
		}
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

	// Stream -> Target
	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		for {
			nr, errRead := br.Read(buf)
			if nr > 0 {
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
		for {
			nr, errRead := targetConn.Read(buf)
			if nr > 0 {
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
		for {
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

			targetIP := host
			if cfg.Resolver != nil {
				if resolvedIP, rErr := cfg.Resolver.Resolve(host); rErr == nil {
					targetIP = resolvedIP
				}
			}
			raddr, rErr := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, fmt.Sprintf("%d", port)))
			if rErr != nil {
				continue
			}
			udpConn.WriteToUDP(payload, raddr)
			stats.AddBytes(int64(len(payload)), 0)
		}
	}()

	// UDP -> Stream
	go func() {
		rawBuf := make([]byte, 65535)
		var lenBuf [2]byte
		batch := newUDPBatch(udpConn)
		for {
			count, errRead := batch.read()
			if errRead != nil {
				errCh <- errRead
				return
			}
			for i := 0; i < count; i++ {
				n := batch.msgs[i].N
				raddr := batch.msgs[i].Addr.(*net.UDPAddr)
				copy(rawBuf[10:], batch.msgs[i].Buffers[0][:n])
				rawBuf[0] = 0
				rawBuf[1] = 0
				rawBuf[2] = 0
				var hdrLen int
				ip4 := raddr.IP.To4()
				if ip4 != nil {
					rawBuf[3] = 0x01
					copy(rawBuf[4:8], ip4)
					binary.BigEndian.PutUint16(rawBuf[8:10], uint16(raddr.Port))
					hdrLen = 10
				} else {
					copy(rawBuf[22:22+n], rawBuf[10:10+n])
					rawBuf[3] = 0x04
					copy(rawBuf[4:20], raddr.IP.To16())
					binary.BigEndian.PutUint16(rawBuf[20:22], uint16(raddr.Port))
					hdrLen = 22
				}
				totalLen := hdrLen + n
				binary.BigEndian.PutUint16(lenBuf[:], uint16(totalLen))
				if _, errWrite := stream.Write(lenBuf[:]); errWrite != nil {
					errCh <- errWrite
					return
				}
				if _, errWrite := stream.Write(rawBuf[:totalLen]); errWrite != nil {
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
	conn     quic.Connection
	mu       sync.Mutex
	dialAddr string
	tlsConf  *tls.Config
	dialing  chan struct{}
	closed   bool
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

	return &QUICClientPool{
		cfg:      cfg,
		dialAddr: dialAddr,
		tlsConf:  tlsConf,
	}, nil
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

		// 1. If an active connection exists, attempt to open a stream outside the lock.
		if p.conn != nil {
			conn := p.conn
			p.mu.Unlock()

			stream, err := conn.OpenStreamSync(ctx)
			if err == nil {
				return stream, nil
			}

			// OpenStreamSync failed on existing connection: close to avoid leak and clear pool reference
			_ = conn.CloseWithError(0x01, "stream open failed")
			p.mu.Lock()
			if p.conn == conn {
				p.conn = nil
			}
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
			if p.conn == newConn {
				p.conn = nil
			}
		} else if !p.closed {
			p.conn = newConn
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

	// 1. DNS Resolve outside lock
	dialHost, dialPort, _ := net.SplitHostPort(p.dialAddr)
	if p.cfg.Resolver != nil {
		if resolvedIP, rErr := p.cfg.Resolver.Resolve(dialHost); rErr == nil {
			dialHost = resolvedIP
		}
	}
	actualAddr := net.JoinHostPort(dialHost, dialPort)

	// 2. DialAddr outside lock
	newConn, dialErr = quic.DialAddr(ctx, actualAddr, p.tlsConf, defaultQUICConfig())
	if dialErr != nil {
		return nil, dialErr
	}

	// 3. OpenStreamSync on the newly established connection outside lock
	stream, dialErr = newConn.OpenStreamSync(ctx)
	if dialErr != nil {
		return nil, dialErr
	}

	return stream, nil
}

func (p *QUICClientPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.conn != nil {
		p.conn.CloseWithError(0, "client closed")
		p.conn = nil
	}
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

	go func() {
		bPtr := cfg.BufPool.Get().(*[]byte)
		defer cfg.BufPool.Put(bPtr)
		buf := *bPtr
		for {
			nr, errRead := localConn.Read(buf)
			if nr > 0 {
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
		for {
			nr, errRead := br.Read(buf)
			if nr > 0 {
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
		var lenBuf [2]byte
		batch := newUDPBatch(udpListener)
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
				copy(buf, pkt)
				binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
				if _, errWrite := stream.Write(lenBuf[:]); errWrite != nil {
					errCh <- errWrite
					return
				}
				if _, errWrite := stream.Write(buf[:n]); errWrite != nil {
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
		for {
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
				if _, errWrite := udpListener.WriteToUDP(rawBuf[:pLen], cAddr); errWrite != nil {
					logDebug("[CLIENT-QUIC-UDP] WriteToUDP failed: %v", errWrite)
				} else {
					stats.AddBytes(0, int64(pLen))
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
