// goway – goway
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math"
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
)

// GOWAY standing engineering rule (user mandate, 2026-09-23, permanent):
// every change to this codebase must be a FORWARD optimization; reverse
// (regressive) changes are NEVER allowed. Before completing any
// performance-relevant change, measure same-machine medians against the
// released baseline v1.8.11 on the shared benchmark harness (throughput
// c1/c8/c32, CPU, RSS; n>=5, setup+steady) with no metric regressed beyond
// noise, and record before/after numbers in goway/AI_HANDOFF.md — no
// numbers, no completion. Every AI taking over this project must read
// goway/AI_HANDOFF.md first and preserve this rule verbatim. If the bar is
// not met: tune it, gate it behind an opt-in flag whose default matches
// baseline behavior, or revert it.

const (
	Version = "1.8.16"
	// MaxWSFrameSize matches the largest frame the sender side can build
	// (BufPool caps at 12MB + MUX header + AEAD overhead) — the old 64MB
	// ceiling was pure memory-flood attack surface: a claimed-but-unsent
	// frame length heap-allocates on receipt before any bytes arrive.
	MaxWSFrameSize = 12*1024*1024 + 64
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

// --- Config ---

type Config struct {
	ProxyHost        string
	ProxyPort        int
	Upstream         string
	FakeHost         string
	Key              string
	BufferSize       int
	NoTcpNoDelay     bool
	NoTcpKeepAlive   bool
	SocketBuffer     int
	ConnTimeout      int
	VerifySSL        bool
	VerifyQUIC       bool
	MaxConns         int
	BlockLocal       bool
	AllowOpen        bool
	TUI              bool
	Mux              bool
	MuxSessions      int
	Obfs             bool
	QUICConns        int
	ServerBlockLocal bool
	Cipher           string

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

// --- Main Logic ---

func main() {
	defer saveLogFile()

	pFlag := flag.String("p", "", "Listen Address (e.g. :8080 or 0.0.0.0:8080) [Required]")
	upFlag := flag.String("up", "", "Upstream WebSocket/QUIC URL (e.g. ws://host:port, wss://host:port, quic://host:port). Omit for Server mode")
	kFlag := flag.String("k", "", "Authentication and XOR encryption key")
	fakeHostFlag := flag.String("fakehost", "", "Spoofing Hostname / SNI for Cloudflare CDN or reverse proxies")
	muxFlag := flag.Bool("mux", true, "Enable 0-RTT Connection Multiplexing (default true)")
	noMuxFlag := flag.Bool("no-mux", false, "Disable 0-RTT Connection Multiplexing (fallback to 1:1 pool)")
	muxSessionsFlag := flag.Int("mux-sessions", 8, "Number of parallel physical Mux sessions (default 8, max 64)")
	obfsFlag := flag.Bool("obfs", false, "Pad MUX DATA frames with random lengths to resist packet-size fingerprinting")
	wFlag := flag.Int("W", 128, "App Buffer Size in KB (default 128KB, recommend 256-1024 for high-throughput streaming)")
	sockBufFlag := flag.Int("socket-buffer", 0, "Kernel Socket Buffer in KB (default 0 = OS auto-tuning)")
	noDelayFlag := flag.Bool("no-tcp-nodelay", false, "Disable TCP_NODELAY (disable Nagle bypass)")
	keepAliveFlag := flag.Bool("no-tcp-keepalive", false, "Disable TCP KeepAlive probes")
	dnsFlag := flag.String("dns", "", "Remote DNS server IP for target host resolution (e.g. 8.8.8.8)")
	blockLocalFlag := flag.Bool("block-local", true, "Drop local/LAN loopback traffic in Client mode (default true)")
	noBlockLocalFlag := flag.Bool("no-block-local", false, "Allow local/LAN loopback traffic in Client mode")
	verifySSLFlag := flag.Bool("verify-ssl", false, "Enable strict SSL certificate verification for wss:// upstream")
	verifyQUICFlag := flag.Bool("verify-quic", false, "Verify the QUIC server certificate against the key-derived pinned cert (both ends this version+, same -k)")
	quicConnsFlag := flag.Int("quic-conns", 1, "Number of parallel QUIC connections (default 1, max 16)")
	serverBlockLocalFlag := flag.Bool("server-block-local", false, "Server mode: reject target hosts on local/LAN addresses (default false)")
	cipherFlag := flag.String("cipher", "", "Application-layer cipher mode: \"aead\" = AES-256-GCM per frame (BOTH ends must match; default \"\" = legacy XOR stream)")
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
		fmt.Fprintf(os.Stderr, "        Number of parallel physical Mux sessions (default 8, max 64)\n")
		fmt.Fprintf(os.Stderr, "  -W int\n")
		fmt.Fprintf(os.Stderr, "        App Buffer Size in KB (default 128, recommend 512-1024 for 4K streaming)\n")
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
		fmt.Fprintf(os.Stderr, "  -verify-quic\n")
		fmt.Fprintf(os.Stderr, "        Verify the QUIC server certificate against the key-derived pinned cert\n")
		fmt.Fprintf(os.Stderr, "  -quic-conns int\n")
		fmt.Fprintf(os.Stderr, "        Number of parallel QUIC connections (default 1, max 16)\n")
		fmt.Fprintf(os.Stderr, "  -server-block-local\n")
		fmt.Fprintf(os.Stderr, "        Server mode: reject target hosts on local/LAN addresses (default false)\n")
		fmt.Fprintf(os.Stderr, "  -cipher string\n")
		fmt.Fprintf(os.Stderr, "        Application-layer cipher mode: \"aead\" = AES-256-GCM per frame\n")
		fmt.Fprintf(os.Stderr, "        (BOTH ends must match; default \"\" = legacy XOR stream)\n")
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

	// Microsecond timestamps: phase-timing DEBUG logs (e.g. mux session
	// setup) are the primary forensic tool for this codebase.
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
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
	if *quicConnsFlag < 1 || *quicConnsFlag > 16 {
		fmt.Printf("Error: -quic-conns must be between 1 and 16, got %d\n", *quicConnsFlag)
		os.Exit(1)
	}
	if *cipherFlag != "" && *cipherFlag != "aead" {
		fmt.Printf("Error: -cipher must be \"aead\" (or empty for the legacy XOR stream), got '%s'\n", *cipherFlag)
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
		Upstream:         *upFlag,
		FakeHost:         *fakeHostFlag,
		Key:              *kFlag,
		BufferSize:       *wFlag * 1024,
		NoTcpNoDelay:     *noDelayFlag,
		NoTcpKeepAlive:   *keepAliveFlag,
		SocketBuffer:     *sockBufFlag,
		ConnTimeout:      *connTimeoutFlag,
		VerifySSL:        *verifySSLFlag,
		VerifyQUIC:       *verifyQUICFlag,
		MaxConns:         *maxConnFlag,
		BlockLocal:       *blockLocalFlag && !*noBlockLocalFlag,
		AllowOpen:        *allowOpenFlag,
		Mux:              *muxFlag && !*noMuxFlag,
		MuxSessions:      *muxSessionsFlag,
		Obfs:             *obfsFlag,
		QUICConns:        *quicConnsFlag,
		ServerBlockLocal: *serverBlockLocalFlag,
		Cipher:           strings.ToLower(strings.TrimSpace(*cipherFlag)),
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

	cipherMode := cipherModeXOR
	if cfg.Cipher == "aead" {
		cipherMode = cipherModeAEAD
	}
	cfg.Crypto = NewCryptoMode(cfg.Key, cipherMode)
	if cipherMode == cipherModeAEAD {
		muxDataChunkLimit = 65535 - aeadOverhead
	}

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
			if cfg.Cipher == "aead" {
				fmt.Printf(" [+] Auth:        %sEnabled (AES-256-GCM)%s\n", AnsiGreen, AnsiReset)
			} else {
				fmt.Printf(" [+] Auth:        %sEnabled (XOR)%s\n", AnsiGreen, AnsiReset)
			}
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
	if cipherMode == cipherModeAEAD {
		// tail room so an in-place [nonce|ct|tag] seal can expand the
		// relay/MUX region without a second buffer
		bufSize += aeadOverhead
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
				connPool = NewConnPool(&cfg, 16) // Pool of 16 pre-established connections for non-Mux mode
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
				break
			default:
			}
			if ne, ok := err.(net.Error); ok && (ne.Temporary() || ne.Timeout()) {
				logWarn("Accept temporary error: %v (retrying...)", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			select {
			case <-shutdown:
				break
			default:
				logError("Accept unrecoverable error: %v", err)
			}
			break
		}

		if !tryAcquireConn(int64(cfg.MaxConns)) {
			logWarn("MaxConns (%d) reached, rejecting connection", cfg.MaxConns)
			_ = conn.Close()
			continue
		}

		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					logError("Connection handler recovered from panic: %v", r)
				}
				releaseConn()
			}()
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
