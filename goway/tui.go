// goway – tui
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- TUI / GUI-Style CLI Implementation ---

var (
	tuiEnabled bool
	tuiLogMu   sync.Mutex

	// Ring buffer for TUI logs — avoids O(n) slice-copy every 100 entries.
	tuiRingBuf [100]string
	tuiRingLen int // number of valid entries (≤ 100)
	tuiRingPos int // index of next write slot

	tuiRefreshCh = make(chan struct{}, 1)

	// stdoutIsTTY gates terminal control sequences (line-clear etc.): they
	// clean up live dashboards on a console but pollute piped/file logs.
	// Pure stdlib (ModeCharDevice), computed once — no extra dependency.
	stdoutIsTTY = func() bool {
		fi, err := os.Stdout.Stat()
		return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
	}()
)

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
