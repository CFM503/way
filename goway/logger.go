// goway – logger
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

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
	// logLastFlush backs the throttled flush in addLogFileEntry; guarded
	// by logRingMu.
	logLastFlush time.Time
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
			if stdoutIsTTY {
				fmt.Print("\r\033[K")
			}
			log.Printf(AnsiCyan+"[DEBUG] "+format+AnsiReset, v...)
		}
	}
}

func logInfo(format string, v ...interface{}) {
	if globalLogLevel <= INFO {
		if tuiEnabled {
			addTuiLog(time.Now().Format("15:04:05") + " " + AnsiGreen + "[INFO] " + fmt.Sprintf(format, v...) + AnsiReset)
		} else {
			if stdoutIsTTY {
				fmt.Print("\r\033[K")
			}
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
			if stdoutIsTTY {
				fmt.Print("\r\033[K")
			}
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
			if stdoutIsTTY {
				fmt.Print("\r\033[K")
			}
			log.Printf(AnsiRed+"[ERROR] "+format+AnsiReset, v...)
		}
		addLogFileEntry("[ERROR] " + msg)
	}
}

// logRingFlushInterval throttles on-disk flushes of the log ring: every
// WARN/ERROR used to rewrite the file SYNCHRONOUSLY under logRingMu, so an
// error storm (e.g. ingress-queue-full spam on relay hot paths) converted
// log volume into disk latency on every relay goroutine. The ring is still
// updated for every entry; the file lags at most one interval behind and is
// always finalized by saveLogFile on exit.
const logRingFlushInterval = 2 * time.Second

func addLogFileEntry(entry string) {
	logRingMu.Lock()
	if logFilePath == "" {
		logRingMu.Unlock()
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	logRingBuf[logRingPos] = ts + " " + entry
	logRingPos = (logRingPos + 1) % len(logRingBuf)
	if logRingLen < len(logRingBuf) {
		logRingLen++
	}
	due := time.Since(logLastFlush) >= logRingFlushInterval
	var content string
	if due {
		logLastFlush = time.Now()
		var lines []string
		start := (logRingPos - logRingLen + len(logRingBuf)) % len(logRingBuf)
		for i := 0; i < logRingLen; i++ {
			lines = append(lines, logRingBuf[(start+i)%len(logRingBuf)])
		}
		content = strings.Join(lines, "\n") + "\n"
	}
	logRingMu.Unlock()
	if due {
		_ = os.WriteFile(logFilePath, []byte(content), 0644)
	}
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
