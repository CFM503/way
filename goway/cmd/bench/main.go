// Command bench is a local A/B benchmark harness for goway.
//
// It starts an in-process full-duplex TCP target, launches a goway server
// and a goway client as subprocesses, opens N SOCKS5 streams, and measures
// steady-state upload/download throughput, process CPU, peak RSS and setup
// latency. Multiple binaries ("arms") are run interleaved per sample with
// the arm order flipped every sample, and results are summarized with
// paired deltas + an exact two-sided sign test (ties dropped, p <= 0.05).
//
// Usage:
//
//	go run ./cmd/bench -arms "old.exe,new.exe" -samples 10
//
// Output: CSV per row + a printed summary table. Numbers are meant to be
// pasted into AI_HANDOFF.md under the forward-only optimization rule.
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type metrics struct {
	upMBs   float64 // MB/s (1e6) upload, higher is better
	downMBs float64 // MB/s download, higher is better
	cpuSec  float64 // client+server CPU seconds over the measure window, lower better
	rssMB   float64 // peak working set of client+server during the run, lower better
	setupMS float64 // client start -> first successful SOCKS5 CONNECT, lower better
}

type row struct {
	arm         string
	sample      int
	order       int
	concurrency int
	metrics
	err string
}

func main() {
	var (
		armsCSV = flag.String("arms", "", "comma-separated binary paths; first = baseline, second = candidate")
		samples = flag.Int("samples", 10, "samples per arm (interleaved, order flipped every sample)")
		concCSV = flag.String("concurrency", "1,8,32", "comma-separated stream concurrency levels")
		warmup  = flag.Duration("warmup", 1500*time.Millisecond, "warmup before the measure window")
		measure = flag.Duration("measure", 6*time.Second, "measure window")
		out     = flag.String("out", "bench_out.csv", "CSV output path")
		mux     = flag.Bool("mux", true, "client -mux value")
		muxSess = flag.Int("mux-sessions", 4, "client -mux-sessions value")
		extra   = flag.String("extra", "", "extra args appended to both server and client")
		extraS  = flag.String("extra-server", "", "extra args appended to the server only (e.g. -cpuprofile,f.pprof)")
		extraC  = flag.String("extra-client", "", "extra args appended to the client only")
		upTempl = flag.String("upstream-template", "ws://127.0.0.1:%d", "client -up value; %d is the per-run server port (e.g. quic://127.0.0.1:%d)")
		timeout = flag.Duration("subrun-timeout", 90*time.Second, "hard timeout per sub-run")
		verbose = flag.Bool("v", false, "keep subprocess output (redirected to bench_<arm>_<n>.log)")
		hsTO    = flag.Duration("hs-timeout", 5*time.Second, "SOCKS connect timeout for streams after the first")
	)
	flag.Parse()

	arms := splitNonEmpty(*armsCSV)
	if len(arms) == 0 {
		fmt.Fprintln(os.Stderr, "bench: -arms is required (baseline,candidate)")
		flag.PrintDefaults()
		os.Exit(2)
	}
	for _, a := range arms {
		if _, err := os.Stat(a); err != nil {
			fmt.Fprintf(os.Stderr, "bench: arm binary %q: %v\n", a, err)
			os.Exit(2)
		}
	}
	var concs []int
	for _, s := range splitNonEmpty(*concCSV) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			fmt.Fprintf(os.Stderr, "bench: bad -concurrency %q\n", s)
			os.Exit(2)
		}
		concs = append(concs, n)
	}

	cfg := config{
		samples:          *samples,
		concurrencies:    concs,
		warmup:           *warmup,
		measure:          *measure,
		mux:              *mux,
		muxSessions:      *muxSess,
		extra:            splitNonEmpty(*extra),
		extraServer:      splitNonEmpty(*extraS),
		extraClient:      splitNonEmpty(*extraC),
		timeout:          *timeout,
		verbose:          *verbose,
		upstreamTemplate: *upTempl,
		hsTimeout:        *hsTO,
	}

	csvFile, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: create %s: %v\n", *out, err)
		os.Exit(2)
	}
	defer csvFile.Close()
	w := csv.NewWriter(csvFile)
	_ = w.Write([]string{"arm", "sample", "order", "concurrency",
		"up_mbps", "down_mbps", "cpu_s", "rss_mb", "setup_ms", "error"})
	defer w.Flush()

	var rows []row
	for sample := 1; sample <= cfg.samples; sample++ {
		order := make([]string, len(arms))
		copy(order, arms)
		if sample%2 == 0 {
			for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
				order[i], order[j] = order[j], order[i]
			}
		}
		for pos, arm := range order {
			for _, c := range cfg.concurrencies {
				r := runSubRun(arm, c, sample, pos+1, cfg)
				rows = append(rows, r)
				_ = w.Write([]string{
					r.arm, strconv.Itoa(r.sample), strconv.Itoa(r.order), strconv.Itoa(r.concurrency),
					fmt.Sprintf("%.2f", r.upMBs), fmt.Sprintf("%.2f", r.downMBs),
					fmt.Sprintf("%.3f", r.cpuSec), fmt.Sprintf("%.1f", r.rssMB),
					fmt.Sprintf("%.0f", r.setupMS), r.err,
				})
				w.Flush()
				if err := w.Error(); err != nil {
					fmt.Fprintf(os.Stderr, "bench: csv write: %v\n", err)
				}
				status := "ok"
				if r.err != "" {
					status = "ERR: " + r.err
				}
				fmt.Printf("[s%d pos%d] %s c=%d up=%.1f down=%.1f cpu=%.2f rss=%.0f setup=%.0fms %s\n",
					sample, pos+1, arm, c, r.upMBs, r.downMBs, r.cpuSec, r.rssMB, r.setupMS, status)
			}
		}
	}

	fmt.Println("\n=== paired summary (baseline = arms[0]) ===")
	summarize(rows, arms, concs)
}

type config struct {
	samples          int
	concurrencies    []int
	warmup           time.Duration
	measure          time.Duration
	mux              bool
	muxSessions      int
	extra            []string
	extraServer      []string
	extraClient      []string
	timeout          time.Duration
	verbose          bool
	upstreamTemplate string
	hsTimeout        time.Duration
}

// ---------------------------------------------------------------------------
// one sub-run: fresh target + fresh server + fresh client + C streams
// ---------------------------------------------------------------------------

func runSubRun(arm string, concurrency, sample, order int, cfg config) row {
	r := row{arm: arm, sample: sample, order: order, concurrency: concurrency}

	serverPort, err := freePort()
	if err != nil {
		r.err = "freePort: " + err.Error()
		return r
	}
	socksPort, err := freePort()
	if err != nil {
		r.err = "freePort: " + err.Error()
		return r
	}
	targetPort, err := freePort()
	if err != nil {
		r.err = "freePort: " + err.Error()
		return r
	}

	targetLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		r.err = "target listen: " + err.Error()
		return r
	}
	defer targetLn.Close()
	go serveTarget(targetLn)

	logS, logC := io.Writer(io.Discard), io.Writer(io.Discard)
	if cfg.verbose {
		logS = createLog(fmt.Sprintf("bench_%s_s%d_c%d_server.log", baseName(arm), sample, concurrency))
		logC = createLog(fmt.Sprintf("bench_%s_s%d_c%d_client.log", baseName(arm), sample, concurrency))
		defer func() {
			if c, ok := logS.(io.Closer); ok {
				_ = c.Close()
			}
			if c, ok := logC.(io.Closer); ok {
				_ = c.Close()
			}
		}()
	}

	serverArgs := []string{
		"-p", fmt.Sprintf("127.0.0.1:%d", serverPort),
		"-k", "benchKey2026",
		"-log", "ERROR",
	}
	serverArgs = append(serverArgs, cfg.extra...)
	serverArgs = append(serverArgs, cfg.extraServer...)
	serverCmd := exec.Command(arm, serverArgs...)
	serverCmd.Stdout, serverCmd.Stderr = logS, logS
	if err := serverCmd.Start(); err != nil {
		r.err = "start server: " + err.Error()
		return r
	}
	defer killProc(serverCmd)

	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", serverPort), 10*time.Second); err != nil {
		r.err = "server not listening: " + err.Error()
		return r
	}

	clientStart := time.Now()
	clientArgs := []string{
		"-p", fmt.Sprintf("127.0.0.1:%d", socksPort),
		"-up", fmt.Sprintf(cfg.upstreamTemplate, serverPort),
		"-k", "benchKey2026",
		"-block-local=false",
		"-log", "ERROR",
		"-mux=" + strconv.FormatBool(cfg.mux),
		"-mux-sessions", strconv.Itoa(cfg.muxSessions),
	}
	clientArgs = append(clientArgs, cfg.extra...)
	clientArgs = append(clientArgs, cfg.extraClient...)
	clientCmd := exec.Command(arm, clientArgs...)
	clientCmd.Stdout, clientCmd.Stderr = logC, logC
	if err := clientCmd.Start(); err != nil {
		r.err = "start client: " + err.Error()
		return r
	}
	defer killProc(clientCmd)

	// First full-path CONNECT = setup complete (tunnel + target reachable).
	var first net.Conn
	deadline := time.Now().Add(15 * time.Second)
	for {
		if time.Now().After(deadline) {
			r.err = "setup timeout (no successful SOCKS5 CONNECT)"
			return r
		}
		c, err := socks5Connect(fmt.Sprintf("127.0.0.1:%d", socksPort), "127.0.0.1", targetPort, 2*time.Second)
		if err == nil {
			first = c
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	r.setupMS = float64(time.Since(clientStart).Microseconds()) / 1000.0

	conns := []net.Conn{first}
	for i := 1; i < concurrency; i++ {
		c, err := socks5Connect(fmt.Sprintf("127.0.0.1:%d", socksPort), "127.0.0.1", targetPort, cfg.hsTimeout)
		if err != nil {
			closeConns(conns)
			r.err = fmt.Sprintf("stream %d: %v", i, err)
			return r
		}
		conns = append(conns, c)
	}

	var upCtr, downCtr atomic.Uint64
	stop := make(chan struct{})
	var pumps sync.WaitGroup
	for _, c := range conns {
		pumps.Add(2)
		go func(cn net.Conn) { defer pumps.Done(); uploadLoop(cn, stop, &upCtr) }(c)
		go func(cn net.Conn) { defer pumps.Done(); downloadLoop(cn, stop, &downCtr) }(c)
	}

	time.Sleep(cfg.warmup)

	cpuBefore, errA := combinedCPU(serverCmd, clientCmd)
	up0, down0 := upCtr.Load(), downCtr.Load()
	t0 := time.Now()
	time.Sleep(cfg.measure)
	elapsed := time.Since(t0)
	up1, down1 := upCtr.Load(), downCtr.Load()
	cpuAfter, errB := combinedCPU(serverCmd, clientCmd)

	if !procsAlive(serverCmd, clientCmd) {
		r.err = "goway process exited during the run"
		return r
	}

	close(stop)
	closeConns(conns)
	waitTimeout(&pumps, 3*time.Second)

	if errA == nil && errB == nil {
		r.cpuSec = cpuAfter - cpuBefore
		if r.cpuSec < 0 {
			r.cpuSec = 0
		}
	}
	if rss, err := combinedPeakRSS(serverCmd, clientCmd); err == nil {
		r.rssMB = float64(rss) / (1024 * 1024)
	}
	secs := elapsed.Seconds()
	if secs > 0 {
		r.upMBs = float64(up1-up0) / 1e6 / secs
		r.downMBs = float64(down1-down0) / 1e6 / secs
	}
	return r
}

// ---------------------------------------------------------------------------
// load loops
// ---------------------------------------------------------------------------

func uploadLoop(conn net.Conn, stop <-chan struct{}, ctr *atomic.Uint64) {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := conn.Write(buf)
		if n > 0 {
			ctr.Add(uint64(n))
		}
		if err != nil {
			return
		}
	}
}

func downloadLoop(conn net.Conn, stop <-chan struct{}, ctr *atomic.Uint64) {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := conn.Read(buf)
		if n > 0 {
			ctr.Add(uint64(n))
		}
		if err != nil {
			return
		}
	}
}

// serveTarget accepts TCP connections and runs a discard-read plus a
// generate-write concurrently, giving every stream full-duplex traffic.
func serveTarget(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				buf := make([]byte, 64*1024)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
				}
			}()
			go func() {
				defer wg.Done()
				buf := make([]byte, 64*1024)
				for i := range buf {
					buf[i] = byte(i)
				}
				for {
					if _, err := conn.Write(buf); err != nil {
						return
					}
				}
			}()
			wg.Wait()
		}(c)
	}
}

// ---------------------------------------------------------------------------
// SOCKS5 client helpers
// ---------------------------------------------------------------------------

func socks5Connect(socksAddr, targetHost string, targetPort int, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, timeout)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (net.Conn, error) {
		_ = conn.Close()
		return nil, e
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	resp := make([]byte, 2)
	if _, err := readFull(conn, resp); err != nil {
		return fail(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fail(fmt.Errorf("socks5 greeting rejected: %v", resp))
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, net.ParseIP(targetHost).To4()...)
	req = append(req, byte(targetPort>>8), byte(targetPort&0xFF))
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}
	connResp := make([]byte, 10)
	if _, err := readFull(conn, connResp); err != nil {
		return fail(err)
	}
	if connResp[1] != 0x00 {
		return fail(fmt.Errorf("socks5 connect rejected: code %d", connResp[1]))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// ---------------------------------------------------------------------------
// process helpers
// ---------------------------------------------------------------------------

func killProc(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

// procsAlive reports whether every subprocess is still running. A dead
// process invalidates the whole sub-run (its traffic counters stop and its
// CPU/RSS samples become meaningless), so callers must mark the row as an
// error instead of recording zeros into the paired comparison.
func procsAlive(cmds ...*exec.Cmd) bool {
	for _, c := range cmds {
		if c.Process == nil || !procAlive(c.Process) {
			return false
		}
	}
	return true
}

func combinedCPU(cmds ...*exec.Cmd) (float64, error) {
	var total float64
	var firstErr error
	seen := map[int]bool{}
	for _, c := range cmds {
		if c.Process == nil || seen[c.Process.Pid] {
			continue
		}
		seen[c.Process.Pid] = true
		s, err := procStatOf(c.Process)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		total += s.cpuSec
	}
	return total, firstErr
}

func combinedPeakRSS(cmds ...*exec.Cmd) (uint64, error) {
	var total uint64
	var firstErr error
	seen := map[int]bool{}
	for _, c := range cmds {
		if c.Process == nil || seen[c.Process.Pid] {
			continue
		}
		seen[c.Process.Pid] = true
		s, err := procStatOf(c.Process)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		total += s.peakRSS
	}
	return total, firstErr
}

func waitTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout dialing %s", addr)
}

func closeConns(conns []net.Conn) {
	for _, c := range conns {
		_ = c.Close()
	}
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func createLog(name string) io.Writer {
	f, err := os.Create(name)
	if err != nil {
		return io.Discard
	}
	return f
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(p, ".exe")
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// summary: paired deltas + exact two-sided sign test
// ---------------------------------------------------------------------------

type metricDef struct {
	name         string
	extract      func(row) float64
	higherBetter bool
	// minRelDelta is the practical-significance gate: a sign-test
	// REGRESSED/IMPROVED verdict only counts when |median delta| also
	// exceeds this fraction of the baseline median. The machine noise on
	// this class of loopback bench is ±20%+, and with 15 metrics at
	// alpha=0.05 the sign test alone produces ~1 false positive per full
	// self-check run (measured: 1/15 on identical binaries).
	minRelDelta float64
}

var metricDefs = []metricDef{
	{"up_mbps", func(r row) float64 { return r.upMBs }, true, 0.03},
	{"down_mbps", func(r row) float64 { return r.downMBs }, true, 0.03},
	{"cpu_s", func(r row) float64 { return r.cpuSec }, false, 0.05},
	{"rss_mb", func(r row) float64 { return r.rssMB }, false, 0.05},
	{"setup_ms", func(r row) float64 { return r.setupMS }, false, 0.05},
}

func summarize(rows []row, arms []string, concs []int) {
	if len(arms) < 2 {
		fmt.Println("(single arm - no pair comparison)")
		return
	}
	base, cand := arms[0], arms[1]
	for _, c := range concs {
		fmt.Printf("\n-- concurrency %d --\n", c)
		for _, m := range metricDefs {
			pair := map[int][2]float64{}
			for _, r := range rows {
				if r.concurrency != c || r.err != "" {
					continue
				}
				v := m.extract(r)
				if v == 0 {
					continue // failed sub-run / no data
				}
				e := pair[r.sample]
				if r.arm == base {
					e[0] = v
				} else if r.arm == cand {
					e[1] = v
				}
				pair[r.sample] = e
			}
			var deltas []float64
			var baseVals, candVals []float64
			bad, good, ties := 0, 0, 0
			for _, e := range pair {
				if e[0] == 0 && e[1] == 0 {
					continue
				}
				if e[0] == 0 || e[1] == 0 {
					continue
				}
				baseVals = append(baseVals, e[0])
				candVals = append(candVals, e[1])
				d := e[1] - e[0]
				deltas = append(deltas, d)
				switch {
				case d == 0:
					ties++
				case m.higherBetter:
					if d > 0 {
						good++
					} else {
						bad++
					}
				default:
					if d < 0 {
						good++
					} else {
						bad++
					}
				}
			}
			n := bad + good
			if n == 0 {
				fmt.Printf("  %-11s  no paired data\n", m.name)
				continue
			}
			crit := signTestCrit(n)
			bMed, cMed, dMed := median(baseVals), median(candVals), median(deltas)
			rel := 0.0
			if bMed != 0 {
				rel = dMed / bMed
			}
			material := abs(rel) >= m.minRelDelta
			verdict := "NOISE"
			if bad >= crit && material {
				verdict = "REGRESSED"
				if n <= 10 {
					verdict += " (confirm at n=20, crit=15)"
				}
			} else if good >= crit && material {
				verdict = "IMPROVED"
			}
			fmt.Printf("  %-11s base_med=%9.2f cand_med=%9.2f  medΔ=%+9.2f (%+.1f%%)  bad/good/tie=%d/%d/%d  crit=%d  → %s\n",
				m.name, bMed, cMed, dMed, rel*100, bad, good, ties, crit, verdict)
		}
	}
}

// signTestCrit returns the smallest count of "bad" pairs for which the
// exact two-sided binomial sign test (p=0.5, ties dropped) reaches
// p <= 0.05, or n+1 if that is impossible at this n.
func signTestCrit(n int) int {
	if n <= 0 {
		return 1
	}
	for b := 1; b <= n; b++ {
		var tail float64
		prob := math.Ldexp(1, -n) // 2^-n
		for k := 0; k <= n; k++ {
			if k >= b {
				tail += prob
			}
			prob = prob * float64(n-k) / float64(k+1)
		}
		if 2*tail <= 0.05 {
			return b
		}
	}
	return n + 1
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}
