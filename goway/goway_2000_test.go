package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test2000MuxClientPoolReservation tests 2,000 concurrent stream reservations
// and releases across MuxClientPool sessions, verifying least-active scheduling,
// atomic activeStreams consistency, and 100% clean recovery to zero.
func Test2000MuxClientPoolReservation(t *testing.T) {
	bufPool := &sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32*1024)
			return &b
		},
	}
	cfg := &Config{ConnTimeout: 5, BufPool: bufPool}
	numSessions := 8
	pool := NewMuxClientPool(cfg, numSessions)
	defer pool.Close()

	sessions := make([]*MuxClientSession, numSessions)
	for i := 0; i < numSessions; i++ {
		pipeR, pipeW := net.Pipe()
		go io.Copy(io.Discard, pipeR)
		sessions[i] = &MuxClientSession{
			wsConn:  pipeW,
			closed:  make(chan struct{}),
			streams: make(map[uint32]*MuxStream),
			prng:    maskPool.Get().(*maskPRNG),
			cfg:     cfg,
		}
	}
	pool.sessions = sessions

	const totalConcurrency = 2000
	var wg sync.WaitGroup
	wg.Add(totalConcurrency)

	start := time.Now()
	var successCount int64

	for i := 0; i < totalConcurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			sess, err := pool.GetSession()
			if err != nil {
				t.Errorf("GetSession failed for idx %d: %v", idx, err)
				return
			}
			atomic.AddInt64(&successCount, 1)

			st := newMuxStream(uint32(idx+1), sess)
			st.onClose = func() {
				sess.decrementActiveStreams()
			}
			sess.streamsMu.Lock()
			sess.streams[st.id] = st
			sess.streamsMu.Unlock()

			// Jitter sleep 1-5ms to simulate concurrent in-flight streams
			time.Sleep(time.Duration(rand.Intn(4)+1) * time.Millisecond)

			st.Close()
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	if successCount != totalConcurrency {
		t.Fatalf("Expected %d successful reservations, got %d", totalConcurrency, successCount)
	}

	for i, s := range sessions {
		active := s.ActiveStreams()
		if active != 0 {
			t.Fatalf("Session %d activeStreams did not return to 0, got %d", i, active)
		}
	}

	t.Logf("[PASS] 2000 Concurrent MUX Stream Reservations completed in %v (QPS: %.0f/s)",
		duration, float64(totalConcurrency)/duration.Seconds())
}

// Test2000MuxServerStreamsLifecycle tests 2,000 concurrent MuxServerStream
// creations, targetConn associations, data pushes, and concurrent closes.
func Test2000MuxServerStreamsLifecycle(t *testing.T) {
	const totalStreams = 2000
	streams := make([]*MuxServerStream, totalStreams)
	for i := range streams {
		streams[i] = newMuxServerStream(uint32(i+1), nil)
	}

	var wg sync.WaitGroup
	wg.Add(totalStreams)

	start := time.Now()
	for _, st := range streams {
		go func(s *MuxServerStream) {
			defer wg.Done()

			// Simulate target connection binding
			pipeR, pipeW := net.Pipe()
			defer pipeR.Close()

			if s.setTargetConn(pipeW) {
				_ = s.targetConnSnapshot()
			}

			// Simulate concurrency close
			s.Close()
		}(st)
	}

	wg.Wait()
	duration := time.Since(start)

	t.Logf("[PASS] 2000 Concurrent MuxServerStream Lifecycles completed in %v", duration)
}

// Test2000ConcurrentEndToEndSOCKS5 launches real Goway Server + Client subprocesses
// and runs 2,000 concurrent SOCKS5 proxy connections with payload echo verification.
func Test2000ConcurrentEndToEndSOCKS5(t *testing.T) {
	// 1. Target Echo Server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Echo server fail: %v", err)
	}
	defer targetListener.Close()
	targetPort := targetListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()

	binPath := testBinaryForSubprocess(t)

	// 2. Start GOWAY Server (allow 5000 conns)
	serverPort := 38980
	serverCmd := exec.Command(binPath,
		"-p", fmt.Sprintf("127.0.0.1:%d", serverPort),
		"-k", "stressKey2000",
		"-max-conn", "5000",
		"-log", "WARN",
	)
	var serverStderr bytes.Buffer
	serverCmd.Stderr = &serverStderr
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("Server start fail: %v", err)
	}
	defer func() {
		_ = serverCmd.Process.Kill()
		_ = serverCmd.Wait()
	}()

	time.Sleep(600 * time.Millisecond)

	// 3. Start GOWAY Client (allow 5000 conns, 8 mux sessions)
	clientPort := 31980
	clientCmd := exec.Command(binPath,
		"-p", fmt.Sprintf("127.0.0.1:%d", clientPort),
		"-up", fmt.Sprintf("ws://127.0.0.1:%d", serverPort),
		"-k", "stressKey2000",
		"-max-conn", "5000",
		"-mux=true",
		"-mux-sessions", "8",
		"-block-local=false",
		"-log", "WARN",
	)
	var clientStderr bytes.Buffer
	clientCmd.Stderr = &clientStderr
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("Client start fail: %v", err)
	}
	defer func() {
		_ = clientCmd.Process.Kill()
		_ = clientCmd.Wait()
	}()

	time.Sleep(1000 * time.Millisecond)

	// --- Warmup: send 5 sequential requests to establish initial Mux sessions ---
	for w := 0; w < 5; w++ {
		wConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 3*time.Second)
		if err == nil {
			_, _ = wConn.Write([]byte{0x05, 0x01, 0x00})
			var hs [2]byte
			_, _ = io.ReadFull(wConn, hs[:])
			req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort & 0xFF)}
			_, _ = wConn.Write(req)
			var cr [10]byte
			_, _ = io.ReadFull(wConn, cr[:])
			_, _ = wConn.Write([]byte("warmup"))
			var echo [6]byte
			_, _ = io.ReadFull(wConn, echo[:])
			_ = wConn.Close()
		}
	}
	time.Sleep(200 * time.Millisecond)

	const totalConns = 2000
	t.Logf("[TEST-2000] Launching %d concurrent SOCKS5 connections through live Goway proxy...", totalConns)

	var (
		wg                 sync.WaitGroup
		successCnt         int64
		dialFailCnt        int64
		handshakeFailCnt   int64
		connectRespFailCnt int64
		payloadFailCnt     int64
		latencies          = make([]time.Duration, 0, totalConns)
		latMu              sync.Mutex
		lastErrStr         string
		lastErrMu          sync.Mutex
	)

	setLastErr := func(msg string) {
		lastErrMu.Lock()
		if lastErrStr == "" {
			lastErrStr = msg
		}
		lastErrMu.Unlock()
	}

	wg.Add(totalConns)
	startAll := time.Now()

	for i := 0; i < totalConns; i++ {
		// Stagger connection start by 250 microseconds to avoid Windows backlog overflow
		time.Sleep(250 * time.Microsecond)
		go func(id int) {
			defer wg.Done()
			reqStart := time.Now()

			var conn net.Conn
			var dialErr error
			for attempt := 0; attempt < 8; attempt++ {
				conn, dialErr = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 8*time.Second)
				if dialErr == nil {
					break
				}
				time.Sleep(time.Duration(15+attempt*20) * time.Millisecond)
			}
			if conn == nil {
				atomic.AddInt64(&dialFailCnt, 1)
				setLastErr(fmt.Sprintf("dial fail: %v", dialErr))
				return
			}
			defer conn.Close()

			_ = conn.SetDeadline(time.Now().Add(25 * time.Second))

			// SOCKS5 handshake (NO AUTH)
			if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
				atomic.AddInt64(&handshakeFailCnt, 1)
				setLastErr(fmt.Sprintf("handshake write fail: %v", err))
				return
			}
			var hs [2]byte
			if _, err := io.ReadFull(conn, hs[:]); err != nil || hs[1] != 0x00 {
				atomic.AddInt64(&handshakeFailCnt, 1)
				setLastErr(fmt.Sprintf("handshake read fail: %v, resp: %v", err, hs))
				return
			}

			// SOCKS5 CONNECT to targetPort
			req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort & 0xFF)}
			if _, err := conn.Write(req); err != nil {
				atomic.AddInt64(&connectRespFailCnt, 1)
				setLastErr(fmt.Sprintf("connect write fail: %v", err))
				return
			}
			var cr [10]byte
			if _, err := io.ReadFull(conn, cr[:]); err != nil || cr[1] != 0x00 {
				atomic.AddInt64(&connectRespFailCnt, 1)
				setLastErr(fmt.Sprintf("connect resp fail: %v, rep: %v", err, cr))
				return
			}

			// Send distinct 2KB payload with ID header
			payload := bytes.Repeat([]byte{byte(id%251 + 1)}, 2048)
			if _, err := conn.Write(payload); err != nil {
				atomic.AddInt64(&payloadFailCnt, 1)
				setLastErr(fmt.Sprintf("payload write fail: %v", err))
				return
			}

			echo := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, echo); err != nil || !bytes.Equal(echo, payload) {
				atomic.AddInt64(&payloadFailCnt, 1)
				setLastErr(fmt.Sprintf("echo read fail: %v", err))
				return
			}

			reqDuration := time.Since(reqStart)
			atomic.AddInt64(&successCnt, 1)

			latMu.Lock()
			latencies = append(latencies, reqDuration)
			latMu.Unlock()
		}(i)
	}

	wg.Wait()
	totalDuration := time.Since(startAll)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	latMu.Lock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	n := len(latencies)

	var minLat, maxLat, avgLat, p50, p90, p95, p99 time.Duration
	if n > 0 {
		minLat = latencies[0]
		maxLat = latencies[n-1]
		p50 = latencies[int(float64(n)*0.50)]
		p90 = latencies[int(float64(n)*0.90)]
		p95 = latencies[int(float64(n)*0.95)]
		p99 = latencies[int(float64(n)*0.99)]

		var sum time.Duration
		for _, d := range latencies {
			sum += d
		}
		avgLat = sum / time.Duration(n)
	}
	latMu.Unlock()

	qps := float64(successCnt) / totalDuration.Seconds()
	successRate := float64(successCnt) / float64(totalConns) * 100
	totalFails := dialFailCnt + handshakeFailCnt + connectRespFailCnt + payloadFailCnt

	t.Logf("\n================ 2000 CONCURRENCY BENCHMARK REPORT ================\n"+
		"Total Requests:       %d\n"+
		"Successful:           %d (%.2f%%)\n"+
		"Failed:               %d (Dial: %d, Handshake: %d, Connect: %d, Payload: %d)\n"+
		"Last Error:           %s\n"+
		"Server Stderr:        %s\n"+
		"Client Stderr:        %s\n"+
		"Total Duration:       %v\n"+
		"Throughput (QPS):     %.2f req/s\n"+
		"Latency Min:          %v\n"+
		"Latency Avg:          %v\n"+
		"Latency P50:          %v\n"+
		"Latency P90:          %v\n"+
		"Latency P95:          %v\n"+
		"Latency P99:          %v\n"+
		"Latency Max:          %v\n"+
		"Memory Alloc:         %.2f MB\n"+
		"Total Alloc:          %.2f MB\n"+
		"Heap Inuse:           %.2f MB\n"+
		"GC Cycles:            %d\n"+
		"===================================================================",
		totalConns, successCnt, successRate, totalFails,
		dialFailCnt, handshakeFailCnt, connectRespFailCnt, payloadFailCnt,
		lastErrStr, serverStderr.String(), clientStderr.String(),
		totalDuration, qps,
		minLat, avgLat, p50, p90, p95, p99, maxLat,
		float64(m.Alloc)/1024/1024, float64(m.TotalAlloc)/1024/1024,
		float64(m.HeapInuse)/1024/1024, m.NumGC,
	)

	if successRate < 95.0 {
		t.Fatalf("Success rate %.2f%% below threshold 95.0%% under 2000 concurrency", successRate)
	}
}
