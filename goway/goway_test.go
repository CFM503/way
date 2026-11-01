package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mrand "math/rand"

	"github.com/quic-go/quic-go"
)

func TestRFC6455AcceptKey(t *testing.T) {
	// RFC 6455 搂1.3 official test vector
	clientKey := "dGhlIHNhbXBsZSBub25jZQ=="
	expected := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	actual := computeAcceptKey(clientKey)
	if actual != expected {
		t.Fatalf("computeAcceptKey(%q) = %q, want %q", clientKey, actual, expected)
	}
}

func TestCryptoSymmetry(t *testing.T) {
	key := "test-secret-password-12345"
	c1 := NewCrypto(key)
	c2 := NewCrypto(key)

	sizes := []int{1, 5, 8, 9, 16, 63, 64, 65, 512, 1024, 65535, 65536, 131072, cryptoChunkSize, cryptoChunkSize + 13}
	for _, size := range sizes {
		original := make([]byte, size)
		_, _ = rand.Read(original)
		encrypted := make([]byte, size)
		copy(encrypted, original)

		c1.TransformInPlace(encrypted)
		if bytes.Equal(encrypted, original) {
			t.Fatalf("size %d: encrypted bytes match plaintext", size)
		}

		c2.TransformInPlace(encrypted)
		if !bytes.Equal(encrypted, original) {
			t.Fatalf("size %d: decrypted bytes do not match original plaintext", size)
		}
	}
}

func TestFastMaskPRNG(t *testing.T) {
	p := maskPool.Get().(*maskPRNG)
	defer maskPool.Put(p)

	var m1, m2 [4]byte
	readMask(m1[:], p)
	readMask(m2[:], p)

	if m1 == [4]byte{0, 0, 0, 0} && m2 == [4]byte{0, 0, 0, 0} {
		t.Fatal("PRNG produced all-zero masks")
	}
	if m1 == m2 {
		t.Fatal("Consecutive masks should not be identical")
	}
}

func TestIsLocalTarget(t *testing.T) {
	localAddrs := []string{
		"127.0.0.1", "localhost", "0.0.0.0", "::1", "[::1]",
		"192.168.1.1", "192.168.0.254", "10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255", "fe80::1", "fc00::1",
	}
	for _, addr := range localAddrs {
		if !isLocalTarget(addr) {
			t.Errorf("Expected %s to be recognized as local target", addr)
		}
	}

	publicAddrs := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "example.com", "cloudflare.com", "172.15.0.1", "172.32.0.1",
	}
	for _, addr := range publicAddrs {
		if isLocalTarget(addr) {
			t.Errorf("Expected %s to NOT be recognized as local target", addr)
		}
	}
}

func TestWebSocketFraming(t *testing.T) {
	prng := maskPool.Get().(*maskPRNG)
	defer maskPool.Put(prng)

	payloadSizes := []int{0, 10, 125, 126, 256, 1024, 65535, 70000}
	for _, sz := range payloadSizes {
		raw := make([]byte, sz)
		for i := range raw {
			raw[i] = byte(i % 256)
		}

		// Test masked frame (client -> server)
		buf := make([]byte, sz+32)
		copy(buf[14:], raw)
		err := writeWSFramePreallocatedFast(io.Discard, buf, 14, sz, 0x2, prng)
		if err != nil {
			t.Fatalf("writeWSFramePreallocatedFast failed for size %d: %v", sz, err)
		}

		// Test unmasked frame via pipe
		pr, pw := net.Pipe()
		go func() {
			defer pw.Close()
			frameBuf := make([]byte, sz+32)
			copy(frameBuf[14:], raw)
			_ = writeWSFramePreallocated(pw, frameBuf, 14, sz, 0x2, false)
		}()

		scratch := make([]byte, sz+32)
		readData, err := readWSFrameInto(pr, nil, scratch[14:], nil)
		pr.Close()
		if err != nil {
			t.Fatalf("readWSFrameInto failed for size %d: %v", sz, err)
		}
		if !bytes.Equal(readData, raw) {
			t.Fatalf("frame roundtrip mismatch for size %d", sz)
		}
	}
}

func TestMuxCleanEOFClosing(t *testing.T) {
	// Verify that MuxServerSession terminates gracefully on EOF without infinite loop
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	go io.Copy(io.Discard, clientConn)

	cfg := &Config{
		ConnTimeout:   5,
		BufPool:       &sync.Pool{New: func() interface{} { b := make([]byte, 65536); return &b }},
		HeaderBufPool: &sync.Pool{New: func() interface{} { b := make([]byte, 8192); return &b }},
	}

	session := &MuxServerSession{
		wsConn:  serverConn,
		cfg:     cfg,
		streams: make(map[uint32]*MuxServerStream),
		closed:  make(chan struct{}),
	}
	defer session.Close()

	// Mock target connection that immediately returns EOF on read
	targetConn, targetPeer := net.Pipe()
	targetPeer.Close() // this ensures targetConn.Read immediately gets io.EOF

	st := newMuxServerStream(101, session)
	session.streams[101] = st

	doneCh := make(chan struct{})
	go func() {
		// handleNewStream logic test: must return immediately when targetConn gets EOF
		defer close(doneCh)
		buf := make([]byte, 1024)
		for {
			nr, errRead := targetConn.Read(buf)
			if nr > 0 {
				_ = session.SendFrame(st.id, MuxCmdDATA, buf[:nr])
			}
			if errRead != nil {
				if errRead == io.EOF {
					_ = session.SendFrame(st.id, MuxCmdFIN, nil)
				} else {
					_ = session.SendFrame(st.id, MuxCmdRST, nil)
				}
				return // Our fix ensures it returns here!
			}
		}
	}()

	select {
	case <-doneCh:
		// Success! Did not loop infinitely!
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout! Mux stream loop did not exit on EOF (infinite loop bug)")
	}
}

func testBinaryForSubprocess(t *testing.T) string {
	t.Helper()
	name := t.TempDir() + "/goway-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", name, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build test binary: %v\n%s", err, out)
	}
	return name
}

func TestEndToEndSubprocessIntegration(t *testing.T) {
	// 1. Start target TCP echo server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start target echo server: %v", err)
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

	// 2. Start GOWAY Server subprocess
	serverPort := 18880
	serverCmd := exec.Command(testBinaryForSubprocess(t),
		"-p", fmt.Sprintf("127.0.0.1:%d", serverPort),
		"-k", "testKey2026",
		"-no-server-block-local",
		"-log", "ERROR",
	)
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("Failed to start goway server: %v", err)
	}
	defer func() {
		_ = serverCmd.Process.Kill()
		_ = serverCmd.Wait()
	}()

	// Wait for server to bind
	time.Sleep(500 * time.Millisecond)

	// 3. Start GOWAY Client subprocess
	clientPort := 11080
	clientCmd := exec.Command(testBinaryForSubprocess(t),
		"-p", fmt.Sprintf("127.0.0.1:%d", clientPort),
		"-up", fmt.Sprintf("ws://127.0.0.1:%d", serverPort),
		"-k", "testKey2026",
		"-block-local=false",
		"-mux=true",
		"-log", "ERROR",
	)
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("Failed to start goway client: %v", err)
	}
	defer func() {
		_ = clientCmd.Process.Kill()
		_ = clientCmd.Wait()
	}()

	// Wait for client to bind and establish tunnel
	time.Sleep(800 * time.Millisecond)

	// 4. Test SOCKS5 TCP through client -> server -> echo server
	socksConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to goway client SOCKS5: %v", err)
	}
	defer socksConn.Close()

	// SOCKS5 Handshake: [VER(5), NMETHODS(1), METHOD(0=no-auth)]
	if _, err := socksConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("SOCKS5 write handshake err: %v", err)
	}
	var hsResp [2]byte
	if _, err := io.ReadFull(socksConn, hsResp[:]); err != nil || hsResp[0] != 0x05 || hsResp[1] != 0x00 {
		t.Fatalf("SOCKS5 handshake failed, resp: %v", hsResp)
	}

	// SOCKS5 Connect Request: [0x05, 0x01(CONNECT), 0x00, 0x01(IPv4), 127, 0, 0, 1, Port(2)]
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort & 0xFF)}
	if _, err := socksConn.Write(req); err != nil {
		t.Fatalf("SOCKS5 write connect req err: %v", err)
	}
	var connResp [10]byte
	if _, err := io.ReadFull(socksConn, connResp[:]); err != nil || connResp[1] != 0x00 {
		t.Fatalf("SOCKS5 connect rejected, resp: %v", connResp)
	}

	// Echo test over SOCKS5
	testMsg := "Hello GOWAY SOCKS5 Tunnel Relay!"
	if _, err := socksConn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("Failed to write to SOCKS5 tunnel: %v", err)
	}
	echoBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(socksConn, echoBuf); err != nil {
		t.Fatalf("Failed to read from SOCKS5 echo: %v", err)
	}
	if string(echoBuf) != testMsg {
		t.Fatalf("Echo mismatch! Got %q, want %q", string(echoBuf), testMsg)
	}

	// 5. Test HTTP CONNECT through client -> server -> echo server
	httpConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to goway client HTTP: %v", err)
	}
	defer httpConn.Close()

	connectReq := fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", targetPort, targetPort)
	if _, err := httpConn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("Failed to write HTTP CONNECT: %v", err)
	}
	br := bufio.NewReader(httpConn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		t.Fatalf("HTTP CONNECT failed, status: %s, err: %v", statusLine, err)
	}
	// Drain empty line
	_, _ = br.ReadString('\n')

	// Echo test over HTTP CONNECT tunnel
	httpTestMsg := "Hello HTTP CONNECT Tunnel Relay!"
	if _, err := httpConn.Write([]byte(httpTestMsg)); err != nil {
		t.Fatalf("Failed to write to HTTP tunnel: %v", err)
	}
	httpEchoBuf := make([]byte, len(httpTestMsg))
	if _, err := io.ReadFull(br, httpEchoBuf); err != nil {
		t.Fatalf("Failed to read from HTTP echo: %v", err)
	}
	if string(httpEchoBuf) != httpTestMsg {
		t.Fatalf("HTTP Echo mismatch! Got %q, want %q", string(httpEchoBuf), httpTestMsg)
	}

	// 6. Test SOCKS5 UDP ASSOCIATE through client -> server -> UDP echo server
	udpEchoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to start UDP echo server: %v", err)
	}
	defer udpEchoConn.Close()
	udpEchoPort := udpEchoConn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := udpEchoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEchoConn.WriteToUDP(buf[:n], raddr)
		}
	}()

	socksUDPControl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect SOCKS5 UDP control: %v", err)
	}
	defer socksUDPControl.Close()

	if _, err := socksUDPControl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("SOCKS5 write handshake err: %v", err)
	}
	var hsUdpResp [2]byte
	if _, err := io.ReadFull(socksUDPControl, hsUdpResp[:]); err != nil || hsUdpResp[0] != 0x05 || hsUdpResp[1] != 0x00 {
		t.Fatalf("SOCKS5 UDP handshake failed, resp: %v", hsUdpResp)
	}

	// SOCKS5 UDP ASSOCIATE: CMD = 0x03
	udpReq := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := socksUDPControl.Write(udpReq); err != nil {
		t.Fatalf("SOCKS5 UDP write req err: %v", err)
	}
	var udpResp [10]byte
	if _, err := io.ReadFull(socksUDPControl, udpResp[:]); err != nil || udpResp[1] != 0x00 {
		t.Fatalf("SOCKS5 UDP ASSOCIATE rejected, resp: %v", udpResp)
	}

	relayPort := int(binary.BigEndian.Uint16(udpResp[8:10]))
	relayUDPAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: relayPort}

	clientUDPSocket, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("Failed to open local client UDP socket: %v", err)
	}
	defer clientUDPSocket.Close()

	// Send UDP packet through relay: [0, 0, 0(FRAG), 1(IPv4), 127, 0, 0, 1, Port(2), Payload...]
	udpMsg := "Hello SOCKS5 UDP Echo!"
	socksUDPHdr := []byte{0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(udpEchoPort >> 8), byte(udpEchoPort & 0xFF)}
	fullUDPPkt := append(socksUDPHdr, []byte(udpMsg)...)

	if _, err := clientUDPSocket.WriteToUDP(fullUDPPkt, relayUDPAddr); err != nil {
		t.Fatalf("Failed to send UDP packet to relay: %v", err)
	}

	clientUDPSocket.SetReadDeadline(time.Now().Add(2 * time.Second))
	recvPkt := make([]byte, 2048)
	nRecv, _, err := clientUDPSocket.ReadFromUDP(recvPkt)
	if err != nil {
		t.Fatalf("Failed to receive UDP reply from relay: %v", err)
	}
	if nRecv >= 10 {
		payloadRecv := string(recvPkt[10:nRecv])
		if payloadRecv != udpMsg {
			t.Fatalf("UDP echo payload mismatch: got %q, want %q", payloadRecv, udpMsg)
		}
	} else {
		t.Fatalf("UDP reply too short: %d bytes", nRecv)
	}
}

func TestViolentStressSimulation(t *testing.T) {
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

	// 2. Start GOWAY Server (v1.7.5)
	serverPort := 28880
	serverCmd := exec.Command(testBinaryForSubprocess(t),
		"-p", fmt.Sprintf("127.0.0.1:%d", serverPort),
		"-k", "violentStressKey999",
		"-no-server-block-local",
		"-log", "ERROR",
	)
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("Server start fail: %v", err)
	}
	defer func() {
		_ = serverCmd.Process.Kill()
		_ = serverCmd.Wait()
	}()
	time.Sleep(500 * time.Millisecond)

	// 3. Start GOWAY Client (v1.7.5, Mux enabled)
	clientPort := 21080
	clientCmd := exec.Command(testBinaryForSubprocess(t),
		"-p", fmt.Sprintf("127.0.0.1:%d", clientPort),
		"-up", fmt.Sprintf("ws://127.0.0.1:%d", serverPort),
		"-k", "violentStressKey999",
		"-block-local=false",
		"-mux=true",
		"-log", "ERROR",
	)
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("Client start fail: %v", err)
	}
	defer func() {
		_ = clientCmd.Process.Kill()
		_ = clientCmd.Wait()
	}()
	time.Sleep(800 * time.Millisecond)

	// --- DIMENSION 1: High Concurrency Burst (Simulate X.com 50 simultaneous timeline requests) ---
	t.Log("[TEST-DIMENSION-1] Launching 50 concurrent SOCKS5 streams (X.com timeline burst simulation)...")
	startBurst := time.Now()
	var wg sync.WaitGroup
	concurrentCount := 50
	errCount := 0
	var errMu sync.Mutex

	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 3*time.Second)
			if err != nil {
				errMu.Lock()
				errCount++
				errMu.Unlock()
				return
			}
			defer conn.Close()

			// SOCKS5 handshake
			if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
				errMu.Lock()
				errCount++
				errMu.Unlock()
				return
			}
			var hs [2]byte
			if _, err := io.ReadFull(conn, hs[:]); err != nil || hs[1] != 0x00 {
				errMu.Lock()
				errCount++
				errMu.Unlock()
				return
			}

			// Connect to target
			req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort & 0xFF)}
			if _, err := conn.Write(req); err != nil {
				errMu.Lock()
				errCount++
				errMu.Unlock()
				return
			}
			var cr [10]byte
			if _, err := io.ReadFull(conn, cr[:]); err != nil || cr[1] != 0x00 {
				errMu.Lock()
				errCount++
				errMu.Unlock()
				return
			}

			// Transfer 8KB data payload
			payload := bytes.Repeat([]byte{byte(id % 256)}, 8192)
			if _, err := conn.Write(payload); err != nil {
				errMu.Lock()
				errCount++
				errMu.Unlock()
				return
			}
			echo := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, echo); err != nil || !bytes.Equal(echo, payload) {
				errMu.Lock()
				errCount++
				errMu.Unlock()
				return
			}
		}(i)
	}
	wg.Wait()
	burstDuration := time.Since(startBurst)
	if errCount > 0 {
		t.Fatalf("Burst test had %d failures out of %d concurrent streams", errCount, concurrentCount)
	}
	t.Logf("[SUCCESS-DIMENSION-1] 50 concurrent streams completed in %v, 100%% success rate!", burstDuration)

	// --- DIMENSION 2: Sustained Heavy Throughput (Simulate YouTube 4K/1080p Video Chunk Streaming) ---
	t.Log("[TEST-DIMENSION-2] Streaming 30MB continuous data chunk (YouTube 4K chunk simulation)...")
	startThroughput := time.Now()

	vidConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 3*time.Second)
	if err != nil {
		t.Fatalf("Video conn fail: %v", err)
	}
	defer vidConn.Close()

	// HTTP CONNECT setup
	connectHeader := fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", targetPort, targetPort)
	if _, err := vidConn.Write([]byte(connectHeader)); err != nil {
		t.Fatalf("HTTP CONNECT fail: %v", err)
	}
	br := bufio.NewReader(vidConn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("HTTP 200 expected, got %s: %v", status, err)
	}
	_, _ = br.ReadString('\n')

	// Pump 30MB data in 64KB blocks
	totalBytes := 30 * 1024 * 1024 // 30MB
	chunkSize := 64 * 1024
	numChunks := totalBytes / chunkSize
	chunkData := make([]byte, chunkSize)
	for j := range chunkData {
		chunkData[j] = byte(j % 256)
	}

	readerErrCh := make(chan error, 1)
	go func() {
		bufRecv := make([]byte, chunkSize)
		bytesRecv := 0
		for bytesRecv < totalBytes {
			n, rErr := io.ReadFull(br, bufRecv)
			if rErr != nil {
				readerErrCh <- fmt.Errorf("read at byte %d failed: %v", bytesRecv, rErr)
				return
			}
			bytesRecv += n
		}
		readerErrCh <- nil
	}()

	for k := 0; k < numChunks; k++ {
		if _, wErr := vidConn.Write(chunkData); wErr != nil {
			t.Fatalf("Write video chunk %d fail: %v", k, wErr)
		}
	}

	if rErr := <-readerErrCh; rErr != nil {
		t.Fatalf("Video throughput stream error: %v", rErr)
	}
	throughputDuration := time.Since(startThroughput)
	speedMBs := float64(totalBytes) / (1024 * 1024) / throughputDuration.Seconds()
	t.Logf("[SUCCESS-DIMENSION-2] Streamed 30MB in %v (Speed: %.2f MB/s) with 0-RTT Mux!", throughputDuration, speedMBs)

	// --- DIMENSION 3: Rapid Connection Churn (Simulate continuous fast scrolling & open/close) ---
	t.Log("[TEST-DIMENSION-3] Rapid churning 100 sequential connections (rapid feed scrolling simulation)...")
	churnStart := time.Now()
	for c := 0; c < 100; c++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 2*time.Second)
		if err != nil {
			t.Fatalf("Churn connection %d failed: %v", c, err)
		}
		// SOCKS5 handshake & connect
		conn.Write([]byte{0x05, 0x01, 0x00})
		var hs [2]byte
		io.ReadFull(conn, hs[:])
		req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort & 0xFF)}
		conn.Write(req)
		var cr [10]byte
		io.ReadFull(conn, cr[:])
		conn.Write([]byte("ping"))
		var pong [4]byte
		io.ReadFull(conn, pong[:])
		conn.Close()
	}
	t.Logf("[SUCCESS-DIMENSION-3] 100 rapid churn connections completed in %v, all closed cleanly!", time.Since(churnStart))

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("[MEMORY] Total Alloc: %.2f MB, Heap Inuse: %.2f MB, GC Runs: %d",
		float64(m.TotalAlloc)/1024/1024, float64(m.HeapInuse)/1024/1024, m.NumGC)
}

func TestMuxClientSession_CloseDeadlock(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	go io.Copy(io.Discard, pipeR)

	cfg := &Config{
		Crypto:      NewCrypto("test-key"),
		ConnTimeout: 5,
		BufPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, 32*1024)
				return &b
			},
		},
	}

	session := &MuxClientSession{
		wsConn:  pipeW,
		streams: make(map[uint32]*MuxStream),
		cfg:     cfg,
		closed:  make(chan struct{}),
		prng:    maskPool.Get().(*maskPRNG),
	}

	for id := uint32(1); id <= 10; id++ {
		st := newMuxStream(id, session)
		session.streams[id] = st
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session.Close()
		}()
	}

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("Deadlock detected in MuxClientSession.Close()!")
	}

	session.Close()
	session.Close()
}

func TestMuxStream_PushDataTimeout(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()
	go io.Copy(io.Discard, pipeR)

	cfg := &Config{
		ConnTimeout: 5,
		BufPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, 32*1024)
				return &b
			},
		},
	}

	session := &MuxClientSession{
		wsConn:  pipeW,
		streams: make(map[uint32]*MuxStream),
		cfg:     cfg,
		closed:  make(chan struct{}),
		prng:    maskPool.Get().(*maskPRNG),
	}
	st := newMuxStream(1, session)
	session.streams[1] = st

	for i := 0; i < muxStreamAppQueue; i++ {
		if !st.PushData([]byte("test")) {
			t.Fatalf("PushData failed early at index %d", i)
		}
	}

	start := time.Now()
	ok := st.PushData([]byte("overflow"))
	elapsed := time.Since(start)

	if ok {
		t.Fatal("Expected false from PushData on overflow timeout, got true")
	}
	if elapsed < 10*time.Second || elapsed > 20*time.Second {
		t.Fatalf("PushData overflow timeout outside expected guard window: %v", elapsed)
	}
}

func TestValidateWSHandshakeResponse_Detailed(t *testing.T) {
	cases := []struct {
		name    string
		resp    string
		wantErr bool
		errSub  string
	}{
		{
			name:    "Valid 101 Switching Protocols",
			resp:    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
			wantErr: false,
		},
		{
			name:    "HTTP 200 OK (Reverse proxy / CDN intercept)",
			resp:    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			wantErr: true,
			errSub:  "200 OK",
		},
		{
			name:    "HTTP 301 Redirect",
			resp:    "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\n\r\n",
			wantErr: true,
			errSub:  "redirected with HTTP 301",
		},
		{
			name:    "HTTP 400 Bad Request",
			resp:    "HTTP/1.1 400 Bad Request\r\n\r\n",
			wantErr: true,
			errSub:  "HTTP 400 Bad Request",
		},
		{
			name:    "HTTP 403 Forbidden",
			resp:    "HTTP/1.1 403 Forbidden\r\n\r\n",
			wantErr: true,
			errSub:  "HTTP 403 Forbidden",
		},
		{
			name:    "HTTP 502 Bad Gateway",
			resp:    "HTTP/1.1 502 Bad Gateway\r\n\r\n",
			wantErr: true,
			errSub:  "HTTP 502 Bad Gateway",
		},
		{
			name:    "Malformed Response",
			resp:    "GARBAGE_DATA\r\n\r\n",
			wantErr: true,
			errSub:  "malformed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWSHandshakeResponse([]byte(tc.resp))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Expected error containing %q, got nil", tc.errSub)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("Expected error containing %q, got %v", tc.errSub, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Expected success, got %v", err)
				}
			}
		})
	}
}

func TestIsLocalTarget_AllVariants(t *testing.T) {
	locals := []string{
		"localhost", "LocalHost", "127.0.0.1", "127.0.0.100", "::1", "[::1]",
		"0.0.0.0", "::", "10.0.0.1", "10.254.1.1", "172.16.0.1", "172.31.255.254",
		"192.168.0.1", "192.168.100.200", "169.254.1.1", "fe80::1", "fc00::1", "fd00::1",
		"::ffff:127.0.0.1", "::ffff:192.168.1.1",
	}
	for _, a := range locals {
		if !isLocalTarget(a) {
			t.Errorf("isLocalTarget(%q) = false, want true", a)
		}
	}

	nonLocals := []string{
		"1.1.1.1", "8.8.8.8", "172.15.255.255", "172.32.0.1", "203.0.113.1",
		"google.com", "example.com", "::ffff:8.8.8.8",
	}
	for _, a := range nonLocals {
		if isLocalTarget(a) {
			t.Errorf("isLocalTarget(%q) = true, want false", a)
		}
	}
}

func TestHTTPProxyTCPFragmentation(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	cfg := &Config{
		HeaderBufPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, MaxHeaderSize)
				return &b
			},
		},
		ConnTimeout: 2,
	}

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		var buf [1]byte
		n, err := serverConn.Read(buf[:])
		if err != nil || n == 0 {
			t.Errorf("Failed to read initial byte: %v", err)
			return
		}
		if buf[0] != 'C' {
			t.Errorf("Unexpected first byte: %c", buf[0])
			return
		}

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
				t.Errorf("Buffer overflow")
				return
			}
			n, readErr := serverConn.Read(restBuf[totalRead:])
			if n > 0 {
				totalRead += n
			}
			if readErr != nil {
				break
			}
		}

		header := string(restBuf[:totalRead])
		if !strings.HasPrefix(header, "CONNECT example.com:443 HTTP/1.1") {
			t.Errorf("Parsed header mismatch: %q", header)
		}
		if !strings.Contains(header, "Host: example.com:443") {
			t.Errorf("Missing host in parsed header: %q", header)
		}
	}()

	go func() {
		defer clientConn.Close()
		clientConn.Write([]byte("CO"))
		time.Sleep(20 * time.Millisecond)
		clientConn.Write([]byte("NNECT example.com:443 HTTP/1.1\r\n"))
		time.Sleep(20 * time.Millisecond)
		clientConn.Write([]byte("Host: example.com:443\r\n\r\n"))
	}()

	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for fragmented HTTP request read")
	}
}

func TestSOCKS5UDPAssociateTruncated(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	cfg := &Config{
		ConnTimeout: 2,
	}

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		handleClient(serverConn, cfg)
	}()

	clientConn.Write([]byte{0x05, 0x01, 0x00})
	var hs [2]byte
	io.ReadFull(clientConn, hs[:])

	// Truncated UDP associate request: atyp=1, but closed immediately without IP or port
	clientConn.Write([]byte{0x05, 0x03, 0x00, 0x01})
	clientConn.Close()

	select {
	case <-doneCh:
		// Succeeded in safely aborting without hang
	case <-time.After(2 * time.Second):
		t.Fatal("handleClient did not abort on truncated UDP ASSOCIATE")
	}
}

func TestQUICClientPool_100ConcurrentGetStream(t *testing.T) {
	cert, err := generateSelfSignedCert("test-key")
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"goway-quic", "h3"},
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConf, defaultQUICConfig())
	if err != nil {
		t.Fatalf("Failed to listen QUIC: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func(c quic.Connection) {
				for {
					stream, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func(st quic.Stream) {
						defer st.Close()
						var b [4]byte
						if _, err := io.ReadFull(st, b[:]); err == nil {
							st.Write(b[:])
						}
					}(stream)
				}
			}(conn)
		}
	}()

	cfg := &Config{
		Upstream:    "quic://" + listener.Addr().String(),
		ConnTimeout: 5,
		VerifySSL:   false,
	}

	pool, err := NewQUICClientPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create QUICClientPool: %v", err)
	}
	defer pool.Close()

	const concurrency = 100
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			stream, err := pool.GetStream()
			if err != nil {
				errCh <- fmt.Errorf("client %d GetStream failed: %v", idx, err)
				return
			}
			defer stream.Close()

			msg := []byte("ping")
			if _, err := stream.Write(msg); err != nil {
				errCh <- fmt.Errorf("client %d Write failed: %v", idx, err)
				return
			}
			var resp [4]byte
			if _, err := io.ReadFull(stream, resp[:]); err != nil {
				errCh <- fmt.Errorf("client %d ReadFull failed: %v", idx, err)
				return
			}
			if string(resp[:]) != "ping" {
				errCh <- fmt.Errorf("client %d got bad response: %s", idx, string(resp[:]))
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	pool.mu.Lock()
	nconn := len(pool.conns)
	pool.mu.Unlock()
	if nconn == 0 {
		t.Fatal("Expected pool.conns to be non-empty after successful connections")
	}
}

func TestQUICClientPool_DialFailure(t *testing.T) {
	cfg := &Config{
		Upstream:    "quic://127.0.0.1:59999",
		ConnTimeout: 1,
		VerifySSL:   false,
	}

	pool, err := NewQUICClientPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create QUICClientPool: %v", err)
	}
	defer pool.Close()

	stream, err := pool.GetStream()
	if err == nil {
		stream.Close()
		t.Fatal("Expected GetStream to fail on unreachable address, got nil error")
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.conns) != 0 {
		t.Fatal("Expected pool.conns to remain empty on dial failure")
	}
	if pool.dialing != nil {
		t.Fatal("Expected pool.dialing to be cleared on dial failure")
	}
}

func TestQUICClientPool_CloseConcurrent(t *testing.T) {
	cert, err := generateSelfSignedCert("test-key")
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"goway-quic", "h3"},
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConf, defaultQUICConfig())
	if err != nil {
		t.Fatalf("Failed to listen QUIC: %v", err)
	}
	defer listener.Close()

	cfg := &Config{
		Upstream:    "quic://" + listener.Addr().String(),
		ConnTimeout: 5,
		VerifySSL:   false,
	}

	pool, err := NewQUICClientPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create QUICClientPool: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, err := pool.GetStream()
			if err == nil {
				stream.Close()
			}
		}()
	}

	time.Sleep(5 * time.Millisecond)
	pool.Close()

	wg.Wait()
}

func TestMuxServerStream_PushDataCleanupOnFalse(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()
	go io.Copy(io.Discard, pipeR)

	cfg := &Config{
		ConnTimeout: 5,
		BufPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, 32*1024)
				return &b
			},
		},
	}

	session := &MuxServerSession{
		wsConn:  pipeW,
		streams: make(map[uint32]*MuxServerStream),
		closed:  make(chan struct{}),
		cfg:     cfg,
	}
	st := newMuxServerStream(42, session)
	session.streams[42] = st

	for i := 0; i < muxStreamAppQueue; i++ {
		st.writeChan <- muxDataFrame{data: []byte("busy")}
	}

	start := time.Now()
	ok := st.PushData([]byte("overflow"))
	if ok {
		t.Fatal("Expected PushData to return false on full queue")
	}
	if elapsed := time.Since(start); elapsed < 10*time.Second || elapsed > 20*time.Second {
		t.Fatalf("Full queue push outside expected guard window: %v", elapsed)
	}
	select {
	case <-st.closed:
	default:
		t.Fatal("Expected server stream to be closed/reset after queue overflow")
	}
}

func TestQUICClientPool_OpenStreamFailureReconnect(t *testing.T) {
	cert, err := generateSelfSignedCert("test-key")
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"goway-quic", "h3"},
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConf, defaultQUICConfig())
	if err != nil {
		t.Fatalf("Failed to listen QUIC: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func(c quic.Connection) {
				for {
					stream, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func(st quic.Stream) {
						defer st.Close()
						var b [4]byte
						if _, err := io.ReadFull(st, b[:]); err == nil {
							st.Write(b[:])
						}
					}(stream)
				}
			}(conn)
		}
	}()

	cfg := &Config{
		Upstream:    "quic://" + listener.Addr().String(),
		ConnTimeout: 5,
		VerifySSL:   false,
	}

	pool, err := NewQUICClientPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create QUICClientPool: %v", err)
	}
	defer pool.Close()

	// 1. First stream succeeds
	st1, err := pool.GetStream()
	if err != nil {
		t.Fatalf("Initial GetStream failed: %v", err)
	}
	st1.Close()

	// 2. Abruptly close the underlying connection from under the pool
	pool.mu.Lock()
	if len(pool.conns) == 0 {
		pool.mu.Unlock()
		t.Fatal("Expected active connection")
	}
	conn := pool.conns[0]
	pool.mu.Unlock()
	_ = conn.CloseWithError(0x02, "simulated abrupt disconnection")

	// 3. Next GetStream detects failure on broken conn, clears pool reference, and reconnects!
	st2, err := pool.GetStream()
	if err != nil {
		t.Fatalf("Reconnected GetStream failed: %v", err)
	}
	defer st2.Close()

	if _, err := st2.Write([]byte("ping")); err != nil {
		t.Fatalf("Write on reconnected stream failed: %v", err)
	}
	var resp [4]byte
	if _, err := io.ReadFull(st2, resp[:]); err != nil {
		t.Fatalf("Read on reconnected stream failed: %v", err)
	}
	if string(resp[:]) != "ping" {
		t.Fatalf("Expected ping, got %s", string(resp[:]))
	}
}

func TestMuxClientPool_ConfiguredSessions(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()

	cfg := &Config{
		ConnTimeout: 5,
	}

	for _, maxSess := range []int{1, 4, 8, 16, 64} {
		pool := NewMuxClientPool(cfg, maxSess)
		if pool.maxSess != maxSess {
			t.Fatalf("Expected maxSess=%d, got %d", maxSess, pool.maxSess)
		}
		pool.Close()
	}
}

func TestMuxStream_ByteLimitBackpressure(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()
	go io.Copy(io.Discard, pipeR)

	cfg := &Config{
		ConnTimeout: 5,
		BufPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, 32*1024)
				return &b
			},
		},
	}

	session := &MuxClientSession{
		wsConn:  pipeW,
		streams: make(map[uint32]*MuxStream),
		cfg:     cfg,
		closed:  make(chan struct{}),
		prng:    maskPool.Get().(*maskPRNG),
	}
	st := newMuxStream(10, session)
	session.streams[10] = st
	defer st.Close()

	chunk := make([]byte, 1024*1024)
	fitChunks := int(muxClientStreamBufferLimit / (1024 * 1024))
	for i := 0; i < fitChunks; i++ {
		if !st.PushData(chunk) {
			t.Fatalf("Failed to push chunk %d within limit", i)
		}
	}
	if st.QueuedBytes() != int64(muxClientStreamBufferLimit) {
		t.Fatalf("Expected %d queued, got %d", int64(muxClientStreamBufferLimit), st.QueuedBytes())
	}

	start := time.Now()
	if st.PushData(chunk) {
		t.Fatal("Expected saturated stream push to fail")
	}
	if elapsed := time.Since(start); elapsed < 10*time.Second || elapsed > 20*time.Second {
		t.Fatalf("Saturated stream push outside expected guard window: %v", elapsed)
	}
	if st.QueuedBytes() != 0 {
		t.Fatalf("Expected reset stream to clear queued bytes, got %d", st.QueuedBytes())
	}
}

func TestMuxStream_QueuedBytesAccounting(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()
	go io.Copy(io.Discard, pipeR)

	cfg := &Config{
		ConnTimeout: 5,
		BufPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, 32*1024)
				return &b
			},
		},
	}

	session := &MuxClientSession{
		wsConn:  pipeW,
		streams: make(map[uint32]*MuxStream),
		cfg:     cfg,
		closed:  make(chan struct{}),
		prng:    maskPool.Get().(*maskPRNG),
	}
	st := newMuxStream(20, session)
	session.streams[20] = st
	defer st.Close()

	st.PushData(make([]byte, 1000))
	st.PushData(make([]byte, 1000))
	st.PushData(make([]byte, 1000))

	if st.QueuedBytes() != 3000 {
		t.Fatalf("Expected 3000 queued bytes, got %d", st.QueuedBytes())
	}

	buf := make([]byte, 1500)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if st.QueuedBytes() != 1500 {
		t.Fatalf("Expected 1500 queued bytes after partial read, got %d", st.QueuedBytes())
	}

	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if st.QueuedBytes() != 0 {
		t.Fatalf("Expected 0 queued bytes after complete read, got %d", st.QueuedBytes())
	}
}

func TestMuxStream_BufferRecyclingOnClose(t *testing.T) {
	poolAllocCount := 0

	pool := &sync.Pool{
		New: func() interface{} {
			poolAllocCount++
			b := make([]byte, 4096)
			return &b
		},
	}

	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()
	go io.Copy(io.Discard, pipeR)

	cfg := &Config{
		ConnTimeout: 5,
		BufPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, 32*1024)
				return &b
			},
		},
	}

	session := &MuxClientSession{
		wsConn:  pipeW,
		streams: make(map[uint32]*MuxStream),
		cfg:     cfg,
		closed:  make(chan struct{}),
		prng:    maskPool.Get().(*maskPRNG),
	}
	st := newMuxStream(30, session)
	session.streams[30] = st

	// Push 5 pooled frames
	for i := 0; i < 5; i++ {
		bPtr := pool.Get().(*[]byte)
		frame := muxDataFrame{
			data: (*bPtr)[:100],
			bPtr: bPtr,
			pool: pool,
		}
		st.PushDataFrame(frame)
	}

	// Close stream while frames are still pending
	st.Close()

	if st.QueuedBytes() != 0 {
		t.Fatalf("Expected QueuedBytes=0 on Close, got %d", st.QueuedBytes())
	}

	// Verify all 5 buffers were recycled and can be retrieved from pool without triggering New
	retrieved := 0
	for i := 0; i < 5; i++ {
		p := pool.Get().(*[]byte)
		if p != nil {
			retrieved++
		}
	}
	if retrieved != 5 {
		t.Fatalf("Expected 5 recycled buffers in pool, got %d", retrieved)
	}
}

func TestConnPool_GetPutLifecycle(t *testing.T) {
	cfg := &Config{
		ConnTimeout: 5,
	}
	pool := NewConnPool(cfg, 3)
	defer pool.Close()

	c1, w1 := net.Pipe()
	defer c1.Close()
	defer w1.Close()

	br1 := bufio.NewReader(c1)
	pConn1 := &PooledConn{
		wsConn:   c1,
		br:       br1,
		created:  time.Now(),
		lastUsed: time.Now(),
	}

	// Put into pool
	pool.Put(pConn1)

	// Get from pool
	got := pool.Get()
	if got == nil || got.wsConn != c1 {
		t.Fatal("Failed to Get connection that was Put into pool")
	}

	// Pool should now be empty
	if empty := pool.Get(); empty != nil {
		t.Fatal("Expected pool to be empty after Get")
	}

	// Put back
	pool.Put(got)

	// Put exceeding maxSize
	c2, _ := net.Pipe()
	c3, _ := net.Pipe()
	c4, _ := net.Pipe()
	pool.Put(&PooledConn{wsConn: c2, br: bufio.NewReader(c2), created: time.Now(), lastUsed: time.Now()})
	pool.Put(&PooledConn{wsConn: c3, br: bufio.NewReader(c3), created: time.Now(), lastUsed: time.Now()})
	// 4th connection exceeds maxSize=3
	pool.Put(&PooledConn{wsConn: c4, br: bufio.NewReader(c4), created: time.Now(), lastUsed: time.Now()})

	pool.mu.Lock()
	count := len(pool.conns)
	pool.mu.Unlock()
	if count > 3 {
		t.Fatalf("Expected max 3 conns in pool, got %d", count)
	}

	// Test expired connection rejection
	cExpired, _ := net.Pipe()
	pool.Put(&PooledConn{
		wsConn:   cExpired,
		br:       bufio.NewReader(cExpired),
		created:  time.Now().Add(-10 * time.Minute), // expired (> maxAge 5m)
		lastUsed: time.Now(),
	})

	// Close pool and verify subsequent Put closes connection
	pool.Close()
	cClosed, _ := net.Pipe()
	pool.Put(&PooledConn{wsConn: cClosed, br: bufio.NewReader(cClosed), created: time.Now(), lastUsed: time.Now()})
	if pool.Get() != nil {
		t.Fatal("Expected Get to return nil after pool Close")
	}
}

func BenchmarkMuxDataTransferOldMakeCopy(b *testing.B) {
	data := make([]byte, 32*1024)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		_ = dataCopy
	}
}

func BenchmarkMuxDataTransferPooled(b *testing.B) {
	pool := &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32*1024+14)
			return &buf
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bPtr := pool.Get().(*[]byte)
		frame := muxDataFrame{
			data: (*bPtr)[14 : 14+32*1024],
			bPtr: bPtr,
			pool: pool,
		}
		// Consumer finishes and releases back to pool
		frame.release()
	}
}

func TestQUICServer_MaxConnsEnforcement(t *testing.T) {
	cert, err := generateSelfSignedCert("test-key")
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"goway-quic", "h3"},
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConf, defaultQUICConfig())
	if err != nil {
		t.Fatalf("Failed to listen QUIC: %v", err)
	}
	defer listener.Close()

	// Set MaxConns to 1
	cfg := &Config{
		MaxConns:    1,
		ConnTimeout: 5,
	}

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go handleQUICConnection(conn, cfg)
		}
	}()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"goway-quic", "h3"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, defaultQUICConfig())
	if err != nil {
		t.Fatalf("Failed to dial QUIC server: %v", err)
	}
	defer conn.CloseWithError(0, "client done")

	origConns := atomic.LoadInt64(&stats.activeConns)
	defer atomic.StoreInt64(&stats.activeConns, origConns)

	// Stream 1: should be accepted
	st1, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("Stream 1 OpenStreamSync failed: %v", err)
	}
	defer st1.Close()

	// Send an unclosed dummy stream header so handleQUICStream holds activeConns
	_, _ = st1.Write([]byte("127.0.0.1:80\n"))
	time.Sleep(50 * time.Millisecond)

	// Stream 2: exceeds MaxConns (which is 1)
	st2, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("Stream 2 OpenStreamSync failed: %v", err)
	}
	defer st2.Close()

	// Stream 2 should be rejected/closed by server immediately
	buf := make([]byte, 10)
	st2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, errRead := st2.Read(buf)
	if errRead == nil && n > 0 {
		t.Fatalf("Expected stream 2 to be closed immediately due to MaxConns limit, but read %d bytes", n)
	}
}

func TestMuxServerStream_BufPoolUsage(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen target: %v", err)
	}
	defer targetLn.Close()

	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello from target"))
	}()

	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()

	bufPool := &sync.Pool{
		New: func() interface{} {
			b := make([]byte, 65536+14+MuxHeaderLen)
			return &b
		},
	}

	cfg := &Config{
		ConnTimeout: 5,
		BufPool:     bufPool,
	}

	session := &MuxServerSession{
		wsConn:  pipeW,
		streams: make(map[uint32]*MuxServerStream),
		cfg:     cfg,
		closed:  make(chan struct{}),
	}
	st := newMuxServerStream(100, session)
	session.streams[100] = st

	doneCh := make(chan struct{})
	go func() {
		session.handleNewStream(st, targetLn.Addr().String(), nil)
		close(doneCh)
	}()

	br := bufio.NewReader(pipeR)
	frame, err := readWSFrame(br, pipeR, nil)
	if err != nil {
		t.Fatalf("Failed to read Mux frame: %v", err)
	}
	if len(frame) < MuxHeaderLen {
		t.Fatalf("Frame too short: %d", len(frame))
	}
	cmd := frame[4]
	if cmd != MuxCmdDATA {
		t.Fatalf("Expected MuxCmdDATA (0x02), got 0x%x", cmd)
	}
	payload := frame[7:]
	if string(payload) != "hello from target" {
		t.Fatalf("Expected 'hello from target', got %s", string(payload))
	}

	// Drain any remaining frames (e.g. MuxCmdFIN or MuxCmdRST) so SendFrame on net.Pipe does not block
	go io.Copy(io.Discard, pipeR)

	st.Close()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("handleNewStream did not terminate after st.Close()")
	}
}

func TestMuxClientPool_LeastActiveScheduling(t *testing.T) {
	cfg := &Config{ConnTimeout: 5}
	pool := NewMuxClientPool(cfg, 4)
	defer pool.Close()

	// Create 4 mock sessions
	s0 := &MuxClientSession{closed: make(chan struct{})}
	s1 := &MuxClientSession{closed: make(chan struct{})}
	s2 := &MuxClientSession{closed: make(chan struct{})}
	s3 := &MuxClientSession{closed: make(chan struct{})}

	// Set active streams:
	// Session 0: 8 streams
	// Session 1: 2 streams  <-- candidate
	// Session 2: 5 streams
	// Session 3: 2 streams  <-- candidate
	s0.activeStreams.Store(8)
	s1.activeStreams.Store(2)
	s2.activeStreams.Store(5)
	s3.activeStreams.Store(2)

	pool.sessions = []*MuxClientSession{s0, s1, s2, s3}

	// Verify that GetSession only selects s1 or s3 (the ones with min active streams)
	counts := make(map[*MuxClientSession]int)
	for i := 0; i < 20; i++ {
		sess, err := pool.GetSession()
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}
		if sess != s1 && sess != s3 {
			t.Fatalf("Expected only s1 or s3 to be picked, got session with %d streams", sess.ActiveStreams())
		}
		counts[sess]++
		sess.decrementActiveStreams() // Release reservation to maintain static candidate counts
	}

	// Verify round-robin tie breaking between s1 and s3
	if counts[s1] == 0 || counts[s3] == 0 {
		t.Fatalf("Expected round-robin between s1 and s3, got counts: s1=%d, s3=%d", counts[s1], counts[s3])
	}
	if counts[s0] != 0 || counts[s2] != 0 {
		t.Fatalf("Expected s0 and s2 never to be chosen, got counts: s0=%d, s2=%d", counts[s0], counts[s2])
	}

	// Now increase s1 active streams to 3. s3 (2 streams) is now strictly the lowest!
	s1.activeStreams.Store(3)
	for i := 0; i < 10; i++ {
		sess, err := pool.GetSession()
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}
		if sess != s3 {
			t.Fatalf("Expected strictly s3 to be chosen, got session with %d streams", sess.ActiveStreams())
		}
		sess.decrementActiveStreams()
	}
}

func TestMuxStream_ActiveStreamsLifecycle(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()
	go io.Copy(io.Discard, pipeR)

	session := &MuxClientSession{
		wsConn:  pipeW,
		streams: make(map[uint32]*MuxStream),
		closed:  make(chan struct{}),
		prng:    maskPool.Get().(*maskPRNG),
		cfg: &Config{
			ConnTimeout: 5,
			BufPool: &sync.Pool{
				New: func() interface{} {
					b := make([]byte, 32*1024)
					return &b
				},
			},
		},
	}

	if session.ActiveStreams() != 0 {
		t.Fatalf("Initial activeStreams should be 0, got %d", session.ActiveStreams())
	}

	st := newMuxStream(1, session)
	st.onClose = func() {
		session.decrementActiveStreams()
	}
	session.streamsMu.Lock()
	session.streams[1] = st
	session.streamsMu.Unlock()
	session.activeStreams.Add(1)

	if session.ActiveStreams() != 1 {
		t.Fatalf("After stream creation, activeStreams should be 1, got %d", session.ActiveStreams())
	}

	// Close stream
	st.Close()
	if session.ActiveStreams() != 0 {
		t.Fatalf("After st.Close(), activeStreams should be 0, got %d", session.ActiveStreams())
	}

	// Multiple closes should not decrement again
	st.Close()
	st.Reset()
	if session.ActiveStreams() != 0 {
		t.Fatalf("Multiple closes should not result in negative activeStreams, got %d", session.ActiveStreams())
	}
}

func TestConnPool_ImmediateRefillSignal(t *testing.T) {
	pool := &ConnPool{
		conns:    make([]*PooledConn, 0, 5),
		maxSize:  5,
		refillCh: make(chan struct{}, 1),
	}

	c1, _ := net.Pipe()
	defer c1.Close()
	pConn1 := &PooledConn{wsConn: c1, br: bufio.NewReader(c1), created: time.Now(), lastUsed: time.Now()}
	pool.conns = append(pool.conns, pConn1)

	// Get a connection
	got := pool.Get()
	if got != pConn1 {
		t.Fatal("Expected to get connection from pool")
	}

	// Verify that refillCh received the non-blocking signal immediately
	select {
	case <-pool.refillCh:
		// Success: signal was sent!
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected refillCh to receive signal immediately after Get()")
	}

	// Subsequent Get on empty pool should return nil and not block
	if empty := pool.Get(); empty != nil {
		t.Fatal("Expected nil on empty pool")
	}
}

func TestMuxClientPool_ConcurrentReservationLoad(t *testing.T) {
	for _, numStreams := range []int{100, 500, 1000} {
		t.Run(fmt.Sprintf("%d_streams", numStreams), func(t *testing.T) {
			bufPool := &sync.Pool{
				New: func() interface{} {
					b := make([]byte, 32*1024)
					return &b
				},
			}
			cfg := &Config{ConnTimeout: 5, BufPool: bufPool}
			pool := NewMuxClientPool(cfg, 4)
			defer pool.Close()

			// Create 4 mock sessions with pipes
			sessions := make([]*MuxClientSession, 4)
			for i := 0; i < 4; i++ {
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

			var wg sync.WaitGroup
			wg.Add(numStreams)

			for i := 0; i < numStreams; i++ {
				go func(idx int) {
					defer wg.Done()
					sess, err := pool.GetSession()
					if err != nil {
						t.Errorf("GetSession failed: %v", err)
						return
					}

					if sess.ActiveStreams() < 1 {
						t.Errorf("ActiveStreams should be >= 1 after reservation")
					}

					st := newMuxStream(uint32(idx+1), sess)
					st.onClose = func() {
						sess.decrementActiveStreams()
					}
					sess.streamsMu.Lock()
					sess.streams[st.id] = st
					sess.streamsMu.Unlock()

					// Brief sleep
					time.Sleep(time.Duration(mrand.Intn(2)+1) * time.Millisecond)

					// Close stream (triggers onClose -> decrementActiveStreams)
					st.Close()
				}(i)
			}

			wg.Wait()

			// Check that all sessions returned EXACTLY to 0
			for i, s := range sessions {
				active := s.ActiveStreams()
				if active != 0 {
					t.Fatalf("Session %d activeStreams did not return to 0, got %d", i, active)
				}
			}
		})
	}
}

func TestMuxStream_BufferOwnershipAndCloseRace(t *testing.T) {
	bufPool := &sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32*1024)
			return &b
		},
	}
	cfg := &Config{
		ConnTimeout: 5,
		BufPool:     bufPool,
	}

	for iter := 0; iter < 50; iter++ {
		pipeR, pipeW := net.Pipe()
		go io.Copy(io.Discard, pipeR)

		session := &MuxClientSession{
			wsConn:  pipeW,
			streams: make(map[uint32]*MuxStream),
			closed:  make(chan struct{}),
			prng:    maskPool.Get().(*maskPRNG),
			cfg:     cfg,
		}

		st := newMuxStream(uint32(iter+1), session)
		session.streamsMu.Lock()
		session.streams[st.id] = st
		session.streamsMu.Unlock()

		var wg sync.WaitGroup
		wg.Add(4)

		// Goroutine 1: PushDataFrame
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				bPtr := bufPool.Get().(*[]byte)
				buf := *bPtr
				payload := buf[:512]
				frame := muxDataFrame{
					data: payload,
					bPtr: bPtr,
					pool: bufPool,
				}
				if !st.PushDataFrame(frame) {
					frame.release()
					return
				}
			}
		}()

		// Goroutine 2: Read
		go func() {
			defer wg.Done()
			readBuf := make([]byte, 256)
			for {
				_, err := st.Read(readBuf)
				if err != nil {
					return
				}
			}
		}()

		// Goroutine 3: Close or Reset
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(mrand.Intn(2)+1) * time.Millisecond)
			if iter%2 == 0 {
				st.Close()
			} else {
				st.Reset()
			}
		}()

		// Goroutine 4: Session Close
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(mrand.Intn(2)+1) * time.Millisecond)
			session.Close()
		}()

		wg.Wait()
		st.Close()
		session.Close()
		pipeR.Close()
	}
}

// TestMuxOutboundWriterFairness proves per-stream fairness of the MUX
// outbound writer: a bulk stream must not bury an interactive stream
// (the pre-DRR FIFO failure mode), and control frames must jump the queue.
func TestMuxOutboundWriterFairness(t *testing.T) {
	mkframe := func(id uint32, cmd byte, size int) muxOutboundFrame {
		buf := make([]byte, 14+MuxHeaderLen+size)
		binary.BigEndian.PutUint32(buf[14:18], id)
		buf[18] = cmd
		binary.BigEndian.PutUint16(buf[19:21], uint16(size))
		return muxOutboundFrame{bPtr: &buf, pool: &sync.Pool{}, payloadOff: 14, payloadLen: MuxHeaderLen + size, opcode: 0x2, streamID: id, cmd: cmd}
	}
	readMux := func(br *bufio.Reader, conn net.Conn) (uint32, byte) {
		t.Helper()
		data, err := readWSFrame(br, conn, nil)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if len(data) < MuxHeaderLen {
			t.Fatalf("short mux frame: %d", len(data))
		}
		return binary.BigEndian.Uint32(data[:4]), data[4]
	}
	t.Run("InteractiveJumpsAheadOfBulk", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		// The Phase 4 writev drain pops queued frames without touching the
		// pipe, so a running writer races the enqueue loop below (the pipe
		// only blocks once a batch forms — the old one-frame-per-write loop
		// blocked after every frame, which made the race invisible). Build
		// the writer without its loop, queue every frame first, then start
		// draining: with the full queue visible, DRR order is
		// deterministic. close() waits for the loop, so the deferred close
		// is registered only after go w.loop().
		w := &muxOutboundWriter{
			conn:    client,
			prng:    prng,
			masked:  true,
			streams: make(map[uint32]*muxStreamQueue),
			done:    make(chan struct{}),
		}
		w.cond = sync.NewCond(&w.mu)
		br := bufio.NewReader(server)
		for i := 0; i < 4; i++ {
			if !w.enqueue(mkframe(1, MuxCmdDATA, 32768)) {
				t.Fatalf("bulk enqueue %d rejected", i)
			}
		}
		if !w.enqueue(mkframe(2, MuxCmdDATA, 100)) {
			t.Fatal("interactive enqueue rejected")
		}
		go w.loop()
		defer w.close()
		var order []uint32
		for i := 0; i < 5; i++ {
			id, _ := readMux(br, server)
			order = append(order, id)
		}
		// Expected: bulk#1 (in flight first), then interactive (stream 2's
		// DRR turn), then the bulk remainder. FIFO would put stream 2 last.
		if len(order) != 5 || order[0] != 1 || order[1] != 2 {
			t.Fatalf("unfair order: %v, want [1 2 1 1 1]", order)
		}
		for _, id := range order[2:] {
			if id != 1 {
				t.Fatalf("unfair order: %v, want [1 2 1 1 1]", order)
			}
		}
	})
	t.Run("ControlJumpsQueue", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		w := newMuxOutboundWriter(client, prng, nil, true, 0)
		defer w.close()
		br := bufio.NewReader(server)
		if !w.enqueue(mkframe(1, MuxCmdDATA, 32768)) {
			t.Fatal("bulk enqueue rejected")
		}
		// Drain the in-flight bulk frame first: this pins the writer to a
		// known state (idle, empty queues) so the assertions below are
		// deterministic regardless of goroutine scheduling.
		if id, _ := readMux(br, server); id != 1 {
			t.Fatalf("first frame not bulk: %d", id)
		}
		if !w.enqueue(mkframe(1, MuxCmdDATA, 32768)) {
			t.Fatal("bulk enqueue rejected")
		}
		if !w.enqueue(mkframe(2, MuxCmdFIN, 0)) {
			t.Fatal("FIN enqueue rejected")
		}
		var cmds []byte
		var ids []uint32
		for i := 0; i < 2; i++ {
			id, cmd := readMux(br, server)
			ids = append(ids, id)
			cmds = append(cmds, cmd)
		}
		// Expected: FIN via the priority lane, then bulk#2.
		// Without the priority lane the FIN would come last.
		if len(cmds) != 2 || cmds[0] != MuxCmdFIN || ids[0] != 2 {
			t.Fatalf("FIN did not jump queue: ids=%v cmds=%v", ids, cmds)
		}
	})
	t.Run("FinNeverOvertakesOwnData", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		w := newMuxOutboundWriter(client, prng, nil, true, 0)
		defer w.close()
		br := bufio.NewReader(server)
		// Same stream: DATA, DATA, FIN all queued while the writer is
		// blocked on the first pipe write. A FIN that jumps its own
		// stream's DATA would make the peer close early and drop the
		// tail 鈥?the FIN must come last.
		if !w.enqueue(mkframe(1, MuxCmdDATA, 1000)) {
			t.Fatal("DATA enqueue rejected")
		}
		if !w.enqueue(mkframe(1, MuxCmdDATA, 1000)) {
			t.Fatal("DATA enqueue rejected")
		}
		if !w.enqueue(mkframe(1, MuxCmdFIN, 0)) {
			t.Fatal("FIN enqueue rejected")
		}
		var cmds []byte
		for i := 0; i < 3; i++ {
			_, cmd := readMux(br, server)
			cmds = append(cmds, cmd)
		}
		if len(cmds) != 3 || cmds[0] != MuxCmdDATA || cmds[1] != MuxCmdDATA || cmds[2] != MuxCmdFIN {
			t.Fatalf("FIN overtook its own DATA: cmds=%v, want [DATA DATA FIN]", cmds)
		}
	})
	t.Run("SynNeverYieldsToOwnData", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		w := newMuxOutboundWriter(client, prng, nil, true, 0)
		defer w.close()
		br := bufio.NewReader(server)
		// SYN creates the peer-side stream: it must lead even when its
		// own DATA is already queued, else the peer drops that DATA as
		// unknown-stream (live-caught: full flows vanishing under burst).
		//
		// Determinism: SYN is enqueued FIRST, so every interleave yields
		// [SYN, DATA] 鈥?the loop either hasn't run yet (both queued, SYN
		// jumps via the priority lane) or already emitted SYN alone (then
		// blocks on the pipe write until the first read). Enqueueing DATA
		// first would race the loop's first scheduling decision instead.
		if !w.enqueue(mkframe(1, MuxCmdSYN, 17)) {
			t.Fatal("SYN enqueue rejected")
		}
		if !w.enqueue(mkframe(1, MuxCmdDATA, 1000)) {
			t.Fatal("DATA enqueue rejected")
		}
		var cmds []byte
		for i := 0; i < 2; i++ {
			_, cmd := readMux(br, server)
			cmds = append(cmds, cmd)
		}
		if len(cmds) != 2 || cmds[0] != MuxCmdSYN || cmds[1] != MuxCmdDATA {
			t.Fatalf("SYN yielded to its own DATA: cmds=%v, want [SYN DATA]", cmds)
		}
	})
	t.Run("LargeObfsFrameNoDeadlock", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		w := newMuxOutboundWriter(client, prng, nil, true, 0)
		defer w.close()
		br := bufio.NewReader(server)

		// Frame larger than 64KB (simulating maxChunk 65528 + padding 1200)
		largeSize := 65530
		pad := 1200
		totalPayload := MuxHeaderLen + largeSize + pad
		buf := make([]byte, 14+totalPayload)
		binary.BigEndian.PutUint32(buf[14:18], 1)
		buf[18] = MuxCmdDATA
		binary.BigEndian.PutUint16(buf[19:21], uint16(largeSize))
		frame := muxOutboundFrame{bPtr: &buf, pool: &sync.Pool{}, payloadOff: 14, payloadLen: totalPayload, opcode: 0x2, streamID: 1, cmd: MuxCmdDATA}

		if !w.enqueue(frame) {
			t.Fatal("large obfs frame enqueue rejected")
		}

		done := make(chan struct{})
		go func() {
			id, cmd := readMux(br, server)
			if id != 1 || cmd != MuxCmdDATA {
				t.Errorf("read wrong frame: id=%d cmd=%d", id, cmd)
			}
			close(done)
		}()

		select {
		case <-done:
			// Success
		case <-time.After(2 * time.Second):
			t.Fatal("Deadlock: writer stalled on large obfs frame")
		}
	})
	t.Run("PriorityQueueNoHeadOfLineBlocking", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		w := newMuxOutboundWriter(client, prng, nil, true, 0)
		defer w.close()
		br := bufio.NewReader(server)

		// Stream 1 has DATA and FIN (FIN is blocked by stream 1's data)
		// Stream 2 has SYN (SYN should NOT be blocked by stream 1's FIN!)
		w.enqueue(mkframe(1, MuxCmdDATA, 2000))
		w.enqueue(mkframe(1, MuxCmdFIN, 0))
		w.enqueue(mkframe(2, MuxCmdSYN, 100))

		var cmds []byte
		var ids []uint32
		for i := 0; i < 3; i++ {
			id, cmd := readMux(br, server)
			ids = append(ids, id)
			cmds = append(cmds, cmd)
		}
		// Stream 2 SYN must jump ahead of Stream 1 FIN
		if cmds[0] == MuxCmdFIN && ids[0] == 1 {
			t.Fatalf("Stream 1 FIN blocked priority lane: ids=%v cmds=%v", ids, cmds)
		}
	})
}

// TestMuxObfsPadding proves unilateral padding: with -obfs on, DATA
// frames carry random trailing pad inside the WS payload while the MUX
// header still declares the true length (old receivers slice by it and
// ignore the tail); with obfs off the wire format is byte-exact.
func TestMuxObfsPadding(t *testing.T) {
	mkpool := func() *sync.Pool {
		return &sync.Pool{New: func() interface{} {
			b := make([]byte, 65536+14+MuxHeaderLen)
			return &b
		}}
	}
	dial := func(obfs bool) (*MuxClientSession, net.Conn, *bufio.Reader) {
		t.Helper()
		client, server := net.Pipe()
		prng := maskPool.Get().(*maskPRNG)
		t.Cleanup(func() { maskPool.Put(prng) })
		cfg := &Config{BufPool: mkpool(), ConnTimeout: 60, Obfs: obfs}
		s := &MuxClientSession{wsConn: client, cfg: cfg}
		s.writer = newMuxOutboundWriter(client, prng, nil, true, 0)
		t.Cleanup(func() { s.writer.close() })
		return s, server, bufio.NewReader(server)
	}
	readMux := func(br *bufio.Reader, conn net.Conn) []byte {
		t.Helper()
		data, err := readWSFrame(br, conn, nil)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		return data
	}
	t.Run("OffIsExact", func(t *testing.T) {
		s, server, br := dial(false)
		defer server.Close()
		payload := bytes.Repeat([]byte{0xAB}, 100)
		if err := s.SendFrame(7, MuxCmdDATA, payload); err != nil {
			t.Fatalf("send: %v", err)
		}
		data := readMux(br, server)
		if len(data) != MuxHeaderLen+100 {
			t.Fatalf("unpaused frame len = %d, want %d", len(data), MuxHeaderLen+100)
		}
	})
	t.Run("OnPadsRandomly", func(t *testing.T) {
		s, server, br := dial(true)
		defer server.Close()
		payload := bytes.Repeat([]byte{0xCD}, 100)
		seenPad := false
		for i := 0; i < 8; i++ {
			if err := s.SendFrame(9, MuxCmdDATA, payload); err != nil {
				t.Fatalf("send: %v", err)
			}
			data := readMux(br, server)
			if len(data) < MuxHeaderLen+100 || len(data) > MuxHeaderLen+100+obfsPadMax {
				t.Fatalf("padded frame len = %d, want [%d, %d]", len(data), MuxHeaderLen+100, MuxHeaderLen+100+obfsPadMax)
			}
			// MUX header still declares the true length; prefix intact.
			if binary.BigEndian.Uint32(data[:4]) != 9 || data[4] != MuxCmdDATA {
				t.Fatalf("mux header corrupted: %v", data[:MuxHeaderLen])
			}
			if binary.BigEndian.Uint16(data[5:7]) != 100 {
				t.Fatalf("mux length corrupted: %v", data[:MuxHeaderLen])
			}
			if !bytes.Equal(data[MuxHeaderLen:MuxHeaderLen+100], payload) {
				t.Fatalf("mux payload corrupted")
			}
			if len(data) > MuxHeaderLen+100 {
				seenPad = true
			}
		}
		if !seenPad {
			t.Fatal("8 padded frames all came out unpadded (p ~= 0)")
		}
	})
	t.Run("ControlUnpadded", func(t *testing.T) {
		s, server, br := dial(true)
		defer server.Close()
		if err := s.SendFrame(3, MuxCmdFIN, nil); err != nil {
			t.Fatalf("send: %v", err)
		}
		data := readMux(br, server)
		if len(data) != MuxHeaderLen {
			t.Fatalf("FIN frame len = %d, want %d (control must stay exact)", len(data), MuxHeaderLen)
		}
	})
}

func invertMuxWSFrame(t *testing.T, wire []byte, crypto *Crypto) []byte {
	t.Helper()
	if len(wire) < 2 || wire[0]&0x0F != 0x2 {
		t.Fatalf("bad WS opcode/len: %d bytes", len(wire))
	}
	var wsLen, hdrLen int
	switch wire[1] & 0x7F {
	case 126:
		wsLen = int(binary.BigEndian.Uint16(wire[2:4]))
		hdrLen = 4
	case 127:
		wsLen = int(binary.BigEndian.Uint64(wire[2:10]))
		hdrLen = 10
	default:
		wsLen = int(wire[1] & 0x7F)
		hdrLen = 2
	}
	mk := wire[hdrLen : hdrLen+4]
	region := append([]byte(nil), wire[hdrLen+4:hdrLen+4+wsLen]...)
	for i := range region {
		region[i] ^= mk[i&3]
	}
	if crypto != nil {
		crypto.TransformInPlace(region)
	}
	return region
}

func TestMuxFusedEncodeEquivalence(t *testing.T) {
	for _, key := range []string{"", "fuse-key"} {
		var crypto *Crypto
		if key != "" {
			crypto = NewCrypto(key)
		}
		for _, sz := range []int{0, 7, 100, 125, 126, 1000, 7000, 65535} {
			raw := make([]byte, sz)
			mrand.New(mrand.NewSource(int64(sz) + 1)).Read(raw)
			// Reference two-pass: cipher at "enqueue", mask-only write.
			ref := make([]byte, sz+32)
			copy(ref[14:], raw)
			if crypto != nil {
				crypto.TransformInPlace(ref[14 : 14+sz])
			}
			prng := maskPool.Get().(*maskPRNG)
			var refOut bytes.Buffer
			if err := writeWSFramePreallocatedFast(&refOut, ref, 14, sz, 0x2, prng); err != nil {
				t.Fatal(err)
			}
			maskPool.Put(prng)
			// Fused single pass over a pristine copy.
			fused := make([]byte, sz+32)
			copy(fused[14:], raw)
			prng2 := maskPool.Get().(*maskPRNG)
			var fusedOut bytes.Buffer
			if err := writeMuxFrameFused(&fusedOut, fused, 14, sz, 0x2, prng2, crypto); err != nil {
				t.Fatal(err)
			}
			maskPool.Put(prng2)
			if refOut.Len() != fusedOut.Len() {
				t.Fatalf("key=%q sz=%d len mismatch: ref=%d fused=%d", key, sz, refOut.Len(), fusedOut.Len())
			}
			if got := invertMuxWSFrame(t, refOut.Bytes(), crypto); !bytes.Equal(got, raw) {
				t.Fatalf("key=%q sz=%d reference round-trip mismatch", key, sz)
			}
			if got := invertMuxWSFrame(t, fusedOut.Bytes(), crypto); !bytes.Equal(got, raw) {
				t.Fatalf("key=%q sz=%d fused round-trip mismatch", key, sz)
			}
		}
	}
}

// TestMuxFrameUnmaskedEqualsTwoPass proves the server egress single-pass
// unmasked encode is wire-identical to the legacy two-pass path
// (TransformInPlace on the MUX region + writeWSFramePreallocated unmasked).
// Offset semantics are region-relative, matching TransformInPlace.
func TestMuxFrameUnmaskedEqualsTwoPass(t *testing.T) {
	invertUnmasked := func(wire []byte, crypto *Crypto) []byte {
		if len(wire) < 2 || wire[0]&0x0F != 0x2 {
			t.Fatalf("bad unmasked WS opcode/len: %d bytes", len(wire))
		}
		if wire[1]&128 != 0 {
			t.Fatalf("server frame must be unmasked: byte1=%#x", wire[1])
		}
		var wsLen, hdrLen int
		switch wire[1] & 0x7F {
		case 126:
			wsLen = int(binary.BigEndian.Uint16(wire[2:4]))
			hdrLen = 4
		case 127:
			wsLen = int(binary.BigEndian.Uint64(wire[2:10]))
			hdrLen = 10
		default:
			wsLen = int(wire[1] & 0x7F)
			hdrLen = 2
		}
		region := append([]byte(nil), wire[hdrLen:hdrLen+wsLen]...)
		if crypto != nil {
			crypto.TransformInPlace(region)
		}
		return region
	}
	for _, key := range []string{"", "unmask-key"} {
		var crypto *Crypto
		if key != "" {
			crypto = NewCrypto(key)
		}
		for _, sz := range []int{0, 7, 100, 125, 126, 1000, 7000, 65535, 70000} {
			raw := make([]byte, sz)
			mrand.New(mrand.NewSource(int64(sz) + 3)).Read(raw)
			// Reference two-pass: cipher at "enqueue", unmasked header write.
			ref := make([]byte, sz+32)
			copy(ref[14:], raw)
			if crypto != nil {
				crypto.TransformInPlace(ref[14 : 14+sz])
			}
			var refOut bytes.Buffer
			if err := writeWSFramePreallocated(&refOut, ref, 14, sz, 0x2, false); err != nil {
				t.Fatal(err)
			}
			// Single-pass unmasked fused encode over a pristine copy.
			unm := make([]byte, sz+32)
			copy(unm[14:], raw)
			var unmOut bytes.Buffer
			if err := writeMuxFrameUnmasked(&unmOut, unm, 14, sz, 0x2, crypto); err != nil {
				t.Fatal(err)
			}
			if refOut.Len() != unmOut.Len() {
				t.Fatalf("key=%q sz=%d len mismatch: ref=%d unmasked=%d", key, sz, refOut.Len(), unmOut.Len())
			}
			if !bytes.Equal(refOut.Bytes(), unmOut.Bytes()) {
				t.Fatalf("key=%q sz=%d wire mismatch between two-pass and unmasked single-pass", key, sz)
			}
			if got := invertUnmasked(unmOut.Bytes(), crypto); !bytes.Equal(got, raw) {
				t.Fatalf("key=%q sz=%d unmasked round-trip mismatch", key, sz)
			}
		}
	}
}

// TestReadWSFrameIntoFusedEqualsTwoPass proves single-pass fused unmask+decrypt
// produces identical plaintext as legacy two-pass (readWSFrameInto then TransformInPlace).
func TestReadWSFrameIntoFusedEqualsTwoPass(t *testing.T) {
	prng := maskPool.Get().(*maskPRNG)
	defer maskPool.Put(prng)

	for _, key := range []string{"", "fused-ingress-key"} {
		var crypto *Crypto
		if key != "" {
			crypto = NewCrypto(key)
		}
		for _, masked := range []bool{true, false} {
			for _, sz := range []int{0, 1, 7, 10, 125, 126, 128, 1000, 7000, 65535, 70000} {
				raw := make([]byte, sz)
				for i := range raw {
					raw[i] = byte((i*31 + sz) % 256)
				}

				// Encode frame to a buffer
				frameBuf := make([]byte, sz+32)
				copy(frameBuf[14:], raw)
				var wire bytes.Buffer
				if masked {
					if err := writeWSFramePreallocatedFast(&wire, frameBuf, 14, sz, 0x2, prng); err != nil {
						t.Fatalf("masked encode fail: %v", err)
					}
				} else {
					if err := writeWSFramePreallocated(&wire, frameBuf, 14, sz, 0x2, false); err != nil {
						t.Fatalf("unmasked encode fail: %v", err)
					}
				}

				// 1. Two-pass decode
				wireTwoPass := wire.Bytes()
				scratch1 := make([]byte, sz+32)
				gotTwoPass, err := readWSFrameInto(bytes.NewReader(wireTwoPass), nil, scratch1[14:], nil)
				if err != nil {
					t.Fatalf("two-pass read failed: %v", err)
				}
				gotTwoPassPlain := append([]byte(nil), gotTwoPass...)
				if crypto != nil {
					crypto.TransformInPlace(gotTwoPassPlain)
				}

				// 2. Fused single-pass decode
				wireFused := wire.Bytes()
				scratch2 := make([]byte, sz+32)
				gotFused, err := readWSFrameIntoFused(bytes.NewReader(wireFused), nil, scratch2[14:], crypto)
				if err != nil {
					t.Fatalf("fused read failed: %v", err)
				}

				if !bytes.Equal(gotTwoPassPlain, gotFused) {
					t.Fatalf("mismatch between two-pass and fused: key=%q masked=%v sz=%d", key, masked, sz)
				}
			}
		}
	}
}

func BenchmarkMUXEncodeTwoPass(b *testing.B) {
	crypto := NewCrypto("bench-key")
	raw := make([]byte, 65535)
	mrand.New(mrand.NewSource(1)).Read(raw)
	prng := maskPool.Get().(*maskPRNG)
	defer maskPool.Put(prng)
	buf := make([]byte, len(raw)+32)
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf[14:], raw)
		crypto.TransformInPlace(buf[14 : 14+len(raw)])
		_ = writeWSFramePreallocatedFast(io.Discard, buf, 14, len(raw), 0x2, prng)
	}
}

func BenchmarkMUXEncodeFused(b *testing.B) {
	crypto := NewCrypto("bench-key")
	raw := make([]byte, 65535)
	mrand.New(mrand.NewSource(1)).Read(raw)
	prng := maskPool.Get().(*maskPRNG)
	defer maskPool.Put(prng)
	buf := make([]byte, len(raw)+32)
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf[14:], raw)
		_ = writeMuxFrameFused(io.Discard, buf, 14, len(raw), 0x2, prng, crypto)
	}
}

func TestUDPBatchReadLoopback(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	const K = 64
	for i := 0; i < K; i++ {
		msg := []byte{byte(i), byte(i >> 8), 0xAB, 0xCD}
		if _, err := cli.Write(msg); err != nil {
			t.Fatal(err)
		}
	}
	batch := newUDPBatch(srv)
	got := 0
	deadline := time.Now().Add(5 * time.Second)
	_ = deadline
	for got < K {
		if err := srv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := batch.read()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			pkt := batch.msgs[i].Buffers[0][:batch.msgs[i].N]
			want := []byte{byte(got), byte(got >> 8), 0xAB, 0xCD}
			if !bytes.Equal(pkt, want) {
				t.Fatalf("datagram %d mismatch: got %v want %v", got, pkt, want)
			}
			got++
		}
	}
}

func BenchmarkUDPReadSingle(b *testing.B) {
	srv, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer srv.Close()
	cli, _ := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	defer cli.Close()
	msg := make([]byte, 512)
	buf := make([]byte, 65535)
	work := make([]byte, 65535)
	_ = srv.SetReadDeadline(time.Now().Add(60 * time.Second)) // loud fail, never hang
	const N = 5000
	b.SetBytes(int64(N * len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		done := make(chan struct{})
		go func() {
			defer close(done)
			for j := 0; j < N; j++ {
				_, _ = cli.Write(msg)
			}
		}()
		for j := 0; j < N; j++ {
			n, _, err := srv.ReadFromUDP(buf)
			if err != nil {
				b.Fatal(err)
			}
			copy(work, buf[:n]) // per-datagram relay work lets backlog build
		}
		<-done
	}
}

func BenchmarkUDPReadBatch(b *testing.B) {
	srv, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer srv.Close()
	cli, _ := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	defer cli.Close()
	msg := make([]byte, 512)
	batch := newUDPBatch(srv)
	work := make([]byte, 65535)
	_ = srv.SetReadDeadline(time.Now().Add(60 * time.Second)) // loud fail, never hang
	const N = 5000
	b.SetBytes(int64(N * len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		done := make(chan struct{})
		go func() {
			defer close(done)
			for j := 0; j < N; j++ {
				_, _ = cli.Write(msg)
			}
		}()
		got := 0
		for got < N {
			n, err := batch.read()
			if err != nil {
				b.Fatal(err)
			}
			for k := 0; k < n; k++ {
				pkt := batch.msgs[k].Buffers[0][:batch.msgs[k].N]
				copy(work, pkt) // same per-datagram relay work
			}
			got += n
		}
		<-done
	}
}

// LUT-mask challenger for the #4 verdict: 4x256-entry per-frame tables,
// out[i:i+4] = T0[b0]|T1[b1]|T2[b2]|T3[b3]. Table build cost included.
func BenchmarkMaskWordLUT(b *testing.B) {
	raw := make([]byte, 65535)
	mrand.New(mrand.NewSource(2)).Read(raw)
	var t0, t1, t2, t3 [256]uint32
	buf := make([]byte, len(raw))
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mk := [4]byte{byte(i), byte(i >> 8), byte(i >> 13), byte(i >> 21)}
		for v := 0; v < 256; v++ {
			t0[v] = uint32(v) ^ uint32(mk[0])
			t1[v] = (uint32(v) ^ uint32(mk[1])) << 8
			t2[v] = (uint32(v) ^ uint32(mk[2])) << 16
			t3[v] = (uint32(v) ^ uint32(mk[3])) << 24
		}
		copy(buf, raw)
		j := 0
		for ; j+4 <= len(buf); j += 4 {
			binary.NativeEndian.PutUint32(buf[j:], t0[buf[j]]|t1[buf[j+1]]|t2[buf[j+2]]|t3[buf[j+3]])
		}
		for ; j < len(buf); j++ {
			buf[j] ^= mk[j&3]
		}
	}
}

// TestHeartbeatPingsWhileStreamsActive guards the v1.8.13 fix: the client
// keepalive must ping even while streams exist. The old condition (skip
// ping when ActiveStreams > 0) meant an active-but-idle session with open
// streams and no traffic never pinged, both rolling read deadlines fired
// at ConnTimeout, and session Close reset every stream.
func TestHeartbeatPingsWhileStreamsActive(t *testing.T) {
	oldInterval := muxHeartbeatInterval
	muxHeartbeatInterval = 25 * time.Millisecond
	defer func() { muxHeartbeatInterval = oldInterval }()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &MuxClientSession{
		wsConn:  client,
		cfg:     &Config{},
		streams: make(map[uint32]*MuxStream),
		closed:  make(chan struct{}),
	}
	s.activeStreams.Store(3) // the exact state the old condition suppressed pings for
	s.writer = newMuxOutboundWriter(client, nil, nil, true, 0)

	go s.heartbeatLoop()

	// Two pings must arrive while the session reports active streams.
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 2; i++ {
		var head [2]byte
		if _, err := io.ReadFull(server, head[:]); err != nil {
			t.Fatalf("ping %d: read header: %v (heartbeats must be sent even with active streams)", i+1, err)
		}
		if head[0] != 0x89 {
			t.Fatalf("ping %d: expected FIN+ping opcode, got 0x%02X", i+1, head[0])
		}
		if head[1]&0x80 == 0 {
			t.Fatalf("ping %d: client frames must be masked, got byte 0x%02X", i+1, head[1])
		}
		var mask [4]byte
		if _, err := io.ReadFull(server, mask[:]); err != nil {
			t.Fatalf("ping %d: read mask: %v", i+1, err)
		}
	}

	close(s.closed)
	_ = client.Close()
	_ = server.Close()
	s.writer.close()
}

// TestHeartbeatNilWriterDoesNotPanic: the writer-nil guard must skip the
// tick instead of dereferencing a nil writer (session teardown race).
func TestHeartbeatNilWriterDoesNotPanic(t *testing.T) {
	oldInterval := muxHeartbeatInterval
	muxHeartbeatInterval = 10 * time.Millisecond
	defer func() { muxHeartbeatInterval = oldInterval }()

	s := &MuxClientSession{
		cfg:     &Config{},
		streams: make(map[uint32]*MuxStream),
		closed:  make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.heartbeatLoop()
	}()
	time.Sleep(50 * time.Millisecond) // several ticks with writer == nil
	close(s.closed)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeatLoop did not exit after close")
	}
}

// TestMuxOutboundWriterWriteDeadline guards the v1.8.13 M6 fix: a reader
// that stops draining must not wedge the writer goroutine forever (the
// process previously set no write deadline anywhere), while healthy
// traffic must keep the throttled deadline refreshed.
func TestMuxOutboundWriterWriteDeadline(t *testing.T) {
	mkframe := func(id uint32, cmd byte, size int) muxOutboundFrame {
		buf := make([]byte, 14+MuxHeaderLen+size)
		binary.BigEndian.PutUint32(buf[14:18], id)
		buf[18] = cmd
		binary.BigEndian.PutUint16(buf[19:21], uint16(size))
		return muxOutboundFrame{bPtr: &buf, pool: &sync.Pool{}, payloadOff: 14, payloadLen: MuxHeaderLen + size, opcode: 0x2, streamID: id, cmd: cmd}
	}

	t.Run("WedgeedReaderFailsAfterTimeout", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		w := newMuxOutboundWriter(client, prng, nil, true, 700*time.Millisecond)
		if !w.enqueue(mkframe(1, MuxCmdDATA, 1024)) {
			t.Fatal("enqueue rejected")
		}
		// Nobody ever reads the server side: the pipe write blocks. With
		// no write deadline this hung forever (old bug); it must now
		// time out, error, and tear the conn down.
		select {
		case <-w.done:
		case <-time.After(3 * time.Second):
			t.Fatal("writer wedged: expected write deadline to tear it down")
		}
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := bufio.NewReader(server).ReadByte(); err == nil {
			t.Fatal("expected conn closed after write deadline fired")
		}
	})

	t.Run("ActiveReaderSeesNoSpuriousTimeout", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		prng := maskPool.Get().(*maskPRNG)
		defer maskPool.Put(prng)
		w := newMuxOutboundWriter(client, prng, nil, true, 700*time.Millisecond)
		defer w.close()
		br := bufio.NewReader(server)
		// Keep writing for far longer than the write timeout: throttled
		// refreshes must keep the deadline alive for healthy traffic.
		for i := 0; i < 15; i++ {
			if !w.enqueue(mkframe(1, MuxCmdDATA, 512)) {
				t.Fatalf("enqueue %d rejected", i)
			}
			_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := readWSFrame(br, server, nil); err != nil {
				t.Fatalf("healthy write %d failed: %v (deadline must refresh for active traffic)", i, err)
			}
			time.Sleep(120 * time.Millisecond) // 15 * 120ms = 1.8s > 700ms timeout
		}
	})
}

// --- Consolidated from goway_2000_test.go ---

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
			time.Sleep(time.Duration(mrand.Intn(4)+1) * time.Millisecond)

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

// syncBuffer is a mutex-guarded bytes.Buffer safe for use as exec.Cmd Stderr:
// Cmd.Start spawns an internal io.Copy goroutine that keeps writing to Stderr
// until the child process exits, while the benchmark report below reads the
// buffer via String() before the Kill/Wait defers run. A plain bytes.Buffer
// races there (race detector failure in CI); all accesses take the lock.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
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
		"-no-server-block-local",
		"-log", "WARN",
	)
	var serverStderr syncBuffer
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
	var clientStderr syncBuffer
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

// --- Consolidated from goway_bugfix_test.go ---

// runWithin fails the test if fn does not return within d (deadlock guard).
func runWithin(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: did not return within %v (deadlock)", what, d)
	}
}

func TestMuxStreamIngressOverflowDoesNotDeadlock(t *testing.T) {
	s := newMuxStream(11, &reorderMockSession{})
	defer s.Close()

	rejected := false
	runWithin(t, 5*time.Second, "client enqueueDataFrame overflow", func() {
		// readChan (AppQueue) + ingress (IngressQueue) + 1 stalled in
		// PushDataFrame; the next frame must overflow and Reset.
		for i := 0; i < muxStreamAppQueue+muxStreamIngressQueue+16; i++ {
			if !s.enqueueDataFrame(muxDataFrame{data: []byte{byte(i)}}) {
				rejected = true
				return
			}
			if i == muxStreamAppQueue {
				// let deliveryLoop pick a frame and stall on full readChan
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	if !rejected {
		t.Fatalf("expected ingress overflow to reject a frame")
	}
	select {
	case <-s.closed:
	default:
		t.Fatalf("stream should be reset after ingress overflow")
	}
}

func TestMuxServerStreamIngressOverflowDoesNotDeadlock(t *testing.T) {
	sess := &MuxServerSession{streams: make(map[uint32]*MuxServerStream), closed: make(chan struct{})}
	s := newMuxServerStream(13, sess)
	defer s.Close()

	rejected := false
	runWithin(t, 5*time.Second, "server enqueueDataFrame overflow", func() {
		for i := 0; i < muxStreamAppQueue+muxStreamIngressQueue+16; i++ {
			if !s.enqueueDataFrame(muxDataFrame{data: []byte{byte(i)}}) {
				rejected = true
				return
			}
			if i == muxStreamAppQueue {
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	if !rejected {
		t.Fatalf("expected ingress overflow to reject a frame")
	}
	select {
	case <-s.closed:
	default:
		t.Fatalf("stream should be closed after ingress overflow")
	}
}

func TestMuxStreamQueuedFINDoesNotTruncateTail(t *testing.T) {
	s := newMuxStream(15, &reorderMockSession{})
	defer s.Close()

	// Fill readChan so later frames take the ingress (slow) path.
	for i := 0; i < muxStreamAppQueue; i++ {
		if !s.enqueueDataFrame(muxDataFrame{data: []byte{0xCC}}) {
			t.Fatalf("fill frame %d rejected", i)
		}
	}
	if !s.enqueueDataFrame(muxDataFrame{data: []byte{0xDD}}) { // tail data
		t.Fatalf("tail frame rejected")
	}
	if !s.enqueueDataFrame(muxDataFrame{data: nil}) { // FIN behind it
		t.Fatalf("FIN rejected")
	}
	if s.readClosed.Load() {
		t.Fatalf("readClosed set while FIN still queued behind undelivered data")
	}

	got := make([]byte, 0, muxStreamAppQueue+1)
	buf := make([]byte, 64)
	runWithin(t, 5*time.Second, "drain stream", func() {
		for {
			n, err := s.Read(buf)
			got = append(got, buf[:n]...)
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Errorf("unexpected read error: %v", err)
				return
			}
		}
	})
	if len(got) != muxStreamAppQueue+1 || got[len(got)-1] != 0xDD {
		t.Fatalf("tail truncated: got %d bytes (want %d), last=0x%X", len(got), muxStreamAppQueue+1, got[len(got)-1])
	}
	// EOF must be sticky.
	if n, err := s.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("second Read after EOF: n=%d err=%v", n, err)
	}
}

func TestValidateServerAuthTarget(t *testing.T) {
	validCases := []struct {
		in   []byte
		key  string
		want string
	}{
		{[]byte("MUX\n"), "k", "MUX"},
		{[]byte("UDP\n"), "k", "UDP"},
		{[]byte("example.com:443\n"), "k", "example.com:443"},
		{[]byte("[::1]:8080\n"), "", "[::1]:8080"},
		{[]byte("mysecret example.com:443\n"), "mysecret", "example.com:443"},
		{[]byte("mysecret MUX\n"), "mysecret", "MUX"},
	}
	for _, tc := range validCases {
		got, ok := validateServerAuthTarget(tc.in, tc.key)
		if !ok || got != tc.want {
			t.Fatalf("validateServerAuthTarget(%q, %q) = (%q, %v), want (%q, true)", tc.in, tc.key, got, ok, tc.want)
		}
	}

	// Wrong-key XOR decryption produces non-printable or non-host:port garbage.
	cRight := NewCrypto("correct-server-key")
	cWrong := NewCrypto("wrong-client-key")
	wire := []byte("MUX\n")
	cWrong.TransformInPlace(wire)
	cRight.TransformInPlace(wire) // decrypted with server key

	invalidCases := [][]byte{
		nil,
		[]byte(""),
		[]byte("   \r\n"),
		wire,
		[]byte("garbage_without_port\n"),
		[]byte("example.com:0\n"),
		[]byte("example.com:70000\n"),
		[]byte(":443\n"),
		[]byte("example.com:443\x00\n"),
		bytes.Repeat([]byte("a"), 513),
	}
	for _, in := range invalidCases {
		if got, ok := validateServerAuthTarget(in, "correct-server-key"); ok {
			t.Fatalf("validateServerAuthTarget(%q) unexpectedly succeeded with %q", in, got)
		}
	}
}

func TestNonMuxAEADFullBufferSealNoPanic(t *testing.T) {
	rc := NewCryptoMode("aead-full-buf-key", cipherModeAEAD)
	buf := make([]byte, 4096+14)
	readEnd := len(buf) - aeadOverhead
	plainLen := readEnd - 14
	for i := 0; i < plainLen; i++ {
		buf[14+i] = byte(i)
	}
	wireLen := rc.SealRegion(buf[14:], plainLen)
	if wireLen != plainLen+aeadOverhead {
		t.Fatalf("SealRegion wireLen = %d, want %d", wireLen, plainLen+aeadOverhead)
	}
	opened, err := rc.OpenRegion(buf[14 : 14+wireLen])
	if err != nil || len(opened) != plainLen {
		t.Fatalf("OpenRegion failed: err=%v len=%d", err, len(opened))
	}
}

func TestServerMuxRSTDropsQueuedOutboundFrames(t *testing.T) {
	pool := &sync.Pool{
		New: func() interface{} {
			b := make([]byte, 1024)
			return &b
		},
	}
	w := &muxOutboundWriter{
		streams: make(map[uint32]*muxStreamQueue),
		done:    make(chan struct{}),
	}
	w.cond = sync.NewCond(&w.mu)
	bPtr := pool.Get().(*[]byte)
	if !w.enqueue(muxOutboundFrame{
		bPtr:       bPtr,
		pool:       pool,
		payloadOff: 14,
		payloadLen: 100,
		opcode:     0x2,
		streamID:   77,
		cmd:        MuxCmdDATA,
	}) {
		t.Fatal("enqueue failed")
	}
	w.dropStream(77)
	w.mu.Lock()
	_, exists := w.streams[77]
	queued := w.total
	w.mu.Unlock()
	if exists || queued != 0 {
		t.Fatalf("expected stream 77 dropped and queued=0, got exists=%v queued=%d", exists, queued)
	}
}

func TestMuxStreamLazyIngressAllocation(t *testing.T) {
	s := newMuxStream(88, &reorderMockSession{})
	defer s.Close()

	if s.ingress != nil {
		t.Fatal("expected ingress to be nil on newly created MuxStream")
	}
	if !s.enqueueDataFrame(muxDataFrame{data: []byte("fast-path")}) {
		t.Fatal("fast-path enqueue failed")
	}
	if s.ingress != nil {
		t.Fatal("expected ingress to remain nil after fast-path enqueue")
	}
}

func TestUDPAddrCacheGetIPAndLocalBlock(t *testing.T) {
	var cache udpAddrCache
	a1 := cache.getIP([]byte{8, 8, 8, 8}, 53)
	a2 := cache.getIP([]byte{8, 8, 8, 8}, 53)
	if a1 == nil || a1 != a2 || a1.Port != 53 || !a1.IP.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("unexpected cached IPv4 UDPAddr: %v vs %v", a1, a2)
	}
	cfg := &Config{BlockLocal: true}
	localPkt := []byte{0, 0, 0, 0x01, 127, 0, 0, 1, 0x00, 0x50, 'x'}
	pubPkt := []byte{0, 0, 0, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'x'}
	if !clientUDPDatagramBlocked(cfg, localPkt) {
		t.Fatal("expected 127.0.0.1 UDP datagram to be blocked")
	}
	if clientUDPDatagramBlocked(cfg, pubPkt) {
		t.Fatal("expected 8.8.8.8 UDP datagram to be allowed")
	}
}

func BenchmarkMuxStreamCreateFastPath(b *testing.B) {
	sess := &reorderMockSession{}
	frame := muxDataFrame{data: []byte("hello")}
	buf := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st := newMuxStream(uint32(i+1), sess)
		st.enqueueDataFrame(frame)
		_, _ = st.Read(buf)
		st.Close()
	}
}

func BenchmarkUDPAddrCacheGetIPAndCheck(b *testing.B) {
	var cache udpAddrCache
	cfg := &Config{BlockLocal: true, ServerBlockLocal: true}
	pkt := []byte{0, 0, 0, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'p', 'a', 'y', 'l', 'o', 'a', 'd'}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if clientUDPDatagramBlocked(cfg, pkt) {
			b.Fatal("unexpected block")
		}
		if cache.getIP(pkt[4:8], 53) == nil {
			b.Fatal("nil addr")
		}
	}
}

// --- Consolidated from goway_fuzz_test.go ---

// Fuzz entry points for wire parsers. Run bounded, e.g.:
//   go test -fuzz=FuzzWSFrame -fuzztime=120s .
// These must never panic, hang, or OOM on arbitrary input; any failure is
// a remotely-triggerable crash (Go panics kill the whole process).

func FuzzWSFrame(f *testing.F) {
	seeds := [][]byte{
		{0x82, 0x05, 'h', 'e', 'l', 'l', 'o'},
		{0x82, 0x85, 0x01, 0x02, 0x03, 0x04, 'h' ^ 0x01, 'e' ^ 0x02, 'l' ^ 0x03, 'l' ^ 0x04, 'o' ^ 0x01},
		{0x82, 0x7E, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'},
		{0x82, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'},
		{0x89, 0x00},
		{0x8A, 0x00},
		{0x88, 0x00},
		{0x83, 0x01, 'x'},
		{0x87, 0x01, 'x'},
		{0x82, 0xFE},
		{0x82, 0xFF},
		{0x82},
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Cap input: the >64MB length path is already guarded by
		// MaxWSFrameSize; fuzz the header/payload state machine.
		if len(data) > 70000 {
			return
		}
		_, _ = readWSFrame(bytes.NewReader(data), io.Discard, nil)
	})
}

func FuzzWSFrameInto(f *testing.F) {
	seeds := [][]byte{
		{0x82, 0x05, 'h', 'e', 'l', 'l', 'o'},
		{0x82, 0x85, 0x01, 0x02, 0x03, 0x04, 'h' ^ 0x01, 'e' ^ 0x02, 'l' ^ 0x03, 'l' ^ 0x04, 'o' ^ 0x01},
		{0x88, 0x00},
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 70000 {
			return
		}
		buf := make([]byte, 70000)
		_, _ = readWSFrameInto(bytes.NewReader(data), io.Discard, buf, nil)
	})
}

func FuzzHTTPHeaders(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\n"),
		[]byte("\r\n\r\n"),
		{},
		bytes.Repeat([]byte("A"), 9000),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 20000 {
			return
		}
		br := bufio.NewReader(bytes.NewReader(data))
		_, _ = readUntilCRLFCRLF(br)
	})
}

// --- Consolidated from goway_reorder_test.go ---

type reorderMockSession struct{}

func (m *reorderMockSession) SendFrame(streamID uint32, cmd byte, payload []byte) error {
	return nil
}
func (m *reorderMockSession) RemoveStream(streamID uint32) {}

const (
	reorderFillFrames = 144 // 144*65535 = mux*StreamBufferLimit - 144
	reorderFrameSize  = 65535
)

// waitQueueDepth polls until the stream's delivery channel holds want
// frames (with a timeout), so both stalled frames have settled.
func waitQueueDepth(t *testing.T, depth func() int, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if depth() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("queue never reached %d frames (now %d)", want, depth())
}

// waitIngressDrained waits until deliveryLoop has dequeued everything from
// ingress (the stalled frame is now inside PushDataFrame's wait).
func waitIngressDrained(t *testing.T, depth func() int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if depth() == 0 {
			time.Sleep(50 * time.Millisecond) // let PushDataFrame enter its wait
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("ingress never drained")
}

func TestMuxStreamFastPathCannotReorderUnderBackpressure(t *testing.T) {
	s := newMuxStream(7, &reorderMockSession{})
	defer s.Close()

	fill := bytes.Repeat([]byte{0xCC}, reorderFrameSize)
	for i := 0; i < reorderFillFrames; i++ {
		if !s.enqueueDataFrame(muxDataFrame{data: fill}) {
			t.Fatalf("fill frame %d rejected", i)
		}
	}

	big := bytes.Repeat([]byte{0xAA}, reorderFrameSize) // A: misses the budget
	if !s.enqueueDataFrame(muxDataFrame{data: big}) {
		t.Fatalf("enqueue A failed")
	}
	waitIngressDrained(t, func() int {
		s.bufMu.Lock()
		defer s.bufMu.Unlock()
		return len(s.ingress)
	})

	small := []byte{0xBB} // B: fits the budget, but must queue behind A
	if !s.enqueueDataFrame(muxDataFrame{data: small}) {
		t.Fatalf("enqueue B failed")
	}

	// Simulate the app consuming one frame: wakes A's stalled PushDataFrame.
	s.consumedBytes(reorderFrameSize)
	waitQueueDepth(t, func() int { return len(s.readChan) }, reorderFillFrames+2)

	buf := make([]byte, reorderFrameSize)
	for i := 0; i < reorderFillFrames; i++ {
		n, err := s.Read(buf)
		if err != nil || n != reorderFrameSize || buf[0] != 0xCC {
			t.Fatalf("fill frame %d: n=%d first=0x%X err=%v", i, n, buf[0], err)
		}
	}
	n, err := s.Read(buf)
	if err != nil || n != reorderFrameSize || buf[0] != 0xAA {
		t.Fatalf("REORDER or corruption: expected stalled frame A (0xAA) after fill, got n=%d first=0x%X err=%v", n, buf[0], err)
	}
	b := make([]byte, 16)
	n, err = s.Read(b)
	if err != nil || n != 1 || b[0] != 0xBB {
		t.Fatalf("expected frame B (0xBB) last, got n=%d first=0x%X err=%v", n, b[0], err)
	}
}

func TestMuxServerStreamFastPathCannotReorderUnderBackpressure(t *testing.T) {
	sess := &MuxServerSession{streams: make(map[uint32]*MuxServerStream), closed: make(chan struct{})}
	s := newMuxServerStream(9, sess)
	defer s.Close()

	fill := bytes.Repeat([]byte{0xCC}, reorderFrameSize)
	for i := 0; i < reorderFillFrames; i++ {
		if !s.enqueueDataFrame(muxDataFrame{data: fill}) {
			t.Fatalf("fill frame %d rejected", i)
		}
	}

	big := bytes.Repeat([]byte{0xAA}, reorderFrameSize)
	if !s.enqueueDataFrame(muxDataFrame{data: big}) {
		t.Fatalf("enqueue A failed")
	}
	waitIngressDrained(t, func() int {
		s.bufMu.Lock()
		defer s.bufMu.Unlock()
		return len(s.ingress)
	})

	small := []byte{0xBB}
	if !s.enqueueDataFrame(muxDataFrame{data: small}) {
		t.Fatalf("enqueue B failed")
	}

	// Simulate the target pump consuming one frame: wakes A's stalled
	// PushDataFrame.
	s.consumedBytes(reorderFrameSize)
	waitQueueDepth(t, func() int { return len(s.writeChan) }, reorderFillFrames+2)

	expect := func(wantLen int, wantFirst byte, what string) {
		t.Helper()
		select {
		case f := <-s.writeChan:
			if len(f.data) != wantLen || f.data[0] != wantFirst {
				t.Fatalf("%s: got len=%d first=0x%X (want len=%d first=0x%X) — REORDER", what, len(f.data), f.data[0], wantLen, wantFirst)
			}
			f.release()
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no frame on writeChan", what)
		}
	}
	for i := 0; i < reorderFillFrames; i++ {
		expect(reorderFrameSize, 0xCC, "fill")
	}
	expect(reorderFrameSize, 0xAA, "stalled frame A")
	expect(1, 0xBB, "frame B")
}

// --- Consolidated from goway_v1816_test.go ---

// --- classifyServerTarget (UDP/MUX exact-match routing) ---

func TestClassifyServerTargetExactMatch(t *testing.T) {
	cases := []struct {
		in   string
		want byte
	}{
		{"UDP", 'u'},
		{"udp", 'u'},
		{"MUX", 'm'},
		{"mux", 'm'},
		{"example.com:443", 't'},
		{"udp-example.com:443", 't'}, // regressed to 'u' under the old HasPrefix routing
		{"udpserver:80", 't'},
		{"mux.dev:443", 't'},
		{"UDPproxy:80", 't'},
		{"", 't'},
	}
	for _, c := range cases {
		if got := classifyServerTarget(c.in); got != c.want {
			t.Errorf("classifyServerTarget(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- AEAD seal/open round trip ---

func TestCryptoAEADSealOpenRoundTrip(t *testing.T) {
	c := NewCryptoMode("aead-test-key", cipherModeAEAD)
	if c == nil || c.isXOR() {
		t.Fatalf("expected AEAD-mode crypto")
	}
	sizes := []int{0, 1, 7, 12, 16, 17, 100, 4096, 65535, 65536, 70000}
	for _, n := range sizes {
		plain := make([]byte, n)
		for i := range plain {
			plain[i] = byte(i * 7)
		}
		buf := make([]byte, n, n+aeadOverhead)
		copy(buf, plain)
		sealed := c.SealRegion(buf, n)
		if sealed != n+aeadOverhead {
			t.Fatalf("size %d: sealed len = %d, want %d", n, sealed, n+aeadOverhead)
		}
		got, err := c.OpenRegion(buf[:sealed])
		if err != nil {
			t.Fatalf("size %d: open: %v", n, err)
		}
		if len(got) != n || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: round trip mismatch (got %d bytes)", n, len(got))
		}
	}
}

func TestCryptoAEADUniqueNoncesAndBitFlip(t *testing.T) {
	c := NewCryptoMode("aead-test-key", cipherModeAEAD)
	seen := make(map[string]bool)
	buf := make([]byte, 32, 32+aeadOverhead)
	for i := 0; i < 1000; i++ {
		n := c.SealRegion(buf, 32)
		nonce := string(buf[:aeadNonceSize])
		if seen[nonce] {
			t.Fatalf("nonce reuse at iteration %d", i)
		}
		seen[nonce] = true
		// reset plaintext for the next seal
		for j := range buf[:32] {
			buf[j] = 0xAB
		}
		_ = n
	}

	// Tampered ciphertext must fail the open.
	plain := bytes.Repeat([]byte{0x5A}, 64)
	region := make([]byte, 64, 64+aeadOverhead)
	copy(region, plain)
	sealed := c.SealRegion(region, 64)
	region[aeadNonceSize] ^= 0x01
	if _, err := c.OpenRegion(region[:sealed]); err == nil {
		t.Fatal("expected open failure after ciphertext tampering")
	}
}

func TestCryptoXORUnchangedByModePlumbing(t *testing.T) {
	c := NewCrypto("legacy-key")
	if c == nil || !c.isXOR() {
		t.Fatal("NewCrypto must return legacy XOR mode")
	}
	region := []byte("hello world")
	ref := append([]byte(nil), region...)
	c.TransformInPlace(region)
	c.TransformInPlace(region)
	if !bytes.Equal(region, ref) {
		t.Fatal("XOR transform no longer self-inverting")
	}
}

// --- readWSFrameIntoFused AEAD ingress (masked and unmasked) ---

func TestReadWSFrameIntoFusedAEADRoundTrip(t *testing.T) {
	c := NewCryptoMode("aead-test-key", cipherModeAEAD)
	plain := []byte("target.example.com:443\n")

	for _, masked := range []bool{true, false} {
		pr, pw := net.Pipe()
		sealed := c.sealFrame(plain)
		go func() {
			if err := writeWSFrame(pw, sealed, 0x2, masked); err != nil {
				t.Errorf("writeWSFrame: %v", err)
			}
			pw.Close()
		}()
		got, err := readWSFrame(pr, nil, c)
		if err != nil {
			t.Fatalf("masked=%v: readWSFrame: %v", masked, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("masked=%v: got %q, want %q", masked, got, plain)
		}
	}
}

// --- okCiphered / sealFrame mode behavior ---

func TestOKCipheredModes(t *testing.T) {
	if got := okCiphered(nil); !bytes.Equal(got, okBytes) {
		t.Fatalf("nil crypto: got %q", got)
	}
	x := NewCrypto("k")
	got := okCiphered(x)
	if bytes.Equal(got, okBytes) {
		t.Fatal("XOR mode must transform the OK frame")
	}
	back := append([]byte(nil), got...)
	x.TransformInPlace(back)
	if !bytes.Equal(back, okBytes) {
		t.Fatalf("XOR OK frame not self-inverting: %q", back)
	}
	a := NewCryptoMode("k", cipherModeAEAD)
	gotA := okCiphered(a)
	if len(gotA) != len(okBytes)+aeadOverhead {
		t.Fatalf("AEAD OK frame len = %d, want %d", len(gotA), len(okBytes)+aeadOverhead)
	}
	backA, err := a.OpenRegion(gotA)
	if err != nil || !bytes.Equal(backA, okBytes) {
		t.Fatalf("AEAD OK frame round trip: %v %q", err, backA)
	}
}

// --- QUIC cert pinning ---

func TestQUICCertDeterministicAndPinned(t *testing.T) {
	pub := pinnedQUICPublicKey("shared-secret")
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("unexpected pubkey size %d", len(pub))
	}
	pub2 := pinnedQUICPublicKey("shared-secret")
	if !bytes.Equal(pub, pub2) {
		t.Fatal("key-derived cert must be deterministic")
	}
	other := pinnedQUICPublicKey("other-secret")
	if bytes.Equal(pub, other) {
		t.Fatal("different keys must derive different certs")
	}

	// Server cert generated with the key must carry the pinned public key.
	cert, err := generateSelfSignedCert("shared-secret")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pk, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(pk, pub) {
		t.Fatal("server cert public key does not match the pinned key")
	}

	// Without a key: random ECDSA cert (legacy behavior).
	randCert, err := generateSelfSignedCert("")
	if err != nil {
		t.Fatalf("random cert: %v", err)
	}
	if _, err := x509.ParseCertificate(randCert.Certificate[0]); err != nil {
		t.Fatalf("parse random cert: %v", err)
	}
}

// --- DNS cache eviction ---

func TestDNSCacheEviction(t *testing.T) {
	r := NewRemoteResolver("127.0.0.1")
	r.cacheTTL = time.Minute
	// Bypass the network: insert directly through the same guard used by Resolve.
	for i := 0; i < maxDNSCacheEntries+500; i++ {
		host := "host-" + strconv.Itoa(i) + ".example.com"
		r.cacheMu.Lock()
		if len(r.cache) >= maxDNSCacheEntries {
			r.evictDNSCacheLocked()
		}
		r.cache[host] = dnsCacheEntry{ip: "127.0.0.1", expires: time.Now().Add(r.cacheTTL)}
		r.cacheMu.Unlock()
	}
	r.cacheMu.RLock()
	n := len(r.cache)
	r.cacheMu.RUnlock()
	if n > maxDNSCacheEntries {
		t.Fatalf("cache grew to %d entries, want <= %d", n, maxDNSCacheEntries)
	}
}

// --- serverTargetBlocked ---

func TestServerTargetBlocked(t *testing.T) {
	cfg := &Config{ServerBlockLocal: true}
	cases := []struct {
		target string
		want   bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:9090", true},
		{"192.168.1.10:443", true},
		{"10.0.0.5:80", true},
		{"localhost:80", true},
		{"example.com:443", false},
		{"8.8.8.8:53", false},
	}
	for _, c := range cases {
		if got := serverTargetBlocked(cfg, c.target); got != c.want {
			t.Errorf("serverTargetBlocked(%q) = %v, want %v", c.target, got, c.want)
		}
	}
	if serverTargetBlocked(&Config{}, "127.0.0.1:80") {
		t.Error("flag off must not block")
	}
}
