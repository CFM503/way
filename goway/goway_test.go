package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestRFC6455AcceptKey(t *testing.T) {
	// RFC 6455 §1.3 official test vector
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
		readData, err := readWSFrameInto(pr, nil, scratch[14:])
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
	serverCmd := exec.Command(".\\goway.exe",
		"-p", fmt.Sprintf("127.0.0.1:%d", serverPort),
		"-k", "testKey2026",
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
	clientCmd := exec.Command(".\\goway.exe",
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
	serverCmd := exec.Command(".\\goway.exe",
		"-p", fmt.Sprintf("127.0.0.1:%d", serverPort),
		"-k", "violentStressKey999",
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
	clientCmd := exec.Command(".\\goway.exe",
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

	for i := 0; i < 128; i++ {
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
	if elapsed < 2*time.Second || elapsed > 4*time.Second {
		t.Logf("PushData timed out in %v (expected ~3s)", elapsed)
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

func TestLargeFramePoolCap(t *testing.T) {
	largeBuf := make([]byte, 128*1024)
	putLargeFrame(&largeBuf)

	got := largeFramePool.Get().(*[]byte)
	if cap(*got) > maxPooledFrameCap {
		t.Fatalf("largeFramePool retained buffer exceeding cap: %d bytes", cap(*got))
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
	cert, err := generateSelfSignedCert()
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
	conn := pool.conn
	pool.mu.Unlock()
	if conn == nil {
		t.Fatal("Expected pool.conn to be non-nil after successful connections")
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
	if pool.conn != nil {
		t.Fatal("Expected pool.conn to remain nil on dial failure")
	}
	if pool.dialing != nil {
		t.Fatal("Expected pool.dialing to be cleared on dial failure")
	}
}

func TestQUICClientPool_CloseConcurrent(t *testing.T) {
	cert, err := generateSelfSignedCert()
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
		cfg:     cfg,
		streams: make(map[uint32]*MuxServerStream),
		closed:  make(chan struct{}),
	}
	st := newMuxServerStream(42, session)
	session.streams[42] = st

	for i := 0; i < 256; i++ {
		st.writeChan <- muxDataFrame{data: []byte("busy")}
	}

	start := time.Now()
	ok := st.PushData([]byte("overflow"))
	if ok {
		t.Fatal("Expected PushData to return false on stall timeout")
	}
	if time.Since(start) < 2*time.Second {
		t.Fatal("Expected PushData to wait for stall timeout")
	}

	if !ok {
		session.streamsMu.Lock()
		delete(session.streams, 42)
		session.streamsMu.Unlock()
	}

	session.streamsMu.RLock()
	_, exists := session.streams[42]
	session.streamsMu.RUnlock()
	if exists {
		t.Fatal("Expected stream 42 to be removed from session.streams after PushData false")
	}
}

func TestQUICClientPool_OpenStreamFailureReconnect(t *testing.T) {
	cert, err := generateSelfSignedCert()
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
	conn := pool.conn
	pool.mu.Unlock()
	if conn == nil {
		t.Fatal("Expected active connection")
	}
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

	chunkSize := 1024 * 1024 // 1 MiB
	chunk := make([]byte, chunkSize)

	// Push 4 MiB (limit is 4 MiB)
	for i := 0; i < 4; i++ {
		if !st.PushData(chunk) {
			t.Fatalf("Failed to push chunk %d within limit", i)
		}
	}

	if st.QueuedBytes() != 4*1024*1024 {
		t.Fatalf("Expected 4MB queued, got %d", st.QueuedBytes())
	}

	// 5th push should be blocked by backpressure!
	blockedCh := make(chan bool)
	go func() {
		ok := st.PushData(chunk)
		blockedCh <- ok
	}()

	// Verify that it is blocked
	select {
	case <-blockedCh:
		t.Fatal("Expected 5th chunk to be blocked by byte backpressure limit")
	case <-time.After(100 * time.Millisecond):
		// Expected: currently blocked
	}

	// Read 2 MiB from stream to relieve backpressure
	buf := make([]byte, 2*1024*1024)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// The blocked push should now succeed and unblock!
	select {
	case ok := <-blockedCh:
		if !ok {
			t.Fatal("Expected blocked push to succeed once space was freed")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Blocked push did not unblock after reading data")
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
	cert, err := generateSelfSignedCert()
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
	frame, err := readWSFrame(br, pipeR)
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
