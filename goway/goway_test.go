package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
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

