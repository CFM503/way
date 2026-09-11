package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type v184Session struct{}

func (*v184Session) SendFrame(uint32, byte, []byte) error { return nil }
func (*v184Session) RemoveStream(uint32)                  {}
func TestV184HeaderHardLimit(t *testing.T) {
	valid := strings.Repeat("a", MaxHeaderSize-4) + "\r\n\r\n"
	got, err := readUntilCRLFCRLF(bufio.NewReaderSize(strings.NewReader(valid), MaxHeaderSize))
	if err != nil || len(got) != MaxHeaderSize {
		t.Fatalf("valid max header: %d %v", len(got), err)
	}
	for _, in := range []string{strings.Repeat("a", MaxHeaderSize+1) + "\r\n\r\n", strings.Repeat("a", MaxHeaderSize-5) + "\r\n" + "b\r\n\r\n"} {
		_, err = readUntilCRLFCRLF(bufio.NewReaderSize(strings.NewReader(in), MaxHeaderSize))
		if err == nil || err.Error() != "header too large" {
			t.Fatalf("oversize err=%v", err)
		}
	}
}
func TestV184MuxClientPRNGLifecycle(t *testing.T) {
	c, p := net.Pipe()
	defer p.Close()
	pool := &sync.Pool{New: func() interface{} { b := make([]byte, 128*1024); return &b }}
	s := &MuxClientSession{wsConn: c, cfg: &Config{BufPool: pool}, streams: map[uint32]*MuxStream{}, closed: make(chan struct{}), prng: maskPool.Get().(*maskPRNG)}
	drained := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, p); close(drained) }()
	var wg sync.WaitGroup
	payload := make([]byte, 1024)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if s.SendFrame(uint32(id), MuxCmdDATA, payload) != nil {
					return
				}
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	wg.Wait()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close hung")
	}
	_ = c.Close()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("drain hung")
	}
	if s.prng != nil {
		t.Fatal("prng not cleared")
	}
}
func TestV184MuxServerTargetLifecycle(t *testing.T) {
	st := newMuxServerStream(1, nil)
	defer st.Close()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, b := net.Pipe()
			_ = b.Close()
			_ = st.setTargetConn(a)
			_ = st.targetConnSnapshot()
			st.closeTargetConn()
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); st.Close() }()
	wg.Wait()
	if st.targetConnSnapshot() != nil {
		t.Fatal("target retained")
	}
}
func TestV184SlowFastAndRST(t *testing.T) {
	slow := newMuxServerStream(1, nil)
	fast := newMuxServerStream(2, nil)
	defer slow.Close()
	defer fast.Close()
	chunk := make([]byte, 64*1024)
	for i := 0; i < muxServerStreamBufferLimit/len(chunk); i++ {
		if !slow.PushData(chunk) {
			t.Fatal("fill")
		}
	}
	blocked := make(chan bool, 1)
	go func() { blocked <- slow.PushData(chunk) }()
	time.Sleep(20 * time.Millisecond)
	if !fast.PushData(chunk) {
		t.Fatal("fast blocked")
	}
	f := <-slow.writeChan
	f.release()
	slow.consumedBytes(len(chunk))
	select {
	case ok := <-blocked:
		if !ok {
			t.Fatal("slow did not resume")
		}
	case <-time.After(time.Second):
		t.Fatal("slow stuck")
	}
	st := newMuxStream(3, &v184Session{})
	done := make(chan struct{})
	go func() { _ = st.PushDataFrame(muxDataFrame{data: chunk}); close(done) }()
	st.Reset()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RST did not unblock")
	}
}
func TestV184ThousandStreams(t *testing.T) {
	ss := make([]*MuxServerStream, 1000)
	for i := range ss {
		ss[i] = newMuxServerStream(uint32(i+1), nil)
	}
	var wg sync.WaitGroup
	wg.Add(len(ss))
	for _, st := range ss {
		go func(s *MuxServerStream) { defer wg.Done(); s.Close() }(st)
	}
	wg.Wait()
}
func TestV184ConcurrentLogRingSave(t *testing.T) {
	f, e := os.CreateTemp("", "goway-v184-*.log")
	if e != nil {
		t.Fatal(e)
	}
	path := f.Name()
	_ = f.Close()
	defer os.Remove(path)
	logRingMu.Lock()
	logFilePath = path
	logRingBuf = [10]string{}
	logRingPos = 0
	logRingLen = 0
	logRingMu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				addLogFileEntry(fmt.Sprintf("%d/%d", id, j))
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				saveLogFile()
			}
		}()
	}
	wg.Wait()
	logRingMu.Lock()
	logFilePath = ""
	logRingMu.Unlock()
}
