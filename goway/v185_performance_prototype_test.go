package main

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// v185OutboundFrame owns its byte slice until the writer has completed Write.
type v185OutboundFrame struct {
	data []byte
}

// v185BoundedWriter is an isolated prototype, deliberately not wired into
// production SendFrame yet. It validates the proposed bounded single-writer
// architecture before touching MUX lifecycle or BufferPool ownership.
type v185BoundedWriter struct {
	q      chan v185OutboundFrame
	closed chan struct{}
	done   chan struct{}
	write  func([]byte) (int, error)
	drops  atomic.Int64
}

func newV185BoundedWriter(depth int, write func([]byte) (int, error)) *v185BoundedWriter {
	w := &v185BoundedWriter{
		q:      make(chan v185OutboundFrame, depth),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
		write:  write,
	}
	go w.loop()
	return w
}

func (w *v185BoundedWriter) loop() {
	defer close(w.done)
	for {
		select {
		case <-w.closed:
			for {
				select {
				case f := <-w.q:
					if f.data != nil {
						_, _ = w.write(f.data)
					}
				default:
					return
				}
			}
		case f := <-w.q:
			if f.data != nil {
				_, _ = w.write(f.data)
			}
		}
	}
}

func (w *v185BoundedWriter) enqueue(data []byte) bool {
	select {
	case <-w.closed:
		return false
	default:
	}
	select {
	case w.q <- v185OutboundFrame{data: data}:
		return true
	default:
		w.drops.Add(1)
		return false
	}
}

func (w *v185BoundedWriter) close() {
	select {
	case <-w.closed:
		return
	default:
		close(w.closed)
	}
	<-w.done
}

func TestV185BoundedWriterOrderingAndDrain(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	w := newV185BoundedWriter(8, func(p []byte) (int, error) {
		mu.Lock()
		got = append(got, p[0])
		mu.Unlock()
		return len(p), nil
	})
	for i := byte(0); i < 8; i++ {
		if !w.enqueue([]byte{i}) {
			t.Fatalf("enqueue %d failed", i)
		}
	}
	w.close()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 8 {
		t.Fatalf("drain wrote %d frames, want 8", len(got))
	}
	for i, v := range got {
		if v != byte(i) {
			t.Fatalf("ordering mismatch at %d: got %d", i, v)
		}
	}
}

func BenchmarkV185BoundedWriterEnqueue(b *testing.B) {
	w := newV185BoundedWriter(1024, io.Discard.Write)
	payload := make([]byte, 32768)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for !w.enqueue(payload) {
			time.Sleep(0)
		}
	}
	b.StopTimer()
	w.close()
}

func TestV185SlowWriterBoundedBackpressure(t *testing.T) {
	w := newV185BoundedWriter(4, func(p []byte) (int, error) {
		time.Sleep(2 * time.Millisecond)
		return len(p), nil
	})
	accepted := 0
	for i := 0; i < 100; i++ {
		if w.enqueue([]byte{byte(i)}) {
			accepted++
		}
	}
	if accepted > 5 {
		t.Fatalf("bounded queue accepted too many frames: %d", accepted)
	}
	w.close()
	if w.drops.Load() == 0 {
		t.Fatal("slow writer did not trigger bounded backpressure")
	}
}
