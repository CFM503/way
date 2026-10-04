package main

// Fuzz entry points for wire parsers. Run bounded, e.g.:
//   go test -fuzz=FuzzWSFrame -fuzztime=120s .
// These must never panic, hang, or OOM on arbitrary input; any failure is
// a remotely-triggerable crash (Go panics kill the whole process).

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

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
