// goway – crypto
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
)

// --- Fast Mask PRNG ---
// WebSocket masking only requires unpredictability from the server's perspective,
// not cryptographic randomness. RFC 6455 §10.3 says masking prevents proxy
// cache poisoning; it is NOT a security primitive. Using crypto/rand here
// costs a getrandom() syscall (~300ns) per frame — replaced with a per-goroutine
// xorshift64 that amortises to ~2ns/frame with zero syscalls.
//
// goroutineMask is a goroutine-local PRNG state stored in a sync.Pool so each
// relay goroutine gets its own instance (no lock contention).

type maskPRNG struct{ state uint64 }

var maskPool = sync.Pool{
	New: func() interface{} {
		var seed [8]byte
		rand.Read(seed[:]) // one-time crypto seed per goroutine
		s := binary.LittleEndian.Uint64(seed[:])
		if s == 0 {
			s = 0xdeadbeefcafebabe
		}
		return &maskPRNG{state: s}
	},
}

// next returns the next 32-bit mask via xorshift64.
func (p *maskPRNG) next32() uint32 {
	x := p.state
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	p.state = x
	return uint32(x)
}

// readMask fills a 4-byte slice with fast pseudorandom mask bytes.
func readMask(dst []byte, p *maskPRNG) {
	v := p.next32()
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

// randIntn returns a pseudorandom int in [0, n) using xorshift64 (zero locks).
func (p *maskPRNG) randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	return int(p.next32() % uint32(n))
}

// fillRandom fills dst with fast pseudorandom bytes (zero locks).
func (p *maskPRNG) fillRandom(dst []byte) {
	i := 0
	for ; i+4 <= len(dst); i += 4 {
		binary.NativeEndian.PutUint32(dst[i:], p.next32())
	}
	if i < len(dst) {
		v := p.next32()
		for j := i; j < len(dst); j++ {
			dst[j] = byte(v)
			v >>= 8
		}
	}
}

// Small-frame stack threshold for readWSFrame pool optimization
const smallFrameSize = 512
const (
	AnsiReset   = "\033[0m"
	AnsiCyan    = "\033[36m"
	AnsiGreen   = "\033[32m"
	AnsiYellow  = "\033[33m"
	AnsiMagenta = "\033[35m"
	AnsiRed     = "\033[31m"
	AnsiGrey    = "\033[90m"
)

// --- Crypto ---

const cryptoChunkSize = 262144 // 256KB pre-expanded key chunk (increased from 64KB)

// Application-layer cipher modes. cipherModeXOR is the legacy repeating
// keystream (wire-compatible with every prior release); cipherModeAEAD is
// opt-in via -cipher aead on BOTH ends: per-frame AES-256-GCM with a
// per-process random 4-byte nonce prefix + 8-byte counter, carried inline
// as [nonce|ciphertext|tag] (+28 bytes per frame).
const (
	cipherModeXOR = iota
	cipherModeAEAD
)

const (
	aeadNonceSize = 12
	aeadTagSize   = 16
	// aeadOverhead is the per-frame wire expansion of AEAD mode.
	aeadOverhead = aeadNonceSize + aeadTagSize
)

type Crypto struct {
	mode        int
	expandedKey []byte        // XOR mode: pre-expanded repeating keystream
	gcm         cipher.AEAD   // AEAD mode: AES-256-GCM built once
	noncePrefix [4]byte       // AEAD: random per-process nonce prefix
	frameCtr    atomic.Uint64 // AEAD: frame counter; prefix+counter is unique per process
}

// NewCrypto builds the legacy XOR cipher (wire-compatible with all prior
// releases; also the mode used by unit tests).
func NewCrypto(key string) *Crypto {
	return NewCryptoMode(key, cipherModeXOR)
}

func NewCryptoMode(key string, mode int) *Crypto {
	if key == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(key))
	kl := len(hash)
	if mode == cipherModeAEAD {
		c := &Crypto{mode: mode}
		block, err := aes.NewCipher(hash[:])
		if err != nil {
			return nil
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil
		}
		c.gcm = gcm
		if _, err := rand.Read(c.noncePrefix[:]); err != nil {
			return nil
		}
		return c
	}
	// Pre-expand key to cryptoChunkSize + 8 for single-loop bulk XOR (prevents panic at end boundary)
	ek := bytes.Repeat(hash[:], (cryptoChunkSize+8)/kl+1)[:cryptoChunkSize+8]
	return &Crypto{
		mode:        cipherModeXOR,
		expandedKey: ek,
	}
}

// isXOR reports legacy mode. nil Crypto counts as XOR (no-op transform).
func (c *Crypto) isXOR() bool {
	return c == nil || c.mode == cipherModeXOR
}

// xorOnly returns c in legacy mode, nil in AEAD mode. Write paths pass this
// to the fused WS encoders: AEAD payloads are already sealed at enqueue
// time and must not be XORed a second time (nil = mask-only/header-only).
func (c *Crypto) xorOnly() *Crypto {
	if c == nil || c.mode == cipherModeAEAD {
		return nil
	}
	return c
}

// fillNonce writes a fresh unique nonce into dst (len aeadNonceSize).
func (c *Crypto) fillNonce(dst []byte) {
	copy(dst, c.noncePrefix[:])
	binary.BigEndian.PutUint64(dst[4:], c.frameCtr.Add(1))
}

// SealRegion seals the plaintext buf[:plainLen] in place into the wire
// layout [nonce|ciphertext|tag], using buf's capacity; requires
// cap(buf[:plainLen]) >= plainLen+aeadOverhead. Returns the sealed length.
func (c *Crypto) SealRegion(buf []byte, plainLen int) int {
	region := buf[:plainLen+aeadOverhead]
	ct := region[aeadNonceSize:]
	// Move the plaintext past the nonce slot FIRST — fillNonce overwrites
	// buf[:12], which is still part of the plaintext until it is shifted.
	copy(ct, buf[:plainLen])
	nonce := region[:aeadNonceSize]
	c.fillNonce(nonce)
	plain := ct[:plainLen]
	c.gcm.Seal(plain[:0], nonce, plain, nil) // in-place encrypt + append tag
	return plainLen + aeadOverhead
}

// OpenRegion decrypts an in-place [nonce|ciphertext|tag] region and returns
// the plaintext as a sub-slice of buf (len(buf)-aeadOverhead bytes).
func (c *Crypto) OpenRegion(buf []byte) ([]byte, error) {
	if len(buf) < aeadOverhead {
		return nil, errors.New("aead region too short")
	}
	nonce := buf[:aeadNonceSize]
	ct := buf[aeadNonceSize:]
	return c.gcm.Open(ct[:0], nonce, ct, nil)
}

// sealFrame seals a small standalone frame payload (auth/target/OK lines)
// when AEAD is active; legacy/XOR and nil crypto return the input as-is
// (callers previously transformed those in place).
func (c *Crypto) sealFrame(plain []byte) []byte {
	if c == nil {
		return plain
	}
	if c.isXOR() {
		// legacy mode: callers previously transformed these frames in
		// place with TransformInPlace — keep exactly that behavior.
		c.TransformInPlace(plain)
		return plain
	}
	out := make([]byte, len(plain)+aeadOverhead)
	copy(out, plain)
	n := c.SealRegion(out, len(plain))
	return out[:n]
}

// okCiphered returns the encrypted "OK\n" auth response for the active
// cipher mode (XOR transform in legacy mode, AEAD seal otherwise).
func okCiphered(c *Crypto) []byte {
	if c == nil {
		return okBytes
	}
	ok := []byte("OK\n")
	if c.isXOR() {
		c.TransformInPlace(ok)
		return ok
	}
	return c.sealFrame(ok)
}

// relayCrypto selects the cipher applied to NON-MUX relay payloads. The
// legacy XOR wire format ships relay data UNENCRYPTED (only auth/OK/MUX/UDP
// frames are ciphered) and must stay byte-compatible, so XOR mode passes
// nil; AEAD mode encrypts the relay data plane too.
func relayCrypto(cfg *Config) *Crypto {
	if cfg != nil && cfg.Crypto != nil && !cfg.Crypto.isXOR() {
		return cfg.Crypto
	}
	return nil
}

func (c *Crypto) TransformInPlace(data []byte) {
	if c == nil || len(data) == 0 {
		return
	}
	ek := c.expandedKey
	n := len(data)
	i := 0
	// Bulk: 8-byte XOR against pre-expanded key — single loop, no nesting
	for ; i+8 <= n; i += 8 {
		off := i & (cryptoChunkSize - 1)
		binary.NativeEndian.PutUint64(data[i:],
			binary.NativeEndian.Uint64(data[i:])^
				binary.NativeEndian.Uint64(ek[off:]))
	}
	// Tail: byte-by-byte for remainder (< 8 bytes)
	for ; i < n; i++ {
		data[i] ^= ek[i&(cryptoChunkSize-1)]
	}
}
