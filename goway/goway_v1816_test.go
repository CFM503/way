package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"net"
	"strconv"
	"testing"
	"time"
)

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
