// goway – resolver
// Split from the original single-file goway.go (v1.8.16). Purely mechanical move:
// same package main, same code; section ownership only.

package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// --- DNS Resolver ---

type dnsCacheEntry struct {
	ip      string
	expires time.Time
}

type RemoteResolver struct {
	serverIP  string
	resolver  *net.Resolver
	sysResolv *net.Resolver // pre-allocated; avoids per-call allocation on fallback
	timeout   time.Duration
	cache     map[string]dnsCacheEntry
	cacheMu   sync.RWMutex
	cacheTTL  time.Duration
}

func NewRemoteResolver(serverIP string) *RemoteResolver {
	r := &RemoteResolver{
		serverIP:  serverIP,
		timeout:   5 * time.Second,
		sysResolv: &net.Resolver{PreferGo: false},
		cache:     make(map[string]dnsCacheEntry),
		cacheTTL:  5 * time.Minute,
	}
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			return d.DialContext(ctx, network, net.JoinHostPort(serverIP, "53"))
		},
	}
	return r
}

// maxDNSCacheEntries bounds RemoteResolver.cache. Entries expired or not
// are never auto-removed from a Go map, so an unbounded cache grew for the
// lifetime of the process with every distinct host ever resolved.
const maxDNSCacheEntries = 4096

// evictDNSCacheLocked drops expired entries first; if the cache is still at
// capacity, it drops a quarter of the remaining entries (map iteration
// order, which is random — acceptable for a best-effort DNS cache).
// Caller must hold r.cacheMu.
func (r *RemoteResolver) evictDNSCacheLocked() {
	now := time.Now()
	for host, entry := range r.cache {
		if now.After(entry.expires) {
			delete(r.cache, host)
		}
	}
	if len(r.cache) < maxDNSCacheEntries {
		return
	}
	victims := maxDNSCacheEntries / 4
	for host := range r.cache {
		if victims <= 0 {
			break
		}
		delete(r.cache, host)
		victims--
	}
}

func (r *RemoteResolver) Resolve(host string) (string, error) {
	// If already an IP, return as-is
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// Check cache first
	r.cacheMu.RLock()
	if entry, ok := r.cache[host]; ok && time.Now().Before(entry.expires) {
		r.cacheMu.RUnlock()
		return entry.ip, nil
	}
	r.cacheMu.RUnlock()

	// Try remote DNS with timeout
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	addrs, err := r.resolver.LookupHost(ctx, host)
	if err == nil && len(addrs) > 0 {
		logInfo("[DNS] %s -> %s (remote: %s)", host, addrs[0], r.serverIP)
		// Cache the result
		r.cacheMu.Lock()
		if len(r.cache) >= maxDNSCacheEntries {
			r.evictDNSCacheLocked()
		}
		r.cache[host] = dnsCacheEntry{ip: addrs[0], expires: time.Now().Add(r.cacheTTL)}
		r.cacheMu.Unlock()
		return addrs[0], nil
	}

	if err != nil {
		logWarn("[DNS] Remote lookup failed for %s: %v, falling back to system DNS", host, err)
	} else {
		logWarn("[DNS] Remote lookup returned no addresses for %s, falling back to system DNS", host)
	}

	// Fallback to pre-allocated system resolver (no heap alloc here)
	sysCtx, sysCancel := context.WithTimeout(context.Background(), r.timeout)
	defer sysCancel()
	sysAddrs, sysErr := r.sysResolv.LookupHost(sysCtx, host)
	if sysErr != nil {
		return "", fmt.Errorf("DNS resolution failed for %s: remote=%v, system=%v", host, err, sysErr)
	}
	if len(sysAddrs) == 0 {
		return "", fmt.Errorf("DNS resolution returned no addresses for %s", host)
	}
	logInfo("[DNS] %s -> %s (system fallback)", host, sysAddrs[0])
	// Cache the system fallback result too
	r.cacheMu.Lock()
	if len(r.cache) >= maxDNSCacheEntries {
		r.evictDNSCacheLocked()
	}
	r.cache[host] = dnsCacheEntry{ip: sysAddrs[0], expires: time.Now().Add(r.cacheTTL)}
	r.cacheMu.Unlock()
	return sysAddrs[0], nil
}

// resolveTargetAddr uses resolver to resolve target's host if configured.
func resolveTargetAddr(resolver *RemoteResolver, target string) string {
	if resolver == nil {
		return target
	}
	host, port, splitErr := net.SplitHostPort(target)
	if splitErr != nil {
		return target
	}
	if resolvedIP, resolveErr := resolver.Resolve(host); resolveErr == nil {
		return net.JoinHostPort(resolvedIP, port)
	}
	return target
}

// verifyAuthKey checks if input matches expectedKey (if key is set).
// The key token is compared in constant time (length leaks via early
// return, which is standard and harmless here).
func verifyAuthKey(input string, expectedKey string) (cleanStr string, ok bool) {
	if expectedKey == "" {
		return input, true
	}
	parts := strings.SplitN(input, " ", 2)
	if len(parts) == 2 && subtle.ConstantTimeCompare([]byte(parts[0]), []byte(expectedKey)) == 1 {
		return parts[1], true
	}
	return "", false
}
