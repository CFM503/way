# Remote DNS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `-dns` flag to goway that resolves hostnames via a remote DNS server (UDP+TCP fallback) before connecting.

**Architecture:** A `RemoteResolver` wraps Go's `net.Resolver` with a custom `Dial` function pointing to the user-specified DNS server. It's integrated into both `handleServer` (target address resolution) and `handleClient` (upstream WebSocket host resolution). On failure, it falls back to system DNS.

**Tech Stack:** Go standard library only (`net`, `net.Resolver`, `context`)

---

## File Structure

Single file modified: `goway/goway1.1.15a.go`

No new files created. All changes are additions/modifications within the existing file.

---

### Task 1: Add RemoteResolver struct and Resolve method

**Files:**
- Modify: `goway/goway1.1.15a.go:126-151` (after Config struct, before Logger section)

- [ ] **Step 1: Add RemoteResolver struct after Config struct**

Insert the following code after line 151 (closing `}` of Config struct), before the `// --- Logger ---` comment on line 153:

```go
// --- DNS Resolver ---

type RemoteResolver struct {
    serverIP string
    resolver *net.Resolver
    timeout  time.Duration
}

func NewRemoteResolver(serverIP string) *RemoteResolver {
    r := &RemoteResolver{
        serverIP: serverIP,
        timeout:  5 * time.Second,
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

func (r *RemoteResolver) Resolve(host string) (string, error) {
    // If already an IP, return as-is
    if ip := net.ParseIP(host); ip != nil {
        return host, nil
    }

    // Try remote DNS with timeout
    ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
    defer cancel()

    addrs, err := r.resolver.LookupHost(ctx, host)
    if err == nil && len(addrs) > 0 {
        logInfo("[DNS] %s -> %s (remote: %s)", host, addrs[0], r.serverIP)
        return addrs[0], nil
    }

    if err != nil {
        logWarn("[DNS] Remote lookup failed for %s: %v, falling back to system DNS", host, err)
    } else {
        logWarn("[DNS] Remote lookup returned no addresses for %s, falling back to system DNS", host)
    }

    // Fallback to system DNS
    sysResolver := &net.Resolver{PreferGo: false}
    sysAddrs, sysErr := sysResolver.LookupHost(context.Background(), host)
    if sysErr != nil {
        return "", fmt.Errorf("DNS resolution failed for %s: remote=%v, system=%v", host, err, sysErr)
    }
    if len(sysAddrs) == 0 {
        return "", fmt.Errorf("DNS resolution returned no addresses for %s", host)
    }
    logInfo("[DNS] %s -> %s (system fallback)", host, sysAddrs[0])
    return sysAddrs[0], nil
}
```

- [ ] **Step 2: Add "context" to import list**

In the import block (lines 3-28), add `"context"` after the `"bytes"` import. The import list should become:

```go
import (
    "bufio"
    "bytes"
    "context"
    "crypto/rand"
    // ... rest unchanged
)
```

- [ ] **Step 3: Verify compilation**

Run: `cd D:/SOFT/AI/github/way && go build ./goway/`
Expected: No errors (the new code compiles but isn't called yet)

- [ ] **Step 4: Commit**

```bash
git add goway/goway1.1.15a.go
git commit -m "feat(dns): add RemoteResolver struct with UDP+TCP fallback"
```

---

### Task 2: Add -dns flag and integrate into Config and Banner

**Files:**
- Modify: `goway/goway1.1.15a.go:511` (add flag definition)
- Modify: `goway/goway1.1.15a.go:523-536` (add Resolver to Config)
- Modify: `goway/goway1.1.15a.go:594-595` (update banner)

- [ ] **Step 1: Add -dns flag definition**

After line 511 (`allowOpenFlag := ...`), add:

```go
dnsFlag := flag.String("dns", "", "Remote DNS server IP (e.g. 8.8.8.8)")
```

- [ ] **Step 2: Create RemoteResolver and add to Config**

After line 536 (closing `}` of cfg construction), before line 538 (`host := "0.0.0.0"`), add:

```go
if *dnsFlag != "" {
    if net.ParseIP(*dnsFlag) == nil {
        fmt.Printf("Error: -dns requires a valid IP address (e.g. 8.8.8.8), got '%s'\n", *dnsFlag)
        os.Exit(1)
    }
    cfg.Resolver = NewRemoteResolver(*dnsFlag)
}
```

- [ ] **Step 3: Update banner DNS display**

Replace lines 594-595:
```go
dnsCol := AnsiYellow
fmt.Printf(" [+] DNS:         %sSystem default%s\n", dnsCol, AnsiReset)
```

With:
```go
if cfg.Resolver != nil {
    fmt.Printf(" [+] DNS:         %sRemote: %s (UDP+TCP)%s\n", AnsiGreen, cfg.Resolver.serverIP, AnsiReset)
} else {
    fmt.Printf(" [+] DNS:         %sSystem default%s\n", AnsiYellow, AnsiReset)
}
```

- [ ] **Step 4: Verify compilation**

Run: `cd D:/SOFT/AI/github/way && go build ./goway/`
Expected: No errors

- [ ] **Step 5: Test banner output**

Run: `cd D:/SOFT/AI/github/way && go run ./goway/ -p 18080 -dns 8.8.8.8 -k test`
Expected: Banner shows `DNS: Remote: 8.8.8.8 (UDP+TCP)` in green

Run: `cd D:/SOFT/AI/github/way && go run ./goway/ -p 18080 -k test`
Expected: Banner shows `DNS: System default` in yellow

Press Ctrl+C to stop.

- [ ] **Step 6: Commit**

```bash
git add goway/goway1.1.15a.go
git commit -m "feat(dns): add -dns flag with IP validation and banner display"
```

---

### Task 3: Integrate DNS resolution into handleServer

**Files:**
- Modify: `goway/goway1.1.15a.go:783-787` (before net.DialTimeout in handleServer)

- [ ] **Step 1: Insert DNS resolution before net.DialTimeout**

In `handleServer`, the current code at lines 783-787 is:

```go
targetStr := string(targetBytes)

logDebug("handleServer targetStr: %s", targetStr)

targetConn, err := net.DialTimeout("tcp4", targetStr, time.Duration(cfg.ConnTimeout)*time.Second)
```

Replace with:

```go
targetStr := string(targetBytes)

logDebug("handleServer targetStr: %s", targetStr)

// Remote DNS resolution for target address
if cfg.Resolver != nil {
    host, port, splitErr := net.SplitHostPort(targetStr)
    if splitErr == nil {
        if resolvedIP, resolveErr := cfg.Resolver.Resolve(host); resolveErr == nil {
            targetStr = net.JoinHostPort(resolvedIP, port)
        } else {
            logError("[DNS] Failed to resolve %s: %v", host, resolveErr)
        }
    }
}

targetConn, err := net.DialTimeout("tcp4", targetStr, time.Duration(cfg.ConnTimeout)*time.Second)
```

- [ ] **Step 2: Verify compilation**

Run: `cd D:/SOFT/AI/github/way && go build ./goway/`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add goway/goway1.1.15a.go
git commit -m "feat(dns): integrate remote DNS resolution in server mode"
```

---

### Task 4: Integrate DNS resolution into handleClient

**Files:**
- Modify: `goway/goway1.1.15a.go:1071-1093` (upstream WebSocket connection in handleClient)

- [ ] **Step 1: Insert DNS resolution before WebSocket dial**

In `handleClient`, the current code at lines 1071-1093 is:

```go
wsHost := wsURL.Hostname()
wsPort := wsURL.Port()
if wsPort == "" {
    if wsURL.Scheme == "wss" || wsURL.Scheme == "https" {
        wsPort = "443"
    } else {
        wsPort = "80"
    }
}

dialAddr := net.JoinHostPort(wsHost, wsPort)
sniHostname := sanitizeHeader(wsHost)
if cfg.FakeHost != "" {
    sniHostname = sanitizeHeader(strings.Split(cfg.FakeHost, ":")[0])
}

if wsURL.Scheme == "wss" || wsURL.Scheme == "https" {
    conf := cfg.TLSBase.Clone()
    conf.ServerName = sniHostname
    wsConn, err = tls.Dial("tcp", dialAddr, conf)
} else {
    wsConn, err = net.Dial("tcp", dialAddr)
}
```

Replace with:

```go
wsHost := wsURL.Hostname()
wsPort := wsURL.Port()
if wsPort == "" {
    if wsURL.Scheme == "wss" || wsURL.Scheme == "https" {
        wsPort = "443"
    } else {
        wsPort = "80"
    }
}

// Remote DNS resolution for upstream host
dialHost := wsHost
if cfg.Resolver != nil {
    if resolvedIP, resolveErr := cfg.Resolver.Resolve(wsHost); resolveErr == nil {
        dialHost = resolvedIP
    } else {
        logError("[DNS] Failed to resolve upstream %s: %v", wsHost, resolveErr)
    }
}

dialAddr := net.JoinHostPort(dialHost, wsPort)
sniHostname := sanitizeHeader(wsHost)
if cfg.FakeHost != "" {
    sniHostname = sanitizeHeader(strings.Split(cfg.FakeHost, ":")[0])
}

if wsURL.Scheme == "wss" || wsURL.Scheme == "https" {
    conf := cfg.TLSBase.Clone()
    conf.ServerName = sniHostname
    wsConn, err = tls.Dial("tcp", dialAddr, conf)
} else {
    wsConn, err = net.Dial("tcp", dialAddr)
}
```

Key detail: `dialHost` uses the resolved IP for the TCP connection, but `sniHostname` keeps the original `wsHost` domain name so TLS SNI works correctly.

- [ ] **Step 2: Verify compilation**

Run: `cd D:/SOFT/AI/github/way && go build ./goway/`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add goway/goway1.1.15a.go
git commit -m "feat(dns): integrate remote DNS resolution in client mode"
```

---

### Task 5: Manual integration test

- [ ] **Step 1: Build the final binary**

Run: `cd D:/SOFT/AI/github/way && go build -o goway/goway.exe ./goway/`
Expected: Binary built successfully

- [ ] **Step 2: Test server mode with -dns**

Run server: `./goway/goway.exe -p 18080 -dns 8.8.8.8 -k testkey`
Expected output includes:
```
 [+] DNS:         Remote: 8.8.8.8 (UDP+TCP)
```

Verify DNS resolution by connecting through the proxy and checking server logs for `[DNS]` entries.

- [ ] **Step 3: Test client mode with -dns**

Run client: `./goway/goway.exe -p 18080 -up ws://your-server:18080 -dns 1.1.1.1 -k testkey`
Expected output includes:
```
 [+] DNS:         Remote: 1.1.1.1 (UDP+TCP)
```

- [ ] **Step 4: Test without -dns (regression check)**

Run: `./goway/goway.exe -p 18080 -k testkey`
Expected: Banner shows `DNS: System default`, behavior identical to before.

- [ ] **Step 5: Test invalid -dns IP**

Run: `./goway/goway.exe -p 18080 -dns notanip -k testkey`
Expected: Error message and exit:
```
Error: -dns requires a valid IP address (e.g. 8.8.8.8), got 'notanip'
```

- [ ] **Step 6: Final commit with version bump**

Update `Version` constant on line 31 from `"1.1.15a"` to `"1.1.16a"`.

```bash
git add goway/goway1.1.15a.go
git commit -m "feat: goway v1.1.16a — remote DNS support via -dns flag"
```
