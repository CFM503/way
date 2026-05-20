# Remote DNS Feature Design

## Overview

Add a `-dns` flag to goway that enables DNS resolution via a remote DNS server, using UDP with TCP fallback. The feature applies to both Server mode (resolving target hostnames) and Client mode (resolving upstream WebSocket server hostnames).

## Command Line Interface

```
-dns string   Remote DNS server IP (e.g. 8.8.8.8)
```

- Format: IP address only (e.g., `8.8.8.8`, `1.1.1.1`, `2001:4860:4860::8888`)
- Port: Always 53 (standard DNS port)
- Optional: When omitted, system default DNS is used (current behavior)

### Banner Output

With `-dns`:
```
 [+] DNS:         Remote: 8.8.8.8 (UDP+TCP)
```

Without `-dns`:
```
 [+] DNS:         System default
```

## Architecture

### RemoteResolver

A new `RemoteResolver` struct encapsulates the remote DNS logic:

```go
type RemoteResolver struct {
    serverIP string
    resolver *net.Resolver
    timeout  time.Duration
}
```

**Constructor:** `NewRemoteResolver(serverIP string) *RemoteResolver`
- Creates a `net.Resolver` with a custom `Dial` function
- The `Dial` function connects to `serverIP:53` via UDP
- Sets timeout to 5 seconds

**Resolve method:** `func (r *RemoteResolver) Resolve(host string) (string, error)`
- If `host` is already an IP address, return it directly
- Use the remote resolver to look up A records (5s timeout)
- On failure, fall back to the system default resolver
- Return the resolved IP address or error

### UDP + TCP Fallback

The `net.Resolver` in Go handles the transport-level fallback internally. The custom `Dial` function specifies the network (`udp` or `tcp`) based on the resolver's needs. When the initial UDP query fails or times out, Go's resolver automatically retries via TCP.

### Fallback Chain

```
Remote DNS (UDP:53, 5s timeout) -> Remote DNS (TCP:53) -> System DNS
```

## Integration Points

### Config Struct

Add a new field to `Config`:

```go
type Config struct {
    // ... existing fields ...
    Resolver *RemoteResolver  // nil when -dns not specified
}
```

### Server Mode (`handleServer`)

Location: Before `net.DialTimeout("tcp4", targetStr, ...)`

1. Parse `targetStr` to extract host and port
2. If `cfg.Resolver != nil` and host is a domain name (not IP):
   - Call `cfg.Resolver.Resolve(host)` to get resolved IP
   - Replace host in `targetStr` with the resolved IP
   - Log: `[DNS] example.com -> 93.184.216.34 (remote)`
3. If resolver is nil, proceed with existing behavior (system DNS)

### Client Mode (`handleClient`)

Location: Before establishing the upstream WebSocket connection

1. If `cfg.Resolver != nil` and `wsHost` is a domain name:
   - Call `cfg.Resolver.Resolve(wsHost)` to get resolved IP
   - Use resolved IP for `dialAddr` (TCP connection)
   - Keep `sniHostname` as the original domain (for TLS SNI)
   - Log: `[DNS] ws.example.com -> 93.184.216.34 (remote)`
2. If resolver is nil, proceed with existing behavior

## Error Handling

| Scenario | Action | Log Level |
|----------|--------|-----------|
| Remote DNS resolves successfully | Use resolved IP | INFO |
| Remote DNS fails (timeout/error) | Fall back to system DNS | WARN |
| System DNS also fails | Connection fails (existing behavior) | ERROR |
| `-dns` flag not specified | Use system DNS (no change) | - |

## Behavioral Guarantees

- **No behavior change without `-dns`:** When the flag is not specified, all logic remains identical to the current version
- **Only DNS resolution is affected:** Encryption, authentication, WebSocket framing, traffic forwarding, and all other features are unchanged
- **No caching:** DNS results are not cached; each resolution queries the remote server
- **No external dependencies:** Uses only Go standard library (`net`, `net.Resolver`)

## Files Modified

Single file: `goway/goway1.1.15a.go`

Changes:
1. Add `-dns` flag definition in `main()`
2. Add `RemoteResolver` struct and methods
3. Add `Resolver` field to `Config` struct
4. Update banner output to show DNS configuration
5. Insert DNS resolution in `handleServer()` before `net.DialTimeout`
6. Insert DNS resolution in `handleClient()` before WebSocket connection
