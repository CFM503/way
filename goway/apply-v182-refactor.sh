#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
SRC="goway.go"
BACKUP="goway.go.v1.8.1.bak"

[[ -f "$SRC" ]] || { echo "ERROR: $SRC not found" >&2; exit 1; }
grep -q 'Version[[:space:]]*=.*"1.8.1"' "$SRC" || { echo "ERROR: expected v1.8.1; refusing to patch" >&2; exit 1; }
cp -p "$SRC" "$BACKUP"

python3 <<'PY'
from pathlib import Path

p = Path('goway.go')
s = p.read_text(encoding='utf-8')
orig = s

def replace_func(src, signature, replacement):
    start = src.find(signature)
    if start < 0:
        raise SystemExit(f'missing function: {signature}')
    brace = src.find('{', start)
    if brace < 0:
        raise SystemExit(f'missing opening brace: {signature}')
    depth = 0
    in_str = in_char = esc = line_comment = block_comment = False
    i = brace
    while i < len(src):
        c = src[i]
        n = src[i+1] if i+1 < len(src) else ''
        if line_comment:
            if c == '\n': line_comment = False
        elif block_comment:
            if c == '*' and n == '/': block_comment = False; i += 1
        elif in_str:
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == '"': in_str = False
        elif in_char:
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == "'": in_char = False
        elif c == '/' and n == '/': line_comment = True; i += 1
        elif c == '/' and n == '*': block_comment = True; i += 1
        elif c == '"': in_str = True
        elif c == "'": in_char = True
        elif c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return src[:start] + replacement + src[i+1:]
        i += 1
    raise SystemExit(f'unclosed function: {signature}')

# 1) Version.
old = 'Version        = "1.8.1"'
if old not in s: raise SystemExit('version marker missing')
s = s.replace(old, 'Version        = "1.8.2"', 1)

# 2) No permessage-deflate: proxy payloads are already framed/compressed often.
s2 = s.replace('\n\t\t"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",', '', 1)
if s2 == s: raise SystemExit('WebSocket extension line missing')
s = s2

# 3) Remove artificial protocol padding. These are exact v1.8.1 blocks.
blocks = [
('''\tbase := "MUX\\n"\n\tpadLen := 1 + mrand.Intn(40)\n\ttargetPayload := make([]byte, len(base)+padLen)\n\tcopy(targetPayload, base)\n\tfor i := len(base); i < len(targetPayload); i++ {\n\t\ttargetPayload[i] = ' '\n\t}''', '''\ttargetPayload := []byte("MUX\\n")'''),
('''\tbase := "UDP\\n"\n\tpadLen := 1 + mrand.Intn(40)\n\ttargetPayload := make([]byte, len(base)+padLen)\n\tcopy(targetPayload, base)\n\tfor i := len(base); i < len(targetPayload); i++ {\n\t\ttargetPayload[i] = ' '\n\t}''', '''\ttargetPayload := []byte("UDP\\n")'''),
('''\tbase := targetHost + ":" + targetPort + "\\n"\n\tpadLen := 1 + mrand.Intn(40)\n\ttargetPayload := make([]byte, len(base)+padLen)\n\tcopy(targetPayload, base)\n\t// fill padding with spaces (constant, no allocation)\n\tfor i := len(base); i < len(targetPayload); i++ {\n\t\ttargetPayload[i] = ' '\n\t}''', '''\ttargetPayload := []byte(targetHost + ":" + targetPort + "\\n")''')]
for a,b in blocks:
    if a not in s: raise SystemExit('padding block missing')
    s = s.replace(a,b,1)

# 4) Linearizable global connection admission. Never overshoot MaxConns.
marker = 'var stats Statistics\n'
if marker not in s: raise SystemExit('stats marker missing')
limiter = '''var stats Statistics

func tryAcquireConn(max int64) bool {
\tfor {
\t\tcur := atomic.LoadInt64(&stats.activeConns)
\t\tif cur >= max { return false }
\t\tif atomic.CompareAndSwapInt64(&stats.activeConns, cur, cur+1) { return true }
\t}
}

func releaseConn() {
\tfor {
\t\tcur := atomic.LoadInt64(&stats.activeConns)
\t\tif cur <= 0 { atomic.StoreInt64(&stats.activeConns, 0); return }
\t\tif atomic.CompareAndSwapInt64(&stats.activeConns, cur, cur-1) { return }
\t}
}
'''
s = s.replace(marker, limiter, 1)

old = '''\t\tif atomic.LoadInt64(&stats.activeConns) >= int64(cfg.MaxConns) {
\t\t\tlogWarn("MaxConns (%d) reached, rejecting connection", cfg.MaxConns)
\t\t\tconn.Close()
\t\t\tcontinue
\t\t}

\t\tstats.AddConn()
\t\tgo func(c net.Conn) {
\t\t\tdefer stats.RemoveConn()
\t\t\thandleConnection(c, &cfg)
\t\t}(conn)'''
new = '''\t\tif !tryAcquireConn(int64(cfg.MaxConns)) {
\t\t\tlogWarn("MaxConns (%d) reached, rejecting connection", cfg.MaxConns)
\t\t\t_ = conn.Close()
\t\t\tcontinue
\t\t}

\t\tgo func(c net.Conn) {
\t\t\tdefer releaseConn()
\t\t\thandleConnection(c, &cfg)
\t\t}(conn)'''
if old not in s: raise SystemExit('main accept limiter missing')
s = s.replace(old,new,1)

old = '''\t\tif atomic.LoadInt64(&stats.activeConns) >= int64(cfg.MaxConns) {
\t\t\tlogWarn("[QUIC-SERVER] MaxConns (%d) reached, rejecting stream", cfg.MaxConns)
\t\t\t_ = stream.Close()
\t\t\tcontinue
\t\t}

\t\tstats.AddConn()
\t\tgo func(st quic.Stream) {
\t\t\tdefer stats.RemoveConn()
\t\t\thandleQUICStream(st, cfg)
\t\t}(stream)'''
new = '''\t\tif !tryAcquireConn(int64(cfg.MaxConns)) {
\t\t\tlogWarn("[QUIC-SERVER] MaxConns (%d) reached, rejecting stream", cfg.MaxConns)
\t\t\t_ = stream.Close()
\t\t\tcontinue
\t\t}

\t\tgo func(st quic.Stream) {
\t\t\tdefer releaseConn()
\t\t\thandleQUICStream(st, cfg)
\t\t}(stream)'''
if old not in s: raise SystemExit('QUIC limiter missing')
s = s.replace(old,new,1)

# 5) Larger Mux chunks, still below uint16 max payload.
if 'const maxChunk = 32 * 1024' not in s: raise SystemExit('mux maxChunk missing')
s = s.replace('const maxChunk = 32 * 1024','const maxChunk = 60 * 1024',1)

# 6) Heartbeat only while session is idle (active streams already prove liveness).
old = '''\t\tcase <-ticker.C:\n\t\t\ts.writeMu.Lock()'''
new = '''\t\tcase <-ticker.C:\n\t\t\tif s.ActiveStreams() > 0 { continue }\n\t\t\ts.writeMu.Lock()'''
if old not in s: raise SystemExit('heartbeat block missing')
s = s.replace(old,new,1)

# 7) Slow Mux streams never stall the single session read loop.
client_sig = 'func (s *MuxStream) PushDataFrame(frame muxDataFrame) bool'
server_sig = 'func (s *MuxServerStream) PushDataFrame(frame muxDataFrame) bool'
client_new = '''func (s *MuxStream) PushDataFrame(frame muxDataFrame) bool {
\tdataLen := int64(len(frame.data))
\ts.bufMu.Lock()
\tselect { case <-s.closed: s.bufMu.Unlock(); return false; default: }
\tif s.queuedBytes+dataLen > muxClientStreamBufferLimit {
\t\ts.bufMu.Unlock()
\t\tlogWarn("[MUX] Stream %d receive buffer limit reached, resetting stream", s.id)
\t\ts.Reset()
\t\treturn false
\t}
\tselect {
\tcase s.readChan <- frame:
\t\ts.queuedBytes += dataLen
\t\ts.bufMu.Unlock()
\t\treturn true
\tdefault:
\t\ts.bufMu.Unlock()
\t\tlogWarn("[MUX] Stream %d receive queue full, resetting stream", s.id)
\t\ts.Reset()
\t\treturn false
\t}
}'''
server_new = '''func (s *MuxServerStream) PushDataFrame(frame muxDataFrame) bool {
\tdataLen := int64(len(frame.data))
\ts.bufMu.Lock()
\tselect { case <-s.closed: s.bufMu.Unlock(); return false; default: }
\tif s.queuedBytes+dataLen > muxServerStreamBufferLimit {
\t\ts.bufMu.Unlock()
\t\tlogWarn("[SERVER-MUX] Stream %d receive buffer limit reached, resetting stream", s.id)
\t\ts.Close()
\t\t_ = s.session.SendFrame(s.id, MuxCmdRST, nil)
\t\treturn false
\t}
\tselect {
\tcase s.writeChan <- frame:
\t\ts.queuedBytes += dataLen
\t\ts.bufMu.Unlock()
\t\treturn true
\tdefault:
\t\ts.bufMu.Unlock()
\t\tlogWarn("[SERVER-MUX] Stream %d receive queue full, resetting stream", s.id)
\t\ts.Close()
\t\t_ = s.session.SendFrame(s.id, MuxCmdRST, nil)
\t\treturn false
\t}
}'''
s = replace_func(s, client_sig, client_new)
s = replace_func(s, server_sig, server_new)

# 8) Cap pooled relay buffers. Keeps user-facing -W but prevents huge per-connection RAM.
old = '''\tbufSize := cfg.BufferSize + 14\n\tif bufSize < 65536+14+MuxHeaderLen {\n\t\tbufSize = 65536 + 14 + MuxHeaderLen\n\t}'''
new = '''\tbufSize := cfg.BufferSize + 14\n\tif bufSize < 65536+14+MuxHeaderLen {\n\t\tbufSize = 65536 + 14 + MuxHeaderLen\n\t}\n\tif bufSize > 256*1024+14+MuxHeaderLen {\n\t\tbufSize = 256*1024 + 14 + MuxHeaderLen\n\t}'''
if old not in s: raise SystemExit('buffer sizing block missing')
s = s.replace(old,new,1)

if s == orig: raise SystemExit('no changes made')
p.write_text(s, encoding='utf-8')
PY

gofmt -w "$SRC"

go test ./...
go test -race ./...
go vet ./...

git diff --check
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /tmp/goway-v1.8.2.exe .

# Only source is committed; the runner is deleted before commit so the repo stays single-file for Goway.
git rm -f --ignore-unmatch apply-v182-refactor.sh >/dev/null 2>&1 || true
git add "$SRC"
git commit -m 'refactor(goway): v1.8.2 performance and mux hardening'
git push origin main
rm -f "$BACKUP"

echo
echo '=== GOWAY v1.8.2 REFRACTOR VERIFIED ==='
git log -2 --oneline
echo "Windows binary: /tmp/goway-v1.8.2.exe"
