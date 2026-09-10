#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
SRC="goway.go"
BACKUP="goway.go.v1.8.1.bak"

[[ -f "$SRC" ]] || { echo "ERROR: $SRC not found" >&2; exit 1; }
grep -q 'Version[[:space:]]*=.*"1.8.1"' "$SRC" || { echo "ERROR: expected v1.8.1 source; refusing to patch" >&2; exit 1; }
cp -p "$SRC" "$BACKUP"

python3 <<'PY'
from pathlib import Path
import re

p = Path('goway.go')
s = p.read_text()
orig = s

def must_once(pattern, repl, label, flags=0):
    global s
    ns, n = re.subn(pattern, repl, s, count=1, flags=flags)
    if n != 1:
        raise SystemExit(f'PATCH FAILED [{label}]: expected 1 match, got {n}')
    s = ns

# Version.
must_once(r'(Version\s*=\s*)"1\.8\.1"', r'\g<1>"1.8.2"', 'version')

# Do not negotiate permessage-deflate for already framed/compressed proxy data.
s = s.replace('\t\t"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\\r\\n"\n', '')
s = s.replace('\t\t"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\\r\\n" +\n', '')

# Remove artificial bootstrap/target padding. Keep protocol delimiters intact.
s = re.sub(r'\+\s*string\(randomInt\(1,\s*40\)\).*?spaces.*?\n', '\n', s)
s = re.sub(r'\+\s*spaces\[:randomInt\(1,\s*40\)\]', '', s)
# Common exact constructions seen in v1.8.x.
s = re.sub(r'strings\.Repeat\(" ",\s*randomInt\(1,\s*40\)\)', '""', s)

# Larger mux frames reduce framing/syscall overhead without exceeding uint16 payload length.
s = s.replace('const maxChunk = 32 * 1024', 'const maxChunk = 60 * 1024')

# Cap the per-connection relay buffer so -W cannot multiply into runaway RAM at scale.
old = '''bufSize := cfg.BufferSize + 14\n\tif bufSize < 64*1024+14 {\n\t\tbufSize = 64*1024 + 14\n\t}\n\tif bufSize < MaxHeaderSize+MuxHeaderLen {\n\t\tbufSize = MaxHeaderSize + MuxHeaderLen\n\t}'''
new = '''bufSize := cfg.BufferSize\n\tif bufSize < 64*1024 {\n\t\tbufSize = 64 * 1024\n\t}\n\tif bufSize > 256*1024 {\n\t\tbufSize = 256 * 1024\n\t}\n\tbufSize += 14\n\tif bufSize < MaxHeaderSize+MuxHeaderLen {\n\t\tbufSize = MaxHeaderSize + MuxHeaderLen\n\t}'''
if old in s:
    s = s.replace(old, new, 1)
else:
    # Refuse silent degradation if the buffer setup changed materially.
    if 'bufSize := cfg.BufferSize' in s and 'bufSize > 256*1024' in s:
        pass
    else:
        raise SystemExit('PATCH FAILED [buffer cap]: expected Config buffer setup not found')

# Replace check-then-increment connection limiting with CAS reservation.
needle = '''func (s *Statistics) AddConn() {\n\tatomic.AddInt64(&s.activeConns, 1)\n}\n\nfunc (s *Statistics) RemoveConn() {\n\tatomic.AddInt64(&s.activeConns, -1)\n}'''
repl = '''func (s *Statistics) AddConn() {\n\tatomic.AddInt64(&s.activeConns, 1)\n}\n\nfunc (s *Statistics) RemoveConn() {\n\tfor {\n\t\tv := atomic.LoadInt64(&s.activeConns)\n\t\tif v <= 0 {\n\t\t\treturn\n\t\t}\n\t\tif atomic.CompareAndSwapInt64(&s.activeConns, v, v-1) {\n\t\t\treturn\n\t\t}\n\t}\n}\n\nfunc (s *Statistics) TryAddConn(limit int64) bool {\n\tif limit <= 0 {\n\t\treturn true\n\t}\n\tfor {\n\t\tv := atomic.LoadInt64(&s.activeConns)\n\t\tif v >= limit {\n\t\t\treturn false\n\t\t}\n\t\tif atomic.CompareAndSwapInt64(&s.activeConns, v, v+1) {\n\t\t\treturn true\n\t\t}\n\t}\n}'''
if needle not in s:
    raise SystemExit('PATCH FAILED [conn limiter primitive]')
s = s.replace(needle, repl, 1)

# Update both TCP/WS and QUIC accept/stream admission sites. These exact forms are v1.8.1.
s = re.sub(
    r'if atomic\.LoadInt64\(&stats\.activeConns\) >= int64\(cfg\.MaxConns\) \{\n(.*?)\n\t\t\}\n\t\tstats\.AddConn\(\)',
    r'if !stats.TryAddConn(int64(cfg.MaxConns)) {\n\1\n\t\t\tcontinue\n\t\t}',
    s, count=1, flags=re.S)
# Some accept paths already have slightly different indentation/close handling; patch the simple check form too.
s = re.sub(
    r'if atomic\.LoadInt64\(&stats\.activeConns\) >= int64\(cfg\.MaxConns\) \{\n(.*?)\n\s*\}\n\s*stats\.AddConn\(\)',
    r'if !stats.TryAddConn(int64(cfg.MaxConns)) {\n\1\n\t\t\tcontinue\n\t\t}',
    s, count=2, flags=re.S)

# Remove permanent dead-IP state; transient failures must be retryable.
s = re.sub(r'\n\tdeadIPs\s+map\[string\]bool', '', s)
s = re.sub(r'\n\t\tdeadIPs:\s*make\(map\[string\]bool\)', '', s)
s = re.sub(r'\n\s*if p\.deadIPs\[[^\n]+\] \{\n\s*continue\n\s*\}', '', s)
s = re.sub(r'\n\s*p\.deadIPs\[[^\n]+\]\s*=\s*true', '', s)

# Heartbeat should be idle-only: active application traffic is already proof of liveness.
s = re.sub(
    r'(?s)(func \(s \*MuxClientSession\) heartbeatLoop\(\) \{.*?for \{\n\s*select \{\n\s*case <-ticker\.C:)(.*?)(\n\s*case <-s\.done:)',
    lambda m: m.group(1) + re.sub(r'\n\s*//.*?$', '', '\n\t\t\t\tif time.Since(s.lastActivityTime()) < 25*time.Second {\n\t\t\t\t\tcontinue\n\t\t\t\t}', count=1, flags=re.M) + m.group(2),
    s, count=1)

# The previous heartbeat patch needs a last-activity accessor; only add it when the session
# already has a last-activity field. Otherwise leave the loop unchanged rather than breaking build.
if 'lastActivityTime()' in s and 'func (s *MuxClientSession) lastActivityTime()' not in s:
    m = re.search(r'type MuxClientSession struct \{(?P<body>.*?)\n\}', s, re.S)
    if not m or 'lastActivity' not in m.group('body'):
        raise SystemExit('PATCH FAILED [heartbeat]: no lastActivity field to gate heartbeats')
    insert = '''\nfunc (s *MuxClientSession) lastActivityTime() time.Time {\n\tv := atomic.LoadInt64(&s.lastActivityUnixNano)\n\tif v <= 0 {\n\t\treturn time.Time{}\n\t}\n\treturn time.Unix(0, v)\n}\n\n'''
    s = s[:m.end()] + insert + s[m.end():]

# Fast-path standard Mux stream queue isolation: never park the single session read loop on a slow stream.
# We patch both client/server PushDataFrame implementations when their bodies contain hasSpace waiting.
for func_name in ('PushDataFrame',):
    positions = [m.start() for m in re.finditer(r'func \([^)]*\) ' + func_name + r'\([^)]*\) error \{', s)]
    for pos in reversed(positions):
        start = s.rfind('\n', 0, pos) + 1
        brace = s.find('{', pos)
        depth = 0; end = None
        for i in range(brace, len(s)):
            if s[i] == '{': depth += 1
            elif s[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1; break
        if end is None: raise SystemExit('PATCH FAILED [PushDataFrame]: unterminated body')
        body = s[start:end]
        if 'hasSpace' not in body:
            continue
        # Preserve the existing method's surrounding validation by replacing only the blocking wait.
        body2 = re.sub(
            r'(?s)for \{\n\s*select \{\n\s*case <-[^:]+:\n\s*case <-time\.After\([^)]*\):.*?\n\s*\}\n\s*\}',
            'if !s.queueHasSpace(len(payload)) {\n\t\treturn errors.New("mux stream backpressure")\n\t}',
            body, count=1)
        if body2 == body:
            # Do not guess; keep this implementation untouched and let tests validate it.
            continue
        s = s[:start] + body2 + s[end:]

if s == orig:
    raise SystemExit('PATCH FAILED: no changes made')
p.write_text(s)
PY

gofmt -w "$SRC"

go test ./...
go test -race ./...
go vet ./...

TMP_EXE="/tmp/goway-v1.8.2.exe"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$TMP_EXE" .

# Only commit after every verification step succeeds.
git diff --check
git status --short

git add "$SRC"
git commit -m 'refactor(goway): v1.8.2 performance and mux hardening'
git push origin main

# Remove temporary runner and local backup after the successful source push.
rm -f "$BACKUP"
git rm --cached --ignore-unmatch apply-v182-refactor.sh >/dev/null 2>&1 || true
git rm -f --ignore-unmatch apply-v182-refactor.sh >/dev/null 2>&1 || true
if ! git diff --cached --quiet; then
  git commit -m 'chore(goway): remove temporary refactor runner'
  git push origin main
fi

echo
echo '=== GOWAY v1.8.2 REFRACTOR COMPLETE ==='
git log -2 --oneline
echo "Windows binary: $TMP_EXE"
