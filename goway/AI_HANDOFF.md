# goway AI handoff

## MANDATORY standing rule — forward-only optimization (every AI, every change)

**Every modification to this project MUST be a forward optimization. Reverse (regressive) optimization is NEVER acceptable. This rule is permanent and survives all future sessions.**

- **Every AI that takes over this work MUST read this file before changing code**, and MUST preserve this rule verbatim — do not delete, weaken, or reword it.
- A performance-relevant change may only be declared complete when same-machine, same-harness medians vs the current released baseline (**v1.8.11**, measured with `scripts/w2_bench.ps1` in the rushway repo: throughput c1/c8/c32, CPU_s, peak RSS; n≥5, setup + steady) show **no metric regressed beyond noise**. Better-or-equal on every metric, or the change does not ship.
- **If the bar is not met: tune it, gate it behind an opt-in flag whose default equals baseline behavior, or revert it. Shipping a known regression violates this rule.**
- New protocol/feature work is allowed only when the default path stays at-or-above baseline performance; capability without measurable regressions.
- Record before/after numbers in this file with every performance-relevant change. **No numbers, no completion.**
- User mandate, 2026-09-23. 违反此规则的改动一律不得合入：只允许正向优化，永远禁止反向优化。

## 2026-09-23 — W3 Phase 3: Mux VERSION/WINDOW credit flow control (paired with RushWay W3)

### Shipped (uncommitted working tree, awaiting user approval)
- `MuxCmdVERSION=0x05` / `MuxCmdWINDOW=0x06` control frames (stream_id=0), post-handshake negotiation: both sides send VERSION (`[u8 ver=1][u16 window_kib BE]`, init 1 MiB) immediately after writer init; first-seen VERSION enables per-stream `creditGate` (idempotent); WINDOW (`[u32 credit BE]`) refunds >=64 KiB consumed, capped at advertised window, floor 64 KiB, credit <=64 MiB and !=0.
- New `creditGate` type (chan-based credit, Enable/Release/Close/Acquire(n, wait)); wired into `MuxStream.Write` (client upload), server target-pump send loop, `refundPending` on both download directions; every Close path closes the gate (waiter wakeup, no deadlock); `addConsumed` booked by the single pump owner (no double-release).
- ReadLoop + server dispatch intercept VERSION/WINDOW before stream lookup (unknown/old frames still skipped by no-default switches -> v1 fallback safe on all old/new pairings).
- Direction bug caught pre-test: server receive path must NOT charge sendGate (only book refunds); fixed before first run.
- New `flow_test.go`: gate semantics (unbounded pass, throttle/release, close wakeup, window clamp, wait-channel abort, idempotent enable) + applyPeerVersion/applyWindow round-trips (9 tests).

### Validation
- `gofmt -l` empty; `go vet` clean; full `go test -count=1` ok 64.8 s.
- Cross/compat smoke `rushway\scripts\w3_compat_smoke.ps1` **8/8 PASS** twice (initial 1 MiB/64 KiB params, and again after retune): new/new both impls both directions assert negotiation logs; all four new/old pairings assert zero negotiation + transfer OK. True-old baseline rebuilt from git HEAD `1aaeee0` (first backup attempt had accidentally captured a W3 build - stash-source is the required method for old baselines).
- **Retune (round 2):** params raised 1 MiB -> 8 MiB window, 64 KiB -> 1 MiB refund (`muxInitialWindowKib`/`muxWindowRefresh`) after round-1 re-test showed throughput regression (goway steady c1/c8/c32 -68%/-56%/-40% vs W2). Round-2 loopback n=5: setup 165/255/257, steady 112/343/287, rss 91-95.
- **CORRECTION (n=10 confirmation, `rushway\bench\w3c_goway_n10.csv`, same binary as round 2):** the round-2 n=5 steady c8/c32 "beat W2" reading did **not** reproduce. n=10 medians vs v1.8.11 (W2 n=5): setup 169.2/231.19/231.08 (cpu 1.9, rss 93.25) = c1 -32%, c8 -21%, c32 -14%, cpu flat, rss +7%; steady 250.34/211.1/185.36 (2.385, 94.3) = c1 -13%, c8 -24%, c32 -29%, cpu +11%, rss +6%. Same-build n=5 vs n=10 disagree wildly (steady c8 343 -> 211), so single-run medians on this machine are not decisive — but under the forward-only rule above, **W3 current state is NOT certified forward on performance**: every candidate number set except one is below baseline. Status: performance claim withheld pending an interleaved same-session A/B vs a v1.8.11 baseline binary, or default-off gating. Functional/compat evidence (8/8 smoke, unit suites) stands.

### Remaining risk / next
- Released as **v1.8.12** (tag + push 2026-09-23); goway version const updated. QUIC/non-mux/UDP intentionally ungated (scope). Steady rushway c8/c32 ~-15% vs W2 still needs a confirmatory run before absolute claims.

### 2026-09-23 follow-up — atomic creditGate + interleaved A/B certification (W3)

- **Forward optimization of the W3 machinery itself:** `creditGate` hot path rewritten lock-free (`state atomic.Int32` unbounded/bounded/closed + `window`/`available atomic.Int64` CAS; `Acquire` fast attempt = state load + window clamp + CAS, `Release` = capped CAS + non-blocking token). `enableMu` now serializes only the rare Enable/Close transitions — the previous per-chunk `Mutex.Lock/Unlock` around gate check-and-consume is gone from `MuxStream.Write` and the server send loop. Semantics unchanged (idempotent first-Version enable, close wakeup, window clamp, wait-channel abort); `flow_test.go` field probes updated to atomic loads.
- Validation: `gofmt -l` empty, `go vet` clean, gate/apply/version tests `-count=2` pass, full `go test -count=1` ok 62.9 s, `go build` OK (`goway.exe` rebuilt).
- **A/B verdict method corrected:** `rushway\scripts\w3_ab_bench.ps1` verdict switched from independent medians (misleading on an interleaved design) to **paired per-sample deltas + exact two-sided sign test** (ties dropped; REGRESSED only when bad-count ≥ crit for effective n; n=10 → crit=9 at p≤0.05). Script bug fixed en route: verdict loop variable `$samples` collided with `param([int]$Samples)` (PowerShell case-insensitive) → renamed `$pairIds`; stale CSV deleted before the run.
- **Interleaved same-session A/B, n=10 per mode, order flipped every sample** (`rushway\bench\w3_ab_goway.csv`, arms: `bench\oldbin\goway_v1811_ab.exe` HEAD-built v1.8.11 vs rebuilt atomic-gate `goway.exe`):
  - **setup:** c1 medΔ +9.72 (4bad/6good), c8 +9.06 (4/6), c32 +2.12 (5/5), cpu -0.19 (6/4), rss -2.30 (7/3) — all NOISE → **VERDICT: NOISE (no metric beyond noise)**.
  - **steady:** c1 medΔ +55.26 (2bad/8good), c8 -2.23 (6/4), c32 -0.02 (6/4), cpu +0.03 (5/5), rss -4.70 (8/2) — all NOISE (crit=9 not reached) → **VERDICT: NOISE (no metric beyond noise)**.
- **Certification:** under the forward-only standing rule (no metric regressed beyond noise, numbers recorded), **W3 as shipped (8 MiB window / 1 MiB refund / atomic gate) is now certified non-inferior vs baseline v1.8.11** by interleaved paired A/B. The atomic rewrite is additionally a strict overhead reduction vs the mutex gate it replaces. Watch item: setup/steady rss trends +2.3/+4.7 MB (7/10 and 8/10 bad, both below crit) — re-check at higher n before claiming RSS parity; steady c1 8/10 favors W3 but stays below crit so no forward-throughput claim either.
- Raw log: `rushway\bench\w3_ab_raw.log`. This supersedes the earlier "NOT certified pending A/B" status above; the n=5/n=10 separate-run conflict remains as documented rationale for why same-session pairing is the required method here.

## 2026-09-22 — v1.8.11 release: Phase 2 server writer + unmasked fused encode

### Shipped
- Version `1.8.10` → **`1.8.11`** (`goway.go` const).
- Content = Phase 2 as previously reviewed (see sections below): `writeMuxFrameUnmasked`, `masked` constructor, `MuxServerSession.writer`, `sendFrameInline` fallback, `TestMuxFrameUnmaskedEqualsTwoPass`.
- Pre-release fix: repaired two mojibake em-dashes in `goway_test.go` comments (`鈥?` → `—`).

### Pre-release code review (no functional bugs found)
- Buffer: `frameLen+14` check + obfs `room = len(buf)-14-frameLen` keeps `14+frameLen+padLen <= len(buf)`; unmasked `frameStart = payloadOffset-hdrLen` with `payloadOffset=14`, `hdrLen ∈ {2,4,10}` stays ≥ 0.
- Close race: `SendFrame` checks `s.closed` then `enqueue`; closed writer returns false and `releaseFrame` returns the pool buf. `Close` closes conn before `writer.close()` so a blocked write errors and the loop exits.
- `sendFrameInline` has no mutex — only used when `writer == nil` (bare unit-test fixtures); production always sets writer in `handleServerMux`.
- Ping mask bit follows `w.masked` (server unmasked / client masked) — correct per RFC 6455 direction rules.
- Wire format unchanged vs v1.8.10 for MUX region; RushWay slices by declared length (interop intact).

### Validation (this release)
- `gofmt -l` empty; `go vet ./...` clean.
- `go test -count=1 -timeout 240s ./...` → ok.
- `go build` → `GOWAY v1.8.11`.
- Phase 4 n=3 loopback A/B vs baseline: noise-level, no throughput claim in release notes.

### Not in this release
- Live RushWay↔GoWay paired e2e; PGO retrain; competitor bench set; commit of pending `goway_fuzz_test.go` if not staged (check `git status` at release).

## Prior: Phase 2 detail (still authoritative for design)

### Correction
Earlier same-day entries in this file claimed Phase 2 was already implemented and tested. Those claims were premature: at the start of this session `goway.go` still had `MuxServerSession.writeMu` held across BufPool + `TransformInPlace` + `conn.Write`, and `newMuxOutboundWriter` was still 3-arg. **This entry is the first record backed by code actually landing and a green suite.**

### Target
- Paired program with RushWay (`D:\SOFT\AI\github\rushway`): objective #1 (forwarding speed), #2 (CPU).
- Bottleneck: `MuxServerSession.SendFrame` held `writeMu` across buffer-pool get, cipher, and network write — full serialization of all server→client MUX frames per session, plus a two-pass memory transform.

### Change
1. **`writeMuxFrameUnmasked(w, buf, payloadOffset, payloadLen, opcode, crypto)`**: single-pass server egress — builds unmasked WS header in-buffer, region XOR matching `TransformInPlace` (offset resets per region), one `w.Write` of header+region. No mask key (server frames never masked).
2. **`muxOutboundWriter.masked bool`**: `newMuxOutboundWriter(conn, prng, crypto, masked bool)`. Client/tests pass `masked=true` (existing `writeMuxFrameFused` path); server passes `masked=false`. Ping frames use `w.masked` for the WS mask bit.
3. **`MuxServerSession`**: field `writer *muxOutboundWriter` replaces `writeMu`. `handleServerMux` constructs `writer = newMuxOutboundWriter(wsConn, nil, cfg.Crypto, false)`.
4. **`SendFrame` (server)**: closed-check → nil-writer → length/buffer checks → encode MUX header+payload (+ optional obfs DATA pad) into pooled buf → `writer.enqueue(frame)`. Cipher deferred to writer goroutine (same pattern as client). No lock held across IO.
5. **`sendFrameInline`**: legacy direct-write path (old `writeWSFramePreallocated` + `TransformInPlace`) used only when a bare `MuxServerSession` fixture has no `writer`. Production always sets `writer` in `handleServerMux`.
6. **`Close`**: `s.writer.close()` after `wsConn.Close()` so the egress loop drains and returns pool buffers.
7. **Tests**: all `newMuxOutboundWriter` call sites updated to 4-arg (`masked=true` for client-style writers). New `TestMuxFrameUnmaskedEqualsTwoPass` proves wire identity vs two-pass (TransformInPlace + unmasked `writeWSFramePreallocated`) across sizes 0…70000 × with/without key, plus unmasked round-trip.

### Astra review
- Ordering: single writer goroutine preserves per-session wire order; DRR priority lane + SYN/FIN/RST rules unchanged (shared scheduler).
- Cipher: region-relative XOR identical to previous two-pass; offset resets per region.
- Obfs: pad still DATA-only, within `obfsPadMax`, outside declared MUX length — receivers ignore tail as before.
- Backpressure: `enqueue` still blocks at `muxOutboundQueueDepth` (64) — same contract as client.
- Failure: enqueue on closed writer returns error (SendFrame fails fast); writer task closes conn on write error.
- Concurrency: enqueue lock never wraps `wsConn.Write`.

### Validation (this session — actual runs)
- `gofmt -w` on `goway.go` / `goway_test.go` / `goway_fuzz_test.go`.
- `go vet ./...` clean (exit 0).
- `go test -count=1 -timeout 240s ./...` → **ok goway 60.751s** (includes `TestMuxFrameUnmaskedEqualsTwoPass`, fused-equivalence, DRR fairness, regressions).
- `go build -o goway_phase2.exe .` → runs `-version` → `GOWAY v1.8.10`.
- `writeMu` field: gone from `MuxServerSession` (only comment mention remains).

### Status
- Phase 2 **code complete** in goway working tree; **not committed/tagged**.
- `goway.exe` in this dir still the pre-Phase-2 artifact (2026-09-20); use `goway_phase2.exe` or rebuild.

### Remaining risk / next
- Live RushWay↔GoWay paired e2e not re-run this cycle.
- No before/after server-egress microbench this cycle (Phase 4 joint bench selected by user).
- `default.pgo` not retrained.
- Next: Phase 4 joint benchmark (user-selected) → then Phase 3 (version negotiation + WINDOW) if wanted.

## Cross-session pointer
- RushWay program state: `D:\SOFT\AI\github\rushway\AI_HANDOFF.md` + `PROGRESS.md`.
- Paired Phase 1 (rushway UX) is in those files; this file is authoritative for **goway-side** Phase 2 only.

## v1.8.13 cycle: Phase 0 (bench) + Phase 1 (bug fixes) — 2026-09-28

### Phase 0 — A/B bench infrastructure
- `git worktree add --detach` at `%LOCALAPPDATA%\Temp\opencode\way_v1812`, built
  `goway_v1812_baseline.exe` (reports `GOWAY v1.8.12`); `git diff v1.8.12 HEAD --stat`
  was empty at baseline build time.
- New `goway/cmd/bench` (stdlib only): in-process full-duplex target, SOCKS5 load,
  spawns server+client per sub-run, metrics up/down MBs, cpu_s, rss_mb, setup_ms,
  CSV out, interleaved paired runs with per-sample order flip, exact paired sign
  test summary (ties removed), proc-death detection.
  - Flags: `-arms "base,cand" -samples N -concurrency 1,8,32 -out file.csv`.
  - Callsite gotcha: `-arms` must be ONE comma-joined string (array args break flag).
- Self-check same-binary n=10 produced 1 false positive of 15 metrics (c32 up 9/1),
  so verdict gates are sign test (alpha=0.05) AND practical thresholds
  (throughput 3%, cpu/rss/setup 5%).
- `.gitignore` += `bench_out*.csv`, `bench_*.log`, `bench.exe`, `cand_*.exe`,
  `bench_*.csv`.

### Phase 1 — three fixes (code complete, tested, A/B certified)
1. **Heartbeat with active streams** (`heartbeatLoop`): old condition skipped pings
   whenever `ActiveStreams() > 0`, so an active-but-idle session let both rolling
   read deadlines fire at ConnTimeout and Close() reset every stream. Now skips only
   when `writer == nil` (teardown). `muxHeartbeatInterval` is a package var for tests.
   Tests: `TestHeartbeatPingsWhileStreamsActive`, `TestHeartbeatNilWriterDoesNotPanic`.
2. **Write deadlines (M6 wedge)**: process previously set NO write deadline anywhere.
   Added `refreshWriteDeadline` (500ms-throttled, same rationale as deadlineThrottle,
   timeout = `cfg.ConnTimeout`, <=0 disables) + `writeDeadlineSetter` interface
   (covers net.Conn and quic.Stream). Applied at 16 sites: muxOutboundWriter.loop
   (ctor now 5-arg, writeTimeout field, loop-goroutine-owned lastWriteSet), client
   mux download pump, server mux target pump + initialData write, non-mux server
   WS<->target both directions, non-mux client WS<->local both directions, QUIC TCP
   server/client both directions, WS-UDP upload (server+client), QUIC-UDP upload
   (server+client). UDP socket WriteTo/WriteToUDP sites intentionally skipped
   (datagrams do not block). Healthy-traffic refresh proven by test:
   `TestMuxOutboundWriterWriteDeadline` (wedge -> teardown <3s; active reader
   survives 1.8s of writes under a 700ms deadline).
   Constraint: ConnTimeout must stay > 500ms (throttle window), holds for any
   sane `-connection-timeout`.
3. **Refund threshold clamp (1c)**: `muxRefundThreshold = min(muxWindowRefresh,
   muxInitialWindowKib*1024/2)` used at both WINDOW emit sites (client download
   refund, server addConsumed). Unchanged at current constants (1MiB < 8MiB/2),
   guards any future window < 2MiB from stalling before the first refund.
   Test: `TestRefundThresholdNeverExceedsHalfWindow`.

### Validation (this session)
- `gofmt -l .` clean; `go vet ./...` clean.
- `go test ./... -count=1` -> **ok goway 66.482s** (full suite incl. new tests).
- `go build -o cand_p1.exe .` -> `GOWAY v1.8.12` banner (version string unchanged
  until release step).

### A/B certification (Phase 1 vs v1.8.12) — data: `goway/bench_p1.csv`
Protocol: interleaved, order flipped per sample, n=10 per arm per concurrency,
sign test crit=9 (alpha=0.05, ties removed), machine noise band +/-20%+.

| conc | metric | base_med | cand_med | med-delta | bad/good/tie | verdict |
|------|--------|----------|----------|-----------|--------------|---------|
| 1 | up | 310.16 | 300.60 | +3.15% | 5/5/0 | NOISE |
| 1 | down | 330.78 | 320.55 | +3.2% | 5/5/0 | NOISE |
| 1 | cpu_s | 19.22 | 20.45 | +4.0% | 7/3/0 | NOISE |
| 1 | rss | 85.46 | 90.81 | +7.9% | 8/2/0 | NOISE |
| 1 | setup_ms | 111.20 | 111.72 | +1.4% | 6/4/0 | NOISE |
| 8 | up | 273.36 | 308.46 | +16.7% | 3/7/0 | NOISE |
| 8 | down | 278.13 | 327.91 | +19.4% | 3/7/0 | NOISE |
| 8 | cpu_s | 21.16 | 23.55 | +11.1% | 8/2/0 | NOISE |
| 8 | rss | 145.00 | 146.57 | +2.3% | 6/4/0 | NOISE |
| 8 | setup_ms | 112.27 | 111.37 | -1.2% | 3/7/0 | NOISE |
| 32 | up | 278.45 | 281.34 | +1.0% | 5/5/0 | NOISE |
| 32 | down | 303.25 | 298.66 | +1.6% | 4/6/0 | NOISE |
| 32 | cpu_s | 22.62 | 22.85 | +1.3% | 5/5/0 | NOISE |
| 32 | rss | 231.54 | 241.58 | +5.0% | 7/3/0 | NOISE |
| 32 | setup_ms | 111.52 | 112.66 | +0.6% | 5/5/0 | NOISE |

**Verdict: 15/15 NOISE, 0 REGRESSED -> Phase 1 passes the forward-optimization
gate; no metric beyond practical thresholds with sign-test significance.**
Closest calls: c1 rss 8/2 (+7.9%), c8 cpu 8/2 (+11.1%) — both short of crit=9;
per protocol they would confirm at n=20 (crit=15) only if a later re-run
reproduces them. Not confirmed -> accepted as noise.

### Status / next
- Phase 0+1 complete, uncommitted (user has not requested commits).
- Next: Phase 2 window retune (muxInitialWindowKib 8192->32768, muxWindowRefresh
  1MiB->8MiB, stream buffer limits 8MiB->40MiB >= window+refresh) with WSL2 netem
  40ms high-BDP acceptance + loopback A/B; then Phase 3 QUIC params, 4 writev,
  5 parallelism, 6 PGO, 7 copy reduction, release v1.8.13.
## v1.8.13 cycle: Phase 2 (window retune attempt + burst-safety fixes) — 2026-09-28

### What was tried
Tuning arm (REVERTED per forward-optimization rule): `muxInitialWindowKib 8192->32768`,
`muxWindowRefresh 1MiB->8MiB`.
Safety fixes (KEPT): `muxClient/ServerStreamBufferLimit 8MiB->40MiB`,
frame queues `muxStreamIngressQueue 128->768`, client `readChan` 128->768, server
`writeChan` 256->768 (new consts `muxStreamIngressQueue`/`muxStreamAppQueue`).

### Netem harness (new, reusable)
- WSL2 Debian: `sudo tc qdisc replace dev lo root netem delay 20ms` (20ms each way =
  40ms RTT); `wsl -d Debian -e bash -lc '<cmd>'`; remove with
  `sudo tc qdisc del dev lo root netem`.
- Linux builds: `GOOS=linux GOARCH=amd64 go build` for goway and cmd/bench; arms run
  from /mnt/d; bench writes CSV into the repo dir.
- Gotchas: bench `-arms` needs ABSOLUTE paths (Go exec ErrDot); `-extra` splits on
  COMMA (`-extra "-log,WARN"`).

### Finding 1 (fixed): frame-depth queues reset streams under window bursts
- With 32MiB window + OLD depths (128/128/256), 40ms netem collapsed throughput:
  c8 -71%/-74%, c32 -57%/-67%, with whole samples at 0.00 Mbps. Evidence (bench -v,
  log WARN): `[MUX] Stream 1 ingress queue full, resetting stream` /
  `[SERVER-MUX] Stream 2 ingress queue full, resetting stream` on the candidate ONLY.
- Mechanism: `enqueueDataFrame` is non-blocking; when the ingress chan (128 frames =
  8MiB at 64KB) fills mid-burst it RESETS the stream instantly. Old depths were sized
  exactly for the old 8MiB window (128 x 64KB), so base never tripped them.
- Fix: depths 768 = ceil(40MiB/65535)=641 rounded up, so the byte budget (not frame
  count) governs admission. Invariant added to `TestStreamBufferLimitCoversWindow`;
  hardcoded 128/256 fill loops in `TestMuxStream_PushDataTimeout` /
  `TestMuxServerStream_PushDataCleanupOnFalse` now use `muxStreamAppQueue`.

### Finding 2 (rule verdict): window raise fails the RSS gate — REVERTED
- With 32MiB window + fixed queues, netem n=10 (`bench_p2_netem.csv`): throughput
  recovered AND improved (c8 down +10.3% IMPROVED 1/9; c32 down +15.6% IMPROVED
  0/10; c1/c8/c32 up NOISE), but RSS regressed on all three levels with sign 10/0:
  c1 49.5->60.8 (+21.5%), c8 132->225 (+59.5%), c32 338.5->982.2 (+190%).
- Mechanism (not noise): steady-state RSS ~= concurrency x advertised window
  (32 streams x 32MiB = 1GiB legal in-flight; 982MB measured, max 993MB).
  The user rule for tuning items: any metric beyond noise -> default reverts.
  Window/refresh reverted to 8192/1MiB; the forfeited gain is recorded here so the
  tradeoff can be revisited deliberately (e.g. 16MiB window would still fail the 5%
  RSS gate at +76% c32).
- Old-window edge kept safe: buffer limit stays 40MiB (>= window+refresh invariant;
  credit gating caps steady-state queues at exactly 8MiB so RSS is neutral) and
  frame depths stay 768 (kills the exact-edge RST risk for small-frame bursts).

### Final certifications (both environments, n=10 interleaved)
- Loopback Windows, cand_p1 vs final cand_p2 (`bench_p2_final_loop.csv`): 15/15
  NOISE, 0 REGRESSED.
- WSL2 40ms netem, same arms (`bench_p2_final_netem.csv`): 15/15 NOISE, 0
  REGRESSED; RSS parity restored (c32 343.6 vs 351.9, +1.3% NOISE).
- `gofmt -l .` clean, `go vet ./...` clean, `go test ./... -count=1` ok ~65s.

### Status / next
- Phase 2 complete: tuning rejected by rule (documented above), safety fixes kept,
  uncommitted.
- Next: Phase 3 QUIC params (MaxIncomingStreams 512->4096 + larger receive window;
  MaxIdleTimeout 30s and EnableDatagrams stay as v1.8.7 left them), then Phase 4
  writev, 5 parallelism, 6 PGO, 7 copy reduction, release v1.8.13.
## v1.8.13 cycle: Phase 3 (QUIC params) + QUIC/netem stall finding — 2026-09-28

### Change (kept)
`defaultQUICConfig`: MaxIncomingStreams 512->4096 (pool opens one stream per local
conn; 512 was below realistic bursts), receive windows x2: InitialStream 2->4MiB,
MaxStream 8->16MiB, InitialConn 4->8MiB, MaxConn 16->32MiB. Idle timeout 30s and
EnableDatagrams false untouched (v1.8.7 trims).

### Harness additions (bench)
- `-upstream-template` (default `ws://127.0.0.1:%d`) — enables QUIC A/B runs with
  `-upstream-template "quic://127.0.0.1:%d"` (server always listens QUIC on -p UDP).
- `-hs-timeout` (default 5s) — SOCKS connect timeout for streams after the first.

### Certification
- Loopback Windows QUIC A/B n=10 (baseline cand_p2, `bench_p3_loop.csv`):
  **15/15 NOISE, 0 REGRESSED** (incl. rss +0.7%/+1.6%/+3.9% all NOISE) -> gate
  GREEN, change kept.
- WSL2 40ms netem QUIC A/B: **cannot certify — pre-existing stall bug hits BOTH
  arms** (see finding below). Not a Phase 3 regression.

### FINDING (pre-existing, needs dedicated investigation): QUIC silent stall under
### WSL2 netem latency + initial bulk burst
- Repro: `bash diag_quic.sh` (netem 20ms each way, client quic://, bench c=5,
  hs-timeout 10s). Symptom: streams 1-4 complete SOCKS/QUIC setup, stream 5's
  "OK" never reaches the client (bench `i/o timeout`); sometimes 3 or 4 succeed.
- Evidence (`quicudp_diag.txt` tcpdump): one second with ~1400-1800 UDP packets
  (target's generate-write blast through the tunnel), then BOTH directions go
  completely silent for the rest of the capture — no PTO retransmits, no
  CONNECTION_CLOSE, no goway errors, quic-go never errors the stream read.
  Healthy runs sustain ~100-160 pkts/s.
- Baseline (p2, old 512/stream config) fails identically -> pre-existing.
- Works at zero RTT (loopback QUIC 83 Mbps full A/B runs, all samples ok).
- Eliminated: GSO (`QUIC_GO_DISABLE_GSO=1` still fails), netem queue tail drops
  (`limit 100000` still fails), -log DEBUG slows traffic enough to MASK the bug
  (run passes), QUIC_GO_LOG_LEVEL=debug also masks it (timing-dependent).
- Also observed while working: QUIC+netem caps ~10 Mbps vs WS+netem 92 Mbps
  same conditions — same investigation bucket.
- Hypotheses left: quic-go send/ACK wedge after burst on WSL loopback+netem;
  WSL UDP GRO/GSO interaction; needs packet-level quic-go trace at full speed
  or repro outside goway (plain quic-go transfer) to bisect.

### Status / next
- Phase 3 code kept (loopback green). QUIC netem certification pending the stall
  fix; WS-mode netem A/B harness unaffected (used for phases 1-2, reusable).
- Next: Phase 4 writev (mux egress batched net.Buffers), then 5 parallelism,
  6 PGO, 7 copy reduction, release v1.8.13.
## v1.8.13 cycle: Phase 4 (writev batching) + Phase 6 (PGO) — 2026-09-28

### Phase 4: mux egress writev (kept — 2 IMPROVED, 0 REGRESSED)
- Change: `writeMuxFrameFused/Unmasked` split into `encodeMuxFrame*` (header +
  mask + cipher in place, returns wire slice, no copy) + thin write wrappers
  (tests keep using them). `muxOutboundWriter.loop` now drains up to
  `muxWritevMaxFrames=8` / `muxWritevMaxBytes=256KB` already-scheduled frames
  via non-blocking `tryNext`/`popLocked` and emits ONE `net.Buffers.WriteTo`
  (single writev syscall). Ping frames flush the accumulator and keep the old
  path. DRR fairness, frame order, FIN/RST yielding unchanged (popLocked =
  old next() body). On any batch error: release batch, dropAll, close conn
  (same as single-frame semantics).
- Harness: bench gains `-extra-server` / `-extra-client` (separate arg lists;
  needed for per-process `-cpuprofile` files).
- Certification: loopback n=10 `bench_p4_loop.csv` 15/15 NOISE;
  WSL2 40ms netem `bench_p4_netem.csv` **0 REGRESSED, 2 IMPROVED**
  (c1 cpu -9.6% 1/9; c32 up +21.2% 1/9). rss signs 9/1 at c1/c32 stayed under
  the 5% practice gate (+2.1%/+4.4%) -> NOISE.

### Phase 6: PGO (kept — regression not confirmed at n=20)
- Profile collection: single-arm bench runs at c=1,8,32 on BOTH loopback and
  netem, server+client each writing `-cpuprofile` (6s `-cpuprofile-duration`
  beats the ~8s subrun kill so files flush). 12 profiles merged:
  `go tool pprof -proto -output default.pgo prof_*.pprof` (34KB, 72s/108s
  samples; hot: runtime.cgocall 40%, osyield 12%, memmove 9% — I/O bound).
- Builds: `-pgo=off` (base) vs `-pgo=auto` (picks up goway/default.pgo).
- Certification: loopback n=10 `bench_p6_loop.csv` had c1 up REGRESSED
  (9/1, -3.8%) -> protocol confirmation run n=20 `bench_p6_c1_confirm.csv`:
  14/6 < crit 15 -> **NOT confirmed, NOISE** (down also 14/6). netem n=10
  `bench_p6_netem.csv`: 15/15 NOISE. Gate passes -> default.pgo kept
  (commit it with the release; `go build` auto-detects it).
- Note: the first loopback pass also showed the machine warming up
  (base med 480->516 across runs) — the n=20 rerun absorbed that drift.
## v1.8.13 cycle: Phase 5 (parallelism) + Phase 7 (copy reduction) — 2026-09-29

### Phase 5: mux-sessions 4→8 + non-mux pool 10→16 (kept per 作务书, verdict NOISE)
- Per task book (作务书), executed after PGO despite the earlier "skip" note:
  flag default `-mux-sessions` 4→8 (help text updated), `NewConnPool(&cfg, 16)`
  for non-mux mode (mux is default-on, so the pool change is config
  consistency; the bench exercises mux mode only).
- Certification (base = Phase 7 build): loopback `bench_p8_loop.csv` 15/15
  NOISE (setup_ms with 8 sessions unchanged, rss +1.9% NOISE);
  netem `bench_p8_netem.csv` 15/15 NOISE (c32 up -4.2% sign 7/3 below
  crit 9 → NOISE; c32 down +3.7% NOISE). The claimed +10~30% high-BDP gain
  did NOT materialize in the 40ms WSL2 harness — no regression either, kept
  because the task book mandates it.

### Phase 7: copy reduction (kept — 0 REGRESSED both envs)
- `readWSFrameInto` handshake path: frames >512B are read DIRECTLY into the
  heap slice returned to the caller (previously pool buffer → copy → heap);
  `largeFramePool`, `maxPooledFrameCap`, `putLargeFrame` and their test
  deleted. Relay path (buf != nil) unchanged (already zero-copy when it fits).
- UDP tunnel→egress write batching (the mirror of the existing recvmmsg read
  side): `newUDPBatchWriter(conn, up)` queues up to `udpBatchCount=8`
  datagrams (payload copied into 8×64KB slots — callers reuse their read
  buffer) and drains via `ipv4.PacketConn.WriteBatch` (sendmmsg on Linux;
  non-Linux writes through per-datagram from the start). Flush points:
  before each blocking read when `br.Buffered()==0` (zero added latency —
  only covers frames already in the bufio buffer), when the queue fills,
  and on loop exit (defer). Partial batch failures pin fallback and resend
  the remainder per-datagram. Stats (up/down bytes) accounted at send time.
  Integrated in all four tunnel→UDP loops: server WS, client WS, QUIC server,
  QUIC client.
- Certification: loopback `bench_p7_loop.csv` 15/15 NOISE; netem
  `bench_p7_netem.csv` 15/15 NOISE (0 REGRESSED → kept). The UDP batch path
  is not exercised by the TCP bench; correctness rests on the runtime
  fallback (Windows = old path byte-for-byte) + symmetry with the proven
  read side.

### Test fix (committed with this release)
- `TestMuxOutboundWriterFairness/InteractiveJumpsAheadOfBulk` failed 10/10
  in the working tree but passed at HEAD: Phase 4's writev drain pops queued
  frames WITHOUT touching the pipe, so it races the test's enqueue loop
  (the old one-frame-per-write loop blocked on the pipe after every frame,
  hiding the race). Instrumented pop trace showed pops 1,1,1,2,1 =
  interleaved enqueue/drain — DRR itself was correct (stream 2 served the
  instant it was queued). Fix: the subtest builds the writer WITHOUT its
  loop, enqueues all frames, then starts `go w.loop()` (deferred close
  registered only after the loop starts, since close() waits on done).
  Fairness ×10 + full suite green.

### Status / next (final)
- All seven phases executed: 1 (bugs), 2 (window tuning), 3 (QUIC), 4
  (writev), 5 (parallelism), 6 (PGO), 7 (copy reduction). Kept: all except
  the Phase 2 32MiB window/RSS-gated items (rolled back per rule).
- Verdicts: 4 = IMPROVED (netem c1 cpu / c32 up); everything else NOISE with
  0 confirmed regressions; Phase 6 c1 regression not confirmed at n=20.
- Release: v1.8.13 (version bump, CHANGELOG, tag). Evidence CSVs local
  (gitignored); profiles prof_*.pprof local (gitignored); `default.pgo`
  committed. Bench harness (`goway/cmd/bench`) committed.
- Open items for the next session: QUIC+WSL2 netem silent stall
  investigation (pre-existing, Phase 3 blocker); real-WAN high-BDP A/B to
  validate the Phase 5 +10~30% claim; Phase 7 UDP batch path has no live
  bench coverage (add a UDP bench arm if UDP throughput becomes a target).

## v1.8.14 cycle: head-to-head regression hunt + handshake-gated writev — 2026-09-29

### Trigger: v1.8.13 vs v1.8.12 head-to-head (user request)
- Weak net (WSL2 40ms netem, n=10): **2 IMPROVED / 0 REGRESSED**
  (c8 up +25.2% 1/9, c1 cpu -9.6% 1/9) — v1.8.13's netem story held.
- Loopback (Windows, n=10): c32 rss flagged 9/1 (+8.0%) → protocol
  confirmation **n=20: c32 down 16/4 -8.4% REGRESSED** (up 14/6, rss
  13/7 both NOISE). The per-phase chain (n=10/crit9) had missed it: five
  steps leaned negative at 6-7/3 individually, all sub-crit.
- Two placebo runs (v12_final vs identical rebuild v12_copy, n=20 each):
  11/9 -4.5% and 9/11 +0.5% — harness has no phantom-regression
  mechanism; later verdicts trustworthy. Order-parity splits (ord1/ord2)
  exposed ±8% positional swings; runs whose signal lives in ONE parity
  only (e.g. v14c 15/5 = ord1 10/10 + ord2 5/10) are suspect, runs
  negative in BOTH parities (v13: -33.7/-30.4) are real.

### Attribution (all n=20, same-day binaries, direct adjacent pairs)
- P1 (heartbeat/deadlines/refund): v12 vs p1 **9/11 +0.5% NOISE** — clean.
- P2 (queue 768/40MiB): p1 vs p2 **9/11 +4.0% NOISE** — clean.
- P3 (QUIC params): p2 vs p3 **9/11 +1.4% NOISE** — clean.
- **P4 (writev) = the culprit:** p3 vs p4 down **16/4 -11.8%** then
  replication **20/0 -7.6%** REGRESSED; up 15/5 -4.7% (confirmed in
  rep 2). v12 vs p4 pooled 29/40 down. Linux loopback p3 vs p4 n=20:
  up **15/4 -6.5%**, down **15/4 -7.9%** REGRESSED → platform-independent
  fast-link cost, not Windows/WSASend.
- v12 vs p3 (P1-P3 cumulative): **8/12 GOOD-leaning NOISE** — confirms
  P1-P3 as a block too.
- P5 (sessions 8): in-context toggle (v14c vs sessions-4 build) all
  NOISE — task-book sessions 8 stays. P6 (PGO): -pgo=off toggle all
  NOISE (13/7 leans "PGO helps") — stays. P7 not exercised by the WS
  TCP bench (handshake-only + UDP paths).
- RSS: v12 vs p4 16/4 +10.6% and v12 vs wv2(f2) 17/3 +11.5% confirmed;
  individual steps sub-noise → thin spread with the 40MiB stream buffer
  limit as the retention driver.

### Frame-cap sweep (single-variable builds off HEAD)
| cap | loopback c32 down (vs f8/v13) | netem up (vs f8) |
|---|---|---|
| 8 | baseline (v13: -8.4% vs v12) | baseline (v13 netem +25% vs v12) |
| 4 | +2.6% 3/7 NOISE | -1.8% 6/4 NOISE |
| 2 | **+10.5% 3/7** (median restored) | c8 -9.5% 8/2, c32 -6.7% 7/3 (sub-crit) |
| 1 | **+10.5% 0/10 IMPROVED** | **c8 -12.8% 9/1, c32 -15.9% 9/1 REGRESSED** |

### Fix shipped (v1.8.14)
1. **Handshake-duration classification** replaces both fixed caps and the
   failed write-duration EMA attempt (EMA selected f8 on loopback too:
   c32 backpressure blocks writes >500µs → v14d reproduced -8.4% —
   documented dead end). Design: client times `dialNewSession` (dial +
   upgrade + MUX auth ≈ 2-3 RTT), server times `handleServer` entry →
   auth frame; `writevBatchFor(setupDur)` = batch8 if >30ms else
   single-frame (loopback/LAN <10ms, 40ms netem 80-120ms). Static per
   session, no protocol change, no per-write state. Plumbing:
   `newMuxOutboundWriterBatched(..., batchMax)`, `w.batchMax` field set
   before `go loop()`; old 5-arg constructor kept as wrapper (tests).
2. **`muxClient/ServerStreamBufferLimit` 40MiB → 9MiB** (= window
   8192KiB + refresh 1MiB exactly; `TestStreamBufferLimitCoversWindow`
   still passes; queue depths stay 768). The 40MiB headroom belonged to
   the reverted 32MiB-window arm and let streams retain pooled buffers.

### Certification (candidate `v14e` vs v12_final, same-machine paired)
- Loopback full c1/c8/c32 n=10: **15/15 NOISE**.
- Loopback c32 n=20: all NOISE — down **+9.8% 6/14 good-leaning**, rss
  +2.5% 11/9 (was 17/3 +11.5%) — both prior regressions eliminated.
- WSL2 40ms netem n=10: **2 IMPROVED / 0 REGRESSED** — c8 up +12.3%
  (1/9), c8 down +14.1% (1/9), c1 cpu -6.2% (1/9); c1 rss +4.6% 10/0
  under the 5% practice gate → NOISE; c8/c32 cpu +13% at 8/2 under crit.
- `gofmt -l` empty, `go vet` clean, full `go test -count=1 ./...` ok
  62.9 s; Windows + cross-compiled Linux builds OK.
- Evidence CSVs: `bench_ab_12_13_*`, `bench_ab_placebo*`, `bench_ab_p4_c32_confirm*`,
  `bench_ab_p1_p4_*`, `bench_ab_p*_c32_confirm*`, `bench_ab_p5off_c32`,
  `bench_ab_p6off_c32`, `bench_ab_v14*_vs12_*`, `bench_ab_wv*` (local, gitignored).

### Session notes (methodology / environment)
- Cross-day chain step-sums are INVALID (regime drift ±10%: base_med
  c32 down swung 315→470 within one day); only direct adjacent same-run
  pairs count. ±3% effects need n=20; n=10/crit9 cannot certify them.
- WSL `go` broken (toolchain go1.25.0 download timeout) → cross-compile
  `GOOS=linux GOARCH=amd64 go build` from Windows (matches how all
  prior `*_linux` binaries were produced). PS5.1 `Set-Content -Raw` /
  `Get-Content -Raw` corrupt UTF-8 source files → always use the Edit
  tool for goway.go; byte-faithful copies via `Copy-Item`.
- Status: **released v1.8.14** (version const, CHANGELOG, tag, push).
  Open items unchanged: QUIC+WSL2 netem stall, real-WAN high-BDP A/B,
  UDP bench arm.