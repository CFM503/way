# Changelog

All notable changes to the **Way Proxy** project (Goway & Pyway) are documented in this file.

> **⛔ Standing rule (2026-09-23, permanent): all Goway changes must be forward optimizations; reverse (regressive) changes are never allowed.** Ship only with same-machine medians vs baseline **v1.8.11** showing no metric regressed beyond noise (c1/c8/c32, CPU, RSS; n≥5; `rushway/scripts/w2_bench.ps1`), numbers recorded in `goway/AI_HANDOFF.md`. Otherwise tune, default-off gate, or revert. All AI taking over must read `goway/AI_HANDOFF.md` first. 详细规则见 `goway/AI_HANDOFF.md` 顶部。

---

## [v1.8.16] - 2026-10-03

### 正确性修复 + 安全加固 + 默认关闭的新能力（P0 乱序 / AEAD / QUIC 证书钉扎 / QUIC 多连接）

- **P0 乱序修复（正确性，实证 3/3 复现）**: v1.8.15 的 `enqueueDataFrame` 直推 fast-path 存在同流帧乱序——大帧 A 落入 ingress 被 `PushDataFrame` 阻塞等待字节预算（已释放 `bufMu`、不在 ingress 内）时，更晚到达的小帧 B 满足 `len(ingress)==0`+预算直推 `readChan`，越过 A 交付 → 背压窗口内混合帧长即触发流数据损坏。修复：`MuxStream`/`MuxServerStream` 增加 `inFlight` 原子计数（fallback 入队 +1、deliveryLoop 处理完 -1），fast-path 仅在 `inFlight==0` 时启用——背压时自动退回 v1.8.14 的纯 ingress 顺序，无背压热路径不变。回归测试 `goway_reorder_test.go`（client+server 双份，修复前 3/3 FAIL）。
- **② 小修四项**: ① UDP/MUX 隧道判定改精确匹配（`classifyServerTarget`）——旧 `HasPrefix("UDP"/"MUX")` 会把 `udp-example.com:443`、`mux.dev:443` 等真实目标误路由进隧道；② `RemoteResolver` DNS 缓存加 4096 条上限+过期淘汰（原 map 只增不减）；③ 日志落盘节流 2s + 锁外写（原每条 WARN/ERROR 在全局锁内同步重写文件，错误风暴拖住全部转发 goroutine）；④ `flag.Usage` 帮助文本与实际默认值对齐（-W 128 / -mux-sessions 8）。
- **③ 安全加固**: ① `MaxWSFrameSize` 64MB→12MB+64（对齐发送端 BufPool 上限；64MB 声称即分配是纯内存洪水攻击面，认证前同样受惠）；② `verifyAuthKey` 常数时间比较；③ **QUIC 证书从密钥确定性派生**（Ed25519，同 -k 同证书）+ `-verify-quic` 客户端钉扎——QUIC 模式从"自签+跳过验证（可 MITM）"升级为真认证，无密钥（-allow-open）保持随机证书；④ 服务端 `-server-block-local`（默认关）堵住 -allow-open 部署的内网 SSRF（TCP/MUX/UDP/QUIC 五个拨号点全覆盖）。
- **③ `-cipher aead`（默认关闭，双端同开）**: 每帧 AES-256-GCM，线格式 `[nonce(4B 进程随机前缀+8B 计数)|ct|tag]`（+28B/帧），`muxDataChunkLimit` 自动降至 65507；同时**修复 non-mux 中继数据面明文传输的设计缺口**（XOR 模式仅加密 auth/OK/MUX/UDP 帧，中继载荷明文上线——本版在 aead 模式下将 non-mux 数据面一并纳入加密；XOR 模式保持字节兼容不变）。MUX 帧头明文路由、载荷密封：readLoop 层 per-region open（WS 层 `xorOnly` 只去掩码，杜绝双重解密）；obfs pad 位于密封区之外不受影响。手动双进程 e2e 验证（含 70KB 载荷往返）。
- **③ 性能与健壮性**: ① `-quic-conns N`（默认 1=基线，≤16）：QUIC 池多连接轮询 + 后台补满，对标 mux-sessions 并联拥塞窗口；② UDP 出口 `ResolveUDPAddr` 结果按会话缓存（`udpAddrCache`，原每数据报解析+分配）；③ `PushDataFrame` 背压等待复用单个 Timer（原每次唤醒分配）；④ QUIC-UDP len 前缀+载荷合并单次 stream.Write（两方向）；⑤ WS/QUIC-UDP atyp=0x04 显式长度校验（原依赖 cap 切片读残留字节）。
- **工程**: 死代码清除（`Statistics.AddConn/RemoveConn`、`Config.TUI`）；gofmt 全仓（cmd/bench、三个测试文件）；`newMuxServerStream` 容忍 nil session（未跟踪的 `goway_2000_test.go` 在 v1.8.15 基线即 panic，已确认非本版回归）。
- **认证**: loopback interleaved A/B vs v1.8.15（n=5, c1/c8/c32, `goway/bench_ab_v16_n5.csv`）——结果与本版全部数据记录于 `goway/AI_HANDOFF.md`。
- **setup_ms 回归调查（2026-10-04，结案：非代码路径成本）**: Round 2（n=10, `bench_ab_v16_n10.csv`）确认 setup_ms 三档 10/0 REGRESSED（恒定 +9-13ms，双侧 parity 均坏向：c1 配对中位差 +8.0/+13.0ms）；安慰剂排除 provenance。插桩定位：全部增量在父进程 `exec.Start()`→子进程 `main()` 之间（CreateProcess 阶段），子进程内各阶段与包 init（GODEBUG=inittrace）完全对等。**根因 = Windows 10 MiB 文件尺寸进程创建悬崖**：≥10,485,760 字节的镜像每次 spawn 多付 ~+12ms（Defender 扫描档位）；未 strip 的 v1.8.15 基线 10,475,520B 恰好压线之下，本版 +28KB 代码使未 strip 基准件 10,503,680B 越线（linker 惰性填充曲线精确复现悬崖位置）。**处置：无代码改动，P0/P1 修复原样保留**——发布构建本就使用 `-trimpath -ldflags='-s -w'`（release.yml:93，7.27MB 远离悬崖）；以发布风格候选件重认证 n=5 与 n=10（`bench_fix_v16_n5.csv` / `bench_fix_v16_n10.csv`）**各 15/15 NOISE**（setup：n=10 c1 -0.8%、c8 +0.0%、c32 -0.5%；n=5 c1 +3.6%、c8 +1.7%、c32 +1.3%，均亚临界）。新增方法论铁律：**基准 A/B 双臂必须按发布风格构建并记录文件尺寸**。全套 `go test -count=1` ok（171s）。

---

## [v1.8.14] - 2026-09-29

### 头对头回归修复：writev 按握手时长自适应门控 + 流缓冲限额 40MiB→9MiB

- **背景（v1.8.13 头对头发现）**: 直接 A/B v1.8.13 vs v1.8.12，loopback c32 下行 **-8.4%（16/4, n=20, REGRESSED）**、RSS +8~11% 偏移——逐步链 A/B（n=10/crit9）因功效不足全部漏检。双安慰剂（同源码重建对打）证明 harness 无假阳性。
- **归因（全部 n=20 双侧直测）**: P1 心跳/期限、P2 队列/缓冲、P3 QUIC 参数、P5 sessions、P6 PGO 全部 NOISE 清白；**P4 writev 攒批 = 元凶**（p3 vs p4 下行 16/4 -11.8% + 复现 20/0 -7.6%，上行 15/5 -4.7% 也确认；Linux loopback 同样 15/4 -6.5/-7.9% → 非平台问题）。批量上限扫描：frames=8 弱网强收益但 loopback -8~-12%；frames=1 loopback 恢复（0/10 +10.5%）但弱网上行 -15.9% REGRESSED；=2 折中仍残留 -3%。
- **修复**: ① writev 改**握手时长分类**（client `dialNewSession` 建链起测、server `handleServer` 到 auth 起测，~2-3 RTT；>30ms 判弱网启用攒批（≤8帧/256KB），否则单帧直写）——无每写状态、无协议变更、按会话一次判定；写时长 EMA 方案实测失效已否决（loopback 背压下写同样阻塞）。② `muxClient/ServerStreamBufferLimit` 40MiB→**9MiB**（= 窗口8192KiB+刷新1MiB 精确满足 `TestStreamBufferLimitCoversWindow`；40MiB 为已回滚的 32MiB 窗口臂设计，驻留池化缓冲 +11.5% RSS 的来源）。
- **认证（v1.8.14 vs v1.8.12 同机直测）**: loopback 全档 n=10 **15/15 NOISE**；loopback c32 n=20 全 NOISE（下行 +9.8% 偏正、RSS +2.5%——两项回归全消）；WSL2 40ms netem n=10 **2 IMPROVED / 0 REGRESSED**（c8 上行 +12.3% 1/9、c8 下行 +14.1% 1/9、c1 CPU -6.2% 1/9——弱网收益保留）。gofmt/vet 干净、全套 `go test` ok 62.9s。
- **方法论备注**: 跨日逐步链相加无效（机况漂移 ±10%）；±3% 量级效应需 n=20+ 才可判定；order 奇偶拆分可检出位置伪影；证据 CSV `goway/bench_ab_*.csv`（本地，gitignore）。

## [v1.8.13] - 2026-09-29

### Goway 不改协议七项优化落地（bug修复 / 调参 / QUIC / writev / 并行度 / PGO / 减拷贝）

- **Phase 1 修 bug**: 心跳保活、16 处写超时覆盖、退款阈值修正；loopback A/B 15/15 NOISE（`bench_p1.csv`）。
- **Phase 2 窗口调参**: ingress 帧数队列 8→768（按 8MiB 窗口设计的帧数队列在 32MiB 窗口下 ingress full 即 RST——本次核心发现，队列 768 + 缓冲 40MiB 消除）；窗口 32MiB/刷新 8MiB 因 RSS 回退（c32 338→982MB, 10/0）按正向规则弃用，维持 8192/1MiB；双环境 15/15 NOISE（`bench_p2_final_loop.csv` / `bench_p2_final_netem.csv`）。
- **Phase 3 QUIC**: `MaxIncomingStreams` 512→4096 + Initial/Max 四窗×2（`defaultQUICConfig`）；loopback QUIC A/B 15/15 NOISE（`bench_p3_loop.csv`）；netem QUIC 被 **pre-existing 静默 stall** 阻塞（QUIC+WSL2 netem 双向 UDP 无 PTO 无错误，基线同样复现；`diag_quic.sh`/`quicudp_diag.txt` 证据，独立调查项）。
- **Phase 4 writev**: mux 出口攒批（≤8 帧 / 256KB）单 `net.Buffers.WriteTo` 一次 writev；帧编码改 `encodeMuxFrame*` 原位零拷贝；锁内 check+Wait 原子化防 lost-wakeup；netem 0 REGRESSED、**2 IMPROVED**（c1 cpu -9.6% 1/9、c32 up +21.2% 1/9，`bench_p4_netem.csv`）→ 保留。
- **Phase 5 并行度**: `-mux-sessions` 默认 4→8、非 mux 连接池 10→16；双环境 15/15 NOISE（0 回归；作务书 +10~30% 的高 BDP 收益在本机 40ms netem 未复现）→ 按作务书保留。
- **Phase 6 PGO**: loopback+netem × c1/c8/c32 × server/client 共 12 份 pprof 合并为 `default.pgo`（入库，`go build` 自动拾取）；首次 A/B c1 up 9/1 REGRESSED → n=20 确认 14/6 < crit15 **未复现**；netem 15/15 NOISE → 保留。
- **Phase 7 减拷贝**: 握手大帧直读返回堆（消除 pool+copy，`largeFramePool` 及测试移除）；UDP 隧道→出口 sendmmsg 批写（Linux `WriteBatch` 8 包/批，读前 flush 零附加时延，非 Linux 即发回退；与 recvmmsg 读侧对称）；双环境 15/15 NOISE（`bench_p7_loop.csv` / `bench_p7_netem.csv`；UDP 批写 TCP bench 不覆盖，依对称设计+审查）。
- **测试修复**: `TestMuxOutboundWriterFairness` 改为暂停构造、全量入队后再启动 loop——Phase 4 批量 drain 不再每帧阻塞于 pipe，原“先入队后出队”时序假设出现竞态（HEAD 单帧阻塞掩盖了该竞态）。
- **数据与规则**: 全部 A/B 数据 `goway/bench_p*.csv`（本地证据，gitignore）；判定 = 精确符号检验 + 实践门限，明细见 `goway/AI_HANDOFF.md`。

## [v1.8.12] - 2026-09-23

### Goway Mux VERSION/WINDOW credit flow control + lock-free credit gate（RushWay 联动 Phase 3）

- **协议**: 新增 `MuxCmdVERSION=0x05` / `MuxCmdWINDOW=0x06` 控制帧（stream_id=0），握手后双侧立即发 VERSION（`[u8 ver=1][u16 window_kib BE]`，初始 8 MiB）；首见 VERSION 幂等启用每流 `creditGate`；WINDOW（`[u32 credit BE]`）按每 1 MiB 已消费量回执，封顶于对端广告窗口。旧版对未知 cmd 静默跳过 → 新旧任意组合安全降级（8/8 兼容冒烟实证）。
- **无锁热路径**: `creditGate` 快路径全原子（`state/window/available` CAS；Acquire = 状态载入+窗口钳制+CAS，Release = 封顶 CAS+非阻塞信号）；`enableMu` 仅序列化 Enable/Close 状态迁移——每帧 Mutex 已从 `MuxStream.Write` 与服务端发送循环移除。语义不变：幂等启用、Close 唤醒防死锁、Oversize 钳制防饿死。
- **范围**: 仅 WS MUX；QUIC/非 mux/UDP 不设门（保持 v1.8.11 行为）。
- **性能认证（正向规则）**: 交错同会话 A/B，n=10/setup + n=10/steady，逐样本配对差分 + 精确符号检验（crit=9, p≤0.05），基线 = HEAD 构建 v1.8.11。**setup c1/c8/c32 中位差 +9.72/+9.06/+2.12，steady +55.26/−2.23/−0.02；cpu/rss 亦全部 NOISE——双模式无任何指标超噪声回退，认证 non-inferior。** 数据 `rushway/bench/w3_ab_goway.csv` + `w3_ab_raw.log`；规则与明细见 `goway/AI_HANDOFF.md`。
- **测试**: `gofmt`/`go vet` 干净；新增 `flow_test.go` 9 用例；全套 `go test` ok 62.9 s；跨实现兼容冒烟 `rushway/scripts/w3_compat_smoke.ps1` 8/8 PASS（新新×双向 + 四组新旧配对）。

## [v1.8.11] - 2026-09-22

### Goway 服务端 MUX 专用写协程与 unmasked 单遍编码（RushWay 联动 Phase 2）

- **服务端出口去串行 (P1)**: `MuxServerSession.SendFrame` 不再在整个 BufPool 取缓冲 + `TransformInPlace` + socket 写期间持有 `writeMu`。帧入队到 per-session `muxOutboundWriter`（与客户端相同的 DRR + 优先级 lane 调度器），cipher 在专职写协程单遍完成；锁不跨网络 IO。
- **`writeMuxFrameUnmasked`**: 服务端→客户端帧永不 mask——单遍组装 unmasked WS 头并对预编码 MUX 区域做 region-relative XOR（语义与 `TransformInPlace` 逐字节一致）。obfs 尾部仍在声明长度区域内，按声明长度切片忽略。
- **`muxOutboundWriter.masked`**: 构造函数改为 `newMuxOutboundWriter(conn, prng, crypto, masked bool)`；客户端/测试 `masked=true`（既有 fused mask 路径），服务端 `masked=false`。Ping 帧 mask 位跟随 writer。
- **`MuxServerSession.writer`**: `handleServerMux` 构造 `newMuxOutboundWriter(wsConn, nil, cfg.Crypto, false)`；`Close` 在关连接后 `writer.close()` 排空并归还池缓冲。无 writer 的裸测试夹具回退 `sendFrameInline`（旧直写路径）。
- **线格式不变**: unmasked 服务端 WS、MUX 7 字节头、XOR 覆盖 header+payload（+obfs 尾）；与 v1.8.10 及 RushWay 字节兼容。
- **回归**: 新增 `TestMuxFrameUnmaskedEqualsTwoPass`（两遍 vs 单遍 unmasked 全长度 × 有/无 key 逐字节等价 + 往返）；`newMuxOutboundWriter` 全部调用点升为 4 参。`go vet` 干净；`go test -count=1 -timeout 240s` 全绿（约 60s）。
- **基准（Windows 回环 n=3 中位，仅供参考）**: 相对 v1.8.10 baseline 同机 A/B 胜负格互换、落在噪声带内；本版本以结构正确性与测试证据为准，不宣称吞吐提升。
- **说明**: 早先同日交接中曾提前写入“已完成”记录，以本条及 `goway/AI_HANDOFF.md` 为准。

## [v1.8.10] - 2026-09-20

### Goway SYN 保序修正、服务端长连接修复与日志终端适配

- **SYN 永不让行 (P0)**: v1.8.8 自保序规则误伤 SYN——排在自己流 DATA 后的 SYN 会让路，导致对端把先到的 DATA 当未知流静默丢弃（整流消失、零日志；RushWay 侧联调抓获）。现仅 FIN/RST 让行，SYN/系统帧永远插队。新增 `SynNeverYieldsToOwnData` 为证（修复前必现 `[DATA, SYN]` 错序）。
- **服务端长连接写限修复 (P0)**: `handleConnection` 的绝对 deadline 在服务端路径从不清掉（已验证 Go 语义：`SetReadDeadline` 刷新不碰写限，过期后写必 `i/o timeout`），服务端会话将在 accept+ConnTimeout 后的第一次写死亡（默认 60s，压测小 timeout 下数秒即现）。现握手完成后清除，行为回退到 v1.8.8（中继期各走滚动读限）。慢消费者长尾另记 backlog，与本次无关。
- **日志清行符 TTY 门控**: `\r\033[K` 只在终端输出，管道/文件不再吃转义垃圾（纯 stdlib `ModeCharDevice` 检测，零依赖）。

## [v1.8.9] - 2026-09-20

### Goway Mux DRR 死锁消除、队头阻塞疏通与生产级韧性加固

- **DRR obfs 死锁消除 (P0)**: 开启 `-obfs` 时单个 DATA 帧加填充最高达 ~67KB，超过原 `muxDRRQuantum` (64KB)。当流赤字不足或单流传输时，旧 `nextDataLocked()` 单轮遍历后直接返回 false，导致写协程在 `w.cond.Wait()` 永久休眠死锁。修复：将 `muxDRRQuantum` 扩至 128KB（赤字上限 512KB），并在 `nextDataLocked()` 引入 `hasFrames` 多轮累加赤字循环直至满足发包条件，绝不误入休眠。
- **优先队列队头阻塞消除 (P1)**: 优先控制队列改为全队列扫描弹出首个未阻塞流的控制帧，消除队首流受阻时对后续其他流 Ping 探针或新流 SYN 建立的队头阻塞（HOL Blocking）。
- **监听瞬态容错与网络重置恢复 (P1)**: `listener.Accept()` 捕获 `net.Error.Temporary() / Timeout()` 瞬态错误并自动退避重试，避免 Windows 瞬态套接字耗尽或重置导致服务端循环意外中断退出。
- **空闲连接超时与连接池耗尽防护**: 本地连接握手增加 60s 读取超时（`SetReadDeadline`），交付 MUX 流后解除，杜绝端口扫描或半开连接占满 `MaxConns` 造成假死；StreamID 32 位计数器回绕至 0 时自动跳过 0，避免流标识碰撞。
- **Panic 级联崩溃防护**: 关键数据流中继与连接分发入口均增加 `defer recover()` 守护，拦截偶发异常，保障核心服务高可用。
- **终端状态刷新优化**: 每次普通日志输出前执行 `\r\033[K` 清除控制台残留的 `[STATS]` 统计行，彻底解决多行日志重叠与字符吞食问题。
- **回归验证**: 新增 `LargeObfsFrameNoDeadlock` 与 `PriorityQueueNoHeadOfLineBlocking` 自动化测试用例，全量单测保持 100% 通过。
- **测试文件裁决**: `goway_test.go` **保留**——它是唯一综合回归集（40+ 测试，含本轮公平/等价/UDP 用例）；已删的是 v1.8.4 旧文件（v1.8.7），当前无无用测试文件。

## [v1.8.8] - 2026-09-20

### Goway 同流保序修复（DRR 优先 lane 数据丢失）

- **Bug（RushWay 联调抓获）**: DRR 优先 lane 让 FIN/RST 无条件插队——当它与同流的排队 DATA 同时在列时，FIN 先发、对端提前关流、尾部 DATA 被丢。RushWay 侧复现为 HTTP 响应 1596B 发出但客户端收不到（`curl 000`）；回环 Go→Go 因单帧写节拍+速度侥幸躲过，属潜伏 bug。
- **证明**: 新增 `FinNeverOvertakesOwnData`（同流 DATA×2 + FIN 同批入列，net.Pipe 阻塞写器）——修复前输出 `[FIN, DATA, DATA]`，确诊。
- **修复**: 优先 lane 改为流感知自保序——队首 control 若其流还有排队 DATA 则本轮让路（仍排在其它流 bulk 之前），无 DATA/新流/SYN/ping 照常插队。跨流公平（`ControlJumpsQueue`、`InteractiveJumpsAheadOfBulk`）不受影响。

## [v1.8.7] - 2026-09-18

### Goway UDP 批量、变换融合与 QUIC 修剪

- **#2 UDP 批量接收（recvmmsg）**: 新增 `udpBatch`（`x/net/ipv4 ReadBatch`，8 包/批，64KB 缓冲无截断），4 条 UDP 中继循环（server/client × WS/QUIC）的 `ReadFromUDP` 全量切换；无 recvmmsg 的平台（Windows）首次自动降级为单包读，行为一致；`cloneUDPAddr` 深拷贝消除批量槽复用竞态。测量（WSL2 Debian，回环，20000 包积压纯 drain）：单包 ~360MB/s → 批量 ~527MB/s（**~1.45×**，满批 maxBatch=8）；无积压时与单包持平。`x/net` 升为直接依赖（已缓存 v0.28.0，离线可构建）。
- **#4 发送路径 cipher+mask 单遍融合**：客户端 MUX DRR 写路径取消入队时 `TransformInPlace`，改为写时 `writeMuxFrameFused` 单遍 `word ^ keystream ^ mask64`（偏移语义与两遍版逐字节一致，`TestMuxFusedEncodeEquivalence` 覆盖 0~65535 字节 × 有/无 key）。测量（64KB 帧）：两遍 ~1730MB/s → 单遍 ~3000MB/s（**~1.7×**）。LUT 挑战者（4×256 表，建表成本计入）仅 ~1770MB/s——**LUT 判负，不装船**。
- **#5 QUIC 修剪**：`MaxIdleTimeout` 60s→30s（死连接更快回收）；补 `MaxIncomingStreams 512` / `MaxIncomingUniStreams 128` 显示上限；`EnableDatagrams` 关（全仓无一处收发 datagram，只耗握手字节）；KeepAlive 保持 15s（防严格 NAT 绑定丢失）。
- **测试清理**：删除 `goway_v184_test.go`（v1.8.4 时代回归文件，其覆盖已被主测试文件包含）；新增 `TestUDPBatchReadLoopback`、`TestMuxFusedEncodeEquivalence` + 5 组 benchmark。

## [v1.8.6] - 2026-09-18

### Goway 公平调度与流量混淆

- **MUX 写端公平 DRR 调度**: `muxOutboundWriter` 改为 per-stream 队列 + 优先级 lane（ping/SYN/FIN/RST 优先）+ DATA 按 deficit round robin（64KB quantum，赤字上限 256KB）；队列上限 8→64（保持背压）；`RemoveStream` 丢弃该流已排队帧；锁不跨网络 IO。解决 bulk 流埋掉交互流的 video-stall 模式。
- **单边 `-obfs` 填充**: 新 flag `-obfs`（`Config.Obfs`）；MUX DATA 帧在 WS payload 内追加随机 `[0,1400]` 填充，MUX 声明长度不变，老端按声明长度切片直接忽略，单边部署安全；客户端 + 服务端 `SendFrame` 双侧生效；填充为随机字节（零填充本身可被指纹）。
- **测试**: 新增 `TestMuxOutboundWriterFairness`、`TestMuxObfsPadding`；`go.mod` 仅将 quic-go 提升为直接依赖（版本不变）。

## [v1.8.4] - 2026-09-11

### Goway 深度并发与生命周期审计

- 修复 MuxClientSession PRNG 与 sync.Pool 的关闭生命周期竞争；SendFrame 在 writeMu 内重新检查状态并固定 PRNG，Close 等待物理写临界区退出后再归还。
- 为 MuxServerStream.targetConn 增加独立 targetMu，保护设置、快照、关闭和清空，不进入数据转发热路径。
- 强化 readUntilCRLFCRLF() 硬上限，超长单行和累计头部均立即返回 header too large。
- 为日志 ring buffer 与保存路径增加并发保护。
- 强化并发回归：慢/快流、RST/EOF、targetConn、1000 Stream、PRNG、日志。
- 审计确认现有 writeMu 会串行化物理 WebSocket Write；本版本不强行引入高风险 bounded queue 重构，保持协议与架构兼容。


## [v1.7.8] - 2026-09-04

### Goway 核心修复与性能结构优化

#### 🐛 P0 核心缺陷修复
- **Mux 客户端与服务端 Session.Close() 死锁修复**:
  - 修复在持有 `streamsMu` 互斥锁的情况下遍历调用 `st.Reset()`，因 `st.Reset()` 内部反向调用 `RemoveStream()` 导致二次争抢互斥锁引发的死锁。
  - 重构为锁内原子提取流快照并清空映射表，释放锁后再在外层逐个调用 `st.Reset()`，确保连接关闭、超时重置与进程退出时 100% 幂等无死锁。
- **QUIC 连接池锁粒度与生命周期修复**:
  - 重构 `QUICClientPool.GetStream()`，将阻塞耗时的 DNS 解析、`quic.DialAddr` 与 `OpenStreamSync` 彻底移出互斥锁临界区。
  - 引入 Single-flight 屏障通道（`dialing` channel），杜绝多协程并发突发获取流时引发的并发建连风暴与互斥锁长时间阻塞假死。
  - 完善失败连接生命周期：`OpenStreamSync` 失败时立即安全关闭连接（`CloseWithError`）并在锁内精准剔除，彻底杜绝孤儿连接泄漏。
- **HTTP 代理 TCP 分包与粘包治理**:
  - 客户端代理在读取 HTTP CONNECT 请求头时引入动态循环缓冲机制，持续读取至完整匹配 `\r\n\r\n` 或 `\n\n`。
  - 严格施加 `MaxHeaderSize` 上限保护，彻底解决因底层 TCP 分包导致头部被截断识别为畸形协议报文的问题，兼备慢速 DoS 攻击防范能力。
- **SOCKS5 UDP ASSOCIATE 截断读取安全校验**:
  - 针对客户端协商 SOCKS5 UDP 关联阶段的 4 处 `io.ReadFull` 补充严格的错误与 EOF 判定，阻断报文残缺时进入未定义状态。

#### ⚡ P1 / P2 性能与协议健壮性
- **Mux 慢流背压与自动回收**:
  - 完善 `MuxServerStream.PushData()` 返回值处理，当探测到底层队列满、超时或对端关闭时，自动从 Session 映射中摘除并向对端发送 RST 帧，杜绝单一卡顿慢流拖死多路复用主读循环。
  - 增加 `handleNewStream()` 初始数据 `Write` 错误检查，写失败时立即中止流并回收资源。
- **WebSocket RFC 6455 规范合规化**:
  - 严格限制控制帧载荷不超过 125 字节，遇到超限控制帧立即报错中断。
  - 增加 Opcode 范围合法性检查（支持 Ping/Pong/Close/Text/Binary）。
  - 服务端与客户端增加针对标准 Ping 控制帧的 Pong 自动回应。
  - 帧内存池实施容量封顶限制（> 64KB 自动回收或防止池无限膨胀）。
- **isLocalTarget 安全精准判定**:
  - 使用 Go 原生 `net.ParseIP` 标准库取代易受混淆的字符串前缀匹配，严格识别 IPv4/IPv6 私网、回环（127.0.0.0/8, ::1）及链路本地地址。
- **代码精简与冗余清理**:
  - 移除未使用的死函数 `tryClientFallbackDial()` 与 `padRight()`。
  - 清理 `Crypto` 结构体中冗余字段 `keyBytes`、`keyLen`。
  - 精简 `Config` 配置中无用字段。

#### 🧪 测试验证与压测
- 自动化全栈测试套件覆盖率进一步提升，增加 QUIC 并发建连、锁竞争、容灾重试、Mux 慢流背压与暴力多协程压测。
- 本地 241 MB/s 暴力吞吐压测与真实海外 VPS 跨国弱网测试均实现 0 错误率、0 丢包。

---

## [v1.7.7] - 2026-09-04

- **QUIC 协议全栈验证**: 完成端到端 SOCKS5 TCP over QUIC、HTTPS 网页加载与大文件持续流传输验证。
- **服务器 UDP 防火墙放行指南**: 完善说明文档，补充服务器端在单端口放行 TCP/UDP 双向流量（ufw / iptables）的操作指引。
- **测试套件规范合规与脱敏**: 测试用例中的 IP 与敏感字段泛化脱敏，杜绝私有凭据与 IP 泄露。

---

## [v1.7.6] - 2026-09-04

- **MUX 连接池无锁异步扩容**: 消除 `GetSession()` 跨国网络握手对全局互斥锁的阻塞，解决并发建流首屏白屏卡顿。
- **WebSocket Ping 心跳保活**: 客户端后台 25s 自动发送 Ping，服务端 Pong 回应，消除空闲超时断连。
- **单流拥塞超时保护**: `MuxStream.PushData` 增加非阻塞探测与超时重置机制。
- **冷启动防假死**: 上游 IP 探测改为异步执行且设置 3 秒硬超时，杜绝冷启动连接拒绝。
- **人性化分组帮助**: 重构 `-help` 界面分类，支持 `-no-mux` 与 `-no-block-local` 便捷参数。

---

## [v1.7.5] - 2026-09-04

- **修复 MUX 100% CPU 死循环**: 修复服务端 `handleNewStream` 在 EOF/断连时缺失 `return` 导致的单核空转缺陷。
- **TLS 指纹切片安全防护**: 增加空切片边界检查与默认 TLS 兜底配置，避免切片越界 panic。
- **HTTP CONNECT 端口容错**: 为缺失 `:port` 的请求增加 443 端口 fallback。
- **全栈自动化测试套件**: 建立 `goway_test.go` 端到端回归测试体系。

---

## [v1.7.4] - 2026-09-04

- **PGO 编译器调优**: 采集真实高并发工况生成 `default.pgo` 配置文件，由 Go 编译器完成机器码级优化。
- **纯单文件固化**: 维持 `goway.go` 单一源码文件自包含架构。
- **Cloudflare CDN 适配**: 支持通过 `-fakehost` 接入 Cloudflare CDN Anycast 边缘网络。

---

## [v1.7.3] - 2026-09-03

- **全面支持 QUIC 协议传输**: 客户端支持 `-up quic://host:port`，抗弱网丢包对标 Hysteria 2。
- **服务端双栈监听**: 同一端口自动同时监听 TCP (WebSocket) 与 UDP (QUIC)。
- **内存自签 TLS 1.3**: 服务端动态在内存生成 ECDSA P-256 证书。

---

## [v1.7.0] - [v1.7.2] - 2026-09-03

- **SOCKS5 UDP ASSOCIATE 代理**: 完整支持 RFC 1928 SOCKS5 UDP 协议，支持 HTTP/3、DNS 与游戏加速。
- **0-RTT 多路复用 (Mux 架构)**: 单一主干长连接并发多虚拟 Stream 通道。
- **Linux 内核级零拷贝与优化**: `TCP_QUICKACK` 消除 40ms 延迟，支持 `SO_REUSEPORT` 多核负载均衡。
- **低内存高并发设计**: 应用缓冲区默认优化为 64KB，提升 CPU L1/L2 缓存命中率。

## [Unreleased]

_(no open entries — Phase 2 server writer shipped in v1.8.11)_
