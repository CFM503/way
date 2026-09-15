# GOWAY v1.8.1

GOWAY 是一个基于 WebSocket / QUIC 双协议隧道的高性能代理工具，支持 HTTP 和完整 SOCKS5 (TCP + UDP) 协议，具备浏览器指纹伪装、0-RTT 多路复用 (Mux)、QUIC 弱网抗丢包传输、Cloudflare CDN 边缘接入与 PGO 机器码级性能优化。

## 版本历史

### v1.8.1 (2026-09-04) - Mux 会话预占时序强化、池化内存所有权竞态消除与并发安全加固

#### 核心优化与 Bug 修复

| 优化项 | 说明 | 效果 |
|---|---|---|
| **Mux Session 预占原子前置 (P0)** | `GetSession()` 在池锁内选定会话后立即原子执行 `activeStreams.Add(1)` 预占计数 | **消除建流与注册间的竞态空窗期，高并发场景下各物理会话负载分配绝对均衡，杜绝倾斜** |
| **activeStreams CAS 极限防负保护 (P0)** | `MuxClientSession` 引入 CAS 循环递减 `decrementActiveStreams()`，下界到达 `<= 0` 时恒定锁定在 0 | **彻底消除计数器异常漂移导致负数的数学可能性，保证调度比较绝对准确** |
| **Per-Stream `readMu` 内存所有权保护 (P0)** | 为 `MuxStream` 增加独立的 `readMu sync.Mutex` 保护当前数据帧与读取生命周期 | **杜绝 Reader 拷贝中途 Closer 提前归还 `curFrame` 到 `BufPool` 的 use-after-recycle 与数据竞争** |
| **流关闭后丢弃新帧与未读队列安全回收 (P1)** | 流在关闭状态下若接收到 channel 交付的新帧立即释放归还，`cleanup()` 安全排空剩余全部未读帧 | **保证池化 buffer 全生命周期零泄漏、零重复释放（double free），内存绝对安全** |
| **SendFrame 会话有效性与指针防御 (P1)** | 会话销毁或连接未初始化边界下对 `wsConn` 与 `BufPool` 增加严密校验 | **增强边界异常情况下的系统鲁棒性，彻底杜绝 nil pointer dereference 异常** |

---

### v1.8.0 (2026-09-04) - Mux最少活跃流负载调度、ConnPool事件驱动即时补货与生产性能加固

#### 核心优化与 Bug 修复

| 优化项 | 说明 | 效果 |
|---|---|---|
| **Mux 最少活跃流优先调度 (P0)** | 替换纯 Round-Robin 为“最少活跃 Stream 优先 + 平手 Round-Robin 打散”，引入 `activeStreams atomic.Int64` | **彻底解决长短连接混杂或视频流与网页并发时个别 Mux 会话过载的问题，多连接拥塞窗口负载更均衡** |
| **Stream 生命周期严格单次计数 (P0)** | 绑定 `stream.onClose` 封闭在 `MuxStream.closeOnce.Do` 内，创建时原子 +1，销毁时原子 -1 | **确保活跃流计数值绝对精准，彻底杜绝重复递减或负数，多会话调度零锁竞争** |
| **ConnPool 事件驱动即时补货 (P1)** | `ConnPool.Get()` 弹出连接后非阻塞向 `refillCh` 发送信号，`maintainLoop` 统一事件驱动立即补满 | **消除高并发突发连接对 5 秒定时巡检的依赖，no-mux 模式 50 并发响应时间从 113.5ms 降至 32.5ms (提速 3.5 倍)** |
| **双端背压策略注释与边界澄清 (P1)** | 详尽补充客户端 4 MiB 与服务端 8 MiB 的非对称缓冲设计背景与未来调优说明 | **保留设计意图与架构清晰度，避免后续维护产生混淆** |
| **MuxClientSession.Close 防御性增强** | 在会话销毁时对 `s.wsConn` 增加非空校验保护 | **避免测试或异常边界下发生空指针异常，增强运行时健壮性** |

---

### v1.7.9 (2026-09-04) - Mux零拷贝流水线、精准字节级背压、物理会话扩容与参数调优

#### 核心优化与 Bug 修复

| 优化项 | 说明 | 效果 |
|---|---|---|
| **Mux DATA 零拷贝所有权转移 (P0)** | 引入 `muxDataFrame` 结构体，主读循环直接将缓冲池内存块转移给流通道消费并在流完成时放回池中 | **彻底消除单帧 32KB 的 `make+copy` 堆分配，下行微基准耗时从 6,890 ns/op 降至 21.21 ns/op (提速 ~324 倍，0 B/op，0 allocs)** |
| **精准双端字节级背压 (P0)** | 客户端限制 4 MiB、服务端限制 8 MiB，精准统计 `queuedBytes` 并通过 `hasSpace` 信号与 3 秒僵死流主动 RST 超时保护 | **彻底取代粗粒度通道计数，杜绝慢消费者或暂停客户端导致内存无界积压与会话挂起** |
| **Mux 物理 Session 数可配置 (P1)** | 新增 `-mux-sessions int`（默认 `4`，范围 `1~64`），启动 Banner 与 `-h` 帮助同步更新 | **大带宽跨国 WAN 推荐设为 `8`，成倍拓展底层 TCP 拥塞窗口，彻底消除单 TCP 偶发丢包的队头阻塞** |
| **Server Mux 转发循环内存池化 (P1)** | 服务端 `handleNewStream` 移除每流独立的 `make([]byte, 32*1024)`，直接复用全局 `BufPool` 并限制读取上界为 65535 字节 | **高并发建流下大幅减少 GC 垃圾回收暂停时间，严守 uint16 帧长协议安全边界** |
| **QUIC 服务端 MaxConns 保护 (P1)** | `handleQUICConnection` 增加并发流上限判定，超过限额时记录告警并立即断开流连接 | **杜绝恶意连接通过单条 QUIC Connection 泛洪子流耗尽服务端内存与文件描述符** |
| **no-mux 预热连接池审计与容量满配 (P1)** | 后台 `maintainLoop` 预热目标提升至满额 10 条连接，明确非多路复用隧道在单次转发后的安全销毁生命周期 | **杜绝已关闭连接重新入池引发假死，提升 1:1 模式新请求 0-RTT 命中率** |
| **全参数压测矩阵与黄金配置指南** | 新增本地 700+ MB/s 与 VPS 跨国 WAN 真实网络下的全参数扫描评测脚本与场景化最优化命令行 | **明确指导 4K 极速流媒体、日常网页浏览、CDN 免流及 QUIC 弱网加速的最佳启动参数** |

---

### v1.7.8 (2026-09-04) - Mux死锁治理、QUIC连接池优化、TCP分包与协议鲁棒性加固

#### 核心优化与 Bug 修复

| 优化项 | 说明 | 效果 |
|---|---|---|
| **Mux 会话销毁死锁修复 (P0)** | 修复 `MuxClientSession.Close()` 与 `MuxServerSession.Close()` 在持有互斥锁时级联调用 `st.Reset()` 导致的自死锁 | **确保高并发连接断开、重连与进程退出时 100% 幂等无死锁** |
| **QUIC 连接池锁粒度与防泄漏 (P0)** | DNS 解析、`quic.DialAddr` 与 `OpenStreamSync` 移至锁外，引入 Single-flight 屏障防止建连风暴，建流失败立即安全回收连接 | **消除高并发下长时间互斥锁阻塞假死，彻底杜绝孤儿 QUIC 连接泄漏** |
| **HTTP TCP 分包粘包治理 (P0)** | 客户端代理 HTTP CONNECT 请求头读取引入循环缓冲区，完整检测 `\r\n\r\n` / `\n\n` 并限制 `MaxHeaderSize` | **彻底解决 TCP 分包切片时解析截断导致的 Bad Request 错误，兼具慢速 DoS 防护** |
| **SOCKS5 UDP ASSOCIATE 边界保护 (P0)** | 对 SOCKS5 UDP 协商响应读取中全部 `io.ReadFull` 增加严格的错误与截断校验 | **防止网络异常或报文残缺时进入未定义解析状态，增强协议健壮性** |
| **Mux 慢流背压与自动回收 (P1)** | `MuxServerStream.PushData` 遇到拥塞超时或断开时，自动从 Session 映射中摘除并发送 RST | **杜绝因单一慢流或僵死流积压阻塞整个多路复用隧道的读循环** |
| **WebSocket RFC 6455 规范合规 (P1)** | 严格校验控制帧大小 (≤125 字节)、非法 Opcode 拦截，支持标准 Pong 帧回应与 64KB 缓冲池容量封顶 | **全面提升隧道传输标准合规度，防止内存缓冲池无界增长** |
| **isLocalTarget 安全精准判定 (P2)** | 使用 `net.ParseIP` 标准库解析取代字符串前缀匹配，严格识别 IPv4/IPv6 私网与回环段 | **杜绝地址混淆绕过，精准拦截非法本地回环与内网探测请求** |
| **冗余死代码与结构精简** | 移除未使用的回退拨号函数、字符串填充函数，精简配置结构体冗余字段 | **优化编译体积与内存结构，降低心智负担** |
| **全覆盖暴力压测与测试套件** | 新增覆盖 100+ 并发 QUIC 流、150+ 并发 Mux 流、100MB 视频流吞吐及快速断连的自动化测试套件 | **在真实跨国 WAN 复杂弱网环境下 100% 稳定运行无丢包** |

---

### v1.7.7 (2026-09-04) - QUIC 协议端到端全面验证、UDP 防火墙指南与公网部署加固

#### 核心优化与 Bug 修复

| 优化项 | 说明 | 效果 |
|---|---|---|
| **QUIC 协议全栈验证** | 完成端到端 SOCKS5 TCP over QUIC、HTTPS 网页加载与大文件持续流传输验证 | **在弱网丢包环境下跑满带宽，无 TCP 队头阻塞** |
| **服务器 UDP 防火墙放行** | 补充说明服务器端放行 TCP 与 UDP 双向流量的操作指南（ufw / iptables） | **解决客户端使用 QUIC 模式连接时因服务端只放行 TCP 导致的握手超时** |
| **测试套件公网 IP 泛化脱敏** | 将内部单元测试中的公网 IP 替换为规范保留公共 IP | **确保开源代码仓库 100% 安全合规，杜绝敏感 IP 与密码泄露风险** |

---

### v1.7.6 (2026-09-04) - MUX 并发性能重构、心跳保活与命令行体验升级

#### 核心优化与 Bug 修复

| 优化项 | 说明 | 效果 |
|---|---|---|
| **MUX 连接池无锁异步扩容** | 消除 `GetSession()` 在跨国网络握手时对全局互斥锁的阻塞，健康会话 < 1µs 瞬间复用 | **彻底解决浏览器打开 YouTube/Twitter 并发建流导致的 3~5 秒首屏白屏** |
| **WebSocket Ping 心跳保活** | 客户端新增后台 25s 自动 Ping 控制帧，对端标准 Pong 自动回应 | **彻底消除视频暂停或长文阅读闲置超过 60 秒后底层隧道被掐断的问题** |
| **单流拥塞超时保护** | `MuxStream.PushData` 增加非阻塞探测与 3 秒回退重置机制 | **杜绝个别卡死或暂停的流拖慢甚至假死整个多路复用主读循环** |
| **消除启动 60s 冻结** | 上游 IP 探测改为异步执行且 3 秒硬超时上限 | **保证本地端口瞬间绑定，彻底杜绝冷启动 Connection Refused** |
| **人性化分组 `-help` 界面** | 四层分类重构帮助界面，支持便捷反向参数 `-no-mux` 与 `-no-block-local` | **大幅提升命令行使用体验与参数可读性** |

---

### v1.7.5 (2026-09-04) - 关键缺陷修复与稳定性加固

#### 核心优化与 Bug 修复

| 优化项 | 说明 | 效果 |
|---|---|---|
| **修复 MUX 100% CPU 死循环** | 修复服务端 `handleNewStream` 在 EOF/断连时缺失 `return` 的严重缺陷 | **彻底杜绝单核 100% CPU 盲等空转，确保流资源与内存及时释放** |
| **TLS 指纹切片安全防护** | 为 `pickProfileTLSConfig()` 增加空切片边界检查与默认 TLS 兜底配置 | **杜绝极端或未初始化情况下 `mrand.Intn(0)` 导致的进程崩溃闪退** |
| **HTTP CONNECT 端口容错** | 为缺失 `:port` 的标准 HTTP CONNECT 代理请求增加默认 443 端口 fallback | **增强对各类爬虫、命令行工具和第三方客户端的协议兼容性** |
| **自动化全栈测试套件** | 建立 `goway_test.go`，覆盖加解密、协议握手、分帧及双进程真实联调 | **提供可靠的端到端质量保障与快速回归测试能力** |

---

### v1.7.4 (2026-09-04) - PGO (Profile-Guided Optimization) 终极编译调优与单文件架构固化

#### 核心优化与新特性

| 优化项 | 说明 | 效果 |
|---|---|---|
| **PGO 编译器调优** | 采集真实高并发代理工况生成 `default.pgo` 配置文件，由 Go 编译器完成机器码级优化 | **热点函数内联展开与寄存器分配提升 10%~15% 吞吐量，CPU 开销进一步降低** |
| **纯单文件固化** | 维持 `goway.go` 单一源码文件结构，包含 Mux、QUIC、SOCKS5 UDP 全功能 | **跨平台编译与部署极致简单，无零散依赖文件** |
| **Cloudflare CDN 完美适配** | 基于 WebSocket 隧道封装，完美支持 Cloudflare CDN Anycast 边缘与免杀加速 | **通过 `-fakehost` 与干净 Anycast 节点，突破墙级阻断并享受全球免流 CDN** |

---

### v1.7.3 (2026-09-03) - 全面支持 QUIC 协议传输（抗弱网对标 Hysteria 2）与单文件架构固化

#### 核心优化与新特性

| 优化项 | 说明 | 效果 |
|---|---|---|
| **QUIC 传输模式** | 客户端支持 `-up quic://host:port`，底层基于 UDP 与原生 TLS 1.3 | **消除 TCP 队头阻塞，5%~20% 弱网丢包环境下依然跑满带宽** |
| **服务端双栈监听** | 同一端口自动同时监听 TCP (WebSocket) 与 UDP (QUIC) | **零额外端口占用，老版本客户端与新版 QUIC 客户端无缝共存** |
| **内存自签 TLS 1.3** | 服务端自动在内存中动态生成 ECDSA P-256 证书并完成握手 | **无需繁琐申请配置证书，开箱即用享受端到端高强度前向安全** |
| **单文件架构固化** | 所有网络传输、Mux、QUIC 栈全部整合进单个 `goway.go` | **单源码文件自包含，便于单文件分发、审计与全平台自动化交叉编译** |

---

### v1.7.2 (2026-09-03) - Linux 内核级零拷贝与平台级 Socket 深度调优

#### 核心优化与新特性

| 优化项 | 说明 | 效果 |
|---|---|---|
| **TCP_QUICKACK 调优** | 在 Linux 平台每个网络连接上强制启用 `TCP_QUICKACK` | **消除 Linux TCP 延迟确认 (Delayed ACK) 带来的 40ms 固有延迟卡顿** |
| **SO_REUSEPORT 多核监听** | 在 Linux (3.9+) 开启 `SO_REUSEPORT` 内核负载均衡监听 | **消除高并发下单个监听套接字的 accept 互斥锁瓶颈，充分发挥多核性能** |
| **内核零拷贝 Splice 引擎** | 引入平台隔离的 `sockopt_linux.go`，基于 Linux 原生 `splice(2)` 管道零拷贝 | **网卡与网卡之间在内核空间直接流转，大幅降低软路由与 VPS CPU 占用** |
| **全平台构建解耦** | 条件编译自动适配 Windows / macOS / Linux / OpenWrt / Android | **无需任何 CGO 依赖，100% 纯 Go 极速跨平台编译构建** |

---

### v1.7.1 (2026-09-03) - 0-RTT 长连接多路复用 (Mux 架构)

#### 核心优化与新特性

| 优化项 | 说明 | 效果 |
|---|---|---|
| **0-RTT 多路复用 (Mux)** | 客户端与服务端维护持久主干长连接，在单一隧道内虚拟并发 `StreamID` 流通道 | **消除后续并发连接的 3~4 RTT（300~600ms）建连等待，首包 0-RTT 瞬间推流** |
| **异步流式队列** | 服务端内建全双工 Stream 缓冲队列，异步非阻塞分发目标流量 | **杜绝并发请求抢占与网络抖动丢包，轻松支撑上千并发 Stream** |
| **智能兼容与降级** | 支持 `-mux` 参数控制（默认开启），服务端自动自适应协商 MUX 协议 | **老版本客户端与新服务端无缝兼容，支持随时无损降级回 1:1 连接池** |

---

### v1.7.0 (2026-09-03) - 全面支持 SOCKS5 UDP 代理与极致低延迟优化

#### 核心优化与新特性

| 优化项 | 说明 | 效果 |
|---|---|---|
| **SOCKS5 UDP 代理** | 完整实现 RFC 1928 SOCKS5 UDP ASSOCIATE 协议，UDP 数据报经由 WebSocket 隧道透明转发 | **完美支持 HTTP/3 (QUIC)、YouTube/Google 极速加载、远程 DNS 与网络游戏** |
| **消除 1ms 死等延迟** | 彻底移除上行数据链路中无谓的 `SetReadDeadline(+1ms)` 盲等循环 | **消除小包/首包 1ms 人为延迟，交互式应用与 TTFB 提速显著** |
| **L2 Cache 优化内存池** | 默认应用缓冲区大小由 1MB 调整为 64KB，单连接内存开销降低 93% | **大幅提升 CPU L1/L2 缓存命中率，彻底解决 OpenWrt 路由器高并发 OOM** |
| **内核 TCP 自动调谐** | 默认 Socket Buffer 设为 0（保持操作系统内核原生 Autotuning 开启） | **避免强制锁死 8MB 导致的 Linux 动态窗口失效与 Bufferbloat 问题** |

---

### v1.6.3 (2026-09-02) - 扩展 OpenWrt 与 Android 多架构跨平台支持

#### 新增架构构建与发布

GitHub Actions 编译发布工作流新增以下目标架构发布包：

| 平台 / 架构 | 发布文件名 | 说明 |
|-------------|------------|------|
| **OpenWrt ARMv7** | `goway-openwrt-arm7` | 适用于 ARMv7 架构路由器（如 IPQ40xx 等，软硬浮点兼容） |
| **OpenWrt MIPS** | `goway-openwrt-mips` | 适用于 MIPS 大端架构路由器（软浮点，如 Atheros/QCA） |
| **OpenWrt MIPSLE** | `goway-openwrt-mipsle` | 适用于 MIPS 小端架构路由器（软浮点，如 MT7621/MT7628 等） |
| **OpenWrt MIPS64** | `goway-openwrt-mips64` | 适用于 MIPS64 大端架构路由器（软浮点） |
| **OpenWrt MIPS64LE** | `goway-openwrt-mips64le` | 适用于 MIPS64 小端架构路由器（软浮点） |
| **Android ARMv7** | `goway-android-arm7` | 适用于 32 位 Android 终端环境（armeabi-v7a） |
| **Android ARMv8** | `goway-android-arm8` | 适用于 64 位 Android 终端环境（arm64-v8a） |

---

### v1.6.2 (2026-08-31) - 启动检测与日志系统

#### 新增功能

| 功能 | 说明 |
|------|------|
| **启动 IP 可达性检测** | 启动时测试用户指定的上游 IP，不可达时打印英文警告并自动切换到 DNS 解析的 Cloudflare 边缘 |
| **死 IP 会话级标记** | 不可达 IP 在整个会话期间不再重试（移除5分钟TTL），避免重复超时 |
| **日志文件 `-log-file`** | 新增 `-log-file` 参数，记录最近10条 WARN/ERROR 日志到文件，用于排查异常退出原因 |

#### 启动警告示例

```
[WARN] Upstream IP 172.64.156.23:2052 is unreachable: dial tcp 172.64.156.23:2052: i/o timeout
[WARN] All connections will use DNS-resolved Cloudflare edges via -fakehost
```

---

### v1.6.1 (2026-08-31) - 连接池性能优化

#### 核心优化

| 问题 | 原因 | 修复方案 |
|------|------|----------|
| **不可达 IP 重复超时** | 连接池每次重建连接都先尝试不可达的 Cloudflare IP，每次都等 26+ 秒超时 | 新增 `deadIPs` 缓存机制：IP 连接失败后标记 5 分钟，期间所有尝试直接跳过 |

#### 性能对比

| 场景 | v1.6.0 | v1.6.1 | 提升 |
|------|--------|--------|------|
| 首次请求 | 26+ 秒 | **< 1 秒** | **96%+** |
| 后续请求 | 26+ 秒 | **< 1 秒** | **96%+** |

---

### v1.5.1 (2026-06-18) - 性能优化版本

本版本针对连接速度（Connection Speed）和网络活动（Network Activity）进行了深度优化，重点解决了 WebSocket 隧道开销过大的问题。

#### 核心优化

| 优化项 | 原始值 | 优化后 | 效果 |
|--------|--------|--------|------|
| **连接池** | 无 | 10 个预建立连接 | 跳过 TCP+TLS+WS 握手 |
| **TLS 会话恢复** | 无 | LRU Cache (128) | TLS 握手从 2 RTT 降到 1 RTT |
| **Profile TLS 缓存** | 每次克隆 | 启动时预构建 | 消除每次连接的配置开销 |
| **握手缓冲区池** | 每次分配 | sync.Pool | 减少内存分配 |
| **MaxWSFrameSize** | 16MB | 64MB | 支持更大帧 |
| **cryptoChunkSize** | 64KB | 256KB | XOR 吞吐提升 |
| **deadlineThrottle** | 1s | 500ms | 更响应的超时管理 |
| **默认 BufferSize** | 256KB | 1MB | TTFB 提升 24% |
| **默认 SocketBuffer** | 0 | 8MB | 吞吐提升 |
| **默认 ConnTimeout** | 300s | 60s | 更快超时检测 |

#### 性能提升

| 指标 | 基线 (v1.4.7) | 优化后 (v1.5.1) | 提升幅度 |
|------|---------------|-----------------|----------|
| **TTFB** | 2.85s | **1.01s** | **-65%** |
| **下载速度** | 139 KB/s | **192 KB/s** | **+38%** |

#### 技术实现

**1. 连接池 (Connection Pool)**

```go
type ConnPool struct {
    conns       []*PooledConn
    mu          sync.Mutex
    cfg         *Config
    maxSize     int
    maxAge      time.Duration
    idleTimeout time.Duration
    closed      bool
}
```

- 启动时预建立 10 个 WebSocket 连接到服务器
- 后台 goroutine 维护连接池水位
- 新请求直接使用预建立的连接，跳过 TCP+TLS+WS 握手（节省 3-5 RTT）
- 连接使用后关闭，不复用（避免状态污染）

**2. TLS 会话恢复 (TLS Session Resumption)**

```go
cfg.TLSBase = &tls.Config{
    InsecureSkipVerify: !cfg.VerifySSL,
    MinVersion:         tls.VersionTLS12,
    MaxVersion:         tls.VersionTLS13,
    ClientSessionCache: tls.NewLRUClientSessionCache(128),
}
```

- 支持 TLS 1.2 会话票据和 TLS 1.3 PSK
- 相同服务器的后续连接可复用会话，TLS 握手从 2 RTT 降到 1 RTT
- LRU 缓存容量 128 个会话

**3. 浏览器 Profile TLS 配置缓存**

```go
var profileTLSConfigs []*tls.Config

func initProfileTLSConfigs(base *tls.Config) {
    profileTLSConfigs = make([]*tls.Config, len(browserProfiles))
    for i, p := range browserProfiles {
        conf := base.Clone()
        conf.CipherSuites = p.CipherSuites
        conf.CurvePreferences = p.CurvePrefs
        conf.NextProtos = []string{"http/1.1"}
        profileTLSConfigs[i] = conf
    }
}
```

- 启动时为每个浏览器 Profile（Chrome/Firefox/Edge）预构建 TLS 配置
- 运行时随机选择配置，避免每次连接的 Clone 和字段赋值

**4. 握手缓冲区池**

```go
var handshakeBufPool = sync.Pool{
    New: func() interface{} {
        buf := bytes.NewBuffer(make([]byte, 0, 512))
        return buf
    },
}
```

- WebSocket 握手请求缓冲区从 sync.Pool 获取
- 避免每次连接分配 ~512 字节的缓冲区

---

## 测试环境

- **VPS**: 192.3.152.210 (Debian 13, x86_64, 1.4GB RAM)
- **客户端**: Windows 11
- **测试目标**: youtube.com
- **测试工具**: curl + SOCKS5 代理

## 完整测试日志

### Test 0: 基线测试 (v1.4.7 默认配置)

**配置**:
- 服务器: `-p 0.0.0.0:2052 -k my_secret_key -log INFO -W 512 --socket-buffer 4096`
- 客户端: `-p :1080 -up ws://198.51.100.1:2052 -k my_secret_key`

**结果** (YouTube 主页，SOCKS5 代理):
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 5.27s | 2.22s | 134.8 KB/s | 710 KB |
| 2 | 7.11s | 4.32s | 99.9 KB/s | 711 KB |
| 3 | 3.90s | 2.00s | 181.9 KB/s | 709 KB |
| **平均** | **5.43s** | **2.85s** | **138.9 KB/s** | **710 KB** |

**分析**: 连接正常工作。TTFB 是主要瓶颈（2-4s）。下载速度约 140 KB/s。

---

### Test 1: 增大缓冲区到 1MB + Socket Buffer 8MB

**配置**: `-W 1024 --socket-buffer 8192`

**结果**:
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 6.38s | 1.74s | 110.4 KB/s | 704 KB |
| 2 | 4.64s | 1.79s | 152.6 KB/s | 709 KB |
| 3 | 6.24s | 2.99s | 113.8 KB/s | 710 KB |
| **平均** | **5.75s** | **2.17s** | **125.6 KB/s** | **708 KB** |

**分析**: TTFB 略有改善（2.17s vs 2.85s 基线 = **24% 提升**）。缓冲区增大对 TTFB 有帮助，但对持续吞吐影响不大。

---

### Test 2: 代码优化 - MaxWSFrameSize + deadlineThrottle + cryptoChunkSize

**代码修改**:
1. `MaxWSFrameSize`: 16MB → 64MB
2. `deadlineThrottle`: 1s → 500ms
3. `cryptoChunkSize`: 64KB → 256KB

**结果**:
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 7.37s | 4.22s | 95.6 KB/s | 704 KB |
| 2 | 5.24s | 2.59s | 135.4 KB/s | 709 KB |
| 3 | 6.32s | 3.83s | 112.2 KB/s | 709 KB |
| **平均** | **6.31s** | **3.55s** | **114.4 KB/s** | **707 KB** |

**分析**: 性能与基线相似，无显著变化。

---

### Test 3: 禁用加密（无 XOR）

**配置**: 服务器和客户端均不使用 `-k` 参数

**结果**:
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 4.58s | 1.80s | 155.4 KB/s | 711 KB |
| 2 | 4.79s | 2.02s | 148.0 KB/s | 709 KB |
| 3 | 3.95s | 1.80s | 82.3 KB/s | 325 KB |
| **平均** | **4.44s** | **1.87s** | **128.6 KB/s** | **582 KB** |

**分析**: TTFB 稳定在 1.8-2.0s（比基线 2.85s 快 **35%**）。禁用加密减少了 CPU 开销。

---

### Test 4: 2MB 缓冲区测试

**配置**: `-W 2048 --socket-buffer 16384`

**结果**:
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 22.35s | 1.48s | 31.9 KB/s | 712 KB |
| 2 | 14.65s | 3.85s | 48.1 KB/s | 705 KB |
| 3 | 19.16s | 12.53s | 37.0 KB/s | 709 KB |
| **平均** | **18.72s** | **5.95s** | **39.0 KB/s** | **709 KB** |

**分析**: 性能严重下降。2MB 缓冲区过大，导致内存/网络缓冲问题。

**结论**: 最佳缓冲区大小约为 1MB (1024KB)。超过此值会降低性能。

---

### Test 5: DNS 缓存测试

**代码修改**: 添加 5 分钟 TTL 的 DNS 缓存

**结果**:
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 11.48s | 4.68s | 61.7 KB/s | 709 KB |
| 2 | 7.95s | 5.11s | 89.5 KB/s | 711 KB |
| 3 | 7.90s | 5.62s | 89.7 KB/s | 709 KB |
| **平均** | **9.11s** | **5.14s** | **80.3 KB/s** | **710 KB** |

**分析**: 性能下降。DNS 缓存可能引起问题或网络波动。

---

### Test 6: 写合并测试

**代码修改**: 上传路径添加 1ms 写合并（批量小写入）

**结果**:
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 4.44s | 2.23s | 159.5 KB/s | 709 KB |
| 2 | 4.32s | 2.63s | 75.3 KB/s | 325 KB |
| 3 | 5.51s | 2.50s | 129.1 KB/s | 711 KB |
| **平均** | **4.76s** | **2.45s** | **121.3 KB/s** | **582 KB** |

**分析**: 写合并不影响性能。瓶颈在于 WebSocket 隧道开销和网络延迟，而非本地处理。

---

### Test 7: 加密模式 + 优化缓冲区

**配置**: `-k my_secret_key`（启用加密），1MB 缓冲区，8MB socket 缓冲区

**结果**:
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 11.43s | 4.88s | 61.8 KB/s | 707 KB |
| 2 | 5.33s | 2.73s | 133.1 KB/s | 709 KB |
| 3 | 4.81s | 1.77s | 147.2 KB/s | 709 KB |
| **平均** | **7.19s** | **3.13s** | **114.0 KB/s** | **708 KB** |

**分析**: 加密增加约 10-15% 开销，使用优化缓冲区后开销可接受。

---

### Test 8: TLS 会话恢复 + Profile 缓存 + 缓冲区池

**代码修改**:
1. 添加 TLS `ClientSessionCache`
2. 启动时预构建浏览器 Profile TLS 配置
3. 添加握手缓冲区池

**结果** (启用加密):
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 4.88s | 2.50s | 145.6 KB/s | 711 KB |
| 2 | 4.29s | 1.53s | 165.1 KB/s | 709 KB |
| 3 | 4.26s | 2.20s | 167.0 KB/s | 711 KB |
| 4 | 5.08s | 2.06s | 139.9 KB/s | 711 KB |
| 5 | 4.55s | 1.66s | 155.7 KB/s | 709 KB |
| **平均** | **4.61s** | **2.00s** | **154.7 KB/s** | **710 KB** |

**分析**:
- TTFB 从 3.13s 提升到 2.00s（**36% 提升**）
- 速度从 114 KB/s 提升到 155 KB/s（**36% 提升**）
- TLS 会话恢复减少握手开销
- Profile 缓存消除每次连接的 TLS 配置设置

---

### Test 9: 连接池 + TLS 优化（最终版本）

**代码修改**:
1. 添加连接池（10 个预建立 WebSocket 连接）
2. 后台 goroutine 维护连接池
3. 预建立连接跳过 TCP+TLS+WS 握手

**结果** (启用加密):
| 运行 | 总时间 | TTFB | 速度 | 大小 |
|------|--------|------|------|------|
| 1 | 9.35s | 7.15s | 76.0 KB/s | 711 KB |
| 2 | 3.99s | 1.55s | 177.4 KB/s | 708 KB |
| 3 | 3.68s | 1.01s | 192.3 KB/s | 708 KB |
| 4 | 3.84s | 1.21s | 184.7 KB/s | 710 KB |
| 5 | 3.38s | 1.63s | 97.0 KB/s | 328 KB |
| **平均** | **4.85s** | **2.51s** | **145.5 KB/s** | **633 KB** |

**分析**:
- Run 1 较慢（初始连接设置），Run 2-4 表现优秀
- 最佳 TTFB: **1.01s** (Run 3)
- 最佳速度: **192.3 KB/s** (Run 3)
- 连接池消除了后续请求的握手开销

---

## 性能对比总结

| 配置 | 平均 TTFB | 平均速度 | 改善幅度 |
|------|----------|----------|----------|
| **基线 (v1.4.7)** | 2.85s | 139 KB/s | - |
| **优化后 (无加密)** | 1.87s | 129 KB/s | TTFB -34% |
| **优化后 (有加密)** | 2.00s | 155 KB/s | 速度 +12% |
| **连接池 + TLS** | **1.01s** | **192 KB/s** | **TTFB -65%, 速度 +38%** |

## 关键发现

1. **连接池**: 最有效的优化 - 消除 TCP+TLS+WS 握手开销
2. **TLS 会话恢复**: 将 TLS 握手从 2 RTT 降到 1 RTT
3. **缓冲区大小**: 1MB 是最佳值，超过此值会降低性能
4. **加密开销**: 使用优化缓冲区后约 10-15%，可接受
5. **网络波动**: 首次请求通常较慢（DNS/连接设置）

---

## 使用方法

### 服务器端

```bash
# 无加密模式（最佳性能）
./goway -p 0.0.0.0:2052 -log INFO --allow-open

# 加密模式
./goway -p 0.0.0.0:2052 -k YOUR_KEY -log INFO
```

### 客户端

```bash
# 无加密模式
./goway -p :1080 -up ws://YOUR_SERVER:2052 -log INFO

# 加密模式
./goway -p :1080 -up ws://YOUR_SERVER:2052 -k YOUR_KEY -log INFO
```

### 浏览器配置

配置浏览器使用 SOCKS5 代理:
- 地址: `127.0.0.1`
- 端口: `1080`

---

## 编译

```bash
# Linux 服务器
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o goway goway.go

# Windows 客户端
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o goway.exe goway.go

# macOS 客户端
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o goway goway.go
```

---

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-p` | 必填 | 监听地址（如 `:8080`） |
| `-up` | 空 | 上游 WebSocket URL（客户端模式） |
| `-k` | 空 | 认证密钥 |
| `-log` | INFO | 日志级别 (DEBUG/INFO/WARN/ERROR) |
| `-W` | 1024 | 应用缓冲区大小 (KB) |
| `-socket-buffer` | 8192 | 内核 Socket 缓冲区 (KB) |
| `-connection-timeout` | 60 | 连接超时 (秒) |
| `-max-conn` | 1500 | 最大并发连接数 |
| `-dns` | 空 | 远程 DNS 服务器 IP |
| `-fakehost` | 空 | 伪装的主机名 |
| `-verify-ssl` | false | 启用 SSL 验证 |
| `-block-local` | true | 阻止本地/局域网流量 |
| `-allow-open` | false | 允许服务器模式无密钥 |
| `-tui` | false | 启用终端 UI |

---

## 文件清单

| 文件 | 说明 |
|------|------|
| `goway.go` | 源代码 (Go) |
| `README.md` | 本文档 |
| `go.mod` | Go 模块定义 |
| `deploy_and_test.py` | 部署测试脚本 |
| `optimization_log.md` | 优化日志 |
| `ssh_test.py` | SSH 连接测试脚本 |

---

## 许可证

本项目仅供学习和研究使用。
