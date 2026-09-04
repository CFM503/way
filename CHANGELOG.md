# Changelog

All notable changes to the **Way Proxy** project (Goway & Pyway) are documented in this file.

---

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
