# 🚀 Way Proxy (Pyway & Goway)

![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![Go](https://img.shields.io/badge/go-1.18%2B-cyan.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Way Proxy 是一个**轻量级**、**高性能**的 HTTP/SOCKS5 转 WebSocket 代理工具，专为流媒体传输、高并发下载以及各种复杂网络环境设计。

本项目包含两个语言的实现版本，它们具有相同的功能和参数用法：
- 🐍 **Pyway**: 基于 Python `asyncio` 实现的异步高性能版本 (当前最新: v2.7.7G)。
- 🐹 **Goway**: 基于 Go 语言实现的高并发、低延迟编译型版本 (当前最新: v1.1.14a)。

---

## 📖 目录

- [✨ 特性](#-特性)
- [📦 安装与运行](#-安装与运行)
  - [使用 Pyway (Python)](#使用-pyway-python)
  - [使用 Goway (Go)](#使用-goway-go)
- [🚀 快速开始](#-快速开始)
- [⚙️ 参数说明](#️-参数说明)
- [📚 使用场景](#-使用场景)
- [🐛 故障排除](#-故障排除)

---

## ✨ 特性

### 🎯 核心功能
- ✅ **支持多种代理协议** - 客户端模式提供 SOCKS5 和 HTTP 代理，服务器端提供 WebSocket 代理。
- ✅ **WebSocket 隧道加密** - 利用 TLS (WSS) 或自定义 XOR 加密过墙，规避深度包检测 (DPI)。
- ✅ **伪装 Host (FakeHost)** - 兼容 CDN (Cloudflare 等) 环境，隐藏真实目标。

### ⚡ 性能与优化
- ✅ **零拷贝/低内存消耗** - Go 和 Python 版本均经过内存池、Socket 缓冲、TCP 优化。
- ✅ **智能流控算法** - 自适应流量排空 (Drain threshold) 防止内存泄露，限制超大请求头部 (DoS 防护)。
- ✅ **多路复用支持极高连接数** - 支持调整 `max-conn` 以及并发安全设计。

---

## 📦 安装与运行

本项目无需复杂配置，只需下载对应的源码文件即可运行。

### 使用 Pyway (Python)

1. **环境要求**: Python 3.7+
2. **下载脚本**: 进入 `pyway` 目录，找到最新的脚本 (例如 `pyway2.7.1g.py`)
3. **运行**:
   ```bash
   python pyway/pyway2.7.1g.py -p :8080
   ```

*推荐安装 `aiodns` 以获取更快的非阻塞解析性能: `pip install aiodns`*

### 使用 Goway (Go)

Goway 提供更好的多线程性能与极低的运行内存。

1. **环境要求**: 只需要编译好的二进制文件 (或者安装 Go 环境 `go1.18+`)
2. **下载代码**: 进入 `goway` 目录。
3. **编译并运行**:
   ```bash
   cd goway
   go build -o goway goway1.1.8a.go
   ./goway -p :8080
   ```

---

## 🚀 快速开始

Way Proxy 支持**服务器端**和**客户端**两种模式，通常成对使用。

### 第 1 步：在你的海外服务器上启动 Server 端

Server 端不使用 `-up` 参数，仅监听一个端口提供 WebSocket 代理接入。

```bash
# 示例：监听 8080 端口，并设置加密密钥为 "my_secret_key"
# Python 版本
python pyway/pyway2.7.1g.py -p :8080 -k "my_secret_key"

# Go 版本 (推荐用于 Server)
./goway -p :8080 -k "my_secret_key"
```

### 第 2 步：在你的本地电脑上启动 Client 端

Client 端通过 `-up` 参数连接到 Server 端，并在本地暴露 HTTP/SOCKS5 代理。

```bash
# 示例：在本地 1080 端口开启 HTTP/SOCKS5 代理，连接到 服务器 WS，带上密钥
# Python 版本
python pyway/pyway2.7.1g.py -p :1080 -up ws://<你的服务器IP>:8080 -k "my_secret_key"

# Go 版本
./goway -p :1080 -up ws://<你的服务器IP>:8080 -k "my_secret_key"
```

### 第 3 步：配置浏览器或工具

现在，你可以在浏览器 (SwitchyOmega 等) 或者其他下载工具中，将代理设置为 `127.0.0.1:1080` (支持 SOCKS5 和 HTTP 代理)，即可通过海外服务器访问网络！

---

## ⚙️ 参数说明

由于 Pyway 和 Goway 共享同一套设计架构，它们的命令行参数完全一致：

| 参数 | 必需 | 默认值 | 描述 |
| :--- | :---: | :---: | :--- |
| `-p` | ✅ | - | 监听的地址和端口 (如 `:8080` 或 `127.0.0.1:1080`)。 |
| `-up` | ❌ | - | 上游的 WebSocket URL。如果指定了该参数，程序将作为 **客户端** 运行，否则作为 **服务器端** 运行。 |
| `-k` | ✅* | - | 流量混淆/认证密钥。（*服务端模式必须，除非使用 `--allow-open`） |
| `-fakehost`| ❌ | - | 伪造的 WS握手 `Host` 头以配合 CDN 或 Nginx 反代过白名单。 |
| `--block-local`| ❌ | `false`| 客户端防回环/防死循环特性：主动拦截发往 `localhost` 及局域网的请求。 |
| `-log` | ❌ | `INFO` | 日志打印级别: `DEBUG`, `INFO`, `WARN`, `ERROR`。 |
| `-W` | ❌ | `64` | 应用层缓冲区大小 (单位: KB)，视频流或大文件建议加大到 `256` 甚至 `512`。|
| `--socket-buffer`| ❌ | `0`(系统默认) | 覆盖 OS 的 TCP Socket 缓冲区 (单位: KB)，用于进一步优化吞吐量。 |
| `--max-conn` | ❌ | `1000` | 安全限制: 单实例最大并发连接数（DoS 防护）。 |
| `--connection-timeout`| ❌ | `300` | 连接空闲超时时间，超过该秒数未活动的连接结构会被主动回收。 |
| `--verify-ssl` | ❌ | `false`| 在客户端模式下启动时，是否对 `wss://` 连接进行严格的证书验证。 |
| `--no-tcp-nodelay` | ❌ | `false`| 禁用 TCP_NODELAY 算法 (不推荐)。 |
| `--no-tcp-keepalive` | ❌ | `false`| 禁用 TCP KeepAlive (不推荐)。 |
| `--allow-open` | ❌ | `false`| 允许服务端模式在无密钥的情况下运行（不推荐，存在开放代理风险）。 |

---

## 📚 使用场景

### 1. YouTube 4K/8K 视频下载加速 (以 yt-dlp 为例)
在本地运行客户端时，加大本地的缓冲区可极大提高高速下载大文件（视频）的吞吐量。

```bash
# 启动本地客户端 (使用 512KB Socket 和应用缓冲)
python pyway/pyway2.7.1g.py -p :9193 -up wss://vps-ip:443/ws -W 512 --socket-buffer 2048 -k "secret"

# 使用 yt-dlp 通过该代理下载
yt-dlp --proxy "http://127.0.0.1:9193" -f "bv*+ba/b" "YOUR_VIDEO_URL"
```

### 2. 通过 Cloudflare CDN 隐藏 IP 转接

Cloudflare 支持 WebSocket，您可以利用 CDN 隐藏真实服务器 IP 并使用边缘网络加速。
假设在 Cloudflare 配置了域名 `proxy.mydomain.com` 回源至 你的 VPS 80 端口。

```bash
# 服务器端 (VPS): 普通监听，不带任何域名限制
./goway -p :80 -k "cdn_secret_key"

# 客户端 (本地电脑): 通过 CDN 接入，带上 Fakehost 保证 WS 握手成功
./goway -p :1080 -up ws://proxy.mydomain.com:80 -fakehost proxy.mydomain.com -k "cdn_secret_key"
```

### 3. 使用 Nginx 进行路径伪装和反向代理（终极伪装）

为了实现更深度的隐藏，你可以利用服务器上的 Nginx 分发流量，并且**通过 Nginx 提供 TLS/SSL 加密**。比如，你可以让 Nginx 监听在标准的 HTTPS `443` 端口上运行一个看似普通的正常网站，然后将发往特定隐蔽路径（如 `/pyway`）的流量偷偷转发给本地运行的 Goway。

在这种架构下，外网传输使用的是标准的 `WSS (WebSocket Secure)` 协议进行加密，而 VPS 内部 Nginx 与 Goway 交互使用的是普通 WS 协议。

**Nginx 配置文件示例 (`/etc/nginx/sites-available/default` 或相应配置):**

```nginx
server {
    listen 443 ssl http2;
    server_name proxy.mydomain.com;

    # SSL 证书配置 (可以使用 Certbot/Let's Encrypt 或 Cloudflare 证书生成)
    ssl_certificate /path/to/your/fullchain.pem;
    ssl_certificate_key /path/to/your/privkey.pem;

    # 正常的网站主页流量 (可选)
    location / {
        root /var/www/html;
        index index.html;
    }

    # 拦截 /pyway 路径，将 WebSocket 请求转发给后端的 Goway 服务
    location /pyway {
        proxy_pass http://127.0.0.1:2052; # 转发给本地独立运行的 Goway 端口 (2052)
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade; # 核心：允许协议升级为 WebSocket
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

**对应的端到端启动命令:**

```bash
# 服务器端 (VPS): 只需监听在一个不暴漏公网的内部本地端口 2052 即可
./goway -p 127.0.0.1:2052 -k "my_secret_key"

# 客户端 (本地电脑): 连接时使用安全的 wss:// 协议和 443 端口，URL带上你设置的隐藏路径
./goway -p :1080 -up wss://proxy.mydomain.com:443/pyway -k "my_secret_key"
```

---

## 🐛 故障排除

**1. 客户端显示 `Upstream Fail: Connection refused`**
- 服务器上 Pyway/Goway 是否正常运行？
- 服务器的防火墙/云安全组是否放行了对应的监听端口？

**2. 连接经常自动断开 (`Server closed connection`)**
- 通过 CDN 代理时，部分 CDN（如 Cloudflare）对长期空闲或大流量的 Websocket 有连接时间或并发的拦截，尝试开启 `wss` 或配置更短的 `--connection-timeout`（如 60）。

**3. 显示 "Header too large" / "Malformed target format"**
- 使用了不兼容的代理协议。需要确认你的浏览器/软件配置的是 **SOCKS5** 或 普通 **HTTP代理**，不要混用其他自定义协议。

**4. 想要后台运行而不挂断？**
- Linux: `nohup ./goway -p :8080 > proxy.log 2>&1 &` 
- 或者使用 `systemd`。

---
---

## 📊 性能优化记录

> 以下记录了从 v1.1.3a / v2.6.6g 到 v1.1.14a / v2.7.7G 共 9 轮性能优化的详细变更。
> 每项优化均保持功能语义不变，仅改变内部实现。如需回退某项优化，可对照「优化前」代码恢复。

### 一、XOR 加密/解密优化

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 1.1 | R1 | Go | TransformInPlace key步长批量XOR | 逐字节XOR `data[i] ^= key[i%kl]` 每次迭代含取模 | 按key长度(32)步长批量XOR，内层循环固定32次，尾部逐字节 | 消除热循环取模运算；编译器可展开固定长度内循环 | 代码3行→6行 | XOR吞吐量 ~2-3x |
| 1.2 | R1 | Go | Crypto.Transform 委托 | Transform独立实现逐字节XOR | `copy(out,data); c.TransformInPlace(out)` | 消除重复代码，自动享受InPlace优化 | 多1次函数调用（可能被内联） | 与1.1同 |
| 1.3 | R1 | Py | Crypto.transform int.from_bytes | 逐字节Python循环 `result[i] = b ^ key[i%kl]` | int.from_bytes批量XOR `r = int.from_bytes(chunk,'big') ^ int.from_bytes(ks,'big')` | Python循环O(n)→O(1)单次C级大整数运算 | 大帧创建巨大Python整数，增加GC压力 | 小帧(<64KB) ~100x |
| 1.4 | R2 | Py | Crypto.transform 64KB分块 | 全帧一次性int.from_bytes | 64KB分块处理 `for off in range(0,len(data),CHUNK)` | 峰值内存O(n)→O(64KB)；1MB帧从~30KB PyLong降到~2KB | 小帧多循环检查开销~1% | 大帧内存峰值降低 ~64x |
| 1.5 | R5 | Py | 帧mask/unmask 64KB分块 | 全帧一次性 `(masking_key*repeats)[:len]; int.from_bytes` | 与Crypto.transform相同的64KB分块模式 | >64KB帧的内存峰值降低64倍 | 同1.4 | 数据面最热路径，每帧必经 |

### 二、WebSocket 帧处理优化

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 2.1 | R1 | Go | getWSHeader 栈分配 | `buf := make([]byte, 14)` 堆分配 | `var buf [14]byte` 栈分配，返回`buf[:n]` | 消除14字节堆分配+GC扫描，零开销 | 无（切片被append立即拷贝） | 每帧减少1次堆分配 |
| 2.2 | R1/2 | Go | readWSFrame 栈分配+批量unmask | `make([]byte, 2/8/4)` 堆分配 + 逐字节unmask `mk[i&3]` | `var b [2/8]byte; var maskKey [4]byte` 栈分配 + 4字节批量展开unmask | 每帧减少3次堆分配；批量unmask消除位运算 | 代码1行→6行 | 每帧减少~3μs；unmask ~1.5x |
| 2.3 | R1 | Go | writeWSFrame 单次分配 | header/data分别写入，多次系统调用 | masked: 单次make+单次Write；unmasked: net.Buffers零拷贝 | 1次分配替代3次；内核可gather写入 | masked仍需拷贝data（需XOR原地修改） | 发送吞吐量 ~1.3x |
| 2.4 | R5 | Go | createWSFrame XOR 4字节展开 | `for i := range payload { payload[i] ^= mk[i&3] }` | 4字节批量展开 `payload[i] ^= mk[0]; ... mk[3]` + 尾部处理 | 消除i&3位运算；与readWSFrame风格一致 | 代码1行→6行 | mask操作 ~1.5x |
| 2.5 | R1 | Go | createWSFrame maskKey 复用 | 额外`make([]byte, 4)`分配maskKey | 复用frame内存 `mk := frame[len(hdr):len(hdr)+4]` | 零额外maskKey分配 | 无 | 每帧减少1次4字节分配 |
| 2.6 | R6 | Py | read_ws_frame 去除unmask后bytes()拷贝 | unmask后将`bytearray`转为`bytes(payload)`二次分配 | 直接返回`bytearray`，调用方`.startswith()`/`.decode()`/`write()`均兼容 | 每帧省1次全帧拷贝 | 无 | 每帧 ~1 alloc |

### 三、Header 解析优化

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 3.1 | R1 | Go | indexFold/asciiToLower 辅助函数 | `strings.ToLower(string(headerBytes))` 全文小写分配 | asciiToLower逐字节转换(A-Z→a-z) + indexFold在原始字节直接搜索，零分配 | 消除整个header的string分配(200-500B)；cache友好 | 代码量增加~30行；仅ASCII | header搜索 ~5x |
| 3.2 | R3/4 | Go | handleServer wsKey直接搜索 | `bytes.Split(headerBytes, CRLF)` 遍历所有行 + 逐行匹配 | `indexFold(headerBytes, "sec-websocket-key:")` 直接定位 + `bytes.Index`截取值 | 消除Split分配(N个[]byte子切片)；O(n)单次扫描替代两次 | 多个同名header取第一个（规范不会出现） | header解析 ~2x |
| 3.3 | R3 | Go | Host header字节级搜索 | `bytes.Split` + `strings.ToLower` + `strings.HasPrefix` | 逐行`bytes.Index`分割 + `indexFold(line[:5], "host:")` | 消除Split+ToLower分配；仅比较前5字节 | 代码略复杂 | Host提取 ~2x |
| 3.4 | R4/5 | Py | header解析 data.find | `data.lower().split(CRLF)` 全文小写+split为list + generator遍历 | `data.lower().find(b'sec-websocket-key:')` 直接定位 + `data.find(CRLF,idx)` 截取 | 消除list分配(N个bytes对象)；O(n)单次扫描 | data.lower()仍全文小写 | header解析 ~2-3x |
| 3.5 | R3 | Py | Host header字节级前缀比较 | `line.lower().startswith(b'host:')` 全行小写 | `len(line)>5 and line[:5].lower() == b'host:'` 仅前5字节 | 仅对5字节小写转换（vs整行20-80字节） | 无 | Host提取 ~1.5x |
| 3.6 | R3 | Go | HTTP首行 bytes.Index | `strings.Split(string(fullData), "\r\n")[0]` 分割全部行 | `bytes.Index(fullData, []byte("\r\n"))` 直接定位首个CRLF | 消除Split分配；仅扫描到第一个CRLF | 无 | 首行解析 ~2x |
| 3.7 | R6 | Go | handleServer auth目标字节级解析 | `string(authData)` + `strings.TrimSpace` + `strings.Fields` 三次分配 | `bytes.TrimSpace` + `bytes.IndexByte` 字节级操作，仅最后做`string()` | 消除3次分配；避免authData全文拷贝 | 代码略长 | 每连接 ~3 allocs |

### 四、TLS/SSL 优化

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 4.1 | R3 | Go | TLS Config Base+Clone | 每次连接`&tls.Config{...}`新建 | 启动时`cfg.TLSBase`，每次`cfg.TLSBase.Clone()` + ServerName | Clone复用内部session cache、证书池 | 需额外字段；Clone仍需分配 | TLS握手准备 ~1.5x |
| 4.2 | R2 | Py | SSL Context 预创建 | 每次连接`ssl.create_default_context()`(~5-20ms) | 启动时创建verified/unverified两个Context存入Config | 消除每连接5-20ms SSL上下文创建开销 | 系统证书链更新需重启 | 每次WSS连接减少5-20ms |

### 五、内存管理优化

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 5.1 | R1 | Go | sync.Pool 缓冲区池 | 无（或已有，未改动） | 64KB缓冲区通过sync.Pool复用 | 高并发避免频繁堆分配 | Pool中对象暂不GC | GC压力降低 |
| 5.2 | R4 | Go | padding append循环 | `[]byte(strings.Repeat(" ", padLen))` 临时string+转换 | `for i<padLen { append(targetPayload, ' ') }` | 消除1次string+1次[]byte分配 | 微小循环开销 | 微小(~1μs) |
| 5.3 | R2 | Py | random.randbytes 替代 os.urandom | `os.urandom(16)` 系统调用 | `random.randbytes(16)` 用户空间PRNG | 避免系统调用~5-10μs | 密码学安全性降低（仅WS Key，可接受） | ~5-10μs/连接 |
| 5.4 | R6 | Go | Crypto.New bytes.Repeat | `copy`循环2048次迭代扩展65536字节key | `bytes.Repeat(hash, kl_repeats)[:65536]` 单次调用 | 内部指数拷贝~11次替代2048次copy | 无 | 启动 ~1ms |
| 5.5 | R6 | Go | handleClient CONNECT延迟fullData分配 | CONNECT请求预先分配`fullData`(~1-8KB)然后丢弃 | 从`restBuf`直接解析首行，仅非CONNECT时分配 | CONNECT占HTTPS流量主要比例，每次省~1-8KB | 非CONNECT路径多1次小string拼接 | 每次CONNECT省1 alloc |
| 5.6 | R6 | Py | Crypto.transform 去除bytes()拷贝 | `return bytes(out)` 将bytearray复制为新bytes | `return out` 直接返回bytearray | 每加密帧省1次全帧拷贝 | 调用方类型签名期望bytes（bytearray兼容） | 每加密帧省1 alloc |

### 六、并发/锁优化

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 6.1 | R1 | Py | Statistics 去锁 | `threading.Lock()` + `with self.lock:` | 直接`self.bytes_up += up`，无锁 | 消除每帧2次锁获取/释放~200ns | GIL下整数+=非严格原子，统计可接受偏差 | 每帧减少~200ns |
| 6.2 | R2 | Py | Semaphore acquire修复 | `conn_semaphore.acquire()` 同步阻塞事件循环 | `await conn_semaphore.acquire()` 异步等待 | 不阻塞事件循环，其他连接正常处理 | 无（原写法是bug） | 高并发下的连接准入 |

### 七、日志/I-O 优化

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 7.1 | R1 | Py | logger lazy formatting (17处) | `logger.debug(f"msg: {var}")` f-string立即求值 | `logger.debug("msg: %s", var)` %s延迟求值 | 日志级别不够时跳过格式化；17处每处省~1μs | 可读性略降 | 关闭debug时 ~17μs/连接 |
| 7.2 | R5 | Go | 101检查 bytes.Contains | `strings.Contains(string(respBytes), "101")` []byte→string拷贝 | `bytes.Contains(respBytes, []byte("101"))` 原字节搜索 | 消除respBytes拷贝(100-200B) | 无 | 微小(~1μs) |
| 7.3 | R5 | Go | isLocalTarget EqualFold | `strings.ToLower(host)` 每次分配新字符串 + Split | `strings.EqualFold(host, "localhost")` + `IndexByte` 替代Split | 非本地目标避免ToLower分配；172.x用IndexByte替代Split | 代码略长 | ~50ns/连接 |
| 7.4 | R1 | Py | Statistics lock已去（同6.1） | - | - | - | - | - |
| 7.5 | R6 | Go | readUntilCRLFCRLF ReadSlice | `br.ReadBytes('\n')` 每行堆分配新[]byte | `br.ReadSlice('\n')` 返回内部缓冲区引用，零分配 | HTTP握手6-12行，每连接省~10次堆分配 | 需配合7.6确保缓冲区足够 | ~10 allocs/连接 |
| 7.6 | R6 | Go | bufio.NewReader→NewReaderSize | `bufio.NewReader(conn)` 默认4KB缓冲区 | `bufio.NewReaderSize(conn, MaxHeaderSize)` 8KB缓冲区 | 确保ReadSlice不会因行>4KB溢出 | 每连接多4KB常驻缓冲区 | 配合7.5 |

### 八、热路径优化 (R7)

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 8.1 | R7 | Go | createWSFrame→writeWSFrame (3处) | `wsConn.Write(createWSFrame(...))` 堆分配帧后写入 | `writeWSFrame(wsConn, ...)` 零拷贝/net.Buffers | unmasked帧零拷贝；masked帧单次分配 | 无 | unmasked零拷贝；masked省1 alloc |
| 8.2 | R7 | Py | create_ws_frame 返回bytearray | `return bytes(frame)` bytearray→bytes二次拷贝 | `return frame` 直接返回bytearray | 每帧省1次整帧拷贝(1-64KB) | 无（bytearray兼容所有bytes-like接口） | 每帧省1 alloc |
| 8.3 | R7 | Go | indexFold 预计算小写模式串 | `asciiToLower(substr[j])` 内层循环重复调用 | 预计算`[]byte(substr)`小写化，内层用切片索引 | 内层循环从函数调用→切片索引；消除重复ASCII转换 | 每次调用多1次≤19字节栈分配 | 握手header搜索 ~1.5x |
| 8.4 | R7 | Py | Crypto.transform小帧快速路径 | ≤4KB帧仍走int.from_bytes大整数路径 | ≤4KB帧走直接bytearray XOR循环 | 避免Python大整数(~2KB+)分配开销 | >4KB帧走原路径 | 小帧XOR ~2-3x |

### 九、内存分配优化 (R7)

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 9.1 | R7 | Go | isLocalTarget首字节快速拒绝 | `strings.ToLower(host)` 无条件分配新字符串 | `host[0] != '1'` 直接返回false | 99%连接(公网)跳过ToLower分配 | 无（私有IPv4首字节必为'1'） | ~50ns/连接 |
| 9.2 | R7 | Go | wsKey提取 bytes.TrimSpace | `strings.TrimSpace(string(headerBytes))` 双重分配 | `bytes.TrimSpace(headerBytes)` 直接操作字节 | 省去[]byte→string→string链 | 无 | 省2 allocs/连接 |
| 9.3 | R7 | Py | connect_to_upstream 移除bytes() | `payload = bytes(payload)` 多余bytearray→bytes拷贝 | 直接使用bytearray payload | 省1次payload拷贝(~20-60B) | 无 | 省1 alloc/连接 |
| 9.4 | R7 | Go | SOCKS5栈数组替代堆分配 | `make([]byte, N)` 7处堆分配 | `var buf [N]byte` 栈分配 | 每SOCKS5连接省7次堆分配+GC扫描 | 无 | 每SOCKS5连接省7 allocs |
| 9.5 | R7 | Go | 删除死代码Crypto.Transform | 未被调用的拷贝+委托方法(8行) | 移除 | 减少代码体积，消除混淆 | 无 | 无运行时影响 |

### 十、缓冲与调度优化 (R7)

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 10.1 | R7 | Py | reader._limit提升 | 握手后8KB buffer限制持续到数据传输 | 握手后提升至stream_limit(~256KB+) | 减少传输阶段read系统调用次数 | 每连接多~248KB缓冲区 | 大帧吞吐提升 |
| 10.2 | R7 | Py | Ping响应去drain | `await writer.drain()` 暂停读循环等待刷出 | 移除drain，pong随下一数据帧自然刷出 | 高吞吐时不阻塞数据读取循环 | pong延迟略增(毫秒级) | 减少读循环暂停 |

### 十一、字符串与I/O优化 (R8)

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 11.1 | R8 | Go | handleServer握手 bytes.Buffer | `wsConn.Write([]byte(fmt.Sprintf("HTTP/1.1 101...%s...", acc)))` 双重分配 | `bytes.Buffer` 直接写入响应，单次Write | 消除fmt.Sprintf+[]byte()双重分配(~150B) | 4行→7行 | 省2 allocs/连接 |
| 11.2 | R8 | Go | handleClient 7处fmt.Sprintf→字符串拼接 | `fmt.Sprintf("Host: %s", hostHeader)` 反射格式化 | `"Host: " + hostHeader` 编译期拼接 | 消除7次fmt.Sprintf分配(每次~50B) | 略长 | 省7 allocs/连接 |
| 11.3 | R8 | Go | targetPayload fmt.Sprintf→拼接 | `fmt.Sprintf("%s:%s\n", host, port)` 格式化 | `host + ":" + port + "\n"` 直接拼接 | 消除fmt.Sprintf分配 | 无 | 省1 alloc/连接 |
| 11.4 | R8 | Py | connect_to_upstream bytes握手 | f-string列表 → str.join → encode 多重分配 | bytes列表 → b"".join 直接构建bytes | 消除14个f-string分配 + join临时str + encode | 无 | 省~16 allocs/连接 |

### 十二、缓冲与解析优化 (R8)

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 12.1 | R8 | Go | readUntilCRLFCRLF Grow预分配 | `buf.Grow(1024)` 1KB初始→多次扩容 | `buf.Grow(MaxHeaderSize)` 8KB一次性分配 | 避免header读取时bytes.Buffer内部多次扩容 | 每连接多7KB初始缓冲 | 省1-2次扩容/连接 |
| 12.2 | R8 | Go | handleClient初始字节栈分配 | `buf := make([]byte, 1)` 堆分配 | `var buf [1]byte` 栈分配 | 省1次堆分配 | 无 | 省1 alloc/连接 |
| 12.3 | R8 | Go | HTTP请求行字节级解析 | `string(buf[0])+string(restBuf)` 两次转换+拼接 + `strings.Fields` 切片分配 | `bytes.IndexByte` 字节级定位，直接提取method/urlPart | 消除1次拼接string + 1次Fields []string分配 | 代码略长 | 省~5 allocs/连接 |
| 12.4 | R8 | Py | get_ws_header预分配+去struct.pack | `bytearray()` 空然后append/extend + `struct.pack('!H')` 临时bytes | 预分配bytearray(N) + 手动位操作 | 避免扩容 + 消除struct.pack临时对象 | 大长度手动位操作7行 | 省1-2 allocs/帧 |
| 12.5 | R8 | Py | read_ws_frame非masked避免bytearray拷贝 | `bytearray(await readexactly(n))` 无差别bytes→bytearray拷贝 | masked时才创建bytearray；非masked直接返回bytes | 非masked帧省1次全帧拷贝(~1-64KB) | 返回类型从bytearray变为bytes（调用方兼容） | 非masked省1 alloc/帧 |

### 十三、代码清理与热路径栈分配 (R9)

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 13.1 | R9 | Go | 删除未使用 createWSFrame | 死代码(~22行)定义但从未调用 | 直接移除函数 | 减少二进制体积，消除混淆 | 无 | 二进制减~600B |
| 13.2 | R9 | Go | handleClient wsKey 栈分配 | `wsKey := make([]byte, 16)` 堆分配 | `var wsKey [16]byte` 栈分配 | 省1次堆分配(16B) | 无 | 省1 alloc/连接 |
| 13.3 | R9 | Go | SOCKS5 discard 条件栈分配 | `discard := make([]byte, nmethods)` 无条件堆分配 | nmethods≤8时使用8字节栈数组，超出才堆分配 | 绝大多数SOCKS5握手省1次堆分配 | 多3行代码 | 省1 alloc/SOCKS5连接 |
| 13.4 | R9 | Go | handleServer okBytes 包级复用 | `ok := []byte("OK\n")` 每连接分配 | 无加密时复用包级 `okBytes`；加密时copy后变换 | 省1次堆分配(3B) | 加密路径多1次copy(3B) | 无加密省1 alloc/连接 |
| 13.5 | R9 | Go | crlfB 包级预分配替换字面量 | `bytes.Index(buf, []byte("\r\n"))` 每次构造新slice | 包级 `crlfB = []byte{'\r', '\n'}`，3处引用直接使用 | 省去每次`[]byte("\r\n")`字面量→slice分配 | 无 | 省~3 allocs/HTTP连接 |

### 十四、分支消除与字节级解析 (R9)

| # | 轮次 | 文件 | 优化项 | 优化前 | 优化后 | 好处 | 坏处 | 预期提升 |
|---|------|------|--------|--------|--------|------|------|----------|
| 14.1 | R9 | Py | ws_forward transfer 闭包拆分为两个模块级函数 | 单transfer函数内含`is_ws_out`分支，每迭代判断；闭包捕获变量 | `_transfer_ws_to_tcp` + `_transfer_tcp_to_ws` 两个独立函数 | 消除热路径每迭代分支预测开销；内联友好 | 代码行数略增(~30行) | 每迭代省1分支 |
| 14.2 | R9 | Py | connect_to_upstream payload 去f-string | `bytearray(f"{target}\n".encode())` f-string分配 + encode分配 | `bytearray(target.encode())` + extend b"\n" + extend空格 | 节省f-string临时字符串 + encode中间bytes | 拆成3行 | 省~2 allocs/连接 |
| 14.3 | R9 | Py | _handle_server_impl auth 字节级目标解析 | `auth_data.decode(errors='ignore').strip()` 全文decode+创建string | 字节遍历找到首个空白字符位置，仅decode目标部分 | 避免整段auth_data(含~40B填充)的decode分配 | 多5行代码 | 省1次大decode/连接 |

### 汇总统计

| 类别 | 优化项数 | 影响路径 | 最大单项提升 |
|------|---------|---------|-------------|
| XOR加密/解密 | 5 | 每帧热路径 | Py int.from_bytes ~100x (R1) |
| WebSocket帧处理 | 6 | 每帧热路径 | Go 栈分配减少GC ~3μs/帧 |
| Header解析 | 7 | 每连接握手 | Go indexFold ~5x (R1) |
| TLS/SSL | 2 | 每WSS连接 | Py 预创建SSL Context ~5-20ms |
| 内存管理 | 6 | 每连接/每帧 | Py 64KB分块内存峰值降低64x |
| 并发/锁 | 2 | 每帧热路径 | Py 去锁 ~200ns/帧 |
| 日志/I-O | 5 | 每次调用 | Py lazy logging ~17μs/连接 |
| 热路径优化 (R7) | 4 | 每帧/每握手 | Py create_ws_frame去拷贝 ~1 alloc/帧 |
| 内存分配优化 (R7) | 5 | 每连接 | Go isLocalTarget快速拒绝 ~50ns/连接 |
| 缓冲与调度优化 (R7) | 2 | 每连接/数据传输 | Py reader._limit提升 吞吐量 ↑ |
| 字符串与I/O优化 (R8) | 4 | 每连接/每握手 | Go 7处fmt.Sprintf消除 ~7 allocs/连接 |
| 缓冲与解析优化 (R8) | 5 | 每连接/每帧 | Py get_ws_header预分配 ~2 allocs/帧 |
| 代码清理与栈分配 (R9) | 5 | 每连接 | Go wsKey/okBytes/crlfB栈分配+包级复用 ~5 allocs/连接 |
| 分支消除与字节解析 (R9) | 3 | 每帧/每连接 | Py transfer拆分消除is_ws_out分支; auth字节解析 |

---

🛡️ **安全声明**: 本工具仅供学习研究网络协议以及网络加速优化使用，请遵守当地法律法规。
