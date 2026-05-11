# 🚀 Way Proxy (Pyway & Goway)

![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![Go](https://img.shields.io/badge/go-1.18%2B-cyan.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Way Proxy 是一个**轻量级**、**高性能**的 HTTP/SOCKS5 转 WebSocket 代理工具，专为流媒体传输、高并发下载以及各种复杂网络环境设计。

本项目包含两个语言的实现版本，它们具有相同的功能和参数用法：
- 🐍 **Pyway**: 基于 Python `asyncio` 实现的异步高性能版本 (当前最新: v2.6.4g)。
- 🐹 **Goway**: 基于 Go 语言实现的高并发、低延迟编译型版本 (当前最新: v1.1.1a)。

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
2. **下载脚本**: 进入 `pyway` 目录，找到最新的脚本 (例如 `pyway2.6.4g.py`)
3. **运行**:
   ```bash
   python pyway/pyway2.6.4g.py -p :8080
   ```

*推荐安装 `aiodns` 以获取更快的非阻塞解析性能: `pip install aiodns`*

### 使用 Goway (Go)

Goway 提供更好的多线程性能与极低的运行内存。

1. **环境要求**: 只需要编译好的二进制文件 (或者安装 Go 环境 `go1.18+`)
2. **下载代码**: 进入 `goway` 目录。
3. **编译并运行**:
   ```bash
   cd goway
   go build -o goway goway1.1.1a.go
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
python pyway/pyway2.6.4g.py -p :8080 -k "my_secret_key"

# Go 版本 (推荐用于 Server)
./goway -p :8080 -k "my_secret_key"
```

### 第 2 步：在你的本地电脑上启动 Client 端

Client 端通过 `-up` 参数连接到 Server 端，并在本地暴露 HTTP/SOCKS5 代理。

```bash
# 示例：在本地 1080 端口开启 HTTP/SOCKS5 代理，连接到 服务器 WS，带上密钥
# Python 版本
python pyway/pyway2.6.4g.py -p :1080 -up ws://<你的服务器IP>:8080 -k "my_secret_key"

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
python pyway/pyway2.6.4g.py -p :9193 -up wss://vps-ip:443/ws -W 512 --socket-buffer 2048 -k "secret"

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
🛡️ **安全声明**: 本工具仅供学习研究网络协议以及网络加速优化使用，请遵守当地法律法规。
