# -*- coding: utf-8 -*-
import argparse
import asyncio
import base64
import hashlib
import logging
import os
import struct
import sys
import urllib.parse
import socket
import ssl
import random
import time
import threading
import shutil
from typing import Optional, Tuple
from dataclasses import dataclass, field

VERSION = "1.5.1"
CRLF = b"\r\n"
CRLFCRLF = b"\r\n\r\n"
MAX_WS_FRAME_SIZE = 64 * 1024 * 1024  # [v1.5.1] 64MB (increased from 10MB)
MAX_HEADER_SIZE = 8192
CHUNK_SIZE = 262144  # [v1.5.1] 256KB crypto chunk (increased from 64KB)

# ANSI color codes
ANSI_RESET = "\033[0m"
ANSI_CYAN = "\033[36m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_MAGENTA = "\033[35m"
ANSI_RED = "\033[31m"
ANSI_GREY = "\033[90m"

# Pre-allocated static responses (avoid per-connection alloc)
SOCKS5_OK_RESP = bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
HTTP_200_RESP = b"HTTP/1.1 200 Connection Established\r\n\r\n"
HTTP_400_RESP = b"HTTP/1.1 400 Bad Request\r\n\r\n"
WS_UPGRADE_PREFIX = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
WS_UPGRADE_SUFFIX = b"\r\n\r\n"


class Statistics:
    def __init__(self):
        self.active_conns = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.speed_up = 0.0
        self.speed_down = 0.0

    def add_conn(self):
        self.active_conns += 1

    def remove_conn(self):
        self.active_conns -= 1

    def add_bytes(self, up=0, down=0):
        if up: self.bytes_up += up
        if down: self.bytes_down += down


stats = Statistics()


# --- Browser Profile System ---
# Each profile bundles UA, TLS config, and HTTP headers that must match.
# Cloudflare cross-checks these signals.

@dataclass
class BrowserProfile:
    ua: str
    accept_lang: str
    sec_ch_ua: str = ""         # Chrome Client Hints; empty for Firefox/Safari
    sec_ch_ua_mob: str = ""     # "?0" desktop, "?1" mobile
    sec_ch_ua_plat: str = ""    # e.g. `"Windows"`, `"macOS"`, `"Android"`
    is_chromium: bool = False
    is_mobile: bool = False
    # TLS cipher suites (best-effort in Python)
    tls_ciphers: str = ""


# Chrome 136 cipher order
_TLS_CIPHERS_CHROME = (
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
    "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
)

# Firefox 138 cipher order
_TLS_CIPHERS_FIREFOX = (
    "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
    "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
)

BROWSER_PROFILES = [
    # Chrome 136 Windows
    BrowserProfile(
        ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        accept_lang="en-US,en;q=0.9",
        sec_ch_ua='"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        sec_ch_ua_mob="?0",
        sec_ch_ua_plat='"Windows"',
        is_chromium=True,
        tls_ciphers=_TLS_CIPHERS_CHROME,
    ),
    # Chrome 136 macOS
    BrowserProfile(
        ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        accept_lang="en-US,en;q=0.9",
        sec_ch_ua='"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        sec_ch_ua_mob="?0",
        sec_ch_ua_plat='"macOS"',
        is_chromium=True,
        tls_ciphers=_TLS_CIPHERS_CHROME,
    ),
    # Chrome 136 Windows (zh-CN)
    BrowserProfile(
        ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        accept_lang="zh-CN,zh;q=0.9,en;q=0.8",
        sec_ch_ua='"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        sec_ch_ua_mob="?0",
        sec_ch_ua_plat='"Windows"',
        is_chromium=True,
        tls_ciphers=_TLS_CIPHERS_CHROME,
    ),
    # Edge 136 Windows
    BrowserProfile(
        ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
        accept_lang="en-US,en;q=0.9",
        sec_ch_ua='"Chromium";v="136", "Microsoft Edge";v="136", "Not.A/Brand";v="99"',
        sec_ch_ua_mob="?0",
        sec_ch_ua_plat='"Windows"',
        is_chromium=True,
        tls_ciphers=_TLS_CIPHERS_CHROME,
    ),
    # Firefox 138 Windows
    BrowserProfile(
        ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
        accept_lang="en-US,en;q=0.5",
        is_chromium=False,
        tls_ciphers=_TLS_CIPHERS_FIREFOX,
    ),
    # Firefox 138 macOS
    BrowserProfile(
        ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:138.0) Gecko/20100101 Firefox/138.0",
        accept_lang="en-US,en;q=0.5",
        is_chromium=False,
        tls_ciphers=_TLS_CIPHERS_FIREFOX,
    ),
    # Chrome 136 Android (mobile)
    BrowserProfile(
        ua="Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36",
        accept_lang="en-US,en;q=0.9",
        sec_ch_ua='"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        sec_ch_ua_mob="?1",
        sec_ch_ua_plat='"Android"',
        is_chromium=True,
        is_mobile=True,
        tls_ciphers=_TLS_CIPHERS_CHROME,
    ),
]


def pick_browser_profile() -> BrowserProfile:
    return random.choice(BROWSER_PROFILES)


# [v1.5.1] Pre-built SSL contexts for each browser profile
_profile_ssl_contexts: list = []


def _init_profile_ssl_contexts(base_verify: bool):
    """Pre-create SSL contexts with cipher suites matching each profile."""
    global _profile_ssl_contexts
    _profile_ssl_contexts = []
    for p in BROWSER_PROFILES:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if not base_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_alpn_protocols(["http/1.1"])
        try:
            ctx.set_ciphers(p.tls_ciphers)
        except ssl.SSLError:
            pass  # fallback to defaults if cipher string not supported
        _profile_ssl_contexts.append(ctx)


def _pick_profile_ssl_context() -> ssl.SSLContext:
    if _profile_ssl_contexts:
        return random.choice(_profile_ssl_contexts)
    # Fallback
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@dataclass
class Config:
    proxy_host: str
    proxy_port: int
    user_agent: str
    dns_info: str
    upstream: Optional[str] = None
    fakehost: Optional[str] = None
    crypto: Optional['Crypto'] = None
    buffer_size: int = 1048576  # [v1.5.1] 1MB default (was 256KB)
    stream_limit: int = 1048576
    drain_threshold: int = 1048576
    tcp_nodelay: bool = True
    tcp_keepalive: bool = True
    socket_buffer: int = 8192  # [v1.5.1] 8MB default (was 0)
    connection_timeout: int = 60  # [v1.5.1] 60s default (was 300s)
    ssl_verify: bool = False
    max_connections: int = 1000
    block_local: bool = False
    allow_open: bool = False
    tui: bool = False
    ssl_context_verified: Optional[ssl.SSLContext] = None
    ssl_context_unverified: Optional[ssl.SSLContext] = None
    resolver: Optional['RemoteResolver'] = None
    # Pre-parsed upstream (avoid per-connection parse)
    upstream_host: str = ""
    upstream_port: str = ""
    upstream_is_wss: bool = False
    # Buffer pool
    buf_pool: list = field(default_factory=list)
    # Browser profile (sticky per connection)
    profile: Optional[BrowserProfile] = None


# --- DNS Resolver with Cache ---

class RemoteResolver:
    """DNS resolver using a remote server via UDP with TCP fallback and caching."""

    def __init__(self, server_ip: str):
        self.server_ip = server_ip
        self.timeout = 5.0
        # [v1.5.1] DNS cache with TTL
        self._cache: dict = {}  # hostname -> (ip, expiry_time)
        self._cache_ttl = 300.0  # 5 minutes
        self._cache_lock = threading.Lock()

    def _build_query(self, hostname: str) -> bytes:
        header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
        question = b''
        for part in hostname.split('.'):
            question += bytes([len(part)]) + part.encode()
        question += b'\x00' + struct.pack('!HH', 1, 1)
        return header + question

    def _parse_response(self, data: bytes) -> Optional[str]:
        if len(data) < 12:
            return None
        qdcount = struct.unpack('!H', data[4:6])[0]
        ancount = struct.unpack('!H', data[6:8])[0]
        offset = 12
        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 5
        for _ in range(ancount):
            if offset >= len(data):
                return None
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1
            if offset + 10 > len(data):
                return None
            rtype, rclass, rdlength = struct.unpack('!HHH', data[offset:offset+6])
            offset += 8
            if rtype == 1 and rclass == 1 and rdlength == 4:
                return '.'.join(str(b) for b in data[offset:offset+4])
            offset += rdlength
        return None

    async def resolve(self, host: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass

        # [v1.5.1] Check cache first
        now = time.monotonic()
        with self._cache_lock:
            if host in self._cache:
                ip, expires = self._cache[host]
                if now < expires:
                    logger.debug("[DNS] %s -> %s (cache hit)", host, ip)
                    return ip

        loop = asyncio.get_event_loop()
        query = self._build_query(host)

        # Try UDP
        try:
            ip = await loop.run_in_executor(None, self._query_udp, query)
            if ip:
                logger.info("[DNS] %s -> %s (remote: %s)", host, ip, self.server_ip)
                with self._cache_lock:
                    self._cache[host] = (ip, time.monotonic() + self._cache_ttl)
                return ip
        except Exception as e:
            logger.warning("[DNS] Remote UDP lookup failed for %s: %s, trying TCP", host, e)

        # Try TCP
        try:
            ip = await loop.run_in_executor(None, self._query_tcp, query)
            if ip:
                logger.info("[DNS] %s -> %s (remote TCP: %s)", host, ip, self.server_ip)
                with self._cache_lock:
                    self._cache[host] = (ip, time.monotonic() + self._cache_ttl)
                return ip
        except Exception as e:
            logger.warning("[DNS] Remote TCP lookup failed for %s: %s", host, e)

        # Fallback to system DNS
        logger.warning("[DNS] Remote lookup failed for %s, falling back to system DNS", host)
        try:
            addrs = await loop.run_in_executor(None, socket.gethostbyname, host)
            logger.info("[DNS] %s -> %s (system fallback)", host, addrs)
            with self._cache_lock:
                self._cache[host] = (addrs, time.monotonic() + self._cache_ttl)
            return addrs
        except socket.gaierror as e:
            raise OSError(f"DNS resolution failed for {host}: remote=timeout, system={e}")

    def _query_udp(self, query: bytes) -> Optional[str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(query, (self.server_ip, 53))
            data, _ = sock.recvfrom(4096)
            return self._parse_response(data)
        except socket.timeout:
            return None
        finally:
            sock.close()

    def _query_tcp(self, query: bytes) -> Optional[str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.server_ip, 53))
            sock.send(struct.pack('!H', len(query)) + query)
            length_data = sock.recv(2)
            if len(length_data) < 2:
                return None
            resp_len = struct.unpack('!H', length_data)[0]
            data = b''
            while len(data) < resp_len:
                chunk = sock.recv(resp_len - len(data))
                if not chunk:
                    break
                data += chunk
            return self._parse_response(data)
        except socket.timeout:
            return None
        finally:
            sock.close()


class ColoredFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno >= logging.ERROR:
            level_color = ANSI_RED
        elif record.levelno >= logging.WARNING:
            level_color = ANSI_YELLOW
        elif record.levelno >= logging.INFO:
            level_color = ANSI_GREEN
        else:
            level_color = ANSI_CYAN
        timestamp = self.formatTime(record, self.datefmt)
        return (
            f"{ANSI_GREY}{timestamp} {level_color}[{record.levelname}] "
            f"{record.getMessage()}{ANSI_RESET}"
        )


def setup_logger(name: str, level: int) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.propagate = False
    handler = logging.StreamHandler()
    formatter = ColoredFormatter(
        '%(asctime)s [%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger


logger = setup_logger('pyway', logging.INFO)


# --- TUI / GUI-Style CLI Implementation ---
_tui_log_lock = threading.Lock()
_tui_ring_buf = [''] * 100  # [v1.5.1] Ring buffer
_tui_ring_len = 0
_tui_ring_pos = 0
_tui_loop = None
tui_refresh_event = None


def _add_tui_log(line: str):
    """Add a log line to the ring buffer."""
    global _tui_ring_pos, _tui_ring_len
    line = line.strip()
    with _tui_log_lock:
        _tui_ring_buf[_tui_ring_pos] = line
        _tui_ring_pos = (_tui_ring_pos + 1) % len(_tui_ring_buf)
        if _tui_ring_len < len(_tui_ring_buf):
            _tui_ring_len += 1


def _tui_log_slice(n: int) -> list:
    """Get last n entries from ring buffer in order. Must hold _tui_log_lock."""
    if n > _tui_ring_len:
        n = _tui_ring_len
    out = []
    start = (_tui_ring_pos - n + len(_tui_ring_buf)) % len(_tui_ring_buf)
    for i in range(n):
        out.append(_tui_ring_buf[(start + i) % len(_tui_ring_buf)])
    return out


def trigger_tui_refresh():
    if _tui_loop and not _tui_loop.is_closed() and tui_refresh_event:
        try:
            _tui_loop.call_soon_threadsafe(tui_refresh_event.set)
        except Exception:
            pass


class TuiLogHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            _add_tui_log(msg)
            trigger_tui_refresh()
        except Exception:
            self.handleError(record)


def visible_length(s: str) -> int:
    in_escape = False
    length = 0
    i = 0
    n = len(s)
    while i < n:
        if s[i] == '\033':
            in_escape = True
            i += 1
            continue
        if in_escape:
            if s[i] == 'm':
                in_escape = False
            i += 1
            continue
        length += 1
        i += 1
    return length


def pad_visible(s: str, width: int) -> str:
    vl = visible_length(s)
    if vl >= width:
        return s
    return s + " " * (width - vl)


def truncate_visible(s: str, max_len: int) -> str:
    vl = visible_length(s)
    if vl <= max_len:
        return s
    result = []
    in_escape = False
    visible_count = 0
    limit = max_len - 3
    i = 0
    n = len(s)
    while i < n:
        if s[i] == '\033':
            in_escape = True
            result.append(s[i])
            i += 1
            continue
        if in_escape:
            result.append(s[i])
            if s[i] == 'm':
                in_escape = False
            i += 1
            continue
        if visible_count < limit:
            result.append(s[i])
            visible_count += 1
        else:
            break
        i += 1
    result.append("...")
    result.append(ANSI_RESET)
    return "".join(result)


def draw_tui_row(rows: list, content: str, width: int):
    vl = visible_length(content)
    padding = ""
    if vl < width - 4:
        padding = " " * (width - 4 - vl)
    rows.append(f"│ {content}{padding} │")


def format_two_columns(left_label: str, left_val: str, right_label: str, right_val: str, col_width: int) -> str:
    left_str = left_label + left_val
    right_str = right_label + right_val
    return pad_visible(left_str, col_width) + right_str


def format_bytes(b: int) -> str:
    if b == 0:
        return "0 B"
    const_unit = 1024
    if b < const_unit:
        return f"{b} B"
    div = const_unit
    exp = 0
    n = b // const_unit
    while n >= const_unit:
        div *= const_unit
        n //= const_unit
        exp += 1
    units = "KMGTPE"
    unit_char = units[exp] if exp < len(units) else "P"
    return f"{b / div:.2f} {unit_char}B"


def get_terminal_size():
    size = shutil.get_terminal_size((80, 24))
    width = size.columns
    height = size.lines
    if width < 50:
        width = 50
    if height < 10:
        height = 10
    return width, height


# [v1.5.1] TUI border cache
_tui_border_width = 0
_tui_border_top = ""
_tui_border_mid = ""
_tui_border_bottom = ""


def draw_tui(config: Config):
    global _tui_border_width, _tui_border_top, _tui_border_mid, _tui_border_bottom
    try:
        term_width, term_height = get_terminal_size()
        box_width = term_width - 2
        if box_width < 50:
            box_width = 50
        if box_width > 110:
            box_width = 110

        inner_width = box_width - 4
        col_width = inner_width // 2

        # [v1.5.1] Cache border strings
        if _tui_border_width != box_width:
            h_line = "─" * (box_width - 2)
            _tui_border_top = "┌" + h_line + "┐"
            _tui_border_mid = "├" + h_line + "┤"
            _tui_border_bottom = "└" + h_line + "┘"
            _tui_border_width = box_width

        lines = []
        lines.append("\033[H\033[J")
        lines.append(_tui_border_top)

        title = f"PYWAY Proxy Dashboard (v{VERSION})"
        pad = (box_width - 2 - len(title)) // 2
        if pad < 0:
            pad = 0
        title_line = " " * pad + ANSI_CYAN + title + ANSI_RESET + " " * (box_width - 2 - pad - len(title))
        lines.append(f"│{title_line}│")
        lines.append(_tui_border_mid)

        mode = "Server" if config.upstream is None else "Client (HTTP + SOCKS5)"
        mode_col = ANSI_GREEN + mode + ANSI_RESET if config.upstream is not None else ANSI_YELLOW + mode + ANSI_RESET
        max_conn_val = str(config.max_connections)
        draw_tui_row(lines, format_two_columns("Mode:      ", mode_col, "Max Conns:   ", max_conn_val, col_width), box_width)

        listen_val = f"{config.proxy_host}:{config.proxy_port}"
        timeout_val = f"{config.connection_timeout}s"
        draw_tui_row(lines, format_two_columns("Listen:    ", ANSI_YELLOW + listen_val + ANSI_RESET, "Timeout:     ", ANSI_YELLOW + timeout_val + ANSI_RESET, col_width), box_width)

        upstream_val = config.upstream if config.upstream else "N/A"
        block_local_val = "Enabled" if config.block_local else "Disabled"
        block_local_col = ANSI_GREEN + block_local_val + ANSI_RESET if config.block_local else ANSI_RED + block_local_val + ANSI_RESET
        draw_tui_row(lines, format_two_columns("Upstream:  ", ANSI_MAGENTA + upstream_val + ANSI_RESET, "Block Local: ", block_local_col, col_width), box_width)

        if config.upstream is not None:
            ssl_verify_str = ANSI_GREEN + "Enabled" + ANSI_RESET if config.ssl_verify else ANSI_RED + "Disabled (Insecure)" + ANSI_RESET
        else:
            ssl_verify_str = ANSI_GREY + "N/A" + ANSI_RESET

        if config.crypto:
            auth_str = ANSI_GREEN + "Enabled (XOR)" + ANSI_RESET
        elif config.upstream is None:
            auth_str = ANSI_RED + "DISABLED (Open Proxy!)" + ANSI_RESET
        else:
            auth_str = ANSI_YELLOW + "Disabled" + ANSI_RESET
        draw_tui_row(lines, format_two_columns("Auth:      ", auth_str, "SSL Verify:  ", ssl_verify_str, col_width), box_width)

        dns_str = ANSI_GREEN + f"Remote: {config.resolver.server_ip}" + ANSI_RESET if config.resolver else ANSI_YELLOW + "System Default" + ANSI_RESET
        log_level_name = logging.getLevelName(logger.level)
        level_color = ANSI_GREEN
        if log_level_name == "DEBUG":
            level_color = ANSI_CYAN
        elif log_level_name == "WARNING":
            level_color = ANSI_YELLOW
        elif log_level_name == "ERROR":
            level_color = ANSI_RED
        level_str = level_color + log_level_name + ANSI_RESET
        draw_tui_row(lines, format_two_columns("DNS:       ", dns_str, "Log Level:   ", level_str, col_width), box_width)

        buf_kb = config.buffer_size // 1024
        buf_info = f"{buf_kb} KB"
        if config.socket_buffer > 0:
            buf_info += f" (Socket: {config.socket_buffer} KB)"

        nd_val = ANSI_GREEN + "On" + ANSI_RESET if config.tcp_nodelay else ANSI_RED + "Off" + ANSI_RESET
        ka_val = ANSI_GREEN + "On" + ANSI_RESET if config.tcp_keepalive else ANSI_RED + "Off" + ANSI_RESET
        tcp_settings = f"NoDelay:{nd_val} KeepAlive:{ka_val}"
        draw_tui_row(lines, format_two_columns("Buffer:    ", buf_info, "TCP Settings:", tcp_settings, col_width), box_width)

        config_lines = 6
        if config.fakehost:
            draw_tui_row(lines, format_two_columns("Fake Host: ", ANSI_MAGENTA + config.fakehost + ANSI_RESET, "", "", col_width), box_width)
            config_lines = 7

        lines.append(_tui_border_mid)

        active = stats.active_conns
        curr_up = stats.bytes_up
        curr_down = stats.bytes_down

        active_str = f"{active} / {config.max_connections}"
        speed_down_str = f"{stats.speed_down:.2f} MB/s"
        speed_up_str = f"{stats.speed_up:.2f} MB/s"
        total_down_str = format_bytes(curr_down)
        total_up_str = format_bytes(curr_up)

        draw_tui_row(lines, format_two_columns("Conns:     ", active_str, "", "", col_width), box_width)
        draw_tui_row(lines, format_two_columns("Download:  ", speed_down_str, "Total Down:  ", total_down_str, col_width), box_width)
        draw_tui_row(lines, format_two_columns("Upload:    ", speed_up_str, "Total Up:    ", total_up_str, col_width), box_width)

        lines.append(_tui_border_mid)

        used_height = 3 + config_lines + 4 + 2 + 1
        max_tui_logs = term_height - used_height
        if max_tui_logs < 5:
            max_tui_logs = 5

        draw_tui_row(lines, ANSI_CYAN + "Recent Logs:" + ANSI_RESET, box_width)
        with _tui_log_lock:
            logs = _tui_log_slice(max_tui_logs)
            for line in logs:
                line = truncate_visible(line, inner_width)
                draw_tui_row(lines, line, box_width)
            for _ in range(len(logs), max_tui_logs):
                draw_tui_row(lines, "", box_width)

        lines.append(_tui_border_bottom)

        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()
    except Exception:
        pass


async def tui_refresh_loop(config: Config):
    # [v1.5.1] 100ms ticker + dirty flag (replaces 0.5s timeout wait)
    draw_tui(config)
    dirty = False
    while True:
        try:
            try:
                await asyncio.wait_for(tui_refresh_event.wait(), timeout=0.1)
                tui_refresh_event.clear()
                dirty = True
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                break
            if dirty:
                draw_tui(config)
                dirty = False
        except asyncio.CancelledError:
            break
        except Exception:
            pass


def custom_exception_handler(loop, context):
    message = context.get("message", "")
    exception = context.get("exception")

    if message and "Task was destroyed but it is pending!" in message:
        return

    if isinstance(exception, (ConnectionResetError, BrokenPipeError,
                              asyncio.CancelledError, ConnectionAbortedError, OSError)):
        return

    if isinstance(exception, RuntimeError) and "coroutine ignored" in str(exception):
        return

    logger.debug("Loop exception: %s", context)


def _ifind(data: bytes, sub: bytes) -> int:
    """Case-insensitive byte search. Zero-allocation, O(n) scan."""
    n, m = len(data), len(sub)
    if m == 0:
        return 0
    sub_lower = sub.lower()
    first = sub_lower[0]
    for i in range(n - m + 1):
        b = data[i]
        if 65 <= b <= 90:
            b += 32
        if b != first:
            continue
        for j in range(1, m):
            bj = data[i+j]
            if 65 <= bj <= 90:
                bj += 32
            if bj != sub_lower[j]:
                break
        else:
            return i
    return -1


def parse_host_port(address: str, default_port: int = 80) -> Tuple[str, str]:
    address = address.strip()
    if not address:
        return "", str(default_port)

    if address.startswith("["):
        if "]:" in address:
            host_part, port_part = address.rsplit(':', 1)
            return host_part.strip('[]'), port_part
        else:
            return address.strip('[]'), str(default_port)
    elif ':' in address:
        if address.count(':') > 1:
            return address, str(default_port)
        host, port = address.rsplit(':', 1)
        return host, port
    else:
        return address, str(default_port)


def is_local_target(host: str) -> bool:
    if not host:
        return False
    h = host.lower()
    if h in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"):
        return True
    # [v1.5.1] IPv6 local address ranges
    if h.startswith("fe80:") or h.startswith("[fe80:"):
        return True
    if h.startswith("fc00:") or h.startswith("[fc00:"):
        return True
    if h.startswith("fd00:") or h.startswith("[fd00:"):
        return True
    # Fast rejection: most public hostnames don't start with these
    if host[0] not in "10lL[":
        return False
    if h.startswith("192.168.") or h.startswith("10."):
        return True
    if h.startswith("172."):
        parts = h.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            b = int(parts[1])
            if 16 <= b <= 31:
                return True
    return False


def sanitize_header(value: str) -> str:
    if not value:
        return ""
    return value.replace('\r', '').replace('\n', '').strip()


def optimize_socket(writer: asyncio.StreamWriter, config: Config, connection_type: str = "unknown"):
    sock = writer.get_extra_info('socket')
    if not sock:
        return
    try:
        if config.tcp_nodelay:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if config.tcp_keepalive:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if config.socket_buffer > 0:
            buffer_bytes = config.socket_buffer * 1024
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_bytes)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_bytes)
    except Exception as e:
        logger.debug("[%s] Socket optimization error: %s", connection_type, e)


async def safe_close_streamwriter(w: Optional[asyncio.StreamWriter]):
    if not w:
        return
    try:
        if hasattr(w, "is_closing") and not w.is_closing():
            w.close()
        if hasattr(w, "wait_closed"):
            await asyncio.wait_for(w.wait_closed(), timeout=2.0)
    except (asyncio.TimeoutError, Exception):
        pass


def get_ws_header(data_len: int, opcode: int = 0x2, masked: bool = False) -> bytes:
    fin_bit = 0b10000000
    mask_bit = 128 if masked else 0

    if data_len < 126:
        header = bytearray(2)
        header[0] = fin_bit | opcode
        header[1] = data_len | mask_bit
    elif data_len < 65536:
        header = bytearray(4)
        header[0] = fin_bit | opcode
        header[1] = 126 | mask_bit
        header[2] = (data_len >> 8) & 0xFF
        header[3] = data_len & 0xFF
    else:
        header = bytearray(10)
        header[0] = fin_bit | opcode
        header[1] = 127 | mask_bit
        header[2] = (data_len >> 56) & 0xFF
        header[3] = (data_len >> 48) & 0xFF
        header[4] = (data_len >> 40) & 0xFF
        header[5] = (data_len >> 32) & 0xFF
        header[6] = (data_len >> 24) & 0xFF
        header[7] = (data_len >> 16) & 0xFF
        header[8] = (data_len >> 8) & 0xFF
        header[9] = data_len & 0xFF
    return header


def create_ws_frame(data: bytes, opcode: int = 0x2, masked: bool = False) -> bytes:
    """Create a WebSocket frame with minimal allocations."""
    dl = len(data)
    hdr = get_ws_header(dl, opcode, masked)
    if masked:
        mask_int = random.getrandbits(32)
        mk = mask_int.to_bytes(4, 'big')
        total = len(hdr) + 4 + dl
        frame = bytearray(total)
        frame[:len(hdr)] = hdr
        frame[len(hdr):len(hdr)+4] = mk
        off = len(hdr) + 4
        if dl <= 256:
            for pos in range(dl):
                frame[off + pos] = data[pos] ^ mk[pos & 3]
        else:
            for pos in range(0, dl, CHUNK_SIZE):
                cs = min(CHUNK_SIZE, dl - pos)
                chunk = data[pos:pos + cs]
                ks = (mk * (cs // 4 + 1))[:cs]
                r = int.from_bytes(chunk, 'big') ^ int.from_bytes(ks, 'big')
                frame[off+pos:off+pos+cs] = r.to_bytes(cs, 'big')
        return frame
    total = len(hdr) + dl
    frame = bytearray(total)
    frame[:len(hdr)] = hdr
    frame[len(hdr):] = data
    return frame


def write_ws_frame_direct(writer: asyncio.StreamWriter, data: bytes,
                           opcode: int = 0x2, masked: bool = False) -> None:
    header = get_ws_header(len(data), opcode, masked)
    if masked:
        writer.write(create_ws_frame(data, opcode, masked=True))
    else:
        writer.write(header)
        writer.write(data)


async def read_ws_frame(reader: asyncio.StreamReader, writer: Optional[asyncio.StreamWriter] = None) -> Optional[bytes]:
    try:
        while True:
            header = await reader.readexactly(2)
            opcode = header[0] & 0b00001111
            masked = bool(header[1] & 0b10000000)
            payload_len = header[1] & 0b01111111

            if payload_len == 126:
                payload_len = struct.unpack('!H', await reader.readexactly(2))[0]
            elif payload_len == 127:
                payload_len = struct.unpack('!Q', await reader.readexactly(8))[0]

            if payload_len > MAX_WS_FRAME_SIZE:
                logger.error("Frame too large: %s", payload_len)
                return None

            masking_key = await reader.readexactly(4) if masked else None
            payload = await reader.readexactly(payload_len)

            if masked and masking_key:
                payload = bytearray(payload)
                for off in range(0, payload_len, CHUNK_SIZE):
                    cs = min(CHUNK_SIZE, payload_len - off)
                    chunk = payload[off:off + cs]
                    ks = (masking_key * (cs // 4 + 1))[:cs]
                    r = int.from_bytes(chunk, 'big') ^ int.from_bytes(ks, 'big')
                    payload[off:off + cs] = r.to_bytes(cs, 'big')

            if opcode in [0x0, 0x1, 0x2]:
                return payload
            elif opcode == 0x9:  # Ping
                if writer and not writer.is_closing():
                    writer.write(create_ws_frame(payload, opcode=0xA, masked=True))
                continue
            elif opcode == 0xA:  # Pong
                continue
            elif opcode == 0x8:  # Close
                return None
            else:
                continue
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return None
    except Exception as e:
        logger.debug("Read frame error: %s", e)
        return None


# --- Buffer Pool ---
_BUFFER_POOL_SIZE = 16
_buffer_pool_lock = threading.Lock()


def _get_buffer(config: Config) -> bytearray:
    """Get a buffer from pool or allocate new one."""
    with _buffer_pool_lock:
        if config.buf_pool:
            return config.buf_pool.pop()
    return bytearray(config.buffer_size)


def _put_buffer(config: Config, buf: bytearray):
    """Return a buffer to the pool."""
    with _buffer_pool_lock:
        if len(config.buf_pool) < _BUFFER_POOL_SIZE:
            config.buf_pool.append(buf)


# --- Connection Pool (Client mode) ---

class PooledConn:
    __slots__ = ('reader', 'writer', 'created', 'last_used')

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.created = time.monotonic()
        self.last_used = time.monotonic()


class ConnPool:
    def __init__(self, config: Config, max_size: int = 10):
        self.conns: list = []
        self.lock = asyncio.Lock()
        self.config = config
        self.max_size = max_size
        self.max_age = 300.0       # 5 minutes
        self.idle_timeout = 30.0   # 30 seconds
        self.closed = False
        self._maintain_task: Optional[asyncio.Task] = None

    async def start(self):
        self._maintain_task = asyncio.create_task(self._maintain_loop())

    async def _maintain_loop(self):
        try:
            while not self.closed:
                await asyncio.sleep(5)
                await self._cleanup()
                # Fill pool to half capacity
                for _ in range(self.max_size // 2):
                    if self.closed:
                        break
                    async with self.lock:
                        if len(self.conns) >= self.max_size // 2:
                            break
                    conn = await self._create_conn()
                    if conn is None:
                        break
                    async with self.lock:
                        if self.closed or len(self.conns) >= self.max_size:
                            await safe_close_streamwriter(conn.writer)
                            break
                        self.conns.append(conn)
        except asyncio.CancelledError:
            pass

    async def _cleanup(self):
        async with self.lock:
            now = time.monotonic()
            valid = []
            for c in self.conns:
                if now - c.created > self.max_age or now - c.last_used > self.idle_timeout:
                    await safe_close_streamwriter(c.writer)
                else:
                    valid.append(c)
            self.conns = valid

    async def _create_conn(self) -> Optional[PooledConn]:
        cfg = self.config
        try:
            reader, writer = await _do_ws_handshake(cfg)
            return PooledConn(reader, writer)
        except Exception as e:
            logger.debug("[Pool] Failed to pre-create connection: %s", e)
            return None

    async def get(self) -> Optional[PooledConn]:
        async with self.lock:
            if self.closed or not self.conns:
                return None
            conn = self.conns.pop()
            conn.last_used = time.monotonic()
            return conn

    async def put(self, conn: PooledConn):
        async with self.lock:
            if self.closed or len(self.conns) >= self.max_size:
                await safe_close_streamwriter(conn.writer)
                return
            if time.monotonic() - conn.created > self.max_age:
                await safe_close_streamwriter(conn.writer)
                return
            self.conns.append(conn)

    async def close(self):
        self.closed = True
        if self._maintain_task:
            self._maintain_task.cancel()
        async with self.lock:
            for c in self.conns:
                await safe_close_streamwriter(c.writer)
            self.conns.clear()


# Global connection pool
_conn_pool: Optional[ConnPool] = None


async def _do_ws_handshake(config: Config) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Perform TCP+TLS+WS handshake to upstream. Returns (reader, writer)."""
    cfg = config
    upstream_parts = urllib.parse.urlparse(cfg.upstream)

    server_host = cfg.upstream_host
    server_port = cfg.upstream_port
    use_ssl = cfg.upstream_is_wss

    ssl_context = None
    if use_ssl:
        ssl_context = _pick_profile_ssl_context()

    # Remote DNS resolution
    dial_host = server_host
    if cfg.resolver:
        try:
            dial_host = await cfg.resolver.resolve(server_host)
        except OSError as e:
            logger.error("[DNS] Failed to resolve upstream %s: %s", server_host, e)

    sni_hostname = sanitize_header(cfg.fakehost.split(':')[0] if cfg.fakehost else server_host)

    server_reader, server_writer = await asyncio.open_connection(
        dial_host, int(server_port),
        limit=config.stream_limit,
        ssl=ssl_context,
        server_hostname=sni_hostname if use_ssl else None
    )

    optimize_socket(server_writer, cfg, "WebSocket Tunnel")

    # [v1.5.1] Browser profile-based handshake
    profile = pick_browser_profile()

    handshake_host = cfg.fakehost if cfg.fakehost else (
        server_host if (use_ssl and int(server_port) == 443) or (not use_ssl and int(server_port) == 80)
        else f"{server_host}:{server_port}"
    )

    handshake_path = upstream_parts.path or "/"
    ws_key = base64.b64encode(random.randbytes(16)).decode()
    protocol_scheme = "https" if use_ssl else "http"

    handshake_host = sanitize_header(handshake_host)
    host_header_no_port = handshake_host.split(':')[0]

    sec_fetch_site = "same-origin" if sni_hostname == host_header_no_port else "cross-site"

    # [v1.5.1] Three-layer header structure (matching Go version)
    req_line = f"GET {handshake_path} HTTP/1.1\r\n"

    fixed_top = [
        f"Host: {handshake_host}",
        "Connection: Upgrade",
        "Upgrade: websocket",
    ]

    shufflable = [
        "Pragma: no-cache",
        "Cache-Control: no-cache",
        f"User-Agent: {profile.ua}",
        f"Accept-Language: {profile.accept_lang}",
        "Accept-Encoding: gzip, deflate, br, zstd",
        f"Origin: {protocol_scheme}://{sni_hostname}",
    ]

    # Chromium profiles include Client Hints
    if profile.is_chromium and profile.sec_ch_ua:
        shufflable.extend([
            f"sec-ch-ua: {profile.sec_ch_ua}",
            f"sec-ch-ua-mobile: {profile.sec_ch_ua_mob}",
            f"sec-ch-ua-platform: {profile.sec_ch_ua_plat}",
        ])

    fixed_bottom = [
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
        "Sec-Fetch-Dest: websocket",
        "Sec-Fetch-Mode: websocket",
        f"Sec-Fetch-Site: {sec_fetch_site}",
    ]

    random.shuffle(shufflable)

    handshake = req_line
    for h in fixed_top:
        handshake += h + "\r\n"
    for h in shufflable:
        handshake += h + "\r\n"
    for h in fixed_bottom:
        handshake += h + "\r\n"
    handshake += "\r\n"

    server_writer.write(handshake.encode())
    await server_writer.drain()

    try:
        response_data = await asyncio.wait_for(server_reader.readuntil(CRLFCRLF), timeout=10.0)
    except asyncio.TimeoutError:
        raise ConnectionError("Upstream handshake timed out")
    except asyncio.LimitOverrunError:
        raise ConnectionError("Upstream header too large (DoS protection)")

    if b"HTTP/1.1 101" not in response_data and b"HTTP/1.0 101" not in response_data:
        raise ConnectionError(f"Handshake failed: {response_data.decode(errors='ignore')[:100]}")

    return server_reader, server_writer


async def connect_to_upstream(target: str, config: Config) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to upstream WS server and send target frame. Returns (reader, writer)."""
    # [v1.5.1] Try connection pool first
    global _conn_pool
    if _conn_pool is not None:
        pooled = await _conn_pool.get()
        if pooled is not None:
            logger.debug("[CLIENT] Using pooled connection")
            # Send target frame
            payload = bytearray(target.encode())
            payload.extend(b"\n")
            payload.extend(b' ' * random.randint(1, 40))
            if config.crypto:
                payload = config.crypto.transform(payload)
            pooled.writer.write(create_ws_frame(payload, opcode=0x2, masked=True))
            await pooled.writer.drain()

            confirmation = await read_ws_frame(pooled.reader)
            if confirmation is None:
                await safe_close_streamwriter(pooled.writer)
                # Fallback to new connection
                return await _new_upstream_connection(target, config)
            if config.crypto:
                confirmation = config.crypto.transform(confirmation)
            if not confirmation.startswith(b"OK"):
                await safe_close_streamwriter(pooled.writer)
                return await _new_upstream_connection(target, config)
            return pooled.reader, pooled.writer

    return await _new_upstream_connection(target, config)


async def _new_upstream_connection(target: str, config: Config) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Create a new upstream WS connection and send target frame."""
    server_reader, server_writer = await _do_ws_handshake(config)

    payload = bytearray(target.encode())
    payload.extend(b"\n")
    payload.extend(b' ' * random.randint(1, 40))

    if config.crypto:
        payload = config.crypto.transform(payload)
    server_writer.write(create_ws_frame(payload, opcode=0x2, masked=True))
    await server_writer.drain()

    confirmation = await read_ws_frame(server_reader)
    if confirmation is None:
        raise ConnectionError("Server closed connection")
    if config.crypto:
        confirmation = config.crypto.transform(confirmation)

    if not confirmation.startswith(b"OK"):
        raise ConnectionError(f"Server rejected")
    return server_reader, server_writer


conn_semaphore: Optional[asyncio.Semaphore] = None


async def handle_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Config):
    global conn_semaphore
    if conn_semaphore:
        if conn_semaphore.locked():
            logger.warning("Max connections reached. Dropping %s", writer.get_extra_info('peername'))
            writer.close()
            return
        await conn_semaphore.acquire()

    try:
        await asyncio.wait_for(
            _handle_server_impl(reader, writer, config),
            timeout=config.connection_timeout
        )
    except Exception as e:
        logger.debug("Server handler error: %s", e)
    finally:
        if conn_semaphore:
            conn_semaphore.release()
        await safe_close_streamwriter(writer)


async def _handle_server_impl(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Config):
    target_writer = None
    try:
        try:
            data = await reader.readuntil(CRLFCRLF)
        except asyncio.LimitOverrunError:
            logger.warning("[Security] Header too large, dropping connection.")
            writer.write(HTTP_400_RESP)
            await writer.drain()
            return

        # [v1.5.1] Check for upgrade: websocket header
        if _ifind(data, b'upgrade: websocket') < 0:
            logger.warning("[Security] Missing upgrade: websocket header")
            writer.write(HTTP_400_RESP)
            await writer.drain()
            return

        idx = _ifind(data, b'sec-websocket-key:')
        ws_key_line = None
        if idx >= 0:
            end = data.find(CRLF, idx)
            if end < 0:
                end = len(data)
            ws_key_line = data[idx:end]

        if not ws_key_line:
            writer.write(HTTP_400_RESP)
            await writer.drain()
            return

        key_val = ws_key_line.split(b':', 1)[1].strip()
        accept_key = base64.b64encode(hashlib.sha1(key_val + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        writer.write(WS_UPGRADE_PREFIX + accept_key + CRLFCRLF)
        await writer.drain()

        reader._limit = config.stream_limit

        auth_data = await read_ws_frame(reader)
        if auth_data is None:
            return

        if config.crypto:
            auth_data = config.crypto.transform(auth_data)

        if not auth_data:
            logger.warning("[Security] Empty auth data from %s", writer.get_extra_info('peername'))
            return

        # Parse target: trim whitespace, find first space/null
        target_bytes = bytes(auth_data).strip()
        space_idx = target_bytes.find(b' ')
        if space_idx >= 0:
            target_bytes = target_bytes[:space_idx]
        try:
            target_str = target_bytes.decode()
            target_host, target_port = parse_host_port(target_str)
        except Exception:
            logger.warning("[Security] Malformed target format: %s", auth_data[:50].decode(errors="ignore"))
            return

        # Remote DNS resolution for target address
        dial_host = target_host
        if config.resolver:
            try:
                dial_host = await config.resolver.resolve(target_host)
            except OSError as e:
                logger.error("[DNS] Failed to resolve %s: %s", target_host, e)

        logger.info("[SERVER] Connect -> %s:%s", dial_host, target_port)
        target_reader, target_writer = await asyncio.open_connection(
            dial_host, int(target_port), limit=config.stream_limit, family=socket.AF_INET
        )

        ok_payload = b"OK\n"
        if config.crypto:
            ok_payload = config.crypto.transform(ok_payload)
        writer.write(create_ws_frame(ok_payload, opcode=0x2, masked=False))
        await writer.drain()

        await ws_forward(reader, writer, target_reader, target_writer, client_side=False, config=config)
    finally:
        await safe_close_streamwriter(target_writer)


async def socks5_negotiate(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Tuple[str, str]:
    nmethods = ord(await reader.readexactly(1))
    await reader.readexactly(nmethods)
    writer.write(b'\x05\x00')
    await writer.drain()

    ver, cmd, rsv, atyp = await reader.readexactly(4)
    if ver != 5:
        raise ConnectionError("Invalid SOCKS5")

    # [v1.5.1] Check for non-CONNECT commands and reply with error code 0x07
    if cmd != 1:
        logger.warning("[SOCKS5] Unsupported command: %d", cmd)
        writer.write(bytes([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
        raise ConnectionError("SOCKS5 command not supported")

    if atyp == 1:
        target_host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
    elif atyp == 3:
        target_host = (await reader.readexactly(ord(await reader.readexactly(1)))).decode()
    elif atyp == 4:
        target_host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        raise ConnectionError(f"Unsupported ATYP: {atyp}")

    target_port = str(struct.unpack('!H', await reader.readexactly(2))[0])
    return target_host, target_port


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Config):
    global conn_semaphore
    if conn_semaphore:
        if conn_semaphore.locked():
            writer.close()
            return
        await conn_semaphore.acquire()

    peername = writer.get_extra_info('peername')
    logger.info("[CLIENT] Connection from %s", peername)
    try:
        await asyncio.wait_for(
            _handle_client_impl(reader, writer, config),
            timeout=config.connection_timeout
        )
    except Exception as e:
        logger.debug("Client handler error: %s", e)
    finally:
        if conn_semaphore:
            conn_semaphore.release()
        await safe_close_streamwriter(writer)


async def _handle_client_impl(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Config):
    server_writer = None
    is_socks5 = False
    try:
        try:
            initial_byte = await asyncio.wait_for(reader.read(1), timeout=10.0)
        except asyncio.TimeoutError:
            return
        if not initial_byte:
            return

        target_host, target_port, full_initial_request = "", "", b""

        if initial_byte == b'\x05':
            is_socks5 = True
            target_host, target_port = await socks5_negotiate(reader, writer)
            logger.info("[CLIENT] SOCKS5 -> %s:%s", target_host, target_port)
        elif initial_byte == b'\x16':
            logger.error("[CLIENT] HTTPS Handshake detected! Please use HTTP/SOCKS5 proxy.")
            return
        else:
            # HTTP Proxy
            try:
                rest_of_line = await asyncio.wait_for(reader.readuntil(CRLF), timeout=10.0)
            except asyncio.LimitOverrunError:
                return

            request_line_data = initial_byte + rest_of_line
            try:
                request_line = request_line_data.decode('utf-8').strip()
                method, target, _ = request_line.split(' ', 2)
                logger.info("[CLIENT] %s %s", method, target)
            except:
                return

            if method == 'CONNECT':
                try:
                    await asyncio.wait_for(reader.readuntil(CRLFCRLF), timeout=5.0)
                except: pass
                target_host, target_port = parse_host_port(target)
            else:
                try:
                    headers = await asyncio.wait_for(reader.readuntil(CRLFCRLF), timeout=10.0)
                except asyncio.LimitOverrunError:
                    return
                full_initial_request = request_line_data + headers
                parsed = urllib.parse.urlparse(target)
                target_host, target_port = parsed.hostname, str(parsed.port or 80)
                if not target_host:
                    for line in headers.split(b'\r\n'):
                        if len(line) > 5 and line[:5].lower() == b'host:':
                            h = line[5:].strip().decode(errors='ignore')
                            target_host, target_port = parse_host_port(h)
                            break

        if not target_host:
            return

        if config.block_local and is_local_target(target_host):
            logger.warning("[CLIENT] Blocked local traffic attempt: %s:%s", target_host, target_port)
            return

        try:
            server_reader, server_writer = await asyncio.wait_for(
                connect_to_upstream(f"{target_host}:{target_port}", config), timeout=30.0
            )
        except Exception as e:
            logger.error("[CLIENT] Upstream Fail: %s", e)
            if is_socks5:
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            else:
                writer.write(HTTP_400_RESP)
            await writer.drain()
            return

        if is_socks5:
            writer.write(SOCKS5_OK_RESP)
            await writer.drain()
        elif not full_initial_request:
            writer.write(HTTP_200_RESP)
            await writer.drain()
        else:
            server_writer.write(create_ws_frame(full_initial_request, opcode=0x2, masked=True))
            await server_writer.drain()

        reader._limit = config.stream_limit

        await ws_forward(server_reader, server_writer, reader, writer, client_side=True, config=config)
    finally:
        await safe_close_streamwriter(server_writer)


async def _transfer_ws_to_tcp(ws_reader, tcp_writer, client_side, config):
    """WebSocket -> TCP: read WS frames, write raw data."""
    pending = 0
    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    read_ws_frame(ws_reader, writer=tcp_writer),
                    timeout=config.connection_timeout
                )
            except asyncio.TimeoutError:
                break
            if data is None or tcp_writer.is_closing():
                break
            if not data:
                continue
            tcp_writer.write(data)
            if client_side:
                stats.add_bytes(down=len(data))
            else:
                stats.add_bytes(up=len(data))
            pending += len(data)
            if pending >= config.drain_threshold:
                await tcp_writer.drain()
                pending = 0
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.debug("WS->TCP transfer error: %s", e)
    finally:
        try:
            if pending > 0 and not tcp_writer.is_closing():
                await asyncio.wait_for(tcp_writer.drain(), timeout=1.0)
        except: pass


async def _transfer_tcp_to_ws(tcp_reader, ws_writer, client_side, config):
    """TCP -> WebSocket: read raw data, write WS frames."""
    pending = 0
    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    tcp_reader.read(config.buffer_size),
                    timeout=config.connection_timeout
                )
            except asyncio.TimeoutError:
                break
            if not data:
                break
            if ws_writer.is_closing():
                break

            # [v1.5.1] Write coalescing: try to read more data before writing
            # This reduces the number of small WebSocket frames
            if client_side:
                total_data = bytearray(data)
                while len(total_data) < config.buffer_size:
                    try:
                        more = await asyncio.wait_for(
                            tcp_reader.read(config.buffer_size - len(total_data)),
                            timeout=0.001  # 1ms
                        )
                        if not more:
                            break
                        total_data.extend(more)
                    except (asyncio.TimeoutError, Exception):
                        break
                data = bytes(total_data)

            if client_side:
                ws_writer.write(create_ws_frame(data, opcode=0x2, masked=True))
                stats.add_bytes(up=len(data))
            else:
                write_ws_frame_direct(ws_writer, data, opcode=0x2, masked=False)
                stats.add_bytes(down=len(data))
            pending += len(data)
            if pending >= config.drain_threshold:
                await ws_writer.drain()
                pending = 0
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.debug("TCP->WS transfer error: %s", e)
    finally:
        try:
            if pending > 0 and not ws_writer.is_closing():
                await asyncio.wait_for(ws_writer.drain(), timeout=1.0)
        except: pass


async def ws_forward(ws_reader, ws_writer, tcp_reader, tcp_writer, client_side, config):

    stats.add_conn()

    task_ws_to_tcp = asyncio.create_task(
        _transfer_ws_to_tcp(ws_reader, tcp_writer, client_side, config))
    task_tcp_to_ws = asyncio.create_task(
        _transfer_tcp_to_ws(tcp_reader, ws_writer, client_side, config))

    try:
        done, pending = await asyncio.wait(
            [task_ws_to_tcp, task_tcp_to_ws],
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    finally:
        stats.remove_conn()
        await safe_close_streamwriter(ws_writer)
        await safe_close_streamwriter(tcp_writer)


async def monitor_stats(config: Config):
    last_up = 0
    last_down = 0
    try:
        while True:
            interval = 1.0 if config.tui else 3.0
            await asyncio.sleep(interval)
            current_up = stats.bytes_up
            current_down = stats.bytes_down

            up_speed = (current_up - last_up) / interval / 1024 / 1024
            down_speed = (current_down - last_down) / interval / 1024 / 1024

            last_up = current_up
            last_down = current_down

            stats.speed_up = up_speed
            stats.speed_down = down_speed

            if not config.tui:
                msg = (f"\r{ANSI_GREY}[STATS] Conns: {stats.active_conns} | "
                       f"Up: {up_speed:.2f} MB/s | Down: {down_speed:.2f} MB/s{ANSI_RESET}")
                sys.stdout.write(msg)
                sys.stdout.flush()
            else:
                trigger_tui_refresh()
    except asyncio.CancelledError:
        pass


async def main_async(config: Config):
    global conn_semaphore, _tui_loop, tui_refresh_event, _conn_pool
    conn_semaphore = asyncio.Semaphore(config.max_connections)

    _tui_loop = asyncio.get_running_loop()
    _tui_loop.set_exception_handler(custom_exception_handler)

    tui_refresh_event = asyncio.Event()

    tui_task = None
    original_handlers = list(logger.handlers)

    if config.tui:
        if os.name == 'nt':
            os.system('')
        if hasattr(sys.stdout, 'reconfigure'):
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except Exception:
                pass

        logger.handlers.clear()
        tui_handler = TuiLogHandler()
        tui_formatter = ColoredFormatter(
            '%(asctime)s [%(levelname)s] %(message)s', '%H:%M:%S'
        )
        tui_handler.setFormatter(tui_formatter)
        logger.addHandler(tui_handler)

        sys.stdout.write("\033[2J\033[?25l")
        sys.stdout.flush()

        tui_task = asyncio.create_task(tui_refresh_loop(config))

    monitor_task = asyncio.create_task(monitor_stats(config))

    # [v1.5.1] Initialize connection pool for client mode
    if config.upstream is not None:
        _conn_pool = ConnPool(config, max_size=10)
        await _conn_pool.start()

    handler = handle_server if config.upstream is None else handle_client

    try:
        server = await asyncio.start_server(
            lambda r, w: handler(r, w, config),
            config.proxy_host, config.proxy_port,
            limit=MAX_HEADER_SIZE
        )
    except OSError as e:
        if config.tui:
            logger.handlers.clear()
            for h in original_handlers:
                logger.addHandler(h)
            sys.stdout.write("\033[?25h\033[2J\033[H")
            sys.stdout.flush()
        logger.error("Could not bind to %s:%s - %s", config.proxy_host, config.proxy_port, e)
        sys.exit(1)

    addrs = ', '.join(str(s.getsockname()) for s in server.sockets)
    mode = "Server" if not config.upstream else "Client (HTTP + SOCKS5)"

    if not config.tui:
        print(f"{ANSI_CYAN}PYWAY v{VERSION}{ANSI_RESET}")
        print(f"{ANSI_CYAN}{'-'*60}{ANSI_RESET}")
        print(f" [+] Mode:        {ANSI_GREEN}{mode}{ANSI_RESET}")
        print(f" [+] Listen:      {ANSI_YELLOW}{addrs}{ANSI_RESET}")
        if config.upstream:
            print(f" [+] Upstream:    {ANSI_MAGENTA}{config.upstream}{ANSI_RESET}")
            verify_str = "Enabled" if config.ssl_verify else "Disabled (Insecure)"
            verify_col = ANSI_GREEN if config.ssl_verify else ANSI_RED
            print(f" [+] SSL Verify:  {verify_col}{verify_str}{ANSI_RESET}")
            print(f" [+] User-Agent:  {ANSI_GREEN}Browser Profile (Sticky TLS+UA){ANSI_RESET}")

        dns_col = ANSI_GREEN if ("aiodns" in config.dns_info or "Remote" in config.dns_info) else ANSI_YELLOW
        print(f" [+] DNS:         {dns_col}{config.dns_info}{ANSI_RESET}")

        if config.crypto:
            auth_str = "Enabled (XOR)"
            auth_color = ANSI_GREEN
        elif config.upstream is None:
            auth_str = "DISABLED (--allow-open enabled -- Open Proxy!)"
            auth_color = ANSI_RED
        else:
            auth_str = "DISABLED"
            auth_color = ANSI_YELLOW
        print(f" [+] Auth:        {auth_color}{auth_str}{ANSI_RESET}")

        buf_info = f"{config.buffer_size//1024} KB"
        if config.socket_buffer:
            buf_info += f" (Socket: {config.socket_buffer} KB)"
        print(f" [+] Buffer:      {buf_info}")
        print(f" [+] Max Conns:   {config.max_connections}")

        print(f"{ANSI_CYAN}{'-'*60}{ANSI_RESET}")
        print(f"{ANSI_CYAN}[INFO] Proxy listening... (Press Ctrl+C to stop){ANSI_RESET}\n")
    else:
        logger.info("PYWAY v%s listening on %s", VERSION, addrs)

    try:
        async with server:
            while True:
                await asyncio.sleep(1)
    finally:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

        if tui_task:
            tui_task.cancel()
            try:
                await tui_task
            except asyncio.CancelledError:
                pass

        if _conn_pool:
            await _conn_pool.close()

        if config.tui:
            sys.stdout.write("\033[?25h\033[2J\033[H")
            sys.stdout.flush()
            logger.handlers.clear()
            for h in original_handlers:
                logger.addHandler(h)


def main():
    parser = argparse.ArgumentParser(description=f"Pyway {VERSION}")
    parser.add_argument('-p', required=True, help="Listen Address (e.g. :8080)")
    parser.add_argument('-up', help="Upstream WebSocket URL")
    parser.add_argument('-k', help="Authentication Key")
    parser.add_argument('-log', default='INFO', help="Log Level")
    parser.add_argument('-fakehost', help="Spoofing Hostname")
    parser.add_argument('-W', type=int, default=1024, help="App Buffer Size in KB (default 1MB)")
    parser.add_argument('--no-tcp-nodelay', action='store_true', help="Disable TCP_NODELAY")
    parser.add_argument('--no-tcp-keepalive', action='store_true', help="Disable TCP KeepAlive")
    parser.add_argument('--socket-buffer', type=int, default=8192, help="Kernel Socket Buffer in KB (default 8MB)")
    parser.add_argument('--connection-timeout', type=int, default=60, help="Connection Timeout (default 60s)")
    parser.add_argument('--verify-ssl', action='store_true', help="Enable SSL Verification")
    parser.add_argument('--max-conn', type=int, default=1000, help="Max Concurrent Connections")
    parser.add_argument('--block-local', '-block-local', dest='block_local', action='store_true', help="Drop local/LAN traffic (Client mode, default)")
    parser.add_argument('--no-block-local', '-no-block-local', dest='block_local', action='store_false', help="Allow local/LAN traffic")
    parser.add_argument('--allow-open', action='store_true', help="Allow server mode without authentication key")
    parser.add_argument('-dns', help="Remote DNS server IP (e.g. 8.8.8.8)")
    parser.add_argument('--tui', '-tui', action='store_true', help="Enable GUI-style TUI dashboard")
    parser.add_argument('--version', '-version', action='version', version=f"PYWAY v{VERSION}")
    parser.set_defaults(block_local=True)

    args = parser.parse_args()
    logger.setLevel(getattr(logging, args.log.upper()))

    buf = (args.W * 1024) if args.W else 1048576  # [v1.5.1] 1MB default

    # Validate upstream scheme
    if args.up:
        parsed = urllib.parse.urlparse(args.up)
        scheme = parsed.scheme.lower()
        if scheme and scheme not in ('ws', 'wss', 'http', 'https'):
            print(f"Error: Invalid upstream scheme '{scheme}'. Must be ws://, wss://, http:// or https://")
            sys.exit(1)

    # Server mode without authentication is an open proxy risk
    if args.up is None and not args.k and not args.allow_open:
        print("Error: Server mode requires -k (authentication key) or --allow-open flag")
        sys.exit(1)

    # Validate and create remote DNS resolver
    resolver = None
    if args.dns:
        import ipaddress
        try:
            ipaddress.ip_address(args.dns)
        except ValueError:
            print(f"Error: -dns requires a valid IP address (e.g. 8.8.8.8), got '{args.dns}'")
            sys.exit(1)
        resolver = RemoteResolver(args.dns)
        dns_info = f"Remote: {args.dns} (UDP+TCP)"
    else:
        try:
            import aiodns
            dns_info = "aiodns (Async)"
        except ImportError:
            dns_info = "System (Default)"

    crypto_obj = Crypto(args.k) if args.k else None

    # [v1.5.1] stream_limit must accommodate MAX_WS_FRAME_SIZE
    stream_limit = max(buf * 4, MAX_WS_FRAME_SIZE + 65536)

    # Pre-create SSL contexts
    ssl_ctx_verified = ssl.create_default_context()
    ssl_ctx_verified.check_hostname = True
    ssl_ctx_verified.verify_mode = ssl.CERT_REQUIRED

    ssl_ctx_unverified = ssl.create_default_context()
    ssl_ctx_unverified.check_hostname = False
    ssl_ctx_unverified.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, 'TLSVersion'):
        ssl_ctx_unverified.minimum_version = ssl.TLSVersion.TLSv1_2

    # Pre-parse upstream URL
    upstream_host = ""
    upstream_port = ""
    upstream_is_wss = False
    if args.up:
        parsed_up = urllib.parse.urlparse(args.up)
        upstream_is_wss = parsed_up.scheme.lower() in ('wss', 'https')
        upstream_host = parsed_up.hostname or ""
        upstream_port = parsed_up.port or ""
        if not upstream_port:
            upstream_port = "443" if upstream_is_wss else "80"
        else:
            upstream_port = str(upstream_port)

    # [v1.5.1] Init browser profile SSL contexts for WSS
    if args.up and upstream_is_wss:
        _init_profile_ssl_contexts(args.verify_ssl)

    config = Config(
        proxy_host=args.p.rsplit(':', 1)[0] or '0.0.0.0',
        proxy_port=int(args.p.rsplit(':', 1)[1]),
        upstream=args.up, fakehost=args.fakehost, crypto=crypto_obj,
        user_agent=pick_browser_profile().ua,  # Initial for display; profile picked per-connection
        dns_info=dns_info, resolver=resolver,
        buffer_size=buf, stream_limit=stream_limit, drain_threshold=buf*4,
        tcp_nodelay=not args.no_tcp_nodelay, tcp_keepalive=not args.no_tcp_keepalive,
        socket_buffer=args.socket_buffer, connection_timeout=args.connection_timeout,
        ssl_verify=args.verify_ssl,
        max_connections=args.max_conn,
        block_local=args.block_local,
        allow_open=args.allow_open,
        tui=args.tui,
        ssl_context_verified=ssl_ctx_verified,
        ssl_context_unverified=ssl_ctx_unverified,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        upstream_is_wss=upstream_is_wss,
    )

    if args.up is None:
        for p in ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']:
            os.environ.pop(p, None)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        main_task = loop.create_task(main_async(config))
        loop.run_until_complete(main_task)
    except KeyboardInterrupt:
        print(f"\n{ANSI_YELLOW}[INFO] Shutting down gracefully...{ANSI_RESET}")
        main_task.cancel()
        try:
            loop.run_until_complete(main_task)
        except asyncio.CancelledError:
            pass
        tasks = asyncio.all_tasks(loop)
        for task in tasks:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
    finally:
        try:
            loop.close()
        except: pass
        print(f"{ANSI_GREEN}[INFO] Proxy stopped.{ANSI_RESET}")


# --- Crypto ---

class Crypto:
    __slots__ = ('key_bytes', 'key_len', 'expanded_key')

    def __init__(self, key: str):
        self.key_bytes = hashlib.sha256(key.encode()).digest()
        self.key_len = len(self.key_bytes)
        # [v1.5.1] Pre-expand to CHUNK_SIZE + 8 for safe bulk XOR
        repeats = (CHUNK_SIZE + 8) // self.key_len + 1
        self.expanded_key = (self.key_bytes * repeats)[:CHUNK_SIZE + 8]

    def transform(self, data) -> bytearray:
        """XOR transform data. Accepts bytes or bytearray, returns bytearray."""
        if not data:
            return bytearray(data)
        ek = self.expanded_key
        dl = len(data)
        out = bytearray(dl)
        if dl <= 4096:
            for i in range(dl):
                out[i] = data[i] ^ ek[i]
        else:
            # [v1.5.1] 8-byte bulk XOR for large data
            i = 0
            while i + 8 <= dl:
                # Pack 8 bytes from data and key as little-endian uint64
                d_val = struct.unpack('<Q', data[i:i+8])[0]
                k_val = struct.unpack('<Q', ek[i & (CHUNK_SIZE - 1):][:8])[0] if (i & (CHUNK_SIZE - 1)) + 8 <= CHUNK_SIZE + 8 else 0
                # Fallback to byte-by-byte if key boundary issue
                if (i & (CHUNK_SIZE - 1)) + 8 > len(ek):
                    for j in range(8):
                        out[i + j] = data[i + j] ^ ek[(i + j) & (CHUNK_SIZE - 1)]
                else:
                    result = d_val ^ k_val
                    struct.pack_into('<Q', out, i, result)
                i += 8
            # Tail: byte-by-byte for remainder (< 8 bytes)
            while i < dl:
                out[i] = data[i] ^ ek[i & (CHUNK_SIZE - 1)]
                i += 1
        return out


if __name__ == "__main__":
    main()
