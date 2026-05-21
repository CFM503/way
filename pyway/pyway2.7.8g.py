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
from typing import Optional, Tuple
from dataclasses import dataclass

VERSION = "2.7.8G"
CRLF = b"\r\n"
CRLFCRLF = b"\r\n\r\n"
MAX_WS_FRAME_SIZE = 10 * 1024 * 1024  # [Security] Limit WS frame to 10MB
MAX_HEADER_SIZE = 8192  # [Security] Limit header size to 8KB

# ANSI color codes
ANSI_RESET = "\033[0m"
ANSI_CYAN = "\033[36m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_MAGENTA = "\033[35m"
ANSI_RED = "\033[31m"
ANSI_GREY = "\033[90m"


class Statistics:
    def __init__(self):
        self.active_conns = 0
        self.bytes_up = 0
        self.bytes_down = 0

    def add_conn(self):
        self.active_conns += 1

    def remove_conn(self):
        self.active_conns -= 1

    def add_bytes(self, up=0, down=0):
        # Acceptable drift for display purposes — lock would hurt throughput
        if up: self.bytes_up += up
        if down: self.bytes_down += down


stats = Statistics()

# Module-level pools to avoid per-call allocation
_UA_POOL = [
    # Chrome 136 - Windows/Mac/Linux
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    # Firefox 138 - Windows/Mac/Linux
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:138.0) Gecko/20100101 Firefox/138.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
    # Edge 136
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
    # Safari 18.4 - macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
    # Mobile: iOS Safari 18.4
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
    # Mobile: Android Chrome 136
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36",
    # Mobile: Android WebView (common in apps)
    "Mozilla/5.0 (Linux; Android 14; Pixel 7 Build/AP2A.240405.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/136.0.0.0 Mobile Safari/537.36",
]

_ACCEPT_LANG_POOL = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,ja;q=0.8",
]


CHUNK_SIZE = 65536  # 64KB chunk for XOR operations

class Crypto:
    __slots__ = ('key_bytes', 'key_len', 'expanded_key')

    def __init__(self, key: str):
        self.key_bytes = hashlib.sha256(key.encode()).digest()
        self.key_len = len(self.key_bytes)
        repeats = CHUNK_SIZE // self.key_len + 1
        self.expanded_key = (self.key_bytes * repeats)[:CHUNK_SIZE]

    def transform(self, data: bytes) -> bytearray:
        if not data:
            return data
        ek = self.expanded_key
        dl = len(data)
        out = bytearray(dl)
        if dl <= 4096:
            # Direct loop for small frames — avoids big-int allocation overhead
            for i in range(dl):
                out[i] = data[i] ^ ek[i]
        else:
            # Big-int XOR per 64KB chunk for large frames (C-level bulk operation)
            for off in range(0, dl, CHUNK_SIZE):
                cs = min(CHUNK_SIZE, dl - off)
                chunk = data[off:off + cs]
                ks = ek if cs == CHUNK_SIZE else ek[:cs]
                r = int.from_bytes(chunk, 'big', signed=False) ^ int.from_bytes(ks, 'big', signed=False)
                out[off:off + cs] = r.to_bytes(cs, 'big')
        return out


@dataclass
class Config:
    proxy_host: str
    proxy_port: int
    user_agent: str
    dns_info: str
    upstream: Optional[str] = None
    fakehost: Optional[str] = None
    crypto: Optional[Crypto] = None
    buffer_size: int = 65536
    stream_limit: int = 1048576
    drain_threshold: int = 262144
    tcp_nodelay: bool = True
    tcp_keepalive: bool = True
    socket_buffer: int = 0
    connection_timeout: int = 300
    ssl_verify: bool = False
    max_connections: int = 1000  # [Security] DoS Protection
    block_local: bool = False
    allow_open: bool = False
    ssl_context_verified: Optional[ssl.SSLContext] = None
    ssl_context_unverified: Optional[ssl.SSLContext] = None
    resolver: Optional['RemoteResolver'] = None


class RemoteResolver:
    """DNS resolver using a remote server via UDP with TCP fallback."""

    def __init__(self, server_ip: str):
        self.server_ip = server_ip
        self.timeout = 5.0

    def _build_query(self, hostname: str) -> bytes:
        """Build a DNS A record query packet."""
        header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
        question = b''
        for part in hostname.split('.'):
            question += bytes([len(part)]) + part.encode()
        question += b'\x00' + struct.pack('!HH', 1, 1)  # A record, IN class
        return header + question

    def _parse_response(self, data: bytes) -> Optional[str]:
        """Parse DNS response and extract first A record IP."""
        if len(data) < 12:
            return None
        qdcount = struct.unpack('!H', data[4:6])[0]
        ancount = struct.unpack('!H', data[6:8])[0]
        offset = 12
        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 5  # null + type(2) + class(2)
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
        """Resolve hostname via remote DNS. Returns IP or original host on failure."""
        import ipaddress
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass

        loop = asyncio.get_event_loop()
        query = self._build_query(host)

        # Try UDP
        try:
            ip = await loop.run_in_executor(None, self._query_udp, query)
            if ip:
                logger.info("[DNS] %s -> %s (remote: %s)", host, ip, self.server_ip)
                return ip
        except Exception as e:
            logger.warning("[DNS] Remote UDP lookup failed for %s: %s, trying TCP", host, e)

        # Try TCP
        try:
            ip = await loop.run_in_executor(None, self._query_tcp, query)
            if ip:
                logger.info("[DNS] %s -> %s (remote TCP: %s)", host, ip, self.server_ip)
                return ip
        except Exception as e:
            logger.warning("[DNS] Remote TCP lookup failed for %s: %s", host, e)

        # Fallback to system DNS
        logger.warning("[DNS] Remote lookup failed for %s, falling back to system DNS", host)
        try:
            addrs = await loop.run_in_executor(None, socket.gethostbyname, host)
            logger.info("[DNS] %s -> %s (system fallback)", host, addrs)
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
        if 65 <= b <= 90:  # A-Z → a-z
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
    # Fast rejection: most public hostnames start with a-z (not 0-1, l/L, [, :)
    if not host or host[0] not in b"10lL[":
        return False
    h = host.lower()
    if h in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"):
        return True
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
    # [Security] Prevent Header Injection
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
            # Small frame fast path: direct byte XOR (avoids int.from_bytes overhead)
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
    # Unmasked: single allocation for header + data
    total = len(hdr) + dl
    frame = bytearray(total)
    frame[:len(hdr)] = hdr
    frame[len(hdr):] = data
    return frame


def write_ws_frame_direct(writer: asyncio.StreamWriter, data: bytes,
                           opcode: int = 0x2, masked: bool = False) -> None:
    """Write a WebSocket frame avoiding header+data concatenation copy."""
    header = get_ws_header(len(data), opcode, masked)
    if masked:
        writer.write(create_ws_frame(data, opcode, masked=True))
    else:
        writer.write(header)  # bytearray is bytes-like, no copy needed
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
                # Only copy to bytearray when unmasking is needed
                payload = bytearray(payload)
                for off in range(0, payload_len, CHUNK_SIZE):
                    cs = min(CHUNK_SIZE, payload_len - off)
                    chunk = payload[off:off + cs]
                    ks = (masking_key * (cs // 4 + 1))[:cs]
                    r = int.from_bytes(chunk, 'big') ^ int.from_bytes(ks, 'big')
                    payload[off:off + cs] = r.to_bytes(cs, 'big')

            if opcode in [0x0, 0x1, 0x2]:  # Text, Binary, Continuation
                return payload
            elif opcode == 0x9:  # Ping — pong flushed with next data drain
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


async def connect_to_upstream(target: str, config: Config) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    upstream_parts = urllib.parse.urlparse(config.upstream)
    server_host = upstream_parts.hostname
    server_port = upstream_parts.port

    # Retry/Fallback parsing for certain formats
    if not server_host:
        try:
            clean_up = config.upstream
            if "://" not in clean_up:
                if clean_up.lower().startswith("ws:"): clean_up = "ws://" + clean_up[3:]
                elif clean_up.lower().startswith("wss:"): clean_up = "wss://" + clean_up[4:]
            p2 = urllib.parse.urlparse(clean_up)
            server_host = p2.hostname
            server_port = p2.port
            upstream_parts = p2
        except: pass

    if not server_host:
        raise ValueError(f"Invalid upstream: {config.upstream}")

    use_ssl = (upstream_parts.scheme in ['wss', 'https'])
    if not server_port:
        server_port = 443 if use_ssl else 80
    if server_port == 443:
        use_ssl = True

    ssl_context = None
    if use_ssl:
        ssl_context = config.ssl_context_verified if config.ssl_verify else config.ssl_context_unverified

    # Remote DNS resolution for upstream host
    dial_host = server_host
    if config.resolver:
        try:
            dial_host = await config.resolver.resolve(server_host)
        except OSError as e:
            logger.error("[DNS] Failed to resolve upstream %s: %s", server_host, e)

    logger.debug("Connecting to upstream %s:%s (SSL: %s)", dial_host, server_port, use_ssl)

    sni_hostname = sanitize_header(config.fakehost.split(':')[0] if config.fakehost else server_host)

    server_reader, server_writer = await asyncio.open_connection(
        dial_host, server_port,
        limit=config.stream_limit,
        ssl=ssl_context,
        server_hostname=sni_hostname if use_ssl else None
    )

    optimize_socket(server_writer, config, "WebSocket Tunnel")

    handshake_host = config.fakehost if config.fakehost else (
        server_host if (use_ssl and server_port == 443) or (not use_ssl and server_port == 80)
        else f"{server_host}:{server_port}"
    )

    handshake_path = upstream_parts.path or "/"
    ws_key = base64.b64encode(random.randbytes(16)).decode()
    protocol_scheme = "https" if use_ssl else "http"

    # [Security] Sanitize inputs
    handshake_host = sanitize_header(handshake_host)
    safe_user_agent = sanitize_header(config.user_agent)

    # Randomize header order to avoid fixed fingerprint
    accept_lang = random.choice(_ACCEPT_LANG_POOL)
    accept_enc = "gzip, deflate, br, zstd"
    sec_fetch = "websocket"

    # Build handshake as bytes directly (avoids f-string allocs)
    remaining = [
        b"Host: " + handshake_host.encode(),
        b"Connection: Upgrade",
        b"Pragma: no-cache",
        b"Cache-Control: no-cache",
        b"User-Agent: " + safe_user_agent.encode(),
        b"Upgrade: websocket",
        b"Origin: " + protocol_scheme.encode() + b"://" + sni_hostname.encode(),
        b"Sec-WebSocket-Version: 13",
        b"Sec-WebSocket-Key: " + ws_key.encode(),
        b"Accept-Language: " + accept_lang.encode(),
        b"Accept-Encoding: " + accept_enc.encode(),
        b"Sec-Fetch-Dest: " + sec_fetch.encode(),
        b"Sec-Fetch-Mode: websocket",
        b"Sec-Fetch-Site: cross-site",
    ]
    # Randomly include permessage-deflate extension (~67% chance) to reduce fingerprint
    if random.random() < 0.67:
        remaining.append(b"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits")
    random.shuffle(remaining)
    handshake = b"GET " + handshake_path.encode() + b" HTTP/1.1\r\n" + b"\r\n".join(remaining) + b"\r\n\r\n"

    server_writer.write(handshake)
    await server_writer.drain()

    try:
        response_data = await asyncio.wait_for(server_reader.readuntil(CRLFCRLF), timeout=10.0)
    except asyncio.TimeoutError:
        raise ConnectionError("Upstream handshake timed out")
    except asyncio.LimitOverrunError:
        raise ConnectionError("Upstream header too large (DoS protection)")

    if b"HTTP/1.1 101" not in response_data and b"HTTP/1.0 101" not in response_data:
        raise ConnectionError(f"Handshake failed: {response_data.decode(errors='ignore')[:100]}")

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


# [Security] Semaphore for DoS protection
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
        # [Security] LimitOverrunError catch for header size abuse
        try:
            data = await reader.readuntil(CRLFCRLF)
        except asyncio.LimitOverrunError:
            logger.warning("[Security] Header too large, dropping connection.")
            return

        idx = _ifind(data, b'sec-websocket-key:')
        ws_key_line = None
        if idx >= 0:
            end = data.find(CRLF, idx)
            if end < 0:
                end = len(data)
            ws_key_line = data[idx:end]

        if not ws_key_line:
            writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            await writer.drain()
            return

        key_val = ws_key_line.split(b':', 1)[1].strip()
        accept_key = base64.b64encode(hashlib.sha1(key_val + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept_key + CRLFCRLF
        )
        await writer.drain()

        # Raise read buffer limit from 8KB (handshake) to data-plane size
        reader._limit = config.stream_limit

        auth_data = await read_ws_frame(reader)
        if auth_data is None:
            return

        # [Security] Auth Check
        if config.crypto:
            auth_data = config.crypto.transform(auth_data)

        if not auth_data:
            logger.warning("[Security] Empty auth data from %s", writer.get_extra_info('peername'))
            return

        # Parse target directly from bytes (avoids full decode + strip)
        # auth_data format: "host:port\n" + random padding spaces
        target_end = len(auth_data)
        for i in range(len(auth_data)):
            if auth_data[i] <= 32:
                target_end = i
                break
        try:
            target_str = bytes(auth_data[:target_end]).decode()
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
        # Force IPv4 to prevent IPv6 routing issues on some VPS
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
    if ver != 5 or cmd != 1:
        raise ConnectionError("Invalid SOCKS5")

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
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            await writer.drain()
            return

        if is_socks5:
            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
        elif not full_initial_request:
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
        else:
            server_writer.write(create_ws_frame(full_initial_request, opcode=0x2, masked=True))
            await server_writer.drain()

        # Raise local reader buffer limit from 8KB to data-plane size
        reader._limit = config.stream_limit

        await ws_forward(server_reader, server_writer, reader, writer, client_side=True, config=config)
    finally:
        await safe_close_streamwriter(server_writer)


async def monitor_stats():
    last_up = 0
    last_down = 0
    try:
        while True:
            await asyncio.sleep(3)
            current_up = stats.bytes_up
            current_down = stats.bytes_down

            up_speed = (current_up - last_up) / 3 / 1024 / 1024
            down_speed = (current_down - last_down) / 3 / 1024 / 1024

            last_up = current_up
            last_down = current_down

            msg = (f"\r{ANSI_GREY}[STATS] Conns: {stats.active_conns} | "
                   f"Up: {up_speed:.2f} MB/s | Down: {down_speed:.2f} MB/s{ANSI_RESET}")
            sys.stdout.write(msg)
            sys.stdout.flush()
    except asyncio.CancelledError:
        pass


async def main_async(config: Config):
    global conn_semaphore
    conn_semaphore = asyncio.Semaphore(config.max_connections)

    loop = asyncio.get_running_loop()
    loop.set_exception_handler(custom_exception_handler)
    handler = handle_server if config.upstream is None else handle_client

    asyncio.create_task(monitor_stats())

    try:
        server = await asyncio.start_server(
            lambda r, w: handler(r, w, config),
            config.proxy_host, config.proxy_port,
            limit=MAX_HEADER_SIZE
        )
    except OSError as e:
        logger.error("Could not bind to %s:%s - %s", config.proxy_host, config.proxy_port, e)
        sys.exit(1)

    addrs = ', '.join(str(s.getsockname()) for s in server.sockets)
    mode = "Server" if not config.upstream else "Client (HTTP + SOCKS5)"

    print(f"{ANSI_CYAN}PYWAY v{VERSION}{ANSI_RESET}")
    print(f"{ANSI_CYAN}{'-'*60}{ANSI_RESET}")
    print(f" [+] Mode:        {ANSI_GREEN}{mode}{ANSI_RESET}")
    print(f" [+] Listen:      {ANSI_YELLOW}{addrs}{ANSI_RESET}")
    if config.upstream:
        print(f" [+] Upstream:    {ANSI_MAGENTA}{config.upstream}{ANSI_RESET}")
        verify_str = "Enabled" if config.ssl_verify else "Disabled (Insecure)"
        verify_col = ANSI_GREEN if config.ssl_verify else ANSI_RED
        print(f" [+] SSL Verify:  {verify_col}{verify_str}{ANSI_RESET}")
        print(f" [+] User-Agent:  {ANSI_GREEN}Randomized (Sticky){ANSI_RESET}")

    dns_col = ANSI_GREEN if ("aiodns" in config.dns_info or "Remote" in config.dns_info) else ANSI_YELLOW
    print(f" [+] DNS:         {dns_col}{config.dns_info}{ANSI_RESET}")

    if config.crypto:
        auth_str = "Enabled (XOR)"
        auth_color = ANSI_GREEN
    elif config.upstream is None:
        auth_str = "DISABLED (--allow-open enabled — Open Proxy!)"
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

    async with server:
        while True:
            await asyncio.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=f"Pyway {VERSION}")
    parser.add_argument('-p', required=True, help="Listen Address (e.g. :8080)")
    parser.add_argument('-up', help="Upstream WebSocket URL")
    parser.add_argument('-k', help="Authentication Key")
    parser.add_argument('-log', default='INFO', help="Log Level")
    parser.add_argument('-fakehost', help="Spoofing Hostname")
    parser.add_argument('-W', type=int, help="App Buffer Size in KB")
    parser.add_argument('--no-tcp-nodelay', action='store_true', help="Disable TCP_NODELAY")
    parser.add_argument('--no-tcp-keepalive', action='store_true', help="Disable TCP KeepAlive")
    parser.add_argument('--socket-buffer', type=int, default=0, help="Kernel Socket Buffer")
    parser.add_argument('--connection-timeout', type=int, default=300, help="Connection Timeout")
    parser.add_argument('--verify-ssl', action='store_true', help="Enable SSL Verification")
    parser.add_argument('--max-conn', type=int, default=1000, help="Max Concurrent Connections")
    parser.add_argument('--block-local', action='store_true', help="Drop local/LAN traffic (Client mode)")
    parser.add_argument('--allow-open', action='store_true', help="Allow server mode without authentication key")
    parser.add_argument('-dns', help="Remote DNS server IP (e.g. 8.8.8.8)")

    args = parser.parse_args()
    logger.setLevel(getattr(logging, args.log.upper()))

    buf = (args.W * 1024) if args.W else 65536

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

    sticky_ua = random.choice(_UA_POOL)

    # [Fix] stream_limit must accommodate MAX_WS_FRAME_SIZE
    stream_limit = max(buf * 4, MAX_WS_FRAME_SIZE + 65536)

    # Pre-create SSL contexts (avoid per-connection overhead)
    ssl_ctx_verified = ssl.create_default_context()
    ssl_ctx_verified.check_hostname = True
    ssl_ctx_verified.verify_mode = ssl.CERT_REQUIRED

    ssl_ctx_unverified = ssl.create_default_context()
    ssl_ctx_unverified.check_hostname = False
    ssl_ctx_unverified.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, 'TLSVersion'):
        ssl_ctx_unverified.minimum_version = ssl.TLSVersion.TLSv1_2

    config = Config(
        proxy_host=args.p.rsplit(':', 1)[0] or '0.0.0.0',
        proxy_port=int(args.p.rsplit(':', 1)[1]),
        upstream=args.up, fakehost=args.fakehost, crypto=crypto_obj,
        user_agent=sticky_ua,
        dns_info=dns_info, resolver=resolver,
        buffer_size=buf, stream_limit=stream_limit, drain_threshold=buf*4,
        tcp_nodelay=not args.no_tcp_nodelay, tcp_keepalive=not args.no_tcp_keepalive,
        socket_buffer=args.socket_buffer, connection_timeout=args.connection_timeout,
        ssl_verify=args.verify_ssl,
        max_connections=args.max_conn,
        block_local=args.block_local,
        allow_open=args.allow_open,
        ssl_context_verified=ssl_ctx_verified,
        ssl_context_unverified=ssl_ctx_unverified,
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


if __name__ == "__main__":
    main()
