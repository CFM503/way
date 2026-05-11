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

VERSION = "2.6.4G"
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
        self.lock = asyncio.Lock()

    async def add_conn(self):
        async with self.lock:
            self.active_conns += 1

    async def remove_conn(self):
        async with self.lock:
            self.active_conns -= 1

    def add_bytes(self, up=0, down=0):
        # Acceptable drift for display purposes — lock would hurt throughput
        if up: self.bytes_up += up
        if down: self.bytes_down += down


stats = Statistics()


class Crypto:
    def __init__(self, key: str):
        self.key_bytes = hashlib.sha256(key.encode()).digest()
        self.key_len = len(self.key_bytes)

    def transform(self, data: bytes) -> bytes:
        if not data:
            return data
        return bytes(b ^ self.key_bytes[i % self.key_len] for i, b in enumerate(data))


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

    logger.debug(f"Loop exception: {context}")


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
        logger.debug(f"[{connection_type}] Socket optimization error: {e}")


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
    header = bytearray()
    fin_bit = 0b10000000
    header.append(fin_bit | opcode)

    mask_bit = 128 if masked else 0

    if data_len < 126:
        header.append(data_len | mask_bit)
    elif data_len < 65536:
        header.append(126 | mask_bit)
        header.extend(struct.pack('!H', data_len))
    else:
        header.append(127 | mask_bit)
        header.extend(struct.pack('!Q', data_len))
    return header


def create_ws_frame(data: bytes, opcode: int = 0x2, masked: bool = False) -> bytes:
    header = get_ws_header(len(data), opcode, masked)

    if masked:
        mask_int = random.getrandbits(32)
        masking_key = mask_int.to_bytes(4, 'big')
        header.extend(masking_key)
        payload_arr = bytearray(data)
        for i in range(len(data)):
            payload_arr[i] ^= masking_key[i % 4]
        return bytes(header) + payload_arr

    return bytes(header) + data


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
                logger.error(f"Frame too large: {payload_len}")
                return None

            masking_key = await reader.readexactly(4) if masked else None
            payload = await reader.readexactly(payload_len)

            if masked and masking_key:
                payload = bytes(payload[i] ^ masking_key[i % 4] for i in range(payload_len))

            if opcode in [0x0, 0x1, 0x2]:  # Text, Binary, Continuation
                return payload
            elif opcode == 0x9:  # Ping
                if writer and not writer.is_closing():
                    writer.write(create_ws_frame(payload, opcode=0xA, masked=True))
                    await writer.drain()
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
        logger.debug(f"Read frame error: {e}")
        return None


async def ws_forward(ws_reader: asyncio.StreamReader, ws_writer: asyncio.StreamWriter,
                      tcp_reader: asyncio.StreamReader, tcp_writer: asyncio.StreamWriter,
                      client_side: bool, config: Config):

    await stats.add_conn()

    async def transfer(reader, writer, is_ws_out: bool):
        pending = 0
        try:
            while True:
                if is_ws_out:
                    # TCP -> WebSocket
                    try:
                        data = await asyncio.wait_for(reader.read(config.buffer_size), timeout=config.connection_timeout)
                    except asyncio.TimeoutError:
                        break  # Idle connection timeout
                    if not data: break
                    if writer.is_closing(): break

                    should_mask = client_side

                    if not should_mask:
                        header = get_ws_header(len(data), opcode=0x2, masked=False)
                        writer.write(header)
                        writer.write(data)
                    else:
                        writer.write(create_ws_frame(data, opcode=0x2, masked=True))

                    if client_side:
                        stats.add_bytes(up=len(data))
                    else:
                        stats.add_bytes(down=len(data))

                else:
                    # WebSocket -> TCP
                    try:
                        data = await asyncio.wait_for(read_ws_frame(reader, writer=writer), timeout=config.connection_timeout)
                    except asyncio.TimeoutError:
                        break  # Idle connection timeout
                    if data is None or writer.is_closing(): break
                    if not data: continue
                    writer.write(data)

                    if client_side:
                        stats.add_bytes(down=len(data))
                    else:
                        stats.add_bytes(up=len(data))

                pending += len(data)

                if pending >= config.drain_threshold:
                    await writer.drain()
                    pending = 0
        except Exception:
            pass
        finally:
            try:
                if pending > 0 and not writer.is_closing():
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
            except: pass

    task_ws_to_tcp = asyncio.create_task(transfer(ws_reader, tcp_writer, is_ws_out=False))
    task_tcp_to_ws = asyncio.create_task(transfer(tcp_reader, ws_writer, is_ws_out=True))

    try:
        done, pending = await asyncio.wait(
            [task_ws_to_tcp, task_tcp_to_ws],
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    finally:
        await stats.remove_conn()
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
        ssl_context = ssl.create_default_context()
        if not config.ssl_verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            if hasattr(ssl, 'TLSVersion'):
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED

    logger.debug(f"Connecting to upstream {server_host}:{server_port} (SSL: {use_ssl})")

    sni_hostname = sanitize_header(config.fakehost.split(':')[0] if config.fakehost else server_host)

    server_reader, server_writer = await asyncio.open_connection(
        server_host, server_port,
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
    ws_key = base64.b64encode(os.urandom(16)).decode()
    protocol_scheme = "https" if use_ssl else "http"

    # [Security] Sanitize inputs
    handshake_host = sanitize_header(handshake_host)
    safe_user_agent = sanitize_header(config.user_agent)

    # Randomize header order to avoid fixed fingerprint
    accept_lang = random.choice([
        "en-US,en;q=0.9",
        "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "en-GB,en;q=0.9,en-US;q=0.8",
        "zh-CN,zh;q=0.9,en;q=0.8",
        "en-US,en;q=0.9,ja;q=0.8",
    ])
    accept_enc = "gzip, deflate, br, zstd"
    sec_fetch = "websocket"

    # Build handshake with randomized header order
    handshake = f"GET {handshake_path} HTTP/1.1\r\n"
    remaining = [
        f"Host: {handshake_host}",
        f"Connection: Upgrade",
        f"Pragma: no-cache",
        f"Cache-Control: no-cache",
        f"User-Agent: {safe_user_agent}",
        f"Upgrade: websocket",
        f"Origin: {protocol_scheme}://{sni_hostname}",
        f"Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Key: {ws_key}",
        f"Accept-Language: {accept_lang}",
        f"Accept-Encoding: {accept_enc}",
        f"Sec-Fetch-Dest: {sec_fetch}",
        f"Sec-Fetch-Mode: websocket",
        f"Sec-Fetch-Site: cross-site",
    ]
    # Randomly include permessage-deflate extension (~67% chance) to reduce fingerprint
    if random.random() < 0.67:
        remaining.append(f"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits")
    random.shuffle(remaining)
    for h in remaining:
        handshake += h + "\r\n"
    handshake += "\r\n"
    handshake = handshake.encode()

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

    payload = bytearray(f"{target}\n".encode())
    payload.extend(b' ' * random.randint(1, 40))

    if config.crypto:
        payload = config.crypto.transform(bytes(payload))
    server_writer.write(create_ws_frame(bytes(payload), opcode=0x2, masked=True))
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
        try:
            await asyncio.wait_for(conn_semaphore.acquire(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning(f"Max connections reached. Dropping {writer.get_extra_info('peername')}")
            writer.close()
            return

    try:
        await asyncio.wait_for(
            _handle_server_impl(reader, writer, config),
            timeout=config.connection_timeout
        )
    except Exception as e:
        logger.debug(f"Server handler error: {e}")
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

        headers = data.lower().split(CRLF)
        ws_key_line = next((h for h in headers if h.startswith(b'sec-websocket-key:')), None)

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

        auth_data = await read_ws_frame(reader)
        if auth_data is None:
            return

        # [Security] Auth Check
        if config.crypto:
            auth_data = config.crypto.transform(auth_data)

        if not auth_data:
            logger.warning(f"[Security] Empty auth data from {writer.get_extra_info('peername')}")
            return

        clean_auth = auth_data.decode(errors='ignore').strip()

        # [Fix] IPv6 Support
        try:
            target_str = clean_auth.split(maxsplit=1)[0]
            target_host, target_port = parse_host_port(target_str)
        except Exception:
            logger.warning(f"[Security] Malformed target format: {clean_auth[:50]}")
            return

        logger.info(f"[SERVER] Connect -> {target_host}:{target_port}")
        # Force IPv4 to prevent IPv6 routing issues on some VPS
        target_reader, target_writer = await asyncio.open_connection(
            target_host, int(target_port), limit=config.stream_limit, family=socket.AF_INET
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
        try:
            await asyncio.wait_for(conn_semaphore.acquire(), timeout=5.0)
        except asyncio.TimeoutError:
            writer.close()
            return

    peername = writer.get_extra_info('peername')
    logger.info(f"[CLIENT] Connection from {peername}")
    try:
        await asyncio.wait_for(
            _handle_client_impl(reader, writer, config),
            timeout=config.connection_timeout
        )
    except Exception as e:
        logger.debug(f"Client handler error: {e}")
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
            logger.info(f"[CLIENT] SOCKS5 -> {target_host}:{target_port}")
        elif initial_byte == b'\x16':
            logger.error(f"[CLIENT] HTTPS Handshake detected! Please use HTTP/SOCKS5 proxy.")
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
                logger.info(f"[CLIENT] {method} {target}")
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
                    for line in headers.decode(errors='ignore').split('\r\n'):
                        if line.lower().startswith('host:'):
                            h = line.split(':', 1)[1].strip()
                            target_host, target_port = parse_host_port(h)
                            break

        if not target_host:
            return

        if config.block_local and is_local_target(target_host):
            logger.warning(f"[CLIENT] Blocked local traffic attempt: {target_host}:{target_port}")
            return

        try:
            server_reader, server_writer = await asyncio.wait_for(
                connect_to_upstream(f"{target_host}:{target_port}", config), timeout=30.0
            )
        except Exception as e:
            logger.error(f"[CLIENT] Upstream Fail: {e}")
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
        logger.error(f"Could not bind to {config.proxy_host}:{config.proxy_port} - {e}")
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

    dns_col = ANSI_GREEN if "aiodns" in config.dns_info else ANSI_YELLOW
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

    try:
        import aiodns
        dns_info = "aiodns (Async)"
    except ImportError:
        dns_info = "System (Default)"

    crypto_obj = Crypto(args.k) if args.k else None

    ua_pool = [
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
    sticky_ua = random.choice(ua_pool)

    # [Fix] stream_limit must accommodate MAX_WS_FRAME_SIZE
    stream_limit = max(buf * 16, MAX_WS_FRAME_SIZE + 1048576)

    config = Config(
        proxy_host=args.p.rsplit(':', 1)[0] or '0.0.0.0',
        proxy_port=int(args.p.rsplit(':', 1)[1]),
        upstream=args.up, fakehost=args.fakehost, crypto=crypto_obj,
        user_agent=sticky_ua,
        dns_info=dns_info,
        buffer_size=buf, stream_limit=stream_limit, drain_threshold=buf*4,
        tcp_nodelay=not args.no_tcp_nodelay, tcp_keepalive=not args.no_tcp_keepalive,
        socket_buffer=args.socket_buffer, connection_timeout=args.connection_timeout,
        ssl_verify=args.verify_ssl,
        max_connections=args.max_conn,
        block_local=args.block_local,
        allow_open=args.allow_open,
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
