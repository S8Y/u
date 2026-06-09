"""
PAC-API Transport Layer — intercepts TCP connections and routes them
through SOCKS5 proxies managed by the ProxyManager.

Strategy:
  - Replace `socket.create_connection` → all sync HTTP libraries that
    use standard Python sockets (httpx, requests, urllib3, etc.) go
    through this function.
  - Replace `socket.socket` with a wrapper that uses PySocks for
    TCP connections to non-local destinations.
  - Async: patch asyncio's event loop `create_connection` so that
    aiohttp / httpx async / anyio async paths are also proxied.

On connection failure the ProxyManager's retry logic kicks in:
  - Try up to 3 different SOCKS5 proxies
  - Blacklist failed proxies for 24h
  - Fall back to direct (unproxied) connection
"""

import asyncio
import logging
import socket as _socket
import socks as _socks
import threading
from typing import Optional, Callable


def _has_colon(s: str) -> bool:
    """Return True if *s* looks like an IPv6 address (contains ':').

    Used to distinguish hostnames from already-resolved IPv6 addresses
    so we can force IPv4 resolution for hostnames before the SOCKS5
    handshake."""
    return ":" in s

try:
    from .proxy_manager import ProxyManager, should_bypass
except ImportError:
    from proxy_manager import ProxyManager, should_bypass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_proxy_manager: Optional[ProxyManager] = None
_patched = False
_patch_lock = threading.Lock()

# Saved originals for unpatching
_original_socket = _socket.socket
_original_create_connection = _socket.create_connection
_original_getaddrinfo = _socket.getaddrinfo


def _pac_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """Patched getaddrinfo that filters out IPv6 (AF_INET6) results.

    Mullvad SOCKS5 relays do not support IPv6 destinations. By forcing
    IPv4 DNS resolution at the lowest level, every connection path
    (sync, async, socket.socket, loop.create_connection, loop.sock_connect)
    receives IPv4 addresses and can be proxied successfully.

    If no IPv4 records exist, falls back to the original (which may
    return IPv6 addresses — these will bypass the proxy via should_bypass).
    """
    results = _original_getaddrinfo(host, port, family, type, proto, flags)
    ipv4 = [r for r in results if r[0] == _socket.AF_INET]
    if ipv4:
        return ipv4
    return results


# ---------------------------------------------------------------------------
# create_connection replacement (sync)
# ---------------------------------------------------------------------------


def _pac_create_connection(
    address,
    timeout=_socket._GLOBAL_DEFAULT_TIMEOUT,
    source_address=None,
    *,
    all_errors: bool = False,
):
    """
    Replacement for socket.create_connection.

    For non-local destinations, attempts SOCKS5 proxy connection through
    the ProxyManager with retry logic. Falls back to direct connection
    if all proxies fail.
    """
    host, port = address

    # Local / messenger destinations -> direct, no proxy
    if should_bypass(host):
        return _original_create_connection(
            address, timeout, source_address, all_errors=all_errors
        )

    pm = _proxy_manager
    if pm is None or not pm:
        return _original_create_connection(
            address, timeout, source_address, all_errors=all_errors
        )

    # Retry through ProxyManager
    return pm.send_with_retry(
        host=host,
        port=port,
        connect_fn=_socks_connect,
        timeout=timeout,
        source_address=source_address,
        all_errors=all_errors,
    )


def _socks_connect(
    proxy,
    host: str,
    port: int,
    timeout=None,
    source_address=None,
    all_errors: bool = False,
):
    """
    Establish a TCP connection, optionally through a SOCKS5 proxy.

    If proxy is None, connects directly (fallback path).

    For SOCKS5 connections, hostnames are resolved to IPv4 addresses first
    because Mullvad SOCKS5 relays do not support IPv6 destinations.
    """
    if proxy is None:
        return _original_create_connection(
            (host, port),
            timeout=timeout if timeout is not None else _socket._GLOBAL_DEFAULT_TIMEOUT,
            source_address=source_address,
            all_errors=all_errors,
        )

    # Force IPv4 resolution: resolve hostname to an IPv4 address locally
    # so the SOCKS5 handshake sends an IPv4 address, not a hostname
    # or an IPv6 address (Mullvad relays don't support IPv6 destinations).
    connect_host = host
    if _has_colon(host) is False:
        # host is a hostname, not an IP — resolve to IPv4
        try:
            info = _socket.getaddrinfo(
                host, port, _socket.AF_INET, _socket.SOCK_STREAM
            )
            if info:
                connect_host = info[0][4][0]
        except Exception:
            pass  # fall back to original hostname
    # If host is an IPv6 address (contains ':'), it stays as-is and will
    # be bypassed by should_bypass before reaching send_with_retry.

    # SOCKS5 via PySocks
    sock = _socks.socksocket()
    sock.set_proxy(
        _socks.SOCKS5,
        proxy.host,
        proxy.port,
        username=proxy.username or None,
        password=proxy.password or None,
    )
    if timeout is not None and timeout is not _socket._GLOBAL_DEFAULT_TIMEOUT:
        sock.settimeout(timeout)
    sock.connect((connect_host, port))
    return sock


# ---------------------------------------------------------------------------
# socket.socket replacement (catches libraries that construct sockets
# directly instead of using create_connection)
# ---------------------------------------------------------------------------


class _PACAwareSocket:
    """
    Proxy-aware socket wrapper.

    For SOCK_STREAM TCP connections to non-local destinations, creates
    a PySocks SOCKS5 socket configured with the current proxy from
    ProxyManager. All other socket types (UDP, raw, etc.) pass through
    to the original socket class.
    """

    def __init__(self, family=_socket.AF_INET, type=_socket.SOCK_STREAM,
                 proto=0, fileno=None):
        self._family = family
        self._type = type
        self._proto = proto
        self._timeout = None
        self._blocking = True

        # Always start with a real socket; swap to SOCKS on connect
        # if conditions are right.
        if fileno is not None:
            self._sock = _original_socket(family, type, proto, fileno)
        else:
            self._sock = _original_socket(family, type, proto)
        self._socks_sock = None
        self._connected = False

    # ------------------------------------------------------------------
    # connect — the critical interception point
    # ------------------------------------------------------------------

    def connect(self, address):
        host, port = address

        # Only intercept TCP SOCK_STREAM to non-local / non-bypass destinations
        if (self._type == _socket.SOCK_STREAM
                and not should_bypass(host)
                and _proxy_manager is not None):
            try:
                self._socks_sock = _proxy_manager.send_with_retry(
                    host=host,
                    port=port,
                    connect_fn=_socks_connect_socket,
                    timeout=self._timeout,
                )
                self._connected = True
                return
            except Exception:
                # Fall through to direct socket if retries exhausted
                logger.exception(
                    "pac-api: SOCKS5 retry exhausted for %s:%s, using direct",
                    host, port,
                )

        self._sock.connect(address)
        self._connected = True

    def connect_ex(self, address):
        try:
            self.connect(address)
            return 0
        except (_socket.error, OSError) as e:
            return e.errno
        except Exception:
            return -1

    # ------------------------------------------------------------------
    # Delegated properties / methods
    # ------------------------------------------------------------------

    @property
    def _active_sock(self):
        return self._socks_sock if self._socks_sock is not None else self._sock

    def settimeout(self, timeout):
        self._timeout = timeout
        self._sock.settimeout(timeout)
        if self._socks_sock is not None:
            self._socks_sock.settimeout(timeout)

    def gettimeout(self):
        return self._timeout

    def setsockopt(self, *args, **kwargs):
        self._sock.setsockopt(*args, **kwargs)
        if self._socks_sock is not None:
            try:
                self._socks_sock.setsockopt(*args, **kwargs)
            except Exception:
                pass

    def fileno(self):
        return self._active_sock.fileno()

    def close(self):
        self._sock.close()
        if self._socks_sock is not None:
            try:
                self._socks_sock.close()
            except Exception:
                pass

    def detach(self):
        return self._active_sock.detach()

    def getsockname(self):
        return self._active_sock.getsockname()

    def getpeername(self):
        return self._active_sock.getpeername()

    def setblocking(self, flag):
        self._blocking = flag
        self._sock.setblocking(flag)
        if self._socks_sock is not None:
            self._socks_sock.setblocking(flag)

    def __getattr__(self, name):
        """Fallback: delegate all other attributes to the active socket."""
        return getattr(self._active_sock, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        return (
            f"<_PACAwareSocket {self._family=} {self._type=} "
            f"connected={self._connected}>"
        )


def _socks_connect_socket(proxy, host: str, port: int, timeout=None):
    """
    Create and connect a SOCKS5 socket through the given proxy.
    Returns the connected socks socket.

    Hostnames are resolved to IPv4 first (Mullvad relays don't support
    IPv6 destinations in the SOCKS5 handshake).
    """
    if proxy is None:
        sock = _original_socket()
        if timeout is not None:
            sock.settimeout(timeout)
        sock.connect((host, port))
        return sock

    # Force IPv4 resolution for hostnames (same as _socks_connect)
    connect_host = host
    if _has_colon(host) is False:
        try:
            info = _socket.getaddrinfo(
                host, port, _socket.AF_INET, _socket.SOCK_STREAM
            )
            if info:
                connect_host = info[0][4][0]
        except Exception:
            pass

    sock = _socks.socksocket()
    sock.set_proxy(
        _socks.SOCKS5,
        proxy.host,
        proxy.port,
        username=proxy.username or None,
        password=proxy.password or None,
    )
    if timeout is not None:
        sock.settimeout(timeout)
    sock.connect((connect_host, port))
    return sock


# ---------------------------------------------------------------------------
# asyncio event loop patching
# ---------------------------------------------------------------------------

_ORIGINAL_LOOP_CREATE_CONNECTION = asyncio.BaseEventLoop.create_connection
_ORIGINAL_LOOP_SOCK_CONNECT = asyncio.BaseEventLoop.sock_connect
_ORIGINAL_LOOP_GETADDRINFO = asyncio.BaseEventLoop.getaddrinfo


async def _patched_loop_getaddrinfo(
    self, host, port, *,
    family=0, type=0, proto=0, flags=0,
):
    """Patched event-loop getaddrinfo that filters out IPv6 results.

    anyio / httpcore use loop.getaddrinfo() to resolve hostnames before
    creating sockets.  By filtering out AF_INET6 results here, every
    async connection gets IPv4 addresses that work through Mullvad
    SOCKS5 relays (which don't support IPv6 destinations).
    """
    results = await _ORIGINAL_LOOP_GETADDRINFO(
        self, host, port,
        family=family, type=type, proto=proto, flags=flags,
    )
    ipv4 = [r for r in results if r[0] == _socket.AF_INET]
    if ipv4:
        return ipv4
    return results


async def _patched_create_connection(
    self,
    protocol_factory,
    host=None,
    port=None,
    *,
    family=0,
    proto=0,
    flags=0,
    sock=None,
    local_addr=None,
    server_hostname=None,
    **kwargs,
):
    """
    Wrapper for asyncio.BaseEventLoop.create_connection that routes
    TCP connections through our SOCKS5 proxy for non-local destinations.
    """
    # If no host/port or is a bypass destination (local / messenger), use original
    if host is None or port is None or should_bypass(host):
        return await _ORIGINAL_LOOP_CREATE_CONNECTION(
            self,
            protocol_factory,
            host=host,
            port=port,
            family=family,
            proto=proto,
            flags=flags,
            sock=sock,
            local_addr=local_addr,
            server_hostname=server_hostname,
            **kwargs,
        )

    pm = _proxy_manager
    if pm is None:
        return await _ORIGINAL_LOOP_CREATE_CONNECTION(
            self,
            protocol_factory,
            host=host,
            port=port,
            family=family,
            proto=proto,
            flags=flags,
            sock=sock,
            local_addr=local_addr,
            server_hostname=server_hostname,
            **kwargs,
        )

    # Try SOCKS5 proxy with retry
    proxy = pm.get_proxy()
    if proxy is None:
        return await _ORIGINAL_LOOP_CREATE_CONNECTION(
            self,
            protocol_factory,
            host=host,
            port=port,
            family=family,
            proto=proto,
            flags=flags,
            sock=sock,
            local_addr=local_addr,
            server_hostname=server_hostname,
            **kwargs,
        )

    # We use the sync socks_connect but offload it to a thread for the async loop
    # This is safe because SOCKS5 handshake is quick and we're in the connection phase.
    try:
        socks_sock = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: pm.send_with_retry(
                host=host,
                port=port,
                connect_fn=_socks_connect_socket,
                timeout=self._timer if hasattr(self, '_timer') else None,
            ),
        )
        # Now wrap the socks socket into the protocol
        # We set sock= to our proxied socket so the event loop uses it
        return await _ORIGINAL_LOOP_CREATE_CONNECTION(
            self,
            protocol_factory,
            host=None,
            port=None,
            family=family,
            proto=proto,
            flags=flags,
            sock=socks_sock,
            local_addr=local_addr,
            server_hostname=server_hostname,
            **kwargs,
        )
    except Exception as e:
        logger.warning(
            "pac-api: async SOCKS5 connect failed for %s:%s — falling back to direct: %s",
            host, port, e,
        )
        return await _ORIGINAL_LOOP_CREATE_CONNECTION(
            self,
            protocol_factory,
            host=host,
            port=port,
            family=family,
            proto=proto,
            flags=flags,
            sock=sock,
            local_addr=local_addr,
            server_hostname=server_hostname,
            **kwargs,
        )


async def _patched_sock_connect(
    self,
    sock,
    address,
):
    """
    Wrapper for asyncio.BaseEventLoop.sock_connect that routes TCP
    connections through our SOCKS5 proxy for non-local destinations.

    httpcore / anyio create sockets via socket.socket() then connect
    via loop.sock_connect, which calls sock.connect() internally.
    Our _PACAwareSocket.connect() intercepts that call, but
    _PACAwareSocket is not a real socket — it has no file descriptor.
    So we handle the proxy connection here and replace the sock's fd.
    """
    host, port = address if isinstance(address, tuple) else (address, 0)

    # Bypass for local/messenger destinations
    if should_bypass(host):
        return await _ORIGINAL_LOOP_SOCK_CONNECT(self, sock, address)

    pm = _proxy_manager
    if pm is None:
        return await _ORIGINAL_LOOP_SOCK_CONNECT(self, sock, address)

    # Check if this is a _PACAwareSocket (wrapper, not a real socket)
    is_fake = type(sock).__name__ == '_PACAwareSocket'

    if not is_fake:
        # Real socket — just do the original sock_connect
        return await _ORIGINAL_LOOP_SOCK_CONNECT(self, sock, address)

    # _PACAwareSocket — create the proxy connection and swap the fd
    try:
        socks_sock = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: _proxy_manager.send_with_retry(
                host=host,
                port=port,
                connect_fn=_socks_connect_socket,
            ),
        )
        # Detach the proxied socket's fd and attach it to the original
        # _PACAwareSocket so the event loop sees a real connected socket.
        fd = socks_sock.detach()
        # Now we need to make a REAL socket with this fd
        # and use that for the connection
        real_sock = _socket.socket(fileno=fd)
        return await _ORIGINAL_LOOP_SOCK_CONNECT(self, real_sock, (host, port))
    except Exception as e:
        logger.warning(
            "pac-api: sock_connect proxy failed for %s:%s — "
            "falling back to direct: %s",
            host, port, e,
        )
        return await _ORIGINAL_LOOP_SOCK_CONNECT(self, sock, address)


# ---------------------------------------------------------------------------
# Patch / unpatch
# ---------------------------------------------------------------------------


def patch(proxy_manager: ProxyManager) -> None:
    """
    Apply all monkey-patches to intercept TCP connections and route
    through the PAC-API ProxyManager.

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _proxy_manager, _patched

    with _patch_lock:
        if _patched:
            logger.debug("pac-api: transport already patched, skipping")
            return

        _proxy_manager = proxy_manager

        # 1. Patch socket.create_connection (catches sync httpx, requests, urllib3)
        _socket.create_connection = _pac_create_connection

        # 2. (removed — _PACAwareSocket breaks trio/anyio/httpcore)
        #    socket.create_connection + asyncio patches below cover all paths.

        # 3. Patch asyncio event loop create_connection (catches async paths)
        asyncio.BaseEventLoop.create_connection = _patched_create_connection

        # 4. Patch asyncio event loop sock_connect (catches httpcore/anyio)
        asyncio.BaseEventLoop.sock_connect = _patched_sock_connect

        # 5. Patch getaddrinfo to prefer IPv4 (Mullvad relays don't do IPv6)
        _socket.getaddrinfo = _pac_getaddrinfo
        asyncio.BaseEventLoop.getaddrinfo = _patched_loop_getaddrinfo

        _patched = True
        logger.info(
            "pac-api: transport patched — all outbound TCP connections "
            "will be routed through SOCKS5 proxy rotation"
        )


def unpatch() -> None:
    """
    Restore all original socket and asyncio functions.
    """
    global _proxy_manager, _patched

    with _patch_lock:
        if not _patched:
            return

        _socket.create_connection = _original_create_connection
        _socket.socket = _original_socket  # restore even though we don't patch it
        _socket.getaddrinfo = _original_getaddrinfo
        asyncio.BaseEventLoop.getaddrinfo = _ORIGINAL_LOOP_GETADDRINFO
        asyncio.BaseEventLoop.create_connection = _ORIGINAL_LOOP_CREATE_CONNECTION
        asyncio.BaseEventLoop.sock_connect = _ORIGINAL_LOOP_SOCK_CONNECT

        _patched = False
        _proxy_manager = None
        logger.info("pac-api: transport unpatched — connections restored to direct")


def is_patched() -> bool:
    return _patched
