"""
PAC-API Proxy Manager — core logic for proxy selection, rotation, and blacklisting.

Handles:
  - PAC file parsing (extract SOCKS5 proxies from FindProxyForURL)
  - Proxy rotation every 180 seconds (3 minutes)
  - Blacklist management (24-hour auto-clear)
  - Retry logic with fallback to direct connection
"""

import ipaddress
import json
import logging
import os
import random
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROXY_ROTATION_SECONDS = 180        # 3 minutes
BLACKLIST_CLEAR_SECONDS = 86400     # 24 hours
MAX_RETRIES = 3

PAC_URL_DEFAULT = (
    "https://raw.githubusercontent.com/S8Y/mullvad-pac/refs/heads/main/pac/mullvad.pac"
)
PAC_REFRESH_SECONDS = 43200         # 12 hours
PROXY_DISABLE_SECONDS = 300        # 5 min cooldown after consecutive failures

# Messenger / channel APIs that already have their own proxy config
# and MUST NOT be routed through our SOCKS5 pool.
NO_PROXY_DOMAINS: set[str] = {
    # Telegram
    "api.telegram.org", "t.me", "telegram.org",
    "telegram-cdn.org", "tdesktop.com",
    # Discord
    "discord.com", "discordapp.com", "discord.gg",
    "discord-media.com", "discordstatus.com",
    # Slack
    "slack.com", "slack-msgs.com", "slack-files.com",
    "slack-imgs.com", "slack-edge.com",
    # WhatsApp
    "whatsapp.com", "wa.me", "whatsapp.net",
    "whatsapp-cdn.net",
    # Signal
    "signal.org", "textsecure.signal.org",
    "signal.tube", "cdn.signal.org",
    # Matrix
    "matrix.org", "matrix-client.net",
    "modular.im",
    # Docker / local infra
    "host.docker.internal",
    "homeassistant.local",
    "homeassistant",
}

# Hardcoded fallback proxies used when PAC fetch fails entirely
_FALLBACK_PROXIES: list[tuple[str, int]] = [
    ("de-ber-wg-socks5-007.relays.mullvad.net", 1080),
    ("de-ber-wg-socks5-006.relays.mullvad.net", 1080),
    ("de-fra-wg-socks5-009.relays.mullvad.net", 1080),
    ("nl-ams-wg-socks5-004.relays.mullvad.net", 1080),
    ("se-sto-wg-socks5-003.relays.mullvad.net", 1080),
    ("gb-lon-wg-socks5-008.relays.mullvad.net", 1080),
    ("us-nyc-wg-socks5-005.relays.mullvad.net", 1080),
    ("us-lax-wg-socks5-002.relays.mullvad.net", 1080),
]

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Proxy:
    """A single SOCKS5 proxy entry parsed from a PAC file."""
    host: str
    port: int
    username: str = ""
    password: str = ""

    @property
    def addr(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username else ""
        return f"socks5://{auth}{self.host}:{self.port}"

    def __hash__(self):
        return hash(self.addr)

    def __eq__(self, other):
        if not isinstance(other, Proxy):
            return NotImplemented
        return self.host == other.host and self.port == other.port


ProxyList = list[Proxy]

# ---------------------------------------------------------------------------
# PAC file parser
# ---------------------------------------------------------------------------

# Regex to extract SOCKS5 proxy entries from the JS array in FindProxyForURL
_PROXY_RE = re.compile(
    r'"SOCKS5\s+([^"]+?)"', re.IGNORECASE
)
_PROXY_SPLIT_RE = re.compile(
    r"""SOCKS5[\s+](\S+)""", re.IGNORECASE
)


def parse_pac_proxies(pac_content: str) -> ProxyList:
    """
    Parse a PAC file's FindProxyForURL function and return a list of
    SOCKS5 Proxy objects.

    Handles both single-line and multi-line proxy arrays, with or without
    trailing commas and quotes.
    """
    proxies: ProxyList = []
    for match in _PROXY_RE.finditer(pac_content):
        raw = match.group(1).strip()
        parts = raw.rsplit(":", 1)
        if len(parts) == 2:
            try:
                port = int(parts[1])
                proxies.append(Proxy(host=parts[0], port=port))
            except ValueError:
                logger.warning("pac-api: invalid proxy entry %r — skipping", raw)
                continue

    # Fallback: try without quotes
    if not proxies:
        for match in _PROXY_SPLIT_RE.finditer(pac_content):
            raw = match.group(1).strip()
            raw = raw.strip('"').strip("'").strip(",")
            parts = raw.rsplit(":", 1)
            if len(parts) == 2:
                try:
                    port = int(parts[1])
                    proxies.append(Proxy(host=parts[0], port=port))
                except ValueError:
                    continue

    return proxies


# ---------------------------------------------------------------------------
# IP / hostname helpers
# ---------------------------------------------------------------------------

# Common non-routable / reserved hostname patterns
_LOCAL_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "0.0.0.0:0",
}

# Suffixes that indicate local network domains
_LOCAL_SUFFIXES = (
    ".local",
    ".localdomain",
    ".lan",
    ".internal",
    ".intranet",
    ".home",
)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_local_destination(host: str) -> bool:
    """
    Return True if the destination host is a local / private / reserved
    address that should NOT be routed through the SOCKS5 proxy.
    """
    if not host:
        return True

    host_lower = host.lower().strip()

    # Exact match local hostnames
    if host_lower in _LOCAL_HOSTNAMES:
        return True

    # Suffix match for mdns / zeroconf domains
    if host_lower.endswith(_LOCAL_SUFFIXES):
        return True

    # Dotted-quad IP or hostname
    if _is_ip(host_lower):
        try:
            addr = ipaddress.ip_address(host_lower)
            return (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_reserved
                or addr.is_unspecified
            )
        except ValueError:
            return False

    # Hostname: treat as public (not local)
    return False


def should_bypass(host: str) -> bool:
    """Standalone version of ProxyManager.should_bypass.

    Returns True if *host* should connect directly (bypass proxy):
      - Messenger API domains (Telegram, Discord, Slack, etc.)
      - Local / loopback / private IP ranges
      - Docker / container-internal hostnames
    """
    if not host:
        return True
    host_lower = host.lower().strip()

    # Exact match against NO_PROXY domains
    if host_lower in NO_PROXY_DOMAINS:
        return True

    # Subdomain match: e.g. "cdn.discord.com" ends with ".discord.com"
    for domain in NO_PROXY_DOMAINS:
        if host_lower.endswith("." + domain):
            return True

    # IP / local hostname check
    if is_local_destination(host_lower):
        return True

    # IPv6 addresses — Mullvad SOCKS5 proxies are IPv4-only and fail
    # with TTL expired for IPv6 destinations. Bypass to avoid filling
    # the blacklist with good proxies.
    if ":" in host_lower:
        return True

    return False


# ---------------------------------------------------------------------------
# ProxyManager — the main engine
# ---------------------------------------------------------------------------


class ProxyManager:
    """
    Thread-safe proxy manager that:

    - Holds a parsed proxy list from the PAC file
    - Selects one proxy per 3-minute window (rotation)
    - Maintains a blacklist of failed proxies (auto-cleared every 24h)
    - Provides retry logic: try up to MAX_RETRIES different proxies,
      then fall back to direct connection
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._proxies: ProxyList = []
        self._current_proxy: Optional[Proxy] = None
        self._current_proxy_index: int = -1
        self._proxy_switched_at: float = 0.0
        self._blacklist: dict[str, float] = {}  # proxy.addr -> timestamp when blacklisted
        self._last_blacklist_clear: float = time.time()
        self._pac_url: str = PAC_URL_DEFAULT
        self._pac_last_fetched: float = 0.0
        self._pac_content: str = ""
        self._enabled: bool = True
        # Consecutive-failure tracking (5-min proxy disable)
        self._consecutive_failures: int = 0
        self._proxy_disabled_until: float = 0.0

    # ------------------------------------------------------------------
    # Proxy management
    # ------------------------------------------------------------------

    def set_proxies(self, proxies: ProxyList) -> None:
        """Replace the proxy list and reset rotation state.

        Falls back to hardcoded Mullvad relays if the provided list is empty.
        """
        with self._lock:
            if not proxies:
                proxies = self._builtin_fallback_proxies()
                logger.info(
                    "pac-api: using %d built-in fallback proxies",
                    len(proxies),
                )
            self._proxies = proxies
            self._current_proxy = None
            self._current_proxy_index = -1
            self._proxy_switched_at = 0.0
            # Reset failure state — new proxy list is a fresh start
            self._blacklist.clear()
            self._consecutive_failures = 0
            self._proxy_disabled_until = 0.0
            logger.info(
                "pac-api: loaded %d proxies from PAC file", len(proxies)
            )

    def get_proxies(self) -> ProxyList:
        with self._lock:
            return list(self._proxies)

    def get_proxy(self) -> Optional[Proxy]:
        """
        Return the current active proxy.

        Rotates to a new random proxy if the current window has expired
        (every PROXY_ROTATION_SECONDS). Returns None if no proxies are
        available.
        """
        with self._lock:
            return self._get_proxy_locked()

    def _extract_host(self, proxy: Optional[Proxy]) -> str:
        """Human-readable hostname from proxy (for logging)."""
        if proxy is None:
            return "none"
        return proxy.host

    @staticmethod
    def _builtin_fallback_proxies() -> ProxyList:
        """Return hardcoded Mullvad relays when PAC fetch fails."""
        return [
            Proxy(host=host, port=port)
            for host, port in _FALLBACK_PROXIES
        ]

    def should_bypass(self, host: str) -> bool:
        """Return True if *host* should bypass the proxy entirely.

        Delegates to the standalone :func:`should_bypass` which checks
        NO_PROXY domains, subdomain matches, and local IP ranges.
        """
        return should_bypass(host)

    def _set_proxy_env(self, proxy: Proxy) -> None:
        """Set ALL_PROXY + variants so subprocesses also use the proxy."""
        proxy_url = proxy.url
        no_proxy_val = ",".join(sorted(NO_PROXY_DOMAINS))
        for key in (
            "ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY",
            "all_proxy", "https_proxy", "http_proxy",
        ):
            os.environ[key] = proxy_url
        os.environ["NO_PROXY"] = no_proxy_val
        os.environ["no_proxy"] = no_proxy_val

    def _clear_proxy_env(self) -> None:
        """Remove all proxy env vars (revert to direct connection)."""
        for key in (
            "ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY",
            "all_proxy", "https_proxy", "http_proxy",
            "NO_PROXY", "no_proxy",
        ):
            os.environ.pop(key, None)

    def reset_failure_state(self) -> None:
        """Called after a successful request to decrement the fail counter."""
        with self._lock:
            self._consecutive_failures = max(
                0, self._consecutive_failures - 1
            )
            if self._consecutive_failures == 0:
                self._proxy_disabled_until = 0.0

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._consecutive_failures

    @property
    def is_disabled(self) -> bool:
        return self._proxy_disabled_until > time.time()

    @property
    def current_host(self) -> str:
        with self._lock:
            return self._extract_host(self._current_proxy)

    def get_current_host(self) -> str:
        """Public getter for current proxy hostname (for logging / display)."""
        return self.current_host

    def get_current_proxy(self) -> Optional[Proxy]:
        """Return the current proxy without triggering rotation (for inspection)."""
        with self._lock:
            return self._current_proxy

    def _get_proxy_locked(self) -> Optional[Proxy]:
        """Internal: caller must hold self._lock."""
        # Check 5-min proxy disable after too many consecutive failures
        if self._proxy_disabled_until > time.time():
            self._current_proxy = None
            return None

        available = self._available_proxies_locked()
        if not available:
            self._current_proxy = None
            return None

        now = time.time()

        # Clear blacklist once per 24h
        if now - self._last_blacklist_clear > BLACKLIST_CLEAR_SECONDS:
            self._blacklist.clear()
            self._last_blacklist_clear = now
            logger.info("pac-api: blacklist cleared (24h cycle)")

        # Rotate if no current proxy or window expired
        if (
            self._current_proxy is None
            or (now - self._proxy_switched_at) > PROXY_ROTATION_SECONDS
        ):
            self._rotate_locked(now)

        return self._current_proxy

    def _rotate_locked(self, now: float) -> None:
        """Pick a new random proxy from available (non-blacklisted) proxies."""
        available = self._available_proxies_locked()
        if not available:
            self._current_proxy = None
            return

        # Remove current from pool so we don't pick the same one
        pool = [p for p in available if p != self._current_proxy]
        if not pool:
            pool = available  # only one proxy available, reuse it

        self._current_proxy = random.choice(pool)
        self._current_proxy_index = self._proxies.index(self._current_proxy)
        self._proxy_switched_at = now

        # NOTE: We do NOT set ALL_PROXY env vars here because:
        #   1. Socket-level patching already intercepts all TCP connections
        #   2. Env vars cause httpx/requests to DOUBLE-PROXY: the socket
        #      layer routes the connection, then httpx tries to use the
        #      SOCKS5 relay as an HTTP proxy -> circular failure
        #   3. The env var approach was designed for the httpx-level patch
        #      (from the existing plugin), not needed in socket-level mode

        logger.info(
            "pac-api: rotated to proxy %s (window: %ds, remaining: %d)",
            self._current_proxy.addr,
            PROXY_ROTATION_SECONDS,
            len(pool),
        )

    def _available_proxies_locked(self) -> ProxyList:
        """Return proxies not in the blacklist (accounting for expired entries)."""
        now = time.time()
        # Clean expired blacklist entries
        expired = [
            addr
            for addr, ts in self._blacklist.items()
            if now - ts > BLACKLIST_CLEAR_SECONDS
        ]
        for addr in expired:
            del self._blacklist[addr]

        if not self._proxies:
            return []
        return [p for p in self._proxies if p.addr not in self._blacklist]

    # ------------------------------------------------------------------
    # Blacklist
    # ------------------------------------------------------------------

    def mark_failed(self, proxy: Optional[Proxy]) -> None:
        """Add a proxy to the blacklist so it won't be selected again.

        After MAX_RETRIES consecutive total failures across the pool,
        disable proxying for PROXY_DISABLE_SECONDS before retrying.
        """
        if not proxy:
            return
        with self._lock:
            self._blacklist[proxy.addr] = time.time()
            logger.warning(
                "pac-api: blacklisted proxy %s (blacklist size: %d)",
                proxy.addr,
                len(self._blacklist),
            )
            # Track consecutive failures
            self._consecutive_failures += 1
            if self._consecutive_failures >= MAX_RETRIES:
                self._proxy_disabled_until = time.time() + PROXY_DISABLE_SECONDS
                logger.warning(
                    "*** pac-api: %d consecutive failures — "
                    "disabling proxy for %ds ***",
                    self._consecutive_failures,
                    PROXY_DISABLE_SECONDS,
                )
            # Force rotation so next call gets a different proxy
            self._proxy_switched_at = 0.0

    def get_blacklist(self) -> dict[str, float]:
        """Return the current blacklist (addr -> timestamp)."""
        with self._lock:
            return dict(self._blacklist)

    def clear_blacklist(self) -> None:
        """Manually clear the proxy blacklist. Also resets the consecutive
        failure counter so the 5-min cooldown is effectively lifted."""
        with self._lock:
            self._blacklist.clear()
            self._last_blacklist_clear = time.time()
            self._consecutive_failures = 0
            self._proxy_disabled_until = 0.0
            logger.info("pac-api: blacklist manually cleared")

    # ------------------------------------------------------------------
    # Retry / send logic
    # ------------------------------------------------------------------

    def send_with_retry(
        self,
        host: str,
        port: int,
        connect_fn,
        **kwargs,
    ):
        """
        Attempt to connect to (host, port) through a SOCKS5 proxy with
        retries.

        connect_fn is a callable that accepts (proxy, host, port, **kwargs)
        and establishes the connection.

        Returns the connection on success, or raises the last error on
        total failure (falling back to direct connection).
        """
        if not self._enabled or should_bypass(host):
            logger.info(
                "pac-api: \033[90m— %s:%s bypassed (NO_PROXY)\033[0m",
                host, port,
            )
            return connect_fn(None, host, port, **kwargs)

        # If proxy is disabled (5-min cooldown), go direct immediately
        if self.is_disabled:
            logger.info(
                "pac-api: proxy disabled (%ds remaining) — direct fallback for %s:%s",
                max(0, int(self._proxy_disabled_until - time.time())),
                host,
                port,
            )
            return connect_fn(None, host, port, **kwargs)

        last_error = None
        tried_proxies: set[str] = set()

        for attempt in range(1, MAX_RETRIES + 1):
            proxy = self.get_proxy()
            if proxy is None:
                break
            if proxy.addr in tried_proxies:
                continue

            try:
                result = connect_fn(proxy, host, port, **kwargs)
                # Success — log the proxied connection and reset failure state
                logger.info(
                    "pac-api: \033[36m→ %s:%s via %s\033[0m",
                    host, port, proxy.addr,
                )
                self.reset_failure_state()
                return result
            except Exception as e:
                last_error = e
                tried_proxies.add(proxy.addr)
                self.mark_failed(proxy)
                logger.error(
                    "pac-api: attempt %d/%d — proxy %s failed for %s:%s: %s",
                    attempt,
                    MAX_RETRIES,
                    proxy.addr,
                    host,
                    port,
                    e,
                )

        # All retries exhausted — fall back to direct
        logger.warning(
            "*** pac-api: All %d SOCKS5 proxy attempts failed for %s:%s — "
            "falling back to direct (unproxied) connection ***",
            MAX_RETRIES,
            host,
            port,
        )
        return connect_fn(None, host, port, **kwargs)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            available = len(self._available_proxies_locked())
            now = time.time()
            return {
                "enabled": self._enabled,
                "total_proxies": len(self._proxies),
                "available_proxies": available,
                "blacklisted": len(self._blacklist),
                "current_proxy": self._current_proxy.addr if self._current_proxy else None,
                "current_host": self._extract_host(self._current_proxy),
                "proxy_switched_at": self._proxy_switched_at,
                "seconds_until_rotation": max(
                    0, PROXY_ROTATION_SECONDS - (now - self._proxy_switched_at)
                ),
                "consecutive_failures": self._consecutive_failures,
                "proxy_disabled": self._proxy_disabled_until > now,
                "proxy_disabled_remaining_s": max(
                    0, int(self._proxy_disabled_until - now)
                ),
                "pac_url": self._pac_url,
                "pac_last_fetched": self._pac_last_fetched,
            }

    def to_json(self) -> str:
        return json.dumps(self.status(), indent=2, default=str)

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        logger.info("pac-api: %s", "enabled" if enabled else "disabled")
