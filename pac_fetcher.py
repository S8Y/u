"""
PAC-API PAC Fetcher — downloads and refreshes the PAC file.

Handles:
  - Initial PAC fetch from the hardcoded Mullvad PAC URL
  - Background refresh every 12 hours
  - Graceful fallback if fetch fails (keep using last known proxy list)
"""

import logging
import threading
import time
from pathlib import Path
from typing import Optional

import httpx

try:
    from .proxy_manager import (
        PAC_URL_DEFAULT,
        PAC_REFRESH_SECONDS,
        ProxyManager,
        parse_pac_proxies,
    )
except ImportError:
    from proxy_manager import (
        PAC_URL_DEFAULT,
        PAC_REFRESH_SECONDS,
        ProxyManager,
        parse_pac_proxies,
    )

logger = logging.getLogger(__name__)

# Cache the raw PAC content to disk so it survives restarts
_PAC_CACHE_DIR = Path.home() / ".hermes" / "plugins" / "pac-api"
_PAC_CACHE_FILE = _PAC_CACHE_DIR / "mullvad.pac"
_PAC_CACHE_PROXIES = _PAC_CACHE_DIR / "proxies.json"


def _ensure_cache_dir():
    _PAC_CACHE_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------


def fetch_pac(url: str = PAC_URL_DEFAULT, timeout: float = 15.0) -> Optional[str]:
    """
    Download the PAC file from the given URL.
    Returns the raw text content, or None on failure.
    """
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        content = resp.text
        logger.info("pac-api: fetched PAC from %s (%d bytes)", url, len(content))
        return content
    except httpx.HTTPStatusError as e:
        logger.error("pac-api: HTTP %d fetching PAC from %s", e.response.status_code, url)
    except httpx.TimeoutException:
        logger.error("pac-api: timeout fetching PAC from %s", url)
    except httpx.RequestError as e:
        logger.error("pac-api: request error fetching PAC: %s", e)
    except Exception as e:
        logger.error("pac-api: unexpected error fetching PAC: %s", e)
    return None


def load_pac(
    proxy_manager: ProxyManager,
    url: str = PAC_URL_DEFAULT,
) -> bool:
    """
    Fetch the PAC file from the URL, parse proxies, and load them into
    the ProxyManager. Falls back to a cached copy on disk if the fetch
    fails.

    Returns True if proxies were loaded (even from cache), False if
    completely empty.
    """
    _ensure_cache_dir()

    content = fetch_pac(url)

    # If fetch failed, try loading from disk cache
    if content is None:
        content = _read_cache()
        if content:
            logger.info("pac-api: using cached PAC from %s", _PAC_CACHE_FILE)

    if content:
        # Save to disk cache
        _write_cache(content)
        proxies = parse_pac_proxies(content)
        proxy_manager.set_proxies(proxies)
        if proxies:
            logger.info(
                "pac-api: loaded %d SOCKS5 proxies into rotation", len(proxies)
            )
            return True
        else:
            logger.warning("pac-api: PAC file contained 0 SOCKS5 proxies")
            return False
    else:
        logger.warning("pac-api: no PAC content available — proxy list empty")
        return False


# ---------------------------------------------------------------------------
# Background refresh thread
# ---------------------------------------------------------------------------


def _refresh_loop(proxy_manager: ProxyManager, url: str, stop_event: threading.Event):
    """
    Background thread: every PAC_REFRESH_SECONDS (12h), fetch the PAC
    file and update the proxy list. Runs until stop_event is set.
    """
    logger.info("pac-api: background refresh thread started (interval: %ds)", PAC_REFRESH_SECONDS)

    while not stop_event.wait(PAC_REFRESH_SECONDS):
        try:
            logger.info("pac-api: scheduled PAC refresh...")
            load_pac(proxy_manager, url)
        except Exception as e:
            logger.error("pac-api: error in PAC refresh loop: %s", e)

    logger.info("pac-api: background refresh thread stopped")


def start_refresh_thread(
    proxy_manager: ProxyManager,
    url: str = PAC_URL_DEFAULT,
) -> threading.Event:
    """
    Start a daemon background thread that refreshes the PAC file every
    12 hours. Returns the stop_event that can be used to signal shutdown.
    """
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_refresh_loop,
        args=(proxy_manager, url, stop_event),
        daemon=True,
        name="pac-api-refresh",
    )
    thread.start()
    logger.info("pac-api: refresh scheduler started (next refresh in 12h)")
    return stop_event


# ---------------------------------------------------------------------------
# Disk cache helpers
# ---------------------------------------------------------------------------


def _read_cache() -> Optional[str]:
    """Read cached PAC content from disk."""
    try:
        if _PAC_CACHE_FILE.exists():
            return _PAC_CACHE_FILE.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning("pac-api: failed to read PAC cache: %s", e)
    return None


def _write_cache(content: str) -> None:
    """Write PAC content to disk cache."""
    try:
        _ensure_cache_dir()
        _PAC_CACHE_FILE.write_text(content, encoding="utf-8")
    except Exception as e:
        logger.warning("pac-api: failed to write PAC cache: %s", e)


def clear_cache() -> None:
    """Delete cached PAC file and proxies."""
    try:
        if _PAC_CACHE_FILE.exists():
            _PAC_CACHE_FILE.unlink()
        if _PAC_CACHE_PROXIES.exists():
            _PAC_CACHE_PROXIES.unlink()
        logger.info("pac-api: cache cleared")
    except Exception as e:
        logger.warning("pac-api: failed to clear cache: %s", e)
