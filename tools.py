"""
PAC-API Tool handlers — CLI management commands for the proxy system.

All imports that depend on PySocks are deferred inside the functions that
need them so the module can be imported before PySocks is installed.
"""

import json
import logging
import time

logger = logging.getLogger(__name__)

# ── Monitored Tools ────────────────────────────────────────────────────────
# HTTP/API tools whose results should be inspected for proxy failures.
_MONITORED_TOOLS = frozenset({
    "web_search", "web_extract", "web",
    "browser_navigate", "browser_snapshot", "browser_click",
    "browser_type", "browser_scroll", "browser_console",
    "browser_get_images",
    "github", "github_issue", "github_pr", "github_search", "github_repo",
    "firecrawl_scrape", "firecrawl_crawl", "firecrawl_map",
    "http_request", "curl", "fetch",
    "delegate_task",
})

# Proxy-typical error substrings (case-insensitive)
_PROXY_ERROR_SIGNALS = frozenset({
    "connection refused", "connection reset", "connection timed out",
    "timeout", "timed out",
    "no route to host", "network is unreachable", "cannot connect",
    "proxy connect error", "socks5", "socks",
    "handshake failure", "tls error", "ssl error",
    "resolve", "dns resolution",
    "name or service not known", "temporary failure in name resolution",
    "500", "502", "503", "504",
    "bad gateway", "service unavailable", "gateway timeout",
    "proxy authentication required", "407",
})


def _get_manager(ctx):
    """Resolve the ProxyManager singleton from plugin context."""
    return ctx.shared.get("pac_api_manager")


def _looks_like_proxy_error(error_text: str) -> bool:
    """Fuzzy-match error text against known proxy-failure signals."""
    lower = error_text.lower()
    for signal in _PROXY_ERROR_SIGNALS:
        if signal in lower:
            return True
    return False


def _parse_result(result: str) -> dict | None:
    """Safely parse a JSON tool result."""
    if not result or not isinstance(result, str):
        return None
    try:
        return json.loads(result)
    except (json.JSONDecodeError, ValueError):
        return None


def _is_failure(data: dict) -> bool:
    """Check if a tool result indicates failure."""
    if "error" in data and data["error"]:
        return True
    if data.get("success") is False:
        return True
    if data.get("status") in ("error", "fail"):
        return True
    if data.get("exit_code", 0) != 0:
        return True
    return False


def _extract_error_text(data: dict) -> str:
    """Extract error text from various possible fields."""
    for key in ("error", "message", "stderr", "error_message", "traceback"):
        val = data.get(key)
        if val:
            return str(val)
    return ""


# ── Tool Handlers ─────────────────────────────────────────────────────────


def pac_status(args: dict, **kwargs) -> str:
    """Show current proxy status."""
    ctx = kwargs.get("_ctx")
    if not ctx:
        return json.dumps({"error": "Plugin context not available"})
    pm = _get_manager(ctx)
    if not pm:
        return json.dumps({"error": "PAC-API manager not initialized"})
    return pm.to_json()


def pac_reload(args: dict, **kwargs) -> str:
    """Force-fetch the PAC file from GitHub and reload the proxy list."""
    ctx = kwargs.get("_ctx")
    if not ctx:
        return json.dumps({"error": "Plugin context not available"})
    pm = _get_manager(ctx)
    if not pm:
        return json.dumps({"error": "PAC-API manager not initialized"})

    # Lazy imports — socks must be installed first
    try:
        from proxy_manager import ProxyManager  # noqa: F401 — used for type check
        from pac_fetcher import fetch_pac, parse_pac_proxies
        from transport import is_patched
    except ImportError:
        pass  # _ensure_dependencies should have run by now in register()

    try:
        content = fetch_pac()
        if content:
            proxies = parse_pac_proxies(content)
            pm.set_proxies(proxies)
            return json.dumps({
                "status": "ok",
                "message": f"PAC file reloaded: {len(proxies)} SOCKS5 proxies loaded",
                "proxies_loaded": len(proxies),
                "transport_patched": is_patched() if 'is_patched' in dir() else False,
            })
        else:
            return json.dumps({
                "status": "error",
                "message": "Failed to fetch PAC file from GitHub — try again later",
            })
    except Exception as e:
        logger.exception("pac-api: pac_reload failed")
        return json.dumps({"error": f"Reload failed: {e}"})


def pac_blacklist(args: dict, **kwargs) -> str:
    """Show or clear the proxy blacklist."""
    ctx = kwargs.get("_ctx")
    if not ctx:
        return json.dumps({"error": "Plugin context not available"})
    pm = _get_manager(ctx)
    if not pm:
        return json.dumps({"error": "PAC-API manager not initialized"})

    action = args.get("action", "show")

    if action == "clear":
        pm.clear_blacklist()
        return json.dumps({
            "status": "ok",
            "message": "Blacklist cleared",
            "hint": "Use pac_reload to refetch PAC if you also want to refresh the proxy list",
        })

    # Show
    blacklist = pm.get_blacklist()
    now = time.time()
    entries = []
    for addr, ts in sorted(blacklist.items(), key=lambda x: x[1], reverse=True):
        remaining = 86400 - (now - ts)
        entries.append({
            "proxy": addr,
            "blacklisted_at_ts": ts,
            "seconds_until_clear": max(0, remaining),
        })
    status = pm.status()
    return json.dumps({
        "status": "ok",
        "blacklisted_count": len(entries),
        "available_proxies": status["available_proxies"],
        "total_proxies": status["total_proxies"],
        "proxy_disabled": status["proxy_disabled"],
        "proxy_disabled_remaining_s": status["proxy_disabled_remaining_s"],
        "entries": entries,
    }, indent=2, default=str)


def pac_cycle(args: dict, **kwargs) -> str:
    """Force immediate proxy rotation — pick a new random proxy now."""
    ctx = kwargs.get("_ctx")
    if not ctx:
        return json.dumps({"error": "Plugin context not available"})
    pm = _get_manager(ctx)
    if not pm:
        return json.dumps({"error": "PAC-API manager not initialized"})

    old_host = pm.get_current_host()
    # Force rotation
    pm._proxy_switched_at = 0.0
    new_proxy = pm.get_proxy()
    new_host = pm.get_current_host()

    status = pm.status()
    return json.dumps({
        "status": "ok",
        "message": f"Rotated from {old_host} to {new_host}",
        "previous_proxy": old_host,
        "current_proxy": new_host,
        "seconds_until_next_rotation": status["seconds_until_rotation"],
        "available_proxies": status["available_proxies"],
    }, default=str)


# ── Hook Callbacks ─────────────────────────────────────────────────────────


def on_pre_llm_call(**kwargs) -> dict:
    """Hook fired once per turn before the LLM call. No context injection."""
    return {}


def on_post_tool_call(**kwargs) -> None:
    """
    Hook fired after any tool returns.

    Inspects HTTP/API tool results for proxy-related failures and triggers
    immediate blacklisting + rotation when detected.
    """
    try:
        tool_name = kwargs.get("tool_name", "")
        result = kwargs.get("result", "")

        if tool_name not in _MONITORED_TOOLS:
            return

        ctx = kwargs.get("_ctx")
        if not ctx:
            return
        pm = _get_manager(ctx)
        if not pm:
            return

        if pm.is_disabled:
            return  # Already in cooldown — no need to keep hammering

        # Parse result (tool handlers return JSON strings)
        result_data = _parse_result(result)
        if result_data is None:
            return

        if not _is_failure(result_data):
            # Success! Reset failure counter
            pm.reset_failure_state()
            return

        # Check if the error looks proxy-related
        error_text = _extract_error_text(result_data)
        if not error_text:
            return

        if not _looks_like_proxy_error(error_text):
            return

        # ── Proxy failure detected ──
        current_proxy = pm.get_current_proxy()
        current_host = pm.get_current_host()

        if current_proxy:
            logger.warning(
                "\033[1mpac-api: ✘ Tool '%s' failed via %s — "
                "blacklisting + rotating\033[0m",
                tool_name,
                current_host,
            )
            logger.warning(
                "\033[1mpac-api: ✘ Error: %s\033[0m",
                error_text[:200],
            )
            pm.mark_failed(current_proxy)
        else:
            # No proxy active but tool still failed — log for visibility
            logger.info(
                "pac-api: Tool '%s' failed (no proxy active): %s",
                tool_name,
                error_text[:150],
            )

    except Exception:
        logger.exception("pac-api: post_tool_call hook error")
