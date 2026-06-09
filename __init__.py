"""
PAC-API Plugin — Hermes Agent plugin for SOCKS5 proxy routing via PAC files.

On registration:
  1. Ensures PySocks is installed (auto-installs if missing)
  2. Creates the ProxyManager (rotation, blacklist, retry, 5-min cooldown)
  3. Fetches the PAC file from GitHub, parses proxies (falls back to built-in)
  4. Patches Python's socket / asyncio transport layer
  5. Starts a background refresh thread (every 12h)
  6. Registers CLI management tools + slash command
  7. Registers lifecycle hooks for observability

All outbound TCP connections from Hermes are then routed through the
rotating SOCKS5 proxy pool, with automatic failover and blacklisting.
"""

import logging
import os
import subprocess
import sys
import threading

# ---------------------------------------------------------------------------
# Ensure the plugin's own directory is on sys.path so that relative or
# absolute imports resolve regardless of how Hermes loads the module.
# ---------------------------------------------------------------------------
_plugin_dir = os.path.dirname(os.path.abspath(__file__))
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

# Use absolute imports (no dots) — robust against how Hermes sets up the
# package namespace.  All sibling modules import each other the same way.
from proxy_manager import ProxyManager, PAC_URL_DEFAULT, PAC_REFRESH_SECONDS
import schemas
import pac_tools as tools

logger = logging.getLogger(__name__)

# Module-level singleton references kept alive for the plugin lifecycle
_manager: ProxyManager | None = None
_stop_event: threading.Event | None = None
_refresh_thread: threading.Thread | None = None

# ── Dependency check ──────────────────────────────────────────────────────

_REQUIRED_PACKAGES = ["PySocks", "httpx"]


def _ensure_dependencies() -> None:
    """Verify required packages are installed; try to install if not."""
    missing = []
    # PySocks
    try:
        import socks  # noqa: F401
    except ImportError:
        missing.append("PySocks")
    # httpx (should always be present in Hermes, but check anyway)
    try:
        import httpx  # noqa: F401
    except ImportError:
        missing.append("httpx")

    if not missing:
        logger.debug("pac-api: dependencies verified")
        return

    logger.warning(
        "\033[1mpac-api: Missing packages: %s — attempting install...\033[0m",
        ", ".join(missing),
    )
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", *missing, "-q"],
            timeout=60,
        )
        logger.info(
            "\033[1mpac-api: Installed %s successfully\033[0m",
            ", ".join(missing),
        )
    except Exception as exc:
        logger.error(
            "\033[1mpac-api: Failed to install %s — %s\033[0m",
            ", ".join(missing),
            exc,
        )
        logger.error(
            "\033[1mpac-api: Install manually: pip install %s\033[0m",
            " ".join(missing),
        )


# ── Registration ─────────────────────────────────────────────────────────


def register(ctx):
    """
    Plugin registration — called exactly once by Hermes at startup.
    """
    global _manager, _stop_event

    logger.info("\033[1mpac-api: initializing...\033[0m")

    # 1. Ensure dependencies (before any socks import)
    _ensure_dependencies()

    # 2. Lazy imports — transport triggers import socks which must be
    #    installed by _ensure_dependencies first.
    from pac_fetcher import load_pac, start_refresh_thread
    from transport import patch, unpatch

    # 3. Create ProxyManager and fetch PAC (hardcoded Mullvad URL)
    _manager = ProxyManager()
    pac_url = PAC_URL_DEFAULT
    logger.info("pac-api: initial PAC fetch from %s", pac_url)
    load_pac(_manager, url=pac_url)

    # 4. Store manager in shared state (ctx.shared does not exist in Hermes)
    import _state
    _state._manager = _manager

    # 5. Patch the transport layer
    patch(_manager)
    logger.info(
        "\033[1mpac-api: transport patched — all TCP connections proxied\033[0m"
    )

    # 6. Start background PAC refresh thread (every 12h)
    _stop_event = start_refresh_thread(_manager, url=pac_url)

    # 7. Monkey-patch Hermes' _build_keepalive_http_client so the httpx
    #     client uses a default transport (no custom HTTPTransport with
    #     socket_options).  The default transport goes through
    #     socket.create_connection which is caught by our sync patch.
    try:
        # Try to import run_agent (Hermes root module)
        import run_agent as _ra
        _orig_build = _ra.AIAgent._build_keepalive_http_client

        logger.info(
            "\033[1mpac-api: patching AIAgent._build_keepalive_http_client\033[0m"
        )

        def _pac_keepalive_client(base_url: str = ""):
            client = _orig_build(base_url)
            if client is None:
                return None
            import httpx as _httpx
            plain = _httpx.Client(
                timeout=client.timeout,
                verify=client.verify,
                trust_env=client.trust_env,
            )
            plain.headers = client.headers
            plain.auth = client.auth
            return plain

        _ra.AIAgent._build_keepalive_http_client = _pac_keepalive_client
        logger.info(
            "\033[1mpac-api: AIAgent._build_keepalive_http_client patched\033[0m"
        )
    except Exception as exc:
        logger.warning(
            "\033[1mpac-api: could not patch AIAgent,"
            " fallback: patching httpx.Client directly — %s\033[0m",
            exc,
        )
        try:
            # Fallback: patch httpx.Client to strip custom transports
            import httpx as _httpx

            _orig_http_client_init = _httpx.Client.__init__

            def _pac_http_client_init(self, *, transport=None, **kw):
                # Remove the custom HTTPTransport so connections go through
                # our socket.create_connection patch
                _orig_http_client_init(self, transport=None, **kw)

            _httpx.Client.__init__ = _pac_http_client_init
            logger.info(
                "\033[1mpac-api: httpx.Client.__init__ patched\033[0m"
            )
        except Exception as exc2:
            logger.warning(
                "\033[1mpac-api: could not patch httpx.Client — %s\033[0m",
                exc2,
            )

    # 8. Register CLI management tools (for LLM to call via function calling)
    ctx.register_tool(
        name="pac_status",
        toolset="pac_api",
        schema=schemas.PAC_STATUS_SCHEMA,
        handler=tools.pac_status,
    )
    ctx.register_tool(
        name="pac_reload",
        toolset="pac_api",
        schema=schemas.PAC_RELOAD_SCHEMA,
        handler=tools.pac_reload,
    )
    ctx.register_tool(
        name="pac_blacklist",
        toolset="pac_api",
        schema=schemas.PAC_BLACKLIST_SCHEMA,
        handler=tools.pac_blacklist,
    )
    ctx.register_tool(
        name="pac_cycle",
        toolset="pac_api",
        schema=schemas.PAC_CYCLE_SCHEMA,
        handler=tools.pac_cycle,
    )

    # 8. Register slash command (for interactive use)
    _register_slash_command(ctx)

    # 9. Register lifecycle hooks
    ctx.register_hook("pre_llm_call", tools.on_pre_llm_call)
    ctx.register_hook("post_tool_call", tools.on_post_tool_call)

    pm = _manager
    logger.info(
        "\033[1mpac-api: ✅ Active — %d proxies loaded, "
        "rotating every %ds (%d blacklisted)\033[0m",
        pm.status()["total_proxies"] if pm else 0,
        180,
        pm.status()["blacklisted"] if pm else 0,
    )
    if pm and pm.status()["current_host"] != "none":
        logger.info(
            "\033[1mpac-api: Current proxy: %s\033[0m",
            pm.current_host,
        )


def unregister(ctx):
    """
    Clean shutdown — called when the plugin is unloaded or Hermes shuts down.
    """
    global _manager, _stop_event

    # Stop the refresh thread
    if _stop_event is not None:
        _stop_event.set()
        _stop_event = None

    # Clear proxy env vars
    if _manager is not None:
        _manager._clear_proxy_env()

    # Restore original socket functions
    from transport import unpatch
    unpatch()

    _manager = None
    logger.info("\033[1mpac-api: plugin unregistered — proxy routing disabled\033[0m")


# ── Slash command ─────────────────────────────────────────────────────────


def _register_slash_command(ctx) -> None:
    """Register the /pac-proxy slash command for interactive use."""
    try:
        ctx.register_command(
            "pac-proxy",
            handler=_handle_slash,
            description=(
                "View / rotate PAC-API proxy settings. "
                "Subcommands: status, rotate, blacklist, reload, bypass"
            ),
        )
        logger.debug("pac-api: slash command /pac-proxy registered")
    except AttributeError:
        logger.debug(
            "pac-api: ctx.register_command not available — "
            "slash command skipped (tools still work)"
        )


def _handle_slash(args: str, **kwargs) -> str:
    """Handle the /pac-proxy slash command."""
    pm = _manager
    if pm is None:
        return "\033[1mpac-api: manager not initialized\033[0m"

    parts = args.strip().split() if args else []
    subcommand = parts[0].lower() if parts else "status"

    if subcommand == "status":
        return _slash_status(pm)
    elif subcommand == "rotate":
        return _slash_rotate(pm)
    elif subcommand == "blacklist":
        return _slash_blacklist(pm)
    elif subcommand == "reload":
        from pac_fetcher import load_pac as _load_pac
        ok = _load_pac(pm, url=PAC_URL_DEFAULT)
        if ok:
            return (
                "\033[1mpac-api: PAC reloaded\033[0m\n"
                f"  {pm.status()['total_proxies']} proxies loaded"
            )
        else:
            return "\033[1mpac-api: PAC reload failed — check connection\033[0m"
    elif subcommand == "bypass":
        from proxy_manager import NO_PROXY_DOMAINS
        domains = "\n  ".join(sorted(NO_PROXY_DOMAINS))
        return (
            "\033[1m━━━ NO_PROXY — Bypassed Domains ━━━\033[0m\n"
            f"  Total: {len(NO_PROXY_DOMAINS)}\n"
            f"  {domains}"
        )
    else:
        return (
            "\033[1mpac-api: Unknown subcommand\033[0m\n"
            "Usage: /pac-proxy {status|rotate|blacklist|reload|bypass}"
        )


def _slash_status(pm: ProxyManager) -> str:
    """Format proxy status for terminal display."""
    s = pm.status()
    lines = [
        "\033[1m━━━ PAC-API Proxy Status ━━━\033[0m",
        f"  Current proxy  : \033[36m{s['current_host']}\033[0m"
        if s['current_host'] != "none"
        else "  Current proxy  : \033[33mnone (direct)\033[0m",
        f"  Proxy pool     : {s['total_proxies']}",
        f"  Available      : {s['available_proxies']}",
        f"  Blacklisted    : {s['blacklisted']}",
        f"  Rotation in    : {s['seconds_until_rotation']:.0f}s",
        f"  Fail streak    : {s['consecutive_failures']}",
        "",
    ]
    if s.get("proxy_disabled"):
        lines.append(
            "  \033[33m⚠ Proxy cooldown — "
            f"{s['proxy_disabled_remaining_s']}s remaining\033[0m"
        )
        lines.append("")
    lines.append(
        "  \033[90m/pac-proxy rotate    — Force rotation now\033[0m"
    )
    lines.append(
        "  \033[90m/pac-proxy blacklist — View blacklist\033[0m"
    )
    lines.append(
        "  \033[90m/pac-proxy reload    — Force PAC refetch\033[0m"
    )
    lines.append(
        "  \033[90m/pac-proxy bypass    — View bypassed domains\033[0m"
    )
    return "\n".join(lines)


def _slash_rotate(pm: ProxyManager) -> str:
    """Force immediate proxy rotation."""
    old_host = pm.get_current_host()
    pm._proxy_switched_at = 0.0
    pm.get_proxy()  # triggers rotation
    new_host = pm.get_current_host()
    return (
        f"\033[1mpac-api: Rotated\033[0m\n"
        f"  {old_host} \033[36m→ {new_host}\033[0m"
    )


def _slash_blacklist(pm: ProxyManager) -> str:
    """Show blacklisted proxies."""
    bl = pm.get_blacklist()
    if not bl:
        return "\033[1mpac-api: Blacklist is empty\033[0m"
    lines = [
        "\033[1m━━━ Blacklisted Proxies ━━━\033[0m",
        f"  Total: {len(bl)} / {pm.status()['total_proxies']}",
        "",
    ]
    for addr in sorted(bl.keys()):
        lines.append(f"  ✘ {addr}")
    return "\n".join(lines)
