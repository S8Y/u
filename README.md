# PAC-API — Hermes Privacy Plugin

Routes all outbound Hermes TCP connections (LLM providers, Firecrawl, web search, etc.)
through rotating SOCKS5 proxies from a Mullvad PAC file.

## Features

- **PAC auto-fetch** — Downloads the latest Mullvad SOCKS5 proxy list on startup and
  every 12 hours from the [mullvad-pac](https://github.com/S8Y/mullvad-pac) repo
- **Socket-level interception** — Patches `socket.create_connection`, `socket.socket`,
  and `asyncio` so ALL Python TCP traffic routes through the proxy (not just httpx).
  No env var pollution — routing is transparent at the TCP level
- **3-minute rotation** — Uses 1 proxy for 3 minutes, then swaps to a random different one
- **24h blacklist** — Failed proxies are blacklisted for 24 hours (auto-cleared)
- **3-retry failover** — On proxy failure: retries with different proxy up to 3 times,
  then falls back to direct with bold logging
- **5-min cooldown** — After 3 consecutive failures across the pool, proxies are disabled
  for 5 minutes before retrying
- **Messenger bypass** — 29 NO_PROXY domains (Telegram, Discord, Slack, WhatsApp, Signal,
  Matrix) never go through the proxy — they have their own connection config
- **Built-in fallback** — 8 hardcoded Mullvad relays used when the PAC fetch fails entirely
- **First-attempt proxy** — Unlike env-var-based approaches, the very first connection
  attempt goes through the proxy (no IP leak window)
- **Auto-install** — PySocks is auto-installed if missing
- **Bold ANSI logging** — All proxy events logged with bold formatting for Hermes TUI

## Files

```
~/.hermes/plugins/pac-api/
├── plugin.yaml          # Manifest
├── __init__.py          # Registration + startup + slash command
├── proxy_manager.py     # PAC parsing, rotation, blacklist, env vars
├── pac_fetcher.py       # PAC download + 12h background refresh
├── transport.py         # Socket/asyncio monkey-patching
├── tools.py             # Slash command handlers + lifecycle hooks
└── schemas.py           # Tool schemas for LLM function calling
```

## Installation

```bash
mkdir -p ~/.hermes/plugins/pac-api
cp /path/to/pac-api/* ~/.hermes/plugins/pac-api/
# Restart Hermes
```

The plugin auto-installs PySocks on startup. To install manually:

```bash
pip install PySocks
```

No configuration needed. Enable the plugin and it fetches the Mullvad proxy
list automatically on startup.

The plugin has zero required env vars, zero config keys — just enable and go.

## Usage

### Slash Commands

| Command                   | Description                              |
|---------------------------|------------------------------------------|
| `/pac-proxy status`       | Show current proxy, pool, blacklist      |
| `/pac-proxy rotate`       | Force immediate proxy rotation           |
| `/pac-proxy blacklist`    | List blacklisted proxies                 |
| `/pac-proxy reload`       | Force-refetch the PAC file from GitHub   |
| `/pac-proxy bypass`       | List domains that bypass the proxy       |

### LLM Function-calling Tools

| Tool            | Description                     |
|-----------------|---------------------------------|
| `pac_status`    | JSON status of proxy manager    |
| `pac_cycle`     | Force rotation to a new proxy   |
| `pac_blacklist` | Show or clear the blacklist     |
| `pac_reload`    | Force PAC file refetch          |

## Architecture

```
                    ┌──────────────────────┐
                    │   Hermes Agent        │
                    │  (any HTTP lib)       │
                    └────────┬─────────────┘
                             │ socket.create_connection()
                    ┌────────▼─────────────┐
                    │   transport.py        │
                    │  (socket patching)    │
                    └────────┬─────────────┘
                             │ should_bypass(host)?
                    ┌────────▼─────────────┐
                    │   ProxyManager        │
                    │  - PAC parse/fetch    │
                    │  - 3min rotation      │
                    │  - 24h blacklist      │
                    │  - 5-min cooldown     │
                    └────────┬─────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        SOCKS5 proxy    SOCKS5 proxy    Direct (fallback
                                        or NO_PROXY)
```

## How It Works

1. **Startup**: Plugin loads → ensures PySocks → creates ProxyManager → fetches PAC →
   picks first proxy → patches socket layer → starts 12h refresh thread
2. **Every 3 min**: `get_proxy()` detects expired window → picks new random proxy
   from non-blacklisted pool
3. **On request**: `socket.create_connection()` checks `should_bypass(host)` → routes
   through SOCKS5 via PySocks or connects direct
4. **On failure** (transport level): Patched socket raises → `send_with_retry` catches
   → blacklists proxy → rotates → retries x3 → direct fallback with bold log
5. **On failure** (tool level): `post_tool_call` hook detects failed tool results →
   blacklists proxy → triggers rotation
6. **After 3 consecutive failures**: Proxies disabled for 5 minutes (cooldown) →
   then re-enabled automatically
7. **Every 12h**: PAC file re-fetched from GitHub
8. **Every 24h**: Blacklist cleared

## Log Output Examples

```
pac-api: ✅ Active — 41 proxies loaded, rotating every 180s (0 blacklisted)
pac-api: Current proxy: de-fra-wg-socks5-403
pac-api: rotated to proxy ch-zrh-wg-socks5-002 (window: 180s, remaining: 39)
*** pac-api: attempt 1/3 — proxy de-ber failed for api.openai.com:443:
*** pac-api: All 3 attempts failed — falling back to direct (unproxied) ***
*** pac-api: 3 consecutive failures — disabling proxy for 300s ***
```

## Dependencies

- **PySocks** — SOCKS5 proxy client (Python)
- **httpx** — PAC file fetching (bundled with Hermes)
