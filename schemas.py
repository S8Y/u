"""
PAC-API Tool schemas — what the LLM sees for each management command.
"""

import json

# ---------------------------------------------------------------------------
# /pac_status — show current proxy manager state
# ---------------------------------------------------------------------------

PAC_STATUS_SCHEMA = {
    "name": "pac_status",
    "description": (
        "Show the current PAC-API proxy status: how many SOCKS5 proxies "
        "are loaded from the PAC file, the currently active proxy and its "
        "remaining time in the 3-minute rotation window, how many proxies "
        "are blacklisted, and the overall enabled/disabled state. "
        "Use this to verify proxy routing is active and debug connectivity issues."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

# ---------------------------------------------------------------------------
# /pac_reload — force-refetch the PAC file
# ---------------------------------------------------------------------------

PAC_RELOAD_SCHEMA = {
    "name": "pac_reload",
    "description": (
        "Force a fresh download of the Mullvad PAC file from GitHub and "
        "reload the proxy list into rotation. Use this after you suspect "
        "the proxy list is stale or after a network change. The PAC file "
        "is normally refreshed every 12 hours automatically."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

# ---------------------------------------------------------------------------
# /pac_blacklist — show or clear the blacklist
# ---------------------------------------------------------------------------

PAC_BLACKLIST_SCHEMA = {
    "name": "pac_blacklist",
    "description": (
        "Show all currently blacklisted SOCKS5 proxies (failed within "
        "the last 24 hours) or clear the blacklist manually. "
        "Failed proxies are automatically removed from rotation for 24h "
        "and the blacklist is cleared every 24h automatically. "
        "Use this to inspect failure history or force-clear when you "
        "know the proxies are working again."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "description": "'show' (default) to list blacklisted proxies, 'clear' to empty the blacklist",
                "enum": ["show", "clear"],
                "default": "show",
            },
        },
        "required": [],
    },
}

# ---------------------------------------------------------------------------
# /pac_cycle — force proxy rotation now
# ---------------------------------------------------------------------------

PAC_CYCLE_SCHEMA = {
    "name": "pac_cycle",
    "description": (
        "Force immediate rotation to a new random SOCKS5 proxy, "
        "resetting the 3-minute timer. Use this if the current proxy "
        "feels slow and you want to switch without waiting for the "
        "normal rotation window."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}
