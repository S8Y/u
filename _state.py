"""
PAC-API shared state — single reference to the active ProxyManager.

Both __init__.py and tools.py import this to avoid depending on
ctx.shared (which doesn't exist in Hermes PluginContext).
"""
_manager = None
