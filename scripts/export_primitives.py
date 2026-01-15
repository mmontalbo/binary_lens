"""Low-level exporter primitives.

This module holds small, dependency-free helpers shared across collectors,
derivations, and writers (address formatting, stable identifiers, symbol name
normalization).
"""

from __future__ import annotations

from typing import Any

SALIENCE_TAGS: set[str] = {"env_var", "usage", "format", "path"}


def addr_str(addr: Any) -> str | None:
    if addr is None:
        return None
    try:
        return addr.toString()
    except Exception:
        try:
            return str(addr)
        except Exception:
            return None


def addr_to_int(addr_text: str | None) -> int:
    if addr_text is None:
        return -1
    try:
        text = addr_text
        if ":" in text:
            text = text.split(":")[-1]
        return int(text, 16)
    except Exception:
        return -1


def sanitize_addr_id(addr_text: str | None) -> str:
    if addr_text is None:
        return "unknown"
    return addr_text.replace(":", "_").replace("0x", "")


def addr_id(prefix: str, addr_text: str | None) -> str:
    return f"{prefix}_{sanitize_addr_id(addr_text)}"


def addr_filename(prefix: str, addr_text: str | None, ext: str) -> str:
    return f"{addr_id(prefix, addr_text)}.{ext}"


def normalize_symbol_name(name: str | None) -> str | None:
    if name is None:
        return None
    base = name
    if "@" in base:
        base = base.split("@")[0]
    if base.startswith("_"):
        base = base[1:]
    return base
