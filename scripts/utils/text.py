"""Text and value helpers shared across the export pipeline."""

from __future__ import annotations

import re
from typing import Any


def as_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def safe_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return cleaned or "item"


def escape_preview(value: Any, limit: int = 160) -> str:
    if not isinstance(value, str) or not value:
        return ""
    escaped = value.replace("\\", "\\\\")
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    safe: list[str] = []
    for ch in escaped:
        code = ord(ch)
        if 32 <= code <= 126:
            safe.append(ch)
        else:
            safe.append("\\u%04x" % code)
    preview = "".join(safe)
    if limit and len(preview) > limit:
        preview = preview[: max(0, limit - 3)] + "..."
    return preview


def string_ref_status(
    string_id: str | None,
    address: str | None,
    *,
    value: Any | None = None,
) -> str:
    if string_id:
        return "resolved"
    if address or value is not None:
        return "unresolved"
    return "unknown"


def is_help_marker_value(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    lowered = value.lower()
    if "usage:" in lowered:
        return True
    if "--help" in value:
        return True
    if "try '" in lowered or "try \"" in lowered:
        return True
    if "options:" in lowered or "options\n" in lowered:
        return True
    if "report bugs" in lowered or "reporting bugs" in lowered:
        return True
    return False


def has_usage_tag(tags: Any) -> bool:
    if not tags:
        return False
    if isinstance(tags, set):
        return "usage" in tags
    if isinstance(tags, (list, tuple)):
        return "usage" in tags
    return False
