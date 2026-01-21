"""Bounds parsing and normalization for exporter limits."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from export_config import (
    DEFAULT_MAX_CALL_EDGES,
    DEFAULT_MAX_DECOMP_LINES,
    DEFAULT_MAX_FULL_FUNCTIONS,
    DEFAULT_MAX_STRINGS,
)

BOUND_OPTION_DEFAULTS: tuple[tuple[str, int], ...] = (
    ("max_full_functions", DEFAULT_MAX_FULL_FUNCTIONS),
    ("max_strings", DEFAULT_MAX_STRINGS),
    ("max_call_edges", DEFAULT_MAX_CALL_EDGES),
    ("max_decomp_lines", DEFAULT_MAX_DECOMP_LINES),
)

BOUND_KEYS = tuple(key for key, _default in BOUND_OPTION_DEFAULTS)
MANIFEST_BOUND_KEYS = BOUND_KEYS
UNBOUNDED_KEYS = {
    "max_strings",
    "max_call_edges",
}


def _parse_int(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


@dataclass(frozen=True)
class Bounds:
    """Normalized exporter bounds with defaults and legacy option passthrough."""

    max_full_functions: int
    max_strings: int
    max_call_edges: int
    max_decomp_lines: int
    _extra: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_options(cls, options: Mapping[str, Any] | None) -> Bounds:
        if isinstance(options, Bounds):
            return options
        options = options or {}
        values: dict[str, int] = {}
        for key, default in BOUND_OPTION_DEFAULTS:
            values[key] = _parse_int(options.get(key, default), default)

        extra = {key: value for key, value in options.items() if key not in values}
        return cls(**values, _extra=extra)

    @classmethod
    def defaults(cls) -> Bounds:
        return cls.from_options({})

    def to_options(self) -> dict[str, int]:
        return {key: getattr(self, key) for key in BOUND_KEYS}

    def get(self, key: str, default: Any | None = None) -> Any | None:
        if key in BOUND_KEYS:
            return getattr(self, key)
        return self._extra.get(key, default)

    def optional(self, key: str) -> int | None:
        value = self.get(key)
        if key in UNBOUNDED_KEYS:
            try:
                return int(value) if int(value) > 0 else None
            except Exception:
                return None
        return value

    def as_manifest(self) -> dict[str, int | None]:
        return {
            key: (self.optional(key) if key in UNBOUNDED_KEYS else self.get(key))
            for key in MANIFEST_BOUND_KEYS
        }
