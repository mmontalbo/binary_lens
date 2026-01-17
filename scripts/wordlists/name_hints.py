"""Load explicit name-hint wordlists used by optional heuristics.

The exporter uses some symbol/function-name patterns to improve mode detection
and help/usage discoverability. These patterns are easy to bake into code and
then forget; keeping them in a wordlist makes the behavior explicit and
configurable.

By default, the exporter loads `name_hints_default.json`. A custom wordlist can
be provided via:
- exporter options: `name_hints_wordlist=/path/to/file.json`
- environment: `BINARY_LENS_NAME_HINTS_WORDLIST=/path/to/file.json`
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from export_bounds import Bounds

_DEFAULT_WORDLIST_PATH = Path(__file__).with_name("name_hints_default.json")
_CACHE: dict[str, "NameHints"] = {}


def _unique_strs(values: Any) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return tuple(out)


def _resolve_repo_root() -> Path:
    # scripts/wordlists/name_hints.py -> scripts/wordlists -> scripts -> repo root
    return Path(__file__).resolve().parents[2]


def _resolve_wordlist_path(source: Bounds | Mapping[str, Any] | None) -> Path:
    option_path = None
    if isinstance(source, Bounds):
        option_path = source.get("name_hints_wordlist")
    elif isinstance(source, Mapping):
        option_path = source.get("name_hints_wordlist")
    env_path = os.environ.get("BINARY_LENS_NAME_HINTS_WORDLIST")
    chosen = option_path if isinstance(option_path, str) and option_path.strip() else env_path
    if not isinstance(chosen, str) or not chosen.strip():
        return _DEFAULT_WORDLIST_PATH
    path = Path(chosen.strip())
    if not path.is_absolute():
        path = (_resolve_repo_root() / path).resolve()
    return path


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def name_hints_enabled(source: Bounds | Mapping[str, Any] | None) -> bool:
    value: Any = 1
    if isinstance(source, Bounds):
        value = source.enable_mode_name_heuristics
    elif isinstance(source, Mapping):
        value = source.get("enable_mode_name_heuristics", 1)
    try:
        return int(value) != 0
    except Exception:
        return bool(value)


@dataclass(frozen=True)
class NameHints:
    schema_version: int
    entry_function_names_always: tuple[str, ...]
    entry_function_names_enabled: tuple[str, ...]
    handler_prefixes: tuple[str, ...]
    handler_exclude_names: tuple[str, ...]
    table_dispatch_symbol_names: tuple[str, ...]
    table_dispatch_symbol_regexes: tuple[str, ...]
    help_function_keywords: tuple[str, ...]
    help_function_prefixes: tuple[str, ...]
    usage_like_function_keywords: tuple[str, ...]
    usage_like_function_prefixes: tuple[str, ...]

    @classmethod
    def from_raw(cls, raw: Mapping[str, Any]) -> "NameHints":
        version = raw.get("schema_version")
        try:
            version_int = int(version)
        except Exception:
            version_int = 1
        return cls(
            schema_version=version_int,
            entry_function_names_always=_unique_strs(raw.get("entry_function_names_always")),
            entry_function_names_enabled=_unique_strs(raw.get("entry_function_names_enabled")),
            handler_prefixes=_unique_strs(raw.get("handler_prefixes")),
            handler_exclude_names=_unique_strs(raw.get("handler_exclude_names")),
            table_dispatch_symbol_names=_unique_strs(raw.get("table_dispatch_symbol_names")),
            table_dispatch_symbol_regexes=_unique_strs(raw.get("table_dispatch_symbol_regexes")),
            help_function_keywords=_unique_strs(raw.get("help_function_keywords")),
            help_function_prefixes=_unique_strs(raw.get("help_function_prefixes")),
            usage_like_function_keywords=_unique_strs(raw.get("usage_like_function_keywords")),
            usage_like_function_prefixes=_unique_strs(raw.get("usage_like_function_prefixes")),
        )


def load_name_hints(source: Bounds | Mapping[str, Any] | None = None) -> NameHints:
    """Load the default wordlist, optionally overlayed with a custom file."""

    path = _resolve_wordlist_path(source)
    cache_key = str(path)
    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    default_raw = _read_json(_DEFAULT_WORDLIST_PATH)
    merged = dict(default_raw)
    if path != _DEFAULT_WORDLIST_PATH:
        merged.update(_read_json(path))

    hints = NameHints.from_raw(merged)
    _CACHE[cache_key] = hints
    return hints
