"""Handler candidate extraction for mode dispatch heuristics.

Mode dispatch sites often compare an argument token and then jump to a handler
function (or assign a function pointer) based on that token. This module contains
heuristics for extracting potential handler names from decompiler C output and
filtering out common non-handler functions.
"""

from __future__ import annotations

import re

from collectors.cli import CLI_COMPARE_SIGNAL_NAMES
from export_primitives import normalize_symbol_name

_HANDLER_ASSIGN_RE = re.compile(r"=\s*(?:\([^)]+\)\s*)*&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*;")
_HANDLER_RETURN_RE = re.compile(r"\breturn\s+([A-Za-z_][A-Za-z0-9_]*)\b")

_MODE_HANDLER_IGNORE_NAMES = set(
    [
        "abort",
        "argp_parse",
        "calloc",
        "dcgettext",
        "dgettext",
        "errno_location",
        "exit",
        "fprintf",
        "free",
        "getopt",
        "getopt_long",
        "getopt_long_only",
        "gettext",
        "libc_csu_fini",
        "libc_csu_init",
        "libc_start_main",
        "malloc",
        "memchr",
        "memcmp",
        "memcpy",
        "memmove",
        "memset",
        "ngettext",
        "perror",
        "printf",
        "putchar",
        "puts",
        "realloc",
        "snprintf",
        "sprintf",
        "strchr",
        "strcmp",
        "strcpy",
        "strdup",
        "strncasecmp",
        "strncmp",
        "strncpy",
        "strndup",
        "strrchr",
        "strstr",
        "strlen",
    ]
)
_MODE_HANDLER_IGNORE_NAMES.update(set(CLI_COMPARE_SIGNAL_NAMES))


def _normalize_handler_name(name):
    if not name:
        return None
    return normalize_symbol_name(name)


def _is_ignored_handler_name(name):
    norm = _normalize_handler_name(name)
    if not norm:
        return True
    return norm in _MODE_HANDLER_IGNORE_NAMES


def _extract_token_block_lines(lines, start_idx, max_lines):
    block = []
    brace_level = 0
    saw_open = False
    semicolon_idx = None
    limit = min(len(lines), start_idx + max_lines)
    for idx in range(start_idx, limit):
        line = lines[idx]
        block.append(line)
        brace_level += line.count("{") - line.count("}")
        if brace_level > 0:
            saw_open = True
        if saw_open and brace_level <= 0 and idx > start_idx:
            break
        if semicolon_idx is None and ";" in line:
            semicolon_idx = idx
        # If we haven't entered a brace-delimited block yet, keep a small lookahead
        # past the terminating semicolon so we can capture `if (...) { ... }` that
        # follows a wrapped compare call like `strcmp(\"token\",\\n param)`.
        if semicolon_idx is not None and not saw_open:
            if idx >= semicolon_idx + 3:
                break
    return block


def _extract_handler_names(lines):
    if not lines:
        return []
    text = "\n".join(lines)
    names = []
    for match in _HANDLER_ASSIGN_RE.finditer(text):
        names.append(match.group(1))
    for match in _HANDLER_RETURN_RE.finditer(text):
        names.append(match.group(1))
    return names


def _extract_handler_candidates_from_decomp(decomp_text, token_literal, max_lines=12):
    if not decomp_text or not token_literal:
        return []
    lines = decomp_text.splitlines()
    seen = set()
    candidates = []
    for idx, line in enumerate(lines):
        if token_literal not in line:
            continue
        block = _extract_token_block_lines(lines, idx, max_lines)
        for name in _extract_handler_names(block):
            if name in seen:
                continue
            seen.add(name)
            candidates.append(name)
    return candidates


def _is_usage_like_handler_name(name):
    if not name:
        return False
    lowered = name.lower()
    if lowered.startswith("_usage_"):
        return True
    if "usage" in lowered:
        return True
    return False
