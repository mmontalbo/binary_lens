"""Symbol normalization and matching helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True)
class SymbolNormalizationPolicy:
    casefold: bool = False
    strip_leading_underscores: int = 1
    strip_version_suffix: bool = True
    strip_glibc_prefix: bool = False
    strip_chk_suffix: bool = False
    strip_suffixes: tuple[str, ...] = ()


DEFAULT_SYMBOL_POLICY = SymbolNormalizationPolicy(
    casefold=False,
    strip_leading_underscores=1,
    strip_version_suffix=True,
)

IMPORT_SYMBOL_POLICY = SymbolNormalizationPolicy(
    casefold=True,
    strip_leading_underscores=-1,
    strip_version_suffix=True,
    strip_glibc_prefix=True,
    strip_chk_suffix=True,
)


IMPORT_ALIAS_GROUPS: dict[str, tuple[str, ...]] = {
    "getenv": ("__getenv", "secure_getenv", "getenv_s"),
    "setenv": ("__setenv", "setenv_s"),
    "unsetenv": ("__unsetenv",),
    "putenv": ("__putenv",),
    "open": ("open64", "__open", "__open_2", "__open64_2"),
    "openat": ("openat64", "__openat_2", "__openat64_2"),
    "fopen": ("fopen64", "__fopen", "__fopen64"),
    "freopen": ("freopen64", "__freopen", "__freopen64"),
    "stat": ("stat64",),
    "lstat": ("lstat64",),
    "fstat": ("fstat64",),
    "fstatat": ("fstatat64",),
}


def _strip_leading_underscores(value: str, count: int) -> str:
    if count == 0:
        return value
    if count < 0:
        return value.lstrip("_")
    current = value
    for _ in range(count):
        if not current.startswith("_"):
            break
        current = current[1:]
    return current


def normalize_symbol_name(
    name: str | None,
    *,
    policy: SymbolNormalizationPolicy = DEFAULT_SYMBOL_POLICY,
) -> str | None:
    if name is None:
        return None
    base = name
    if policy.strip_version_suffix and "@" in base:
        base = base.split("@", 1)[0]
    base = _strip_leading_underscores(base, policy.strip_leading_underscores)
    if policy.strip_glibc_prefix and base.startswith("GI_"):
        base = base[3:]
    if policy.strip_chk_suffix and base.endswith("_chk"):
        base = base[:-4]
    for suffix in policy.strip_suffixes:
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    if policy.casefold:
        base = base.lower()
    return base or None


def normalize_import_name(name: str | None) -> str | None:
    return normalize_symbol_name(name, policy=IMPORT_SYMBOL_POLICY)


def normalize_name_set(
    names: Iterable[str],
    *,
    policy: SymbolNormalizationPolicy = DEFAULT_SYMBOL_POLICY,
) -> set[str]:
    normalized = set()
    for name in names:
        norm = normalize_symbol_name(name, policy=policy)
        if norm:
            normalized.add(norm)
    return normalized


def build_name_map(
    canonical_to_names: Mapping[str, Iterable[str]],
    *,
    policy: SymbolNormalizationPolicy = IMPORT_SYMBOL_POLICY,
) -> dict[str, str]:
    name_map: dict[str, str] = {}
    for canonical, names in canonical_to_names.items():
        canon_norm = normalize_symbol_name(canonical, policy=policy)
        if not canon_norm:
            continue
        for name in names:
            norm = normalize_symbol_name(name, policy=policy)
            if norm:
                name_map[norm] = canonical
    return name_map


def build_alias_map(
    alias_groups: Mapping[str, Iterable[str]],
    *,
    policy: SymbolNormalizationPolicy = IMPORT_SYMBOL_POLICY,
) -> dict[str, str]:
    alias_map: dict[str, str] = {}
    for canonical, aliases in alias_groups.items():
        canon_norm = normalize_symbol_name(canonical, policy=policy)
        if not canon_norm:
            continue
        for alias in aliases:
            alias_norm = normalize_symbol_name(alias, policy=policy)
            if alias_norm:
                alias_map[alias_norm] = canonical
    return alias_map


@dataclass(frozen=True)
class MatchResult:
    canonical: str
    normalized: str
    kind: str


def match_signal(
    name: str | None,
    *,
    name_map: Mapping[str, str],
    alias_map: Mapping[str, str] | None = None,
    policy: SymbolNormalizationPolicy = IMPORT_SYMBOL_POLICY,
    allow_substring: bool = False,
) -> MatchResult | None:
    normalized = normalize_symbol_name(name, policy=policy)
    if not normalized:
        return None
    canonical = name_map.get(normalized)
    if canonical:
        return MatchResult(canonical=canonical, normalized=normalized, kind="exact")
    if alias_map:
        alias_target = alias_map.get(normalized)
        if alias_target:
            return MatchResult(canonical=alias_target, normalized=normalized, kind="alias")
    if allow_substring:
        for token, canonical in name_map.items():
            if token in normalized:
                return MatchResult(canonical=canonical, normalized=normalized, kind="substring")
    return None
