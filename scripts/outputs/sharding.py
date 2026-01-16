"""Helpers for sharded list outputs."""

from __future__ import annotations

import re
from typing import Any, Mapping

from outputs.io import pack_path

DEFAULT_SHARD_SIZE = 200


def _safe_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return cleaned or "item"


def _collect_item_ids(items: list[Any], item_id_key: str | None) -> list[str] | None:
    if not item_id_key:
        return None
    safe_ids: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            return None
        raw = item.get(item_id_key)
        if not isinstance(raw, str) or not raw.strip():
            return None
        safe = _safe_component(raw)
        if safe in seen:
            return None
        seen.add(safe)
        safe_ids.append(safe)
    return safe_ids


def build_sharded_list_index(
    payload: Mapping[str, Any],
    *,
    list_key: str,
    shard_dir: str,
    item_id_key: str | None,
    item_kind: str,
    shard_size: int = DEFAULT_SHARD_SIZE,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split a list payload into an index + shard payloads."""
    items_raw = payload.get(list_key)
    items = list(items_raw) if isinstance(items_raw, list) else []

    safe_ids = _collect_item_ids(items, item_id_key)
    shards: list[dict[str, Any]] = []
    shard_payloads: dict[str, Any] = {}

    if safe_ids is not None:
        strategy = "by_id"
        for item, safe_id in zip(items, safe_ids):
            rel_path = pack_path(shard_dir, f"{safe_id}.json")
            shard_payloads[rel_path] = {list_key: [item]}
            shard_entry = {"path": rel_path, "count": 1}
            if item_id_key and isinstance(item, Mapping):
                shard_entry["id"] = item.get(item_id_key)
            shards.append(shard_entry)
    else:
        strategy = "chunked"
        size = shard_size if shard_size > 0 else DEFAULT_SHARD_SIZE
        for offset in range(0, len(items), size):
            chunk = items[offset : offset + size]
            shard_index = offset // size + 1
            rel_path = pack_path(shard_dir, f"shard_{shard_index:03d}.json")
            shard_payloads[rel_path] = {list_key: chunk}
            shard_entry = {"path": rel_path, "count": len(chunk), "start_index": offset}
            if chunk:
                shard_entry["end_index"] = offset + len(chunk) - 1
            shards.append(shard_entry)

    index_payload = dict(payload)
    index_payload.pop(list_key, None)
    index_payload["format"] = "sharded_list/v1"
    index_payload["item_kind"] = item_kind
    index_payload["list_key"] = list_key
    index_payload["total_items"] = len(items)
    index_payload["shard_strategy"] = strategy
    if strategy == "chunked":
        index_payload["shard_size"] = size
    index_payload["shards"] = shards
    index_payload["shard_count"] = len(shards)

    return index_payload, shard_payloads
