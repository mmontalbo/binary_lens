"""Pack filesystem helpers.

These helpers are used by the exporter to write a diff-friendly context pack.
The JSON formatting (indentation, sorted keys, ASCII escaping) is intentionally
stable because it is part of the workflow for reviewing output changes.
"""

from __future__ import annotations

import json
import os
from typing import Any

PathLike = str | os.PathLike[str]


def ensure_dir(path: PathLike) -> None:
    os.makedirs(path, exist_ok=True)


def write_json(path: PathLike, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True))
        handle.write("\n")


def write_text(path: PathLike, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def pack_path(*parts: str) -> str:
    return "/".join(parts)
