"""Path helpers for the on-disk context pack layout."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class PackLayout:
    """Computed paths for a `binary.lens` pack on disk."""

    root: Path
    docs_dir: Path
    schema_dir: Path
    views_dir: Path
    facts_dir: Path
    evidence_dir: Path
    evidence_decomp_dir: Path

    @classmethod
    def from_root(cls, pack_root: str | Path) -> "PackLayout":
        root = Path(pack_root)
        return cls(
            root=root,
            docs_dir=root / "docs",
            schema_dir=root / "schema",
            views_dir=root / "views",
            facts_dir=root / "facts",
            evidence_dir=root / "evidence",
            evidence_decomp_dir=root / "evidence" / "decomp",
        )

    def iter_dirs(self) -> Iterable[Path]:
        return (
            self.root,
            self.docs_dir,
            self.schema_dir,
            self.views_dir,
            self.facts_dir,
            self.evidence_dir,
            self.evidence_decomp_dir,
        )
