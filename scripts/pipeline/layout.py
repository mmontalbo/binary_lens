"""Path helpers for the on-disk context pack layout."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class PackLayout:
    """Computed paths for a `binary.lens` pack on disk."""

    root: Path
    functions_dir: Path
    cli_dir: Path
    errors_dir: Path
    modes_dir: Path
    evidence_decomp_dir: Path
    evidence_callsites_dir: Path

    @classmethod
    def from_root(cls, pack_root: str | Path) -> "PackLayout":
        root = Path(pack_root)
        evidence_dir = root / "evidence"
        return cls(
            root=root,
            functions_dir=root / "functions",
            cli_dir=root / "cli",
            errors_dir=root / "errors",
            modes_dir=root / "modes",
            evidence_decomp_dir=evidence_dir / "decomp",
            evidence_callsites_dir=evidence_dir / "callsites",
        )

    def iter_dirs(self) -> Iterable[Path]:
        return (
            self.root,
            self.functions_dir,
            self.cli_dir,
            self.errors_dir,
            self.modes_dir,
            self.evidence_decomp_dir,
            self.evidence_callsites_dir,
        )

