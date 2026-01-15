"""Mode ("Milestone 3") entrypoint shim.

Historically, `export_modes.py` hosted Milestone 3's mode extraction end-to-end.
To reduce cognitive overhead, the implementation now lives in the `modes/` package.

This module preserves the original import path used by:
- `scripts/binary_lens_export.py` (Ghidra script entrypoint)
- other export subsystems importing mode helpers
"""

from modes.candidates import collect_mode_candidates
from modes.slices import build_mode_slices
from modes.surface import attach_mode_callsite_refs, build_modes_surface

__all__ = [
    "attach_mode_callsite_refs",
    "build_mode_slices",
    "build_modes_surface",
    "collect_mode_candidates",
]
