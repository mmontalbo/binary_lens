"""Table-dispatch entrypoint shim.

Historically, `modes/table_dispatch.py` hosted all table-dispatch heuristics (memory
scanning, candidate discovery, site attachment, token projection). To keep the modes
package navigable, the implementation is now split into focused modules:
- `modes/table_dispatch_scan.py` (memory decoding + record parsing)
- `modes/table_dispatch_candidates.py` (discovery strategies)
- `modes/table_dispatch_payload.py` (payload shaping helpers)

This module preserves the import path used by the modes exporter.
"""

from modes.table_dispatch_candidates import _collect_table_dispatch_mode_candidates
from modes.table_dispatch_payload import (
    _attach_table_dispatch_sites,
    _collect_table_dispatch_site_infos,
    _collect_table_dispatch_tokens,
)
from modes.table_dispatch_scan import _collect_table_dispatch_targets

__all__ = [
    "_attach_table_dispatch_sites",
    "_collect_table_dispatch_mode_candidates",
    "_collect_table_dispatch_site_infos",
    "_collect_table_dispatch_targets",
    "_collect_table_dispatch_tokens",
]

