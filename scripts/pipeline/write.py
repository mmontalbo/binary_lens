"""Write stage for the context pack export pipeline."""

from __future__ import annotations

import shutil
from typing import Any, Iterable

from export_bounds import Bounds
from outputs.io import ensure_dir, write_json, write_text
from outputs.writers import write_function_exports
from pipeline.layout import PackLayout
from pipeline.phases import phase
from pipeline.types import CollectedData, DerivedPayloads


def _remove_deprecated_function_index(layout: PackLayout) -> None:
    index_json = layout.functions_dir / "index.json"
    index_dir = layout.functions_dir / "index"
    for path in (index_json, index_dir):
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def _ensure_pack_dirs(layout: PackLayout) -> None:
    for path in (
        layout.root / "strings",
        layout.root / "callgraph" / "edges",
        layout.root / "callgraph" / "nodes",
        layout.modes_dir / "slices",
        layout.cli_dir / "parse_loops",
        layout.cli_dir / "options",
        layout.errors_dir / "messages",
        layout.errors_dir / "exit_paths",
        layout.errors_dir / "error_sites",
        layout.interfaces_dir / "env",
        layout.interfaces_dir / "fs",
        layout.interfaces_dir / "process",
        layout.interfaces_dir / "net",
        layout.interfaces_dir / "output",
        layout.contracts_dir / "index",
        layout.contracts_dir / "modes",
    ):
        ensure_dir(path)


def _write_json_payloads(items: Iterable[tuple[Any, Any]]) -> None:
    for path, payload in items:
        write_json(path, payload)


def _write_shards(layout: PackLayout, *shard_maps: dict[str, Any]) -> None:
    for shard_map in shard_maps:
        for rel_path, content in shard_map.items():
            write_json(layout.root / rel_path, content)


def write_outputs(
    program: Any,
    collected: CollectedData,
    derived: DerivedPayloads,
    layout: PackLayout,
    bounds: Bounds,
    monitor: Any,
    profiler: Any,
) -> None:
    _remove_deprecated_function_index(layout)

    with phase(profiler, "write_function_exports"):
        write_function_exports(
            program,
            derived.full_functions,
            bounds,
            collected.string_refs_by_func,
            collected.selected_string_ids,
            collected.string_tags_by_id,
            collected.string_value_by_id,
            layout.functions_dir,
            layout.evidence_decomp_dir,
            monitor,
        )

    with phase(profiler, "write_outputs"):
        _ensure_pack_dirs(layout)

        _write_json_payloads(
            [
                (layout.root / "index.json", derived.pack_index_payload),
                (layout.root / "manifest.json", derived.manifest),
                (layout.root / "evidence" / "callsites.json", derived.callsites_index),
                (layout.root / "strings.json", derived.strings_index),
                (layout.root / "callgraph.json", derived.callgraph_index),
                (layout.root / "callgraph" / "nodes.json", derived.callgraph_nodes_index),
                (layout.errors_dir / "messages.json", derived.error_messages_index),
                (layout.errors_dir / "exit_paths.json", derived.exit_paths_index),
                (layout.errors_dir / "error_sites.json", derived.error_sites_index),
                (layout.modes_dir / "index.json", collected.modes_payload),
                (layout.modes_dir / "slices.json", derived.modes_slices_index),
                (layout.interfaces_dir / "index.json", collected.interfaces_index_payload),
                (layout.interfaces_dir / "env.json", derived.interfaces_env_index),
                (layout.interfaces_dir / "fs.json", derived.interfaces_fs_index),
                (layout.interfaces_dir / "process.json", derived.interfaces_process_index),
                (layout.interfaces_dir / "net.json", derived.interfaces_net_index),
                (layout.interfaces_dir / "output.json", derived.interfaces_output_index),
                (layout.cli_dir / "options.json", derived.cli_options_index),
                (layout.cli_dir / "parse_loops.json", derived.cli_parse_loops_index),
                (layout.contracts_dir / "index.json", derived.contracts_index),
            ]
        )
        _write_shards(
            layout,
            derived.callsites_shards,
            derived.modes_slices_shards,
            derived.cli_parse_loops_shards,
            derived.strings_shards,
            derived.callgraph_shards,
            derived.callgraph_nodes_shards,
            derived.cli_options_shards,
            derived.error_messages_shards,
            derived.exit_paths_shards,
            derived.error_sites_shards,
            derived.interfaces_env_shards,
            derived.interfaces_fs_shards,
            derived.interfaces_process_shards,
            derived.interfaces_net_shards,
            derived.interfaces_output_shards,
            derived.contracts_shards,
        )
        write_text(layout.root / "README.md", derived.pack_readme)
        for rel_path, content in derived.pack_docs.items():
            write_text(layout.root / rel_path, content)
        for rel_path, content in derived.contract_docs.items():
            write_text(layout.root / rel_path, content)
