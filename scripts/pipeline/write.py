"""Write stage for the context pack export pipeline."""

from __future__ import annotations

from typing import Any

from export_bounds import Bounds
from export_primitives import addr_filename
from outputs.io import ensure_dir, pack_path, write_json, write_text
from outputs.writers import write_function_exports
from pipeline.layout import PackLayout
from pipeline.phases import phase
from pipeline.types import CollectedData, DerivedPayloads


def write_outputs(
    program: Any,
    collected: CollectedData,
    derived: DerivedPayloads,
    layout: PackLayout,
    bounds: Bounds,
    monitor: Any,
    profiler: Any,
) -> None:
    with phase(profiler, "write_function_exports"):
        write_function_exports(
            program,
            derived.full_functions,
            bounds,
            collected.string_refs_by_func,
            collected.selected_string_ids,
            collected.string_tags_by_id,
            collected.string_value_by_id,
            derived.calls_by_func,
            layout.functions_dir,
            layout.evidence_decomp_dir,
            monitor,
        )

    with phase(profiler, "write_outputs"):
        ensure_dir(layout.root / "strings")
        ensure_dir(layout.root / "callgraph" / "edges")
        ensure_dir(layout.root / "callgraph" / "nodes")
        ensure_dir(layout.modes_dir / "slices")
        ensure_dir(layout.cli_dir / "parse_loops")
        ensure_dir(layout.cli_dir / "options")
        ensure_dir(layout.errors_dir / "messages")
        ensure_dir(layout.errors_dir / "exit_paths")
        ensure_dir(layout.errors_dir / "error_sites")
        ensure_dir(layout.interfaces_dir / "env")
        ensure_dir(layout.interfaces_dir / "fs")
        ensure_dir(layout.interfaces_dir / "process")
        ensure_dir(layout.interfaces_dir / "net")
        ensure_dir(layout.interfaces_dir / "output")
        ensure_dir(layout.contracts_dir / "index")
        ensure_dir(layout.contracts_dir / "modes")
        ensure_dir(layout.functions_dir / "index")

        for callsite, record in derived.callsite_evidence.items():
            rel_path = pack_path("evidence", "callsites", addr_filename("cs", callsite, "json"))
            write_json(layout.root / rel_path, record)

        write_json(layout.root / "index.json", derived.pack_index_payload)
        write_json(layout.root / "manifest.json", derived.manifest)
        write_json(layout.root / "binary.json", collected.binary_info)
        write_json(layout.root / "imports.json", collected.imports)
        write_json(layout.root / "strings.json", derived.strings_index)
        write_json(layout.root / "callgraph.json", derived.callgraph_index)
        write_json(layout.root / "callgraph" / "nodes.json", derived.callgraph_nodes_index)
        write_json(layout.errors_dir / "messages.json", derived.error_messages_index)
        write_json(layout.errors_dir / "exit_paths.json", derived.exit_paths_index)
        write_json(layout.errors_dir / "error_sites.json", derived.error_sites_index)
        write_json(layout.modes_dir / "index.json", collected.modes_payload)
        write_json(layout.modes_dir / "dispatch_sites.json", collected.dispatch_sites_payload)
        write_json(layout.modes_dir / "slices.json", derived.modes_slices_index)
        write_json(layout.interfaces_dir / "index.json", collected.interfaces_index_payload)
        write_json(layout.interfaces_dir / "env.json", derived.interfaces_env_index)
        write_json(layout.interfaces_dir / "fs.json", derived.interfaces_fs_index)
        write_json(layout.interfaces_dir / "process.json", derived.interfaces_process_index)
        write_json(layout.interfaces_dir / "net.json", derived.interfaces_net_index)
        write_json(layout.interfaces_dir / "output.json", derived.interfaces_output_index)
        write_json(layout.cli_dir / "options.json", derived.cli_options_index)
        write_json(layout.cli_dir / "parse_loops.json", derived.cli_parse_loops_index)
        write_json(layout.contracts_dir / "index.json", derived.contracts_index)
        for rel_path, content in derived.modes_slices_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.cli_parse_loops_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.strings_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.callgraph_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.callgraph_nodes_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.cli_options_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.error_messages_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.exit_paths_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.error_sites_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.interfaces_env_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.interfaces_fs_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.interfaces_process_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.interfaces_net_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.interfaces_output_shards.items():
            write_json(layout.root / rel_path, content)
        for rel_path, content in derived.contracts_shards.items():
            write_json(layout.root / rel_path, content)
        write_json(layout.functions_dir / "index.json", derived.functions_index)
        for rel_path, content in derived.functions_index_shards.items():
            write_json(layout.root / rel_path, content)
        write_text(layout.root / "README.md", derived.pack_readme)
        for rel_path, content in derived.pack_docs.items():
            write_text(layout.root / rel_path, content)
        for rel_path, content in derived.contract_docs.items():
            write_text(layout.root / rel_path, content)
