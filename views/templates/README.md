# `binary_lens` pack: `{{binary_name}}`

This pack contains Parquet facts, DuckDB SQL lenses, and bounded evidence excerpts.

## Pack snapshot

- binary: `{{binary_name}}`
- sha256: `{{binary_sha256}}`
- executable_format: {{executable_format}}
- target_arch: {{target_arch}}
- ghidra_version: {{ghidra_version}}
- binary_lens_version: {{binary_lens_version}}
- pack_format_version: {{pack_format_version}}

## Facts summary (row counts)

- callgraph_nodes: {{callgraph_nodes_count}}
- call_edges: {{call_edges_count}}
- callsites: {{callsites_count}}
- callsite_arg_observations: {{callsite_arg_observations_count}}
- strings: {{strings_count}}

## Quick start (DuckDB)

Load tables:

```sh
duckdb -c ".read views/queries/load_tables.sql"
```

Then run queries or open `docs/examples.md`. To re-render pack views:

```sh
python views/run.py --pack .
```

## Evidence excerpts

- `evidence/index.json`: bounded registry of available decompiler excerpts.
- `evidence/decomp/f_<function_id>.json`: decompiler excerpt for a function.

## Entry points

- index.json
- facts/index.json
- views/index.json
- execution/roots.json
- execution/sinks.json
- docs/examples.md
- schema/README.md
