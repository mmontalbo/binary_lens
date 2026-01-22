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

Quick health check: start with `pack_summary.json` (bounds, coverage summary, and row counts).

## Facts summary (row counts)

- callgraph_nodes: {{callgraph_nodes_count}}
- call_edges: {{call_edges_count}}
- callsites: {{callsites_count}}
- callsite_arg_observations: {{callsite_arg_observations_count}}
- strings: {{strings_count}}

## Quick start (views/run.py)

Render pack views and load tables:

```sh
python views/run.py --pack .
```

If you use `nix develop`:

```sh
nix develop -c python views/run.py --pack .
```

Then run queries or open `docs/examples.md`. `views/run.py` needs Python + `duckdb`,
and it chdirs to the pack root so evidence paths resolve.

Advanced/manual DuckDB (requires `cd` to pack root first):

```sh
cd /path/to/binary.lens
duckdb -c ".read views/queries/load_tables.sql"
```

## Create your first lens

1. Write a SQL query at `views/queries/<lens>.sql` (DuckDB SQL).
2. Register it in `views/index.json` with an `id` + `output_path` + `query_ref`.
3. Render it from the pack root:

```sh
python views/run.py --pack . --view <id>
```

Outputs land at the `output_path` you choose (e.g., `man/<lens>.json`, `docs/<lens>.md`, `execution/<lens>.json`).
JSON outputs include `_lens` metadata; Markdown outputs append a `<!-- lens: ... -->` comment with the reproduce recipe.

Example view entry:

```json
{
  "id": "man/<lens>.json",
  "output_path": "man/<lens>.json",
  "query_ref": "views/queries/<lens>.sql",
  "output_format": "json"
}
```

## Evidence excerpts

- `evidence/index.json`: bounded registry of available decompiler excerpts.
- `evidence/decomp/f_<function_id>.json`: decompiler excerpt for a function.
- Evidence index entries include `truncated`, `excerpt_line_count`, and `max_lines_applied` to show completeness.

## Evidence steering (re-export)

Re-export the pack with `key=value` overrides to force-include extra functions
into `evidence/decomp/`:

- `evidence_include_name_regex=...`
- `evidence_include_function_ids=0x401000,0x402000`

Applied hints are recorded in `manifest.json` and remain bounded by
`max_full_functions`.

## Entry points

- index.json
- pack_summary.json
- facts/index.json
- views/index.json
- views/queries/string_occurrences.sql
- execution/roots.json
- execution/sinks.json
- docs/examples.md
- schema/README.md
