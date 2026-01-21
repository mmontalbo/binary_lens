# `binary_lens` pack format (v2)

This pack uses Parquet facts + DuckDB SQL lenses.

## Facts schema

{{schema_table}}

## Conventions

- `facts/index.json` declares table paths, primary keys, and schema versions.
- `function_id`, `callsite_id`, and `string_id` are stable join keys.
- Rendered view outputs include `_lens` metadata (sources + reproduce command).
- `manifest.json` records export metadata and coverage summary.
- `evidence/index.json` lists bounded evidence excerpts (see `evidence/decomp/`).
- Evidence entries include `truncated`, `excerpt_line_count`, and `max_lines_applied` so you can tell if a `_usage_*` excerpt is complete (`line_count` is full decomp size).

## Keys and ordering

- `function_id` is the function entry address (Ghidra address string).
- `callsite_id` is the call instruction address (Ghidra address string).
- Canonical ordering is increasing numeric address. Use `function_addr_int` and
  `callsite_addr_int` for ordering instead of lexicographic string sort.
- Symbol-name normalization (leading underscores, `__*_chk` wrappers, etc.)
  affects call target names, not these address keys.

## Views

- `views/index.json`: view definitions
- `views/run.py`: view renderer
- `views/queries/`: SQL sources
- `execution/sinks.json`: termination sinks (`kind`: `exit`, `abort`, `return_from_main`)
