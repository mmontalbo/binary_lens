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

## Views

- `views/index.json`: view definitions
- `views/run.py`: view renderer
- `views/queries/`: SQL sources
- `execution/sinks.json`: termination sinks (`kind`: `exit`, `abort`, `return_from_main`)
