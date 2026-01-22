# `binary_lens` pack format (v2)

This pack uses Parquet facts + DuckDB SQL lenses.

## Facts schema

{{schema_table}}

## Conventions

- `facts/index.json` declares table paths, primary keys, and schema versions.
- `function_id`, `callsite_id`, and `string_id` are stable join keys.
- Rendered view outputs include `_lens` metadata (sources + reproduce command + lens_schema_version).
- `manifest.json` records export metadata and coverage summary.
- `pack_summary.json` is a quick health check (bounds + coverage + row counts).
- `evidence/index.json` lists bounded evidence excerpts (see `evidence/decomp/`).
- Evidence entries include `truncated`, `excerpt_line_count`, and `max_lines_applied` so you can tell if a `_usage_*` excerpt is complete (`line_count` is full decomp size).

## Keys and ordering

- `function_id` is the function entry address (Ghidra address string).
- `callsite_id` is the call instruction address (Ghidra address string).
- Canonical ordering is increasing numeric address. Use `function_addr_int` and
  `callsite_addr_int` for ordering instead of lexicographic string sort.
- The string provenance recipe (`views/queries/string_occurrences.sql`) orders by
  `callsite_addr_int`, `arg_index`, `callsite_id`, `to_function_id`, and `observation_id`.
- Symbol-name normalization (leading underscores, `__*_chk` wrappers, etc.)
  affects call target names, not these address keys.

## Views

- `views/index.json`: view definitions
- `views/run.py`: view renderer
- `views/queries/`: SQL sources
- `views/queries/string_occurrences.sql`: string provenance join recipe
- `execution/sinks.json`: termination sinks (`kind`: `exit`, `abort`, `return_from_main`)

## `callsite_arg_observations` notes

Argument recovery is **best-effort** and only attempted for a curated allowlist
of call targets (string/env/dispatch helpers, printf-family, gettext-family,
etc.). The set may evolve over time; names are normalized under the import
symbol policy (leading underscores stripped, `__*_chk` suffix removed, and
similar wrappers) so callsites like `__printf_chk` are treated as `printf`.
Coverage depends on successful decompilation and constant-propagation; indirect
calls and non-constant pointers often yield no resolved args. To see what was
observed in this pack, use the "observed arg-recovery call targets" recipe in
`docs/examples.md` or run:

```sql
select
  lower(n.name) as callee,
  count(distinct e.callsite_id) as callsite_count
from call_edges e
join callsite_arg_observations a on a.callsite_id = e.callsite_id
join callgraph_nodes n on n.function_id = e.to_function_id
where n.name is not null
group by lower(n.name)
order by callsite_count desc, callee
limit 25;
```

Observed fields:
- `status`: `resolved` (string arg mapped to `string_id`), `unresolved` (string-like
  value seen but not in selected strings), `unknown` (no value recovered), or
  `known` (non-string value recovered; see `int_value`/`address`/`name`).
- `basis`: `string_direct` (string literal), `string_gettext` (gettext-like), `const_int`
  (constant integer), `data_address` (pointer into data), `symbol` (named symbol).

Rule of thumb: trust string args when `status=resolved` and `basis` is
`string_direct`/`string_gettext`; otherwise treat them as hints and pivot to
`strings.tags` and/or `evidence/decomp/` excerpts.

## `strings.tags` glossary

- `usage`: usage/help-like banner string (see `docs/examples.md` "usage-marker strings").
- `env_var`: likely environment variable name (see `docs/examples.md` "usage-marker strings" with `env_var`).
- `path`: filesystem path or path template (see `docs/examples.md` "usage-marker strings" with `path`).
- `format`: printf-style format string (see `docs/examples.md` "usage-marker strings" with `format`).
