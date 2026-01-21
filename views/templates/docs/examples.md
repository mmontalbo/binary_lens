# DuckDB recipes: `{{binary_name}}`

These examples show how to query Parquet facts with DuckDB. Prefer `views/run.py`;
it chdirs to the pack root so evidence paths resolve.

Recommended:

```sh
python views/run.py --pack .
```

If you use `nix develop`:

```sh
nix develop -c python views/run.py --pack .
```

Advanced/manual DuckDB (requires `cd` to pack root first):

```sh
cd /path/to/binary.lens
duckdb -c ".read views/queries/load_tables.sql"
```

Schema details (including `function_addr_int` and `callsite_addr_int`) are in
`schema/README.md`.

SQL blocks below point to the canonical query sources under `views/queries/`.

## Example: execution roots

```sql
-- SQL: views/queries/examples_execution_roots.sql
```

Results (first 25 rows):

{{example_execution_roots_table}}

## Recipe: canonical ordering by address

Use the numeric address helpers for stable ordering.

```sql
-- SQL: views/queries/examples_canonical_ordering.sql
```

Results (first 25 rows):

{{example_canonical_ordering_table}}

## Recipe: reachability from roots

```sql
-- SQL: views/queries/examples_reachability.sql
```

Results (first 25 rows):

{{example_reachability_table}}

## Recipe: env vars touched

```sql
-- SQL: views/queries/examples_env_vars.sql
```

Results (first 25 rows):

{{example_env_vars_table}}

## Recipe: stderr/output templates (heuristic)

```sql
-- SQL: views/queries/examples_output_templates.sql
```

Results (first 25 rows):

{{example_output_templates_table}}

## Recipe: usage-marker strings

```sql
-- SQL: views/queries/examples_usage_strings.sql
```

Results (first 25 rows):

{{example_usage_strings_table}}

## Recipe: observed arg-recovery call targets

Shows which callees had argument recovery applied in this pack.

```sql
-- SQL: views/queries/examples_observed_arg_targets.sql
```

Results (first 25 rows):

{{example_observed_arg_targets_table}}

## Recipe: ordered help-text strings from evidence (decoded)

Run via `views/run.py` (preferred). This focuses on gettext-family callsites
(`dcgettext` line + the following line) to reduce unrelated literals.

```sql
-- SQL: views/queries/examples_evidence_usage_text.sql
```

Results (first 50 rows):

{{example_evidence_usage_text_table}}

`literal_display` re-escapes newlines/tabs/returns for Markdown tables; use `literal_decoded` to reconstruct output.

## Recipe: quoted usage/help strings from evidence

Run via `views/run.py` (preferred) so `evidence/decomp/*.json` resolves. If using DuckDB
directly, `cd` to the pack root first.

```sql
-- SQL: views/queries/examples_evidence_usage_quotes.sql
```

Results (first 25 rows):

{{example_evidence_usage_quotes_table}}

## Recipe: usage/help coverage snapshot

Run via `views/run.py` (preferred) so `evidence/index.json` resolves. If using DuckDB
directly, `cd` to the pack root first. Adjust the `usage_help_functions` view
definition (or replace it) to match the functions you care about.

```sql
-- SQL: views/queries/examples_usage_coverage.sql
```

Results (first 25 rows):

{{example_usage_coverage_table}}

## Cookbook: multicall heuristics

These are heuristics for common multicall patterns; expect false negatives.

### `_usage_*` helpers

```sql
-- SQL: views/queries/examples_usage_functions.sql
```

Results (first 25 rows):

{{example_usage_functions_table}}

### `single_binary_main_*` dispatch

```sql
-- SQL: views/queries/examples_single_binary_main.sql
```

Results (first 25 rows):

{{example_single_binary_main_table}}

### argv0/mode token candidates (strcmp/strncmp)

Uses best-effort `callsite_arg_observations` for the strcmp/strncmp family.

```sql
-- SQL: views/queries/examples_argv0_tokens.sql
```

Results (first 25 rows):

{{example_argv0_tokens_table}}

## Recipe: exit callsites

```sql
-- SQL: views/queries/examples_exit_callsites.sql
```

Results (first 25 rows):

{{example_exit_callsites_table}}

## Recipe: top external calls

```sql
-- SQL: views/queries/examples_top_external_calls.sql
```

Results (first 25 rows):

{{example_top_external_calls_table}}
