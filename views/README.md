# Views

This directory contains view sources shipped with the pack.

- `index.json` lists the default views and their sources.
- `queries/` contains DuckDB SQL sources for default lenses.
- `templates/` contains raw Markdown templates for text views.
- `run.py` renders views into their output paths.

The view runner loads Parquet facts into DuckDB and executes the SQL queries
deterministically. Rendered outputs include reproduce commands.

Example:

```sh
python views/run.py --pack . --view README.md
```
