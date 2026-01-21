# Development Workflow

This document captures the local dev workflow for `binary_lens`. The flake is the source
of truth for dependencies and the preferred way to run the exporter.

## Run the exporter (recommended)

The `binary_lens` wrapper mirrors the intended CLI surface and runs the end-to-end
headless pipeline via PyGhidra.

```sh
nix run .#binary_lens -- /path/to/binary -o /path/to/out
```

From another directory, point at the flake path:

```sh
nix run /path/to/binary_lens#binary_lens -- /path/to/binary -o /path/to/out
```

The output directory defaults to `out/`, so you can omit `-o`:

```sh
nix run .#binary_lens -- /path/to/binary
```

The wrapper can also resolve binaries from `PATH`:

```sh
nix run .#binary_lens -- ls -o /path/to/out
```

You can pass exporter bounds as `key=value` arguments:

```sh
nix run .#binary_lens -- /path/to/binary -o /path/to/out max_full_functions=50 max_strings=200
```

Output is written to `/path/to/out/binary.lens/`.

## Re-render views from an existing pack

This runs the view renderer only and does not require Ghidra.

```sh
nix run .#binary_lens -- /path/to/out/binary.lens
nix run .#binary_lens -- /path/to/out
```

## Enter the dev shell (for development)

```sh
nix develop
```

The dev shell provides:
- Ghidra (Linux) and its PyGhidra components
- Python with `pyghidra`, `duckdb`, and `pyarrow`
- `binary_lens` wrapper CLI
- DuckDB CLI (`duckdb`)

It also exports:
- `GHIDRA_INSTALL_DIR`
- `BINARY_LENS_GHIDRA_HEADLESS`
- `BINARY_LENS_GHIDRA_VERSION`

Notes:

- Linux shells include the `ghidra` package; on other platforms, install Ghidra separately.
- `nix fmt` runs the `alejandra` formatter for `flake.nix`.

## Notes and troubleshooting

- The exporter is a PyGhidra script. Running `analyzeHeadless` directly will not
  execute Python scripts unless launched via PyGhidra.
- If you see `GHIDRA_INSTALL_DIR is not set`, run exports via `nix run .#binary_lens -- ...`
  or enter the dev shell. For view rendering, pass a pack root (binary.lens).
- The wrapper defaults to an in-store source snapshot; set `BINARY_LENS_ROOT=/path/to/binary_lens`
  to use a working tree with local edits.

## Git hooks

Hooks live in `tools/git_hooks/`. The pre-commit hook runs `ruff check .`, and the
commit-msg hook runs `tools/lint_commit.py`. Install them locally by copying or
symlinking into `.git/hooks/`.

## Linting

```sh
ruff check .
```

Auto-fix import order and safe lint issues:

```sh
ruff check --fix .
```

## Output layout (high level)

- `binary.lens/README.md`: pack overview and entrypoints
- `binary.lens/manifest.json`: export bounds + versions
- `binary.lens/index.json`: entrypoints + conventions
- `binary.lens/facts/index.json`: Parquet table registry
- `binary.lens/facts/*.parquet`: canonical facts
- `binary.lens/views/index.json`: lens definitions + sources
- `binary.lens/execution/roots.json`: entry roots (SQL lens)
- `binary.lens/execution/sinks.json`: termination sinks (SQL lens)
- `binary.lens/docs/examples.md`: DuckDB query recipes (with deterministic sample results)
- `binary.lens/evidence/index.json`: bounded decompiler excerpt registry

## Validation (Milestone 5)

Regenerate git + coreutils packs:

```sh
nix develop -c binary_lens /etc/profiles/per-user/mmontalbo/bin/git -o out/profile_git_m5_duckdb profile=1 analysis_profile=full
nix develop -c binary_lens coreutils -o out/profile_coreutils_m5_duckdb profile=1 analysis_profile=full
```

Run fast checks (no Ghidra):

```sh
python tools/check_pack_refs.py out/profile_git_m5_duckdb/binary.lens --include-docs
nix develop -c python tools/check_lens_repro.py out/profile_git_m5_duckdb/binary.lens
python tools/check_pack_refs.py out/profile_coreutils_m5_duckdb/binary.lens --include-docs
nix develop -c python tools/check_lens_repro.py out/profile_coreutils_m5_duckdb/binary.lens
```
