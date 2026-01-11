# Development Workflow

This document captures the local dev workflow for Binary Lens. The flake is the source
of truth for dependencies and the preferred way to run the exporter.

## Enter the dev shell

```sh
nix develop
```

The dev shell provides:
- Ghidra (Linux) and its PyGhidra components
- Python with `pyghidra`
- `binary_lens` wrapper CLI

It also exports:
- `GHIDRA_INSTALL_DIR`
- `BINARY_LENS_GHIDRA_HEADLESS`
- `BINARY_LENS_GHIDRA_VERSION`

Notes:

- Linux shells include the `ghidra` package; on other platforms, install Ghidra separately.
- `nix fmt` runs the `alejandra` formatter for `flake.nix`.

## Run the exporter (recommended)

The `binary_lens` wrapper mirrors the intended CLI surface and runs the end-to-end
headless pipeline via PyGhidra.

```sh
binary_lens /path/to/binary -o /path/to/out
```

The output directory defaults to `out/`, so you can omit `-o`:

```sh
binary_lens /path/to/binary
```

The wrapper can also resolve binaries from `PATH`:

```sh
binary_lens ls -o /path/to/out
```

You can pass exporter bounds as `key=value` arguments:

```sh
binary_lens /path/to/binary -o /path/to/out max_full_functions=50 max_strings=200
```

Output is written to `/path/to/out/binary.lens/`.

You can also run it without entering a shell:

```sh
nix run .#binary_lens -- /path/to/binary -o /path/to/out
```

## Notes and troubleshooting

- The exporter is a PyGhidra script. Running `analyzeHeadless` directly will not
  execute Python scripts unless launched via PyGhidra.
- If you see `GHIDRA_INSTALL_DIR is not set`, you are likely outside the dev shell.
- The wrapper expects to run from the repo root. To run elsewhere, set:
  `BINARY_LENS_ROOT=/path/to/binary_lens`.

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

- `binary.lens/manifest.json`: export bounds + versions
- `binary.lens/capabilities.json`: evidence-backed capabilities
- `binary.lens/cli/options.json`: CLI option inventory
