# `binary_lens`

`binary_lens` extracts **evidence-linked, language-model-friendly context packs** from binaries.
The exported pack is designed to be **diffable**, **bounded**, and safe for downstream LM consumers to use without inventing facts.

## Quickstart

Recommended (via Nix; works from any CWD):

```sh
nix run .#binary_lens -- /path/to/binary -o /path/to/out
```

From another directory, point at the flake path:

```sh
nix run /path/to/binary_lens#binary_lens -- /path/to/binary -o /path/to/out
```

Re-render views from an existing pack (no Ghidra needed):

```sh
nix run .#binary_lens -- /path/to/out/binary.lens
nix run .#binary_lens -- /path/to/out
```

You can pass export bounds as `key=value` arguments:

```sh
nix run .#binary_lens -- /path/to/binary -o /path/to/out max_full_functions=50 max_strings=200
```

You can also drive exports via JSON config/requests or a single export plan:

```sh
nix run .#binary_lens -- /path/to/binary -o /path/to/out --config export_config.json --requests export_requests.json
nix run .#binary_lens -- /path/to/binary -o /path/to/out --plan export_plan.json
```

Resolve settings without running Ghidra:

```sh
nix run .#binary_lens -- /path/to/binary --config export_config.json --explain
```

Inspect pack capabilities:

```sh
nix run .#binary_lens -- inspect /path/to/out/binary.lens --json
```

Re-export from an existing pack (fresh pack by default):

```sh
nix run .#binary_lens -- --from-pack /path/to/out/binary.lens --requests more.json -o /path/to/out/reexport
nix run .#binary_lens -- --from-pack /path/to/out/binary.lens --in-place --requests more.json
```

Config/request schema details live in `docs/EXPORT_CONFIG.md`.

Or enter a dev shell and use the wrapper directly:

```sh
nix develop
binary_lens /path/to/binary -o /path/to/out
```

## Output: context pack

`binary_lens` writes a context pack to `out/binary.lens/` (or your chosen `-o` directory).
Facts are stored as Parquet tables; evidence files are bounded excerpts.

Consumer docs are embedded in each generated pack: see `binary.lens/README.md` and `binary.lens/docs/`.

Key entrypoints:

- `binary.lens/README.md`
- `binary.lens/docs/examples.md`
- `binary.lens/schema/README.md`
- `binary.lens/facts/index.json`
- `binary.lens/views/index.json`
- `binary.lens/execution/roots.json`
- `binary.lens/execution/sinks.json`
- `binary.lens/evidence/index.json`

## Design principles

- **Evidence before interpretation**: exports facts and mechanically derived structure; does not write narrative claims.
- **Ground truth**: exports are anchored to the analysis database (currently Ghidra ProgramDB via PyGhidra).
- **Bounded output**: caps are explicit; large binaries stay usable and diff-friendly.

## Project status

See `docs/MILESTONES.md` for milestone goals and current status.

## Development

See `docs/DEV.md` for the dev shell, wrapper CLI details, and troubleshooting.
