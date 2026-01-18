# `binary_lens`

`binary_lens` extracts **evidence-linked, language-model-friendly context packs** from binaries.
The exported pack is designed to be **diffable**, **bounded**, and safe for downstream LM consumers to use without inventing facts.

## Quickstart

Recommended (via Nix):

```sh
nix run .#binary_lens -- /path/to/binary -o out/
```

Or enter a dev shell and use the wrapper directly:

```sh
nix develop
binary_lens /path/to/binary -o out/
```

You can pass export bounds as `key=value` arguments:

```sh
binary_lens /path/to/binary -o out/ max_full_functions=50 max_strings=200
```

## Output: context pack

`binary_lens` writes a context pack to `out/binary.lens/` (or your chosen `-o` directory).
JSON files are authoritative; evidence files are bounded excerpts.

Consumer docs are embedded in each generated pack: see `binary.lens/README.md` and `binary.lens/docs/`.

Key files (high level):

- `binary.lens/manifest.json`: export metadata and bounds
- `binary.lens/docs/overview.md`: pack overview (tailored to the target binary)
- `binary.lens/cli/options.json`: CLI option inventory
- `binary.lens/errors/messages.json`: error message catalog
- `binary.lens/errors/exit_paths.json`: exit/abort inventory
- `binary.lens/modes/index.json`: mode inventory
- `binary.lens/modes/slices.json`: per-mode “start here” slices
- `binary.lens/callgraph/nodes.json`: address → name/signature lookup table
- `binary.lens/evidence/…`: evidence callsites + decompiler excerpts

## Design principles

- **Evidence before interpretation**: exports facts and mechanically derived structure; does not write narrative claims.
- **Ground truth**: exports are anchored to the analysis database (currently Ghidra ProgramDB via PyGhidra).
- **Bounded output**: caps are explicit; large binaries stay usable and diff-friendly.

## Project status

See `docs/MILESTONES.md` for milestone goals and current status.

## Development

See `docs/DEV.md` for the dev shell, wrapper CLI details, and troubleshooting.
