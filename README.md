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

Key files (high level):

- `binary.lens/manifest.json`: export metadata and bounds
- `binary.lens/surface_map.json`: “start here” routing pointers
- `binary.lens/cli/options.json`: CLI option inventory (Milestone 1)
- `binary.lens/errors/messages.json`: error message catalog (Milestone 2)
- `binary.lens/errors/exit_paths.json`: exit/abort inventory (Milestone 2)
- `binary.lens/modes/index.json`: mode inventory (Milestone 3, in progress)
- `binary.lens/modes/slices.json`: per-mode “start here” slices (Milestone 3, in progress)
- `binary.lens/functions/index.json`: function index plus selected function exports
- `binary.lens/evidence/…`: evidence callsites + decompiler excerpts

## Design principles

- **Evidence before interpretation**: exports facts and mechanically derived structure; does not write narrative claims.
- **Ground truth**: exports are anchored to the analysis database (currently Ghidra ProgramDB via PyGhidra).
- **Bounded output**: caps are explicit; large binaries stay usable and diff-friendly.

## Project status

- Milestone 3 (Dispatch & Mode Surface Lens): in progress (`docs/MILESTONES.md`)
  - Current focus: generalize mode detection beyond coreutils-style multicall patterns and improve mode-scoped routing.
- Milestone 2 (Error & Exit Lens): complete (`docs/MILESTONES.md`)
- Milestone 1 (CLI Surface Lens): complete (`docs/MILESTONES.md`)

## Development

See `docs/DEV.md` for the dev shell, wrapper CLI details, and troubleshooting.
