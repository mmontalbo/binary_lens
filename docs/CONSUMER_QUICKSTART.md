# Consumer Quickstart

This guide is for **consumers of a generated `binary_lens` pack** (the exported `binary.lens/` directory).

## Find the pack root

The pack root is the directory that contains `manifest.json`.

Common layouts:

- If you ran `binary_lens ... -o out/some_run`, the pack root is typically `out/some_run/binary.lens/`.
- If you were given a pack directory directly, it is the folder containing `manifest.json`.

## Canonical entrypoints ("start here")

Start with either:

- `index.json` (pack-root index; entrypoint pointers + navigation notes), or
- `surface_map.json` (high-signal “start here” routing pointers, with `*_ref` paths to deeper files).

Then use:

- `manifest.json`: pack metadata, export bounds, and coverage/truncation summary.
- `binary.json`: target-binary facts (format, arch, pointer size, hashes).

## Modes: enumerate and follow evidence

Modes are the Milestone 3 "primary surface".

1. Open `modes/index.json` (or follow `surface_map.json` → `modes.index_ref`).
2. Pick a mode entry and note:
   - `mode_id` (stable identifier)
   - `name` + `unknown_name` / `name_confidence` / `name_strength` (how reliable the label is)
   - `dispatch_site_count` + `dispatch_sites_truncated` (coverage vs bounds)
3. Open `modes/dispatch_sites.json` (or follow `surface_map.json` → `modes.dispatch_sites_ref`) to see the top dispatch sites and their token candidates.
4. Open `modes/slices.json` (or follow `surface_map.json` → `modes.slices_ref`) for compact per-mode slices:
   - `dispatch_sites[*].callsite_ref` points to evidence callsites in `evidence/callsites/`.
   - `top_options_ref` / `top_messages_ref` / `top_strings_ref` point to the canonical inventories for cross-linking.

## Evidence navigation

Many payloads include `*_ref` fields:

- A single `*_ref` is a relative path from the pack root to another pack file.
- A `*_refs` field is a list of such paths.

Evidence paths are typically:

- `evidence/callsites/cs_<addr>.json`: callsite context + recovered args (when available).
- `evidence/decomp/f_<addr>.json`: bounded decompiler excerpts (function-level evidence).

## Unknowns, missing data, and truncation

The pack is intentionally **bounded**; most lists include `truncated` + a `max_*` field.

- If `truncated: true`, treat the list as a **partial export** (missing entries may exist).
- If `truncated: false` and a list is empty, treat it as **not found** under current collection rules.
- When a field carries `*_confidence` / `*_strength`, a value of `"unknown"` means **the exporter did not establish it** (not “false”).

For a pack-level summary, see `manifest.json` (coverage/truncation summary).

