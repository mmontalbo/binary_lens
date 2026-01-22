# `binary_lens` milestones

This document defines near-term milestones for adding **LM-tailored interface lenses** on top of `binary_lens`'s existing facts and evidence-linked outputs. These milestones are **static-first**, evidence-linked, and designed to help many downstream LM consumers (documentation, test generation, indexing, analysis), without centering any single consumer.

---

## Milestone 7 — Runtime Scenarios (Sandboxed Runs + Trace Overlay)

Status: planned

Acceptance snapshot (target):
- Scenario runs: `binary.lens/runs/<run_id>/manifest.json` records argv/env/cwd/timeouts + sandbox config + exit status/timings.
- Captures: `binary.lens/runs/<run_id>/stdout.txt`, `stderr.txt`, and `strace/` logs (per pid via `-ff`) are present for each run.
- Pack integration: `binary.lens/runs/index.json` lists runs + minimal summaries; pack `index.json` links a `runs_index_ref`.
- Safe defaults (Linux): runs execute under a filesystem/network sandbox (Bubblewrap) when available; run artifacts record whether sandboxing was enabled or degraded.

### Goal
Add a **runtime overlay** to `binary_lens` packs so downstream consumers can validate “what actually happened” when running real scenarios against a binary, while keeping the feature general-purpose and joinable to static facts later.

### Deliverables
1) **Scenario spec + run manifest**
- Define a minimal scenario description (argv/env/cwd/stdin policy/timeout) and how it maps to a `runs/<run_id>/manifest.json`.
- Record tool versions, binary hash/name, and any sandbox/tracing configuration used.

2) **Linux sandbox backend (first pass)**
- Run scenarios via Bubblewrap (`bwrap`) with safe-by-default settings (restricted mounts, fresh tmp, limited write locations, optional no-network).
- Keep UX flat: reuse the existing `binary_lens` entrypoint and prefer `key=value` configuration rather than new subcommands.

3) **First-pass capture: syscall trace + I/O**
- Capture stdout/stderr and exit status.
- Capture a syscall trace via `strace` (including child processes), written into the run directory.
- Optionally capture `/proc/<pid>/maps` (or equivalent) as a future-proof join key for PIE/ASLR-aware address mapping.

4) **Pack-level run index**
- Add `runs/index.json` that lists available runs and provides a small summary (exit code, duration, sandbox enabled, trace paths).
- Link the run index from the pack root `index.json` entrypoints.

5) **Docs**
- Document the “run a scenario” workflow inside the pack README and show where to look for results.
- Make limitations explicit (runtime data is observational; sandboxing reduces risk but is not a security boundary).

### Non-goals (explicit)
- No callsite/basic-block coverage tracing in this milestone (leave DBI/`rr`/`perf` for later).
- No man/help/documentation-specific dynamic features; keep outputs general-purpose.
- No Windows/macOS support beyond design notes; Linux-first implementation is acceptable.

## Milestone 6 — Custom Lenses + Evidence Steering (binary_man UX)

Status: complete

Acceptance snapshot:
- Lens authoring UX: `binary.lens/README.md` documents `views/run.py` + "Create your first lens".
- Evidence steering: `manifest.json:evidence_hints` records applied hints; hinted functions can receive deeper decomp excerpts without making the default pack unbounded.
- Lens cookbook: `binary.lens/docs/examples.md` includes evidence-based queries, multicall heuristics, "observed arg-recovery call targets", and a coverage snapshot recipe.
- Semantics + ordering: `binary.lens/schema/README.md` documents `callsite_arg_observations` fields/limits and canonical ordering via address-int helper columns.

### Goal
Make it straightforward for downstream consumers (e.g., `binary_man`) to **author, run, and iterate on custom lenses** using only a generated pack, with clear guidance on when to use facts vs evidence and a small mechanism to steer decompiler evidence extraction without bloating the default pack.

### Deliverables
1) **“Create your first lens” guide (in-pack)**
- Document the minimal workflow: add a SQL file → register it in `views/index.json` → render with `views/run.py` → inspect outputs.
- Show expected output layout under the pack (e.g., `man/*.json`, `docs/*.md`, `execution/*.json`), and where `_lens` metadata appears.

2) **Evidence usage is explicit and reproducible**
- Add at least one example lens recipe that reads `evidence/decomp/*.json` (e.g., usage/help string extraction).
- Clarify path expectations for `read_json_auto('evidence/decomp/*.json')` and how to run queries so relative paths resolve (pack root as CWD, or via the shipped runner).

3) **Lens “cookbook” recipes for multicall binaries**
- Provide example patterns for:
  - `_usage_*` functions (usage/help extraction and line splitting)
  - `single_binary_main_*` functions (per-command “main” candidates)
  - argv0/mode token candidates from string-compare callsites (`strcmp`/`strncmp` family)
- Keep these as recipes/lenses (not canonical facts) and label heuristics clearly.

4) **Document `callsite_arg_observations` limitations**
- Explicitly list what call types are targeted for arg recovery and what “status”/“basis” mean.
- Document common failure modes (wrappers like `__printf_chk`, non-constant pointers, table indirection) and when to fall back to `strings.tags` and/or `evidence/decomp/`.

5) **Decompiler hint overrides via existing `key=value` options**
- Support user-provided hints to include additional functions in `evidence/decomp/` on re-export (e.g., include-by-name pattern and/or `function_id` list).
- Keep selection bounded and deterministic; record the applied hints in `manifest.json`.
- Ensure re-running `binary_lens` with updated hints cleanly regenerates the pack.

6) **Minimal runtime notes**
- Document the minimal dependencies to run `views/run.py` (Python + `duckdb`), and the supported nix invocation path.

### Non-goals (explicit)
- No new subcommands or flag-driven CLI surface; use the existing `key=value` override style.
- No baking `binary_man`-specific schemas into canonical facts; prefer reusable recipes + evidence.
- No unbounded evidence export by default; packs remain size-bounded and diff-friendly.

## Milestone 5 — Queryable Evidence Graph (Table Pack + SQL Lenses)

Status: complete

Acceptance snapshot:
- Pack format v2: `binary.lens/facts/index.json` + Parquet facts tables.
- Views/lenses: `binary.lens/views/index.json` + `views/queries/*.sql` + `views/run.py`.
- Execution anchors: `binary.lens/execution/roots.json` + `binary.lens/execution/sinks.json`.
- Pack docs from SQL: `binary.lens/README.md` + `binary.lens/docs/examples.md` + `binary.lens/schema/README.md`.
- Validation: `tools/check_pack_refs.py` + `tools/check_lens_repro.py`.

### Goal
Make a `binary_lens` pack **mechanically queryable** as an evidence-linked graph, so consumers can answer “where/why” questions via deterministic joins and reachability **using a standard query engine**, without bespoke shard-walking or relying on symbol-name conventions.

### Key idea
Break pack-format compatibility in favor of a **table-first facts schema** that supports reproducible, consumer-augmentable queries.

Keep **facts** skinny and stable, but represent them as typed tables (Parquet). Add small, derived **indexes** only when they materially improve common joins/traversals. Treat everything interpretive (grouping, summaries, “start here”, Markdown, and view-specific JSON) as **lenses**: default views generated from the pack’s facts and reproducible/modifiable by consumers using DuckDB + SQL.

### Layers (facts → indexes → lenses) — pack format v2
- **Facts (Parquet tables)**: comprehensive, low-interpretation inventories that describe what was observed (e.g., callgraph, strings, callsite observations), with explicit unknowns and stable IDs.
- **Indexes (optional Parquet tables)**: deterministic accelerators for common joins/traversals (e.g., sorted edge tables, pre-joined helpers).
- **Lenses (SQL + templates)**: default views (JSON + Markdown) whose contents are sourced from versioned SQL queries shipped with the pack; rendered outputs include a “how to reproduce” recipe (DuckDB invocation).

### Deliverables
1) **Pack format v2: table-first facts**
- Introduce `facts/` as the canonical fact store, backed by Parquet files and a small, machine-readable table registry (e.g., `facts/index.json`).
- Facts must be **row-oriented** (explicit `*_id` columns), not JSON maps with dynamic keys.
- Tables must be joinable via stable IDs (`function_id`, `callsite_id`, `string_id`, `mode_id`, `option_id`, …).

2) **Callsite observations (facts that power lenses)**
- A canonical callsite table that supports deterministic joins without re-running analysis.
  - Minimum: `callsite_id -> from_function_id` and callsite targets.
  - Preferred: best-effort recovered constant arguments as a normalized table (e.g., `callsite_arg_observations`) with explicit `status` + `basis` fields so lenses can be computed from the pack alone.

3) **Graph facts (reachability-ready)**
- A canonical edge table (e.g., `call_edges`) that supports reachability queries with callsite witnesses:
  - Minimum columns: `from_function_id`, `to_function_id`, `callsite_id`.
- A canonical node table (e.g., `callgraph_nodes`) for name/signature joins.

4) **Execution anchors (default lens; evidence-backed, not narrative)**
- `execution/roots.json`: best-effort entry roots (entrypoint/main candidates) with stable `function_id` anchors and explicit unknowns.
- `execution/sinks.json`: termination sinks (exit/abort/return-from-main when detectable) with callsite witnesses (`callsite_id`, `from_function_id`) and constant exit codes when directly visible.

5) **Lens sources + pack docs (SQL-first)**
- Pack includes `views/` containing:
  - SQL query sources for default lenses (e.g., `views/queries/*.sql`).
  - Templates for Markdown rendering.
  - A small runner/wrapper that loads Parquet facts into DuckDB and renders lens outputs deterministically.
- All shipped Markdown (`README.md`, `docs/`, `schema/`) and default lens JSON outputs are rendered from shipped SQL queries so docs can’t drift from the data without being detectable.

6) **Pack docs: SQL query recipes**
- Extend `binary.lens/docs/examples.md` with a small set of binary-agnostic DuckDB recipes (env vars touched, top external calls, stderr templates, usage-marker strings, exit-call sites, reachability pivots) that demonstrate evidence trails.

### Non-goals (explicit)
- No new semantic extraction (no structured help parsing, no option-description inference).
- No new opaque ranking/scoring fields in canonical outputs (views may sort/rank, but must show derivation).
- Not optimizing for “paste the whole pack into the prompt”: consumers should use lenses + selective queries instead of ingesting all facts at once.

### Acceptance Criteria
- A consumer can start from `execution/roots.json`, compute reachability using the edge facts, and land on cited evidence (`callsite_id`/`function_id`/`string_id` joins, plus optional decompiler excerpts via `evidence/index.json`) without bespoke shard-walking.
- The pack documents the table registry and schemas (`schema/`), and table contents are deterministic.
- Default lenses are reproducible: the pack ships the SQL sources for default views, and the rendered Markdown/JSON outputs can be regenerated from the pack alone via DuckDB.
- Works on both `git` and `coreutils` packs without binary-specific naming heuristics being required.

## Milestone 4 — Contract Anchors (Callsites + Tables + Strings)

Status: complete

Note: The v2-only lean pack no longer emits the M4-era surfaces. Treat the
following artifacts as deprecated: `contracts/`, `interfaces/`, `errors/`,
`modes/` contract views, and the old `docs/overview.md` + `docs/navigation.md`.

Acceptance snapshot:
- Pack navigation: `binary.lens/index.json` (`start_here` + `entrypoints`)
- Mode contracts: `binary.lens/contracts/index.json` + `binary.lens/contracts/modes/*.md`
- Pack docs: `binary.lens/docs/overview.md` + `binary.lens/docs/navigation.md` + `binary.lens/docs/examples.md`
- Fast verification: `tools/check_pack_refs.py` (no Ghidra)

### Goal
Shift the pack’s primary interface toward a **user-facing contract model** (commands/modes, inputs, outputs, diagnostics), backed by evidence. Low-level implementation conventions (`getopt_long`, `strcmp` chains, custom parsers, `fprintf`, etc.) should be treated as *evidence sources*, not the interface.

This milestone should make it easy to answer:
- “For mode X, what inputs does it accept (options/env/positionals), and what outputs/diagnostics does it emit?”
- “What evidence supports each claim (callsite refs, function refs, string IDs)?”
- “What is known vs unknown for this specific mode (coverage), without manual joins?”

### Context
Many binaries encode “user contracts” through multiple mechanisms:
- stable APIs (`getenv`, `open`, `execve`, `connect`, `fprintf`, …)
- constant arguments and static tables (string keys, path templates, format strings)
- custom parsing/dispatch code (table-driven, compare chains, bespoke parsers)

`binary_lens` already exports modes, CLI option tokens, errors, interface surfaces, strings, and evidence. This milestone focuses on:
- reducing reliance on “read the code and infer the joins”
- presenting **mode-scoped contract views** that are convention-agnostic
- keeping the pack comprehensive without becoming unreadable (sharding + small indexes)

### Deliverables
1) **Sharded inventories (no dropped records)**
- Large inventories are exported via `format=sharded_list/v1`:
  - Small index file at a stable path (e.g., `strings.json`, `callgraph.json`, `cli/options.json`).
  - Full set stored in shard files under a sibling directory.
  - Reruns clear the pack root before writing to prevent stale shards from accumulating.

2) **Mode-scoped contract views (Markdown-first)**
- Add a mode-first “start here” surface that joins existing inventories into a per-mode contract view, with explicit coverage/unknowns and evidence trails.
- Recommended pack layout (subject to iteration):
  - `contracts/index.json`: list modes + refs to per-mode contract docs
  - `contracts/modes/<mode_id>.md`: one page per mode that summarizes:
    - command/mode identity + implementation roots
    - inputs: options (spellings + arg shape) and env vars, with recognizer evidence
    - outputs: user-visible templates/help text, with evidence
    - diagnostics: error templates + exit paths, with evidence
    - per-mode coverage summary (what we have vs missing), and truncation/unknown markers

3) **Interface inventories remain evidence-backed building blocks**
Maintain the existing `interfaces/` surfaces as atomic, evidence-linked inventories. They should be useful on their own, and also serve as inputs to the mode-scoped contract views.

For `interfaces/*` specifics, keep the existing surface split (`env`, `fs`, `process`, `net`, `output`) and preserve explicit unknowns + evidence refs.

4) **Pack-embedded docs and schema guide**
- Packs include `README.md`, `index.json`, `docs/`, and `schema/` so humans and LMs can navigate without repo context.

5) **Ref integrity guardrail**
- `tools/check_pack_refs.py` validates JSON refs and contract/doc links against the exported artifact set.

### Implementation notes
- Name-based heuristics are explicit and overrideable (wordlists), and should not be treated as canonical “interface truth”.
- Contract views avoid misleading attributions when localization is missing (prefer explicit unknowns over weak inference).

### Approach (static-first)
- Prefer **import-signal anchors** + existing callgraph/callsite evidence to localize sites.
- Add **derived joins/views** (contracts) on top of existing inventories; do not introduce new deep semantic extraction as part of this milestone.
- Recover constant-ish arguments using existing bounded argument-resolution helpers; degrade gracefully when decompilation fails.
- Emit evidence-linked records with explicit `unknown` fields and coverage summaries rather than narrative claims.
- Keep outputs comprehensive via sharding; keep navigation small via indexes and per-mode docs.

### Acceptance Criteria (met)
**A. Mode-first UX**
- For both `git` and `coreutils`, consumers can pick an arbitrary mode from `modes/index.json` and find a single mode-scoped contract view that links to options/env/output/diagnostics evidence with explicit coverage/unknowns.
- No mode is “missing” from key routing surfaces due to top-N truncation (sharded inventories instead).

**B. Generic-first**
- Core functionality does not depend on binary-specific symbol naming conventions; any name-based shortcuts are optional and labeled as heuristic.

**C. Comprehensive + navigable**
- Large lists are comprehensive via sharding; small indexes and Markdown views keep navigation tractable.
- Every contract claim links back to evidence (callsites, functions, string IDs/addresses), and missing data is represented explicitly (unknown vs missing).

## Milestone 3 — Dispatch & Mode Surface Lens

Status: complete

Note: The v2-only lean pack no longer emits `modes/` or uses the modes goldens;
`modes/index.json`, `modes/slices.json`, and `goldens/modes/*` are deprecated.

Acceptance snapshot:
- `goldens/modes/git/` + `goldens/modes/coreutils/` (deprecated; `tools/check_modes_goldens.py` removed in v2-only pack)

### Goal
Extract an **evidence-linked model of behavioral modes and dispatch**, enabling LM consumers to:
- discover “what modes exist?” (subcommands, verbs, applets, argv0-based multicall, etc.)
- understand how the binary selects a mode (dispatch mechanism + decision sites)
- scope other surfaces (CLI options, diagnostics, exits, outputs) to a selected mode
- generate interaction plans/tests that are mode-aware (“invoke mode X with args Y”)

This milestone should make it easy to answer:
- “How many ‘commands’ live inside this binary, and what are their names?”
- “Where does dispatch happen, and what does it dispatch on (argv0, argv[1], flags)?”
- “If I care about mode X, what code regions should I focus on?”

### Context
Many real-world binaries multiplex behavior:
- multicall binaries select behavior based on `argv[0]` (or a shim name)
- subcommand CLIs dispatch on `argv[1]` (“verb” commands)
- argument-driven mode selection uses string-compare chains or lookup tables
- some binaries dispatch via tables (name → function pointer) or hash/switch patterns

`binary_lens` already exports call edges, strings, and evidence callsites, but it does not yet:
- surface a stable inventory of modes/subcommands with evidence
- localize dispatch decision sites and their mechanisms
- provide a bounded, navigable “mode slice” to reduce context for consumers

### Relationship to CLI Options
This milestone is intentionally **orthogonal** to the CLI Surface Lens:
- **Modes** describe *which behavior is selected* (subcommand/verb/applet/variant).
- **Options** describe *parameters and toggles* that affect behavior.

In multiplexing binaries, options may be:
- **global** (parsed before mode selection or shared across many modes), or
- **mode-scoped** (parsed/checked only within a specific mode’s implementation), or
- **mode-selecting** (an option/flag that effectively selects a mode).

Milestone 3 should not duplicate option extraction. Instead, it should enable consumers to **scope and route** existing CLI option artifacts to a selected mode, with explicit `derived/heuristic` labels.

### Deliverables
Add a `modes/` (or `dispatch/`) section to the context pack:

1. `modes/index.json`
   - Inventory of discovered modes with conservative metadata:
     - `mode_id` (stable ID)
     - `name` (string token, when discoverable)
     - `kind` (e.g., `argv0`, `subcommand`, `verb`, `flag_mode`, `unknown`)
     - `dispatch_roots` (best-effort function IDs that anchor the mode)
     - `dispatch_sites` (callsite IDs where the mode token is tested/selected)
     - `implementation_roots` (function IDs + sources)

2. `modes/dispatch_sites.json` (optional debug surface; no longer emitted by default)
   - Use `modes/index.json` dispatch sites + `evidence/callsites.json` instead.

3. `modes/slices.json` (optional, but recommended)
   - Bounded per-mode “start here” slices to make consumers efficient:
     - `mode_id`
     - `root_functions` (bounded list)
     - `top_strings` / `top_messages` (bounded references into existing outputs)
     - recommended: `option_scope` hints (global/mode_scoped/mode_selecting/unknown), explicitly labeled as derived/heuristic
     - `top_exit_paths` (bounded references)
     - explicit `selection_strategy` + bounds metadata

4. Routing entry in `index.json`
   - “start here” pointers:
     - top dispatch sites
     - top N modes (by evidence strength / number of distinct sites)
     - top N mode roots (functions)

### Approach (static-first)
- Identify dispatch signals (imports and patterns):
  - string compare imports (`strcmp`, `strncmp`, `strcasecmp`, …)
  - table-driven dispatch (string constants adjacent to function pointers)
  - switch/jumptable patterns in functions that also reference many tokens
- Extract candidate mode tokens conservatively:
  - string constants observed as arguments to compare/lookup callsites
  - string constants co-located in apparent mode tables
- Link tokens → dispatch sites and best-effort roots:
  - record callsite evidence where token is used
  - heuristically associate nearby/internal calls as potential roots (explicitly labeled)
- Export bounded slices:
  - keep per-mode exports small and stable; prioritize high-salience evidence
  - avoid full decompiler dumps; reference existing evidence files
  - link to existing CLI artifacts where possible:
    - include parse loops / options that are reachable from a mode root (derived, bounded)
    - treat “global vs mode-scoped” as a best-effort hint, not a guarantee

### Acceptance Criteria
**A. Mode inventory**
- `modes/index.json` contains a non-trivial set of modes (≥ 5) for a multiplexing binary.
- Each mode includes:
  - `name` (or explicit `unknown_name`) and at least one dispatch-site evidence reference.

**B. Dispatch localization**
- At least one dispatch decision site is exported with:
  - function ID and representative callsite evidence
  - token(s) involved (when discoverable) or explicit unknowns

**C. Scope reduction**
- Provide at least a minimal per-mode slice for the top few modes, containing:
  - a bounded list of root functions and evidence-linked pointers into existing surfaces
  - explicit `strength/confidence` tags for heuristic associations
  - at least some mode → option references when options are discoverably scoped

**D. Bounded output**
- Cap counts (tokens, modes, sites, slice sizes) and include bounds metadata.
- Ensure slices are diff-friendly and don’t explode pack size.

---

## Milestone 2 — Error & Exit Lens

Status: complete

### Goal
Extract an **evidence-linked taxonomy of errors and exits**, enabling LM consumers to:
- enumerate likely error conditions
- understand how errors are reported (stderr patterns)
- identify exit paths and likely exit codes
- generate robust runtime checks for error behavior

This milestone should make it easy to answer:
- “What errors can this binary emit?”
- “Where are errors produced?”
- “Which errors cause exit vs recover?”
- “What exit codes are likely?”

### Context
Coreutils binaries have rich error reporting via:
- `error()`, `perror()`, `fprintf(stderr, ...)`, `warn*`-style helpers
- `exit()`, `_exit()`, `abort()`, `return`-based propagation
- error strings + formatting patterns

`binary_lens` currently exports strings and callsites, but does not:
- classify error strings vs other strings
- connect error emissions to exit behavior
- surface a compact, navigable “diagnostics surface”

### Deliverables
Add an `errors/` section to the context pack:

1. `errors/messages.json`
   - Catalog of error/diagnostic message templates:
     - string ID + preview (single-line escaped)
     - bucket (error/usage/warn/diagnostic)
     - emitting functions (top-N)
     - emitting callsites (bounded)
     - related imports (fprintf/perror/error/strerror/etc.)
     - confidence and evidence refs

2. `errors/exit_paths.json`
   - Exit and fatal-path extraction:
     - calls to `exit`, `_exit`, `abort`
     - “likely fatal” patterns (e.g., `error(...); exit(code)` or `error(...); return nonzero`)
     - best-effort exit codes (constants when statically visible)
     - evidence references for each path

3. `errors/error_sites.json` (optional, but recommended)
   - A list of “error production sites”:
     - function ID
     - evidence cluster IDs
     - imports used (error/perror/fprintf)
     - whether followed by exit/return propagation

4. Routing entry in `index.json`
   - “start here” pointers:
     - top emitting functions
     - top fatal exit paths
     - top message templates

### Approach (static-first)
- Identify error-printing imports and helpers:
  - `fprintf`, `fputs`, `puts`, `perror`, `strerror`, `error` (and local wrappers)
  - detect stderr usage (`stderr`, fd=2) when visible
- Classify message strings:
  - heuristics: contains “error”, “cannot”, “failed”, “invalid”, “No such file”, etc.
  - formatting strings with `%s` + newline patterns
  - keep classification conservative; allow “unknown/diagnostic”
- Link messages to sites:
  - string xrefs → emitting functions
  - callsite evidence where format string is used
- Extract exit behavior:
  - direct calls to `exit/_exit/abort`
  - return-based exit patterns: function returns constant nonzero after an error emission
  - record as `heuristic` when not direct

### Acceptance Criteria
**A. Error message catalog**
- `errors/messages.json` contains a meaningful set of message templates.
- Each entry includes:
  - string ID + escaped single-line preview
  - at least one emitting function + evidence reference

**B. Exit path inventory**
- `errors/exit_paths.json` includes:
  - all direct calls to `exit/_exit/abort` (bounded but complete within the exported slice)
  - evidence refs for each callsite
  - exit code when statically visible (constant) or explicitly marked unknown

**C. Fatal vs non-fatal distinction**
- At least a subset of error sites are labeled with:
  - `severity: fatal | non_fatal | unknown`
  - based on proximity to exit/abort or clear return propagation
- Must include explicit strength/confidence tags.

**D. Bounded output**
- Cap message templates and evidence per template (e.g., top 200 templates, 5 callsites each).
- Avoid dumping entire decompiler functions; reference existing evidence files.

---

## Milestone 1 — CLI Surface Lens

Status: complete

### Goal
Extract a **machine-readable model of the CLI surface** from the binary (coreutils multicall binary), including:
- option names (long and short)
- argument requirements
- where options are parsed
- where options are checked/used (coarse linkage)

This milestone should make it easy for an LM consumer to answer:
- “What options exist?”
- “Which functions implement/consult each option?”
- “Where is the parsing loop and what variables represent flags?”

### Context
`binary_lens` already detects **option parsing capability** (e.g., `getopt_long`) and localizes it, but it does not yet provide:
- a concrete list of options
- stable references to option tables/strings
- a mapping from options → internal flag variables → check sites

Coreutils-style binaries commonly use `getopt_long` with:
- `struct option[]` tables (long options)
- short option strings
- a parse loop that sets internal flags/fields

### Deliverables
Add a `cli/` section to the context pack:

1. `cli/options.json`
   - A list of discovered options with evidence and linkage:
     - `long_name` (if present)
     - `short_name` (if present)
     - `has_arg` (no/required/optional)
     - `evidence` (strings, table entries, parse-loop callsites)
     - `parse_sites` (callsite IDs)
     - `flag_vars` (best-effort: varnode/local/global identifiers and evidence)
     - `check_sites` (best-effort: function IDs + evidence refs where flag is tested)

2. `cli/parse_loops.json` (optional, but recommended)
   - Identify one or more parse loops:
     - function ID
     - representative evidence cluster
     - notes like “uses getopt_long”, “uses getopt”
     - discovered option table references (addresses / data symbols)

3. Minimal routing entry in `index.json`
   - “start here” pointers:
     - primary parse loop(s)
     - top option table(s)
     - top N high-salience options (by usage frequency / check-site count)

### Approach (static-first)
- Identify parse sites:
  - internal callsites to `getopt_long` / `getopt`
- Recover option tables:
  - locate `struct option[]` in memory via references from parse loop
  - decode entries: `{ name_ptr, has_arg, flag_ptr, val }`
  - resolve `name_ptr` to strings
- Recover short option strings:
  - locate string argument passed to getopt/getopt_long
- Link options → flag variables (best-effort):
  - observe stores to locals/globals based on `getopt` return value (`c`)
  - treat as heuristic with explicit confidence labels
- Link options → check sites (best-effort):
  - find conditional branches comparing flag vars
  - record function IDs + evidence refs; avoid deep dataflow

### Acceptance Criteria
**A. Concrete option inventory**
- `cli/options.json` contains a non-trivial set of options (long and/or short) recovered from the binary.
- Each option has at least one evidence reference:
  - string ID for name and/or table-entry address, plus a parse-site callsite.

**B. Evidence-linked parse sites**
- At least one parse loop is identified with:
  - function ID
  - one representative evidence cluster
  - list of callsites invoking getopt/getopt_long

**C. Minimal linkage**
- For at least the top ~10 highest-salience options, include one of:
  - a `flag_var` with evidence, or
  - a `check_site` with evidence
- All linkage fields must be explicitly tagged with:
  - `strength: observed | derived | heuristic`
  - `confidence: high | medium | low`

**D. Bounded output**
- Option inventory and evidence remain bounded:
  - cap per-option evidence to a small number (e.g., 3–10 refs)
  - cap parse loops exported (e.g., 10)
- No full p-code dumps required.

---

## Notes on Epistemic Hygiene

All milestones must preserve `binary_lens` invariants:
- no narrative prose as “facts”
- every extracted item is evidence-linked
- derived/heuristic fields are explicitly labeled
- outputs are bounded and diffable

These lenses exist to make downstream LM consumers *far easier to build*, not to replace runtime verification.
