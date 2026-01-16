# `binary_lens` milestones

This document defines near-term milestones for adding **LM-tailored interface lenses** on top of `binary_lens`'s existing facts/capabilities/subsystems output. These milestones are **static-first**, evidence-linked, and designed to help many downstream LM consumers (documentation, test generation, indexing, analysis), without centering any single consumer.

---

## Milestone 4 — Contract Anchors (Callsites + Tables + Strings)

Status: planned

### Goal
Expand the context pack with **evidence-backed contract anchors** beyond modes/errors/options: stable, bounded surfaces derived from callsites + constant/table arguments that help consumers understand what the binary *interacts with* (filesystem, env, subprocesses, network, stdout/stderr) without relying on narrative decompiler output.

This milestone should make it easy to answer:
- “What external interfaces does this binary touch (files, env vars, subprocesses, sockets)?”
- “What user-visible text/output templates exist, and where are they emitted?”
- “Which constants/strings participate in those interfaces (paths, env var names, argv tokens)?”

### Context
Many binaries encode “user contracts” through:
- calls into stable APIs (`getenv`, `open`, `execve`, `connect`, `fprintf`, …)
- constant arguments and static tables (string keys, path templates, format strings)

`binary_lens` already exports call edges, strings, and evidence callsites, plus focused lenses (errors, modes). This milestone adds **generic interface surfaces** that scale beyond the current test binaries and remain useful to non-LM reverse engineering workflows (triage, auditing, diffing).

### Deliverables
Add a new top-level `interfaces/` section to the context pack. Keep the section cohesive, and treat its JSON schemas as stable once introduced.

1. `interfaces/index.json`
   - Index of available interface surfaces, with refs + bounded counts/truncation metadata.

2. `interfaces/env.json`
   - Environment-variable interactions anchored to callsites:
     - `getenv`/`setenv`/`unsetenv`/`putenv` callsites (bounded)
     - resolved constant env var names when visible (string IDs + addresses)
     - explicit “unknown name” when not recoverable

3. `interfaces/fs.json`
   - Filesystem interactions anchored to callsites:
     - `open/openat/fopen/stat/lstat/access/unlink/rename/mkdir/opendir/...` callsites (bounded)
     - resolved constant path-like strings when visible (string IDs + addresses)
     - flags/modes when statically visible (constant ints) with explicit unknowns otherwise

4. `interfaces/process.json`
   - Subprocess interactions anchored to callsites:
     - `exec*`, `posix_spawn`, `system`, `popen` callsites (bounded)
     - resolved constant argv0/command strings when visible

5. `interfaces/net.json`
   - Network interactions anchored to callsites:
     - `socket/connect/bind/listen/send/recv/getaddrinfo/...` callsites (bounded)
     - resolved constant protocol/port/host strings when visible (explicit unknowns otherwise)

6. `interfaces/output.json`
   - User-visible output templates anchored to callsites:
     - `printf/fprintf/dprintf/write/puts/fputs/...` callsites (bounded)
     - resolved constant format strings and/or message templates when visible
     - best-effort output channel hints when statically visible (e.g., fd=1/2, stderr) with explicit unknowns otherwise

### Implementation hygiene (required)
To keep the pack generic and reduce future churn while adding new pattern families:
- Factor shared “signal-driven callsite scan” logic into reusable helpers (CLI/errors/capabilities should not each re-implement the same walk-and-filter loop).
- Centralize symbol/import normalization and make matching policy explicit (casefolding, `_chk`/version suffix stripping, substring vs exact matches).
- Isolate name-convention heuristics (e.g., `cmd_*`/`cmd_main`) behind clearly-labeled modules/flags so they don’t become the generic story.

### Approach (static-first)
- Prefer **import-signal anchors** + existing callgraph/callsite evidence to localize sites.
- Recover constant-ish arguments using existing bounded argument-resolution helpers; degrade gracefully when decompilation fails.
- Emit **atomic, evidence-linked records** with explicit `status`/`unknown` fields rather than narrative claims.
- Enforce bounds and stable ordering; include totals + truncation flags so consumers can distinguish “absent” vs “not exported”.

### Acceptance Criteria
**A. Non-trivial surfaces**
- On at least two diverse binaries, each `interfaces/*.json` surface contains meaningful anchored evidence (not just empty shells), with explicit `truncated`/bounds metadata.
- `git` and `coreutils` remain primary validation targets, but the exporter should avoid tailoring heuristics specifically to them.

**B. Generic-first**
- Core functionality does not depend on binary-specific symbol naming conventions; any name-based shortcuts are optional and labeled as heuristic.

**C. Bounded + auditable**
- Records are diff-friendly and bounded.
- Every entry links back to evidence (callsites, functions, string IDs/addresses), and missing data is represented explicitly (unknown vs truncated).

## Milestone 3 — Dispatch & Mode Surface Lens

Status: complete

Acceptance snapshot:
- `goldens/modes/git/` + `goldens/modes/coreutils/` (see `tools/check_modes_goldens.py`)

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
     - `dispatch_sites` (callsite IDs + evidence refs where the mode token is tested/selected)
     - `evidence` (strings/callsites/functions)
     - `strength/confidence` tags for all non-trivial fields

2. `modes/dispatch_sites.json` (optional, but recommended)
   - A compact list of dispatch decision regions:
     - function ID(s)
     - representative compare/lookup callsites
     - candidate tokens observed (bounded)
     - notes like “strcmp-chain”, “table lookup”, “switch/jumptable” (heuristic)

3. `modes/slices.json` (optional, but recommended)
   - Bounded per-mode “start here” slices to make consumers efficient:
     - `mode_id`
     - `root_functions` (bounded list)
     - `top_strings` / `top_messages` / `top_options` (bounded references into existing outputs)
     - recommended: `option_scope` hints (global/mode_scoped/mode_selecting/unknown), explicitly labeled as derived/heuristic
     - `top_exit_paths` (bounded references)
     - explicit `selection_strategy` + bounds metadata

4. Routing entry in `surface_map.json`
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

4. Routing entry in `surface_map.json`
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
     - `parse_sites` (function IDs + callsite IDs)
     - `flag_vars` (best-effort: varnode/local/global identifiers and evidence)
     - `check_sites` (best-effort: function IDs + evidence refs where flag is tested)

2. `cli/parse_loops.json` (optional, but recommended)
   - Identify one or more parse loops:
     - function ID
     - representative evidence cluster
     - notes like “uses getopt_long”, “uses getopt”
     - discovered option table references (addresses / data symbols)

3. Minimal routing entry in `surface_map.json` (or equivalent index)
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
