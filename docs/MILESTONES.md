# Binary Lens Milestones

This document defines near-term milestones for adding **LM-tailored interface lenses** on top of Binary Lens’s existing facts/capabilities/subsystems output. These milestones are **static-first**, evidence-linked, and designed to help many downstream LM consumers (documentation, test generation, indexing, analysis), without centering any single consumer.

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
Binary Lens already detects **option parsing capability** (e.g., `getopt_long`) and localizes it, but it does not yet provide:
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

## Milestone 2 — Error & Exit Lens

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

Binary Lens currently exports strings and callsites, but does not:
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

## Notes on Epistemic Hygiene

Both milestones must preserve Binary Lens invariants:
- no narrative prose as “facts”
- every extracted item is evidence-linked
- derived/heuristic fields are explicitly labeled
- outputs are bounded and diffable

These lenses exist to make downstream LM consumers *far easier to build*, not to replace runtime verification.
