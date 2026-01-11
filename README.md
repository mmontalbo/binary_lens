# Binary Lens

Binary Lens extracts **language-model-friendly, evidence-based context**
from binaries using **Ghidra’s ProgramDB**.

It provides language models with a reliable substrate for reasoning about
compiled programs—without hallucination, over-interpretation, or loss of
grounding.

---

## Motivation

Reverse-engineering tools like Ghidra excel at analysis, but their outputs
are not structured for **language-model reasoning**.

Binary Lens sits between:

- **Ghidra ProgramDB** (ground truth)
- **Language models** (reasoning, synthesis, construction)

and produces a **context pack** that preserves evidence while enabling
many downstream uses.

---

## Primary consumers

The primary consumers of Binary Lens outputs are **language models**.

Binary Lens is intentionally **multi-consumer** and does not privilege
any single downstream application.

Example consumers include:

- documentation synthesis
- semantic indexing and search
- behavior summarization
- test generation
- compliance or policy analysis
- cross-binary comparison
- reimplementation or refactoring assistance

Binary Lens provides the substrate; downstream tools decide how to use it.

---

## Design principles

### 1. ProgramDB as ground truth

All exported information comes from:

- Ghidra ProgramDB
- Ghidra reference model
- Ghidra decompiler API

Binary Lens does not re-analyze raw bytes or mutate analysis state.

---

### 2. Evidence before interpretation

Binary Lens exports:

- mechanically derived facts
- derived structural information
- explicit evidence pointers

It does **not** infer intent or explain meaning.

---

### 3. Capabilities, not narratives

Binary Lens derives **capabilities**: neutral descriptions of what a
binary demonstrably does.

Capabilities are:

- evidence-linked
- confidence-weighted
- reusable across consumers

They are not documentation prose and not semantic claims.

---

### 4. Bounded output

Large binaries are summarized by default:

- only top-N relevant functions exported fully
- others included as stubs
- p-code and CFG exported selectively

This keeps artifacts usable and diffable.

---

## Conceptual layers

Binary Lens distinguishes three layers:

### Layer 1 — Facts

Raw, observed data from ProgramDB:

- calls, strings, references
- control summaries
- decompiler excerpts

---

### Layer 2 — Capabilities

Derived, mechanical descriptions of behavior:

- option parsing
- filesystem interaction
- environment usage
- output formatting
- process interaction

---

### Layer 3 — Views (external)

Documentation, tests, summaries, analyses.

Binary Lens does not own this layer.

---

## Output: Binary Lens Context Pack

A typical context pack:

binary.lens/
├── manifest.json
├── binary.json
├── imports.json
├── strings.json
├── callgraph.json
├── capabilities.json
├── functions/
│ ├── index.json
│ ├── f_<addr>.json
│ └── f_<addr>.md
└── evidence/
├── decomp/
└── callsites/


### JSON

- authoritative
- stable identifiers
- machine-readable
- diffable

### Markdown

- instructions for LM consumption
- routing guidance
- annotation slots

### Evidence

- bounded excerpts
- stable references
- citation-friendly

---

## Typical workflow

1. Analyze a binary in Ghidra
2. Run the Binary Lens exporter
3. Produce a context pack
4. Provide the pack to one or more LM-based tools
5. Optionally validate or round-trip results externally

---

## Exporter (Ghidra script)

Script: `scripts/binary_lens_export.py`

Headless example:

```sh
analyzeHeadless <project_dir> <project_name> \
  -import <binary> \
  -scriptPath /path/to/binary_lens/scripts \
  -postScript binary_lens_export.py <out_dir>
```

Options are provided as `key=value` after the output directory:

```sh
... -postScript binary_lens_export.py <out_dir> max_full_functions=50 max_strings=200
```

The exporter writes a context pack to `<out_dir>/binary.lens/`.

---

## Roadmap

### v0 — Minimal viable lens

- ELF support
- facts + conservative capability extraction
- top-N function export
- clean, bounded artifacts

### v1 — Capability refinement

- richer capability taxonomy
- improved confidence modeling
- better evidence grouping

### v2 — Optional round-trip support

- LM annotation patches
- safe application back to ProgramDB
- provenance tracking
