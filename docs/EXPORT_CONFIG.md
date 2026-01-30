# Export Configuration (Milestone 8)

This document describes the versioned JSON inputs and how settings resolve.

## Config schema: `binary_lens_config` (v1)

Top-level fields:

```json
{
  "schema": { "name": "binary_lens_config", "version": "v1" },
  "artifacts": {
    "strings": true,
    "callgraph": true,
    "call_args": true,
    "evidence_decomp": true
  },
  "budgets": {
    "max_full_functions": 50,
    "max_strings": 0,
    "max_call_edges": 0,
    "max_decomp_lines": 200
  },
  "timeouts": {
    "decompile_seconds": 30
  },
  "advanced": {
    "analysis_profile": "full",
    "profile": false,
    "evidence": {
      "decomp": {
        "include_name_regex": "",
        "include_function_ids": []
      }
    },
    "call_args": {
      "targets": {
        "function_ids": [],
        "symbol_names": []
      },
      "max_callsites": null
    }
  }
}
```

Key reference (defaults, types, and affected artifacts):

- `artifacts.strings` (bool, default `true`): enables string facts and string-backed lenses.
- `artifacts.callgraph` (bool, default `true`): enables callgraph/callsite facts.
- `artifacts.call_args` (bool, default `true`): enables callsite argument recovery (depends on callgraph).
- `artifacts.evidence_decomp` (bool, default `true`): enables decompiler evidence excerpts.
- `budgets.max_full_functions` (int, default `50`): bounds decompiler evidence selection (`evidence/decomp`).
- `budgets.max_strings` (int, default `0` meaning unbounded): bounds strings table size.
- `budgets.max_call_edges` (int, default `0` meaning unbounded): bounds callgraph edge selection.
- `budgets.max_decomp_lines` (int, default `200`): bounds decompiler excerpt length per function.
- `timeouts.decompile_seconds` (int, default `30`): decompile timeout (evidence + call-arg recovery).
- `advanced.analysis_profile` (string, default `full`): Ghidra analysis mode (`full|minimal|none|reuse`).
- `advanced.profile` (bool, default `false`): emit profiling artifacts (does not change pack layout).
- `advanced.evidence.decomp.include_name_regex` (string, default `""`): regex for evidence inclusion.
- `advanced.evidence.decomp.include_function_ids` (list[string], default `[]`): explicit `function_id`s to include in evidence.
- `advanced.call_args.targets.function_ids` (list[string], default `[]`): additional call-arg target addresses.
- `advanced.call_args.targets.symbol_names` (list[string], default `[]`): additional call-arg target names.
- `advanced.call_args.max_callsites` (int or null, default `null`): optional cap on callsites to recover args for.

## Baseline plan (bounded-first)

Start with a fast, bounded baseline configuration:

```json
{
  "schema": { "name": "binary_lens_config", "version": "v1" },
  "artifacts": {
    "strings": true,
    "callgraph": true,
    "call_args": false,
    "evidence_decomp": true
  },
  "budgets": {
    "max_full_functions": 10,
    "max_strings": 5000,
    "max_call_edges": 20000,
    "max_decomp_lines": 200
  },
  "timeouts": {
    "decompile_seconds": 20
  },
  "advanced": {
    "analysis_profile": "minimal"
  }
}
```

Then progressively request more evidence or call-arg recovery during re-export:

```json
{
  "schema": { "name": "binary_lens_requests", "version": "v1" },
  "evidence": {
    "decomp": {
      "include_function_ids": ["0x401000", "0x402000"]
    }
  },
  "call_args": {
    "targets": {
      "symbol_names": ["getopt", "getopt_long"]
    },
    "max_callsites": 50
  }
}
```

Re-export from an existing pack (with optional binary override):

```sh
binary_lens --from-pack /path/to/out/binary.lens --requests more.json -o /path/to/out/reexport
binary_lens --from-pack /path/to/out/binary.lens --requests more.json --binary /path/to/binary -o /path/to/out/reexport
```

## Requests schema: `binary_lens_requests` (v1)

Requests are narrowly scoped, additive "ask for more" inputs.

```json
{
  "schema": { "name": "binary_lens_requests", "version": "v1" },
  "evidence": {
    "decomp": {
      "include_function_ids": ["0x401000"]
    }
  },
  "call_args": {
    "targets": {
      "symbol_names": ["getopt_long"]
    },
    "max_callsites": 25
  }
}
```

Requests are additive: function ID/target lists are unioned, and `max_callsites` raises (never lowers) the cap.

## Export plan schema: `binary_lens_export_plan` (v1)

Combine both config and requests in one file:

```json
{
  "schema": { "name": "binary_lens_export_plan", "version": "v1" },
  "config": { ...binary_lens_config... },
  "requests": { ...binary_lens_requests... }
}
```

## Resolution and precedence

Settings resolve deterministically:

```
defaults → config → requests → CLI overrides
```

Implied dependencies:
- `call_args` implies `callgraph`.
- evidence requests imply `evidence_decomp`.

The resolved settings and the requested settings are recorded in `binary.lens/manifest.json` under `export_config`. A stable cache key is available at top-level `export_config_digest`, derived from resolved settings + tool versions + Ghidra version + binary hash.
