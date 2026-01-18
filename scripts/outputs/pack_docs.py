from __future__ import annotations

import json
from collections import Counter
from typing import Any, Mapping


def _as_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _fmt_optional(value: Any) -> str:
    if value is None:
        return "\u2014"
    return str(value)


def _fmt_bool(value: Any) -> str:
    as_bool = _as_bool(value)
    if as_bool is None:
        return "unknown"
    return "yes" if as_bool else "no"


def _escape_preview(value: Any, limit: int = 160) -> str:
    if not isinstance(value, str) or not value:
        return ""
    escaped = value.replace("\\", "\\\\")
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    safe: list[str] = []
    for ch in escaped:
        code = ord(ch)
        if 32 <= code <= 126:
            safe.append(ch)
        else:
            safe.append("\\u%04x" % code)
    preview = "".join(safe)
    if limit and len(preview) > limit:
        preview = preview[: max(0, limit - 3)] + "..."
    return preview


def _manifest_value(manifest: Mapping[str, Any], *keys: str) -> Any:
    current: Any = manifest
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _coverage_row(
    coverage: Mapping[str, Any],
    key: str,
    *,
    label: str | None = None,
    path: str | None = None,
) -> str | None:
    entry = coverage.get(key)
    if not isinstance(entry, Mapping):
        return None
    total = entry.get("total")
    selected = entry.get("selected")
    candidates = entry.get("candidate_total")
    excluded = entry.get("excluded")
    max_entries = entry.get("max")
    truncated = entry.get("truncated")
    rendered_path = path or "\u2014"
    return (
        f"| {label or key} | {rendered_path} | {_fmt_optional(selected)} | "
        f"{_fmt_optional(total)} | {_fmt_optional(candidates)} | {_fmt_optional(excluded)} | "
        f"{_fmt_optional(max_entries)} | {_fmt_bool(truncated)} |"
    )


def _coverage_table(manifest: Mapping[str, Any]) -> str:
    coverage = _manifest_value(manifest, "coverage_summary")
    if not isinstance(coverage, Mapping):
        return "_No coverage summary present._\n"

    preferred = [
        ("strings", "strings.json"),
        ("callgraph_edges", "callgraph.json"),
        ("full_functions", "functions/f_<addr>.json"),
        ("cli_options", "cli/options.json"),
        ("cli_parse_loops", "cli/parse_loops.json"),
        ("error_messages", "errors/messages.json"),
        ("error_sites", "errors/error_sites.json"),
        ("exit_calls", "errors/exit_paths.json"),
        ("modes_index", "modes/index.json"),
        ("mode_slices", "modes/slices.json"),
        ("interfaces_env", "interfaces/env.json"),
        ("interfaces_fs", "interfaces/fs.json"),
        ("interfaces_process", "interfaces/process.json"),
        ("interfaces_net", "interfaces/net.json"),
        ("interfaces_output", "interfaces/output.json"),
    ]
    covered = set()
    rows: list[str] = []
    for key, path in preferred:
        row = _coverage_row(coverage, key, label=key, path=path)
        if row is None:
            continue
        rows.append(row)
        covered.add(key)

    for key in sorted(k for k in coverage.keys() if k not in covered):
        row = _coverage_row(coverage, key, label=key)
        if row is None:
            continue
        rows.append(row)

    lines = [
        "| Surface | Path | Exported | Total | Candidates | Excluded | Max | Truncated |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
        *rows,
        "",
    ]
    return "\n".join(lines)


def _string_entry_known(entry: Mapping[str, Any]) -> bool:
    status = _as_str(entry.get("status")) or "unknown"
    if status == "unknown":
        return False
    return bool(_as_str(entry.get("string_id")) or _as_str(entry.get("value")))


def _interface_value(entry: Mapping[str, Any], string_value_by_id: Mapping[str, str]) -> str | None:
    if not _string_entry_known(entry):
        return None
    value = _as_str(entry.get("value"))
    if value:
        return value
    string_id = _as_str(entry.get("string_id"))
    if string_id:
        return _as_str(string_value_by_id.get(string_id))
    return None


def _interface_operation_counts(entries: list[Mapping[str, Any]], *, max_items: int = 8) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for entry in entries:
        op = _as_str(entry.get("operation"))
        if op:
            counter[op] += 1
    return counter.most_common(max_items)


def _interface_known_values(
    entries: list[Mapping[str, Any]],
    *,
    field: str,
    string_value_by_id: Mapping[str, str],
    max_items: int = 25,
) -> list[str]:
    values: set[str] = set()
    for entry in entries:
        raw = entry.get(field)
        if isinstance(raw, Mapping):
            value = _interface_value(raw, string_value_by_id)
            if value:
                values.add(value)
    return sorted(values)[:max_items]


def _interface_known_values_list(
    entries: list[Mapping[str, Any]],
    *,
    list_field: str,
    string_value_by_id: Mapping[str, str],
    max_items: int = 25,
) -> list[str]:
    values: set[str] = set()
    for entry in entries:
        raw = entry.get(list_field)
        if not isinstance(raw, list):
            continue
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            value = _interface_value(item, string_value_by_id)
            if value:
                values.add(value)
    return sorted(values)[:max_items]


def _format_kv_block(pairs: list[tuple[str, Any]]) -> str:
    lines: list[str] = []
    for key, value in pairs:
        if value is None:
            continue
        lines.append(f"- **{key}**: `{value}`")
    if not lines:
        return "- _No metadata available._\n"
    return "\n".join(lines) + "\n"


def _json_code_block(value: Any) -> str:
    return "```json\n" + json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n```\n"


def _first_dict_entry(items: Any) -> Mapping[str, Any] | None:
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, Mapping):
            return item
    return None


def _first_dict_entry_matching(items: Any, predicate) -> Mapping[str, Any] | None:
    if not isinstance(items, list):
        return None
    for item in items:
        if not isinstance(item, Mapping):
            continue
        try:
            if predicate(item):
                return item
        except Exception:
            continue
    return None


def _find_by_id(items: Any, item_id: str) -> Mapping[str, Any] | None:
    if not isinstance(items, list):
        return None
    for item in items:
        if not isinstance(item, Mapping):
            continue
        if item.get("id") == item_id:
            return item
    return None


def _interfaces_known_counts(interfaces_payloads: Mapping[str, Any]) -> dict[str, Any]:
    counts: dict[str, Any] = {}
    env_payload = interfaces_payloads.get("env")
    if isinstance(env_payload, Mapping):
        entries = env_payload.get("entries")
        if isinstance(entries, list):
            known_vars = 0
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                var = entry.get("var")
                if isinstance(var, Mapping) and _string_entry_known(var):
                    known_vars += 1
            counts["env_known_vars"] = known_vars
            counts["env_total_entries"] = len(entries)

    fs_payload = interfaces_payloads.get("fs")
    if isinstance(fs_payload, Mapping):
        entries = fs_payload.get("entries")
        if isinstance(entries, list):
            entries_with_known_path = 0
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                paths = entry.get("paths")
                if isinstance(paths, list) and any(
                    isinstance(path, Mapping) and _string_entry_known(path) for path in paths
                ):
                    entries_with_known_path += 1
            counts["fs_entries_with_known_path"] = entries_with_known_path
            counts["fs_total_entries"] = len(entries)

    process_payload = interfaces_payloads.get("process")
    if isinstance(process_payload, Mapping):
        entries = process_payload.get("entries")
        if isinstance(entries, list):
            entries_with_known_command = 0
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                commands = entry.get("commands")
                if isinstance(commands, list) and any(
                    isinstance(cmd, Mapping) and _string_entry_known(cmd) for cmd in commands
                ):
                    entries_with_known_command += 1
            counts["process_entries_with_known_command"] = entries_with_known_command
            counts["process_total_entries"] = len(entries)

    net_payload = interfaces_payloads.get("net")
    if isinstance(net_payload, Mapping):
        entries = net_payload.get("entries")
        if isinstance(entries, list):
            ports_known = 0
            hosts_known = 0
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                ports = entry.get("ports")
                if isinstance(ports, Mapping) and ports.get("status") == "known":
                    ports_known += 1
                hosts = entry.get("hosts")
                if isinstance(hosts, list) and any(
                    isinstance(host, Mapping) and _string_entry_known(host) for host in hosts
                ):
                    hosts_known += 1
            counts["net_entries_with_known_port"] = ports_known
            counts["net_entries_with_known_host"] = hosts_known
            counts["net_total_entries"] = len(entries)

    output_payload = interfaces_payloads.get("output")
    if isinstance(output_payload, Mapping):
        entries = output_payload.get("entries")
        if isinstance(entries, list):
            channel_known = 0
            templates_known = 0
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                channel = entry.get("channel")
                if isinstance(channel, Mapping) and channel.get("status") == "known":
                    channel_known += 1
                templates = entry.get("templates")
                if isinstance(templates, list) and any(
                    isinstance(t, Mapping) and _string_entry_known(t) for t in templates
                ):
                    templates_known += 1
            counts["output_channel_known"] = channel_known
            counts["output_templates_known"] = templates_known
            counts["output_total_entries"] = len(entries)

    return counts


def _interfaces_summary(interfaces_payloads: Mapping[str, Any]) -> str:
    if not isinstance(interfaces_payloads, Mapping):
        return "_No interfaces payload present._\n"

    known_counts = _interfaces_known_counts(interfaces_payloads)

    sections: list[str] = ["## Interfaces (summary)\n"]
    for surface in ("env", "fs", "process", "net", "output"):
        payload = interfaces_payloads.get(surface)
        if not isinstance(payload, Mapping):
            continue
        entries = payload.get("entries")
        if not isinstance(entries, list):
            continue
        entry_count = len(entries)
        total_candidates = payload.get("total_candidates")
        truncated = payload.get("truncated")
        max_entries = payload.get("max_entries")
        detail_bits: list[str] = []
        if surface == "env":
            env_known = known_counts.get("env_known_vars")
            if isinstance(env_known, int):
                detail_bits.append(f"vars_known={env_known}/{entry_count}")
        elif surface == "fs":
            fs_known = known_counts.get("fs_entries_with_known_path")
            if isinstance(fs_known, int):
                detail_bits.append(f"entries_with_known_path={fs_known}/{entry_count}")
        elif surface == "process":
            proc_known = known_counts.get("process_entries_with_known_command")
            if isinstance(proc_known, int):
                detail_bits.append(f"entries_with_known_command={proc_known}/{entry_count}")
        elif surface == "net":
            ports_known = known_counts.get("net_entries_with_known_port")
            hosts_known = known_counts.get("net_entries_with_known_host")
            if isinstance(ports_known, int):
                detail_bits.append(f"entries_with_known_port={ports_known}/{entry_count}")
            if isinstance(hosts_known, int):
                detail_bits.append(f"entries_with_known_host={hosts_known}/{entry_count}")
        elif surface == "output":
            channel_known = known_counts.get("output_channel_known")
            templates_known = known_counts.get("output_templates_known")
            if isinstance(channel_known, int):
                detail_bits.append(f"channel_known={channel_known}/{entry_count}")
            if isinstance(templates_known, int):
                detail_bits.append(f"template_known={templates_known}/{entry_count}")

        detail = f" ({', '.join(detail_bits)})" if detail_bits else ""
        sections.append(
            f"- `{surface}`: {entry_count}/{_fmt_optional(total_candidates)} "
            f"(max={_fmt_optional(max_entries)}, truncated={_fmt_bool(truncated)}){detail}"
        )

    sections.append("")

    output_payload = interfaces_payloads.get("output")
    if isinstance(output_payload, Mapping):
        entries = output_payload.get("entries")
        if isinstance(entries, list):
            known_channel = 0
            channel_kinds: Counter[str] = Counter()
            known_template_entries = 0
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                channel = entry.get("channel")
                if isinstance(channel, Mapping) and channel.get("status") == "known":
                    known_channel += 1
                    kind = _as_str(channel.get("kind"))
                    if kind:
                        channel_kinds[kind] += 1
                templates = entry.get("templates")
                if isinstance(templates, list) and any(
                    isinstance(t, Mapping) and _string_entry_known(t) for t in templates
                ):
                    known_template_entries += 1

            if entries:
                sections.append("### Output details\n")
                sections.append(f"- Channel known: {known_channel}/{len(entries)}")
                if channel_kinds:
                    rendered = ", ".join(f"{kind}={count}" for kind, count in channel_kinds.most_common())
                    sections.append(f"- Channel kinds: {rendered}")
                sections.append(f"- Entries with a known template: {known_template_entries}/{len(entries)}")
                sections.append("")

    return "\n".join(sections)


def build_pack_markdown_docs(
    *,
    pack_index: Mapping[str, Any],
    manifest: Mapping[str, Any],
    binary_info: Mapping[str, Any],
    modes: Mapping[str, Any],
    interfaces_index: Mapping[str, Any],
    interfaces: Mapping[str, Any],
    strings: Mapping[str, Any] | None = None,
    cli_options: Mapping[str, Any] | None = None,
    error_messages: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Generate Markdown documentation embedded into the pack itself.

    These docs are intended to be the canonical consumer guidance for a specific
    exported pack (human and LM readable). They should only summarize/route
    existing pack content and must not introduce new "semantic extraction".
    """

    binary_name = (
        _as_str(_manifest_value(manifest, "binary_name"))
        or _as_str(binary_info.get("name"))
        or "unknown-binary"
    )
    sha256 = _as_str(_manifest_value(manifest, "binary_hashes", "sha256")) or _as_str(
        _manifest_value(binary_info, "hashes", "sha256")
    )

    created_at = _as_str(_manifest_value(manifest, "created_at"))
    tool_version = _as_str(_manifest_value(manifest, "tool", "version"))
    tool_revision = _as_str(_manifest_value(manifest, "tool", "revision"))
    ghidra_version = _as_str(_manifest_value(manifest, "ghidra_version"))
    executable_format = _as_str(_manifest_value(manifest, "executable_format"))
    target_arch = _as_str(_manifest_value(manifest, "target_arch"))
    compiler_spec = _as_str(_manifest_value(manifest, "compiler_spec"))

    docs: dict[str, str] = {}
    string_value_by_id: dict[str, str] = {}
    if isinstance(strings, Mapping):
        for entry in strings.get("strings", []) or []:
            if not isinstance(entry, Mapping):
                continue
            string_id = _as_str(entry.get("id"))
            value = entry.get("value")
            if string_id and isinstance(value, str):
                string_value_by_id[string_id] = value

    docs["docs/README.md"] = (
        "# Pack docs\n\n"
        "This directory contains the canonical consumer documentation for this exported `binary_lens` pack.\n\n"
        "Start here:\n\n"
        f"- [`overview.md`](overview.md) \u2014 summary for `{binary_name}`\n"
        "- [`navigation.md`](navigation.md) \u2014 how to navigate evidence + interpret unknowns/truncation\n"
        "- [`surfaces.md`](surfaces.md) \u2014 what each file/directory represents\n"
        "- [`field_guide.md`](field_guide.md) \u2014 field meanings and common patterns\n"
        "- [`examples.md`](examples.md) \u2014 worked examples (with evidence trails)\n"
    )

    caveats: list[str] = []
    coverage = _manifest_value(manifest, "coverage_summary")
    if isinstance(coverage, Mapping):
        truncated_entries: list[tuple[int, str]] = []
        for key, entry in coverage.items():
            if not isinstance(entry, Mapping):
                continue
            if entry.get("truncated") is not True:
                continue
            total = entry.get("total")
            selected = entry.get("selected")
            if isinstance(total, int) and isinstance(selected, int):
                truncated_entries.append((total - selected, f"`{key}` truncated: {selected}/{total}"))
            else:
                truncated_entries.append((0, f"`{key}` truncated"))
        truncated_entries.sort(reverse=True)
        if truncated_entries:
            caveats.append("Some surfaces are truncated (bounded excerpts or capped exports):")
            caveats.extend([item for _, item in truncated_entries[:8]])

        cli_parse = coverage.get("cli_parse_loops")
        cli_opts = coverage.get("cli_options")
        if isinstance(cli_parse, Mapping) and isinstance(cli_opts, Mapping):
            if (
                isinstance(cli_parse.get("total"), int)
                and cli_parse.get("total") == 0
                and isinstance(cli_opts.get("total"), int)
                and cli_opts.get("total") > 0
            ):
                caveats.append(
                    "CLI options were found but parse loops were not localized (treat option scoping as uncertain)."
                )

    known_counts = _interfaces_known_counts(interfaces)
    output_total = known_counts.get("output_total_entries")
    output_channel_known = known_counts.get("output_channel_known")
    if isinstance(output_total, int) and output_total > 0 and isinstance(output_channel_known, int):
        unknown = output_total - output_channel_known
        if unknown > 0:
            caveats.append(f"Some output channels are unknown ({unknown}/{output_total}).")

    overview_sections: list[str] = [
        f"# Overview: `{binary_name}`\n",
        "This pack is an evidence-linked export produced by `binary_lens`.\n"
        "Large inventories are sharded; evidence excerpts remain bounded.\n",
        "## Pack metadata\n",
        _format_kv_block(
            [
                ("binary", binary_name),
                ("sha256", sha256),
                ("created_at", created_at),
                ("executable_format", executable_format),
                ("target_arch", target_arch),
                ("compiler_spec", compiler_spec),
                ("ghidra_version", ghidra_version),
                ("binary_lens_version", tool_version),
                ("binary_lens_revision", tool_revision),
            ]
        ),
        "## Coverage\n",
        _coverage_table(manifest),
        "## Observations & caveats\n",
        ("- _No notable caveats detected._\n" if not caveats else "\n".join(f"- {c}" for c in caveats) + "\n"),
        "## Suggested entrypoints\n",
        "- `docs/overview.md` (this file)\n"
        "- `contracts/index.json` (mode-scoped contract index; recommended human/LLM entrypoint)\n"
        "- `contracts/modes/<mode_id>.md` (per-mode contract view)\n"
        "- `index.json` (machine-readable entrypoints)\n"
        "- `manifest.json` (coverage summary)\n",
        _interfaces_summary(interfaces),
        "## Notes\n",
        "- When a field is `unknown`, the exporter could not establish it (not \"false\").\n"
        "- When `truncated: true` appears, treat the record/list as partial; see `manifest.json` for coverage context.\n"
        "- Coverage `Candidates`/`Excluded` are pre-classification counts when available; `Total` "
        "is the exportable/discovered count.\n"
        "- `manifest.json` is the canonical metadata source (coverage + bounds).\n"
        "- Callsite evidence lives in `evidence/callsites.json` (sharded list); resolve by `callsite_id`.\n"
        "- Callsite evidence is emitted on-demand for referenced callsites; re-export with "
        "`callsite_evidence=all` to include every callgraph callsite.\n",
    ]
    docs["docs/overview.md"] = "\n".join(overview_sections).strip() + "\n"

    docs["docs/navigation.md"] = (
        "# Navigation guide\n\n"
        "This pack is a directory of JSON + evidence excerpts. JSON files are authoritative; evidence files are bounded.\n\n"
        "## Start here\n\n"
        "- `index.json` \u2192 structured entrypoints + conventions\n"
        "- `manifest.json` \u2192 coverage summary (what was exported vs omitted)\n"
        "- `contracts/index.json` \u2192 mode-scoped contract views (recommended human/LLM entrypoint)\n\n"
        "## Follow `*_ref` pointers\n\n"
        "Many records include `*_ref` / `*_refs` fields. These are paths relative to the pack root.\n"
        "When in doubt, follow the refs instead of guessing file names.\n\n"
        "## Sharded lists\n\n"
        "Some large lists are sharded into multiple files. The index file includes\n"
        "`format: sharded_list/v1` and a `shards` list with relative paths to follow.\n\n"
        "## Evidence files\n\n"
        "- `evidence/callsites.json`: sharded callsite evidence index (follow `shards[*].path`).\n"
        "- `evidence/decomp/f_<addr>.json`: bounded decompiler excerpt for a function (may include `error: decompile_failed`).\n\n"
        "Callsite evidence is emitted only for referenced callsites. Re-export with "
        "`callsite_evidence=all` to include evidence for every callgraph callsite.\n\n"
        "## IDs and lookups\n\n"
        "- `function_id` values are addresses as hex strings (e.g., `00118020`). Resolve names/signatures via `callgraph/nodes.json` (sharded index).\n"
        "- `string_id` values (e.g., `s_0020733a`) resolve via `strings.json` (sharded index).\n"
        "- `callgraph.json` edges use `from`/`to` addresses; resolve names/signatures via `callgraph/nodes.json` (sharded index).\n"
        "- `callgraph/nodes.json` is the canonical address \u2192 name/signature table (includes isolated functions).\n"
        "- `callsite_id` values resolve via `evidence/callsites.json` (sharded index).\n\n"
        "## Truncation and unknowns\n\n"
        "- Coverage/truncation is summarized in `manifest.json` (`coverage_summary`).\n"
        "- `status: resolved|unresolved|unknown` marks string-valued fields (`unresolved` means a value was seen without a `string_id`).\n"
        "- `status: known|unknown` marks non-string constant recovery (ports, flags, etc.).\n"
        "\n"
        "## Two-minute walkthrough\n\n"
        "1. Pick a mode from `modes/index.json` \u2192 `modes[*]`.\n"
        "2. From `modes/index.json`, use `dispatch_sites[*].callsite_id` with `evidence/callsites.json` to locate the callsite record.\n"
        "3. From the callsite record, note the `from` function address and open `functions/f_<addr>.json`.\n"
        "4. Use that function record to pivot to `strings.json`, `errors/`, `cli/`, and (if present) `evidence/decomp/`.\n"
    )

    docs["docs/surfaces.md"] = (
        "# Pack surfaces\n\n"
        "This is a guided map of the major sections in the pack.\n\n"
        "## Pack root\n\n"
        "- `README.md`: top-level pointer into docs and key entry files\n"
        "- `index.json`: machine-readable index of canonical entrypoints and conventions\n"
        "- `manifest.json`: canonical export metadata and coverage summary\n"
        "\n"
        "## Evidence-linked lenses\n\n"
        "- `modes/`: multiplexing/subcommand surfaces (mode inventory, dispatch sites, per-mode slices)\n"
        "- `contracts/`: mode-scoped contract views (joins over modes/cli/interfaces/errors)\n"
        "- `interfaces/`: callsite-anchored external interface inventory (env/fs/process/net/output)\n"
        "- `cli/`: CLI option inventory and parse loop localization\n"
        "- `errors/`: error message catalog + emitting callsites + exit paths\n\n"
        "## Low-level inventories\n\n"
        "- `functions/`: selected full function exports\n"
        "- `strings.json`: string inventory (`id` + `value`, sharded index)\n"
        "- `callgraph.json`: call edges (sharded index)\n"
        "- `callgraph/nodes.json`: callgraph node metadata (sharded index)\n\n"
        "## Raw evidence\n\n"
        "- `evidence/callsites.json`: callsite ids with `from`/`targets` addresses (resolve names via `callgraph/nodes.json`)\n"
        "- `evidence/decomp/`: bounded decompiler excerpts\n\n"
        "## Schemas\n\n"
        "- `schema/README.md`: format notes for this pack version\n"
    )

    docs["docs/field_guide.md"] = (
        "# Field guide\n\n"
        "This is a reference for what the major files and common fields mean.\n\n"
        "## Common patterns\n\n"
        "- `*_ref` / `*_refs`: file paths relative to the pack root.\n"
        "- `callsites_ref`: shared callsite evidence index (sharded list).\n"
        "- `truncated`: when present, exporter bounded that record/list; see `manifest.json` for coverage context.\n"
        "- `status: resolved|unresolved|unknown`: string-valued field resolution (`unresolved` means value without a `string_id`).\n"
        "- `status: known|unknown`: non-string constant recovery (ports, flags, etc.).\n"
        "- `string_id`: canonical string reference; resolve via `strings.json` (address/value omitted when resolved).\n"
        "- `format: sharded_list/v1`: index into shard files; follow `shards[*].path` to enumerate.\n\n"
        "## Evidence\n\n"
        "- `evidence/callsites.json`: callsite ids with `from`/`targets` addresses (resolve names via `callgraph/nodes.json`).\n"
        "- `evidence/decomp/f_<addr>.json`: bounded decompiler excerpt for a function.\n\n"
        "## Modes (`modes/`)\n\n"
        "- `modes/index.json`: mode inventory; each mode includes `mode_id`, `kind`, and dispatch evidence (resolve names via `token.string_id` + `strings.json`).\n"
        "- `modes/slices.json`: per-mode \"start here\" slices (sharded index).\n\n"
        "## Contracts (`contracts/`)\n\n"
        "- `contracts/index.json`: mode contract index (sharded list).\n"
        "- `contracts/modes/<mode_id>.md`: per-mode contract view (inputs/outputs/diagnostics with evidence refs).\n\n"
        "## Interfaces (`interfaces/`)\n\n"
        "Each entry is anchored to a `callsite_id` (resolve owning functions via `callsites_ref`); string-valued fields prefer `string_id` and omit value/address when resolved.\n\n"
        "- `env.json`: getenv/setenv/etc; `var` may be `resolved`, `unresolved`, or `unknown`.\n"
        "- `fs.json`: open/chdir/stat/etc; `paths[*]` may be `resolved`, `unresolved`, or `unknown`.\n"
        "- `process.json`: exec*/spawn/system; `commands[*]` may be `resolved`, `unresolved`, or `unknown`.\n"
        "- `net.json`: socket/connect/getaddrinfo/etc; `hosts[*]`/`ports` are best-effort.\n"
        "- `output.json`: printf/fprintf/write/etc; `templates[*]` and `channel` are best-effort.\n\n"
        "## CLI (`cli/`)\n\n"
        "- `cli/options.json`: option token inventory (ids + parse loop/callsite refs).\n"
        "- `cli/parse_loops.json`: localized parse loops (callsite ids + optstring evidence; resolve owning functions via callsites).\n\n"
        "## Errors (`errors/`)\n\n"
        "- `errors/messages.json`: `string_id`, `bucket`, and emitting callsite ids (resolve values via `strings.json`).\n"
        "- `errors/exit_paths.json`: exit/abort callsites with recovered exit codes when possible (sharded index).\n"
        "- `errors/error_sites.json`: error emitter aggregates with `callsites[{callsite_id,status}]` (`status_arg_zero|status_arg_nonzero|unknown`), plus `imports` and `severity` (sharded index).\n"
        "\n"
        "## Callgraph (`callgraph/`)\n\n"
        "- `callgraph.json`: call edges; each edge includes `callsite`, `from`, and `to` addresses.\n"
        "- `callgraph/nodes.json`: canonical address \u2192 name/signature table (includes isolated functions).\n"
    )

    examples_sections: list[str] = [
        f"# Worked examples: `{binary_name}`\n",
        "These examples use real records from this pack and show how to follow evidence trails.\n",
    ]

    top_mode = _first_dict_entry(modes.get("modes")) if isinstance(modes, Mapping) else None
    if isinstance(top_mode, Mapping):
        mode_id = _as_str(top_mode.get("mode_id"))
        dispatch_site = _first_dict_entry(top_mode.get("dispatch_sites"))
        rep_callsite = _as_str(dispatch_site.get("callsite_id")) if isinstance(dispatch_site, Mapping) else None
        mode_name = _as_str(top_mode.get("name"))
        if not mode_name:
            token = top_mode.get("token") if isinstance(top_mode.get("token"), Mapping) else {}
            string_id = _as_str(token.get("string_id"))
            if string_id:
                mode_name = _as_str(string_value_by_id.get(string_id))
        rendered = {
            "mode_id": mode_id,
            "name": mode_name,
            "kind": top_mode.get("kind"),
            "dispatch_sites": (top_mode.get("dispatch_sites") or [])[:1],
            "dispatch_roots": (top_mode.get("dispatch_roots") or [])[:1],
        }
        if rep_callsite:
            rendered["representative_callsite_id"] = rep_callsite
        if isinstance(modes, Mapping) and modes.get("callsites_ref"):
            rendered["callsites_ref"] = modes.get("callsites_ref")
        examples_sections.extend(
            [
                "## Example: a mode dispatch trail\n",
                "Start from a mode and pivot into evidence and owning functions.\n\n"
                "Steps:\n\n"
                "1. Open `modes/index.json` and locate the mode by `mode_id`.\n"
                "2. Use `dispatch_sites[*].callsite_id` from `modes/index.json` with `callsites_ref` to locate the callsite record.\n"
                "3. From the callsite record, open the owning function (`functions/f_<addr>.json`) and its decompiler excerpt (`evidence/decomp/`).\n",
                _json_code_block(rendered),
            ]
        )

    output_payload = interfaces.get("output") if isinstance(interfaces, Mapping) else None
    if isinstance(output_payload, Mapping):
        entries = output_payload.get("entries")
        output_example = _first_dict_entry_matching(
            entries,
            lambda e: isinstance(e.get("channel"), Mapping)
            and e.get("channel", {}).get("status") == "known"
            and isinstance(e.get("templates"), list)
            and any(isinstance(t, Mapping) and _string_entry_known(t) for t in e.get("templates")),
        )
        if isinstance(output_example, Mapping):
            channel = output_example.get("channel") if isinstance(output_example.get("channel"), Mapping) else {}
            template_value = None
            templates = output_example.get("templates")
            if isinstance(templates, list):
                for template in templates:
                    if isinstance(template, Mapping) and _string_entry_known(template):
                        template_value = _interface_value(template, string_value_by_id)
                        break
            examples_sections.extend(
                [
                    "## Example: an output template\n",
                    "This record anchors a user-visible template to a specific callsite.\n",
                    _json_code_block(
                        {
                            "operation": output_example.get("operation"),
                            "channel": channel,
                            "template_preview": template_value,
                            "callsite_id": output_example.get("callsite_id"),
                            "callsites_ref": output_payload.get("callsites_ref"),
                        }
                    ),
                ]
            )

    env_payload = interfaces.get("env") if isinstance(interfaces, Mapping) else None
    if isinstance(env_payload, Mapping):
        env_example = _first_dict_entry_matching(
            env_payload.get("entries"),
            lambda e: isinstance(e.get("var"), Mapping) and _string_entry_known(e.get("var", {})),
        )
        if isinstance(env_example, Mapping):
            examples_sections.extend(
                [
                    "## Example: an environment-variable interaction\n",
                    _json_code_block(
                        {
                            "operation": env_example.get("operation"),
                            "var": env_example.get("var"),
                            "callsite_id": env_example.get("callsite_id"),
                            "callsites_ref": env_payload.get("callsites_ref"),
                        }
                    ),
                ]
            )

    fs_payload = interfaces.get("fs") if isinstance(interfaces, Mapping) else None
    if isinstance(fs_payload, Mapping):
        fs_example = _first_dict_entry_matching(
            fs_payload.get("entries"),
            lambda e: isinstance(e.get("paths"), list)
            and any(isinstance(p, Mapping) and _string_entry_known(p) for p in e.get("paths")),
        )
        if isinstance(fs_example, Mapping):
            path_preview = None
            paths = fs_example.get("paths")
            if isinstance(paths, list):
                for path in paths:
                    if isinstance(path, Mapping) and _string_entry_known(path):
                        path_preview = _interface_value(path, string_value_by_id)
                        break
            examples_sections.extend(
                [
                    "## Example: a filesystem interaction\n",
                    _json_code_block(
                        {
                            "operation": fs_example.get("operation"),
                            "path_preview": path_preview,
                            "callsite_id": fs_example.get("callsite_id"),
                            "callsites_ref": fs_payload.get("callsites_ref"),
                        }
                    ),
                ]
            )

    if isinstance(cli_options, Mapping):
        options_list = cli_options.get("options")
        cli_example = _first_dict_entry(options_list)
        if isinstance(cli_example, Mapping):
            examples_sections.extend(
                [
                    "## Example: a CLI option record\n",
                    _json_code_block(
                        {
                            "id": cli_example.get("id"),
                            "short_name": cli_example.get("short_name"),
                            "long_name": cli_example.get("long_name"),
                            "has_arg": cli_example.get("has_arg"),
                            "parse_loop_ids": cli_example.get("parse_loop_ids"),
                            "parse_sites": cli_example.get("parse_sites"),
                            "callsites_ref": cli_options.get("callsites_ref"),
                        }
                    ),
                ]
            )

    if isinstance(error_messages, Mapping):
        messages = error_messages.get("messages")
        message = _first_dict_entry(messages)
        if isinstance(message, Mapping):
            string_id = _as_str(message.get("string_id"))
            examples_sections.extend(
                [
                    "## Example: an error/usage message\n",
                    _json_code_block(
                        {
                            "bucket": message.get("bucket"),
                            "string_id": string_id,
                            "emitting_callsites": message.get("emitting_callsites"),
                            "callsites_ref": error_messages.get("callsites_ref"),
                            "strings_ref": "strings.json",
                        }
                    ),
                ]
            )

    docs["docs/examples.md"] = "\n".join(examples_sections).strip() + "\n"

    schema_version = _as_str(_manifest_value(manifest, "format_version")) or _as_str(
        _manifest_value(pack_index, "schema", "version")
    )
    docs["schema/README.md"] = (
        f"# `binary_lens` pack format ({schema_version or 'unknown'})\n\n"
        "This directory documents the on-disk layout and conventions for this pack.\n\n"
        "## Conventions\n\n"
        "- `*_ref` / `*_refs` paths are relative to the pack root.\n"
        "- `callsites_ref` points at the shared callsite evidence index (sharded list).\n"
        "- Large inventories are sharded (`format: sharded_list/v1`); evidence excerpts may be bounded.\n"
        "- Consult `manifest.json` for coverage and known omissions.\n"
        "- `status: resolved|unresolved|unknown` applies to string-valued fields (`unresolved` means value without `string_id`).\n"
        "- `status: known|unknown` applies to non-string constant recovery.\n"
        "- `unknown` indicates the exporter could not establish a value.\n"
        "- `format: sharded_list/v1` marks a shard index; follow `shards[*].path`.\n\n"
        "## Canonical entrypoints\n\n"
        "- `index.json` (start here)\n"
        "- `manifest.json`\n"
        "- `docs/overview.md`\n"
        "- `docs/field_guide.md`\n"
        "\n"
        "## Callgraph\n\n"
        "- `callgraph.json` is a sharded list of call edges; edges include `callsite`, `from`, and `to` addresses.\n"
        "- `callgraph/nodes.json` is the canonical address \u2192 name/signature table (includes isolated functions).\n"
        "\n"
        "## Callsites\n\n"
        "- `evidence/callsites.json` is a sharded list of callsite ids with `from`/`targets` addresses.\n"
        "\n"
        "## Errors\n\n"
        "- `errors/messages.json` is a sharded list of `{string_id, bucket, emitting_callsites}` records.\n"
        "- `errors/error_sites.json` is a sharded list of `{callsites, imports, severity}` aggregates (each callsite includes `callsite_id` + `status` (`status_arg_zero|status_arg_nonzero|unknown`)).\n"
        "- `errors/exit_paths.json` is a sharded list of `{callsite_id, exit_code}` records.\n"
    )

    return docs
