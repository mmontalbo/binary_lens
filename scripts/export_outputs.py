import json
import os

from export_collectors import collect_flow_summary, function_size
from export_primitives import addr_filename, addr_str
from ghidra.app.decompiler import DecompInterface
from ghidra.framework import Application


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def write_json(path, obj):
    handle = open(path, "w")
    try:
        handle.write(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True))
        handle.write("\n")
    finally:
        handle.close()


def write_text(path, content):
    handle = open(path, "w")
    try:
        handle.write(content)
    finally:
        handle.close()


def pack_path(*parts):
    return "/".join(parts)


def maybe_call(obj, method_name):
    try:
        method = getattr(obj, method_name)
    except Exception:
        return None
    try:
        return method()
    except Exception:
        return None


def get_program_hashes(program):
    hashes = {}
    sha256 = maybe_call(program, "getExecutableSHA256")
    if sha256:
        hashes["sha256"] = sha256
    md5 = maybe_call(program, "getExecutableMD5")
    if md5:
        hashes["md5"] = md5
    return hashes


def build_binary_info(program):
    language = program.getLanguage()
    compiler = program.getCompilerSpec()
    info = {
        "name": program.getName(),
        "executable_format": program.getExecutableFormat(),
        "language": {
            "id": str(language.getLanguageID()),
            "processor": str(language.getProcessor()),
            "endian": "big" if language.isBigEndian() else "little",
        },
        "compiler_spec": str(compiler.getCompilerSpecID()),
        "default_pointer_size": program.getDefaultPointerSize(),
        "image_base": addr_str(program.getImageBase()),
        "address_range": {
            "min": addr_str(program.getMinAddress()),
            "max": addr_str(program.getMaxAddress()),
        },
    }
    hashes = get_program_hashes(program)
    if hashes:
        info["hashes"] = hashes
    return info, hashes


def write_callsite_records(callsite_records, call_edges, evidence_callsites_dir, extra_callsites=None):
    # Only emit callsite evidence for selected edges plus explicitly requested extras.
    selected_callsite_records = {}
    for edge in call_edges:
        callsite = edge.get("callsite")
        base_record = callsite_records.get(callsite)
        if base_record is None:
            continue
        record = selected_callsite_records.get(callsite)
        if record is None:
            record = {
                "callsite": base_record.get("callsite"),
                "from": base_record.get("from"),
                "instruction": base_record.get("instruction"),
                "targets": [],
            }
            selected_callsite_records[callsite] = record
        record["targets"].append(edge.get("to"))

    if extra_callsites:
        for callsite in extra_callsites:
            if callsite in selected_callsite_records:
                continue
            base_record = callsite_records.get(callsite)
            if base_record is None:
                continue
            selected_callsite_records[callsite] = {
                "callsite": base_record.get("callsite"),
                "from": base_record.get("from"),
                "instruction": base_record.get("instruction"),
                "targets": list(base_record.get("targets") or []),
            }

    callsite_paths = {}
    for callsite, record in selected_callsite_records.items():
        filename = addr_filename("cs", callsite, "json")
        callsite_paths[callsite] = pack_path("evidence", "callsites", filename)
        write_json(os.path.join(evidence_callsites_dir, filename), record)
    return callsite_paths


def build_callgraph_payload(call_edges, total_edges, truncated_edges, options, call_edge_stats):
    return {
        "total_edges": total_edges,
        "selected_edges": len(call_edges),
        "truncated": truncated_edges,
        "max_edges": options["max_call_edges"],
        "selection_strategy": "capability_signals_then_sorted_internal_calls",
        "filters": {
            "exclude_external_callers": True,
            "exclude_thunk_callers": True,
            "exclude_jump_calls": True,
        },
        "metrics": call_edge_stats,
        "edges": call_edges,
    }


def build_cli_options_payload(options_list, total_options, truncated, options):
    return {
        "total_options": total_options,
        "selected_options": len(options_list),
        "truncated": truncated,
        "max_options": options.get("max_cli_options", 0),
        "options": options_list,
    }


def build_cli_parse_loops_payload(parse_loops, total_parse_loops, truncated, options):
    return {
        "total_parse_loops": total_parse_loops,
        "selected_parse_loops": len(parse_loops),
        "truncated": truncated,
        "max_parse_loops": options.get("max_cli_parse_loops", 0),
        "parse_loops": parse_loops,
    }


def build_surface_map_payload(cli_surface, options):
    cli_section = {}
    parse_loops = cli_surface.get("parse_loops", [])
    options_list = cli_surface.get("options", [])

    # Provide a minimal "start here" map for CLI exploration.
    primary_parse_loops = []
    for entry in parse_loops[:3]:
        primary_parse_loops.append({
            "function": entry.get("function"),
            "representative_callsite_id": entry.get("representative_callsite_id"),
            "representative_callsite_ref": entry.get("representative_callsite_ref"),
        })

    table_candidates = {}
    for entry in parse_loops:
        longopts = entry.get("longopts") or {}
        addr = longopts.get("address")
        if not addr:
            continue
        count = longopts.get("entry_count", 0)
        existing = table_candidates.get(addr, 0)
        if count > existing:
            table_candidates[addr] = count
    option_tables = []
    for addr, count in sorted(table_candidates.items(), key=lambda item: (-item[1], item[0])):
        option_tables.append({
            "address": addr,
            "entry_count": count,
        })
        if len(option_tables) >= 3:
            break

    top_options = []
    for entry in options_list[:10]:
        top_options.append({
            "id": entry.get("id"),
            "long_name": entry.get("long_name"),
            "short_name": entry.get("short_name"),
            "parse_site_count": len(entry.get("parse_sites") or []),
            "evidence_count": len(entry.get("evidence") or []),
        })

    if primary_parse_loops:
        cli_section["primary_parse_loops"] = primary_parse_loops
    if option_tables:
        cli_section["option_tables"] = option_tables
    if top_options:
        cli_section["top_options"] = top_options

    return {
        "cli": cli_section,
    }


def write_function_exports(
    program,
    full_functions,
    options,
    string_refs_by_func,
    selected_string_ids,
    calls_by_func,
    functions_dir,
    evidence_decomp_dir,
    monitor,
):
    listing = program.getListing()
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(program)

    for func in full_functions:
        entry_addr = addr_str(func.getEntryPoint())
        func_filename = addr_filename("f", entry_addr, "json")
        func_md_filename = addr_filename("f", entry_addr, "md")
        decomp_filename = addr_filename("f", entry_addr, "json")
        decomp_ref = pack_path("evidence", "decomp", decomp_filename)

        params = []
        try:
            for param in func.getParameters():
                params.append({
                    "name": param.getName(),
                    "data_type": param.getDataType().getDisplayName(),
                    "storage": str(param.getVariableStorage()),
                })
        except Exception:
            params = []

        try:
            return_type = func.getReturnType().getDisplayName()
        except Exception:
            return_type = None

        calls = calls_by_func.get(entry_addr, [])
        if len(calls) > options["max_calls_per_function"]:
            calls = calls[: options["max_calls_per_function"]]
            calls_truncated = True
        else:
            calls_truncated = False

        string_refs = []
        raw_refs = string_refs_by_func.get(entry_addr, set())
        for string_id in raw_refs:
            if string_id in selected_string_ids:
                string_refs.append(string_id)

        flow_summary = collect_flow_summary(listing, func)

        detail = {
            "name": func.getName(),
            "address": entry_addr,
            "size": function_size(func),
            "is_external": func.isExternal(),
            "is_thunk": func.isThunk(),
            "signature": func.getSignature().toString(),
            "calling_convention": func.getCallingConventionName(),
            "return_type": return_type,
            "parameters": params,
            "strings": sorted(string_refs),
            "calls": calls,
            "calls_truncated": calls_truncated,
            "control_flow": flow_summary,
            "decompiler_excerpt": decomp_ref,
        }

        write_json(os.path.join(functions_dir, func_filename), detail)

        md_content = "# Function %s (%s)\n\n" % (func.getName(), entry_addr)
        md_content += "Evidence:\n\n"
        md_content += "- JSON: %s\n" % pack_path("functions", func_filename)
        md_content += "- Decompiler excerpt: %s\n\n" % decomp_ref
        md_content += "Notes:\n\n- [ ] Observations\n- [ ] Questions\n"
        write_text(os.path.join(functions_dir, func_md_filename), md_content)

        # Decompiler excerpts are bounded to keep evidence lightweight.
        result = decomp_interface.decompileFunction(func, 30, monitor)
        decomp_excerpt = {
            "function": {
                "name": func.getName(),
                "address": entry_addr,
            },
            "truncated": False,
            "line_count": 0,
            "lines": [],
        }
        if result and result.decompileCompleted():
            try:
                decomp_text = result.getDecompiledFunction().getC()
            except Exception:
                decomp_text = None
            if decomp_text:
                lines = decomp_text.splitlines()
                decomp_excerpt["line_count"] = len(lines)
                if len(lines) > options["max_decomp_lines"]:
                    decomp_excerpt["lines"] = lines[: options["max_decomp_lines"]]
                    decomp_excerpt["truncated"] = True
                else:
                    decomp_excerpt["lines"] = lines
        else:
            decomp_excerpt["error"] = "decompile_failed"
        write_json(os.path.join(evidence_decomp_dir, decomp_filename), decomp_excerpt)


def build_manifest(options, hashes, binary_lens_version, format_version):
    manifest = {
        "binary_lens_version": binary_lens_version,
        "format_version": format_version,
        "ghidra_version": str(Application.getApplicationVersion()),
        "bounds": {
            "max_full_functions": options["max_full_functions"],
            "max_functions_index": options["max_functions_index"],
            "max_strings": options["max_strings"],
            "max_call_edges": options["max_call_edges"],
            "max_calls_per_function": options["max_calls_per_function"],
            "max_decomp_lines": options["max_decomp_lines"],
            "max_cli_options": options.get("max_cli_options"),
            "max_cli_parse_loops": options.get("max_cli_parse_loops"),
            "max_cli_option_evidence": options.get("max_cli_option_evidence"),
            "max_cli_parse_sites_per_option": options.get("max_cli_parse_sites_per_option"),
            "max_cli_longopt_entries": options.get("max_cli_longopt_entries"),
            "max_cli_callsites_per_parse_loop": options.get("max_cli_callsites_per_parse_loop"),
            "max_cli_flag_vars": options.get("max_cli_flag_vars"),
            "max_cli_check_sites": options.get("max_cli_check_sites"),
        },
    }
    if hashes:
        manifest["binary_hashes"] = hashes
    return manifest


def build_strings_payload(strings, total_strings, strings_truncated, options, string_bucket_counts, string_bucket_limits):
    return {
        "total_strings": total_strings,
        "truncated": strings_truncated,
        "max_strings": options["max_strings"],
        "selection_strategy": "bucketed_then_most_referenced",
        "buckets": {
            "env_vars": {
                "limit": string_bucket_limits.get("env_vars", 0),
                "selected": string_bucket_counts.get("env_vars", 0),
            },
            "usage": {
                "limit": string_bucket_limits.get("usage", 0),
                "selected": string_bucket_counts.get("usage", 0),
            },
            "format": {
                "limit": string_bucket_limits.get("format", 0),
                "selected": string_bucket_counts.get("format", 0),
            },
            "path": {
                "limit": string_bucket_limits.get("path", 0),
                "selected": string_bucket_counts.get("path", 0),
            },
        },
        "strings": strings,
    }


def build_index_payload(functions, full_functions, index_functions, summaries, options):
    return {
        "total_functions": len(functions),
        "max_functions": options["max_functions_index"],
        "truncated": len(functions) > options["max_functions_index"],
        "full_function_selection": "mixed_relevance",
        "full_function_selection_metrics": [
            "import_calls",
            "import_diversity",
            "string_salience",
            "callgraph_degree",
            "size",
        ],
        "index_selection": "full_functions_then_largest_by_size",
        "full_functions": [addr_str(func.getEntryPoint()) for func in full_functions],
        "omitted_functions": max(0, len(functions) - len(index_functions)),
        "functions": summaries,
    }


def build_pack_readme():
    pack_readme = "# Binary Lens Context Pack\n\n"
    pack_readme += "This pack contains observed facts and mechanically derived capabilities.\n"
    pack_readme += "JSON files are authoritative; evidence files are bounded excerpts.\n\n"
    pack_readme += "Files:\n\n"
    pack_readme += "- manifest.json\n"
    pack_readme += "- binary.json\n"
    pack_readme += "- imports.json\n"
    pack_readme += "- strings.json\n"
    pack_readme += "- callgraph.json\n"
    pack_readme += "- capabilities.json\n"
    pack_readme += "- subsystems.json\n"
    pack_readme += "- surface_map.json\n"
    pack_readme += "- cli/options.json\n"
    pack_readme += "- cli/parse_loops.json\n"
    pack_readme += "- functions/index.json\n"
    pack_readme += "- functions/f_<addr>.json\n"
    pack_readme += "- evidence/decomp/f_<addr>.json\n"
    pack_readme += "- evidence/callsites/cs_<addr>.json\n"
    return pack_readme
