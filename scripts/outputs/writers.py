import os

from collectors.callgraph import collect_flow_summary, function_size
from export_bounds import Bounds
from export_config import DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE
from export_primitives import addr_filename, addr_str, addr_to_int
from export_profile import profiled_decompile
from ghidra.app.decompiler import DecompInterface

from .io import pack_path, write_json

MAX_HELP_DECOMP_LINES = 600


def _is_help_marker_value(value):
    if value is None:
        return False
    lowered = value.lower()
    if "usage:" in lowered:
        return True
    if "--help" in value:
        return True
    if "try '" in lowered or "try \"" in lowered:
        return True
    if "options:" in lowered or "options\n" in lowered:
        return True
    if "report bugs" in lowered or "reporting bugs" in lowered:
        return True
    return False


def _has_usage_tag(tags):
    if not tags:
        return False
    if isinstance(tags, set):
        return "usage" in tags
    if isinstance(tags, (list, tuple)):
        return "usage" in tags
    return False


def _looks_like_help_printer(func_id, string_refs_by_func, string_tags_by_id, string_value_by_id):
    string_tags_by_id = string_tags_by_id or {}
    string_value_by_id = string_value_by_id or {}
    for string_id in string_refs_by_func.get(func_id, []) or []:
        tags = string_tags_by_id.get(string_id)
        if _has_usage_tag(tags):
            return True
        value = string_value_by_id.get(string_id)
        if value and _is_help_marker_value(value):
            return True
    return False


def build_callsite_records(callsite_records, call_edges, extra_callsites=None, callsite_ids=None):
    """Prepare callsite evidence records for the sharded callsites surface."""
    def _addr_from_entry(entry):
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            return entry.get("address")
        return None

    # Only emit callsite evidence for selected edges plus explicitly requested extras.
    selected_callsite_records = {}
    if callsite_ids is None:
        for edge in call_edges:
            callsite = edge.get("callsite")
            base_record = callsite_records.get(callsite)
            if base_record is None:
                continue
            record = selected_callsite_records.get(callsite)
            if record is None:
                from_addr = _addr_from_entry(base_record.get("from"))
                record = {
                    "callsite": base_record.get("callsite"),
                    "from": from_addr,
                    "targets": [],
                }
                selected_callsite_records[callsite] = record
            to_addr = _addr_from_entry(edge.get("to"))
            if to_addr:
                record["targets"].append(to_addr)

        if extra_callsites:
            for callsite in extra_callsites:
                if callsite in selected_callsite_records:
                    continue
                base_record = callsite_records.get(callsite)
                if base_record is None:
                    continue
                from_addr = _addr_from_entry(base_record.get("from"))
                targets = []
                for target in base_record.get("targets") or []:
                    target_addr = _addr_from_entry(target)
                    if target_addr:
                        targets.append(target_addr)
                selected_callsite_records[callsite] = {
                    "callsite": base_record.get("callsite"),
                    "from": from_addr,
                    "targets": targets,
                }
    else:
        ordered_callsites = []
        seen = set()
        for callsite in callsite_ids:
            if not callsite or callsite in seen:
                continue
            seen.add(callsite)
            ordered_callsites.append(callsite)
        if extra_callsites:
            for callsite in extra_callsites:
                if not callsite or callsite in seen:
                    continue
                seen.add(callsite)
                ordered_callsites.append(callsite)
        callsite_set = set(ordered_callsites)
        for edge in call_edges:
            callsite = edge.get("callsite")
            if callsite not in callsite_set:
                continue
            base_record = callsite_records.get(callsite)
            if base_record is None:
                continue
            record = selected_callsite_records.get(callsite)
            if record is None:
                from_addr = _addr_from_entry(base_record.get("from"))
                record = {
                    "callsite": base_record.get("callsite"),
                    "from": from_addr,
                    "targets": [],
                }
                selected_callsite_records[callsite] = record
            to_addr = _addr_from_entry(edge.get("to"))
            if to_addr:
                record["targets"].append(to_addr)
        for callsite in ordered_callsites:
            if callsite in selected_callsite_records:
                continue
            base_record = callsite_records.get(callsite)
            if base_record is None:
                continue
            from_addr = _addr_from_entry(base_record.get("from"))
            targets = []
            for target in base_record.get("targets") or []:
                target_addr = _addr_from_entry(target)
                if target_addr:
                    targets.append(target_addr)
            selected_callsite_records[callsite] = {
                "callsite": base_record.get("callsite"),
                "from": from_addr,
                "targets": targets,
            }

    ordered_callsites = sorted(selected_callsite_records.keys(), key=addr_to_int)
    return [selected_callsite_records[callsite] for callsite in ordered_callsites]


def write_callsite_records(
    callsite_records,
    call_edges,
    evidence_callsites_dir,
    extra_callsites=None,
    callsite_ids=None,
):
    """Deprecated: callsite evidence is now written via sharded list outputs."""
    _ = (
        callsite_records,
        call_edges,
        evidence_callsites_dir,
        extra_callsites,
        callsite_ids,
    )
    return {}


def write_function_exports(
    program,
    full_functions,
    bounds: Bounds,
    string_refs_by_func,
    selected_string_ids,
    string_tags_by_id,
    string_value_by_id,
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
            "control_flow": flow_summary,
            "decompiler_excerpt": decomp_ref,
        }

        write_json(os.path.join(functions_dir, func_filename), detail)

        # Decompiler excerpts are bounded to keep evidence lightweight.
        timeout_seconds = 30
        if detail.get("size", 0) > DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE:
            timeout_seconds = 1
        result = profiled_decompile(
            decomp_interface,
            func,
            timeout_seconds,
            monitor,
            purpose="export_outputs.write_function_exports",
        )
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
                max_lines = bounds.max_decomp_lines
                if _looks_like_help_printer(
                    entry_addr,
                    string_refs_by_func,
                    string_tags_by_id,
                    string_value_by_id,
                ):
                    max_lines = max(
                        max_lines,
                        min(MAX_HELP_DECOMP_LINES, max_lines * 3),
                    )
                if len(lines) > max_lines:
                    decomp_excerpt["lines"] = lines[:max_lines]
                    decomp_excerpt["truncated"] = True
                else:
                    decomp_excerpt["lines"] = lines
        else:
            decomp_excerpt["error"] = "decompile_failed"
        write_json(os.path.join(evidence_decomp_dir, decomp_filename), decomp_excerpt)
