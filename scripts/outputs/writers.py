import os

from export_bounds import Bounds
from export_config import DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE
from export_primitives import addr_filename, addr_str, addr_to_int
from export_profile import profiled_decompile
from ghidra.app.decompiler import DecompInterface
from utils.text import has_usage_tag as _has_usage_tag
from utils.text import is_help_marker_value as _is_help_marker_value

from .io import pack_path, write_json

MAX_HELP_DECOMP_LINES = 600


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


def write_decomp_excerpts(
    program,
    full_functions,
    bounds: Bounds,
    string_refs_by_func,
    selected_string_ids,
    string_tags_by_id,
    string_value_by_id,
    evidence_decomp_dir,
    monitor,
):
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(program)
    entries = []

    for func in full_functions:
        entry_addr = addr_str(func.getEntryPoint())
        decomp_filename = addr_filename("f", entry_addr, "json")
        decomp_ref = pack_path("evidence", "decomp", decomp_filename)

        try:
            func_name = func.getName()
        except Exception:
            func_name = None
        if not isinstance(func_name, str) or not func_name.strip():
            func_name = "unknown"

        # Decompiler excerpts are bounded to keep evidence lightweight.
        timeout_seconds = 30
        try:
            func_size = func.getBody().getNumAddresses()
        except Exception:
            func_size = 0
        if func_size > DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE:
            timeout_seconds = 1
        result = profiled_decompile(
            decomp_interface,
            func,
            timeout_seconds,
            monitor,
            purpose="export_outputs.write_decomp_excerpts",
        )
        decomp_excerpt = {
            "function": {
                "name": func_name,
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

        entries.append({
            "function_id": entry_addr,
            "name": func_name,
            "decomp_ref": decomp_ref,
            "line_count": decomp_excerpt.get("line_count", 0),
        })

    entries.sort(key=lambda entry: addr_to_int(entry.get("function_id")))
    return entries
