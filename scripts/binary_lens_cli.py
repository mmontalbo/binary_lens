#!/usr/bin/env python
import json
import os
import shutil
import sys
import time
from pathlib import Path

from export_cli import resolve_pack_root
from pyghidra import core as pyghidra_core


def usage(exit_code=1):
    print(
        "Usage: binary_lens <binary> [-o <output_dir>] [key=value ...]",
        file=sys.stderr,
    )
    print("Default output dir: out", file=sys.stderr)
    raise SystemExit(exit_code)


def parse_args(argv):
    binary_path = None
    # Default to a local out dir to keep the CLI terse for quick runs.
    out_dir = "out"
    script_args = []
    idx = 0
    count = len(argv)
    while idx < count:
        arg = argv[idx]
        idx += 1
        if arg in ("-h", "--help"):
            usage(0)
        if arg in ("-o", "--output"):
            if idx >= count:
                print("Missing value for -o/--output.", file=sys.stderr)
                usage(1)
            out_dir = argv[idx]
            idx += 1
            continue
        if arg == "--":
            script_args.extend(argv[idx:])
            break
        if arg.startswith("-"):
            script_args.append(arg)
            continue
        if binary_path is None:
            binary_path = arg
        else:
            script_args.append(arg)
    if not binary_path:
        usage(1)
    return binary_path, out_dir, script_args


def resolve_binary(binary_path):
    binary_file = Path(binary_path)
    if binary_file.is_file():
        return binary_file
    # Allow PATH-based resolution so `binary_lens ls` works inside nix shells.
    resolved = shutil.which(binary_path)
    if resolved:
        resolved_path = Path(resolved)
        if resolved_path.is_file():
            return resolved_path
    print(f"Binary not found: {binary_path}", file=sys.stderr)
    print("Hint: provide a full path or a binary available in PATH.", file=sys.stderr)
    raise SystemExit(1)


def _parse_script_options(script_args):
    profile_enabled = False
    analysis_profile = None
    for arg in script_args:
        if arg.startswith("profile="):
            value = arg.split("=", 1)[1].strip().lower()
            profile_enabled = value in ("1", "true", "yes", "on")
        elif arg.startswith("analysis_profile="):
            analysis_profile = arg.split("=", 1)[1].strip().lower()
    return profile_enabled, analysis_profile


def _should_analyze(profile_enabled, analysis_profile):
    if profile_enabled:
        return False
    if analysis_profile and analysis_profile != "full":
        return False
    return True


def _write_cli_timings(profile_dir, enter_seconds, run_seconds, exit_seconds):
    payload = {
        "version": 1,
        "unit": "seconds",
        "enter_seconds": enter_seconds,
        "run_seconds": run_seconds,
        "exit_seconds": exit_seconds,
    }
    try:
        (profile_dir / "cli_timings.json").write_text(json.dumps(payload, indent=2, sort_keys=True))
    except Exception:
        pass


def main(argv):
    binary_path, out_dir, script_args = parse_args(argv)
    binary_file = resolve_binary(binary_path)

    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_dir:
        # PyGhidra needs a concrete Ghidra install; nix develop wires this in.
        print("GHIDRA_INSTALL_DIR is not set. Run inside nix develop.", file=sys.stderr)
        raise SystemExit(1)

    root_dir = Path(
        os.environ.get("BINARY_LENS_ROOT", Path(__file__).resolve().parent.parent)
    ).resolve()
    script_path = root_dir / "scripts" / "binary_lens_export.py"
    if not script_path.is_file():
        print(
            "Could not locate scripts/binary_lens_export.py. Run from repo root or set BINARY_LENS_ROOT.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    # Ghidra's ProjectLocator requires an absolute path.
    out_dir_path = Path(out_dir).resolve()
    project_dir = out_dir_path / "ghidra_project"
    project_name = binary_file.stem
    program_name = binary_file.name

    out_dir_path.mkdir(parents=True, exist_ok=True)
    pack_root = Path(resolve_pack_root(str(out_dir_path)))
    manifest_path = pack_root / "manifest.json"
    error_path = pack_root / "export_error.txt"
    for path in (manifest_path, error_path):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    profile_enabled, analysis_profile = _parse_script_options(script_args)
    analyze = _should_analyze(profile_enabled, analysis_profile)

    enter_seconds = None
    run_seconds = None
    exit_seconds = None
    exit_start = None

    # Use PyGhidra's flat API to avoid the deprecated run_script helper and
    # the open_project + ghidra_script path that hangs in headless runs.
    enter_start = time.perf_counter()
    with pyghidra_core._flat_api(
        str(binary_file),
        str(project_dir),
        project_name,
        analyze=analyze,
        program_name=program_name,
        # Keep a stable, non-nested project path under the output dir.
        nested_project_location=False,
        install_dir=Path(install_dir),
    ) as script:
        enter_seconds = time.perf_counter() - enter_start
        run_start = time.perf_counter()
        script.run(str(script_path), [str(out_dir_path)] + script_args)
        run_seconds = time.perf_counter() - run_start
        exit_start = time.perf_counter()
    if exit_start is not None:
        exit_seconds = time.perf_counter() - exit_start

    if profile_enabled:
        if pack_root == out_dir_path:
            profile_dir = out_dir_path.parent / "profile"
        else:
            profile_dir = out_dir_path / "profile"
        try:
            profile_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            profile_dir = None
        if profile_dir is not None:
            _write_cli_timings(profile_dir, enter_seconds, run_seconds, exit_seconds)

    if error_path.is_file():
        print(f"Binary Lens export failed; see {error_path}", file=sys.stderr)
        raise SystemExit(1)
    if not manifest_path.is_file():
        print(f"Binary Lens export failed; missing {manifest_path}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
