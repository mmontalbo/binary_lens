#!/usr/bin/env python
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from export_cli import parse_args as parse_export_args
from export_cli import resolve_pack_root
from export_settings import build_export_explain_payload
from pack_inspect import build_capability_report
from runtime_runs import parse_run_options, run_scenario


def usage(exit_code=1):
    print("Usage:", file=sys.stderr)
    print(
        "  binary_lens <binary> [-o <output_dir>] [options] [key=value ...]",
        file=sys.stderr,
    )
    print(
        "  binary_lens --from-pack <pack_root> [-o <output_dir>] [options] [key=value ...]",
        file=sys.stderr,
    )
    print("  binary_lens inspect <pack_root> --json", file=sys.stderr)
    print(
        "  binary_lens [options] run=1 <binary|pack_root> [scenario args...]",
        file=sys.stderr,
    )
    print("When run=1 is set, options/kv must appear before <binary>.", file=sys.stderr)
    print("Default output dir: out", file=sys.stderr)
    raise SystemExit(exit_code)


def _run_inspect(argv):
    json_only = False
    pack_path = None
    for arg in argv:
        if arg == "--json":
            json_only = True
            continue
        if pack_path is None:
            pack_path = arg
            continue
        print(f"Unexpected inspect argument: {arg}", file=sys.stderr)
        usage(2)
    if not pack_path:
        print("Missing pack path for inspect.", file=sys.stderr)
        usage(2)
    if not json_only:
        print("inspect requires --json.", file=sys.stderr)
        usage(2)
    pack_root = _resolve_pack_root_for_reexport(pack_path)
    if pack_root is None:
        print(f"Pack not found: {pack_path}", file=sys.stderr)
        raise SystemExit(1)
    payload = build_capability_report(pack_root)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _parse_args_legacy(argv, *, allow_missing_binary=False):
    binary_path = None
    # Default to a local out dir to keep the CLI terse for quick runs.
    out_dir = "out"
    out_dir_set = False
    script_args = []
    scenario_argv = []
    value_flags = {"--config", "--requests", "--plan", "--from-pack", "--binary"}
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
            out_dir_set = True
            idx += 1
            continue
        if arg in value_flags:
            if idx >= count:
                print(f"Missing value for {arg}.", file=sys.stderr)
                usage(1)
            script_args.append(arg)
            script_args.append(argv[idx])
            idx += 1
            continue
        if arg == "--":
            scenario_argv = argv[idx:]
            break
        if "=" in arg:
            script_args.append(arg)
            continue
        if arg.startswith("-"):
            script_args.append(arg)
            continue
        if binary_path is None:
            binary_path = arg
        else:
            script_args.append(arg)
    if not binary_path and not allow_missing_binary:
        usage(1)
    return binary_path, out_dir, out_dir_set, script_args, scenario_argv


def _parse_args_for_run(argv):
    binary_path = None
    out_dir = "out"
    out_dir_set = False
    script_args = []
    rest = []
    idx = 0
    count = len(argv)
    while idx < count:
        arg = argv[idx]
        idx += 1
        if arg == "--":
            if idx >= count:
                break
            binary_path = argv[idx]
            rest = argv[idx + 1:]
            return binary_path, out_dir, out_dir_set, script_args, rest
        if arg in ("-h", "--help"):
            usage(0)
        if arg in ("-o", "--output"):
            if idx >= count:
                print("Missing value for -o/--output.", file=sys.stderr)
                usage(1)
            out_dir = argv[idx]
            out_dir_set = True
            idx += 1
            continue
        if arg.startswith("-") or "=" in arg:
            script_args.append(arg)
            continue
        binary_path = arg
        rest = argv[idx:]
        return binary_path, out_dir, out_dir_set, script_args, rest
    return binary_path, out_dir, out_dir_set, script_args, rest


def _strip_leading_separator(args):
    if args and args[0] == "--":
        return args[1:], True
    return args, False


def _parse_reexport_flags(args):
    from_pack = None
    binary_override = None
    in_place = False
    idx = 0
    while idx < len(args):
        arg = args[idx]
        idx += 1
        if arg == "--in-place":
            in_place = True
            continue
        if arg in ("--from-pack", "--binary"):
            if idx >= len(args):
                break
            value = args[idx]
            idx += 1
            if arg == "--from-pack":
                from_pack = value
            else:
                binary_override = value
            continue
        if arg.startswith("--from-pack="):
            from_pack = arg.split("=", 1)[1]
            continue
        if arg.startswith("--binary="):
            binary_override = arg.split("=", 1)[1]
            continue
    return from_pack, binary_override, in_place


def _resolve_pack_root_for_reexport(path: str) -> Path | None:
    candidate = Path(path)
    if candidate.is_dir():
        if (candidate / "manifest.json").is_file():
            return candidate
        nested = candidate / "binary.lens"
        if (nested / "manifest.json").is_file():
            return nested
    return None


def _default_reexport_out_dir(pack_root: Path) -> Path:
    base = pack_root.parent
    candidate = base / "reexport"
    if not candidate.exists():
        return candidate
    idx = 1
    while True:
        candidate = base / f"reexport_{idx}"
        if not candidate.exists():
            return candidate
        idx += 1


def _error_run_option_order(binary_path):
    target = binary_path or "<binary>"
    print(
        "When run=1 is set, binary_lens options must appear before <binary>.",
        file=sys.stderr,
    )
    print(f"Example: binary_lens -o out run=1 {target} --version", file=sys.stderr)
    raise SystemExit(2)


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


def _find_pack_root(path):
    if not path.is_dir():
        return None
    if path.name.endswith(".lens"):
        return path
    candidate = path / "binary.lens"
    if candidate.is_dir():
        return candidate
    return None


def _resolve_pack_binary(pack_root: Path) -> Path:
    manifest_path = pack_root / "manifest.json"
    if not manifest_path.is_file():
        print(f"Pack manifest not found: {manifest_path}", file=sys.stderr)
        raise SystemExit(1)
    try:
        payload = json.loads(manifest_path.read_text())
    except Exception as exc:
        print(f"Failed to parse pack manifest {manifest_path}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(payload, dict):
        print(f"Pack manifest is not a JSON object: {manifest_path}", file=sys.stderr)
        raise SystemExit(1)
    binary_path = payload.get("binary_path")
    if not isinstance(binary_path, str) or not binary_path.strip():
        print(f"Pack manifest missing binary_path: {manifest_path}", file=sys.stderr)
        raise SystemExit(1)
    binary_file = Path(binary_path)
    if not binary_file.is_file():
        print(f"Binary not found at manifest binary_path: {binary_file}", file=sys.stderr)
        print("Hint: regenerate the pack in the current environment.", file=sys.stderr)
        raise SystemExit(1)
    return binary_file


def _run_view_renderer(
    pack_root,
    *,
    out_dir,
    script_args,
):
    pack_root = pack_root.resolve()
    runner_path = pack_root / "views" / "run.py"
    if not runner_path.is_file():
        print(f"View runner not found: {runner_path}", file=sys.stderr)
        raise SystemExit(1)
    cmd = [sys.executable, str(runner_path), "--pack", str(pack_root)]
    if out_dir:
        cmd.extend(["--out", out_dir])
    if script_args:
        cmd.extend(script_args)
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def _should_analyze(settings):
    options = settings.options if settings is not None else {}
    profile_enabled = False
    analysis_profile = None
    if isinstance(options, dict):
        try:
            profile_enabled = int(options.get("profile") or 0) == 1
        except Exception:
            profile_enabled = False
        analysis_profile = options.get("analysis_profile")
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
    if argv and argv[0] == "inspect":
        _run_inspect(argv[1:])
        return
    from_pack_hint, _binary_hint, _in_place_hint = _parse_reexport_flags(argv)

    (
        run_binary_path,
        run_out_dir,
        run_out_dir_set,
        run_script_args,
        run_rest,
    ) = _parse_args_for_run(argv)
    run_config, run_script_args = parse_run_options(run_script_args)
    if run_config.enabled:
        if not run_binary_path:
            usage(1)
        scenario_argv, _ = _strip_leading_separator(run_rest)
        binary_path = run_binary_path
        out_dir = run_out_dir
        out_dir_set = run_out_dir_set
        script_args = run_script_args
    else:
        rest, rest_has_separator = _strip_leading_separator(run_rest)
        if not rest_has_separator:
            rest_run_config, _ = parse_run_options(rest)
            if rest_run_config.enabled:
                _error_run_option_order(run_binary_path)
        binary_path, out_dir, out_dir_set, script_args, scenario_argv = _parse_args_legacy(
            argv,
            allow_missing_binary=bool(from_pack_hint),
        )
        run_config, script_args = parse_run_options(script_args)
        if not run_config.enabled and scenario_argv:
            script_args.extend(scenario_argv)
            scenario_argv = []
    from_pack, binary_override, in_place = _parse_reexport_flags(script_args)
    reexport_pack_root = (
        _resolve_pack_root_for_reexport(from_pack) if from_pack else None
    )
    if from_pack and reexport_pack_root is None:
        print(f"Pack not found: {from_pack}", file=sys.stderr)
        raise SystemExit(1)

    if not reexport_pack_root:
        pack_root = _find_pack_root(Path(binary_path)) if binary_path else None
        if pack_root is not None:
            if run_config.enabled:
                binary_file = _resolve_pack_binary(pack_root.resolve())
                run_scenario(pack_root, binary_file, scenario_argv, run_config)
            else:
                _run_view_renderer(
                    pack_root,
                    out_dir=out_dir if out_dir_set else None,
                    script_args=script_args,
                )
            return

    if reexport_pack_root:
        if not out_dir_set:
            if in_place:
                out_dir = str(reexport_pack_root.parent)
            else:
                out_dir = str(_default_reexport_out_dir(reexport_pack_root))
        if out_dir:
            candidate_root = Path(resolve_pack_root(str(out_dir))).resolve()
            if candidate_root == reexport_pack_root.resolve() and not in_place:
                print(
                    "Refusing to overwrite existing pack without --in-place.",
                    file=sys.stderr,
                )
                raise SystemExit(2)

    parse_args_list = []
    if out_dir:
        parse_args_list.append(str(out_dir))
    parse_args_list.extend(script_args)
    _parsed_out_dir, settings, show_help, explain = parse_export_args(parse_args_list)
    if show_help:
        usage(0)
    if explain:
        if settings is None:
            print("Failed to resolve export settings.", file=sys.stderr)
            raise SystemExit(1)
        payload = build_export_explain_payload(settings)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if settings is None:
        print("Failed to resolve export settings.", file=sys.stderr)
        raise SystemExit(1)

    if reexport_pack_root:
        if binary_override:
            binary_path = binary_override
        elif binary_path and _find_pack_root(Path(binary_path)) is None:
            binary_path = binary_path
        else:
            binary_path = str(_resolve_pack_binary(reexport_pack_root))
        if binary_path is None:
            usage(1)

    if not binary_path:
        usage(1)
    binary_file = resolve_binary(binary_path)

    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_dir:
        # PyGhidra needs a concrete Ghidra install; nix develop/nix run wires this in.
        print(
            "GHIDRA_INSTALL_DIR is not set. For exports, run inside nix develop "
            "or `nix run .#binary_lens -- <binary> ...`. For view rendering, pass "
            "a pack root (binary.lens).",
            file=sys.stderr,
        )
        raise SystemExit(1)

    from pyghidra import core as pyghidra_core

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

    analyze = _should_analyze(settings)
    profile_enabled = False
    if isinstance(settings.options, dict):
        try:
            profile_enabled = int(settings.options.get("profile") or 0) == 1
        except Exception:
            profile_enabled = False

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

    if run_config.enabled:
        run_scenario(pack_root, binary_file, scenario_argv, run_config)


if __name__ == "__main__":
    main(sys.argv[1:])
