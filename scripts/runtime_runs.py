"""Runtime scenario capture for binary_lens packs."""

from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from outputs.io import ensure_dir, write_json

DEFAULT_RUN_TIMEOUT_SECONDS = 10.0
RUNS_INDEX_SCHEMA = {"name": "binary_lens_runs_index", "version": "v1"}
RUN_MANIFEST_SCHEMA = {"name": "binary_lens_run_manifest", "version": "v1"}
ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "TZ")
SEED_DIR_NAME = "seed"


@dataclass
class RunConfig:
    enabled: bool = False
    timeout_seconds: float | None = DEFAULT_RUN_TIMEOUT_SECONDS
    no_sandbox: bool = False
    no_strace: bool = False
    net_mode: str = "off"
    argv0: str | None = None
    seed_dir: str | None = None
    cwd: str | None = None


def _parse_bool(value: str) -> bool:
    lowered = (value or "").strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    try:
        return float(lowered) > 0
    except Exception:
        return False


def _parse_timeout(value: str, default: float | None) -> float | None:
    if value is None:
        return default
    raw = value.strip()
    if not raw:
        return default
    try:
        seconds = float(raw)
    except Exception:
        return default
    if seconds <= 0:
        return None
    return seconds


def _parse_net_mode(value: str, default: str) -> str:
    lowered = (value or "").strip().lower()
    if lowered in ("off", "inherit"):
        return lowered
    return default


def _resolve_seed_dir(seed_dir: str) -> Path:
    raw = Path(seed_dir.strip())
    if raw.is_absolute():
        return raw.resolve()
    return (Path.cwd() / raw).resolve()


def _seed_work_dir(seed_dir: Path, work_dir: Path) -> Path:
    if not seed_dir.is_dir():
        print(f"seed_dir is not a directory: {seed_dir}", file=sys.stderr)
        raise SystemExit(1)
    seed_root = work_dir / SEED_DIR_NAME
    ensure_dir(seed_root)
    try:
        shutil.copytree(
            seed_dir,
            seed_root,
            symlinks=True,
            copy_function=shutil.copy2,
            dirs_exist_ok=True,
        )
    except Exception as exc:
        print(f"Failed to copy seed_dir {seed_dir}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    return seed_root


def _resolve_run_cwd(base_dir: Path, run_cwd: str) -> Path:
    raw = run_cwd.strip()
    if not raw:
        raw = "."
    cwd_path = Path(raw)
    if cwd_path.is_absolute():
        print(f"run_cwd must be a relative path (got {raw})", file=sys.stderr)
        raise SystemExit(1)
    if any(part == ".." for part in cwd_path.parts):
        print(f"run_cwd must not contain '..' (got {raw})", file=sys.stderr)
        raise SystemExit(1)
    candidate = base_dir / cwd_path
    base_resolved = base_dir.resolve()
    try:
        candidate.resolve().relative_to(base_resolved)
    except Exception:
        print(f"run_cwd escapes base dir {base_dir}: {raw}", file=sys.stderr)
        raise SystemExit(1)
    if not candidate.is_dir():
        print(f"run_cwd does not exist or is not a directory: {candidate}", file=sys.stderr)
        raise SystemExit(1)
    return candidate


def parse_run_options(args: list[str]) -> tuple[RunConfig, list[str]]:
    """Extract run=1 config from key=value args, return remaining args."""
    config = RunConfig()
    remaining: list[str] = []
    for arg in args:
        if not isinstance(arg, str) or "=" not in arg:
            remaining.append(arg)
            continue
        key, value = arg.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key == "run":
            config.enabled = _parse_bool(value)
            continue
        if key == "run_timeout_seconds":
            config.timeout_seconds = _parse_timeout(value, config.timeout_seconds)
            continue
        if key == "run_no_sandbox":
            config.no_sandbox = _parse_bool(value)
            continue
        if key == "run_no_strace":
            config.no_strace = _parse_bool(value)
            continue
        if key == "run_net":
            config.net_mode = _parse_net_mode(value, config.net_mode)
            continue
        if key == "run_argv0":
            cleaned = value.strip()
            config.argv0 = cleaned if cleaned else None
            continue
        if key == "run_seed_dir":
            cleaned = value.strip()
            config.seed_dir = cleaned if cleaned else None
            continue
        if key == "run_cwd":
            cleaned = value.strip()
            config.cwd = cleaned if cleaned else None
            continue
        remaining.append(arg)
    return config, remaining


def _default_runs_index() -> dict[str, Any]:
    return {"schema": RUNS_INDEX_SCHEMA, "run_count": 0, "runs": []}


def ensure_runs_index(pack_root: Path) -> dict[str, Any]:
    runs_dir = pack_root / "runs"
    ensure_dir(runs_dir)
    index_path = runs_dir / "index.json"
    payload: dict[str, Any] | None = None
    if index_path.is_file():
        try:
            data = json.loads(index_path.read_text())
        except Exception:
            data = None
        if isinstance(data, dict):
            payload = data
            if not isinstance(payload.get("runs"), list):
                payload["runs"] = []
            if not isinstance(payload.get("schema"), dict):
                payload["schema"] = RUNS_INDEX_SCHEMA
    if payload is None:
        payload = _default_runs_index()
    run_count = payload.get("run_count")
    if not isinstance(run_count, int):
        payload["run_count"] = len(payload.get("runs") or [])
    if not index_path.is_file():
        write_json(index_path, payload)
    return payload


def _next_run_id(runs_index: dict[str, Any]) -> str:
    runs = runs_index.get("runs") if isinstance(runs_index, dict) else None
    existing: set[str] = set()
    if isinstance(runs, list):
        for entry in runs:
            if isinstance(entry, dict):
                run_id = entry.get("run_id")
                if isinstance(run_id, str) and run_id.strip():
                    existing.add(run_id)
    idx = 1
    while True:
        candidate = f"run_{idx:04d}"
        if candidate not in existing:
            return candidate
        idx += 1


def _tool_version(path: str, args: list[str] | None = None) -> str | None:
    if not path:
        return None
    cmd = [path] + (args or ["--version"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception:
        return None
    output = (result.stdout or result.stderr or "").strip()
    if not output:
        return None
    return output.splitlines()[0].strip() or None


def _build_env_record(env: dict[str, str]) -> dict[str, Any]:
    allowlist: dict[str, str] = {}
    for key in ENV_ALLOWLIST:
        value = env.get(key)
        if value is not None:
            allowlist[key] = value
    return {
        "recording": "allowlist+keys",
        "used": "full",
        "allowlist": allowlist,
        "keys": sorted(env.keys()),
    }


def _resolve_timestamp() -> tuple[str, int]:
    epoch = int(time.time())
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z"), epoch


def _kill_process(proc: subprocess.Popen[bytes] | subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
        return
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def _maybe_capture_proc_maps(
    *,
    proc_pid: int,
    run_dir: Path,
    allow: bool,
) -> dict[str, Any]:
    info: dict[str, Any] = {"captured": False}
    if not allow:
        info["reason"] = "wrapped_process"
        return info
    maps_path = Path("/proc") / str(proc_pid) / "maps"
    if not maps_path.is_file():
        info["reason"] = "not_available"
        return info
    try:
        content = maps_path.read_text()
    except Exception:
        info["reason"] = "read_failed"
        return info
    dest = run_dir / "proc_maps.txt"
    try:
        dest.write_text(content)
    except Exception:
        info["reason"] = "write_failed"
        return info
    info.update(
        {
            "captured": True,
            "pid": proc_pid,
            "ref": f"runs/{run_dir.name}/proc_maps.txt",
        }
    )
    return info


def run_scenario(
    pack_root: Path,
    binary_file: Path,
    scenario_argv: list[str],
    config: RunConfig,
) -> str:
    pack_root = pack_root.resolve()
    runs_index = ensure_runs_index(pack_root)
    run_id = _next_run_id(runs_index)
    run_dir = pack_root / "runs" / run_id
    ensure_dir(run_dir)

    strace_dir = run_dir / "strace"
    ensure_dir(strace_dir)
    work_dir = run_dir / "work"
    ensure_dir(work_dir)
    run_out_dir = run_dir / "run_out"
    ensure_dir(run_out_dir)

    seed_root = None
    if config.seed_dir:
        seed_source = _resolve_seed_dir(config.seed_dir)
        seed_root = _seed_work_dir(seed_source, work_dir)
    base_cwd = seed_root if seed_root else work_dir
    run_cwd_path = _resolve_run_cwd(base_cwd, config.cwd or ".")
    run_cwd_rel = run_cwd_path.relative_to(work_dir)

    env = os.environ.copy()
    pack_manifest: dict[str, Any] | None = None
    pack_manifest_path = pack_root / "manifest.json"
    if pack_manifest_path.is_file():
        try:
            data = json.loads(pack_manifest_path.read_text())
        except Exception:
            data = None
        if isinstance(data, dict):
            pack_manifest = data

    argv0_info: dict[str, Any] = {"requested": config.argv0, "used": False}
    argv0_name = (config.argv0 or "").strip()
    if argv0_name and ("/" in argv0_name or "\\" in argv0_name or argv0_name in (".", "..")):
        argv0_info["reason"] = "invalid_name"
        argv0_name = ""

    argv0_link_path: Path | None = None
    if argv0_name:
        argv0_link_path = work_dir / argv0_name
        try:
            argv0_link_path.symlink_to(binary_file)
            argv0_info.update(
                {
                    "used": True,
                    "strategy": "symlink+path",
                    "ref": f"runs/{run_id}/work/{argv0_name}",
                }
            )
            env_path = env.get("PATH") or ""
            env["PATH"] = (
                f"{work_dir}{':' if env_path else ''}{env_path}"
            )
        except Exception as exc:
            argv0_info.update(
                {
                    "reason": "symlink_failed",
                    "error": str(exc),
                }
            )
            argv0_name = ""

    argv = ([argv0_name] if argv0_name else [str(binary_file)]) + list(scenario_argv)
    cmd = list(argv)

    sandbox_info: dict[str, Any] = {
        "enabled": False,
        "backend": None,
        "reason": None,
        "net_mode": config.net_mode,
        "work_dir_ref": f"runs/{run_id}/work/",
        "run_out_dir_ref": f"runs/{run_id}/run_out/",
        "cwd_rel": run_cwd_rel.as_posix(),
    }
    bwrap_path = shutil.which("bwrap")
    if config.no_sandbox:
        sandbox_info["reason"] = "disabled_by_config"
    elif platform.system().lower() != "linux":
        sandbox_info["reason"] = "unsupported_platform"
    elif not bwrap_path:
        sandbox_info["reason"] = "bwrap_not_found"
    else:
        mount_suffix = f"{os.getpid()}_{secrets.token_hex(4)}"
        work_mount = f"/tmp/binary_lens_work_{mount_suffix}"
        run_out_mount = f"/tmp/binary_lens_out_{mount_suffix}"
        sandbox_info.update(
            {
                "enabled": True,
                "backend": "bwrap",
                "reason": None,
                "tool_path": bwrap_path,
                "work_dir_mount": work_mount,
                "run_out_dir_mount": run_out_mount,
            }
        )
        rel_cwd = run_cwd_rel.as_posix()
        work_mount_cwd = work_mount if rel_cwd == "." else f"{work_mount}/{rel_cwd}"
        sandbox_info["cwd_mount"] = work_mount_cwd
        bwrap_cmd = [
            bwrap_path,
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            work_mount,
            "--dir",
            run_out_mount,
            "--bind",
            str(work_dir),
            work_mount,
            "--bind",
            str(run_out_dir),
            run_out_mount,
            "--chdir",
            work_mount_cwd,
        ]
        if config.net_mode != "inherit":
            bwrap_cmd.append("--unshare-net")
        bwrap_cmd.append("--")
        sandbox_info["argv"] = bwrap_cmd
        cmd = bwrap_cmd + cmd

    tracer_info: dict[str, Any] = {
        "enabled": False,
        "backend": None,
        "reason": None,
        "output_dir_ref": f"runs/{run_id}/strace/",
    }
    strace_path = shutil.which("strace")
    if config.no_strace:
        tracer_info["reason"] = "disabled_by_config"
    elif not strace_path:
        tracer_info["reason"] = "strace_not_found"
    else:
        tracer_info.update(
            {
                "enabled": True,
                "backend": "strace",
                "reason": None,
                "tool_path": strace_path,
            }
        )
        trace_prefix = str(strace_dir / "trace")
        tracer_argv = [strace_path, "-ff", "-o", trace_prefix, "--"]
        tracer_info["argv"] = tracer_argv
        tracer_info["output_prefix"] = f"runs/{run_id}/strace/trace"
        cmd = tracer_argv + cmd

    started_at, started_epoch = _resolve_timestamp()
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"
    proc = None
    timed_out = False
    proc_maps_info: dict[str, Any] = {"captured": False, "reason": "not_started"}
    run_seconds = None

    with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open(
        "w",
        encoding="utf-8",
    ) as stderr_handle:
        start_perf = time.perf_counter()
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=stdout_handle,
            stderr=stderr_handle,
            cwd=str(run_cwd_path),
            env=env,
            start_new_session=True,
        )
        proc_maps_info = _maybe_capture_proc_maps(
            proc_pid=proc.pid,
            run_dir=run_dir,
            allow=not sandbox_info["enabled"] and not tracer_info["enabled"],
        )
        try:
            if config.timeout_seconds is None:
                proc.wait()
            else:
                proc.wait(timeout=config.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process(proc)
            proc.wait()
        run_seconds = time.perf_counter() - start_perf

    exit_code = None
    exit_signal = None
    if proc is not None and proc.returncode is not None:
        if proc.returncode < 0:
            exit_signal = -proc.returncode
        else:
            exit_code = proc.returncode

    ended_at, ended_epoch = _resolve_timestamp()

    tool_versions: dict[str, str] = {}
    if sandbox_info.get("enabled") and sandbox_info.get("tool_path"):
        version = _tool_version(str(sandbox_info["tool_path"]))
        if version:
            tool_versions["bwrap"] = version
    if tracer_info.get("enabled") and tracer_info.get("tool_path"):
        version = _tool_version(str(tracer_info["tool_path"]))
        if version:
            tool_versions["strace"] = version

    binary_hashes = None
    binary_name = None
    binary_lens_version = None
    if isinstance(pack_manifest, dict):
        binary_hashes = pack_manifest.get("binary_hashes")
        binary_name = pack_manifest.get("binary_name")
        binary_lens_version = pack_manifest.get("binary_lens_version")
        if not binary_lens_version:
            tool = pack_manifest.get("tool")
            if isinstance(tool, dict):
                binary_lens_version = tool.get("version")

    scenario_cwd = str(run_cwd_path)
    if sandbox_info.get("enabled"):
        mount_cwd = sandbox_info.get("cwd_mount") or sandbox_info.get("work_dir_mount")
        if isinstance(mount_cwd, str) and mount_cwd:
            scenario_cwd = mount_cwd

    env_record = _build_env_record(env)

    manifest = {
        "schema": RUN_MANIFEST_SCHEMA,
        "run_id": run_id,
        "created_at": started_at,
        "created_at_epoch_seconds": started_epoch,
        "binary_lens_version": binary_lens_version,
        "binary": {
            "path": str(binary_file),
            "name": binary_name,
            "hashes": binary_hashes,
            "argv": argv,
        },
        "scenario": {
            "argv": argv,
            "argv0": argv0_info,
            "cwd": scenario_cwd,
            "cwd_host": str(run_cwd_path),
            "cwd_rel": run_cwd_rel.as_posix(),
            "seed_dir": config.seed_dir,
            "timeout_seconds": config.timeout_seconds,
            "stdin": "null",
            "net_mode": config.net_mode,
        },
        "env": env_record,
        "sandbox": sandbox_info,
        "tracer": tracer_info,
        "artifacts": {
            "stdout_ref": f"runs/{run_id}/stdout.txt",
            "stderr_ref": f"runs/{run_id}/stderr.txt",
            "strace_dir_ref": f"runs/{run_id}/strace/",
            "proc_maps_ref": proc_maps_info.get("ref"),
        },
        "proc_maps": proc_maps_info,
        "result": {
            "exit_code": exit_code,
            "exit_signal": exit_signal,
            "timed_out": timed_out,
            "duration_seconds": run_seconds,
            "started_at": started_at,
            "started_at_epoch_seconds": started_epoch,
            "ended_at": ended_at,
            "ended_at_epoch_seconds": ended_epoch,
        },
        "tool_versions": tool_versions,
    }

    run_manifest_path = run_dir / "manifest.json"
    write_json(run_manifest_path, manifest)

    runs = runs_index.get("runs")
    if not isinstance(runs, list):
        runs = []
        runs_index["runs"] = runs
    entry = {
        "run_id": run_id,
        "manifest_ref": f"runs/{run_id}/manifest.json",
        "stdout_ref": f"runs/{run_id}/stdout.txt",
        "stderr_ref": f"runs/{run_id}/stderr.txt",
        "strace_dir_ref": f"runs/{run_id}/strace/",
        "proc_maps_ref": proc_maps_info.get("ref"),
        "started_at": started_at,
        "exit_code": exit_code,
        "exit_signal": exit_signal,
        "timed_out": timed_out,
        "duration_seconds": run_seconds,
        "sandbox_enabled": sandbox_info.get("enabled"),
        "strace_enabled": tracer_info.get("enabled"),
    }
    runs.append(entry)
    runs_index["run_count"] = len(runs)
    write_json(pack_root / "runs" / "index.json", runs_index)

    return run_id
