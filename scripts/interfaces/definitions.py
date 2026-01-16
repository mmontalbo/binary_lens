"""Static interface surface definitions."""

from __future__ import annotations

from dataclasses import dataclass

from symbols import IMPORT_ALIAS_GROUPS


@dataclass(frozen=True)
class OperationSpec:
    name: str
    string_arg_indices: tuple[int, ...] = ()
    var_arg_index: int | None = None
    flags_arg_index: int | None = None
    mode_arg_index: int | None = None
    fd_arg_index: int | None = None
    stream_arg_index: int | None = None
    channel_kind: str | None = None
    port_arg_index: int | None = None


ENV_OPERATIONS = {
    "getenv": OperationSpec("getenv", var_arg_index=0),
    "setenv": OperationSpec("setenv", var_arg_index=0),
    "unsetenv": OperationSpec("unsetenv", var_arg_index=0),
    "putenv": OperationSpec("putenv", var_arg_index=0),
}
ENV_ALIASES = {
    "getenv": IMPORT_ALIAS_GROUPS.get("getenv", ()),
    "setenv": IMPORT_ALIAS_GROUPS.get("setenv", ()),
    "unsetenv": IMPORT_ALIAS_GROUPS.get("unsetenv", ()),
    "putenv": IMPORT_ALIAS_GROUPS.get("putenv", ()),
}

FS_OPERATIONS = {
    "open": OperationSpec("open", string_arg_indices=(0,), flags_arg_index=1, mode_arg_index=2),
    "openat": OperationSpec("openat", string_arg_indices=(1,), flags_arg_index=2, mode_arg_index=3),
    "fopen": OperationSpec("fopen", string_arg_indices=(0,)),
    "freopen": OperationSpec("freopen", string_arg_indices=(0,)),
    "stat": OperationSpec("stat", string_arg_indices=(0,)),
    "lstat": OperationSpec("lstat", string_arg_indices=(0,)),
    "access": OperationSpec("access", string_arg_indices=(0,)),
    "unlink": OperationSpec("unlink", string_arg_indices=(0,)),
    "rename": OperationSpec("rename", string_arg_indices=(0, 1)),
    "mkdir": OperationSpec("mkdir", string_arg_indices=(0,)),
    "opendir": OperationSpec("opendir", string_arg_indices=(0,)),
    "rmdir": OperationSpec("rmdir", string_arg_indices=(0,)),
    "chdir": OperationSpec("chdir", string_arg_indices=(0,)),
    "readlink": OperationSpec("readlink", string_arg_indices=(0,)),
}

FS_ALIASES = {
    "open": IMPORT_ALIAS_GROUPS.get("open", ()),
    "openat": IMPORT_ALIAS_GROUPS.get("openat", ()),
    "fopen": IMPORT_ALIAS_GROUPS.get("fopen", ()),
    "freopen": IMPORT_ALIAS_GROUPS.get("freopen", ()),
    "stat": IMPORT_ALIAS_GROUPS.get("stat", ()) + ("__xstat", "__xstat64"),
    "lstat": IMPORT_ALIAS_GROUPS.get("lstat", ()) + ("__lxstat", "__lxstat64"),
    "access": ("__access",),
}

PROCESS_OPERATIONS = {
    "execve": OperationSpec("execve", string_arg_indices=(0,)),
    "execv": OperationSpec("execv", string_arg_indices=(0,)),
    "execvp": OperationSpec("execvp", string_arg_indices=(0,)),
    "execvpe": OperationSpec("execvpe", string_arg_indices=(0,)),
    "execl": OperationSpec("execl", string_arg_indices=(0,)),
    "execlp": OperationSpec("execlp", string_arg_indices=(0,)),
    "execle": OperationSpec("execle", string_arg_indices=(0,)),
    "posix_spawn": OperationSpec("posix_spawn", string_arg_indices=(1,)),
    "posix_spawnp": OperationSpec("posix_spawnp", string_arg_indices=(1,)),
    "system": OperationSpec("system", string_arg_indices=(0,)),
    "popen": OperationSpec("popen", string_arg_indices=(0,)),
}

PROCESS_ALIASES = {}

NET_OPERATIONS = {
    "socket": OperationSpec("socket"),
    "connect": OperationSpec("connect"),
    "bind": OperationSpec("bind"),
    "listen": OperationSpec("listen"),
    "accept": OperationSpec("accept"),
    "send": OperationSpec("send"),
    "sendto": OperationSpec("sendto"),
    "recv": OperationSpec("recv"),
    "recvfrom": OperationSpec("recvfrom"),
    "getaddrinfo": OperationSpec("getaddrinfo", string_arg_indices=(0,), port_arg_index=1),
    "getnameinfo": OperationSpec("getnameinfo"),
    "gethostbyname": OperationSpec("gethostbyname", string_arg_indices=(0,)),
    "gethostbyname_r": OperationSpec("gethostbyname_r", string_arg_indices=(0,)),
}

NET_ALIASES = {}

OUTPUT_OPERATIONS = {
    "printf": OperationSpec("printf", string_arg_indices=(0,), channel_kind="stdout"),
    "vprintf": OperationSpec("vprintf", string_arg_indices=(0,), channel_kind="stdout"),
    "puts": OperationSpec("puts", string_arg_indices=(0,), channel_kind="stdout"),
    "putchar": OperationSpec("putchar", channel_kind="stdout"),
    "fprintf": OperationSpec("fprintf", string_arg_indices=(1,), stream_arg_index=0),
    "vfprintf": OperationSpec("vfprintf", string_arg_indices=(1,), stream_arg_index=0),
    "fputs": OperationSpec("fputs", string_arg_indices=(0,), stream_arg_index=1),
    "dprintf": OperationSpec("dprintf", string_arg_indices=(1,), fd_arg_index=0),
    "vdprintf": OperationSpec("vdprintf", string_arg_indices=(1,), fd_arg_index=0),
    "write": OperationSpec("write", string_arg_indices=(1,), fd_arg_index=0),
    "writev": OperationSpec("writev", fd_arg_index=0),
    "fwrite": OperationSpec("fwrite", string_arg_indices=(0,), stream_arg_index=3),
}

OUTPUT_ALIASES = {}

SURFACE_ORDER = ("env", "fs", "process", "net", "output")

SURFACE_SPECS = {
    "env": (ENV_OPERATIONS, ENV_ALIASES),
    "fs": (FS_OPERATIONS, FS_ALIASES),
    "process": (PROCESS_OPERATIONS, PROCESS_ALIASES),
    "net": (NET_OPERATIONS, NET_ALIASES),
    "output": (OUTPUT_OPERATIONS, OUTPUT_ALIASES),
}
