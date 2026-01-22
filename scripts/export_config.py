BINARY_LENS_VERSION = "0.1.0-dev"

# Pack format version: bump when the core on-disk layout or fact table schemas change.
FORMAT_VERSION = "v2"

# Pack schema version: bump when pack-level JSON contracts change (manifest/index/pack_summary fields).
PACK_SCHEMA_VERSION = "v1"

# Lens schema version: bump when rendered lens outputs or _lens metadata shape changes.
LENS_SCHEMA_VERSION = "v1"

# Defaults cap export size to keep packs bounded and diff-friendly.
DEFAULT_MAX_FULL_FUNCTIONS = 50
DEFAULT_MAX_STRINGS = 0
DEFAULT_MAX_CALL_EDGES = 0
DEFAULT_MAX_DECOMP_LINES = 200
DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE = 10000

CALLGRAPH_SIGNAL_RULES = [
    {
        "id": "parses_command_line_options",
        "name": "parses command-line options",
        "signals": [
            "getopt",
            "getopt_long",
            "__getopt_long",
            "getopt_long_only",
            "argp_parse",
        ],
    },
    {
        "id": "reads_environment_variables",
        "name": "reads environment variables",
        "signals": [
            "getenv",
            "__getenv",
            "secure_getenv",
            "getenv_s",
        ],
    },
    {
        "id": "opens_filesystem_paths",
        "name": "opens filesystem paths",
        "signals": [
            "open",
            "open64",
            "openat",
            "openat64",
            "fopen",
            "fopen64",
            "freopen",
        ],
    },
    {
        "id": "reads_file_data",
        "name": "reads file data",
        "signals": [
            "read",
            "pread",
            "pread64",
            "readv",
            "fread",
        ],
    },
    {
        "id": "writes_file_data",
        "name": "writes file data",
        "signals": [
            "write",
            "pwrite",
            "pwrite64",
            "writev",
            "fwrite",
        ],
    },
    {
        "id": "inspects_filesystem_metadata",
        "name": "inspects filesystem metadata",
        "signals": [
            "stat",
            "stat64",
            "lstat",
            "lstat64",
            "fstat",
            "fstat64",
            "fstatat",
            "statx",
        ],
    },
    {
        "id": "traverses_directories",
        "name": "traverses directories",
        "signals": [
            "opendir",
            "readdir",
            "readdir64",
            "closedir",
            "ftw",
            "nftw",
        ],
    },
    {
        "id": "writes_formatted_output",
        "name": "writes formatted output",
        "signals": [
            "printf",
            "fprintf",
            "vprintf",
            "vfprintf",
            "puts",
            "fputs",
            "putchar",
        ],
    },
    {
        "id": "formats_strings",
        "name": "formats strings",
        "signals": [
            "sprintf",
            "snprintf",
            "vsprintf",
            "vsnprintf",
            "asprintf",
            "vasprintf",
        ],
    },
    {
        "id": "spawns_subprocesses",
        "name": "spawns subprocesses",
        "signals": [
            "execve",
            "execv",
            "execvp",
            "execvpe",
            "posix_spawn",
            "posix_spawnp",
            "system",
            "popen",
            "fork",
            "vfork",
            "clone",
        ],
    },
    {
        "id": "uses_network_sockets",
        "name": "uses network sockets",
        "signals": [
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "send",
            "recv",
            "sendto",
            "recvfrom",
        ],
    },
    {
        "id": "performs_name_resolution",
        "name": "performs name resolution",
        "signals": [
            "getaddrinfo",
            "getnameinfo",
            "gethostbyname",
            "gethostbyname_r",
            "gethostbyaddr",
            "gethostbyaddr_r",
        ],
    },
]
