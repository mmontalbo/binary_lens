BINARY_LENS_VERSION = "0.1.0-dev"
FORMAT_VERSION = "0.1"

# Defaults cap export size to keep packs bounded and diff-friendly.
DEFAULT_MAX_FULL_FUNCTIONS = 50
DEFAULT_MAX_FUNCTIONS_INDEX = 0
DEFAULT_MAX_STRINGS = 0
DEFAULT_MAX_CALL_EDGES = 0
DEFAULT_MAX_CALLS_PER_FUNCTION = 200
DEFAULT_MAX_DECOMP_LINES = 200
DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE = 10000
DEFAULT_MAX_CLI_OPTIONS = 0
DEFAULT_MAX_CLI_PARSE_LOOPS = 0
DEFAULT_MAX_CLI_PARSE_SITES_PER_OPTION = 6
DEFAULT_MAX_CLI_LONGOPT_ENTRIES = 256
DEFAULT_MAX_CLI_CALLSITES_PER_PARSE_LOOP = 8
DEFAULT_MAX_ERROR_MESSAGES = 0
DEFAULT_MAX_ERROR_MESSAGE_CALLSITES = 5
DEFAULT_MAX_ERROR_MESSAGE_FUNCTIONS = 10
DEFAULT_MAX_EXIT_PATHS = 0
DEFAULT_MAX_EXIT_PATTERNS = 100
DEFAULT_MAX_ERROR_EMITTER_CALLSITES = 2000
DEFAULT_MAX_ERROR_SITES = 0
DEFAULT_MAX_ERROR_SITE_CALLSITES = 8
DEFAULT_MAX_MODE_DISPATCH_FUNCTIONS = 12
DEFAULT_MAX_MODE_CALLSITES_PER_FUNCTION = 160
DEFAULT_MAX_MODE_TOKENS_PER_CALLSITE = 6
DEFAULT_MAX_MODE_TOKEN_LENGTH = 32
DEFAULT_MAX_MODES = 0
DEFAULT_MAX_MODE_DISPATCH_SITES_PER_MODE = 12
DEFAULT_MAX_MODE_DISPATCH_ROOTS_PER_MODE = 6
DEFAULT_MAX_MODE_DISPATCH_SITE_CALLSITES = 20
DEFAULT_MAX_MODE_DISPATCH_SITE_TOKENS = 20
DEFAULT_MAX_MODE_DISPATCH_SITE_IGNORED_TOKENS = 6
DEFAULT_MAX_MODE_LOW_CONFIDENCE_CANDIDATES = 50
DEFAULT_MAX_MODE_SLICES = 0
DEFAULT_MAX_MODE_SLICE_ROOTS = 5
DEFAULT_MAX_MODE_SLICE_DISPATCH_SITES = 6
DEFAULT_MAX_MODE_SLICE_OPTIONS = 10
DEFAULT_MAX_MODE_SLICE_STRINGS = 10
DEFAULT_MAX_MODE_SLICE_MESSAGES = 10
DEFAULT_MAX_MODE_SLICE_EXIT_PATHS = 10
DEFAULT_MAX_MODE_SURFACE_ENTRIES = 5
DEFAULT_ENABLE_MODE_NAME_HEURISTICS = 1
DEFAULT_MAX_INTERFACE_ENV = 0
DEFAULT_MAX_INTERFACE_FS = 0
DEFAULT_MAX_INTERFACE_PROCESS = 0
DEFAULT_MAX_INTERFACE_NET = 0
DEFAULT_MAX_INTERFACE_OUTPUT = 0
DEFAULT_CALLGRAPH_EDGE_SHARD_SIZE = 2000

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
