BINARY_LENS_VERSION = "0.1.0-dev"
FORMAT_VERSION = "0.1"

# Defaults cap export size to keep packs bounded and diff-friendly.
DEFAULT_MAX_FULL_FUNCTIONS = 50
DEFAULT_MAX_FUNCTIONS_INDEX = 2000
DEFAULT_MAX_STRINGS = 200
DEFAULT_MAX_CALL_EDGES = 2000
DEFAULT_MAX_CALLS_PER_FUNCTION = 200
DEFAULT_MAX_DECOMP_LINES = 200
DEFAULT_MAX_CLI_OPTIONS = 400
DEFAULT_MAX_CLI_PARSE_LOOPS = 12
DEFAULT_MAX_CLI_OPTION_EVIDENCE = 8
DEFAULT_MAX_CLI_PARSE_SITES_PER_OPTION = 6
DEFAULT_MAX_CLI_LONGOPT_ENTRIES = 256
DEFAULT_MAX_CLI_CALLSITES_PER_PARSE_LOOP = 8
DEFAULT_MAX_CLI_FLAG_VARS = 6
DEFAULT_MAX_CLI_CHECK_SITES = 8

CAPABILITY_RULES = [
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
