"""Shared bounds and signal sets for derived lenses."""

DEFAULT_MAX_CAPABILITY_FUNCTIONS = 5
DEFAULT_MAX_CAPABILITY_CALLSITE_CLUSTERS = 5
DEFAULT_MAX_CAPABILITY_CALLSITES_PER_CLUSTER = 3
DEFAULT_MAX_CAPABILITY_STRINGS = 8

DEFAULT_MAX_SUBSYSTEMS = 60
DEFAULT_MAX_SUBSYSTEM_REP_FUNCTIONS = 8
DEFAULT_MAX_SUBSYSTEM_IMPORTS = 8
DEFAULT_MAX_SUBSYSTEM_STRING_BUCKETS = 4
DEFAULT_MAX_SUBSYSTEM_CLUSTER_SIZE = 200
DEFAULT_MAX_SUBSYSTEM_STRONG_LINKS = 6

try:
    INT_TYPES = (int, long)
except NameError:
    INT_TYPES = (int,)

OPTION_SIGNALS = set([
    "getopt",
    "getopt_long",
    "__getopt_long",
    "getopt_long_only",
    "argp_parse",
])
FORMAT_SIGNALS = set([
    "printf",
    "fprintf",
    "vprintf",
    "vfprintf",
    "puts",
    "fputs",
    "putchar",
    "sprintf",
    "snprintf",
    "vsprintf",
    "vsnprintf",
    "asprintf",
    "vasprintf",
])
TRAVERSAL_SIGNALS = set([
    "opendir",
    "readdir",
    "readdir64",
])
CALLBACK_SIGNALS = set([
    "ftw",
    "nftw",
])

