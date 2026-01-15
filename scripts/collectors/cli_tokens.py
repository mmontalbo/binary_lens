"""Small, dependency-free CLI token helpers.

These helpers are used by collectors and derivations to recognize option tokens
in strings and decode `getopt`-style optstrings.
"""


def _is_probable_longopt_name(value):
    if value is None:
        return False
    for ch in value:
        if ch.isalnum():
            continue
        if ch in "_-":
            continue
        return False
    return True


def parse_option_token(value):
    if not value:
        return None
    if any(ch.isspace() for ch in value):
        return None
    if value.startswith("--"):
        name = value[2:]
        if not name:
            return None
        has_arg = "no"
        if name.endswith("="):
            name = name[:-1]
            has_arg = "required"
        if not name or not _is_probable_longopt_name(name):
            return None
        return {
            "long_name": name,
            "short_name": None,
            "has_arg": has_arg,
        }
    if value.startswith("-") and len(value) == 2:
        ch = value[1]
        if not ch.isalnum():
            return None
        return {
            "long_name": None,
            "short_name": ch,
            "has_arg": "no",
        }
    return None


def decode_short_opt_string(value):
    if not value:
        return []
    options = []
    idx = 0
    length = len(value)
    while idx < length:
        ch = value[idx]
        if idx == 0 and ch in (":", "+", "-"):
            idx += 1
            continue
        if ch == ":":
            idx += 1
            continue
        has_arg = "no"
        if idx + 1 < length and value[idx + 1] == ":":
            if idx + 2 < length and value[idx + 2] == ":":
                has_arg = "optional"
                idx += 2
            else:
                has_arg = "required"
                idx += 1
        options.append({
            "short_name": ch,
            "has_arg": has_arg,
        })
        idx += 1
    return options

