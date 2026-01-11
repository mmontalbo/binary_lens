SALIENCE_TAGS = set(["env_var", "usage", "format", "path"])


def addr_str(addr):
    if addr is None:
        return None
    try:
        return addr.toString()
    except Exception:
        try:
            return str(addr)
        except Exception:
            return None


def addr_to_int(addr_text):
    if addr_text is None:
        return -1
    try:
        text = addr_text
        if ":" in text:
            text = text.split(":")[-1]
        if text.startswith("0x") or text.startswith("0X"):
            return int(text, 16)
        return int(text, 16)
    except Exception:
        return -1


def sanitize_addr_id(addr_text):
    if addr_text is None:
        return "unknown"
    return addr_text.replace(":", "_").replace("0x", "")


def addr_id(prefix, addr_text):
    return "%s_%s" % (prefix, sanitize_addr_id(addr_text))


def addr_filename(prefix, addr_text, ext):
    return "%s.%s" % (addr_id(prefix, addr_text), ext)


def normalize_symbol_name(name):
    if name is None:
        return None
    base = name
    if "@" in base:
        base = base.split("@")[0]
    if base.startswith("_"):
        base = base[1:]
    return base
