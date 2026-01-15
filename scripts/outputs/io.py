import json
import os


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def write_json(path, obj):
    handle = open(path, "w")
    try:
        handle.write(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True))
        handle.write("\n")
    finally:
        handle.close()


def write_text(path, content):
    handle = open(path, "w")
    try:
        handle.write(content)
    finally:
        handle.close()


def pack_path(*parts):
    return "/".join(parts)

