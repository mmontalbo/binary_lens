"""String-derived helpers for higher-level lenses."""

from export_primitives import SALIENCE_TAGS


def build_string_bucket_counts(string_refs_by_func, string_tags_by_id):
    bucket_counts_by_func = {}
    for addr, string_ids in string_refs_by_func.items():
        counts = {}
        for string_id in string_ids:
            tags = string_tags_by_id.get(string_id) or set()
            for tag in tags:
                if tag not in SALIENCE_TAGS:
                    continue
                counts[tag] = counts.get(tag, 0) + 1
        if counts:
            bucket_counts_by_func[addr] = counts
    return bucket_counts_by_func

