"""Import (external symbol) collection."""

from export_primitives import addr_str


def collect_imports(program):
    external_manager = program.getExternalManager()
    imports = []
    library_names = []
    try:
        library_names = list(external_manager.getExternalLibraryNames())
    except Exception:
        library_names = []

    for library_name in library_names:
        try:
            loc_iter = external_manager.getExternalLocations(library_name)
        except Exception:
            loc_iter = None
        if loc_iter is None:
            continue
        while loc_iter.hasNext():
            loc = loc_iter.next()
            try:
                symbol = loc.getSymbol()
            except Exception:
                symbol = None
            if symbol:
                name = symbol.getName()
            else:
                try:
                    name = loc.getLabel()
                except Exception:
                    name = None
            entry = {
                "name": name,
                "address": addr_str(loc.getAddress()),
            }
            try:
                entry["library"] = loc.getLibraryName()
            except Exception:
                entry["library"] = library_name
            if symbol:
                entry["symbol_type"] = str(symbol.getSymbolType())
            try:
                func = loc.getFunction()
            except Exception:
                func = None
            if func:
                entry["signature"] = func.getSignature().toString()
            imports.append(entry)

    imports.sort(
        key=lambda item: (item.get("library") or "", item.get("name") or "", item.get("address") or "")
    )
    return imports

