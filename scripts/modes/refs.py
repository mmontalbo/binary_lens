"""Attach callsite reference paths to mode payloads."""


def attach_mode_callsite_refs(modes_payload, dispatch_sites_payload, callsites_ref):
    if not callsites_ref:
        return
    if isinstance(modes_payload, dict):
        modes_payload["callsites_ref"] = callsites_ref
    if isinstance(dispatch_sites_payload, dict):
        dispatch_sites_payload["callsites_ref"] = callsites_ref
