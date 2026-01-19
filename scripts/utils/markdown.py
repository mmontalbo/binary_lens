"""Markdown formatting helpers."""

from __future__ import annotations

from typing import Sequence


def format_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    divider: Sequence[str] | None = None,
    render_empty: bool = False,
) -> str:
    if not rows and not render_empty:
        return ""
    if divider is None:
        divider = ["---"] * len(headers)
    else:
        divider = list(divider)
        if len(divider) < len(headers):
            divider.extend(["---"] * (len(headers) - len(divider)))
    header_line = "| " + " | ".join(headers) + " |"
    divider_line = "| " + " | ".join(divider) + " |"
    lines = [header_line, divider_line]
    if rows:
        body = "\n".join("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
        lines.append(body)
    return "\n".join(lines)
