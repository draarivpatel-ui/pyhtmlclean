"""Entity decoding and canonical escaping helpers."""

from __future__ import annotations

import html


def decode_entities(value: str) -> str:
    """Decode HTML character references once, matching browser parsing."""

    return html.unescape(value)


def decode_entities_deep(value: str, rounds: int = 6) -> str:
    """Decode nested references a small fixed number of times.

    This is intentionally limited. It is used only for security decisions in
    URL and CSS values, never as a substitute for correct output escaping.
    """

    current = value
    for _ in range(rounds):
        if "&" not in current:
            break
        decoded = html.unescape(current)
        if decoded == current:
            break
        current = decoded
    return current


def escape_text(value: str) -> str:
    """Escape text for canonical HTML output."""

    return html.escape(value, quote=False)


def escape_attribute(value: str) -> str:
    """Escape an attribute value for canonical double-quoted output."""

    return html.escape(value, quote=True)
