"""Entity decoding and canonical escaping helpers."""

from __future__ import annotations

import html

_MAX_DECIMAL_REFERENCE = "1114111"
_MAX_HEX_REFERENCE = "10ffff"


def _is_hex_digit(ch: str) -> bool:
    return ("0" <= ch <= "9") or ("a" <= ch <= "f") or ("A" <= ch <= "F")


def _cap_numeric_character_references(value: str) -> str:
    if "&#" not in value:
        return value
    out = []
    pos = 0
    size = len(value)
    while pos < size:
        amp = value.find("&#", pos)
        if amp == -1:
            out.append(value[pos:])
            break
        out.append(value[pos:amp])
        scan = amp + 2
        base = 10
        if scan < size and value[scan] in "xX":
            base = 16
            scan += 1
        digit_start = scan
        if base == 10:
            while scan < size and "0" <= value[scan] <= "9":
                scan += 1
        else:
            while scan < size and _is_hex_digit(value[scan]):
                scan += 1
        if scan == digit_start:
            out.append("&")
            pos = amp + 1
            continue
        digit_end = scan
        if scan < size and value[scan] == ";":
            scan += 1
        significant = value[digit_start:digit_end].lstrip("0") or "0"
        if base == 10:
            too_large = (
                len(significant) > len(_MAX_DECIMAL_REFERENCE)
                or (len(significant) == len(_MAX_DECIMAL_REFERENCE) and significant > _MAX_DECIMAL_REFERENCE)
            )
            if too_large:
                out.append("&#x110000;")
            else:
                out.append("&#" + significant + ";")
        else:
            folded = significant.lower()
            too_large = (
                len(folded) > len(_MAX_HEX_REFERENCE)
                or (len(folded) == len(_MAX_HEX_REFERENCE) and folded > _MAX_HEX_REFERENCE)
            )
            if too_large:
                out.append("&#x110000;")
            else:
                out.append("&#x" + folded + ";")
        pos = scan
    return "".join(out)


def decode_entities(value: str) -> str:
    """Decode HTML character references once, matching browser parsing."""

    return html.unescape(_cap_numeric_character_references(value))


def decode_entities_deep(value: str, rounds: int = 6) -> str:
    """Decode nested references a small fixed number of times.

    This is intentionally limited. It is used only for security decisions in
    URL and CSS values, never as a substitute for correct output escaping.
    """

    current = value
    for _ in range(rounds):
        if "&" not in current:
            break
        decoded = decode_entities(current)
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
