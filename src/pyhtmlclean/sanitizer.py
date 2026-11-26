"""Allowlist HTML sanitizer and audit inspector."""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional, Sequence, Tuple

from .entities import (
    decode_entities,
    decode_entities_deep,
    escape_attribute,
    escape_text,
)
from .errors import DepthLimitError, HtmlCleanError, InputTooLargeError
from .policy import POLICY_STRIP_ALL, Policy, PolicyInput, resolve_policy
from .tokenizer import Tokenizer, VOID_ELEMENTS

DROP_CONTENT_ELEMENTS = frozenset({
    "script", "style", "iframe", "object", "embed", "svg", "math", "noscript",
    "template", "textarea", "title", "xmp", "noembed", "noframes", "plaintext",
    "applet", "frame", "frameset",
})

HARD_DISALLOWED_ELEMENTS = frozenset(set(DROP_CONTENT_ELEMENTS) | {
    "html", "head", "body", "base", "meta", "link",
})

URL_ATTRIBUTES = frozenset({"href", "src", "action", "poster", "cite", "background"})
BLOCKED_URL_SCHEMES = frozenset({"javascript", "vbscript", "data", "file", "blob"})
SAFE_TARGETS = frozenset({"_blank", "_self", "_parent", "_top"})
FOREIGN_SELF_CLOSING = frozenset({"svg", "math"})

P_CLOSERS = frozenset({
    "address", "article", "aside", "blockquote", "div", "dl", "fieldset", "footer",
    "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "main", "nav", "ol",
    "p", "pre", "section", "table", "ul",
})

_ATTR_ORDER = {
    "href": 0,
    "src": 0,
    "cite": 0,
    "poster": 0,
    "action": 0,
    "srcset": 1,
    "rel": 2,
    "target": 3,
}


def _is_ignorable_url_char(ch: str) -> bool:
    code = ord(ch)
    return code <= 0x20 or 0x7F <= code <= 0x9F or ch.isspace()


def _canonical_url_text(raw: str) -> str:
    decoded = decode_entities_deep(raw)
    return "".join(ch for ch in decoded if not _is_ignorable_url_char(ch))


def _valid_scheme_name(value: str) -> bool:
    if not value or not (("a" <= value[0] <= "z") or ("A" <= value[0] <= "Z")):
        return False
    for ch in value[1:]:
        if ch.isascii() and (ch.isalnum() or ch in "+-."):
            continue
        return False
    return True


def _extract_scheme(url: str) -> Optional[str]:
    for index, ch in enumerate(url):
        if ch in "/?#":
            return None
        if ch == ":":
            candidate = url[:index]
            if _valid_scheme_name(candidate):
                return candidate.lower()
            return ""
    return None


def _looks_like_encoded_scheme_obfuscation(raw: str, canonical: str) -> bool:
    """Conservatively flag malformed entity obfuscation of dangerous schemes.

    HTML hexadecimal references consume trailing ASCII hex letters, so an attack
    spelling such as ``&#x3aalert`` does not reliably become a colon across
    parser generations. The dangerous alphabetic prefix is still visible after
    decoding; treating that malformed remainder as hostile avoids depending on
    browser error-recovery details. Ordinary relative names such as
    ``javascriptor`` remain allowed because the next character is ASCII
    alphanumeric.
    """

    if "&" not in raw:
        return False
    lower = canonical.lower()
    for scheme in BLOCKED_URL_SCHEMES:
        if not lower.startswith(scheme):
            continue
        remainder = lower[len(scheme):]
        if remainder and not (remainder[0].isascii() and remainder[0].isalnum()):
            return True
    return False


def sanitize_url(raw: str, policy: Policy) -> Optional[str]:
    """Canonicalize and validate a URL under policy, or return None."""

    url = _canonical_url_text(raw)
    if url == "" or url == "#":
        return url
    if _looks_like_encoded_scheme_obfuscation(raw, url):
        return None
    if "\\" in url:
        return None
    if url.startswith("//"):
        if not policy.allow_protocol_relative:
            return None
        return "https:" + url
    scheme = _extract_scheme(url)
    if scheme is not None:
        if scheme in BLOCKED_URL_SCHEMES:
            return None
        if scheme in policy.schemes:
            return url
        return None
    if policy.allow_relative_urls:
        return url
    return None


def _is_digits(value: str) -> bool:
    return bool(value) and all("0" <= ch <= "9" for ch in value)


def _valid_srcset_descriptor(descriptor: str) -> Tuple[str, bool]:
    lower = descriptor.lower()
    if lower.endswith("w") and _is_digits(lower[:-1]) and any(ch != "0" for ch in lower[:-1]):
        return "width", True
    if lower.endswith("h") and _is_digits(lower[:-1]) and any(ch != "0" for ch in lower[:-1]):
        return "height", True
    if lower.endswith("x"):
        number = lower[:-1]
        if number.count(".") <= 1 and number.replace(".", "").isdigit():
            try:
                if float(number) > 0:
                    return "density", True
            except ValueError:
                pass
    return "", False


_SRCSET_ASCII_WHITESPACE = " \t\n\r\f"


def _parse_srcset_candidates(value: str) -> Optional[List[Tuple[str, Tuple[str, ...]]]]:
    """Parse srcset using the HTML standard's comma-aware candidate grammar."""

    candidates = []  # type: List[Tuple[str, Tuple[str, ...]]]
    pos = 0
    size = len(value)
    while True:
        saw_comma = False
        while pos < size and (value[pos] in _SRCSET_ASCII_WHITESPACE or value[pos] == ","):
            if value[pos] == ",":
                saw_comma = True
            pos += 1
        if saw_comma:
            return None
        if pos >= size:
            break

        url_start = pos
        while pos < size and value[pos] not in _SRCSET_ASCII_WHITESPACE:
            pos += 1
        url = value[url_start:pos]
        descriptors = []
        ended_with_comma = False
        malformed = False

        if url.endswith(","):
            trailing = len(url) - len(url.rstrip(","))
            if trailing != 1:
                return None
            url = url[:-1]
            if not url:
                return None
        else:
            while pos < size and value[pos] in _SRCSET_ASCII_WHITESPACE:
                pos += 1
            current = []
            state = "descriptor"
            while True:
                eof = pos >= size
                ch = "" if eof else value[pos]
                if state == "descriptor":
                    if not eof and ch in _SRCSET_ASCII_WHITESPACE:
                        if current:
                            descriptors.append("".join(current))
                            current = []
                        state = "after"
                    elif not eof and ch == ",":
                        pos += 1
                        if current:
                            descriptors.append("".join(current))
                        ended_with_comma = True
                        break
                    elif not eof and ch == "(":
                        current.append(ch)
                        state = "parens"
                    elif eof:
                        if current:
                            descriptors.append("".join(current))
                        break
                    else:
                        current.append(ch)
                elif state == "parens":
                    if not eof and ch == ")":
                        current.append(ch)
                        state = "descriptor"
                    elif eof:
                        malformed = True
                        break
                    else:
                        current.append(ch)
                else:
                    if not eof and ch in _SRCSET_ASCII_WHITESPACE:
                        pass
                    elif eof:
                        break
                    else:
                        state = "descriptor"
                        pos -= 1
                if eof:
                    break
                pos += 1

        if malformed:
            return None
        if ended_with_comma:
            lookahead = pos
            while lookahead < size and value[lookahead] in _SRCSET_ASCII_WHITESPACE:
                lookahead += 1
            if lookahead >= size:
                return None
        candidates.append((url, tuple(descriptors)))

    if not candidates:
        return None
    return candidates


def sanitize_srcset(raw: str, policy: Policy) -> Optional[str]:
    """Validate a srcset strictly. Any invalid candidate drops the attribute."""

    decoded = decode_entities_deep(raw)
    parsed = _parse_srcset_candidates(decoded)
    if parsed is None:
        return None
    candidates = []
    for raw_url, raw_descriptors in parsed:
        url = sanitize_url(raw_url, policy)
        if url is None:
            return None
        descriptors = []
        seen = set()
        for descriptor in raw_descriptors:
            kind, valid = _valid_srcset_descriptor(descriptor)
            if not valid or kind in seen:
                return None
            seen.add(kind)
            descriptors.append(descriptor.lower())
        if "density" in seen and ("width" in seen or "height" in seen):
            return None
        if "height" in seen and "width" not in seen:
            return None
        candidate = url
        if descriptors:
            candidate += " " + " ".join(descriptors)
        candidates.append(candidate)
    return ", ".join(candidates)


SAFE_CSS_FUNCTIONS = frozenset({
    "rgb", "rgba", "hsl", "hsla", "hwb", "lab", "lch", "oklab", "oklch",
    "color", "color-mix", "calc", "min", "max", "clamp", "round", "mod",
    "rem", "abs", "sign", "sin", "cos", "tan", "asin", "acos", "atan",
    "atan2", "pow", "sqrt", "hypot", "log", "exp", "linear-gradient",
    "radial-gradient", "conic-gradient", "repeating-linear-gradient",
    "repeating-radial-gradient", "repeating-conic-gradient", "cubic-bezier",
    "steps", "matrix", "matrix3d", "perspective", "rotate", "rotate3d",
    "rotatex", "rotatey", "rotatez", "scale", "scale3d", "scalex", "scaley",
    "scalez", "skew", "skewx", "skewy", "translate", "translate3d",
    "translatex", "translatey", "translatez", "blur", "brightness", "contrast",
    "drop-shadow", "grayscale", "hue-rotate", "invert", "opacity", "saturate",
    "sepia", "counter", "counters", "symbols",
})


def _strip_css_comments(value: str) -> Optional[str]:
    out = []
    pos = 0
    quote = ""
    while pos < len(value):
        ch = value[pos]
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
            pos += 1
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            pos += 1
            continue
        if value.startswith("/*", pos):
            end = value.find("*/", pos + 2)
            if end == -1:
                return None
            pos = end + 2
            continue
        out.append(ch)
        pos += 1
    return "".join(out)


def _css_has_disallowed_function(value: str) -> bool:
    quote = ""
    for index, ch in enumerate(value):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch != "(":
            continue
        end = index - 1
        while end >= 0:
            scan = value[end]
            if scan.isascii() and (scan.isalnum() or scan in "-_"):
                end -= 1
                continue
            if not scan.isascii() and scan.isalpha():
                end -= 1
                continue
            break
        name = value[end + 1:index].lower()
        if not name or name not in SAFE_CSS_FUNCTIONS:
            return True
    return False


def _css_is_dangerous(value: str) -> bool:
    lower = value.lower()
    compact = "".join(ch for ch in lower if not ch.isspace())
    dangerous = (
        "expression", "url", "@import", "behavior", "-moz-binding", "progid:",
        "javascript:", "vbscript:", "data:", "file:", "blob:", "var(", "env(", "attr(",
    )
    for term in dangerous:
        if term in lower or term in compact:
            return True
    return _css_has_disallowed_function(value)


def _split_css_declarations(value: str) -> Optional[List[str]]:
    parts = []
    current = []
    quote = ""
    depth = 0
    for ch in value:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            current.append(ch)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return None
            depth -= 1
        if ch == ";" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if quote or depth:
        return None
    parts.append("".join(current))
    return parts


def sanitize_style(raw: str, policy: Policy) -> Optional[str]:
    """Validate inline CSS against a strict property allowlist.

    The parser is deliberately conservative. CSS escapes, comments that hide
    dangerous keywords, custom properties, URLs, expressions and unknown
    properties cause the entire attribute to be dropped.
    """

    if not policy.allow_inline_styles or not policy.css_properties:
        return None
    decoded = decode_entities_deep(raw)
    if "\\" in decoded:
        return None
    css = _strip_css_comments(decoded)
    if css is None or _css_is_dangerous(css):
        return None
    parts = _split_css_declarations(css)
    if parts is None:
        return None
    declarations = []
    for part in parts:
        if not part.strip():
            continue
        if ":" not in part:
            return None
        prop, value = part.split(":", 1)
        prop = prop.strip().lower()
        value = value.strip()
        if not prop or prop.startswith("--") or prop not in policy.css_properties:
            return None
        if not value or any(ch in value for ch in "<>{}@\\"):
            return None
        if any(ord(ch) < 0x20 and ch not in " \t\n\r" for ch in value):
            return None
        if _css_is_dangerous(value):
            return None
        declarations.append("{0}: {1}".format(prop, value))
    if not declarations:
        return None
    return "; ".join(declarations)


def _integer_attribute(value: str, minimum: int, maximum: int) -> Optional[str]:
    stripped = value.strip()
    if not _is_digits(stripped):
        return None
    normalized = stripped.lstrip("0") or "0"
    if len(normalized) > len(str(maximum)):
        return None
    number = int(normalized)
    if number < minimum or number > maximum:
        return None
    return str(number)


def _sanitize_identifier(value: str, policy: Policy) -> Optional[str]:
    if not value or any(ch.isspace() or ord(ch) < 0x20 for ch in value):
        return None
    if policy.clobber_prefix and not value.startswith(policy.clobber_prefix):
        return policy.clobber_prefix + value
    return value


def _attribute_stats_increment(stats: Optional[Dict[str, Counter]], key: str, name: str) -> None:
    if stats is not None:
        stats[key][name] += 1


def sanitize_attributes(
    element: str,
    attributes: Sequence[Tuple[str, Optional[str]]],
    policy: Policy,
    stats: Optional[Dict[str, Counter]] = None,
) -> List[Tuple[str, str]]:
    """Canonicalize all attributes for one element."""

    result = []
    seen = set()
    hard_denied = {"srcdoc", "formaction", "xlink:href", "is"}
    for raw_name, raw_value in attributes:
        name = raw_name.lower()
        if name in seen:
            _attribute_stats_increment(stats, "duplicate_attributes", name)
            continue
        seen.add(name)
        if name.startswith("on") or name in hard_denied or (name == "style" and not policy.allow_inline_styles):
            _attribute_stats_increment(stats, "attributes_dropped", name)
            continue
        if not policy.allows_attribute(element, name):
            _attribute_stats_increment(stats, "attributes_dropped", name)
            continue

        value = "" if raw_value is None else decode_entities(raw_value)
        canonical = None  # type: Optional[str]
        if name in URL_ATTRIBUTES:
            canonical = sanitize_url("" if raw_value is None else raw_value, policy)
            if canonical is None:
                _attribute_stats_increment(stats, "urls_blocked", name)
        elif name == "srcset":
            canonical = sanitize_srcset("" if raw_value is None else raw_value, policy)
            if canonical is None:
                _attribute_stats_increment(stats, "urls_blocked", name)
        elif name == "style":
            canonical = sanitize_style("" if raw_value is None else raw_value, policy)
        elif name in {"id", "name"}:
            canonical = _sanitize_identifier(value, policy)
        elif name == "target":
            lowered = value.strip().lower()
            if lowered in SAFE_TARGETS:
                canonical = lowered
        elif name == "rel":
            lowered = " ".join(value.lower().split())
            if "stylesheet" not in lowered and "import" not in lowered:
                canonical = lowered
        elif name in {"colspan", "rowspan"}:
            canonical = _integer_attribute(value, 1, 1000)
        elif name in {"width", "height"}:
            canonical = _integer_attribute(value, 0, 100000)
        elif name == "loading":
            lowered = value.strip().lower()
            if lowered in {"eager", "lazy"}:
                canonical = lowered
        elif name == "decoding":
            lowered = value.strip().lower()
            if lowered in {"sync", "async", "auto"}:
                canonical = lowered
        else:
            canonical = value

        if canonical is None:
            _attribute_stats_increment(stats, "attributes_dropped", name)
            continue
        result.append((name, canonical))
        _attribute_stats_increment(stats, "attributes_allowed", name)

    names = {name for name, _ in result}
    if policy.rel_noopener and "target" in names:
        target = next((value for key, value in result if key == "target"), "")
        if target == "_blank":
            existing = ""
            index = -1
            for pos, pair in enumerate(result):
                if pair[0] == "rel":
                    existing = pair[1]
                    index = pos
                    break
            tokens = []
            for token in existing.split():
                if token == "opener":
                    continue
                if token not in tokens:
                    tokens.append(token)
            for required in ("noopener", "noreferrer"):
                if required not in tokens:
                    tokens.append(required)
            pair = ("rel", " ".join(tokens))
            if index == -1:
                result.append(pair)
            else:
                result[index] = pair

    result.sort(key=lambda pair: (_ATTR_ORDER.get(pair[0], 4), pair[0]))
    return result


class _AuditState:
    def __init__(self) -> None:
        self.counters = {
            "elements_allowed": Counter(),
            "elements_stripped": Counter(),
            "elements_dropped": Counter(),
            "attributes_allowed": Counter(),
            "attributes_dropped": Counter(),
            "duplicate_attributes": Counter(),
            "urls_blocked": Counter(),
        }
        self.token_count = 0
        self.comments_removed = 0
        self.processing_instructions_removed = 0
        self.cdata_removed = 0
        self.doctypes_removed = 0
        self.nul_bytes_removed = 0
        self.dropped_text_chars = 0


def _counter_dict(counter: Counter) -> Dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def sanitize_with_policy(source: str, policy: Policy, audit: Optional[_AuditState] = None) -> str:
    if not isinstance(source, str):
        raise HtmlCleanError("HTML input must be a string", "INVALID_INPUT")
    if len(source) > policy.max_input_bytes:
        raise InputTooLargeError(policy.max_input_bytes)
    if len(source.encode("utf-8", errors="surrogatepass")) > policy.max_input_bytes:
        raise InputTooLargeError(policy.max_input_bytes)
    if any("\ud800" <= ch <= "\udfff" for ch in source):
        source = "".join("\ufffd" if "\ud800" <= ch <= "\udfff" else ch for ch in source)

    nul_count = source.count("\x00")
    if audit is not None:
        audit.nul_bytes_removed = nul_count
    if nul_count:
        source = source.replace("\x00", "")

    out = []
    stack = []
    drop_name = ""
    drop_depth = 0

    def close_top() -> None:
        if stack:
            out.append("</" + stack.pop() + ">")

    def close_through(name: str) -> None:
        while stack:
            top = stack.pop()
            out.append("</" + top + ">")
            if top == name:
                break

    def prepare_start(name: str) -> None:
        if name == "a" and "a" in stack:
            close_through("a")
        if stack and stack[-1] == "p" and name in P_CLOSERS:
            close_top()
        if name == "li" and stack and stack[-1] == "li":
            close_top()
        if name in {"dt", "dd"} and stack and stack[-1] in {"dt", "dd"}:
            close_top()
        if name == "tr":
            while stack and stack[-1] in {"td", "th"}:
                close_top()
            if stack and stack[-1] == "tr":
                close_top()
        if name in {"td", "th"} and stack and stack[-1] in {"td", "th"}:
            close_top()
        if name in {"thead", "tbody", "tfoot"}:
            while stack and stack[-1] in {"td", "th", "tr"}:
                close_top()
            if stack and stack[-1] in {"thead", "tbody", "tfoot"}:
                close_top()

    tokens = list(Tokenizer(source, max_tokens=policy.max_tokens))
    void_close_count = Counter()
    for token in tokens:
        if token.type == "end" and token.name in VOID_ELEMENTS and token.name in DROP_CONTENT_ELEMENTS:
            void_close_count[token.name] += 1
    void_close_remaining = Counter(void_close_count)

    for token in tokens:
        if audit is not None:
            audit.token_count += 1

        if token.type in {"comment", "bogus_comment"}:
            if audit is not None:
                audit.comments_removed += 1
            continue
        if token.type == "pi":
            if audit is not None:
                audit.processing_instructions_removed += 1
            continue
        if token.type == "doctype":
            if audit is not None:
                audit.doctypes_removed += 1
            continue
        if token.type == "cdata":
            if audit is not None:
                audit.cdata_removed += 1
            continue

        if drop_depth:
            if token.type == "start" and token.name == drop_name:
                if not (token.name in FOREIGN_SELF_CLOSING and token.self_closing):
                    if token.name not in VOID_ELEMENTS:
                        drop_depth += 1
            elif token.type == "end" and token.name == drop_name:
                drop_depth -= 1
                if drop_depth == 0:
                    drop_name = ""
            if token.type in {"text", "rawtext"} and audit is not None:
                audit.dropped_text_chars += len(token.data)
            continue

        if token.type in {"text", "rawtext"}:
            out.append(escape_text(decode_entities(token.data)))
            continue

        if token.type == "end":
            name = token.name
            if not name or name in VOID_ELEMENTS:
                continue
            if name in stack:
                close_through(name)
            continue

        if token.type != "start":
            continue

        name = token.name
        if not name:
            continue
        foreign_self_closed = token.self_closing and name in FOREIGN_SELF_CLOSING
        if name in DROP_CONTENT_ELEMENTS:
            if audit is not None:
                audit.counters["elements_dropped"][name] += 1
            if foreign_self_closed:
                continue
            if name in VOID_ELEMENTS:
                if void_close_remaining[name] < 1:
                    continue
                void_close_remaining[name] -= 1
            drop_name = name
            drop_depth = 1
            continue
        if name in HARD_DISALLOWED_ELEMENTS or name not in policy.elements:
            if audit is not None:
                audit.counters["elements_stripped"][name] += 1
            continue

        prepare_start(name)
        if len(stack) >= policy.max_depth:
            raise DepthLimitError(policy.max_depth)

        attributes = sanitize_attributes(
            name,
            token.attributes,
            policy,
            audit.counters if audit is not None else None,
        )
        piece = ["<", name]
        for attr_name, attr_value in attributes:
            piece.extend([" ", attr_name, '="', escape_attribute(attr_value), '"'])
        piece.append(">")
        out.append("".join(piece))
        if audit is not None:
            audit.counters["elements_allowed"][name] += 1
        if name not in VOID_ELEMENTS:
            stack.append(name)

    while stack:
        close_top()
    return "".join(out)


def sanitize(source: str, policy: PolicyInput = "prose") -> str:
    """Sanitize HTML with a preset name or custom Policy."""

    return sanitize_with_policy(source, resolve_policy(policy))


def strip_html(source: str) -> str:
    """Return decoded plain text with all markup removed.

    The result is plain text, not HTML-safe output. Escape it before inserting
    it into another HTML document.
    """

    cleaned = sanitize_with_policy(source, POLICY_STRIP_ALL)
    return decode_entities(cleaned)


def inspect_html(source: str, policy: PolicyInput = "prose") -> Dict[str, object]:
    """Sanitize source and return a JSON-serializable audit report."""

    resolved = resolve_policy(policy)
    audit = _AuditState()
    output = sanitize_with_policy(source, resolved, audit)
    report = {
        "input_length": len(source) if isinstance(source, str) else 0,
        "output_length": len(output),
        "output": output,
        "tokens": audit.token_count,
        "elements_allowed": _counter_dict(audit.counters["elements_allowed"]),
        "elements_stripped": _counter_dict(audit.counters["elements_stripped"]),
        "elements_dropped": _counter_dict(audit.counters["elements_dropped"]),
        "attributes_allowed": _counter_dict(audit.counters["attributes_allowed"]),
        "attributes_dropped": _counter_dict(audit.counters["attributes_dropped"]),
        "duplicate_attributes": _counter_dict(audit.counters["duplicate_attributes"]),
        "urls_blocked": _counter_dict(audit.counters["urls_blocked"]),
        "comments_removed": audit.comments_removed,
        "processing_instructions_removed": audit.processing_instructions_removed,
        "cdata_removed": audit.cdata_removed,
        "doctypes_removed": audit.doctypes_removed,
        "nul_bytes_removed": audit.nul_bytes_removed,
        "dropped_text_chars": audit.dropped_text_chars,
    }
    return report


class Sanitizer:
    """Reusable sanitizer bound to one normalized policy."""

    def __init__(self, policy: PolicyInput = "prose") -> None:
        self.policy = resolve_policy(policy)

    def sanitize(self, source: str) -> str:
        return sanitize_with_policy(source, self.policy)

    def inspect(self, source: str) -> Dict[str, object]:
        return inspect_html(source, self.policy)

    def strip(self, source: str) -> str:
        empty = self.policy.replace(elements=frozenset())
        return decode_entities(sanitize_with_policy(source, empty))
