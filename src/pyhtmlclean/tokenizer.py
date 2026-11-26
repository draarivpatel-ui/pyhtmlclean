"""Explicit character-stream HTML tokenizer.

The tokenizer is a small state machine. It does not use regular expressions
to strip markup, and raw-text regions are consumed in disjoint linear scans.
"""

from __future__ import annotations

from typing import Iterator, NamedTuple, Optional, Tuple

from .errors import TokenLimitError

RAW_TEXT_ELEMENTS = frozenset({
    "script", "style", "textarea", "title", "xmp", "iframe", "noembed",
    "noframes", "noscript", "plaintext",
})

VOID_ELEMENTS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
})

Attribute = Tuple[str, Optional[str]]


class Token(NamedTuple):
    type: str
    data: str = ""
    name: str = ""
    attributes: Tuple[Attribute, ...] = ()
    self_closing: bool = False


def _is_html_space(ch: str) -> bool:
    return ch in " \t\n\r\f"


def _is_ascii_alpha(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z")


def _ascii_lower(value: str) -> str:
    chars = []
    for ch in value:
        code = ord(ch)
        if 65 <= code <= 90:
            chars.append(chr(code + 32))
        else:
            chars.append(ch)
    return "".join(chars)


def _ascii_equal_at(source: str, pos: int, needle: str) -> bool:
    if pos + len(needle) > len(source):
        return False
    for offset, expected in enumerate(needle):
        code = ord(source[pos + offset])
        if 65 <= code <= 90:
            code += 32
        if code != ord(expected):
            return False
    return True


def _find_raw_end(source: str, name: str, start: int) -> int:
    """Find a case-insensitive raw-text end tag without copying the input."""

    pos = source.find("</", start)
    end_len = 2 + len(name)
    while pos != -1:
        if _ascii_equal_at(source, pos + 2, name):
            after = pos + end_len
            if after >= len(source) or source[after] in " \t\n\r\f/>":
                return pos
        pos = source.find("</", pos + 1)
    return -1


class Tokenizer(Iterator[Token]):
    """Streaming tokenizer with a hard token limit."""

    def __init__(self, source: str, max_tokens: int = 100000) -> None:
        self.source = source
        self.max_tokens = max_tokens
        self.pos = 0
        self.count = 0
        self.raw_tag: Optional[str] = None

    def __iter__(self) -> "Tokenizer":
        return self

    def __next__(self) -> Token:
        token = self._scan_token()
        if token is None:
            raise StopIteration
        self.count += 1
        if self.count > self.max_tokens:
            raise TokenLimitError(self.max_tokens)
        return token

    def _scan_token(self) -> Optional[Token]:
        source = self.source
        size = len(source)
        while self.pos < size:
            if self.raw_tag is not None:
                tag = self.raw_tag
                if tag == "plaintext":
                    data = source[self.pos:]
                    self.pos = size
                    if data:
                        return Token("rawtext", data=data)
                    return None
                end = _find_raw_end(source, tag, self.pos)
                if end == -1:
                    data = source[self.pos:]
                    self.pos = size
                    self.raw_tag = None
                    if data:
                        return Token("rawtext", data=data)
                    return None
                if end > self.pos:
                    data = source[self.pos:end]
                    self.pos = end
                    return Token("rawtext", data=data)
                self.pos = end
                self.raw_tag = None
                continue

            lt = source.find("<", self.pos)
            if lt == -1:
                data = source[self.pos:]
                self.pos = size
                if data:
                    return Token("text", data=data)
                return None
            if lt > self.pos:
                data = source[self.pos:lt]
                self.pos = lt
                return Token("text", data=data)

            if source.startswith("<!--", lt):
                return self._scan_comment(lt)
            if source.startswith("<![CDATA[", lt):
                return self._scan_cdata(lt)
            if source[lt:lt + 9].lower() == "<!doctype":
                return self._scan_doctype(lt)
            if source.startswith("<!", lt):
                return self._scan_bogus_comment(lt, "bogus_comment")
            if source.startswith("<?", lt):
                return self._scan_bogus_comment(lt, "pi")
            if source.startswith("</", lt):
                if lt + 2 < size and _is_ascii_alpha(source[lt + 2]):
                    return self._scan_end_tag(lt)
                return self._scan_bogus_comment(lt, "bogus_comment")
            if lt + 1 < size and _is_ascii_alpha(source[lt + 1]):
                return self._scan_start_tag(lt)

            self.pos = lt + 1
            return Token("text", data="<")
        return None

    def _scan_comment(self, start: int) -> Token:
        source = self.source
        size = len(source)
        if source.startswith("<!-->", start):
            self.pos = start + 5
            return Token("comment", data="")
        if source.startswith("<!--->", start):
            self.pos = start + 6
            return Token("comment", data="")
        scan = start + 4
        close = -1
        width = 0
        probe = source.find("--", scan)
        while probe != -1:
            if source.startswith("-->", probe):
                close = probe
                width = 3
                break
            if source.startswith("--!>", probe):
                close = probe
                width = 4
                break
            probe = source.find("--", probe + 1)
        if close == -1:
            self.pos = size
            return Token("comment", data=source[start + 4:])
        self.pos = close + width
        return Token("comment", data=source[start + 4:close])

    def _scan_cdata(self, start: int) -> Token:
        close = self.source.find("]]>", start + 9)
        if close == -1:
            data = self.source[start + 9:]
            self.pos = len(self.source)
        else:
            data = self.source[start + 9:close]
            self.pos = close + 3
        return Token("cdata", data=data)

    def _scan_doctype(self, start: int) -> Token:
        scan = start + 2
        bracket_depth = 0
        quote = ""
        while scan < len(self.source):
            ch = self.source[scan]
            if quote:
                if ch == quote:
                    quote = ""
            elif ch in "\"'":
                quote = ch
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]" and bracket_depth:
                bracket_depth -= 1
            elif ch == ">" and bracket_depth == 0:
                data = self.source[start:scan + 1]
                self.pos = scan + 1
                return Token("doctype", data=data)
            scan += 1
        data = self.source[start:]
        self.pos = len(self.source)
        return Token("doctype", data=data)

    def _scan_bogus_comment(self, start: int, kind: str) -> Token:
        close = self.source.find(">", start + 2)
        if close == -1:
            data = self.source[start + 2:]
            self.pos = len(self.source)
        else:
            data = self.source[start + 2:close]
            self.pos = close + 1
        return Token(kind, data=data)

    def _scan_end_tag(self, start: int) -> Token:
        source = self.source
        scan = start + 2
        while scan < len(source) and not _is_html_space(source[scan]) and source[scan] not in "/>":
            scan += 1
        name = _ascii_lower(source[start + 2:scan])
        close = source.find(">", scan)
        if close == -1:
            self.pos = len(source)
            return Token("text", data=source[start:])
        self.pos = close + 1
        return Token("end", name=name)

    def _scan_start_tag(self, start: int) -> Token:
        source = self.source
        size = len(source)
        scan = start + 1
        while scan < size and not _is_html_space(source[scan]) and source[scan] not in "/>":
            scan += 1
        name = _ascii_lower(source[start + 1:scan])
        attributes = []
        self_closing = False
        closed = False

        while scan < size:
            while scan < size and _is_html_space(source[scan]):
                scan += 1
            if scan >= size:
                break
            if source[scan] == ">":
                scan += 1
                closed = True
                break
            if source[scan] == "/":
                if scan + 1 < size and source[scan + 1] == ">":
                    scan += 2
                    self_closing = True
                    closed = True
                    break
                scan += 1
                continue

            attr_start = scan
            while (scan < size and not _is_html_space(source[scan])
                   and source[scan] not in "=/>"):
                scan += 1
            if scan == attr_start:
                scan += 1
                continue
            attr_name = _ascii_lower(source[attr_start:scan])
            while scan < size and _is_html_space(source[scan]):
                scan += 1
            value = None
            if scan < size and source[scan] == "=":
                scan += 1
                while scan < size and _is_html_space(source[scan]):
                    scan += 1
                if scan < size and source[scan] in "\"'":
                    quote = source[scan]
                    scan += 1
                    end_quote = source.find(quote, scan)
                    if end_quote == -1:
                        scan = size
                        break
                    value = source[scan:end_quote]
                    scan = end_quote + 1
                else:
                    value_start = scan
                    while scan < size and not _is_html_space(source[scan]) and source[scan] != ">":
                        scan += 1
                    value = source[value_start:scan]
            attributes.append((attr_name, value))

        if not closed:
            self.pos = size
            return Token("text", data=source[start:])

        self.pos = scan
        token = Token(
            "start",
            name=name,
            attributes=tuple(attributes),
            self_closing=self_closing,
        )
        if name in RAW_TEXT_ELEMENTS and name not in VOID_ELEMENTS:
            self.raw_tag = name
        return token


def tokenize(source: str, max_tokens: int = 100000) -> Tokenizer:
    """Return a streaming tokenizer for source."""

    return Tokenizer(source, max_tokens=max_tokens)
