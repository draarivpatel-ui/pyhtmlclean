"""Sanitizer policy objects and safe presets."""

from __future__ import annotations

from types import MappingProxyType
from typing import Dict, FrozenSet, Iterable, Mapping, Optional, Union

from .errors import InvalidPolicyError

_DEFAULT_SCHEMES = frozenset({"http", "https", "mailto", "tel"})
_EMPTY = frozenset()


def _frozen_names(value: Iterable[str], label: str) -> FrozenSet[str]:
    if isinstance(value, str):
        items = (value,)
    else:
        try:
            items = tuple(value)
        except TypeError:
            raise InvalidPolicyError("{0} must be an iterable of strings".format(label))
    names = []
    for item in items:
        if not isinstance(item, str):
            raise InvalidPolicyError("{0} entries must be strings".format(label))
        names.append(item.strip().lower())
    return frozenset(names)


def _positive_int(value: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise InvalidPolicyError("{0} must be a positive integer".format(label))
    return value


def _valid_ascii_token(value: str, allow_wildcard: bool = False) -> bool:
    """Validate a policy token that may later be serialized into markup."""

    if not value:
        return False
    if allow_wildcard and value == "*":
        return True
    body = value[:-1] if allow_wildcard and value.endswith("*") else value
    if not body or not (("a" <= body[0] <= "z") or body[0] == "-"):
        return False
    for ch in body:
        if "a" <= ch <= "z" or "0" <= ch <= "9" or ch in "-._:":
            continue
        return False
    return True


def _require_valid_names(names: FrozenSet[str], label: str, allow_wildcard: bool = False) -> None:
    for name in names:
        if not _valid_ascii_token(name, allow_wildcard=allow_wildcard):
            raise InvalidPolicyError("{0} contains an unsafe or invalid name: {1!r}".format(label, name))


class Policy:
    """Immutable sanitizer policy.

    attributes maps an element name to attribute names. The special element
    key "*" applies to every element. An attribute entry ending in "*" is a
    prefix wildcard, so "data-*" can be enabled without enabling every field.
    """

    __slots__ = (
        "elements",
        "attributes",
        "schemes",
        "allow_relative_urls",
        "allow_protocol_relative",
        "allow_inline_styles",
        "css_properties",
        "clobber_prefix",
        "rel_noopener",
        "max_depth",
        "max_tokens",
        "max_input_bytes",
    )

    def __init__(
        self,
        elements: Iterable[str],
        attributes: Optional[Mapping[str, Iterable[str]]] = None,
        schemes: Iterable[str] = _DEFAULT_SCHEMES,
        allow_relative_urls: bool = True,
        allow_protocol_relative: bool = False,
        allow_inline_styles: bool = False,
        css_properties: Iterable[str] = (),
        clobber_prefix: Optional[str] = None,
        rel_noopener: bool = True,
        max_depth: int = 64,
        max_tokens: int = 100000,
        max_input_bytes: int = 512 * 1024,
    ) -> None:
        self.elements = _frozen_names(elements, "elements")
        _require_valid_names(self.elements, "elements")

        attr_map: Dict[str, FrozenSet[str]] = {}
        if attributes is not None:
            if not isinstance(attributes, Mapping):
                raise InvalidPolicyError("attributes must be a mapping")
            for raw_tag, raw_names in attributes.items():
                if not isinstance(raw_tag, str):
                    raise InvalidPolicyError("attributes keys must be strings")
                tag = raw_tag.strip().lower()
                if not tag:
                    raise InvalidPolicyError("attributes keys must not be empty")
                if tag != "*" and not _valid_ascii_token(tag):
                    raise InvalidPolicyError("attributes contains an unsafe element key: {0!r}".format(tag))
                attr_map[tag] = _frozen_names(raw_names, "attributes[{0}]".format(tag))
                _require_valid_names(attr_map[tag], "attributes[{0}]".format(tag), allow_wildcard=True)
        self.attributes = MappingProxyType(attr_map)

        schemeset = set()
        for scheme in _frozen_names(schemes, "schemes"):
            normalized = scheme[:-1] if scheme.endswith(":") else scheme
            if not normalized or not (("a" <= normalized[0] <= "z")):
                raise InvalidPolicyError("schemes contains an invalid scheme: {0!r}".format(scheme))
            if not all(ch.isascii() and (ch.isalnum() or ch in "+-.") for ch in normalized[1:]):
                raise InvalidPolicyError("schemes contains an invalid scheme: {0!r}".format(scheme))
            schemeset.add(normalized)
        self.schemes = frozenset(schemeset)

        self.allow_relative_urls = bool(allow_relative_urls)
        self.allow_protocol_relative = bool(allow_protocol_relative)
        self.allow_inline_styles = bool(allow_inline_styles)
        self.css_properties = _frozen_names(css_properties, "css_properties")
        _require_valid_names(self.css_properties, "css_properties")

        if clobber_prefix is not None:
            if not isinstance(clobber_prefix, str) or not clobber_prefix:
                raise InvalidPolicyError("clobber_prefix must be a non-empty string or None")
            safe = clobber_prefix.replace("_", "").replace("-", "")
            if not safe.isalnum() or not safe.isascii():
                raise InvalidPolicyError(
                    "clobber_prefix may contain only ASCII letters, digits, underscore and hyphen"
                )
        self.clobber_prefix = clobber_prefix
        self.rel_noopener = bool(rel_noopener)
        self.max_depth = _positive_int(max_depth, "max_depth")
        self.max_tokens = _positive_int(max_tokens, "max_tokens")
        self.max_input_bytes = _positive_int(max_input_bytes, "max_input_bytes")

    def allows_attribute(self, element: str, name: str) -> bool:
        """Return whether name is allowlisted on element."""

        entries = set(self.attributes.get("*", _EMPTY))
        entries.update(self.attributes.get(element, _EMPTY))
        if name in entries or "*" in entries:
            return True
        for entry in entries:
            if entry.endswith("*") and len(entry) > 1 and name.startswith(entry[:-1]):
                return True
        return False

    def replace(self, **changes: object) -> "Policy":
        """Return a new policy with selected fields replaced."""

        config = {
            "elements": self.elements,
            "attributes": self.attributes,
            "schemes": self.schemes,
            "allow_relative_urls": self.allow_relative_urls,
            "allow_protocol_relative": self.allow_protocol_relative,
            "allow_inline_styles": self.allow_inline_styles,
            "css_properties": self.css_properties,
            "clobber_prefix": self.clobber_prefix,
            "rel_noopener": self.rel_noopener,
            "max_depth": self.max_depth,
            "max_tokens": self.max_tokens,
            "max_input_bytes": self.max_input_bytes,
        }
        config.update(changes)
        return Policy(**config)  # type: ignore[arg-type]


STRICT_ELEMENTS = frozenset({
    "a", "abbr", "b", "blockquote", "br", "code", "em", "i", "li", "ol",
    "p", "pre", "q", "strong", "ul",
})

PROSE_ELEMENTS = frozenset(set(STRICT_ELEMENTS) | {
    "article", "aside", "caption", "dd", "del", "details", "div", "dl", "dt",
    "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6",
    "header", "hr", "ins", "kbd", "main", "mark", "nav", "s", "samp",
    "section", "small", "span", "sub", "summary", "sup", "table", "tbody",
    "td", "tfoot", "th", "thead", "tr", "u", "var", "wbr",
})

BASIC_ELEMENTS = frozenset(set(PROSE_ELEMENTS) | {"img", "picture", "source"})

CORE_ATTRIBUTES = {
    "*": frozenset({"title", "lang", "dir"}),
    "a": frozenset({"href", "target", "rel"}),
    "blockquote": frozenset({"cite"}),
    "q": frozenset({"cite"}),
    "td": frozenset({"colspan", "rowspan"}),
    "th": frozenset({"colspan", "rowspan"}),
}

BASIC_ATTRIBUTES = dict(CORE_ATTRIBUTES)
BASIC_ATTRIBUTES.update({
    "img": frozenset({"alt", "src", "srcset", "sizes", "width", "height", "loading", "decoding"}),
    "source": frozenset({"src", "srcset", "sizes", "type", "media", "width", "height"}),
})

POLICY_STRICT = Policy(STRICT_ELEMENTS, CORE_ATTRIBUTES)
POLICY_PROSE = Policy(PROSE_ELEMENTS, CORE_ATTRIBUTES)
POLICY_BASIC = Policy(BASIC_ELEMENTS, BASIC_ATTRIBUTES)
POLICY_STRIP_ALL = Policy(frozenset(), {})

POLICIES = MappingProxyType({
    "strict": POLICY_STRICT,
    "prose": POLICY_PROSE,
    "basic": POLICY_BASIC,
    "strip_all": POLICY_STRIP_ALL,
})

PolicyInput = Union[str, Policy, None]


def resolve_policy(policy: PolicyInput = "prose") -> Policy:
    """Resolve a preset name or validate a Policy instance."""

    if policy is None:
        return POLICY_PROSE
    if isinstance(policy, str):
        key = policy.strip().lower()
        if key in POLICIES:
            return POLICIES[key]
        raise InvalidPolicyError("unknown policy preset: {0}".format(policy))
    if isinstance(policy, Policy):
        return policy
    raise InvalidPolicyError("policy must be a preset name or Policy instance")
