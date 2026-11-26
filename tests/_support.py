"""Shared assertions for sanitizer tests."""

import unittest

from pyhtmlclean import POLICY_BASIC, sanitize, sanitize_url, tokenize

FORBIDDEN_TAGS = {
    "script", "style", "iframe", "object", "embed", "svg", "math", "noscript",
    "template", "textarea", "title", "xmp", "noembed", "noframes", "plaintext",
    "applet", "frame", "frameset", "base", "meta", "link",
}
URL_ATTRS = {"href", "src", "action", "poster", "cite", "background", "srcset"}
HARD_ATTRS = {"srcdoc", "formaction", "xlink:href", "is"}
NON_MARKUP_TOKENS = {"comment", "bogus_comment", "pi", "doctype", "cdata", "rawtext"}


def assert_inert_output(case: unittest.TestCase, output: str, original: str) -> None:
    """Parse output and assert that no executable markup survives."""

    for token in tokenize(output, max_tokens=200000):
        case.assertNotIn(token.type, NON_MARKUP_TOKENS, original)
        if token.type not in {"start", "end"}:
            continue
        case.assertNotIn(token.name, FORBIDDEN_TAGS, original)
        for name, value in token.attributes:
            case.assertFalse(name.startswith("on"), (name, original))
            case.assertNotIn(name, HARD_ATTRS, original)
            case.assertNotEqual(name, "style", original)
            if name in URL_ATTRS and value is not None:
                if name == "srcset":
                    for part in value.split(","):
                        pieces = part.strip().split()
                        if pieces:
                            case.assertIsNotNone(
                                sanitize_url(pieces[0], POLICY_BASIC),
                                (name, value, original),
                            )
                else:
                    case.assertIsNotNone(
                        sanitize_url(value, POLICY_BASIC),
                        (name, value, original),
                    )


def assert_secure_and_idempotent(case: unittest.TestCase, source: str, policy="prose") -> str:
    once = sanitize(source, policy)
    assert_inert_output(case, once, source)
    twice = sanitize(once, policy)
    case.assertEqual(twice, once, source)
    return once
