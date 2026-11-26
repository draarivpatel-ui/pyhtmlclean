"""Inline CSS hardening and policy behavior tests."""

import unittest

from pyhtmlclean import POLICY_BASIC, Policy, sanitize, sanitize_style

CSS_PROPERTIES = {
    "color", "background-color", "font-weight", "font-style", "text-align",
    "text-decoration", "margin", "margin-left", "margin-right", "padding",
    "border-color", "border-width", "border-style",
}


def css_policy():
    return Policy(
        ["div", "p", "span"],
        {"*": ["style"]},
        allow_inline_styles=True,
        css_properties=CSS_PROPERTIES,
    )


DANGEROUS_STYLES = [
    "background-color:url(javascript:alert(1))",
    "color:expression(alert(1))",
    "color:EXPRESSION(alert(1))",
    "behavior:url(#default#time2)",
    "-moz-binding:url(https://evil.invalid/x.xml)",
    "color:red; behavior:url(x)",
    "@import url(https://evil.invalid/x.css)",
    "color:red; @import 'https://evil.invalid/x.css'",
    "background-color:u/**/rl(javascript:alert(1))",
    "background-color:u\\72l(javascript:alert(1))",
    "color:exp\\72 ession(alert(1))",
    "color:var(--evil)",
    "color:env(safe-area-inset-top)",
    "color:attr(data-evil)",
    "color:javascript:alert(1)",
    "color:vbscript:msgbox(1)",
    "color:data:text/html,x",
    "color:file:///etc/passwd",
    "color:blob:https://example.invalid/x",
    "color:red; unknown-property:blue",
    "--evil:red; color:blue",
    "color:{red}",
    "color:red}",
    "color:red<script>",
    "color:red@import",
    "margin",
]


class DangerousStyleTests(unittest.TestCase):
    pass


def _make_dangerous_style_test(style):
    def test(self):
        source = '<div style="{0}">x</div>'.format(style.replace('"', '&quot;'))
        self.assertEqual(sanitize(source, css_policy()), "<div>x</div>", style)
    return test


for _index, _style in enumerate(DANGEROUS_STYLES, 1):
    setattr(
        DangerousStyleTests,
        "test_dangerous_style_{0:03d}".format(_index),
        _make_dangerous_style_test(_style),
    )


class InlineStyleTests(unittest.TestCase):
    def test_safe_style_is_preserved(self):
        self.assertEqual(
            sanitize('<div style="color: red; text-align: center">x</div>', css_policy()),
            '<div style="color: red; text-align: center">x</div>',
        )

    def test_style_declarations_are_canonicalized(self):
        self.assertEqual(
            sanitize('<div style=" color : red ;">x</div>', css_policy()),
            '<div style="color: red">x</div>',
        )

    def test_safe_rgb_function_is_allowed(self):
        self.assertEqual(
            sanitize('<div style="color: rgb(1, 2, 3)">x</div>', css_policy()),
            '<div style="color: rgb(1, 2, 3)">x</div>',
        )

    def test_safe_calc_function_is_allowed(self):
        policy = Policy(
            ["div"], {"*": ["style"]}, allow_inline_styles=True,
            css_properties={"margin"},
        )
        self.assertEqual(
            sanitize('<div style="margin: calc(1em + 2px)">x</div>', policy),
            '<div style="margin: calc(1em + 2px)">x</div>',
        )

    def test_style_is_stripped_by_default(self):
        self.assertEqual(sanitize('<div style="color:red">x</div>'), "<div>x</div>")

    def test_style_is_stripped_when_enabled_without_properties(self):
        policy = Policy(["div"], {"*": ["style"]}, allow_inline_styles=True)
        self.assertEqual(sanitize('<div style="color:red">x</div>', policy), "<div>x</div>")

    def test_property_allowlist_is_enforced_exactly(self):
        policy = Policy(
            ["div"], {"*": ["style"]}, allow_inline_styles=True,
            css_properties={"color"},
        )
        self.assertEqual(
            sanitize('<div style="color:red; margin:0">x</div>', policy),
            "<div>x</div>",
        )

    def test_custom_properties_are_never_emitted(self):
        policy = Policy(
            ["div"], {"*": ["style"]}, allow_inline_styles=True,
            css_properties={"--x", "color"},
        )
        self.assertIsNone(sanitize_style("--x: red; color: blue", policy))

    def test_css_comments_are_removed_before_keyword_checks(self):
        self.assertIsNone(sanitize_style("color: exp/**/ression(alert(1))", css_policy()))

    def test_css_entities_are_decoded_before_keyword_checks(self):
        self.assertIsNone(sanitize_style("color: &#117;rl(javascript:alert(1))", css_policy()))

    def test_css_backslash_escapes_are_rejected(self):
        self.assertIsNone(sanitize_style("color: red\\61", css_policy()))

    def test_empty_style_is_omitted(self):
        self.assertEqual(sanitize('<div style="   ">x</div>', css_policy()), "<div>x</div>")

    def test_unclosed_css_comment_is_fail_closed(self):
        self.assertEqual(sanitize('<div style="color:red /*">x</div>', css_policy()), "<div>x</div>")

    def test_safe_important_is_preserved(self):
        self.assertEqual(
            sanitize('<div style="color: red !important">x</div>', css_policy()),
            '<div style="color: red !important">x</div>',
        )

    def test_multiple_safe_properties_keep_input_order(self):
        self.assertEqual(
            sanitize('<div style="margin: 0; color: red">x</div>', css_policy()),
            '<div style="margin: 0; color: red">x</div>',
        )


class AttributePolicyTests(unittest.TestCase):
    def test_title_lang_and_dir_are_global_in_presets(self):
        self.assertEqual(
            sanitize('<p title="t" lang="en" dir="ltr">x</p>'),
            '<p dir="ltr" lang="en" title="t">x</p>',
        )

    def test_class_is_not_allowed_by_default(self):
        self.assertEqual(sanitize('<p class="x">x</p>'), "<p>x</p>")

    def test_class_can_be_explicitly_allowed(self):
        policy = Policy(["p"], {"p": ["class"]})
        self.assertEqual(sanitize('<p class="x">x</p>', policy), '<p class="x">x</p>')

    def test_boolean_attribute_is_emitted_with_empty_value(self):
        policy = Policy(["input"], {"input": ["disabled"]})
        self.assertEqual(sanitize("<input disabled>", policy), '<input disabled="">')
