"""Tests for common bleach migration behavior."""

import unittest

from pyhtmlclean import Policy, sanitize, strip_html


def migration_policy(tags, attributes=None):
    return Policy(tags, attributes or {})


class BleachMigrationTests(unittest.TestCase):
    def test_simple_allowed_bold_is_preserved(self):
        policy = migration_policy(["b"])
        self.assertEqual(sanitize("<b>hello</b>", policy), "<b>hello</b>")

    def test_disallowed_tag_is_unwrapped_not_deleted(self):
        policy = migration_policy(["b"])
        self.assertEqual(sanitize("<u>x</u><b>y</b>", policy), "x<b>y</b>")

    def test_script_is_not_unwrapped(self):
        policy = migration_policy(["b"])
        self.assertEqual(sanitize("<script>alert(1)</script>safe", policy), "safe")

    def test_nested_allowed_markup_is_preserved(self):
        policy = migration_policy(["p", "b", "em"])
        self.assertEqual(sanitize("<p>a <b>b <em>c</em></b></p>", policy), "<p>a <b>b <em>c</em></b></p>")

    def test_text_entities_round_trip_canonically(self):
        policy = migration_policy(["p"])
        self.assertEqual(sanitize("<p>fish &amp; chips</p>", policy), "<p>fish &amp; chips</p>")

    def test_raw_angle_text_is_escaped(self):
        policy = migration_policy(["p"])
        self.assertEqual(sanitize("<p>1 < 2</p>", policy), "<p>1 &lt; 2</p>")

    def test_link_href_requires_attribute_allowlist(self):
        policy = migration_policy(["a"])
        self.assertEqual(sanitize('<a href="https://example.invalid">x</a>', policy), "<a>x</a>")

    def test_link_href_with_attribute_allowlist(self):
        policy = migration_policy(["a"], {"a": ["href"]})
        self.assertEqual(
            sanitize('<a href="https://example.invalid">x</a>', policy),
            '<a href="https://example.invalid">x</a>',
        )

    def test_javascript_href_is_removed_in_migration_policy(self):
        policy = migration_policy(["a"], {"a": ["href"]})
        self.assertEqual(sanitize('<a href="javascript:alert(1)">x</a>', policy), "<a>x</a>")

    def test_data_href_is_removed_in_migration_policy(self):
        policy = migration_policy(["a"], {"a": ["href"]})
        self.assertEqual(sanitize('<a href="data:text/html,x">x</a>', policy), "<a>x</a>")

    def test_relative_link_is_allowed_by_default(self):
        policy = migration_policy(["a"], {"a": ["href"]})
        self.assertEqual(sanitize('<a href="/docs">x</a>', policy), '<a href="/docs">x</a>')

    def test_protocol_relative_link_is_blocked_by_default(self):
        policy = migration_policy(["a"], {"a": ["href"]})
        self.assertEqual(sanitize('<a href="//example.invalid/x">x</a>', policy), "<a>x</a>")

    def test_protocols_option_maps_to_schemes(self):
        policy = migration_policy(["a"], {"a": ["href"]}).replace(schemes={"https"})
        self.assertEqual(
            sanitize('<a href="https://example.invalid/x">x</a>', policy),
            '<a href="https://example.invalid/x">x</a>',
        )
        self.assertEqual(sanitize('<a href="http://example.invalid/x">x</a>', policy), "<a>x</a>")

    def test_mailto_is_in_default_schemes(self):
        policy = migration_policy(["a"], {"a": ["href"]})
        self.assertEqual(
            sanitize('<a href="mailto:user@example.invalid">x</a>', policy),
            '<a href="mailto:user@example.invalid">x</a>',
        )

    def test_event_attribute_is_removed_even_when_starred(self):
        policy = migration_policy(["p"], {"p": ["*"]})
        self.assertEqual(sanitize('<p onclick="alert(1)">x</p>', policy), "<p>x</p>")

    def test_style_is_not_enabled_accidentally(self):
        policy = migration_policy(["p"], {"p": ["style"]})
        self.assertEqual(sanitize('<p style="color:red">x</p>', policy), "<p>x</p>")

    def test_explicit_css_allowlist_enables_safe_style(self):
        policy = migration_policy(["p"], {"p": ["style"]}).replace(
            allow_inline_styles=True,
            css_properties={"color"},
        )
        self.assertEqual(sanitize('<p style="color: red">x</p>', policy), '<p style="color: red">x</p>')

    def test_title_attribute_can_be_allowed(self):
        policy = migration_policy(["abbr"], {"abbr": ["title"]})
        self.assertEqual(
            sanitize('<abbr title="Hypertext">HTML</abbr>', policy),
            '<abbr title="Hypertext">HTML</abbr>',
        )

    def test_table_markup_can_be_allowed(self):
        tags = ["table", "tr", "td"]
        policy = migration_policy(tags, {"td": ["colspan"]})
        self.assertEqual(
            sanitize('<table><tr><td colspan="2">x</td></tr></table>', policy),
            '<table><tr><td colspan="2">x</td></tr></table>',
        )

    def test_empty_tag_set_strips_all_markup(self):
        policy = migration_policy([])
        self.assertEqual(sanitize("<p>a <b>b</b></p>", policy), "a b")

    def test_strip_html_matches_bleach_strip_intent(self):
        self.assertEqual(strip_html("<p>a <b>b</b></p>"), "a b")

    def test_target_blank_gets_noopener_by_default(self):
        policy = migration_policy(["a"], {"a": ["href", "target"]})
        self.assertEqual(
            sanitize('<a href="/x" target="_blank">x</a>', policy),
            '<a href="/x" rel="noopener noreferrer" target="_blank">x</a>',
        )

    def test_noopener_can_be_opted_out_for_legacy_parity(self):
        policy = migration_policy(["a"], {"a": ["href", "target"]}).replace(rel_noopener=False)
        self.assertEqual(
            sanitize('<a href="/x" target="_blank">x</a>', policy),
            '<a href="/x" target="_blank">x</a>',
        )

    def test_bleach_style_comment_is_not_emitted(self):
        policy = migration_policy(["p"])
        self.assertEqual(sanitize("<p>a</p><!-- comment -->", policy), "<p>a</p>")

    def test_second_pass_is_stable_for_migration_output(self):
        policy = migration_policy(["p", "a"], {"a": ["href", "target"]})
        once = sanitize('<p><a href="/x" target="_blank">x</a></p>', policy)
        self.assertEqual(sanitize(once, policy), once)

    def test_img_is_not_implicitly_allowed(self):
        policy = migration_policy(["p"])
        self.assertEqual(sanitize('<p>x</p><img src="/x.png">', policy), "<p>x</p>")

    def test_img_can_be_migrated_with_src_and_alt(self):
        policy = migration_policy(["img"], {"img": ["src", "alt"]})
        self.assertEqual(
            sanitize('<img src="/x.png" alt="x">', policy),
            '<img src="/x.png" alt="x">',
        )

    def test_srcset_is_validated_when_migrated(self):
        policy = migration_policy(["img"], {"img": ["srcset"]})
        self.assertEqual(sanitize('<img srcset="javascript:alert(1) 1x">', policy), "<img>")

    def test_dom_ids_are_not_implicitly_rewritten_without_prefix(self):
        policy = migration_policy(["div"], {"div": ["id"]})
        self.assertEqual(sanitize('<div id="note">x</div>', policy), '<div id="note">x</div>')

    def test_dom_ids_can_be_prefixed_during_migration(self):
        policy = migration_policy(["div"], {"div": ["id"]}).replace(clobber_prefix="user-")
        self.assertEqual(sanitize('<div id="note">x</div>', policy), '<div id="user-note">x</div>')

    def test_custom_element_names_are_supported(self):
        policy = migration_policy(["x-note"], {"x-note": ["data-*"]})
        self.assertEqual(
            sanitize('<x-note data-kind="a">x</x-note>', policy),
            '<x-note data-kind="a">x</x-note>',
        )
