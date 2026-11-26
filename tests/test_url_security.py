"""URL scheme, obfuscation and srcset hardening tests."""

import unittest

from pyhtmlclean import POLICY_BASIC, Policy, Sanitizer, sanitize, sanitize_srcset, sanitize_url

DANGEROUS_URLS = [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "vbscript:msgbox(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:image/svg+xml;base64,PHN2Zz4=",
    "blob:https://example.invalid/uuid",
    "file:///etc/passwd",
    "ftp://example.invalid/x",
    "jav&#x61;script:alert(1)",
    "java&#115;cript:alert(1)",
    "&#106;avascript:alert(1)",
    "&#0000106;avascript:alert(1)",
    "&#x6a;avascript:alert(1)",
    "javascript&colon;alert(1)",
    "javascript&#58;alert(1)",
    "javascript&#x3a;alert(1)",
    "java&Tab;script:alert(1)",
    "&Tab;javascript:alert(1)",
    "java&NewLine;script:alert(1)",
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "java\rscript:alert(1)",
    "java\x00script:alert(1)",
    "\x01javascript:alert(1)",
    "jav&#x09;ascript:alert(1)",
    "java&#x0A;script:alert(1)",
    "java&#13;script:alert(1)",
    "&#x6a;ava&#x09;script:alert(1)",
    " javascript:alert(1)",
    "\tjavascript:alert(1)",
    "\njavascript:alert(1)",
    "java\u2028script:alert(1)",
    "jav&#x09;ascript&colon;alert(1)",
    "&#x09;java&#x0a;script:alert(1)",
    "&#106&#97&#118&#97script:alert(1)",
    "&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3aalert(1)",
    "&amp;#106;avascript:alert(1)",
    "javascript\\:alert(1)",
    "/\\evil.invalid",
    "C:\\Windows\\x",
    "//evil.invalid/x",
]

SAFE_URLS = [
    "https://example.invalid/x",
    "http://example.invalid/x",
    "mailto:user@example.invalid",
    "tel:+15551234567",
    "/path",
    "./path",
    "../path",
    "#section",
    "path/page.html",
    "?q=1",
    "",
    "#",
]


class DangerousURLTests(unittest.TestCase):
    pass


def _make_dangerous_url_test(url):
    def test(self):
        source = '<a href="{0}">x</a>'.format(url)
        self.assertEqual(sanitize(source, "strict"), "<a>x</a>", url)
        self.assertEqual(sanitize(sanitize(source, "strict"), "strict"), "<a>x</a>")
    return test


for _index, _url in enumerate(DANGEROUS_URLS, 1):
    setattr(
        DangerousURLTests,
        "test_dangerous_url_{0:03d}".format(_index),
        _make_dangerous_url_test(_url),
    )


class SafeURLTests(unittest.TestCase):
    pass


def _make_safe_url_test(url):
    def test(self):
        source = '<a href="{0}">x</a>'.format(url)
        expected = '<a href="{0}">x</a>'.format(url)
        self.assertEqual(sanitize(source, "strict"), expected, url)
    return test


for _index, _url in enumerate(SAFE_URLS, 1):
    setattr(
        SafeURLTests,
        "test_safe_url_{0:03d}".format(_index),
        _make_safe_url_test(_url),
    )


class URLPolicyTests(unittest.TestCase):
    def test_custom_schemes_cannot_allowlist_blocked_schemes(self):
        for scheme in ("javascript", "vbscript", "data", "file", "blob"):
            with self.subTest(scheme=scheme):
                policy = Policy(["a"], {"a": ["href"]}, schemes=[scheme])
                self.assertEqual(sanitize('<a href="{0}:x">x</a>'.format(scheme), policy), "<a>x</a>")

    def test_allowed_schemes_can_be_changed(self):
        policy = Policy(["a"], {"a": ["href"]}, schemes=["https", "ftp"])
        self.assertEqual(
            sanitize('<a href="ftp://example.invalid/x">x</a>', policy),
            '<a href="ftp://example.invalid/x">x</a>',
        )
        self.assertEqual(sanitize('<a href="http://example.invalid/x">x</a>', policy), "<a>x</a>")

    def test_protocol_relative_opt_in(self):
        policy = Policy(["a"], {"a": ["href"]}, allow_protocol_relative=True)
        self.assertEqual(
            sanitize('<a href="//example.invalid/x">x</a>', policy),
            '<a href="https://example.invalid/x">x</a>',
        )

    def test_protocol_relative_blocked_by_default(self):
        self.assertEqual(sanitize('<a href="//example.invalid/x">x</a>', "strict"), "<a>x</a>")

    def test_relative_urls_can_be_disabled(self):
        policy = Policy(["a"], {"a": ["href"]}, allow_relative_urls=False)
        self.assertEqual(sanitize('<a href="/x">x</a>', policy), "<a>x</a>")
        self.assertEqual(
            sanitize('<a href="https://example.invalid/x">x</a>', policy),
            '<a href="https://example.invalid/x">x</a>',
        )

    def test_empty_and_fragment_urls_survive_relative_opt_out(self):
        policy = Policy(["a"], {"a": ["href"]}, allow_relative_urls=False)
        self.assertEqual(sanitize('<a href="">x</a>', policy), '<a href="">x</a>')
        self.assertEqual(sanitize('<a href="#">x</a>', policy), '<a href="#">x</a>')

    def test_colon_after_path_is_relative(self):
        self.assertEqual(
            sanitize('<a href="/path/javascript:alert(1)">x</a>', "strict"),
            '<a href="/path/javascript:alert(1)">x</a>',
        )

    def test_invalid_scheme_like_prefix_is_blocked(self):
        self.assertIsNone(sanitize_url("1javascript:alert(1)", POLICY_BASIC))

    def test_nested_entity_decoding_is_conservative(self):
        self.assertIsNone(sanitize_url("&amp;#106;avascript:alert(1)", POLICY_BASIC))

    def test_unicode_whitespace_inside_scheme_is_removed(self):
        self.assertIsNone(sanitize_url("java\u2028script:alert(1)", POLICY_BASIC))

    def test_url_attributes_cover_required_names(self):
        attrs = ["href", "src", "action", "poster", "cite", "background"]
        policy = Policy(["x"], {"x": attrs})
        for attr in attrs:
            with self.subTest(attr=attr):
                bad = '<x {0}="javascript:alert(1)">x</x>'.format(attr)
                good = '<x {0}="https://example.invalid/x">x</x>'.format(attr)
                self.assertEqual(sanitize(bad, policy), "<x>x</x>")
                self.assertEqual(
                    sanitize(good, policy),
                    '<x {0}="https://example.invalid/x">x</x>'.format(attr),
                )

    def test_target_values_are_limited(self):
        self.assertEqual(
            sanitize('<a href="/x" target="_blank">x</a>', "strict"),
            '<a href="/x" rel="noopener noreferrer" target="_blank">x</a>',
        )
        self.assertEqual(sanitize('<a href="/x" target="evil">x</a>', "strict"), '<a href="/x">x</a>')

    def test_rel_noopener_merges_existing_tokens(self):
        self.assertEqual(
            sanitize('<a href="/x" target="_blank" rel="ugc">x</a>', "strict"),
            '<a href="/x" rel="ugc noopener noreferrer" target="_blank">x</a>',
        )

    def test_rel_noopener_can_be_disabled_explicitly(self):
        policy = Policy(["a"], {"a": ["href", "target"]}, rel_noopener=False)
        self.assertEqual(
            sanitize('<a href="/x" target="_blank">x</a>', policy),
            '<a href="/x" target="_blank">x</a>',
        )

    def test_rel_stylesheet_and_import_are_removed(self):
        self.assertEqual(
            sanitize('<a href="/x" rel="stylesheet">x</a>', "strict"),
            '<a href="/x">x</a>',
        )
        self.assertEqual(
            sanitize('<a href="/x" rel="import">x</a>', "strict"),
            '<a href="/x">x</a>',
        )

    def test_rel_opener_is_removed_when_blank_target_is_forced(self):
        self.assertEqual(
            sanitize('<a href="/x" target="_blank" rel="opener ugc">x</a>', "strict"),
            '<a href="/x" rel="ugc noopener noreferrer" target="_blank">x</a>',
        )

    def test_srcset_zero_width_is_rejected(self):
        self.assertIsNone(sanitize_srcset("/x.png 0w", POLICY_BASIC))

    def test_srcset_long_width_digits_do_not_use_bignum_conversion(self):
        digits = "9" * 10000
        value = "/x.png " + digits + "w"
        self.assertEqual(sanitize_srcset(value, POLICY_BASIC), value)


class SrcsetTests(unittest.TestCase):
    def test_safe_density_srcset_is_preserved(self):
        self.assertEqual(
            sanitize(
                '<img src="/a.png" srcset="/a.png 1x, /a@2x.png 2x">',
                "basic",
            ),
            '<img src="/a.png" srcset="/a.png 1x, /a@2x.png 2x">',
        )

    def test_safe_width_srcset_is_preserved(self):
        self.assertEqual(
            sanitize('<img srcset="/small.png 480w, /large.png 1024w">', "basic"),
            '<img srcset="/small.png 480w, /large.png 1024w">',
        )

    def test_javascript_srcset_candidate_drops_whole_attribute(self):
        self.assertEqual(
            sanitize('<img srcset="/ok.png 1x, javascript:alert(1) 2x">', "basic"),
            "<img>",
        )

    def test_data_srcset_candidate_drops_whole_attribute(self):
        self.assertEqual(
            sanitize('<img srcset="data:image/svg+xml;base64,AAAA 1x">', "basic"),
            "<img>",
        )

    def test_entity_obfuscated_srcset_is_blocked(self):
        self.assertEqual(
            sanitize('<img srcset="&#106;avascript:alert(1) 1x">', "basic"),
            "<img>",
        )

    def test_unknown_srcset_descriptor_is_rejected(self):
        self.assertIsNone(sanitize_srcset("/x.png 1q", POLICY_BASIC))

    def test_duplicate_srcset_descriptors_are_rejected(self):
        self.assertIsNone(sanitize_srcset("/x.png 1x 2x", POLICY_BASIC))

    def test_mixed_width_and_density_are_rejected(self):
        self.assertIsNone(sanitize_srcset("/x.png 100w 2x", POLICY_BASIC))

    def test_empty_srcset_is_rejected(self):
        self.assertIsNone(sanitize_srcset("", POLICY_BASIC))

    def test_srcset_without_descriptor_is_valid(self):
        self.assertEqual(sanitize_srcset("/x.png", POLICY_BASIC), "/x.png")

    def test_srcset_decimal_density_is_valid(self):
        self.assertEqual(sanitize_srcset("/x.png 1.5x", POLICY_BASIC), "/x.png 1.5x")

    def test_srcset_height_descriptor_requires_width(self):
        self.assertIsNone(sanitize_srcset("/x.png 100h", POLICY_BASIC))
        self.assertEqual(sanitize_srcset("/x.png 100w 100h", POLICY_BASIC), "/x.png 100w 100h")

    def test_srcset_commas_inside_urls_are_preserved(self):
        value = "https://cdn.example.invalid/w_400,h_300,c_fill/sample.jpg 400w"
        self.assertEqual(sanitize_srcset(value, POLICY_BASIC), value)

    def test_srcset_comma_url_without_descriptor_is_not_split(self):
        self.assertEqual(sanitize_srcset("/comma,inside.png", POLICY_BASIC), "/comma,inside.png")

    def test_srcset_dangerous_candidate_after_comma_url_drops_attribute(self):
        value = "/safe,optimized.png 1x, javascript:alert(1) 2x"
        self.assertIsNone(sanitize_srcset(value, POLICY_BASIC))

    def test_srcset_zero_density_is_rejected(self):
        self.assertIsNone(sanitize_srcset("/x.png 0x", POLICY_BASIC))

    def test_srcset_protocol_relative_respects_policy(self):
        self.assertIsNone(sanitize_srcset("//example.invalid/x.png 1x", POLICY_BASIC))
        policy = POLICY_BASIC.replace(allow_protocol_relative=True)
        self.assertEqual(
            sanitize_srcset("//example.invalid/x.png 1x", policy),
            "https://example.invalid/x.png 1x",
        )
