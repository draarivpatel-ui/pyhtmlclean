"""Core sanitizer, tokenizer, serializer and inspector tests."""

import unittest

from pyhtmlclean import (
    DepthLimitError,
    HtmlCleanError,
    InputTooLargeError,
    InvalidPolicyError,
    POLICY_BASIC,
    POLICY_STRIP_ALL,
    Policy,
    Sanitizer,
    TokenLimitError,
    inspect_html,
    sanitize,
    strip_html,
    tokenize,
)


class PresetTests(unittest.TestCase):
    def test_prose_keeps_common_markup(self):
        self.assertEqual(
            sanitize("<p>Hello <strong>world</strong></p>", "prose"),
            "<p>Hello <strong>world</strong></p>",
        )

    def test_prose_drops_images(self):
        self.assertEqual(sanitize('<p>a</p><img src="/x.png">', "prose"), "<p>a</p>")

    def test_basic_keeps_safe_images(self):
        self.assertEqual(
            sanitize('<img src="/x.png" alt="x">', "basic"),
            '<img src="/x.png" alt="x">',
        )

    def test_strict_has_a_small_text_element_set(self):
        self.assertEqual(sanitize("<div><b>x</b></div>", "strict"), "<b>x</b>")

    def test_strip_all_removes_every_element(self):
        self.assertEqual(sanitize("<p>a <b>b</b></p>", "strip_all"), "a b")

    def test_strip_all_still_drops_script_content(self):
        self.assertEqual(sanitize("<script>alert(1)</script><p>safe</p>", "strip_all"), "safe")

    def test_unknown_preset_raises_invalid_policy(self):
        with self.assertRaises(InvalidPolicyError):
            sanitize("x", "missing")

    def test_invalid_policy_type_raises_invalid_policy(self):
        with self.assertRaises(InvalidPolicyError):
            sanitize("x", object())

    def test_none_policy_uses_prose(self):
        self.assertEqual(sanitize("<div>x</div>", None), "<div>x</div>")


class SerializerTests(unittest.TestCase):
    def test_text_is_entity_decoded_once_and_reescaped(self):
        self.assertEqual(sanitize("&lt;b&gt;x&lt;/b&gt;"), "&lt;b&gt;x&lt;/b&gt;")

    def test_double_encoded_text_stays_stable(self):
        self.assertEqual(sanitize("&amp;lt;b&amp;gt;"), "&amp;lt;b&amp;gt;")

    def test_attribute_quotes_are_escaped(self):
        self.assertEqual(
            sanitize('<p title="a&quot;b">x</p>'),
            '<p title="a&quot;b">x</p>',
        )

    def test_attribute_apostrophes_are_escaped(self):
        out = sanitize("<p title=\"a'b\">x</p>")
        self.assertIn("&#x27;", out)

    def test_nonvoid_self_closing_tag_is_balanced(self):
        self.assertEqual(sanitize("<div/><p>x</p>"), "<div><p>x</p></div>")

    def test_nonvoid_self_closing_paragraph_is_balanced(self):
        self.assertEqual(sanitize("<p/>a"), "<p>a</p>")

    def test_void_self_closing_tag_is_canonical(self):
        self.assertEqual(sanitize("<br/>x"), "<br>x")

    def test_unclosed_elements_are_closed_at_end(self):
        self.assertEqual(sanitize("<div><p>x"), "<div><p>x</p></div>")

    def test_end_tag_closes_intervening_elements(self):
        self.assertEqual(sanitize("<div><p>x</div>after"), "<div><p>x</p></div>after")

    def test_orphan_end_tag_is_ignored(self):
        self.assertEqual(sanitize("a</div>b"), "ab")

    def test_list_items_get_implied_closes(self):
        self.assertEqual(sanitize("<ul><li>one<li>two</ul>"), "<ul><li>one</li><li>two</li></ul>")

    def test_paragraph_closes_before_div(self):
        self.assertEqual(sanitize("<p>one<div>two</div>"), "<p>one</p><div>two</div>")

    def test_table_cells_get_implied_closes(self):
        self.assertEqual(
            sanitize("<table><tr><td>a<td>b</tr></table>"),
            "<table><tr><td>a</td><td>b</td></tr></table>",
        )

    def test_attribute_order_is_canonical(self):
        self.assertEqual(
            sanitize('<a target="_blank" title="t" href="/x">x</a>'),
            '<a href="/x" rel="noopener noreferrer" target="_blank" title="t">x</a>',
        )

    def test_duplicate_attributes_use_the_first_browser_visible_value(self):
        self.assertEqual(
            sanitize('<a href="https://example.invalid" href="javascript:alert(1)">x</a>'),
            '<a href="https://example.invalid">x</a>',
        )

    def test_duplicate_dangerous_first_attribute_does_not_fall_through(self):
        self.assertEqual(
            sanitize('<a href="javascript:alert(1)" href="https://example.invalid">x</a>'),
            "<a>x</a>",
        )

    def test_unquoted_slash_is_part_of_url_like_browsers_parse_it(self):
        self.assertEqual(sanitize("<a href=/x/>x</a>"), '<a href="/x/">x</a>')

    def test_spaced_slash_is_self_closing_syntax(self):
        self.assertEqual(sanitize("<br />x"), "<br>x")


class DropElementTests(unittest.TestCase):
    def test_script_content_is_dropped(self):
        self.assertEqual(sanitize("<script>alert(1)</script>safe"), "safe")

    def test_style_content_is_dropped(self):
        self.assertEqual(sanitize("<style>body{color:red}</style>safe"), "safe")

    def test_iframe_content_is_dropped(self):
        self.assertEqual(sanitize("<iframe>hidden</iframe>safe"), "safe")

    def test_object_content_is_dropped(self):
        self.assertEqual(sanitize("<object>hidden</object>safe"), "safe")

    def test_svg_content_is_dropped(self):
        self.assertEqual(sanitize("<svg><g>hidden</g></svg>safe"), "safe")

    def test_math_content_is_dropped(self):
        self.assertEqual(sanitize("<math><mi>x</mi></math>safe"), "safe")

    def test_template_content_is_dropped(self):
        self.assertEqual(sanitize("<template>hidden</template>safe"), "safe")

    def test_noscript_content_is_dropped(self):
        self.assertEqual(sanitize("<noscript>hidden</noscript>safe"), "safe")

    def test_textarea_content_is_dropped(self):
        self.assertEqual(sanitize("<textarea>hidden</textarea>safe"), "safe")

    def test_title_content_is_dropped(self):
        self.assertEqual(sanitize("<title>hidden</title>safe"), "safe")

    def test_xmp_content_is_dropped(self):
        self.assertEqual(sanitize("<xmp>hidden</xmp>safe"), "safe")

    def test_plaintext_consumes_the_rest(self):
        self.assertEqual(sanitize("<plaintext>hidden<p>x</p>"), "")

    def test_embed_with_explicit_end_drops_enclosed_content(self):
        self.assertEqual(sanitize("<embed>hidden</embed>safe"), "safe")

    def test_embed_without_explicit_end_does_not_drop_following_text(self):
        self.assertEqual(sanitize("<embed><p>safe</p>"), "<p>safe</p>")

    def test_self_closed_svg_does_not_drop_following_text(self):
        self.assertEqual(sanitize("<svg/>safe"), "safe")

    def test_self_closed_math_does_not_drop_following_text(self):
        self.assertEqual(sanitize("<math/>safe"), "safe")

    def test_custom_policy_cannot_allow_script(self):
        policy = Policy(["script", "p"], {"script": ["src"]})
        self.assertEqual(sanitize("<script>alert(1)</script><p>x</p>", policy), "<p>x</p>")

    def test_disallowed_normal_element_preserves_text(self):
        self.assertEqual(sanitize("<unknown>a<b>b</b></unknown>", "strict"), "a<b>b</b>")


class TokenAndNoiseTests(unittest.TestCase):
    def test_comment_is_removed(self):
        self.assertEqual(sanitize("a<!-- secret -->b"), "ab")

    def test_abrupt_comment_close_does_not_swallow_markup(self):
        self.assertEqual(sanitize("<!--><p>x</p>"), "<p>x</p>")

    def test_comment_bang_close_is_removed(self):
        self.assertEqual(sanitize("<!-- x --!><p>x</p>"), "<p>x</p>")

    def test_unclosed_comment_is_removed(self):
        self.assertEqual(sanitize("a<!-- x"), "a")

    def test_processing_instruction_is_removed(self):
        self.assertEqual(sanitize("<?xml version='1.0'?><p>x</p>"), "<p>x</p>")

    def test_processing_instruction_stops_at_first_angle_close(self):
        self.assertEqual(sanitize("<?<img src=x>?> <p>y</p>"), "?&gt; <p>y</p>")

    def test_cdata_is_removed(self):
        self.assertEqual(sanitize("<![CDATA[<p>x</p>]]>after"), "after")

    def test_unclosed_cdata_is_removed(self):
        self.assertEqual(sanitize("a<![CDATA[x"), "a")

    def test_doctype_is_removed(self):
        self.assertEqual(sanitize("<!DOCTYPE html><p>x</p>"), "<p>x</p>")

    def test_doctype_with_internal_subset_is_removed(self):
        self.assertEqual(sanitize("<!DOCTYPE html [ <!ENTITY x 'y'> ]><p>x</p>"), "<p>x</p>")

    def test_doctype_subset_quoted_bracket_is_removed(self):
        source = "<!DOCTYPE html [ <!ENTITY x ']>'> ]><p>x</p>"
        self.assertEqual(sanitize(source), "<p>x</p>")

    def test_bogus_comment_is_removed(self):
        self.assertEqual(sanitize("<!bogus><p>x</p>"), "<p>x</p>")

    def test_nul_bytes_are_stripped(self):
        self.assertEqual(sanitize("a\x00b<p>\x00x</p>"), "ab<p>x</p>")

    def test_rawtext_close_with_slash_variant_is_recognized(self):
        self.assertEqual(sanitize("<script>x</script/foo><p>safe</p>"), "<p>safe</p>")

    def test_rawtext_close_with_space_variant_is_recognized(self):
        self.assertEqual(sanitize("<style>x</style ><p>safe</p>"), "<p>safe</p>")

    def test_malformed_unclosed_start_tag_is_inert_text(self):
        self.assertEqual(sanitize("a<div"), "a&lt;div")

    def test_lone_angle_open_is_escaped(self):
        self.assertEqual(sanitize("a < b"), "a &lt; b")


class StripAndInspectTests(unittest.TestCase):
    def test_strip_html_returns_plain_text(self):
        self.assertEqual(strip_html("<p>A &amp; B</p>"), "A & B")

    def test_strip_html_removes_script_text(self):
        self.assertEqual(strip_html("<script>alert(1)</script>Safe"), "Safe")

    def test_strip_html_removes_foreign_text(self):
        self.assertEqual(strip_html("<svg>hidden</svg>visible"), "visible")

    def test_strip_html_result_is_not_html_safe_by_contract(self):
        self.assertEqual(strip_html("&lt;script&gt;x&lt;/script&gt;"), "<script>x</script>")

    def test_strip_all_policy_text_matches_strip_html(self):
        source = "<p>A &amp; B</p><script>x</script>"
        self.assertEqual(strip_html(source), sanitize(source, POLICY_STRIP_ALL).replace("&amp;", "&"))

    def test_inspect_reports_counts(self):
        report = inspect_html("<p onclick='x'>a</p><!--c--><script>x</script>")
        self.assertEqual(report["output"], "<p>a</p>")
        self.assertEqual(report["elements_allowed"], {"p": 1})
        self.assertEqual(report["attributes_dropped"], {"onclick": 1})
        self.assertEqual(report["elements_dropped"], {"script": 1})
        self.assertEqual(report["comments_removed"], 1)
        self.assertGreater(report["tokens"], 0)

    def test_inspect_reports_noise_counts(self):
        report = inspect_html("<?x?><!DOCTYPE html><![CDATA[x]]>a\x00b")
        self.assertEqual(report["processing_instructions_removed"], 1)
        self.assertEqual(report["doctypes_removed"], 1)
        self.assertEqual(report["cdata_removed"], 1)
        self.assertEqual(report["nul_bytes_removed"], 1)

    def test_inspect_reports_blocked_urls(self):
        report = inspect_html("<a href='javascript:alert(1)'>x</a>")
        self.assertEqual(report["urls_blocked"], {"href": 1})

    def test_inspect_output_is_json_serializable_shape(self):
        report = inspect_html("<p>x</p>")
        for key in ("input_length", "output_length", "output", "tokens"):
            self.assertIn(key, report)


class LimitAndPolicyTests(unittest.TestCase):
    def test_input_type_must_be_string(self):
        with self.assertRaises(HtmlCleanError):
            sanitize(None)

    def test_max_input_bytes_is_enforced(self):
        policy = Policy(["p"], {}, max_input_bytes=4)
        with self.assertRaises(InputTooLargeError):
            sanitize("<p>abcde</p>", policy)

    def test_max_input_bytes_counts_utf8_bytes(self):
        policy = Policy(["p"], {}, max_input_bytes=5)
        with self.assertRaises(InputTooLargeError):
            sanitize("ééé", policy)

    def test_max_tokens_is_enforced_with_typed_error(self):
        policy = Policy(["p"], {}, max_tokens=2)
        with self.assertRaises(TokenLimitError):
            sanitize("<p>a</p><p>b</p>", policy)

    def test_token_limit_is_htmlclean_error_subclass(self):
        policy = Policy(["p"], {}, max_tokens=2)
        with self.assertRaises(HtmlCleanError):
            sanitize("<p>a</p><p>b</p>", policy)

    def test_max_depth_is_enforced(self):
        policy = Policy(["div"], {}, max_depth=1)
        with self.assertRaises(DepthLimitError):
            sanitize("<div><div>x</div></div>", policy)

    def test_zero_depth_policy_is_invalid(self):
        with self.assertRaises(InvalidPolicyError):
            Policy(["p"], {}, max_depth=0)

    def test_invalid_max_tokens_policy_is_rejected(self):
        with self.assertRaises(InvalidPolicyError):
            Policy(["p"], {}, max_tokens=0)

    def test_custom_policy_allows_custom_element(self):
        policy = Policy(["x-card"], {"x-card": ["title"]})
        self.assertEqual(
            sanitize('<x-card title="hello">x</x-card>', policy),
            '<x-card title="hello">x</x-card>',
        )

    def test_global_attribute_allowlist(self):
        policy = Policy(["p"], {"*": ["title"]})
        self.assertEqual(sanitize('<p title="t">x</p>', policy), '<p title="t">x</p>')

    def test_attribute_prefix_wildcard(self):
        policy = Policy(["p"], {"p": ["data-*"]})
        self.assertEqual(
            sanitize('<p data-id="1" data-x="2" onclick="x">x</p>', policy),
            '<p data-id="1" data-x="2">x</p>',
        )

    def test_event_handlers_are_never_allowed_by_star(self):
        policy = Policy(["p"], {"p": ["*"]})
        self.assertEqual(sanitize('<p onclick="x">x</p>', policy), "<p>x</p>")

    def test_hard_deny_attributes_are_never_allowed(self):
        policy = Policy(["p"], {"p": ["*"]})
        for attr in ("srcdoc", "formaction", "xlink:href", "is"):
            with self.subTest(attr=attr):
                self.assertEqual(sanitize('<p {0}="x">x</p>'.format(attr), policy), "<p>x</p>")

    def test_clobber_prefix_is_applied_once(self):
        policy = Policy(["div"], {"div": ["id", "name"]}, clobber_prefix="uc-")
        out = sanitize('<div id="location" name="window">x</div>', policy)
        self.assertEqual(out, '<div id="uc-location" name="uc-window">x</div>')
        self.assertEqual(sanitize(out, policy), out)

    def test_identifier_with_whitespace_is_removed(self):
        policy = Policy(["div"], {"div": ["id"]}, clobber_prefix="uc-")
        self.assertEqual(sanitize('<div id="a b">x</div>', policy), "<div>x</div>")

    def test_invalid_clobber_prefix_is_rejected(self):
        with self.assertRaises(InvalidPolicyError):
            Policy(["div"], {}, clobber_prefix="bad prefix")

    def test_unsafe_element_name_in_policy_is_rejected(self):
        with self.assertRaises(InvalidPolicyError):
            Policy(['div onclick="x"'], {})

    def test_unsafe_attribute_name_in_policy_is_rejected(self):
        with self.assertRaises(InvalidPolicyError):
            Policy(["p"], {"p": ['title onclick="x"']})

    def test_unsafe_attribute_map_key_in_policy_is_rejected(self):
        with self.assertRaises(InvalidPolicyError):
            Policy(["p"], {'p onclick="x"': ["title"]})

    def test_invalid_scheme_name_in_policy_is_rejected(self):
        with self.assertRaises(InvalidPolicyError):
            Policy(["a"], {}, schemes=["java script"])

    def test_colspan_bounds(self):
        self.assertEqual(
            sanitize('<table><tr><td colspan="2">x</td></tr></table>'),
            '<table><tr><td colspan="2">x</td></tr></table>',
        )
        self.assertEqual(
            sanitize('<table><tr><td colspan="99999">x</td></tr></table>'),
            "<table><tr><td>x</td></tr></table>",
        )

    def test_image_dimension_and_loading_attributes(self):
        self.assertEqual(
            sanitize('<img src="/x" width="100" height="50" loading="lazy" decoding="async">', "basic"),
            '<img src="/x" decoding="async" height="50" loading="lazy" width="100">',
        )

    def test_invalid_image_dimension_is_removed(self):
        self.assertEqual(sanitize('<img src="/x" width="-1">', "basic"), '<img src="/x">')

    def test_long_image_dimension_digit_flood_is_removed(self):
        digits = "9" * 10000
        source = '<img src="/x" width="' + digits + '">'
        self.assertEqual(sanitize(source, "basic"), '<img src="/x">')

    def test_sanitizer_reuses_policy(self):
        cleaner = Sanitizer("strict")
        self.assertEqual(cleaner.sanitize("<div><b>x</b></div>"), "<b>x</b>")
        self.assertEqual(cleaner.sanitize("<p>x</p>"), "<p>x</p>")

    def test_sanitizer_strip_uses_empty_elements(self):
        cleaner = Sanitizer("basic")
        self.assertEqual(cleaner.strip("<p>A &amp; B</p>"), "A & B")

    def test_tokenizer_is_streaming_and_counts_tokens(self):
        cursor = tokenize("<p>x</p>")
        kinds = [token.type for token in cursor]
        self.assertEqual(kinds, ["start", "text", "end"])
        self.assertEqual(cursor.count, 3)
