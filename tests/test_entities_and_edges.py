"""Entity decoding and malformed markup edge tests."""

import unittest

from pyhtmlclean import Policy, sanitize, tokenize
from pyhtmlclean.entities import decode_entities_deep


class EntityEdgeTests(unittest.TestCase):
    def test_legacy_lt_without_semicolon_decodes(self):
        self.assertEqual(sanitize("<p>&lt</p>"), "<p>&lt;</p>")

    def test_standard_lt_decodes(self):
        self.assertEqual(sanitize("<p>&lt;</p>"), "<p>&lt;</p>")

    def test_nested_amp_lt_is_stable(self):
        self.assertEqual(sanitize("<p>&amp;lt</p>"), "<p>&amp;lt</p>")

    def test_named_entity_decodes_in_text(self):
        self.assertEqual(sanitize("<p>&copy;</p>"), "<p>©</p>")

    def test_named_entity_without_semicolon_uses_html5_legacy_rules(self):
        self.assertEqual(sanitize("<p>&notin</p>"), "<p>¬in</p>")

    def test_hex_reference_with_semicolon_decodes(self):
        self.assertEqual(sanitize("<p>&#x6a;avascript</p>"), "<p>javascript</p>")

    def test_hex_reference_without_semicolon_uses_maximal_digits(self):
        self.assertEqual(sanitize("<p>&#x6avascript</p>"), "<p>jvascript</p>")

    def test_decimal_reference_without_semicolon_uses_maximal_digits(self):
        self.assertEqual(sanitize("<p>&#106javascript</p>"), "<p>jjavascript</p>")

    def test_invalid_large_numeric_reference_becomes_replacement(self):
        self.assertEqual(sanitize("<p>&#x110000;</p>"), "<p>\ufffd</p>")

    def test_invalid_huge_numeric_reference_becomes_replacement(self):
        self.assertEqual(sanitize("<p>&#99999999999999999999;</p>"), "<p>\ufffd</p>")

    def test_numeric_reference_digit_flood_is_bounded(self):
        digits = "9" * 10000
        self.assertEqual(sanitize("<p>&#" + digits + ";</p>"), "<p>\ufffd</p>")
        self.assertEqual(sanitize("<p>&#x" + digits + ";</p>"), "<p>\ufffd</p>")
        self.assertEqual(decode_entities_deep("&#" + digits + ";"), "\ufffd")

    def test_numeric_reference_long_leading_zeros_still_decode(self):
        digits = "0" * 10000 + "106"
        self.assertEqual(sanitize("<p>&#" + digits + ";</p>"), "<p>j</p>")

    def test_surrogate_numeric_reference_becomes_replacement(self):
        self.assertEqual(sanitize("<p>&#xD800;</p>"), "<p>\ufffd</p>")

    def test_zero_numeric_reference_becomes_replacement(self):
        self.assertEqual(sanitize("<p>&#0;</p>"), "<p>\ufffd</p>")

    def test_unknown_named_entity_is_literal_text(self):
        self.assertEqual(sanitize("<p>&madeup;</p>"), "<p>&amp;madeup;</p>")

    def test_raw_surrogate_input_is_replaced_not_crashing(self):
        self.assertEqual(sanitize("<p>a\ud800b</p>"), "<p>a\ufffdb</p>")

    def test_entities_decode_in_attribute_values(self):
        self.assertEqual(sanitize('<p title="a &amp; b">x</p>'), '<p title="a &amp; b">x</p>')

    def test_invalid_entity_in_attribute_is_escaped_literally(self):
        self.assertEqual(sanitize('<p title="&madeup;">x</p>'), '<p title="&amp;madeup;">x</p>')


class AttributeParserEdgeTests(unittest.TestCase):
    def test_spaces_around_equals_are_accepted(self):
        self.assertEqual(sanitize('<p title = "x">x</p>'), '<p title="x">x</p>')

    def test_unquoted_attribute_is_accepted(self):
        self.assertEqual(sanitize("<p title=x>x</p>"), '<p title="x">x</p>')

    def test_single_quoted_attribute_is_canonicalized(self):
        self.assertEqual(sanitize("<p title='x'>x</p>"), '<p title="x">x</p>')

    def test_unquoted_slash_before_close_is_part_of_value(self):
        self.assertEqual(sanitize("<p title=x/>x</p>"), '<p title="x/">x</p>')

    def test_spaced_slash_before_close_is_self_closing_syntax(self):
        self.assertEqual(sanitize("<p title=x />x</p>"), '<p title="x">x</p>')

    def test_newlines_and_tabs_inside_quoted_attribute_are_preserved(self):
        self.assertEqual(sanitize('<p title="a\nb\tc">x</p>'), '<p title="a\nb\tc">x</p>')

    def test_unclosed_quoted_attribute_is_inert_text(self):
        self.assertEqual(
            sanitize('<p title="unclosed>x</p>'),
            '&lt;p title="unclosed&gt;x&lt;/p&gt;',
        )

    def test_duplicate_allowed_attributes_keep_first_value(self):
        self.assertEqual(
            sanitize('<p title="first" title="second">x</p>'),
            '<p title="first">x</p>',
        )

    def test_duplicate_attribute_case_is_browser_like(self):
        self.assertEqual(
            sanitize('<p TITLE="first" title="second">x</p>'),
            '<p title="first">x</p>',
        )

    def test_empty_attribute_is_canonicalized(self):
        self.assertEqual(sanitize("<p title>x</p>"), '<p title="">x</p>')

    def test_escaped_quote_in_attribute_does_not_break_out(self):
        self.assertEqual(
            sanitize('<p title="a&quot;b onclick=alert(1)">x</p>'),
            '<p title="a&quot;b onclick=alert(1)">x</p>',
        )

    def test_raw_quote_breaks_attribute_and_strips_event_text_markup(self):
        out = sanitize('<p title="a"b" onclick="alert(1)">x</p>')
        self.assertNotIn("onclick", out)

    def test_custom_attribute_can_be_allowed(self):
        policy = Policy(["p"], {"p": ["a"]})
        self.assertEqual(sanitize('<p a="1">x</p>', policy), '<p a="1">x</p>')

    def test_disallowed_custom_attribute_is_removed(self):
        self.assertEqual(sanitize('<p a="1">x</p>'), "<p>x</p>")

    def test_attributes_are_sorted_deterministically(self):
        policy = Policy(["p"], {"p": ["z", "a", "m"]})
        self.assertEqual(sanitize('<p z="1" a="2" m="3">x</p>', policy), '<p a="2" m="3" z="1">x</p>')


class TokenizerEdgeTests(unittest.TestCase):
    def test_tokenizes_start_text_end(self):
        kinds = [token.type for token in tokenize("<p>x</p>")]
        self.assertEqual(kinds, ["start", "text", "end"])

    def test_tokenizes_rawtext_as_one_region(self):
        tokens = list(tokenize("<script>a<b>c</script>"))
        self.assertEqual([token.type for token in tokens], ["start", "rawtext", "end"])
        self.assertEqual(tokens[1].data, "a<b>c")

    def test_rawtext_end_is_case_insensitive(self):
        tokens = list(tokenize("<SCRIPT>x</SCRIPT>"))
        self.assertEqual([token.type for token in tokens], ["start", "rawtext", "end"])

    def test_rawtext_end_requires_delimiter(self):
        tokens = list(tokenize("<script>x</scriptx>y"))
        self.assertEqual(tokens[-1].type, "rawtext")
        self.assertIn("</scriptx>y", tokens[-1].data)

    def test_comment_token_is_emitted(self):
        tokens = list(tokenize("<!--x-->"))
        self.assertEqual(tokens[0].type, "comment")

    def test_pi_token_is_emitted(self):
        tokens = list(tokenize("<?xml?>"))
        self.assertEqual(tokens[0].type, "pi")

    def test_cdata_token_is_emitted(self):
        tokens = list(tokenize("<![CDATA[x]]>"))
        self.assertEqual(tokens[0].type, "cdata")

    def test_doctype_token_is_emitted(self):
        tokens = list(tokenize("<!DOCTYPE html>"))
        self.assertEqual(tokens[0].type, "doctype")

    def test_bogus_comment_token_is_emitted(self):
        tokens = list(tokenize("<!x>"))
        self.assertEqual(tokens[0].type, "bogus_comment")

    def test_unclosed_start_tag_is_text_token(self):
        tokens = list(tokenize("a<div"))
        self.assertEqual(tokens[-1].type, "text")
        self.assertEqual(tokens[-1].data, "<div")

    def test_end_tag_attributes_are_consumed(self):
        tokens = list(tokenize("</p onclick=x><p>x</p>"))
        self.assertEqual(tokens[0].type, "end")
        self.assertEqual(tokens[0].name, "p")

    def test_tag_names_are_ascii_lowercased(self):
        tokens = list(tokenize("<P>x</P>"))
        self.assertEqual(tokens[0].name, "p")

    def test_attribute_names_are_ascii_lowercased(self):
        tokens = list(tokenize("<p TITLE='x'>"))
        self.assertEqual(tokens[0].attributes[0][0], "title")

    def test_missing_end_of_rawtext_is_one_text_region(self):
        tokens = list(tokenize("<script>abc"))
        self.assertEqual([token.type for token in tokens], ["start", "rawtext"])
        self.assertEqual(tokens[1].data, "abc")
