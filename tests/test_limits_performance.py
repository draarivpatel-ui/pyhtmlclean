"""Resource limit, idempotency and linear performance tests."""

import time
import unittest

from pyhtmlclean import HtmlCleanError, Policy, TokenLimitError, sanitize
from pyhtmlclean.policy import POLICY_PROSE
from _support import assert_secure_and_idempotent

PERFORMANCE_POLICY = POLICY_PROSE.replace(max_tokens=1000000)

HOSTILE_IDEMPOTENCY_INPUTS = [
    "<div/><p>x</p>",
    "<p/>a",
    "<a href=javascript:alert(1)/>x",
    "<ul><li>one<li>two</ul>",
    "<table><tr><td>a<td>b</tr></table>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<p>&amp;lt;script&amp;gt;</p>",
    "<!--><p>x</p>",
    "<?xml?><p>x</p>",
    "<![CDATA[x]]><p>x</p>",
    "<script>x</script><p>safe</p>",
    "<svg><desc>x</desc></svg><p>safe</p>",
    "<p title='a&quot;b'>x</p>",
    "<a href='/x' target='_blank'>x</a>",
    "<div><span><b>deep</b></span></div>",
]


class IdempotencyTests(unittest.TestCase):
    pass


def _make_idempotency_test(source):
    def test(self):
        assert_secure_and_idempotent(self, source, "basic")
    return test


for _index, _source in enumerate(HOSTILE_IDEMPOTENCY_INPUTS, 1):
    setattr(
        IdempotencyTests,
        "test_idempotency_{0:03d}".format(_index),
        _make_idempotency_test(_source),
    )


class PerformanceTests(unittest.TestCase):
    def _best_milliseconds(self, source, rounds=2):
        best = None
        for _ in range(rounds):
            start = time.perf_counter()
            sanitize(source, PERFORMANCE_POLICY)
            elapsed = (time.perf_counter() - start) * 1000.0
            best = elapsed if best is None else min(best, elapsed)
        return best if best is not None else 0.0

    def test_repeated_raw_text_regions_scale_linearly(self):
        small = "<script>x</script>" * ((128 * 1024) // 18)
        large = "<script>x</script>" * ((500 * 1024) // 18)
        small_time = self._best_milliseconds(small)
        large_time = self._best_milliseconds(large)
        ratio = large_time / max(small_time, 1.0)
        self.assertLess(ratio, 15.0, "scaling ratio {0:.2f}".format(ratio))
        self.assertLess(large_time, 10000.0, "500KB took {0:.2f}ms".format(large_time))

    def test_500kb_unclosed_script_flood_completes_linearly(self):
        source = "<script>" * ((500 * 1024) // 8)
        elapsed = self._best_milliseconds(source, rounds=1)
        self.assertLess(elapsed, 5000.0)

    def test_100kb_angle_bracket_flood_completes_linearly(self):
        elapsed = self._best_milliseconds("<" * (100 * 1024), rounds=1)
        self.assertLess(elapsed, 5000.0)

    def test_100kb_entity_flood_completes_linearly(self):
        elapsed = self._best_milliseconds("&" * (100 * 1024), rounds=1)
        self.assertLess(elapsed, 5000.0)

    def test_large_attribute_flood_completes_linearly(self):
        source = "<p " + ("a=1 " * 20000) + ">x</p>"
        elapsed = self._best_milliseconds(source, rounds=1)
        self.assertLess(elapsed, 5000.0)

    def test_comment_flood_completes_linearly(self):
        elapsed = self._best_milliseconds("<!--x-->" * 10000, rounds=1)
        self.assertLess(elapsed, 5000.0)

    def test_end_tag_flood_completes_linearly(self):
        elapsed = self._best_milliseconds("</div>" * 10000, rounds=1)
        self.assertLess(elapsed, 5000.0)

    def test_default_token_limit_stops_extreme_token_flood(self):
        source = "<p>x</p>" * 40000
        with self.assertRaises(TokenLimitError):
            sanitize(source)

    def test_default_token_limit_error_is_typed(self):
        source = "<p>x</p>" * 40000
        try:
            sanitize(source)
        except HtmlCleanError as exc:
            self.assertEqual(exc.code, "TOKEN_LIMIT_EXCEEDED")
        else:
            self.fail("expected HtmlCleanError")

    def test_custom_high_token_limit_can_process_large_valid_markup(self):
        policy = Policy(["p"], {}, max_tokens=150000)
        source = "<p>x</p>" * 30000
        out = sanitize(source, policy)
        self.assertEqual(out, source)


class LimitRegressionTests(unittest.TestCase):
    def test_depth_check_counts_after_implied_close(self):
        policy = Policy(["ul", "li"], {}, max_depth=2)
        self.assertEqual(sanitize("<ul><li>a<li>b</ul>", policy), "<ul><li>a</li><li>b</li></ul>")

    def test_deeply_nested_input_raises_before_huge_output(self):
        policy = Policy(["div"], {}, max_depth=8)
        with self.assertRaises(HtmlCleanError) as caught:
            sanitize("<div>" * 20 + "x", policy)
        self.assertEqual(caught.exception.code, "MAX_DEPTH_EXCEEDED")

    def test_large_input_byte_limit_is_inclusive(self):
        policy = Policy([], {}, max_input_bytes=3)
        self.assertEqual(sanitize("abc", policy), "abc")

    def test_max_input_bytes_counts_nul_before_stripping(self):
        policy = Policy([], {}, max_input_bytes=2)
        with self.assertRaises(HtmlCleanError):
            sanitize("a\x00b", policy)
