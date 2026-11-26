# Good first issues

Fifteen modular starter tasks for new contributors. Each is scoped to one file or one focused behavior.

1. **Expand tokenizer delimiter tests in `tests/test_core.py`** for form feed, carriage return and tab placements in start tags.
2. **Add a typed `AuditReport` dataclass** beside `inspect_html` while keeping the dictionary API unchanged.
3. **Document every preset element** in the README with one short use case per element.
4. **Add a benchmark script** under `scripts/` using only stdlib `timeit` for repeated script-region input.
5. **Add mutation tests for list implied closes** covering nested formatting inside `li` elements.
6. **Add table structure tests** for `thead`, `tbody`, `tfoot`, missing `tr` closes and stray end tags.
7. **Add a `pyhtmlclean.__main__` command** that reads stdin, sanitizes with a named preset and writes stdout.
8. **Add tests for non-ASCII element and attribute names** to prove they never bypass the allowlist.
9. **Expand CSS tests for quoted semicolons** and parentheses inside safe declaration values.
10. **Add a policy serialization helper** that converts a `Policy` into plain JSON-compatible data.
11. **Write `docs/threat-model.md`** describing attacker capabilities, protected contexts and non-goals.
12. **Add fuzz seed corpus files** under `tests/corpus/` and a loader that checks idempotency without network access.
13. **Improve inspect counters** by separating hard-denied attributes from attributes missing from the allowlist.
14. **Add migration examples for Django templates and Flask view functions** to the README migration section.
15. **Expand `SECURITY.md`** with a coordinated disclosure timeline and accepted proof-of-concept formats.

All tasks must keep the zero dependency rule and the Python 3.9 syntax floor. Add tests with every change.
