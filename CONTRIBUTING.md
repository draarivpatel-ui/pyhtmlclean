# Contributing

Thanks for helping improve pyhtmlclean. Security-correctness changes are
welcome, and the bar is high: every behavior change needs a regression test.

## Setup

Python 3.9 or newer is required. There are no runtime or development
dependencies. Run the test suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Rules for contributions

- Keep the library pure Python and standard library only.
- Preserve the Python 3.9 syntax floor.
- Never implement HTML handling with regex-only stripping. The tokenizer is an explicit character-stream state machine.
- Treat output escaping and idempotency as security properties.
- Add adversarial tests for every parser, URL, CSS or policy change.
- Keep tests offline and deterministic. Timing tests must use generous thresholds.
- Do not commit `__pycache__`, build output, virtual environments or editor files.

## Security changes

Do not open a public pull request with a novel exploit. Follow `SECURITY.md`
first. After maintainers agree on a fix, include a regression test that is
safe to publish.

## Style

Use compact, typed, stdlib-only Python. Prefer exact behavior and small state
machines over broad permissive parsing. Public API changes need README updates
in the same pull request.
