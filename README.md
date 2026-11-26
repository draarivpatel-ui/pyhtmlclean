# pyhtmlclean

Zero-dependency, allowlist-only HTML and XSS sanitization for Python 3.9 and newer.

`pyhtmlclean` is a maintained pure-stdlib replacement for the common use cases of the deprecated Mozilla `bleach` package. It uses an explicit character-stream tokenizer and a canonical serializer. It never strips HTML with regular expressions, never needs a browser or DOM library, and makes no network calls.

## Install

```bash
pip install pyhtmlclean
```

No runtime dependencies. The package includes a `py.typed` marker for type checkers.

## Verified test count

The offline `unittest` suite passes **464 tests** on Python 3.9:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Quick start

```python
from pyhtmlclean import sanitize, strip_html

sanitize('<p>Hello <strong>world</strong></p><script>alert(1)</script>')
# '<p>Hello <strong>world</strong></p>'

sanitize('<a href="javascript:alert(1)" onclick="alert(2)">x</a>')
# '<a>x</a>'

strip_html('<script>alert(1)</script><p>A &amp; B</p>')
# 'A & B'
```

The default preset is `prose`. Choose another preset by name:

```python
sanitize('<img src="/x.png" alt="x">', policy='basic')
sanitize('<p>text</p>', policy='strict')
sanitize('<p>text</p>', policy='strip_all')
```

## Presets

| Preset | Purpose |
| --- | --- |
| `strict` | Small text-formatting allowlist for user comments and compact input. |
| `prose` | Default article, table and text structure. No images or embedded media. |
| `basic` | `prose` plus safe image and responsive image elements. |
| `strip_all` | No elements. Useful when only text should remain. |

Dangerous raw-text and embedded elements are never re-enabled by a custom policy. Their content is discarded completely: `script`, `style`, `iframe`, `object`, `embed`, `svg`, `math`, `noscript`, `template`, `textarea`, `title`, `xmp`, `noembed`, `noframes`, `plaintext`, and legacy frame or applet elements.

## Custom policies

```python
from pyhtmlclean import Policy, sanitize

policy = Policy(
    elements=['p', 'a', 'strong'],
    attributes={
        '*': ['title'],
        'a': ['href', 'target', 'rel'],
    },
    schemes=['https', 'mailto'],
    clobber_prefix='user-',
)

sanitize('<p><a href="https://example.com" target="_blank">safe</a></p>', policy)
```

Important policy fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `elements` | required | Exact lowercase element allowlist. |
| `attributes` | `{}` | Per-element attribute allowlist. Key `*` applies to all elements. |
| `schemes` | `http`, `https`, `mailto`, `tel` | Allowed URL schemes. |
| `allow_relative_urls` | `True` | Allow relative paths, queries and fragments. |
| `allow_protocol_relative` | `False` | Convert `//host/path` to `https://host/path` only when explicitly enabled. |
| `allow_inline_styles` | `False` | Enable the strict inline CSS sanitizer. |
| `css_properties` | empty | Exact CSS property allowlist required when styles are enabled. |
| `clobber_prefix` | `None` | Prefix allowed `id` and `name` values to reduce DOM clobbering risk. |
| `rel_noopener` | `True` | Add `rel="noopener noreferrer"` to `target="_blank"` links. |
| `max_depth` | `64` | Maximum emitted element nesting depth. |
| `max_tokens` | `100000` | Maximum tokenizer tokens before a typed error. |
| `max_input_bytes` | `524288` | Maximum UTF-8 input size before a typed error. |

Attribute entries ending in `*` are prefix wildcards, so `data-*` can be enabled deliberately. Event handlers, `srcdoc`, `formaction`, `xlink:href` and `is` are hard-denied even when a broad custom attribute rule exists.

## API

### `sanitize(html, policy='prose')`

Returns canonical sanitized HTML. Text and attribute values are decoded as a browser would decode them, validated, and then fully re-escaped. Non-void self-closing input such as `<div/>` is treated as an opening tag, matching browser behavior, and closed by the serializer. This preserves strict idempotency:

```python
once = sanitize(untrusted)
assert sanitize(once) == once
```

### `Policy` and `Sanitizer`

Reuse a normalized policy when sanitizing many values:

```python
from pyhtmlclean import Sanitizer

cleaner = Sanitizer('strict')
safe_comment = cleaner.sanitize(comment_html)
```

### `strip_html(html)`

Returns decoded plain text with all markup removed. Dangerous element content is discarded rather than unwrapped. Text order and original whitespace are preserved, but layout whitespace is not inferred where the input has none. The result is not HTML-safe. Escape it if it is inserted back into HTML.

### `inspect_html(html, policy='prose')`

Sanitizes once and returns a JSON-compatible audit dictionary:

```python
from pyhtmlclean import inspect_html

report = inspect_html('<p onclick="x">hello</p><!-- hidden -->')
assert report['output'] == '<p>hello</p>'
assert report['attributes_dropped'] == {'onclick': 1}
assert report['comments_removed'] == 1
```

The report includes input and output lengths, token count, allowed and stripped elements, dropped attributes, blocked URL attributes, comments, processing instructions, CDATA sections, doctypes, NUL bytes and dropped raw-text character counts.

## URL hardening

`href`, `src`, `action`, `poster`, `cite`, `background` and `srcset` are URL-aware. Before the scheme is checked, values are entity-decoded and ASCII controls, tabs, newlines and whitespace are removed. This blocks direct and obfuscated forms of `javascript:`, `vbscript:`, `data:`, `file:`, `blob:` and every other scheme not in the explicit allowlist. The five dangerous schemes are hard-blocked even if a custom policy names them.

Examples that are blocked:

```text
javascript:alert(1)
jav&#x09;ascript:alert(1)
&#106;avascript:alert(1)
java\nscript:alert(1)
javascript&colon;alert(1)
```

`srcset` candidates are parsed and validated individually. One invalid or dangerous candidate causes the whole `srcset` attribute to be dropped, avoiding browser error-recovery differences.

## Inline CSS

Inline styles are always stripped unless both conditions are true:

1. `allow_inline_styles=True`
2. `css_properties` contains an exact property allowlist

The CSS sanitizer is conservative. It rejects `expression()`, `url()`, `@import`, `behavior`, `-moz-binding`, script URL schemes, CSS escapes, custom properties, `var()`, `env()`, malformed declarations and unknown properties. If any declaration is unsafe or disallowed, the entire `style` attribute is omitted.

```python
policy = Policy(
    elements=['p'],
    attributes={'p': ['style']},
    allow_inline_styles=True,
    css_properties={'color', 'text-align'},
)
```

## mXSS and parser hardening

The sanitizer removes HTML comments including `--!>` forms, processing instructions, CDATA sections and doctypes. NUL bytes are stripped before tokenization. Foreign-content vectors in SVG and MathML, template breakout vectors, raw-text confusion and malformed markup cannot survive because output is serialized from scratch instead of copying input markup.

The tokenizer consumes raw-text regions in disjoint linear scans. It does not lowercase or rescan the whole document for each region. Resource limits raise typed errors:

- `InputTooLargeError` with code `INPUT_TOO_LARGE`
- `TokenLimitError` with code `TOKEN_LIMIT_EXCEEDED`
- `DepthLimitError` with code `MAX_DEPTH_EXCEEDED`

All are subclasses of `HtmlCleanError`.

## Migrating from bleach

Basic migration:

```python
# Before
# import bleach
# clean = bleach.clean(html, tags={'p', 'a', 'b'}, attributes={'a': {'href'}}, protocols={'https'})

from pyhtmlclean import Policy, sanitize

policy = Policy(
    elements={'p', 'a', 'b'},
    attributes={'a': {'href'}},
    schemes={'https'},
)
clean = sanitize(html, policy)
```

Mapping notes:

| bleach concept | pyhtmlclean equivalent |
| --- | --- |
| `tags` | `Policy(elements=...)` |
| `attributes` | `Policy(attributes=...)` with exact names or prefix entries such as `data-*` |
| `protocols` | `Policy(schemes=...)` without trailing colons |
| `strip=True` | Default behavior for ordinary disallowed elements: unwrap the tag and keep safe text |
| `strip_comments=True` | Always enabled |
| `css_sanitizer` | `allow_inline_styles=True` plus `css_properties` |
| `bleach.clean` | `sanitize` |
| text extraction | `strip_html` |

Important differences from bleach:

- Output is canonical and strictly idempotent.
- `target="_blank"` gains `noopener noreferrer` unless `rel_noopener=False`.
- `srcset` is URL-aware.
- `svg` and `math` content is always dropped because foreign-namespace mutation XSS is outside the safe subset.
- Protocol-relative URLs are blocked unless explicitly enabled, in which case they are canonicalized to `https:`.
- Linkification is not included. `pyhtmlclean` deliberately focuses on sanitization only.

## Framework examples

### FastAPI

```python
from fastapi import FastAPI
from pydantic import BaseModel
from pyhtmlclean import sanitize

app = FastAPI()

class CommentIn(BaseModel):
    body: str

@app.post('/comments')
def create_comment(comment: CommentIn):
    safe_body = sanitize(comment.body, 'prose')
    return {'body': safe_body}
```

### Django

```python
from django import forms
from pyhtmlclean import sanitize

class CommentForm(forms.Form):
    body = forms.CharField()

    def clean_body(self):
        return sanitize(self.cleaned_data['body'], 'prose')
```

Django templates autoescape variables. Store the sanitized HTML separately and mark it safe only after this sanitization boundary.

### Flask

```python
from flask import Flask, request, jsonify
from pyhtmlclean import sanitize

app = Flask(__name__)

@app.post('/comments')
def create_comment():
    body = request.get_json(force=True).get('body', '')
    return jsonify({'body': sanitize(body, 'prose')})
```

## Security boundary

Sanitized output is meant for insertion into an HTML body context. Do not place it inside a script, style block, event handler or unquoted attribute. Use a strict Content Security Policy as defense in depth. Keep custom policies narrow: every allowlisted element or attribute expands the attack surface.
